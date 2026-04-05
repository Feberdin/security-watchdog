"""
Purpose: Coordinate repository, container, Home Assistant, threat intel, and alert workflows.
Input/Output: Runs complete scans end-to-end and returns a small summary for APIs and jobs.
Important invariants: Each stage persists enough detail to debug failures later; one asset failing
must not stop the remaining assets from being scanned in the same run.
Debugging: This is the best entry point when the overall pipeline misbehaves because each stage logs
and records its own scan result from here.
"""

from __future__ import annotations

import logging
from pathlib import Path

from sqlalchemy import desc, select
from sqlalchemy.orm import Session

from app.models.entities import AIExtractedThreat, Alert, Dependency, Repository
from app.models.schemas import DependencyRecord, ScanRequest, ScanResponse, VulnerabilityRecord
from app.repositories.store import (
    link_dependency_to_vulnerability,
    record_scan_result,
    replace_repository_dependencies,
    upsert_alert,
    upsert_vulnerability,
)
from app.scanners.container_scanner import ContainerScanner
from app.scanners.dependency_extractor import DependencyExtractor
from app.scanners.homeassistant_scanner import HomeAssistantScanner
from app.scanners.repository_scanner import RepositoryScanner
from app.scanners.secret_scanner import SecretScanner
from app.scanners.unraid_scanner import UnraidScanner
from app.services.ai_extraction import AIExtractionService
from app.services.alerts import AlertDispatcher
from app.services.matching import normalize_version, version_matches
from app.services.risk import calculate_risk_score
from app.services.sbom import SbomService
from app.services.threat_intelligence import ThreatIntelligenceService
from app.services.vulnerability_service import VulnerabilityService

LOGGER = logging.getLogger(__name__)


class ScanOrchestrator:
    """Single orchestrator that ties together all scanners and correlation stages."""

    def __init__(self) -> None:
        self.repository_scanner = RepositoryScanner()
        self.unraid_scanner = UnraidScanner()
        self.homeassistant_scanner = HomeAssistantScanner()
        self.dependency_extractor = DependencyExtractor()
        self.secret_scanner = SecretScanner()
        self.container_scanner = ContainerScanner()
        self.vulnerability_service = VulnerabilityService()
        self.threat_service = ThreatIntelligenceService()
        self.ai_service = AIExtractionService()
        self.sbom_service = SbomService()
        self.alert_dispatcher = AlertDispatcher()

    def run_manual_scan(self, session: Session, request: ScanRequest) -> ScanResponse:
        """Run the complete asset scan workflow immediately."""

        repositories = self.repository_scanner.sync_repositories(
            session,
            repository_full_name=request.repository_full_name,
            include_archived=request.include_archived,
        )
        unraid_assets = self.unraid_scanner.sync_assets(session)
        homeassistant_assets = self.homeassistant_scanner.sync_assets(session)
        session.commit()

        processed_count = 0
        created_alerts = 0

        for repository in repositories:
            created_alerts += self._scan_repository_asset(session, repository)
            processed_count += 1

        for asset in unraid_assets:
            created_alerts += self._scan_unraid_asset(session, asset["repository"], asset["image_ref"])
            processed_count += 1

        for asset in homeassistant_assets:
            created_alerts += self._scan_homeassistant_asset(
                session,
                asset["repository"],
                asset["manifest_path"],
            )
            processed_count += 1

        session.commit()
        self._dispatch_open_alerts(session)
        session.commit()
        return ScanResponse(
            message="Scan completed",
            repository_count=processed_count,
            alert_count=created_alerts,
        )

    def collect_threat_intelligence(self, session: Session) -> int:
        """Run the feed collector and persist new articles."""

        count = self.threat_service.collect_and_store(session)
        session.commit()
        return count

    def run_ai_analysis(self, session: Session) -> int:
        """Run monthly AI extraction and persist structured threats."""

        count = self.ai_service.extract_pending_articles(session)
        session.commit()
        return count

    def _scan_repository_asset(self, session: Session, repository: Repository) -> int:
        """Run dependency, secret, container, and SBOM stages for a GitHub repository."""

        local_path = Path(repository.local_path)
        dependencies = self.dependency_extractor.extract_from_repository(local_path)
        orm_dependencies = replace_repository_dependencies(session, repository, dependencies)
        record_scan_result(
            session,
            repository_id=repository.id,
            scanner_name="dependency_extractor",
            status="success",
            findings_count=len(orm_dependencies),
            details={"source_type": repository.source_type},
        )

        alerts_created = 0
        alerts_created += self._correlate_dependencies(session, repository, orm_dependencies)

        secrets = self.secret_scanner.scan_directory(local_path)
        record_scan_result(
            session,
            repository_id=repository.id,
            scanner_name="secret_scanner",
            status="success",
            findings_count=len(secrets),
            details={"sample_findings": [finding.model_dump() for finding in secrets[:10]]},
        )
        for finding in secrets:
            alert = upsert_alert(
                session,
                repository_id=repository.id,
                title=f"Potential secret in {repository.full_name}",
                description=(
                    f"Detector `{finding.detector}` matched {finding.file_path}:{finding.line_number}. "
                    "Review the file, rotate the credential if valid, and remove it from history."
                ),
                severity="critical",
                risk_score=95.0,
                source_type="secret_scanner",
                metadata=finding.model_dump(),
            )
            alerts_created += 1 if alert else 0

        dockerfile_paths = [path for path in local_path.rglob("Dockerfile") if path.is_file()]
        for dockerfile_path in dockerfile_paths:
            findings = self.container_scanner.scan_dockerfile(dockerfile_path)
            record_scan_result(
                session,
                repository_id=repository.id,
                scanner_name="container_scanner",
                status="success",
                findings_count=len(findings),
                details={"dockerfile": str(dockerfile_path)},
            )
            for finding in findings:
                alert = upsert_alert(
                    session,
                    repository_id=repository.id,
                    title=f"Container issue for {repository.full_name}",
                    description=finding.description or f"{finding.tool} reported {finding.vulnerability_id}",
                    severity=finding.severity,
                    risk_score=85.0 if finding.severity in {"critical", "high"} else 55.0,
                    source_type="container_scanner",
                    metadata=finding.model_dump(),
                )
                alerts_created += 1 if alert else 0

        self.sbom_service.generate(repository, orm_dependencies)
        repository.risk_score = self._calculate_repository_risk(session, repository.id)
        return alerts_created

    def _scan_unraid_asset(self, session: Session, repository: Repository, image_ref: str) -> int:
        """Scan one running Unraid container image and persist alerts/findings."""

        synthetic_dependency = DependencyRecord(
            package_name=image_ref.split(":")[0],
            version=image_ref.split(":")[1] if ":" in image_ref else "latest",
            ecosystem="docker",
            manifest_path="runtime:image",
            metadata={"image_ref": image_ref},
        )
        orm_dependencies = replace_repository_dependencies(session, repository, [synthetic_dependency])
        findings = self.container_scanner.scan_image(image_ref)
        record_scan_result(
            session,
            repository_id=repository.id,
            scanner_name="unraid_container_scanner",
            status="success",
            findings_count=len(findings),
            details={"image_ref": image_ref},
        )
        alerts_created = self._correlate_dependencies(session, repository, orm_dependencies)
        for finding in findings:
            alert = upsert_alert(
                session,
                repository_id=repository.id,
                title=f"Unraid container vulnerability in {repository.name}",
                description=finding.description or f"{finding.vulnerability_id} affects {finding.package_name}",
                severity=finding.severity,
                risk_score=90.0 if finding.severity == "critical" else 70.0,
                source_type="unraid_container",
                metadata=finding.model_dump(),
            )
            alerts_created += 1 if alert else 0
        repository.risk_score = self._calculate_repository_risk(session, repository.id)
        return alerts_created

    def _scan_homeassistant_asset(
        self,
        session: Session,
        repository: Repository,
        manifest_path: Path | None,
    ) -> int:
        """Scan a Home Assistant integration manifest and optional local files."""

        dependencies: list[DependencyRecord] = []
        if manifest_path and manifest_path.exists():
            dependencies = self.dependency_extractor.extract_from_path(
                manifest_path,
                manifest_path.parent.parent if manifest_path.parent.parent.exists() else manifest_path.parent,
            )
        orm_dependencies = replace_repository_dependencies(session, repository, dependencies)
        record_scan_result(
            session,
            repository_id=repository.id,
            scanner_name="homeassistant_dependency_scan",
            status="success",
            findings_count=len(orm_dependencies),
            details={"manifest_path": str(manifest_path) if manifest_path else ""},
        )

        alerts_created = self._correlate_dependencies(session, repository, orm_dependencies)
        if repository.local_path:
            integration_path = Path(repository.local_path)
            secrets = self.secret_scanner.scan_directory(integration_path)
            for finding in secrets:
                alert = upsert_alert(
                    session,
                    repository_id=repository.id,
                    title=f"Potential secret in Home Assistant integration {repository.name}",
                    description=(
                        f"Detector `{finding.detector}` matched {finding.file_path}:{finding.line_number}. "
                        "Review the integration config and rotate any exposed credentials."
                    ),
                    severity="critical",
                    risk_score=95.0,
                    source_type="homeassistant_secret",
                    metadata=finding.model_dump(),
                )
                alerts_created += 1 if alert else 0
        self.sbom_service.generate(repository, orm_dependencies)
        repository.risk_score = self._calculate_repository_risk(session, repository.id)
        return alerts_created

    def _correlate_dependencies(
        self,
        session: Session,
        repository: Repository,
        orm_dependencies: list[Dependency],
    ) -> int:
        """Match dependencies against known vulnerabilities and AI-derived malicious versions."""

        created_alerts = 0
        for dependency in orm_dependencies:
            dependency_record = DependencyRecord(
                package_name=dependency.package_name,
                version=dependency.version,
                ecosystem=dependency.ecosystem,
                manifest_path=dependency.manifest_path,
                group_name=dependency.group_name,
                direct_dependency=dependency.direct_dependency,
                metadata=dependency.metadata_json,
            )
            vulnerability_records = self.vulnerability_service.correlate_dependency(dependency_record)
            created_alerts += self._persist_vulnerability_matches(
                session, repository, dependency, vulnerability_records
            )
            created_alerts += self._match_ai_threats(session, repository, dependency)
        return created_alerts

    def _persist_vulnerability_matches(
        self,
        session: Session,
        repository: Repository,
        dependency: Dependency,
        vulnerability_records: list[VulnerabilityRecord],
    ) -> int:
        """Persist vulnerability matches and open repository-level alerts."""

        created_alerts = 0
        for vulnerability_record in vulnerability_records:
            vulnerability = upsert_vulnerability(session, vulnerability_record)
            risk = calculate_risk_score(
                cvss_score=vulnerability.cvss_score,
                kev=vulnerability.kev,
                exploit_available=vulnerability.exploit_available,
                malicious_package=vulnerability.malicious_package,
            )
            link_dependency_to_vulnerability(
                session,
                dependency_id=dependency.id,
                vulnerability_id=vulnerability.id,
                risk_score=risk.score,
                match_reason=f"Matched {dependency.package_name}@{dependency.version} via {vulnerability.source}",
            )
            alert = upsert_alert(
                session,
                repository_id=repository.id,
                title=f"Vulnerable dependency {dependency.package_name}",
                description=(
                    f"{dependency.package_name} {dependency.version} in {repository.full_name} "
                    f"matched {vulnerability.source_identifier}. Reasons: {', '.join(risk.reasons)}."
                ),
                severity=risk.severity,
                risk_score=risk.score,
                source_type="dependency_vulnerability",
                metadata={
                    "dependency": dependency.package_name,
                    "version": dependency.version,
                    "manifest_path": dependency.manifest_path,
                    "vulnerability": vulnerability.source_identifier,
                    "references": vulnerability.reference_urls,
                },
            )
            created_alerts += 1 if alert else 0
        return created_alerts

    def _match_ai_threats(self, session: Session, repository: Repository, dependency: Dependency) -> int:
        """Compare dependencies to AI-extracted malicious package versions."""

        created_alerts = 0
        threats = session.scalars(
            select(AIExtractedThreat).where(
                AIExtractedThreat.package_name == dependency.package_name,
                AIExtractedThreat.ecosystem == dependency.ecosystem,
            )
        ).all()
        for threat in threats:
            if not version_matches(normalize_version(dependency.version), threat.affected_versions):
                continue
            risk_score = min(max(threat.confidence_score * 100, 50), 95)
            alert = upsert_alert(
                session,
                repository_id=repository.id,
                title=f"Malicious or compromised dependency {dependency.package_name}",
                description=(
                    f"{dependency.package_name} {dependency.version} matches AI-extracted threat intelligence "
                    f"from {threat.source_url}. Attack type: {threat.attack_type}. Summary: {threat.summary}"
                ),
                severity="critical" if threat.confidence_score >= 0.8 else "high",
                risk_score=risk_score,
                source_type="ai_correlation",
                metadata={
                    "dependency": dependency.package_name,
                    "version": dependency.version,
                    "affected_versions": threat.affected_versions,
                    "source_url": threat.source_url,
                    "attack_type": threat.attack_type,
                },
            )
            created_alerts += 1 if alert else 0
        return created_alerts

    def _dispatch_open_alerts(self, session: Session) -> None:
        """Deliver the newest unresolved alerts to external channels."""

        alerts = session.scalars(select(Alert).order_by(desc(Alert.created_at)).limit(50)).all()
        for alert in alerts:
            repository = session.get(Repository, alert.repository_id) if alert.repository_id else None
            self.alert_dispatcher.dispatch(alert, repository)

    def _calculate_repository_risk(self, session: Session, repository_id: int) -> float:
        """Set repository risk to the current highest open alert score."""

        alerts = session.scalars(select(Alert).where(Alert.repository_id == repository_id)).all()
        return max((alert.risk_score for alert in alerts), default=0.0)
