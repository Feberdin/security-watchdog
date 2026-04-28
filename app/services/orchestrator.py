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
    build_alert_fingerprint,
    link_dependency_to_vulnerability,
    record_scan_result,
    resolve_stale_alerts,
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
from app.services.matching import is_exact_version, version_matches
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

        repositories = self._run_inventory_stage(
            session,
            scanner_name="repository_inventory",
            details={
                "repository_full_name": request.repository_full_name or "",
                "include_archived": request.include_archived,
            },
            loader=lambda: self.repository_scanner.sync_repositories(
                session,
                repository_full_name=request.repository_full_name,
                include_archived=request.include_archived,
            ),
        )
        unraid_assets = self._run_inventory_stage(
            session,
            scanner_name="unraid_inventory",
            details={"source_type": "unraid_docker"},
            loader=lambda: self.unraid_scanner.sync_assets(session),
        )
        homeassistant_assets = self._run_inventory_stage(
            session,
            scanner_name="homeassistant_inventory",
            details={"source_type": "homeassistant"},
            loader=lambda: self.homeassistant_scanner.sync_assets(session),
        )

        processed_count = 0
        created_alerts = 0
        failed_system_count = 0

        for repository in repositories:
            alerts_created, failed = self._run_guarded_asset_scan(
                session,
                repository=repository,
                scanner_name="repository_asset_scan",
                details={
                    "full_name": repository.full_name,
                    "source_type": repository.source_type,
                },
                scan_callable=lambda repository=repository: self._scan_repository_asset(session, repository),
            )
            created_alerts += alerts_created
            processed_count += 1
            failed_system_count += failed

        for asset in unraid_assets:
            repository = asset["repository"]
            alerts_created, failed = self._run_guarded_asset_scan(
                session,
                repository=repository,
                scanner_name="unraid_asset_scan",
                details={
                    "full_name": repository.full_name,
                    "source_type": repository.source_type,
                    "image_ref": asset["image_ref"],
                },
                scan_callable=lambda asset=asset: self._scan_unraid_asset(
                    session,
                    asset["repository"],
                    asset["image_ref"],
                ),
            )
            created_alerts += alerts_created
            processed_count += 1
            failed_system_count += failed

        for asset in homeassistant_assets:
            repository = asset["repository"]
            alerts_created, failed = self._run_guarded_asset_scan(
                session,
                repository=repository,
                scanner_name="homeassistant_asset_scan",
                details={
                    "full_name": repository.full_name,
                    "source_type": repository.source_type,
                    "manifest_path": str(asset["manifest_path"] or ""),
                },
                scan_callable=lambda asset=asset: self._scan_homeassistant_asset(
                    session,
                    asset["repository"],
                    asset["manifest_path"],
                ),
            )
            created_alerts += alerts_created
            processed_count += 1
            failed_system_count += failed

        self._dispatch_open_alerts(session)
        session.commit()
        return ScanResponse(
            message="Scan completed with warnings" if failed_system_count else "Scan completed",
            repository_count=processed_count,
            alert_count=created_alerts,
            failed_system_count=failed_system_count,
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
        active_alerts_by_source = {
            "dependency_vulnerability": set(),
            "ai_correlation": set(),
            "secret_scanner": set(),
            "container_scanner": set(),
        }
        dependency_alerts_created, dependency_active_alerts = self._correlate_dependencies(
            session,
            repository,
            orm_dependencies,
        )
        alerts_created += dependency_alerts_created
        for source_type, fingerprints in dependency_active_alerts.items():
            active_alerts_by_source[source_type].update(fingerprints)

        include_git_history = self._should_scan_repository_git_history(repository)
        secrets = self.secret_scanner.scan_directory(
            local_path,
            include_git_history=include_git_history,
        )
        record_scan_result(
            session,
            repository_id=repository.id,
            scanner_name="secret_scanner",
            status="success",
            findings_count=len(secrets),
            details={"sample_findings": [finding.model_dump() for finding in secrets[:10]]},
        )
        for finding in secrets:
            metadata = finding.model_dump()
            active_alerts_by_source["secret_scanner"].add(
                build_alert_fingerprint(
                    repository_id=repository.id,
                    title=f"Potential secret in {repository.full_name}",
                    source_type="secret_scanner",
                    metadata=metadata,
                )
            )
            alert = upsert_alert(
                session,
                repository_id=repository.id,
                title=f"Potential secret in {repository.full_name}",
                description=self._describe_secret_finding(
                    finding,
                    git_history_is_public=include_git_history,
                ),
                severity="critical",
                risk_score=95.0,
                source_type="secret_scanner",
                metadata=metadata,
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
                metadata = finding.model_dump()
                active_alerts_by_source["container_scanner"].add(
                    build_alert_fingerprint(
                        repository_id=repository.id,
                        title=f"Container issue for {repository.full_name}",
                        source_type="container_scanner",
                        metadata=metadata,
                    )
                )
                alert = upsert_alert(
                    session,
                    repository_id=repository.id,
                    title=f"Container issue for {repository.full_name}",
                    description=finding.description or f"{finding.tool} reported {finding.vulnerability_id}",
                    severity=finding.severity,
                    risk_score=85.0 if finding.severity in {"critical", "high"} else 55.0,
                    source_type="container_scanner",
                    metadata=metadata,
                )
                alerts_created += 1 if alert else 0

        resolve_stale_alerts(
            session,
            repository_id=repository.id,
            source_types=list(active_alerts_by_source),
            active_fingerprints=self._merge_active_alert_fingerprints(active_alerts_by_source),
        )
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
        active_alerts_by_source = {
            "dependency_vulnerability": set(),
            "ai_correlation": set(),
            "unraid_container": set(),
        }
        alerts_created, dependency_active_alerts = self._correlate_dependencies(
            session,
            repository,
            orm_dependencies,
        )
        for source_type, fingerprints in dependency_active_alerts.items():
            active_alerts_by_source[source_type].update(fingerprints)
        for finding in findings:
            metadata = finding.model_dump()
            active_alerts_by_source["unraid_container"].add(
                build_alert_fingerprint(
                    repository_id=repository.id,
                    title=f"Unraid container vulnerability in {repository.name}",
                    source_type="unraid_container",
                    metadata=metadata,
                )
            )
            alert = upsert_alert(
                session,
                repository_id=repository.id,
                title=f"Unraid container vulnerability in {repository.name}",
                description=finding.description or f"{finding.vulnerability_id} affects {finding.package_name}",
                severity=finding.severity,
                risk_score=90.0 if finding.severity == "critical" else 70.0,
                source_type="unraid_container",
                metadata=metadata,
            )
            alerts_created += 1 if alert else 0
        resolve_stale_alerts(
            session,
            repository_id=repository.id,
            source_types=list(active_alerts_by_source),
            active_fingerprints=self._merge_active_alert_fingerprints(active_alerts_by_source),
        )
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
            details={
                "manifest_path": str(manifest_path) if manifest_path else "",
                "source_type": repository.source_type,
                "inventory_source": repository.metadata_json.get("inventory_source", "local_files"),
                "homeassistant_base_url": repository.metadata_json.get("homeassistant_base_url", ""),
            },
        )

        active_alerts_by_source = {
            "dependency_vulnerability": set(),
            "ai_correlation": set(),
            "homeassistant_secret": set(),
        }
        alerts_created, dependency_active_alerts = self._correlate_dependencies(
            session,
            repository,
            orm_dependencies,
        )
        for source_type, fingerprints in dependency_active_alerts.items():
            active_alerts_by_source[source_type].update(fingerprints)
        if repository.local_path:
            integration_path = Path(repository.local_path)
            secrets = self.secret_scanner.scan_directory(integration_path)
            for finding in secrets:
                metadata = finding.model_dump()
                active_alerts_by_source["homeassistant_secret"].add(
                    build_alert_fingerprint(
                        repository_id=repository.id,
                        title=f"Potential secret in Home Assistant integration {repository.name}",
                        source_type="homeassistant_secret",
                        metadata=metadata,
                    )
                )
                alert = upsert_alert(
                    session,
                    repository_id=repository.id,
                    title=f"Potential secret in Home Assistant integration {repository.name}",
                    description=self._describe_secret_finding(
                        finding,
                        remediation_hint=(
                            "Review the integration config and rotate any exposed credentials."
                        ),
                    ),
                    severity="critical",
                    risk_score=95.0,
                    source_type="homeassistant_secret",
                    metadata=metadata,
                )
                alerts_created += 1 if alert else 0
        resolve_stale_alerts(
            session,
            repository_id=repository.id,
            source_types=list(active_alerts_by_source),
            active_fingerprints=self._merge_active_alert_fingerprints(active_alerts_by_source),
        )
        self.sbom_service.generate(repository, orm_dependencies)
        repository.risk_score = self._calculate_repository_risk(session, repository.id)
        return alerts_created

    def _correlate_dependencies(
        self,
        session: Session,
        repository: Repository,
        orm_dependencies: list[Dependency],
    ) -> tuple[int, dict[str, set[str]]]:
        """Match dependencies against known vulnerabilities and AI-derived malicious versions."""

        created_alerts = 0
        active_alerts_by_source = {
            "dependency_vulnerability": set(),
            "ai_correlation": set(),
        }
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
            dependency_alerts_created, vulnerability_fingerprints = self._persist_vulnerability_matches(
                session, repository, dependency, vulnerability_records
            )
            created_alerts += dependency_alerts_created
            active_alerts_by_source["dependency_vulnerability"].update(vulnerability_fingerprints)
            ai_alerts_created, ai_fingerprints = self._match_ai_threats(session, repository, dependency)
            created_alerts += ai_alerts_created
            active_alerts_by_source["ai_correlation"].update(ai_fingerprints)
        return created_alerts, active_alerts_by_source

    def _should_scan_repository_git_history(self, repository: Repository) -> bool:
        """Only scan git history when the repository is public and therefore historically exposed."""

        return repository.source_type == "github" and not repository.metadata_json.get("private", False)

    def _describe_secret_finding(
        self,
        finding,
        *,
        git_history_is_public: bool = False,
        remediation_hint: str | None = None,
    ) -> str:
        """Explain whether a secret was found in the working tree or in publicly reachable history."""

        location = f"{finding.file_path}:{finding.line_number}"
        hint = remediation_hint or "Review the file, rotate the credential if valid, and remove it from history."
        if finding.content_source == "git_history" and finding.commit_sha:
            exposure_scope = "public git history" if git_history_is_public else "git history"
            return (
                f"Detector `{finding.detector}` matched {location} in {exposure_scope} commit "
                f"{finding.commit_sha[:12]}. {hint}"
            )
        return f"Detector `{finding.detector}` matched {location}. {hint}"

    def _persist_vulnerability_matches(
        self,
        session: Session,
        repository: Repository,
        dependency: Dependency,
        vulnerability_records: list[VulnerabilityRecord],
    ) -> tuple[int, set[str]]:
        """Persist vulnerability matches and open repository-level alerts."""

        created_alerts = 0
        active_fingerprints: set[str] = set()
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
            metadata = {
                "dependency": dependency.package_name,
                "version": dependency.version,
                "manifest_path": dependency.manifest_path,
                "vulnerability": vulnerability.source_identifier,
                "references": vulnerability.reference_urls,
            }
            active_fingerprints.add(
                build_alert_fingerprint(
                    repository_id=repository.id,
                    title=f"Vulnerable dependency {dependency.package_name}",
                    source_type="dependency_vulnerability",
                    metadata=metadata,
                )
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
                metadata=metadata,
            )
            created_alerts += 1 if alert else 0
        return created_alerts, active_fingerprints

    def _match_ai_threats(
        self,
        session: Session,
        repository: Repository,
        dependency: Dependency,
    ) -> tuple[int, set[str]]:
        """Compare dependencies to AI-extracted malicious package versions."""

        if not is_exact_version(dependency.version):
            return 0, set()

        created_alerts = 0
        active_fingerprints: set[str] = set()
        threats = session.scalars(
            select(AIExtractedThreat).where(
                AIExtractedThreat.package_name == dependency.package_name,
                AIExtractedThreat.ecosystem == dependency.ecosystem,
            )
        ).all()
        for threat in threats:
            if threat.affected_versions and not version_matches(dependency.version, threat.affected_versions):
                continue
            risk_score = min(max(threat.confidence_score * 100, 50), 95)
            metadata = {
                "dependency": dependency.package_name,
                "version": dependency.version,
                "affected_versions": threat.affected_versions,
                "source_url": threat.source_url,
                "attack_type": threat.attack_type,
            }
            active_fingerprints.add(
                build_alert_fingerprint(
                    repository_id=repository.id,
                    title=f"Malicious or compromised dependency {dependency.package_name}",
                    source_type="ai_correlation",
                    metadata=metadata,
                )
            )
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
                metadata=metadata,
            )
            created_alerts += 1 if alert else 0
        return created_alerts, active_fingerprints

    def _dispatch_open_alerts(self, session: Session) -> None:
        """Deliver the newest unresolved alerts to external channels."""

        alerts = session.scalars(
            select(Alert)
            .where(Alert.status == "open")
            .order_by(desc(Alert.updated_at))
            .limit(50)
        ).all()
        for alert in alerts:
            repository = session.get(Repository, alert.repository_id) if alert.repository_id else None
            self.alert_dispatcher.dispatch(alert, repository)

    def _run_inventory_stage(
        self,
        session: Session,
        *,
        scanner_name: str,
        details: dict[str, str | bool],
        loader,
    ) -> list:
        """Run one inventory stage and convert hard failures into auditable error records."""

        try:
            assets = loader()
            record_scan_result(
                session,
                repository_id=None,
                scanner_name=scanner_name,
                status="success",
                findings_count=len(assets),
                details=details,
            )
            session.commit()
            return assets
        except Exception as error:  # noqa: BLE001
            session.rollback()
            LOGGER.exception("Inventory stage failed", extra={"scanner_name": scanner_name, **details})
            record_scan_result(
                session,
                repository_id=None,
                scanner_name=scanner_name,
                status="error",
                findings_count=0,
                details={**details, "error": str(error)},
            )
            session.commit()
            return []

    def _run_guarded_asset_scan(
        self,
        session: Session,
        *,
        repository: Repository,
        scanner_name: str,
        details: dict[str, str],
        scan_callable,
    ) -> tuple[int, int]:
        """
        Run one asset scan without letting a single failure abort the whole manual scan.

        Why this exists:
        Operators run `/scan` to refresh a large mixed estate. A single Git checkout problem or
        scanner edge case should be visible in logs and scan history, but it should not block every
        remaining repository, container, and Home Assistant integration from being processed.
        """

        try:
            alerts_created = scan_callable()
            session.commit()
            return alerts_created, 0
        except Exception as error:  # noqa: BLE001
            session.rollback()
            LOGGER.exception("Asset scan failed", extra={"repository": repository.full_name, **details})
            record_scan_result(
                session,
                repository_id=repository.id,
                scanner_name=scanner_name,
                status="error",
                findings_count=0,
                details={**details, "error": str(error)},
            )
            session.commit()
            return 0, 1

    def _calculate_repository_risk(self, session: Session, repository_id: int) -> float:
        """Set repository risk to the current highest open alert score."""

        alerts = session.scalars(
            select(Alert).where(
                Alert.repository_id == repository_id,
                Alert.status != "resolved",
            )
        ).all()
        return max((alert.risk_score for alert in alerts), default=0.0)

    def _merge_active_alert_fingerprints(
        self,
        fingerprints_by_source: dict[str, set[str]],
    ) -> set[str]:
        """Collapse source-keyed fingerprint sets into one repository-wide active fingerprint set."""

        merged: set[str] = set()
        for fingerprints in fingerprints_by_source.values():
            merged.update(fingerprints)
        return merged
