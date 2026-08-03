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
from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path

from sqlalchemy import desc, select
from sqlalchemy.orm import Session

from app.models.entities import AIExtractedThreat, Alert, Dependency, ManualScanJob, Repository, ScanResult
from app.models.schemas import DependencyRecord, ScanRequest, ScanResponse, VulnerabilityRecord
from app.repositories.store import (
    build_alert_fingerprint,
    link_dependency_to_vulnerability,
    record_scan_result,
    replace_repository_dependencies,
    resolve_stale_alerts,
    update_manual_scan_job_checkpoint,
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
from app.services.scan_control import ScanCanceledError
from app.services.scan_progress import ScanProgressCallback, ScanProgressReporter
from app.services.threat_intelligence import ThreatIntelligenceService
from app.services.vulnerability_service import VulnerabilityService

LOGGER = logging.getLogger(__name__)
ScanCancellationCheck = Callable[[], None]


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

    def run_manual_scan(
        self,
        session: Session,
        request: ScanRequest,
        *,
        job_id: int | None = None,
        resume_started_at: datetime | None = None,
        progress_callback: ScanProgressCallback | None = None,
        cancellation_check: ScanCancellationCheck | None = None,
    ) -> ScanResponse:
        """Run the complete asset scan workflow immediately."""

        selected_sources = set(request.scan_sources)
        progress = ScanProgressReporter(progress_callback)
        self._check_cancellation(cancellation_check)
        progress.emit(
            phase="inventory",
            message="Scan-Inventar wird aktualisiert.",
            percent=2.0,
            current=0,
            total=0,
        )
        repositories = []
        if "github" in selected_sources:
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
            repositories = [
                repository
                for repository in repositories
                if self._should_scan_repository_for_request(repository, request)
            ]
        self._check_cancellation(cancellation_check)
        progress.emit(
            phase="inventory",
            message=f"GitHub-Inventar geladen: {len(repositories)} Repositories.",
            percent=5.0,
            current=0,
            total=0,
        )
        unraid_assets = []
        if "unraid" in selected_sources:
            unraid_assets = self._run_inventory_stage(
                session,
                scanner_name="unraid_inventory",
                details={"source_type": "unraid_docker"},
                loader=lambda: self.unraid_scanner.sync_assets(session),
            )
            unraid_assets = [
                asset
                for asset in unraid_assets
                if self._should_scan_repository_for_request(asset["repository"], request)
            ]
        self._check_cancellation(cancellation_check)
        progress.emit(
            phase="inventory",
            message=f"Container-Inventar geladen: {len(unraid_assets)} Systeme.",
            percent=7.0,
            current=0,
            total=0,
        )
        homeassistant_assets = []
        if "homeassistant" in selected_sources:
            homeassistant_assets = self._run_inventory_stage(
                session,
                scanner_name="homeassistant_inventory",
                details={"source_type": "homeassistant"},
                loader=lambda: self.homeassistant_scanner.sync_assets(session),
            )
            homeassistant_assets = [
                asset
                for asset in homeassistant_assets
                if self._should_scan_repository_for_request(asset["repository"], request)
            ]
        self._check_cancellation(cancellation_check)
        progress.emit(
            phase="inventory",
            message=f"Home-Assistant-Inventar geladen: {len(homeassistant_assets)} Integrationen.",
            percent=9.0,
            current=0,
            total=0,
        )
        progress.configure_assets(len(repositories) + len(unraid_assets) + len(homeassistant_assets))

        processed_count, created_alerts, failed_system_count = self._load_manual_scan_checkpoint(
            session,
            job_id,
        )
        resume_counts_are_persisted = processed_count > 0

        for repository in repositories:
            self._check_cancellation(cancellation_check)
            already_finished, previously_failed = self._asset_scan_finished_since(
                session,
                repository=repository,
                scanner_name="repository_asset_scan",
                started_at=resume_started_at,
            )
            if already_finished:
                progress.asset_step(
                    phase="repository",
                    asset_name=repository.full_name,
                    message="vor dem Neustart bereits verarbeitet.",
                    fraction=1.0,
                    level="warning" if previously_failed else "info",
                )
                processed_count, failed_system_count = self._count_resumed_asset(
                    processed_count,
                    failed_system_count,
                    previously_failed=previously_failed,
                    resume_counts_are_persisted=resume_counts_are_persisted,
                )
                self._save_manual_scan_checkpoint(
                    session,
                    job_id=job_id,
                    repository_count=processed_count,
                    alert_count=created_alerts,
                    failed_system_count=failed_system_count,
                )
                progress.finish_asset(asset_name=repository.full_name, failed=previously_failed)
                continue

            progress.asset_step(
                phase="repository",
                asset_name=repository.full_name,
                message="Repository-Scan wird vorbereitet.",
                fraction=0.0,
            )
            alerts_created, failed = self._run_guarded_asset_scan(
                session,
                repository=repository,
                scanner_name="repository_asset_scan",
                details={
                    "full_name": repository.full_name,
                    "source_type": repository.source_type,
                },
                scan_callable=lambda repository=repository: self._scan_repository_asset(
                    session,
                    repository,
                    progress,
                    cancellation_check=cancellation_check,
                ),
            )
            created_alerts += alerts_created
            processed_count += 1
            failed_system_count += failed
            self._save_manual_scan_checkpoint(
                session,
                job_id=job_id,
                repository_count=processed_count,
                alert_count=created_alerts,
                failed_system_count=failed_system_count,
            )
            progress.finish_asset(asset_name=repository.full_name, failed=bool(failed))

        for asset in unraid_assets:
            self._check_cancellation(cancellation_check)
            repository = asset["repository"]
            already_finished, previously_failed = self._asset_scan_finished_since(
                session,
                repository=repository,
                scanner_name="unraid_asset_scan",
                started_at=resume_started_at,
            )
            if already_finished:
                progress.asset_step(
                    phase="container",
                    asset_name=repository.full_name,
                    message="vor dem Neustart bereits verarbeitet.",
                    fraction=1.0,
                    level="warning" if previously_failed else "info",
                )
                processed_count, failed_system_count = self._count_resumed_asset(
                    processed_count,
                    failed_system_count,
                    previously_failed=previously_failed,
                    resume_counts_are_persisted=resume_counts_are_persisted,
                )
                self._save_manual_scan_checkpoint(
                    session,
                    job_id=job_id,
                    repository_count=processed_count,
                    alert_count=created_alerts,
                    failed_system_count=failed_system_count,
                )
                progress.finish_asset(asset_name=repository.full_name, failed=previously_failed)
                continue

            progress.asset_step(
                phase="container",
                asset_name=repository.full_name,
                message="Laufzeit-Container wird vorbereitet.",
                fraction=0.0,
            )
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
                    progress,
                    cancellation_check=cancellation_check,
                ),
            )
            created_alerts += alerts_created
            processed_count += 1
            failed_system_count += failed
            self._save_manual_scan_checkpoint(
                session,
                job_id=job_id,
                repository_count=processed_count,
                alert_count=created_alerts,
                failed_system_count=failed_system_count,
            )
            progress.finish_asset(asset_name=repository.full_name, failed=bool(failed))

        for asset in homeassistant_assets:
            self._check_cancellation(cancellation_check)
            repository = asset["repository"]
            already_finished, previously_failed = self._asset_scan_finished_since(
                session,
                repository=repository,
                scanner_name="homeassistant_asset_scan",
                started_at=resume_started_at,
            )
            if already_finished:
                progress.asset_step(
                    phase="homeassistant",
                    asset_name=repository.full_name,
                    message="vor dem Neustart bereits verarbeitet.",
                    fraction=1.0,
                    level="warning" if previously_failed else "info",
                )
                processed_count, failed_system_count = self._count_resumed_asset(
                    processed_count,
                    failed_system_count,
                    previously_failed=previously_failed,
                    resume_counts_are_persisted=resume_counts_are_persisted,
                )
                self._save_manual_scan_checkpoint(
                    session,
                    job_id=job_id,
                    repository_count=processed_count,
                    alert_count=created_alerts,
                    failed_system_count=failed_system_count,
                )
                progress.finish_asset(asset_name=repository.full_name, failed=previously_failed)
                continue

            progress.asset_step(
                phase="homeassistant",
                asset_name=repository.full_name,
                message="Integration wird vorbereitet.",
                fraction=0.0,
            )
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
                    progress,
                    cancellation_check=cancellation_check,
                ),
            )
            created_alerts += alerts_created
            processed_count += 1
            failed_system_count += failed
            self._save_manual_scan_checkpoint(
                session,
                job_id=job_id,
                repository_count=processed_count,
                alert_count=created_alerts,
                failed_system_count=failed_system_count,
            )
            progress.finish_asset(asset_name=repository.full_name, failed=bool(failed))

        progress.emit(
            phase="finalizing",
            message="Offene Alerts und Scan-Ergebnisse werden abgeschlossen.",
            percent=98.0,
            current=processed_count,
            total=progress.total_assets,
        )
        self._check_cancellation(cancellation_check)
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

    def _should_scan_repository_for_request(self, repository: Repository, request: ScanRequest) -> bool:
        """
        Apply operator scan selection to one repository-like asset.

        Why this exists:
        Inventory refresh and scan execution are separate decisions. Operators can keep irrelevant
        assets in the database for audit history while excluding them from future scan work and
        dashboard reports.
        """

        if not repository.scan_enabled:
            return False
        if request.repository_full_name and repository.full_name != request.repository_full_name:
            return False
        return True

    def _check_cancellation(self, cancellation_check: ScanCancellationCheck | None) -> None:
        """Run the supplied cancellation checkpoint when a scan job is cancelable."""

        if cancellation_check is not None:
            cancellation_check()

    def _scan_repository_asset(
        self,
        session: Session,
        repository: Repository,
        progress: ScanProgressReporter | None = None,
        cancellation_check: ScanCancellationCheck | None = None,
    ) -> int:
        """Run dependency, secret, container, and SBOM stages for a GitHub repository."""

        self._check_cancellation(cancellation_check)
        local_path = Path(repository.local_path)
        if progress:
            progress.asset_step(
                phase="dependencies",
                asset_name=repository.full_name,
                message="Manifest-Dateien werden ausgewertet.",
                fraction=0.03,
            )
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
        if progress:
            progress.asset_step(
                phase="dependencies",
                asset_name=repository.full_name,
                message=f"{len(orm_dependencies)} Abhängigkeiten gefunden.",
                fraction=0.10,
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
            progress=progress,
            progress_start=0.12,
            progress_end=0.70,
            cancellation_check=cancellation_check,
        )
        alerts_created += dependency_alerts_created
        for source_type, fingerprints in dependency_active_alerts.items():
            active_alerts_by_source[source_type].update(fingerprints)

        self._check_cancellation(cancellation_check)
        include_git_history = self._should_scan_repository_git_history(repository)
        if progress:
            progress.asset_step(
                phase="secrets",
                asset_name=repository.full_name,
                message="Dateien und freigegebene Git-Historie werden auf Secrets geprüft.",
                fraction=0.74,
            )
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
        for dockerfile_index, dockerfile_path in enumerate(dockerfile_paths, start=1):
            self._check_cancellation(cancellation_check)
            if progress:
                progress.asset_step(
                    phase="container",
                    asset_name=repository.full_name,
                    message=(f"Dockerfile {dockerfile_index}/{len(dockerfile_paths)} wird geprüft."),
                    fraction=0.82 + (dockerfile_index - 1) / max(len(dockerfile_paths), 1) * 0.10,
                )
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

        self._check_cancellation(cancellation_check)
        resolve_stale_alerts(
            session,
            repository_id=repository.id,
            source_types=list(active_alerts_by_source),
            active_fingerprints=self._merge_active_alert_fingerprints(active_alerts_by_source),
        )
        if progress:
            progress.asset_step(
                phase="sbom",
                asset_name=repository.full_name,
                message="SBOM und Risikowert werden aktualisiert.",
                fraction=0.96,
            )
        self.sbom_service.generate(repository, orm_dependencies)
        repository.risk_score = self._calculate_repository_risk(session, repository.id)
        return alerts_created

    def _scan_unraid_asset(
        self,
        session: Session,
        repository: Repository,
        image_ref: str,
        progress: ScanProgressReporter | None = None,
        cancellation_check: ScanCancellationCheck | None = None,
    ) -> int:
        """Scan one running Unraid container image and persist alerts/findings."""

        self._check_cancellation(cancellation_check)
        synthetic_dependency = DependencyRecord(
            package_name=image_ref.split(":")[0],
            version=image_ref.split(":")[1] if ":" in image_ref else "latest",
            ecosystem="docker",
            manifest_path="runtime:image",
            metadata={"image_ref": image_ref},
        )
        orm_dependencies = replace_repository_dependencies(session, repository, [synthetic_dependency])
        if progress:
            progress.asset_step(
                phase="container",
                asset_name=repository.full_name,
                message=f"Container-Image {image_ref} wird analysiert.",
                fraction=0.15,
            )
        findings = self.container_scanner.scan_image(image_ref)
        self._check_cancellation(cancellation_check)
        if progress:
            progress.asset_step(
                phase="container",
                asset_name=repository.full_name,
                message=f"Image-Scan abgeschlossen: {len(findings)} Findings.",
                fraction=0.65,
            )
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
            progress=progress,
            progress_start=0.68,
            progress_end=0.90,
            cancellation_check=cancellation_check,
        )
        for source_type, fingerprints in dependency_active_alerts.items():
            active_alerts_by_source[source_type].update(fingerprints)
        for finding in findings:
            self._check_cancellation(cancellation_check)
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
        progress: ScanProgressReporter | None = None,
        cancellation_check: ScanCancellationCheck | None = None,
    ) -> int:
        """Scan a Home Assistant integration manifest and optional local files."""

        self._check_cancellation(cancellation_check)
        dependencies: list[DependencyRecord] = []
        if progress:
            progress.asset_step(
                phase="homeassistant",
                asset_name=repository.full_name,
                message="Manifest und Requirements werden ausgewertet.",
                fraction=0.08,
            )
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
            progress=progress,
            progress_start=0.15,
            progress_end=0.72,
            cancellation_check=cancellation_check,
        )
        for source_type, fingerprints in dependency_active_alerts.items():
            active_alerts_by_source[source_type].update(fingerprints)
        if repository.local_path:
            self._check_cancellation(cancellation_check)
            integration_path = Path(repository.local_path)
            if progress:
                progress.asset_step(
                    phase="secrets",
                    asset_name=repository.full_name,
                    message="Integrationsdateien werden auf Secrets geprüft.",
                    fraction=0.78,
                )
            secrets = self.secret_scanner.scan_directory(integration_path)
            for finding in secrets:
                self._check_cancellation(cancellation_check)
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
        if progress:
            progress.asset_step(
                phase="sbom",
                asset_name=repository.full_name,
                message="SBOM und Risikowert werden aktualisiert.",
                fraction=0.96,
            )
        self.sbom_service.generate(repository, orm_dependencies)
        repository.risk_score = self._calculate_repository_risk(session, repository.id)
        return alerts_created

    def _correlate_dependencies(
        self,
        session: Session,
        repository: Repository,
        orm_dependencies: list[Dependency],
        *,
        progress: ScanProgressReporter | None = None,
        progress_start: float = 0.15,
        progress_end: float = 0.75,
        cancellation_check: ScanCancellationCheck | None = None,
    ) -> tuple[int, dict[str, set[str]]]:
        """Match dependencies against known vulnerabilities and AI-derived malicious versions."""

        created_alerts = 0
        active_alerts_by_source = {
            "dependency_vulnerability": set(),
            "ai_correlation": set(),
        }
        dependency_count = len(orm_dependencies)
        progress_interval = max(1, dependency_count // 20)
        for dependency_index, dependency in enumerate(orm_dependencies, start=1):
            if dependency_index == 1 or (dependency_index - 1) % progress_interval == 0:
                self._check_cancellation(cancellation_check)
            if progress and (
                dependency_index == 1
                or dependency_index == dependency_count
                or (dependency_index - 1) % progress_interval == 0
            ):
                fraction = progress_start + ((dependency_index - 1) / max(dependency_count, 1)) * (
                    progress_end - progress_start
                )
                progress.asset_step(
                    phase="vulnerabilities",
                    asset_name=repository.full_name,
                    message=(
                        f"Abhängigkeit {dependency.package_name} wird geprüft ({dependency_index}/{dependency_count})."
                    ),
                    fraction=fraction,
                )
            dependency_record = DependencyRecord(
                package_name=dependency.package_name,
                version=dependency.version,
                ecosystem=dependency.ecosystem,
                manifest_path=dependency.manifest_path,
                group_name=dependency.group_name,
                direct_dependency=dependency.direct_dependency,
                metadata=dependency.metadata_json,
            )
            vulnerability_records = self.vulnerability_service.correlate_dependency(
                dependency_record,
                cache_session=session,
            )
            dependency_alerts_created, vulnerability_fingerprints = self._persist_vulnerability_matches(
                session, repository, dependency, vulnerability_records
            )
            created_alerts += dependency_alerts_created
            active_alerts_by_source["dependency_vulnerability"].update(vulnerability_fingerprints)
            ai_alerts_created, ai_fingerprints = self._match_ai_threats(session, repository, dependency)
            created_alerts += ai_alerts_created
            active_alerts_by_source["ai_correlation"].update(ai_fingerprints)
        if progress:
            progress.asset_step(
                phase="vulnerabilities",
                asset_name=repository.full_name,
                message=f"{dependency_count} Abhängigkeiten korreliert.",
                fraction=progress_end,
            )
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

    def _load_manual_scan_checkpoint(
        self,
        session: Session,
        job_id: int | None,
    ) -> tuple[int, int, int]:
        """
        Return persisted manual-scan counters before a resumed run continues.

        Why this exists:
        A deployment can interrupt the worker after several assets already committed their scan
        results. The job row stores conservative progress counters, so the resumed worker does not
        reset visible progress or double-count assets that were checkpointed before restart.
        """

        if job_id is None:
            return 0, 0, 0

        job = session.get(ManualScanJob, job_id)
        if job is None:
            return 0, 0, 0

        return job.repository_count, job.alert_count, job.failed_system_count

    def _save_manual_scan_checkpoint(
        self,
        session: Session,
        *,
        job_id: int | None,
        repository_count: int,
        alert_count: int,
        failed_system_count: int,
    ) -> None:
        """
        Persist current manual-scan counters after one asset decision.

        Why this exists:
        The worker may be restarted by a deployment at any time. Committing the checkpoint after
        each asset keeps the job resumable without requiring a separate migration or external state
        store.
        """

        if job_id is None:
            return

        update_manual_scan_job_checkpoint(
            session,
            job_id=job_id,
            repository_count=repository_count,
            alert_count=alert_count,
            failed_system_count=failed_system_count,
        )
        session.commit()

    def _asset_scan_finished_since(
        self,
        session: Session,
        *,
        repository: Repository,
        scanner_name: str,
        started_at: datetime | None,
    ) -> tuple[bool, bool]:
        """
        Decide whether a resumed job can skip one asset.

        Why this exists:
        Successful scans update `repositories.last_scanned_at`; failed guarded asset scans write an
        error `scan_results` row. Combining those two existing signals lets a restarted manual scan
        continue after the last durable asset outcome without adding a new table.
        """

        normalized_started_at = self._normalize_datetime(started_at)
        if normalized_started_at is None:
            return False, False

        last_scanned_at = self._normalize_datetime(repository.last_scanned_at)
        if last_scanned_at is not None and last_scanned_at >= normalized_started_at:
            LOGGER.info(
                "Skipping already scanned asset during manual scan resume",
                extra={"repository": repository.full_name, "scanner_name": scanner_name},
            )
            return True, False

        failed_scan_id = session.scalar(
            select(ScanResult.id)
            .where(
                ScanResult.repository_id == repository.id,
                ScanResult.scanner_name == scanner_name,
                ScanResult.status == "error",
                ScanResult.started_at >= normalized_started_at,
            )
            .order_by(desc(ScanResult.started_at))
            .limit(1)
        )
        if failed_scan_id is not None:
            LOGGER.info(
                "Skipping already failed asset during manual scan resume",
                extra={"repository": repository.full_name, "scanner_name": scanner_name},
            )
            return True, True

        return False, False

    def _count_resumed_asset(
        self,
        processed_count: int,
        failed_system_count: int,
        *,
        previously_failed: bool,
        resume_counts_are_persisted: bool,
    ) -> tuple[int, int]:
        """
        Count skipped assets only when the job row did not already checkpoint counters.

        Example:
        A pre-upgrade scan has no checkpoint counters yet, but it may have committed
        `last_scanned_at` on 20 repositories. On resume those 20 skipped assets still need to count
        as processed. A post-upgrade restart already has those counters on the job row, so counting
        skipped assets again would inflate progress.
        """

        if resume_counts_are_persisted:
            return processed_count, failed_system_count

        return processed_count + 1, failed_system_count + (1 if previously_failed else 0)

    def _normalize_datetime(self, value: datetime | None) -> datetime | None:
        """Normalize database datetimes so SQLite and PostgreSQL comparisons behave the same."""

        if value is None:
            return None
        if value.tzinfo is None:
            return value.replace(tzinfo=UTC)
        return value.astimezone(UTC)

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
        except Exception as error:
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

        effective_details = dict(details)
        try:
            if scanner_name == "repository_asset_scan":
                effective_details["commit_sha"] = self.repository_scanner.get_checkout_commit_sha(
                    Path(repository.local_path)
                )
            alerts_created = scan_callable()
            record_scan_result(
                session,
                repository_id=repository.id,
                scanner_name=scanner_name,
                status="success",
                findings_count=alerts_created,
                details=effective_details,
            )
            session.commit()
            return alerts_created, 0
        except ScanCanceledError:
            session.rollback()
            raise
        except Exception as error:
            session.rollback()
            LOGGER.exception(
                "Asset scan failed",
                extra={"repository": repository.full_name, **effective_details},
            )
            record_scan_result(
                session,
                repository_id=repository.id,
                scanner_name=scanner_name,
                status="error",
                findings_count=0,
                details={**effective_details, "error": str(error)},
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
