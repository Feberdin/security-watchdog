"""
Purpose: Persist repositories, dependencies, vulnerabilities, articles, and alerts in PostgreSQL.
Input/Output: SQLAlchemy ORM models map security-watchdog runtime data to relational tables.
Important invariants: Natural identifiers should stay unique where possible so recurring scans can
upsert safely; JSON columns store raw scan context without losing vendor-specific details.
Debugging: Use `SELECT` queries against these tables when a dashboard card or API response looks
wrong; most correlation bugs are visible by inspecting foreign keys and timestamps here.
"""

from __future__ import annotations

from datetime import UTC, datetime
from enum import StrEnum

from sqlalchemy import JSON, Boolean, DateTime, Float, ForeignKey, Integer, String, Text, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base


def utcnow() -> datetime:
    """Return timezone-aware UTC timestamps for default columns."""

    return datetime.now(UTC)


class Severity(StrEnum):
    """Normalized severity values for vulnerabilities and alerts."""

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class AlertStatus(StrEnum):
    """Lifecycle states for operator-facing alerts."""

    OPEN = "open"
    ACKNOWLEDGED = "acknowledged"
    RESOLVED = "resolved"


class Repository(Base):
    """Tracked GitHub repository metadata and local checkout status."""

    __tablename__ = "repositories"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    source_type: Mapped[str] = mapped_column(String(50), default="github", index=True)
    github_id: Mapped[int | None] = mapped_column(Integer, unique=True, index=True, nullable=True)
    owner: Mapped[str] = mapped_column(String(255), index=True)
    name: Mapped[str] = mapped_column(String(255), index=True)
    full_name: Mapped[str] = mapped_column(String(255), unique=True, index=True)
    clone_url: Mapped[str | None] = mapped_column(String(1024), nullable=True)
    default_branch: Mapped[str] = mapped_column(String(255), default="")
    local_path: Mapped[str] = mapped_column(String(1024), default="")
    archived: Mapped[bool] = mapped_column(Boolean, default=False)
    last_scanned_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    risk_score: Mapped[float] = mapped_column(Float, default=0.0)
    metadata_json: Mapped[dict] = mapped_column("metadata", JSON, default=dict)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, onupdate=utcnow
    )

    dependencies: Mapped[list["Dependency"]] = relationship(back_populates="repository")
    scan_results: Mapped[list["ScanResult"]] = relationship(back_populates="repository")
    alerts: Mapped[list["Alert"]] = relationship(back_populates="repository")


class Dependency(Base):
    """A dependency discovered in one repository manifest or Docker definition."""

    __tablename__ = "dependencies"
    __table_args__ = (
        UniqueConstraint(
            "repository_id",
            "manifest_path",
            "package_name",
            "version",
            "ecosystem",
            name="uq_dependency_repository_manifest_package_version",
        ),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    repository_id: Mapped[int] = mapped_column(ForeignKey("repositories.id"), index=True)
    manifest_path: Mapped[str] = mapped_column(String(1024))
    package_name: Mapped[str] = mapped_column(String(255), index=True)
    version: Mapped[str] = mapped_column(String(255), index=True)
    ecosystem: Mapped[str] = mapped_column(String(100), index=True)
    group_name: Mapped[str | None] = mapped_column(String(255), nullable=True)
    direct_dependency: Mapped[bool] = mapped_column(Boolean, default=True)
    metadata_json: Mapped[dict] = mapped_column("metadata", JSON, default=dict)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, onupdate=utcnow
    )

    repository: Mapped["Repository"] = relationship(back_populates="dependencies")
    vulnerability_links: Mapped[list["DependencyVulnerability"]] = relationship(
        back_populates="dependency",
        cascade="all, delete-orphan",
    )


class Vulnerability(Base):
    """Normalized vulnerability or malicious package record from multiple sources."""

    __tablename__ = "vulnerabilities"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    source: Mapped[str] = mapped_column(String(100), index=True)
    source_identifier: Mapped[str] = mapped_column(String(255), unique=True, index=True)
    package_name: Mapped[str] = mapped_column(String(255), index=True)
    ecosystem: Mapped[str] = mapped_column(String(100), index=True)
    summary: Mapped[str] = mapped_column(Text)
    severity: Mapped[str] = mapped_column(String(20), default=Severity.MEDIUM.value)
    cvss_score: Mapped[float | None] = mapped_column(Float, nullable=True)
    kev: Mapped[bool] = mapped_column(Boolean, default=False)
    exploit_available: Mapped[bool] = mapped_column(Boolean, default=False)
    malicious_package: Mapped[bool] = mapped_column(Boolean, default=False)
    affected_versions: Mapped[list[str]] = mapped_column(JSON, default=list)
    reference_urls: Mapped[list[str]] = mapped_column(JSON, default=list)
    raw_payload: Mapped[dict] = mapped_column(JSON, default=dict)
    published_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, onupdate=utcnow
    )

    dependency_links: Mapped[list["DependencyVulnerability"]] = relationship(
        back_populates="vulnerability",
        cascade="all, delete-orphan",
    )


class DependencyVulnerability(Base):
    """Link table that captures which dependency matched which vulnerability and why."""

    __tablename__ = "dependency_vulnerabilities"
    __table_args__ = (
        UniqueConstraint("dependency_id", "vulnerability_id", name="uq_dependency_vulnerability"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    dependency_id: Mapped[int] = mapped_column(ForeignKey("dependencies.id"), index=True)
    vulnerability_id: Mapped[int] = mapped_column(ForeignKey("vulnerabilities.id"), index=True)
    risk_score: Mapped[float] = mapped_column(Float, default=0.0)
    match_reason: Mapped[str] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)

    dependency: Mapped["Dependency"] = relationship(back_populates="vulnerability_links")
    vulnerability: Mapped["Vulnerability"] = relationship(back_populates="dependency_links")


class ScanResult(Base):
    """High-level result for one scan stage against one repository."""

    __tablename__ = "scan_results"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    repository_id: Mapped[int | None] = mapped_column(
        ForeignKey("repositories.id"), index=True, nullable=True
    )
    scanner_name: Mapped[str] = mapped_column(String(100), index=True)
    status: Mapped[str] = mapped_column(String(20), default="success")
    findings_count: Mapped[int] = mapped_column(Integer, default=0)
    started_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    details_json: Mapped[dict] = mapped_column("details", JSON, default=dict)

    repository: Mapped["Repository | None"] = relationship(back_populates="scan_results")


class ThreatArticle(Base):
    """Normalized threat intelligence article from RSS, Reddit, HN, or GitHub issues."""

    __tablename__ = "threat_articles"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    source_type: Mapped[str] = mapped_column(String(100), index=True)
    title: Mapped[str] = mapped_column(String(500))
    source_url: Mapped[str] = mapped_column(String(1024), unique=True)
    published_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    content_hash: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    raw_content: Mapped[str] = mapped_column(Text)
    normalized_text: Mapped[str] = mapped_column(Text)
    tags: Mapped[list[str]] = mapped_column(JSON, default=list)
    processed_by_ai: Mapped[bool] = mapped_column(Boolean, default=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class AIExtractedThreat(Base):
    """Structured threat observations extracted from unstructured content by AI."""

    __tablename__ = "ai_extracted_threats"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    threat_article_id: Mapped[int] = mapped_column(ForeignKey("threat_articles.id"), index=True)
    package_name: Mapped[str] = mapped_column(String(255), index=True)
    ecosystem: Mapped[str] = mapped_column(String(100), index=True)
    affected_versions: Mapped[list[str]] = mapped_column(JSON, default=list)
    attack_type: Mapped[str] = mapped_column(String(100))
    confidence_score: Mapped[float] = mapped_column(Float, default=0.0)
    summary: Mapped[str] = mapped_column(Text, default="")
    source_url: Mapped[str] = mapped_column(String(1024))
    raw_payload: Mapped[dict] = mapped_column(JSON, default=dict)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class Alert(Base):
    """Operator-facing alert created from correlated vulnerabilities or secret findings."""

    __tablename__ = "alerts"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    repository_id: Mapped[int | None] = mapped_column(ForeignKey("repositories.id"), nullable=True)
    title: Mapped[str] = mapped_column(String(500))
    description: Mapped[str] = mapped_column(Text)
    severity: Mapped[str] = mapped_column(String(20), default=Severity.MEDIUM.value)
    risk_score: Mapped[float] = mapped_column(Float, default=0.0)
    fingerprint: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    status: Mapped[str] = mapped_column(String(20), default=AlertStatus.OPEN.value)
    source_type: Mapped[str] = mapped_column(String(100))
    metadata_json: Mapped[dict] = mapped_column("metadata", JSON, default=dict)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, onupdate=utcnow
    )

    repository: Mapped[Repository | None] = relationship(back_populates="alerts")
