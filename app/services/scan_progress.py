"""
Purpose: Translate real scan stages into stable percentage and operator-log updates.
Input/Output: Accepts optional progress callbacks and emits validated `ScanProgressUpdate` values.
Important invariants: Progress is monotonic within the asset phase, remains between 0 and 100, and
must never make the security scan fail when persistence or UI reporting is unavailable.
Debugging: Set `LOG_LEVEL=debug` and inspect callback failures tagged with the progress phase.
"""

from __future__ import annotations

import logging
from collections.abc import Callable
from dataclasses import dataclass

from app.models.schemas import ScanProgressUpdate

LOGGER = logging.getLogger(__name__)
ScanProgressCallback = Callable[[ScanProgressUpdate], None]


@dataclass
class ScanProgressReporter:
    """Calculate estate-wide progress from inventory and per-asset scan stages."""

    callback: ScanProgressCallback | None = None
    total_assets: int = 0
    completed_assets: int = 0

    def emit(
        self,
        *,
        phase: str,
        message: str,
        percent: float,
        level: str = "info",
        current: int | None = None,
        total: int | None = None,
    ) -> None:
        """Deliver one validated update without coupling scan success to progress persistence."""

        if self.callback is None:
            return
        update = ScanProgressUpdate(
            phase=phase,
            message=message,
            level=level,
            current=self.completed_assets if current is None else current,
            total=self.total_assets if total is None else total,
            percent=max(0.0, min(100.0, percent)),
        )
        try:
            self.callback(update)
        except Exception:
            LOGGER.exception(
                "Manual scan progress callback failed",
                extra={"progress_phase": phase},
            )

    def configure_assets(self, total_assets: int) -> None:
        """Set the work denominator after all inventory sources have completed."""

        self.total_assets = max(0, total_assets)
        self.completed_assets = 0
        self.emit(
            phase="scan",
            message=f"Inventar vollständig: {self.total_assets} Systeme werden geprüft.",
            percent=10.0,
            current=0,
        )

    def asset_step(
        self,
        *,
        phase: str,
        asset_name: str,
        message: str,
        fraction: float,
        level: str = "info",
    ) -> None:
        """Emit progress inside the currently active asset using its fractional completion."""

        if self.total_assets <= 0:
            percent = 96.0
            current = 0
        else:
            bounded_fraction = max(0.0, min(1.0, fraction))
            percent = 10.0 + ((self.completed_assets + bounded_fraction) / self.total_assets) * 86.0
            current = min(self.completed_assets + 1, self.total_assets)
        self.emit(
            phase=phase,
            message=f"{asset_name}: {message}",
            percent=min(percent, 96.0),
            level=level,
            current=current,
        )

    def finish_asset(self, *, asset_name: str, failed: bool) -> None:
        """Advance the estate-wide counter after a guarded asset scan returns."""

        self.completed_assets = min(self.completed_assets + 1, self.total_assets)
        self.emit(
            phase="asset",
            message=(f"{asset_name}: mit Warnung abgeschlossen." if failed else f"{asset_name}: abgeschlossen."),
            percent=(96.0 if self.total_assets <= 0 else 10.0 + (self.completed_assets / self.total_assets) * 86.0),
            level="warning" if failed else "info",
            current=self.completed_assets,
        )
