from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any


@dataclass(frozen=True)
class ScannerTarget:
    value: str
    scope_id: int
    organization_id: int


@dataclass(frozen=True)
class PreparedScannerJob:
    adapter_name: str
    target: str
    config: dict[str, Any]
    command: list[str] = field(default_factory=list)
    timeout_seconds: int | None = None


@dataclass(frozen=True)
class NormalizedScannerResult:
    assets: list[dict[str, Any]] = field(default_factory=list)
    services: list[dict[str, Any]] = field(default_factory=list)
    findings: list[dict[str, Any]] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)


class ScannerAdapter(ABC):
    name: str
    display_name: str
    supported_target_notes: str
    execution_supported: bool = False

    @abstractmethod
    def validate_target(self, target: ScannerTarget) -> None:
        """Validate adapter-specific target syntax without expanding scope."""

    @abstractmethod
    def prepare_job(self, target: ScannerTarget) -> PreparedScannerJob:
        """Prepare an execution plan. This must not execute external tools."""

    @abstractmethod
    def execute(self, prepared_job: PreparedScannerJob) -> str:
        """Execute the external tool and return raw output."""

    @abstractmethod
    def parse_result(self, raw_output: str) -> Any:
        """Parse raw scanner output into adapter-specific structured data."""

    @abstractmethod
    def normalize_result(self, parsed_result: Any) -> NormalizedScannerResult:
        """Normalize adapter-specific parsed data into platform result objects."""
