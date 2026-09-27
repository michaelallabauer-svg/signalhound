from typing import Any

from app.scanners.base import NormalizedScannerResult, PreparedScannerJob, ScannerAdapter, ScannerTarget


class PlaceholderScannerAdapter(ScannerAdapter):
    display_name = "Placeholder scanner"
    supported_target_notes = "Framework placeholder only; execution is not implemented in Epic 4."

    def validate_target(self, target: ScannerTarget) -> None:
        if not target.value.strip():
            raise ValueError("Scanner target must not be empty")

    def prepare_job(self, target: ScannerTarget) -> PreparedScannerJob:
        self.validate_target(target)
        return PreparedScannerJob(
            adapter_name=self.name,
            target=target.value,
            config={
                "adapter": self.name,
                "target": target.value,
                "scope_id": target.scope_id,
                "organization_id": target.organization_id,
                "execution": "not_implemented",
            },
        )

    def execute(self, prepared_job: PreparedScannerJob) -> str:
        raise NotImplementedError("Scanner execution is not implemented in Epic 4")

    def parse_result(self, raw_output: str) -> Any:
        raise NotImplementedError("Scanner result parsing is not implemented in Epic 4")

    def normalize_result(self, parsed_result: Any) -> NormalizedScannerResult:
        raise NotImplementedError("Scanner result normalization is not implemented in Epic 4")


class NmapAdapter(PlaceholderScannerAdapter):
    name = "nmap"
    display_name = "Nmap"
    supported_target_notes = "Future service discovery adapter; execution is intentionally deferred."


class AmassAdapter(PlaceholderScannerAdapter):
    name = "amass"
    display_name = "OWASP Amass"
    supported_target_notes = "Future external asset discovery adapter; execution is intentionally deferred."


class NucleiAdapter(PlaceholderScannerAdapter):
    name = "nuclei"
    display_name = "ProjectDiscovery Nuclei"
    supported_target_notes = "Future finding discovery adapter; execution is intentionally deferred."

