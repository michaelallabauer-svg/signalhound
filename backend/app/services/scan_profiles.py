from dataclasses import dataclass


@dataclass(frozen=True)
class ScanProfile:
    name: str
    display_name: str
    description: str
    scan_zone: str
    adapter_sequence: tuple[str, ...]


SCAN_PROFILES: dict[str, ScanProfile] = {
    "external_quick": ScanProfile(
        name="external_quick",
        display_name="External quick check",
        description="Runs web service discovery and a small non-intrusive Nuclei profile against one scoped target.",
        scan_zone="EXTERNAL",
        adapter_sequence=("nmap", "nuclei"),
    ),
    "external_discovery": ScanProfile(
        name="external_discovery",
        display_name="External discovery",
        description="Runs Amass discovery, web service discovery, and a small non-intrusive Nuclei profile.",
        scan_zone="EXTERNAL",
        adapter_sequence=("amass", "nmap", "nuclei"),
    ),
    "internal_it_quick": ScanProfile(
        name="internal_it_quick",
        display_name="Internal IT quick check",
        description="Runs conservative Nmap service discovery against one explicitly scoped internal host or CIDR.",
        scan_zone="INTERNAL_IT",
        adapter_sequence=("nmap",),
    ),
}


def list_scan_profiles() -> list[ScanProfile]:
    return list(SCAN_PROFILES.values())


def get_scan_profile(name: str) -> ScanProfile | None:
    return SCAN_PROFILES.get(name)
