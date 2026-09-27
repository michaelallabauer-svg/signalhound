import json
import ipaddress
import shutil
import subprocess
import xml.etree.ElementTree as ET
from typing import Any

from app.scanners.base import NormalizedScannerResult, PreparedScannerJob, ScannerAdapter, ScannerTarget


class ExternalToolScannerAdapter(ScannerAdapter):
    binary_name: str
    execution_supported = True
    return_stderr_when_stdout_empty = False

    def execute(self, prepared_job: PreparedScannerJob) -> str:
        if not prepared_job.command:
            raise RuntimeError("Scanner command is not configured")

        binary_path = shutil.which(prepared_job.command[0])
        if binary_path is None:
            raise FileNotFoundError(f"Required scanner binary not found: {prepared_job.command[0]}")

        command = [binary_path, *prepared_job.command[1:]]
        try:
            completed = subprocess.run(
                command,
                capture_output=True,
                check=False,
                text=True,
                timeout=prepared_job.timeout_seconds,
            )
        except subprocess.TimeoutExpired as exc:
            raise RuntimeError(
                f"{prepared_job.adapter_name} scan timed out after {prepared_job.timeout_seconds} seconds for "
                f"{prepared_job.target}"
            ) from exc
        if completed.returncode != 0:
            stderr = completed.stderr.strip()
            raise RuntimeError(stderr or f"Scanner exited with code {completed.returncode}")
        if completed.stdout or not self.return_stderr_when_stdout_empty:
            return completed.stdout
        return completed.stderr


class PlaceholderScannerAdapter(ScannerAdapter):
    display_name = "Placeholder scanner"
    supported_target_notes = "Framework placeholder only; execution is not implemented for this adapter yet."
    execution_supported = False

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
    binary_name = "nmap"
    supported_target_notes = "Service discovery adapter for a single scope-approved host or CIDR target."
    execution_supported = True

    def prepare_job(self, target: ScannerTarget) -> PreparedScannerJob:
        self.validate_target(target)
        command = [
            "nmap",
            "-oX",
            "-",
            "-n",
            "--max-retries",
            "1",
            "--host-timeout",
            "240s",
            "-sV",
            "--version-intensity",
            "2",
            "-p",
            "80,443",
            target.value,
        ]
        if not _is_private_ip_target(target.value):
            command.insert(3, "-Pn")
        return PreparedScannerJob(
            adapter_name=self.name,
            target=target.value,
            command=command,
            config={
                "adapter": self.name,
                "target": target.value,
                "scope_id": target.scope_id,
                "organization_id": target.organization_id,
                "command": command,
                "output_format": "xml",
                "profile": "web_service_discovery",
            },
        )

    def execute(self, prepared_job: PreparedScannerJob) -> str:
        return ExternalToolScannerAdapter.execute(self, prepared_job)

    def parse_result(self, raw_output: str) -> Any:
        return ET.fromstring(raw_output)

    def normalize_result(self, parsed_result: Any) -> NormalizedScannerResult:
        assets: list[dict[str, Any]] = []
        services: list[dict[str, Any]] = []
        require_open_service = _is_private_cidr_nmaprun(parsed_result)

        for host in parsed_result.findall("host"):
            address = host.find("address")
            if address is None:
                continue
            asset_value = address.attrib.get("addr")
            address_type = address.attrib.get("addrtype")
            if not asset_value:
                continue

            asset_type = "IP" if address_type in {"ipv4", "ipv6"} else "HOST"
            host_services: list[dict[str, Any]] = []
            for port in host.findall("./ports/port"):
                protocol = port.attrib.get("protocol", "").upper()
                port_id = port.attrib.get("portid")
                state = port.find("state")
                if state is not None and state.attrib.get("state") != "open":
                    continue
                service = port.find("service")
                if protocol not in {"TCP", "UDP"} or port_id is None:
                    continue
                host_services.append(
                    {
                        "asset_type": asset_type,
                        "asset_value": asset_value,
                        "protocol": protocol,
                        "port": int(port_id),
                        "name": service.attrib.get("name") if service is not None else None,
                        "source": self.name,
                        "metadata": {
                            "product": service.attrib.get("product") if service is not None else None,
                            "version": service.attrib.get("version") if service is not None else None,
                        },
                    }
                )

            status = host.find("status")
            status_state = status.attrib.get("state") if status is not None else None
            status_reason = status.attrib.get("reason") if status is not None else None
            if status_state != "up":
                continue
            if require_open_service and not host_services:
                continue
            if status_reason in {"user-set", "unknown-response"} and not host_services:
                continue

            assets.append(
                {
                    "asset_type": asset_type,
                    "value": asset_value,
                    "source": self.name,
                    "metadata": {"addrtype": address_type, "status_reason": status_reason},
                }
            )
            services.extend(host_services)

        return NormalizedScannerResult(assets=assets, services=services, metadata={"adapter": self.name})


def _is_private_ip_target(value: str) -> bool:
    try:
        if "/" in value:
            network = ipaddress.ip_network(value, strict=False)
            return network.is_private
        return ipaddress.ip_address(value).is_private
    except ValueError:
        return False


def _is_private_cidr_nmaprun(parsed_result: Any) -> bool:
    args = str(parsed_result.attrib.get("args", ""))
    for token in args.split():
        try:
            if "/" in token and ipaddress.ip_network(token, strict=False).is_private:
                return True
        except ValueError:
            continue
    return False


class AmassAdapter(PlaceholderScannerAdapter):
    name = "amass"
    display_name = "OWASP Amass"
    binary_name = "amass"
    supported_target_notes = "External hostname discovery adapter for a single scope-approved domain target."
    execution_supported = True

    def prepare_job(self, target: ScannerTarget) -> PreparedScannerJob:
        self.validate_target(target)
        command = ["amass", "enum", "-nocolor", "-timeout", "1", "-d", target.value]
        return PreparedScannerJob(
            adapter_name=self.name,
            target=target.value,
            command=command,
            config={
                "adapter": self.name,
                "target": target.value,
                "scope_id": target.scope_id,
                "organization_id": target.organization_id,
                "command": command,
                "output_format": "text",
                "profile": "passive_subdomain_discovery",
            },
        )

    def execute(self, prepared_job: PreparedScannerJob) -> str:
        return ExternalToolScannerAdapter.execute(self, prepared_job)

    def parse_result(self, raw_output: str) -> Any:
        records = []
        for line in raw_output.splitlines():
            value = line.strip().lower().rstrip(".")
            if not value:
                continue
            if value.startswith("{"):
                records.append(json.loads(value))
                continue
            if " " in value or value.startswith(("[", "usage:", "-")):
                continue
            records.append({"name": value})
        return records

    def normalize_result(self, parsed_result: Any) -> NormalizedScannerResult:
        assets: list[dict[str, Any]] = []
        seen: set[str] = set()
        for record in parsed_result:
            name = str(record.get("name", "")).strip().lower().rstrip(".")
            if not name or name in seen:
                continue
            seen.add(name)
            assets.append(
                {
                    "asset_type": "SUBDOMAIN" if "." in name else "HOST",
                    "value": name,
                    "source": self.name,
                    "metadata": {
                        "domain": record.get("domain"),
                        "addresses": record.get("addresses", []),
                        "tag": record.get("tag"),
                    },
                }
            )
        return NormalizedScannerResult(assets=assets, metadata={"adapter": self.name})


class NucleiAdapter(PlaceholderScannerAdapter):
    name = "nuclei"
    display_name = "ProjectDiscovery Nuclei"
    binary_name = "nuclei"
    supported_target_notes = "External finding discovery adapter for a single scope-approved target."
    execution_supported = True
    return_stderr_when_stdout_empty = True

    def prepare_job(self, target: ScannerTarget) -> PreparedScannerJob:
        self.validate_target(target)
        target_url = f"http://{target.value}"
        command = [
            "nuclei",
            "-jsonl",
            "-no-color",
            "-disable-update-check",
            "-ni",
            "-follow-redirects",
            "-max-redirects",
            "3",
            "-target",
            target_url,
            "-templates",
            "http/technologies/php-detect.yaml",
            "-templates",
            "http/technologies/wordpress-detect.yaml",
            "-templates",
            "http/technologies/default-apache-miracle.yaml",
            "-templates",
            "http/exposed-panels/wordpress-login.yaml",
            "-templates",
            "http/misconfiguration/xss-deprecated-header.yaml",
            "-timeout",
            "8",
            "-retries",
            "1",
            "-concurrency",
            "5",
            "-rate-limit",
            "10",
        ]
        return PreparedScannerJob(
            adapter_name=self.name,
            target=target.value,
            command=command,
            config={
                "adapter": self.name,
                "target": target.value,
                "scope_id": target.scope_id,
                "organization_id": target.organization_id,
                "command": command,
                "output_format": "jsonl",
                "profile": "web_finding_discovery",
            },
        )

    def execute(self, prepared_job: PreparedScannerJob) -> str:
        return ExternalToolScannerAdapter.execute(self, prepared_job)

    def parse_result(self, raw_output: str) -> Any:
        records = []
        for line in raw_output.splitlines():
            if line.strip().startswith("{"):
                records.append(json.loads(line))
        return records

    def normalize_result(self, parsed_result: Any) -> NormalizedScannerResult:
        findings: list[dict[str, Any]] = []
        for record in parsed_result:
            info = record.get("info", {})
            severity = str(info.get("severity", "info")).upper()
            if severity == "UNKNOWN":
                severity = "INFO"
            host = str(record.get("host") or record.get("matched-at") or record.get("ip") or "").strip().lower()
            host = host.rstrip("/")
            if "://" in host:
                host = host.split("://", 1)[1]
            host = host.split("/", 1)[0].rstrip(".")
            if not host:
                continue

            findings.append(
                {
                    "asset_type": "HOST",
                    "asset_value": host,
                    "title": str(info.get("name") or record.get("template-id") or "Nuclei finding"),
                    "description": info.get("description"),
                    "severity": severity if severity in {"INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"} else "INFO",
                    "source": self.name,
                    "external_reference": record.get("template-id"),
                    "remediation": info.get("remediation"),
                    "evidence": {
                        "matched_at": record.get("matched-at"),
                        "type": record.get("type"),
                        "matcher_name": record.get("matcher-name"),
                        "template_id": record.get("template-id"),
                        "metadata": info.get("metadata", {}),
                    },
                }
            )
        return NormalizedScannerResult(findings=findings, metadata={"adapter": self.name})
