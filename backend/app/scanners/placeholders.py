import json
import html
import http.client
import ipaddress
import shutil
import socket
import ssl
import subprocess
import xml.etree.ElementTree as ET
from typing import Any

from app.scanners.base import NormalizedScannerResult, PreparedScannerJob, ScannerAdapter, ScannerTarget

INTERNAL_WEB_SERVICE_PORTS = "80,443,3000,5000,7000,8000,8080,8443,9000,9443"


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
        is_private_target = _is_private_ip_target(target.value)
        scanned_ports = INTERNAL_WEB_SERVICE_PORTS if is_private_target else "80,443"
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
            scanned_ports,
            target.value,
        ]
        if not is_private_target:
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
                "scanned_ports": scanned_ports,
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
                            "cpes": [node.text for node in service.findall("cpe") if node.text] if service is not None else [],
                        },
                    }
                )

            status = host.find("status")
            status_state = status.attrib.get("state") if status is not None else None
            status_reason = status.attrib.get("reason") if status is not None else None
            if status_state != "up":
                continue
            if require_open_service and not host_services and not _is_reliable_host_discovery_reason(status_reason):
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


def _is_reliable_host_discovery_reason(reason: str | None) -> bool:
    if reason is None:
        return False
    if reason in {"reset", "user-set", "unknown-response", "no-response"}:
        return False
    return True


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
    supported_target_notes = "Limited web finding checks for one scope-approved host, not a subnet. Discover LAN hosts/services with Nmap first."
    execution_supported = True
    return_stderr_when_stdout_empty = True

    def validate_target(self, target: ScannerTarget) -> None:
        super().validate_target(target)
        if "/" in target.value:
            raise ValueError(
                "Nuclei requires a single host, not a CIDR/subnet or URL. "
                "Run Internal IT quick check (Nmap) first, then prepare web checks for discovered hosts."
            )

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
                        "classification": info.get("classification", {}),
                    },
                }
            )
        return NormalizedScannerResult(findings=findings, metadata={"adapter": self.name})


class WebFingerprintAdapter(PlaceholderScannerAdapter):
    name = "web_fingerprint"
    display_name = "Web fingerprint"
    supported_target_notes = "Conservative HTTP(S) metadata collection for a single scope-approved web host."
    execution_supported = True

    def prepare_job(self, target: ScannerTarget) -> PreparedScannerJob:
        self.validate_target(target)
        command = ["web_fingerprint", target.value]
        endpoints = [
            {"scheme": "http", "host": target.value, "port": 80},
            {"scheme": "https", "host": target.value, "port": 443},
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
                "output_format": "json",
                "profile": "web_fingerprint",
                "endpoints": endpoints,
            },
        )

    def execute(self, prepared_job: PreparedScannerJob) -> str:
        target = str(prepared_job.target).strip().lower().rstrip(".")
        endpoints = prepared_job.config.get("endpoints", [])
        if not isinstance(endpoints, list):
            endpoints = []
        if not endpoints:
            endpoints = [{"scheme": "http", "host": target, "port": 80}, {"scheme": "https", "host": target, "port": 443}]

        results = []
        for endpoint in endpoints[:8]:
            if not isinstance(endpoint, dict):
                continue
            host = str(endpoint.get("host", target)).strip().lower().rstrip(".")
            if host != target:
                continue
            scheme = str(endpoint.get("scheme", "http")).lower()
            if scheme not in {"http", "https"}:
                continue
            try:
                port = int(endpoint.get("port", 443 if scheme == "https" else 80))
            except (TypeError, ValueError):
                continue
            if port < 1 or port > 65535:
                continue
            results.append(_fingerprint_web_endpoint(host=host, scheme=scheme, port=port))
        return json.dumps({"target": target, "results": results}, sort_keys=True)

    def parse_result(self, raw_output: str) -> Any:
        return json.loads(raw_output)

    def normalize_result(self, parsed_result: Any) -> NormalizedScannerResult:
        target = str(parsed_result.get("target", "")).strip().lower().rstrip(".")
        services: list[dict[str, Any]] = []
        for result in parsed_result.get("results", []):
            if not isinstance(result, dict):
                continue
            try:
                port = int(result.get("port"))
            except (TypeError, ValueError):
                continue
            scheme = str(result.get("scheme", "http")).lower()
            service_name = "https" if scheme == "https" else "http"
            services.append(
                {
                    "asset_type": "IP" if _looks_like_ip(target) else "HOST",
                    "asset_value": target,
                    "protocol": "TCP",
                    "port": port,
                    "name": service_name,
                    "source": self.name,
                    "metadata": {
                        "url": result.get("url"),
                        "http_status": result.get("http_status"),
                        "title": result.get("title"),
                        "server": result.get("server"),
                        "content_type": result.get("content_type"),
                        "redirect_location": result.get("redirect_location"),
                        "tls_subject": result.get("tls_subject"),
                        "tls_issuer": result.get("tls_issuer"),
                        "tls_not_after": result.get("tls_not_after"),
                        "error": result.get("error"),
                    },
                }
            )
        return NormalizedScannerResult(services=services, metadata={"adapter": self.name})


def _fingerprint_web_endpoint(*, host: str, scheme: str, port: int) -> dict[str, Any]:
    url = f"{scheme}://{host}" if port in {80, 443} else f"{scheme}://{host}:{port}"
    result: dict[str, Any] = {"url": url, "host": host, "scheme": scheme, "port": port}
    try:
        if scheme == "https":
            connection = http.client.HTTPSConnection(
                host,
                port=port,
                timeout=4,
                context=ssl._create_unverified_context(),
            )
        else:
            connection = http.client.HTTPConnection(host, port=port, timeout=4)
        connection.request("GET", "/", headers={"User-Agent": "SignalHound-WebFingerprint/1.0"})
        response = connection.getresponse()
        body = response.read(65536)
        headers = {key.lower(): value for key, value in response.getheaders()}
        result.update(
            {
                "http_status": response.status,
                "server": headers.get("server"),
                "content_type": headers.get("content-type"),
                "redirect_location": headers.get("location"),
                "title": _extract_html_title(body, headers.get("content-type")),
            }
        )
        connection.close()
        if scheme == "https":
            result.update(_read_tls_certificate(host=host, port=port))
    except (OSError, http.client.HTTPException, ssl.SSLError, socket.timeout) as exc:
        result["error"] = str(exc)
    return result


def _extract_html_title(body: bytes, content_type: str | None) -> str | None:
    if content_type and "html" not in content_type.lower():
        return None
    try:
        text = body.decode("utf-8", errors="ignore")
    except ValueError:
        return None
    lower = text.lower()
    start = lower.find("<title")
    if start == -1:
        return None
    start = lower.find(">", start)
    end = lower.find("</title>", start)
    if start == -1 or end == -1:
        return None
    title = html.unescape(text[start + 1 : end]).strip()
    return " ".join(title.split())[:240] or None


def _read_tls_certificate(*, host: str, port: int) -> dict[str, Any]:
    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    with socket.create_connection((host, port), timeout=4) as sock:
        with context.wrap_socket(sock, server_hostname=host) as tls:
            cert = tls.getpeercert()
    return {
        "tls_subject": _certificate_name(cert.get("subject", ())),
        "tls_issuer": _certificate_name(cert.get("issuer", ())),
        "tls_not_after": cert.get("notAfter"),
    }


def _certificate_name(parts: Any) -> str | None:
    names: list[str] = []
    for group in parts:
        for key, value in group:
            if key in {"commonName", "organizationName"}:
                names.append(str(value))
    return ", ".join(names) or None


def _looks_like_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False
