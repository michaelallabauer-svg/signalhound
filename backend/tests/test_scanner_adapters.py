from app.scanners.base import ScannerTarget
from app.scanners.placeholders import AmassAdapter, NmapAdapter, NucleiAdapter, WebFingerprintAdapter


def test_nmap_adapter_parses_open_services() -> None:
    raw_output = """
    <nmaprun>
      <host>
        <status state="up"/>
        <address addr="203.0.113.10" addrtype="ipv4"/>
        <ports>
          <port protocol="tcp" portid="443">
            <state state="open"/>
            <service name="https" product="nginx" version="1.25"/>
          </port>
          <port protocol="tcp" portid="22">
            <state state="closed"/>
            <service name="ssh"/>
          </port>
        </ports>
      </host>
    </nmaprun>
    """

    adapter = NmapAdapter()
    parsed = adapter.parse_result(raw_output)
    normalized = adapter.normalize_result(parsed)

    assert normalized.assets == [
        {
            "asset_type": "IP",
            "value": "203.0.113.10",
            "source": "nmap",
            "metadata": {"addrtype": "ipv4", "status_reason": None},
        }
    ]
    assert normalized.services == [
        {
            "asset_type": "IP",
            "asset_value": "203.0.113.10",
            "protocol": "TCP",
            "port": 443,
            "name": "https",
            "source": "nmap",
            "metadata": {"product": "nginx", "version": "1.25", "cpes": []},
        }
    ]


def test_nmap_adapter_keeps_external_pn_but_uses_discovery_for_private_targets() -> None:
    adapter = NmapAdapter()

    external = adapter.prepare_job(ScannerTarget(value="www.example.com", scope_id=1, organization_id=1))
    internal = adapter.prepare_job(ScannerTarget(value="192.168.1.0/24", scope_id=1, organization_id=1))

    assert "-Pn" in external.command
    assert "-Pn" not in internal.command
    assert external.config["scanned_ports"] == "80,443"
    assert internal.config["scanned_ports"] == "80,443,3000,5000,7000,8000,8080,8443,9000,9443"


def test_nmap_adapter_ignores_pn_user_set_hosts_without_open_services() -> None:
    raw_output = """
    <nmaprun>
      <host>
        <status state="up" reason="user-set"/>
        <address addr="192.168.1.42" addrtype="ipv4"/>
        <ports>
          <port protocol="tcp" portid="443">
            <state state="closed"/>
          </port>
        </ports>
      </host>
      <host>
        <status state="up" reason="syn-ack"/>
        <address addr="192.168.1.43" addrtype="ipv4"/>
      </host>
      <host>
        <status state="down" reason="no-response"/>
        <address addr="192.168.1.44" addrtype="ipv4"/>
      </host>
    </nmaprun>
    """

    adapter = NmapAdapter()
    normalized = adapter.normalize_result(adapter.parse_result(raw_output))

    assert [asset["value"] for asset in normalized.assets] == ["192.168.1.43"]


def test_nmap_adapter_ignores_unknown_response_hosts_without_open_services() -> None:
    raw_output = """
    <nmaprun>
      <host>
        <status state="up" reason="unknown-response"/>
        <address addr="192.168.1.42" addrtype="ipv4"/>
        <ports>
          <port protocol="tcp" portid="443">
            <state state="filtered"/>
          </port>
        </ports>
      </host>
      <host>
        <status state="up" reason="unknown-response"/>
        <address addr="192.168.1.43" addrtype="ipv4"/>
        <ports>
          <port protocol="tcp" portid="443">
            <state state="open"/>
            <service name="https"/>
          </port>
        </ports>
      </host>
    </nmaprun>
    """

    adapter = NmapAdapter()
    normalized = adapter.normalize_result(adapter.parse_result(raw_output))

    assert [asset["value"] for asset in normalized.assets] == ["192.168.1.43"]
    assert [service["asset_value"] for service in normalized.services] == ["192.168.1.43"]


def test_nmap_adapter_keeps_reliable_discovery_hosts_for_private_cidr() -> None:
    raw_output = """
    <nmaprun args="/usr/bin/nmap -oX - -n -p 80,443 192.168.0.0/24">
      <host>
        <status state="up" reason="reset"/>
        <address addr="192.168.0.42" addrtype="ipv4"/>
        <ports>
          <port protocol="tcp" portid="443">
            <state state="closed"/>
          </port>
        </ports>
      </host>
      <host>
        <status state="up" reason="syn-ack"/>
        <address addr="192.168.0.43" addrtype="ipv4"/>
        <ports>
          <port protocol="tcp" portid="443">
            <state state="open"/>
            <service name="https"/>
          </port>
        </ports>
      </host>
      <host>
        <status state="up" reason="echo-reply"/>
        <address addr="192.168.0.44" addrtype="ipv4"/>
        <ports>
          <port protocol="tcp" portid="443">
            <state state="closed"/>
          </port>
        </ports>
      </host>
    </nmaprun>
    """

    adapter = NmapAdapter()
    normalized = adapter.normalize_result(adapter.parse_result(raw_output))

    assert [asset["value"] for asset in normalized.assets] == ["192.168.0.43", "192.168.0.44"]
    assert [service["asset_value"] for service in normalized.services] == ["192.168.0.43"]


def test_amass_adapter_parses_json_lines() -> None:
    raw_output = """
    {"name":"www.example.com","domain":"example.com","addresses":[{"ip":"203.0.113.10"}],"tag":"api"}
    {"name":"api.example.com","domain":"example.com","addresses":[],"tag":"dns"}
    {"name":"www.example.com","domain":"example.com","addresses":[],"tag":"duplicate"}
    """

    adapter = AmassAdapter()
    parsed = adapter.parse_result(raw_output)
    normalized = adapter.normalize_result(parsed)

    assert [asset["value"] for asset in normalized.assets] == ["www.example.com", "api.example.com"]
    assert all(asset["asset_type"] == "SUBDOMAIN" for asset in normalized.assets)
    assert normalized.assets[0]["metadata"]["addresses"] == [{"ip": "203.0.113.10"}]


def test_amass_adapter_prepares_v5_plain_text_command() -> None:
    adapter = AmassAdapter()
    prepared = adapter.prepare_job(ScannerTarget(value="example.com", scope_id=1, organization_id=1))

    assert prepared.command == ["amass", "enum", "-nocolor", "-timeout", "1", "-d", "example.com"]
    assert prepared.config["output_format"] == "text"
    assert prepared.config["profile"] == "passive_subdomain_discovery"


def test_amass_adapter_parses_plain_text_lines() -> None:
    raw_output = """
    www.example.com
    api.example.com
    [INF] ignored status line
    Usage: ignored help text
    www.example.com
    """

    adapter = AmassAdapter()
    parsed = adapter.parse_result(raw_output)
    normalized = adapter.normalize_result(parsed)

    assert [asset["value"] for asset in normalized.assets] == ["www.example.com", "api.example.com"]


def test_nuclei_adapter_parses_findings() -> None:
    raw_output = """
    {"template-id":"exposed-panel","matched-at":"https://www.example.com/panel","host":"https://www.example.com","type":"http","info":{"name":"Exposed panel","severity":"high","description":"Panel exposed","remediation":"Restrict access","metadata":{"cwe":"CWE-200"}}}
    """

    adapter = NucleiAdapter()
    parsed = adapter.parse_result(raw_output)
    normalized = adapter.normalize_result(parsed)

    assert normalized.findings == [
        {
            "asset_type": "HOST",
            "asset_value": "www.example.com",
            "title": "Exposed panel",
            "description": "Panel exposed",
            "severity": "HIGH",
            "source": "nuclei",
            "external_reference": "exposed-panel",
            "remediation": "Restrict access",
            "evidence": {
                "matched_at": "https://www.example.com/panel",
                "type": "http",
                "matcher_name": None,
                "template_id": "exposed-panel",
                "metadata": {"cwe": "CWE-200"},
                "classification": {},
            },
        }
    ]


def test_nuclei_adapter_prepares_bounded_web_profile() -> None:
    adapter = NucleiAdapter()
    prepared = adapter.prepare_job(ScannerTarget(value="www.example.com", scope_id=1, organization_id=1))

    assert prepared.command[0] == "nuclei"
    assert prepared.config["profile"] == "web_finding_discovery"
    assert prepared.config["command"] == prepared.command
    assert "-target" in prepared.command
    assert "http://www.example.com" in prepared.command
    assert "http/technologies/php-detect.yaml" in prepared.command
    assert "http/technologies/wordpress-detect.yaml" in prepared.command
    assert "http/exposed-panels/wordpress-login.yaml" in prepared.command
    assert "-disable-update-check" in prepared.command
    assert "-ni" in prepared.command
    assert "-concurrency" in prepared.command
    assert "-rate-limit" in prepared.command


def test_nuclei_adapter_ignores_log_lines_when_parsing_jsonl() -> None:
    raw_output = """
    [INF] Scan completed in 1s. No results found.
    {"template-id":"wordpress-detect","matched-at":"https://www.example.com","host":"https://www.example.com","type":"http","info":{"name":"WordPress Detect","severity":"info"}}
    """

    adapter = NucleiAdapter()
    parsed = adapter.parse_result(raw_output)

    assert len(parsed) == 1
    assert parsed[0]["template-id"] == "wordpress-detect"


def test_web_fingerprint_adapter_prepares_internal_probe_plan() -> None:
    adapter = WebFingerprintAdapter()
    prepared = adapter.prepare_job(ScannerTarget(value="192.168.0.1", scope_id=1, organization_id=1))

    assert prepared.command == ["web_fingerprint", "192.168.0.1"]
    assert prepared.config["profile"] == "web_fingerprint"
    assert prepared.config["command"] == prepared.command
    assert prepared.config["endpoints"] == [
        {"scheme": "http", "host": "192.168.0.1", "port": 80},
        {"scheme": "https", "host": "192.168.0.1", "port": 443},
    ]


def test_web_fingerprint_adapter_normalizes_service_observations() -> None:
    adapter = WebFingerprintAdapter()
    parsed = adapter.parse_result(
        """
        {
          "target": "192.168.0.1",
          "results": [
            {
              "url": "https://192.168.0.1",
              "host": "192.168.0.1",
              "scheme": "https",
              "port": 443,
              "http_status": 200,
              "title": "Router Admin",
              "server": "router-httpd",
              "content_type": "text/html",
              "tls_subject": "router.local"
            }
          ]
        }
        """
    )
    normalized = adapter.normalize_result(parsed)

    assert normalized.services == [
        {
            "asset_type": "IP",
            "asset_value": "192.168.0.1",
            "protocol": "TCP",
            "port": 443,
            "name": "https",
            "source": "web_fingerprint",
            "metadata": {
                "url": "https://192.168.0.1",
                "http_status": 200,
                "title": "Router Admin",
                "server": "router-httpd",
                "content_type": "text/html",
                "redirect_location": None,
                "tls_subject": "router.local",
                "tls_issuer": None,
                "tls_not_after": None,
                "error": None,
            },
        }
    ]
