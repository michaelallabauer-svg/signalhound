from app.scanners.placeholders import AmassAdapter, NmapAdapter, NucleiAdapter


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
            "metadata": {"addrtype": "ipv4"},
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
            "metadata": {"product": "nginx", "version": "1.25"},
        }
    ]


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
            },
        }
    ]
