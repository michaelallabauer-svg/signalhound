from datetime import datetime, timedelta, timezone

import pytest
from sqlalchemy import func, select

from app.core.config import get_settings
from app.intelligence import providers
from app.intelligence.providers import canonical_cpe, ProviderError
from app.models.audit_log import AuditLog
from app.models.finding import Finding
from app.models.intelligence import IntelligenceCache, IntelligenceRun
from app.models.scanner_job import ScannerJob
from tests.test_findings_api import create_asset

CVE = 'CVE-2021-44228'
CPE = 'cpe:2.3:a:apache:log4j:2.14.1:*:*:*:*:*:*:*'


def finding(client, org, asset):
    return client.post('/api/v1/findings', json={
        'organization_id': org, 'asset_id': asset, 'title': 'Scanner evidence', 'severity': 'HIGH',
        'source': 'nuclei', 'external_reference': CVE, 'evidence': {'classification': {'cve-id': [CVE]}},
    }).json()


def service(client, asset, cpes=None, version='2.14.1'):
    response = client.post('/api/v1/services', json={
        'asset_id': asset, 'protocol': 'TCP', 'port': 443, 'name': 'https', 'source': 'nmap',
        'metadata': {'product': 'Log4j', 'version': version, 'cpes': cpes or []},
    })
    assert response.status_code == 201, response.text
    return response.json()


def get_data(client, org, asset):
    return client.get(f'/api/v1/assets/{asset}/intelligence?organization_id={org}').json()


def lookup(client, org, asset, key):
    return client.post(f'/api/v1/assets/{asset}/intelligence', json={'organization_id': org, 'evidence_key': key})


@pytest.fixture
def enabled(monkeypatch):
    monkeypatch.setattr(get_settings(), 'intelligence_enabled', True)


@pytest.fixture
def public_data(monkeypatch):
    calls = []
    def fetch(url):
        calls.append(url)
        if url.startswith(providers.NVD.url):
            return {'totalResults': 1, 'vulnerabilities': [{'cve': {
                'id': CVE, 'vulnStatus': 'Analyzed', 'lastModified': '2026-01-01',
                'descriptions': [{'lang': 'en', 'value': '<script>not HTML</script>'}],
                'metrics': {'cvssMetricV31': [{'type': 'Primary', 'source': 'nvd@nist.gov',
                    'cvssData': {'version': '3.1', 'baseScore': 10, 'vectorString': 'CVSS:3.1/AV:N'}}]},
                'configurations': [{'nodes': [{'cpeMatch': [{'criteria': CPE, 'vulnerable': True}]}]}],
            }}]}
        if url.startswith(providers.EPSS.url):
            return {'status': 'OK', 'data': [{'cve': CVE, 'epss': '0.94', 'percentile': '0.99', 'date': '2026-10-03'}]}
        return {'count': 1, 'catalogVersion': '2026.10.03', 'dateReleased': '2026-10-03', 'vulnerabilities': [
            {'cveID': CVE, 'dateAdded': '2021-12-10', 'requiredAction': 'Patch', 'dueDate': '2021-12-24'}]}
    monkeypatch.setattr(providers, 'fetch_json', fetch)
    return calls


def test_enrichment_separate_audited_historized_cached(client, db_session, enabled, public_data):
    org, asset = create_asset(client)
    original = finding(client, org, asset)
    key = get_data(client, org, asset)['inputs'][0]['key']
    first = lookup(client, org, asset, key)
    assert first.status_code == 201
    run = first.json()
    candidate = run['result']['candidates'][0]
    assert run['status'] == 'COMPLETED'
    assert candidate['assessment'] == 'FINDING_REFERENCE'
    assert candidate['cvss']['score'] == 10
    assert candidate['epss']['score'] == .94
    assert candidate['kev'] is True
    second = lookup(client, org, asset, key).json()
    assert len(public_data) == 3
    assert all(p['cached'] for p in second['result']['sources'])
    assert second['id'] != run['id']
    assert len(get_data(client, org, asset)['runs']) == 2
    assert db_session.scalar(select(func.count(Finding.id))) == 1
    assert db_session.scalar(select(func.count(ScannerJob.id))) == 0
    assert client.get(f"/api/v1/findings/{original['id']}").json() == original
    assert 'intelligence.enriched' in db_session.scalars(select(AuditLog.action)).all()
    assert all('app.example.com' not in u and 'Finding+Corp' not in u for u in public_data)
    for row in db_session.scalars(select(IntelligenceCache)):
        row.fetched_at = datetime.now(timezone.utc) - timedelta(days=2)
    db_session.commit()
    lookup(client, org, asset, key)
    assert len(public_data) == 6
    assert db_session.get(IntelligenceRun, run['id']).result == run['result']


def test_cpe_only_latest_software_never_confirms(client, db_session, enabled, public_data):
    org, asset = create_asset(client)
    service(client, asset, [CPE])
    key = get_data(client, org, asset)['inputs'][0]['key']
    candidate = lookup(client, org, asset, key).json()['result']['candidates'][0]
    assert candidate['assessment'] == 'MAY_BE_AFFECTED'
    assert candidate['confidence'] == 'MODERATE'
    assert db_session.scalar(select(func.count(Finding.id))) == 0
    service(client, asset, [], version=None)
    assert get_data(client, org, asset)['inputs'] == []
    assert lookup(client, org, asset, key).status_code == 422


def test_disabled_cross_org_and_injected_queries(client, db_session, monkeypatch, public_data):
    monkeypatch.setattr(get_settings(), "intelligence_enabled", False)
    org, asset = create_asset(client)
    finding(client, org, asset)
    key = get_data(client, org, asset)['inputs'][0]['key']
    assert lookup(client, org, asset, key).status_code == 409
    monkeypatch.setattr(get_settings(), 'intelligence_enabled', True)
    assert lookup(client, org + 1, asset, key).status_code == 404
    assert client.get(f'/api/v1/assets/{asset}/intelligence?organization_id={org + 1}').status_code == 404
    assert lookup(client, org, asset + 1, key).status_code == 404
    assert lookup(client, org, asset, 'https://127.0.0.1/admin').status_code == 422
    assert lookup(client, org, asset, 'finding:999:CVE-2021-44228').status_code == 422
    assert not public_data
    assert db_session.scalar(select(func.count(IntelligenceRun.id))) == 0


def test_partial_error_zero_are_distinct(client, enabled, monkeypatch, public_data):
    org, asset = create_asset(client)
    finding(client, org, asset)
    key = get_data(client, org, asset)['inputs'][0]['key']
    def failure(self, reference):
        raise ProviderError('Unavailable')
    monkeypatch.setattr(providers.KEV, 'lookup', failure)
    monkeypatch.setattr(providers.EPSS, 'lookup', lambda self, reference: {})
    result = lookup(client, org, asset, key).json()
    assert result['status'] == 'PARTIAL'
    assert result['result']['candidates'][0]['kev'] is None
    assert result['result']['candidates'][0]['epss'] is None
    service(client, asset, [CPE])
    cpe_key = get_data(client, org, asset)['inputs'][0]['key']
    monkeypatch.setattr(providers.NVD, 'lookup', failure)
    failed = lookup(client, org, asset, cpe_key).json()
    assert failed['status'] == 'ERROR' and failed['result']['total'] is None
    monkeypatch.setattr(providers.NVD, 'lookup', lambda self, ref: {'records': [], 'total': 0, 'truncated': False})
    empty = lookup(client, org, asset, cpe_key).json()
    assert empty['status'] == 'COMPLETED' and empty['result']['total'] == 0


@pytest.mark.parametrize('value', ['cpe:/a:apache:log4j', 'cpe:/a:apache:log4j:*', 'cpe:2.3:a:apache:log4j:*:*:*:*:*:*:*:*',
                                  'https://localhost', 'cpe:/a:apache:log4j:2.*', 'cpe:/a:apache:log4j:2\\:14'])
def test_reject_ambiguous_cpes(value):
    assert canonical_cpe(value) is None


def test_nmap_uri_cpe_converted_without_guessing():
    assert canonical_cpe('cpe:/a:apache:log4j:2.14.1') == CPE
    assert canonical_cpe(CPE) == CPE


def test_provider_validation_missing_values(monkeypatch):
    monkeypatch.setattr(providers, 'fetch_json', lambda url: {'totalResults': 1, 'vulnerabilities': [
        {'cve': {'id': CVE, 'vulnStatus': 'Rejected', 'descriptions': []}}]})
    row = providers.NVD().lookup(CVE)['records'][0]
    assert row['status'] == 'Rejected' and row['cvss'] is None
    with pytest.raises(ProviderError):
        providers.NVD().lookup('https://evil.test')
    with pytest.raises(ProviderError):
        providers.EPSS().lookup('invalid')
    with pytest.raises(ProviderError):
        providers.score('nan', 1)
    monkeypatch.setattr(providers, 'fetch_json', lambda url: {'count': 2, 'vulnerabilities': [{'cveID': CVE}]})
    with pytest.raises(ProviderError):
        providers.KEV().lookup('catalog')


def test_truncation_rejected_explicit(client, enabled, monkeypatch):
    org, asset = create_asset(client)
    service(client, asset, [CPE])
    monkeypatch.setattr(providers.NVD, 'lookup', lambda self, ref: {
        'records': [{'cve_id': CVE, 'status': 'Rejected', 'cvss': None}], 'total': 99, 'truncated': True})
    monkeypatch.setattr(providers.EPSS, 'lookup', lambda self, ref: {})
    monkeypatch.setattr(providers.KEV, 'lookup', lambda self, ref: {'entries': {}})
    key = get_data(client, org, asset)['inputs'][0]['key']
    result = lookup(client, org, asset, key).json()
    assert result['status'] == 'PARTIAL' and result['result']['truncated']
    candidate = result['result']['candidates'][0]
    assert candidate['assessment'] == 'EXTERNAL_INTELLIGENCE'
    assert candidate['kev'] is False


def test_history_pagination(client, enabled, public_data):
    org, asset = create_asset(client)
    finding(client, org, asset)
    key = get_data(client, org, asset)['inputs'][0]['key']
    first = lookup(client, org, asset, key).json()
    lookup(client, org, asset, key)
    response = client.get(f'/api/v1/assets/{asset}/intelligence?organization_id={org}&limit=1&offset=1')
    assert response.json()['runs'][0]['id'] == first['id']


def test_scanner_import_preserves_identity_evidence():
    import json
    from app.scanners.placeholders import NmapAdapter, NucleiAdapter
    nmap = NmapAdapter()
    xml = '<nmaprun><host><status state="up"/><address addr="192.0.2.1" addrtype="ipv4"/><ports><port protocol="tcp" portid="443"><state state="open"/><service name="https" product="Log4j" version="2.14.1"><cpe>cpe:/a:apache:log4j:2.14.1</cpe></service></port></ports></host></nmaprun>'
    result = nmap.normalize_result(nmap.parse_result(xml))
    assert result.services[0]['metadata']['cpes'] == ['cpe:/a:apache:log4j:2.14.1']
    nuclei = NucleiAdapter()
    raw = json.dumps({'host': 'https://app.example.com', 'template-id': 'example', 'info': {'classification': {'cve-id': [CVE]}}})
    assert nuclei.normalize_result(nuclei.parse_result(raw)).findings[0]['evidence']['classification']['cve-id'] == [CVE]


def test_transport_limits_and_redirects(monkeypatch):
    class Response:
        def __enter__(self): return self
        def __exit__(self, *args): pass
        def read(self, size): return b'x' * size
    class Opener:
        def open(self, request, timeout):
            assert timeout == 10
            return Response()
    monkeypatch.setattr(providers, 'build_opener', lambda *args: Opener())
    with pytest.raises(ProviderError, match='size limit'):
        providers.fetch_json(providers.KEV.url)
    with pytest.raises(ProviderError, match='redirect refused'):
        providers.NoRedirect().redirect_request(None, None, 302, '', {}, 'http://127.0.0.1')
    # Failed reads release the lock for the next caller.
    assert providers._request_lock.acquire(blocking=False)
    providers._request_lock.release()


def test_unstructured_observation_metadata_is_safe(client):
    org, asset = create_asset(client)
    client.post('/api/v1/services', json={
        'asset_id': asset, 'protocol': 'TCP', 'port': 80, 'source': 'nmap',
        'metadata': {'product': {'bad': True}, 'version': [], 'cpes': [{'unexpected': 'object'}]},
    })
    data = get_data(client, org, asset)
    assert data['software'][0]['product'] is None
    assert data['software'][0]['cpes'] == []
    assert data['inputs'] == []
