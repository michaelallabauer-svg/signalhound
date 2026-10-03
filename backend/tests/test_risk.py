from datetime import datetime, timedelta, timezone
import math

import pytest
from sqlalchemy import func, select
from app.models.audit_log import AuditLog
from app.models.finding import Finding
from app.models.intelligence import IntelligenceRun
from app.models.risk import RiskSnapshot
from app.models.scanner_job import ScannerJob
from app.risk.engine import VERSION, calculate
from app.risk.service import build_result
from tests.test_findings_api import create_asset
from tests.test_intelligence import CVE, CPE, finding, service, get_data

NOW = datetime(2026, 10, 3, 12, tzinfo=timezone.utc)
CONTEXT = {'exposure': 'INTERNET', 'criticality': 'CRITICAL', 'rationale': 'Internet service supporting critical operations'}


def complete_values():
    return {'cvss': 10, 'epss': 1, 'kev': True, 'exposure': 'INTERNET', 'criticality': 'CRITICAL', 'finding_age': 90, 'confidence': 'HIGH'}


def intel(db, asset, evidence, *, status='COMPLETED', days=0, truncated=False):
    date = NOW - timedelta(days=days)
    record = IntelligenceRun(asset_id=asset, created_at=date, status=status, evidence=evidence, result={
        'sources': [{'provider': p, 'status': 'OK', 'fetched_at': date.isoformat()} for p in ['NVD','FIRST EPSS','CISA KEV']],
        'candidates': [] if status == 'ERROR' else [{'cve_id': CVE, 'assessment': 'FINDING_REFERENCE' if evidence['kind']=='CVE' else 'MAY_BE_AFFECTED',
            'status': 'Analyzed', 'confidence': 'HIGH' if evidence['kind']=='CVE' else 'MODERATE',
            'cvss': {'score': 10, 'version': '3.1'}, 'epss': {'score': 1, 'date': date.date().isoformat()}, 'kev': True}],
        'truncated': truncated,
    })
    db.add(record); db.commit()
    return record


def setup(client, db):
    org, asset = create_asset(client)
    record = finding(client, org, asset)
    row = db.get(Finding, record['id'])
    row.first_seen = NOW - timedelta(days=90)
    row.last_seen = NOW
    db.commit()
    evidence = get_data(client, org, asset)['inputs'][0]
    intel(db, asset, evidence)
    return org, asset, row, evidence


def test_algorithm_exact_ledger_replay_and_monotonicity():
    values = complete_values()
    score = calculate(values, {})
    assert score['score'] == 100 and score['status'] == 'COMPLETE'
    assert len(score['components']) == 7
    assert sum(c['weight'] or 0 for c in score['components']) == 100
    assert score['lower'] == sum(c['lower'] for c in score['components'][:-1]) * score['components'][-1]['lower']
    for name, replacement in [('cvss', 5), ('epss', .1), ('kev', False), ('exposure', 'INTERNAL'), ('criticality', 'LOW'), ('finding_age', 0), ('confidence', 'LOW')]:
        changed = calculate({**values, name: replacement}, {})
        assert changed['upper'] < score['upper']
    assert calculate({**values, 'confidence': 'MODERATE'}, {})['score'] == 75
    assert calculate({**values, 'finding_age': 1000}, {})['score'] == 100


def test_unknown_is_interval_not_zero_and_score_is_not_invented():
    result = calculate({}, {})
    assert result['score'] is None and result['status'] == 'INCOMPLETE'
    assert (result['lower'], result['upper']) == (0, 100)
    values = complete_values()
    unknown_kev = calculate({**values, 'kev': None}, {})
    known_absent = calculate({**values, 'kev': False}, {})
    assert unknown_kev['upper'] == 100 and unknown_kev['lower'] == 80
    assert known_absent['score'] == 80
    assert unknown_kev['components'][2]['known'] is False


@pytest.mark.parametrize('invalid', [math.nan, math.inf, -1, 11, True, '10'])
def test_invalid_cvss_is_unknown(invalid):
    result = calculate({**complete_values(), 'cvss': invalid}, {})
    assert result['components'][0]['known'] is False
    assert result['score'] is None
    assert result['lower'] <= result['upper'] <= 100


def test_snapshot_current_lifecycle_and_replay(client, db_session):
    org, asset, row, evidence = setup(client, db_session)
    before = client.get(f'/api/v1/findings/{row.id}').json()
    path = f'/api/v1/assets/{asset}/risk'
    response = client.post(path, json={'organization_id': org, **CONTEXT})
    assert response.status_code == 201, response.text
    snap = response.json()
    assert snap['algorithm_version'] == VERSION
    assert len(snap['result']['entries']) == 1
    stored = snap['result']['entries'][0]
    replay = calculate(stored['values'], {c['name']: c['source'] for c in stored['components']})
    assert replay['lower'] == stored['lower'] and replay['upper'] == stored['upper']
    assert client.get(f'/api/v1/findings/{row.id}').json() == before
    assert db_session.scalar(select(func.count(ScannerJob.id))) == 0
    assert 'risk.calculated' in db_session.scalars(select(AuditLog.action)).all()
    client.patch(f'/api/v1/findings/{row.id}/status', json={'status':'RESOLVED'})
    second = client.post(path, json={'organization_id': org}).json()
    assert second['result']['status'] == 'NO_EVIDENCE'
    assert second['result']['lower'] is None
    assert second['result']['excluded'][0]['status'] == 'RESOLVED'
    assert db_session.get(RiskSnapshot, snap['id']).result == snap['result']
    history = client.get(path, params={'organization_id':org,'limit':1,'offset':1}).json()
    assert history['snapshots'][0]['id'] == snap['id']


def test_complete_sources_then_failure_and_staleness(client, db_session):
    org, asset, row, evidence = setup(client, db_session)
    result = build_result(db_session, asset, CONTEXT, NOW)
    assert result['lower'] == result['upper'] == 100
    intel(db_session, asset, evidence, days=3)
    stale = build_result(db_session, asset, CONTEXT, NOW)['entries'][0]
    assert stale['components'][0]['known'] is True
    assert stale['components'][1]['known'] is False
    assert stale['components'][2]['known'] is False
    intel(db_session, asset, evidence, status='ERROR')
    failed = build_result(db_session, asset, CONTEXT, NOW)
    assert failed['entries'][0]['values']['cvss'] is None
    assert failed['warnings'] and failed['status'] == 'INCOMPLETE'
    assert failed['entries'][0]['values']['confidence'] is None


def test_accepted_risk_remains_false_positive_excluded(client, db_session):
    org, asset, row, _ = setup(client, db_session)
    for status, count in [('ACCEPTED_RISK', 1), ('FALSE_POSITIVE', 0), ('NEW', 1)]:
        client.patch(f'/api/v1/findings/{row.id}/status', json={'status':status})
        result = build_result(db_session, asset, CONTEXT, NOW)
        assert len(result['entries']) == count


def test_potential_stays_unconfirmed_dedup_max_and_current_evidence(client, db_session):
    org, asset = create_asset(client)
    service(client, asset, [CPE])
    evidence = get_data(client, org, asset)['inputs'][0]
    first = intel(db_session, asset, evidence)
    newest = intel(db_session, asset, evidence, truncated=True)
    result = build_result(db_session, asset, CONTEXT, NOW)
    assert len(result['entries']) == 1
    item = result['entries'][0]
    assert item['kind'] == 'MAY_BE_AFFECTED' and item['finding_id'] is None
    assert item['intelligence_run_id'] == newest.id
    assert result['upper'] == item['upper'] <= 75
    assert result['status'] == 'INCOMPLETE' and result['warnings']
    assert db_session.scalar(select(func.count(Finding.id))) == 0
    service(client, asset, [], version=None)
    assert build_result(db_session, asset, CONTEXT, NOW)['status'] == 'NO_EVIDENCE'


def test_org_boundary_input_validation_and_no_exposure_inference(client, db_session):
    org, asset = create_asset(client)
    finding(client, org, asset)
    path = f'/api/v1/assets/{asset}/risk'
    assert client.get(path, params={'organization_id':org+1}).status_code == 404
    assert client.post(path, json={'organization_id':org+1}).status_code == 404
    for extra in [{'exposure':'INTERNET'}, {'criticality':'HIGH','rationale':'   '}, {'score':100}, {'criticality':'BOGUS'}, {'rationale':'x'*2001}]:
        assert client.post(path, json={'organization_id':org, **extra}).status_code == 422
    assert db_session.scalar(select(func.count(RiskSnapshot.id))) == 0
    data = client.post(path, json={'organization_id':org}).json()
    values = data['result']['entries'][0]['values']
    assert values['exposure'] == values['criticality'] == 'UNKNOWN'
    assert values['cvss'] is None  # Finding HIGH severity never masquerades as a CVSS.
    assert data['result']['status'] == 'INCOMPLETE'


def test_rejected_cve_does_not_become_potential_priority(client, db_session):
    org, asset = create_asset(client)
    service(client, asset, [CPE])
    evidence = get_data(client, org, asset)['inputs'][0]
    run = intel(db_session, asset, evidence)
    run.result = {**run.result, 'candidates': [{**run.result['candidates'][0], 'status':'Rejected'}]}
    db_session.commit()
    result = build_result(db_session, asset, CONTEXT, NOW)
    assert result['entries'] == [] and result['warnings']


def test_fresh_fetch_cannot_hide_old_epss_model_date(client, db_session):
    org, asset, row, evidence = setup(client, db_session)
    run = intel(db_session, asset, evidence)
    record = run.result['candidates'][0]
    run.result = {**run.result, 'candidates': [{**record, 'epss': {'score':1,'date':'2020-01-01'}}]}
    db_session.commit()
    result = build_result(db_session, asset, CONTEXT, NOW)['entries'][0]
    assert result['values']['epss'] is None


def test_old_nvd_future_age_and_asset_inactive_do_not_fabricate_safety(client, db_session):
    org, asset, row, evidence = setup(client, db_session)
    intel(db_session, asset, evidence, days=31)
    row.first_seen = NOW + timedelta(days=1)
    db_session.commit()
    result = build_result(db_session, asset, CONTEXT, NOW)['entries'][0]
    assert result['values']['cvss'] is None
    assert result['values']['confidence'] is None
    assert result['values']['finding_age'] is None
    assert result['status'] == 'INCOMPLETE'
    client.patch(f'/api/v1/assets/{asset}', json={'active':False})
    snap = client.post(f'/api/v1/assets/{asset}/risk', json={'organization_id':org}).json()
    assert snap['context']['asset_active'] is False
    assert len(snap['result']['entries']) == 1


def test_upper_lower_bounds_with_context_combinations():
    from itertools import product
    for cvss, epss, kev, confidence in product([None, 0, 5, 10], [None, 0, .5, 1], [None, False, True], [None, 'LOW', 'MODERATE', 'HIGH']):
        result = calculate({**complete_values(), 'cvss':cvss, 'epss':epss, 'kev':kev, 'confidence':confidence}, {})
        assert 0 <= result['lower'] <= result['upper'] <= 100
        if result['score'] is not None:
            assert result['lower'] == result['score'] == result['upper']


def test_large_assets_fail_without_silent_partial_snapshot(client, db_session):
    from app.models.finding import FindingSeverity, FindingStatus
    org, asset = create_asset(client)
    db_session.add_all([Finding(organization_id=org,asset_id=asset,title=f'Issue {i}',source='manual',
                               severity=FindingSeverity.LOW,status=FindingStatus.NEW,evidence={}) for i in range(501)])
    db_session.commit()
    response=client.post(f'/api/v1/assets/{asset}/risk',json={'organization_id':org})
    assert response.status_code==422 and 'no partial score' in response.text
    assert db_session.scalar(select(func.count(RiskSnapshot.id)))==0
