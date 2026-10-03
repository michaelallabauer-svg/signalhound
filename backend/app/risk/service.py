"""Build point-in-time ledgers from stored evidence only; no external I/O."""
from datetime import datetime, timezone, timedelta
from sqlalchemy import select
from sqlalchemy.orm import Session
from app.intelligence.service import evidence_inputs
from app.models.finding import Finding
from app.models.intelligence import IntelligenceRun
from app.models.risk import RiskSnapshot
from app.risk.engine import VERSION, WEIGHTS, calculate
from app.services.audit import record_audit_event


def utc(value):
    if isinstance(value, str):
        try:
            value = datetime.fromisoformat(value.replace('Z', '+00:00'))
        except ValueError:
            return None
    if not isinstance(value, datetime):
        return None
    return value.replace(tzinfo=timezone.utc) if value.tzinfo is None else value.astimezone(timezone.utc)


def fresh_source(run, provider, now, days):
    if run is None or run.status == 'ERROR':
        return None
    for source in run.result.get('sources', []):
        stamp = utc(source.get('fetched_at'))
        if source.get('provider') == provider and source.get('status') == 'OK' and stamp and timedelta(0) <= now - stamp <= timedelta(days=days):
            return f"Intelligence #{run.id} / {provider} / {stamp.isoformat()}"
    return None


def entry(key, title, finding, run, candidate, context, now):
    candidate = candidate or {}
    nvd = fresh_source(run, 'NVD', now, 30)
    epss = fresh_source(run, 'FIRST EPSS', now, 2)
    kev = fresh_source(run, 'CISA KEV', now, 2)
    # EPSS has its own model observation date; a fresh fetch alone is insufficient.
    epss_record = candidate.get('epss') or {}
    epss_date = utc(epss_record.get('date'))
    if not epss_date or not timedelta(0) <= now - epss_date <= timedelta(days=3):
        epss = None
    cvss = candidate.get('cvss') or {}
    first_seen = utc(finding.first_seen) if finding else None
    age = (now - first_seen).total_seconds() / 86400 if first_seen and first_seen <= now else None
    confidence = candidate.get('confidence') if nvd else None
    values = {'cvss': cvss.get('score') if nvd else None, 'epss': epss_record.get('score') if epss else None,
              'kev': candidate.get('kev') if kev else None, 'exposure': context['exposure'],
              'criticality': context['criticality'], 'finding_age': age, 'confidence': confidence}
    sources = {'cvss': nvd or 'Missing, failed or older than 30 days; finding severity is not substituted for CVSS',
               'epss': epss or 'Missing/failed/stale EPSS (fetch >2 days or model date >3 days)',
               'kev': kev or 'Missing/failed/stale KEV (>2 days)',
               'exposure': 'Analyst snapshot context; not inferred from scan zone',
               'criticality': 'Analyst snapshot context; not a stored asset attribute',
               'finding_age': f'Finding #{finding.id} first seen {finding.first_seen.isoformat()}' if finding else 'No finding: potential-match age is unknown',
               'confidence': f'Intelligence #{run.id}: identifier linkage only, not exploitability' if confidence else 'No fresh identifier-linkage confidence'}
    return {'key': key, 'title': title, 'kind': 'FINDING' if finding else 'MAY_BE_AFFECTED',
            'finding_id': finding.id if finding else None, 'finding_status': finding.status.value if finding else None,
            'finding_severity': finding.severity.value if finding else None,
            'finding_source': finding.source if finding else None,
            'intelligence_run_id': run.id if run else None, 'cve_id': candidate.get('cve_id'),
            'evidence': run.evidence if run else None, 'values': values,
            'assessment': candidate.get('assessment'), 'cvss_metadata': cvss,
            **calculate(values, sources)}


def build_result(db: Session, asset_id: int, context: dict, now: datetime) -> dict:
    findings = list(db.scalars(select(Finding).where(Finding.asset_id == asset_id).order_by(Finding.id).limit(501)))
    runs = list(db.scalars(select(IntelligenceRun).where(IntelligenceRun.asset_id == asset_id)
                           .order_by(IntelligenceRun.id.desc()).limit(5001)))
    if len(findings) > 500 or len(runs) > 5000:
        raise ValueError('Asset exceeds the interactive limit (500 findings / 5000 intelligence snapshots); no partial score was saved.')
    current_keys = {item['key'] for item in evidence_inputs(db, asset_id)['inputs']}
    latest = {}
    for run in runs:
        key = run.evidence.get('key')
        if key in current_keys and key not in latest:
            latest[key] = run  # Including failures: never silently fall back to older success.
    linked = {}
    potentials = []
    warnings = []
    for run in latest.values():
        observed_at = utc(run.evidence.get('observed_at'))
        if observed_at is None or not timedelta(0) <= now - observed_at <= timedelta(days=30):
            warnings.append(f'Intelligence #{run.id} references missing, future or older-than-30-day observation dates; verify current applicability.')
        if run.status != 'COMPLETED':
            warnings.append(f'Intelligence #{run.id} is {run.status}; coverage may be incomplete.')
        if run.result.get('truncated'):
            warnings.append(f'Intelligence #{run.id} was truncated; this is not a complete vulnerability list.')
        for candidate in run.result.get('candidates', []):
            if candidate.get('status') == 'Rejected' or candidate.get('assessment') == 'EXTERNAL_INTELLIGENCE':
                warnings.append(f"Rejected CVE {candidate.get('cve_id')} is excluded as an intelligence match.")
                continue
            if run.evidence.get('kind') == 'CVE':
                linked.setdefault(run.evidence.get('finding_id'), []).append((run, candidate))
            else:
                potentials.append((run, candidate))
    entries, excluded = [], []
    for finding in findings:
        if finding.status.value in {'RESOLVED', 'FALSE_POSITIVE'}:
            excluded.append({'finding_id': finding.id, 'status': finding.status.value, 'reason': 'Not open; excluded from current priority'})
            continue
        for run, candidate in linked.get(finding.id, [(None, None)]):
            suffix = candidate['cve_id'] if candidate else 'unenriched'
            entries.append(entry(f'finding:{finding.id}:{suffix}', finding.title, finding, run, candidate, context, now))
    # A CPE-only match remains separate evidence even when the same CVE occurs on a finding.
    # Max aggregation (never sum) prevents duplicate observations increasing asset priority.
    for run, candidate in potentials:
        entries.append(entry(f"potential:{run.evidence['key']}:{candidate['cve_id']}", candidate['cve_id'], None, run, candidate, context, now))
    if len(entries) > 1000:
        raise ValueError('Asset exceeds 1000 prioritization entries; no partial score was saved.')
    entries.sort(key=lambda row: (-row['upper'], -row['lower'], row['key']))
    lower = max((row['lower'] for row in entries), default=None)
    upper = max((row['upper'] for row in entries), default=None)
    return {'status': 'NO_EVIDENCE' if not entries else 'INCOMPLETE' if warnings or any(e['status'] != 'COMPLETE' for e in entries) else 'COMPLETE',
            'lower': lower, 'upper': upper, 'entries': entries, 'excluded': excluded, 'warnings': warnings,
            'aggregation': 'Maximum across entries, never sum. Sorted by upper bound then lower bound; review uncertainty before remediation.',
            'intelligence_run_ids': [run.id for run in latest.values()],
            'weights': WEIGHTS, 'confidence_factors': {'LOW': .5, 'MODERATE': .75, 'HIGH': 1, 'UNKNOWN': [.5, 1]},
            'notice': 'Heuristic priority, not breach probability or confirmed vulnerability. No evidence does not mean safe. Recalculate after inventory, finding or intelligence changes.'}


def create_snapshot(db, asset, context):
    now = datetime.now(timezone.utc)
    result = build_result(db, asset.id, context, now)
    snapshot = RiskSnapshot(asset_id=asset.id, created_at=now, algorithm_version=VERSION,
                            context={**context, 'asset_active': asset.active, 'scope_id': asset.scope_id}, result=result)
    db.add(snapshot)
    db.flush()
    record_audit_event(db, action='risk.calculated', affected_object_type='asset', affected_object_id=str(asset.id),
                       result='success', metadata={'snapshot_id': snapshot.id, 'algorithm_version': VERSION, 'status': result['status']})
    db.commit()
    db.refresh(snapshot)
    return snapshot
