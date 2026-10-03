"""Provider-independent orchestration. No scans, finding writes or scope changes."""
import re
from datetime import datetime, timedelta, timezone

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.intelligence.providers import CVE, EPSS, KEV, NVD, Provider, ProviderError, canonical_cpe
from app.models.finding import Finding
from app.models.intelligence import IntelligenceCache, IntelligenceRun
from app.models.service import Service, ServiceObservation
from app.services.audit import record_audit_event


def evidence_inputs(db: Session, asset_id: int) -> dict:
    software, inputs = [], []
    observations = db.scalars(select(ServiceObservation).join(Service).where(
        Service.asset_id == asset_id, Service.active.is_(True)
    ).order_by(ServiceObservation.observed_at.desc(), ServiceObservation.id.desc()))
    seen = set()
    for obs in observations:
        meta = obs.metadata_ or {}
        if obs.service_id in seen or not (obs.source == "nmap" or meta.get("product") or meta.get("cpes")):
            continue
        seen.add(obs.service_id)
        cpes = meta.get("cpes", [])
        cpes = [c for c in cpes if isinstance(c, str)] if isinstance(cpes, list) else []
        identity = {"service_id": obs.service_id, "observation_id": obs.id, "source": obs.source,
                    "observed_at": obs.observed_at.isoformat(),
                    "product": meta.get("product") if isinstance(meta.get("product"), str) else None,
                    "version": meta.get("version") if isinstance(meta.get("version"), str) else None, "cpes": cpes}
        software.append(identity)
        for cpe in dict.fromkeys(c for c in cpes if isinstance(c, str)):
            reference = canonical_cpe(cpe)
            if reference:
                inputs.append({**identity, "key": f"observation:{obs.id}:{reference}", "reference": reference,
                               "kind": "CPE", "confidence": "MODERATE",
                               "reason": "Observed exact product/version CPE; deployment conditions and backported patches are not verified."})
    findings = db.scalars(select(Finding).where(Finding.asset_id == asset_id).order_by(Finding.id))
    for finding in findings:
        evidence = finding.evidence or {}
        classification = evidence.get("classification", {})
        classification = classification if isinstance(classification, dict) else {}
        raw_ids = classification.get("cve-id", [])
        raw_ids = raw_ids if isinstance(raw_ids, list) else [raw_ids]
        refs = set(re.findall(r"(?<![A-Z0-9])CVE-\d{4}-\d{4,19}(?![A-Z0-9])", (finding.external_reference or "").upper()))
        refs.update(value.upper() for value in raw_ids if isinstance(value, str) and CVE.fullmatch(value.upper()))
        for reference in sorted(refs):
            inputs.append({"key": f"finding:{finding.id}:{reference}", "reference": reference, "kind": "CVE",
                           "finding_id": finding.id, "finding_status": finding.status.value, "source": finding.source,
                           "observed_at": finding.last_seen.isoformat(), "confidence": "HIGH",
                           "reason": "Explicit CVE reference in an existing finding. Confidence describes identifier linkage, not confirmed exploitability."})
    return {"software": software, "inputs": inputs}


def cached_lookup(db: Session, provider: Provider, reference: str) -> tuple[dict | None, dict]:
    now = datetime.now(timezone.utc)
    key = provider.name + ":" + reference
    cached = db.get(IntelligenceCache, key)
    provenance = {"provider": provider.name, "url": provider.url, "queried_at": now.isoformat()}
    if cached and now - cached.fetched_at.replace(tzinfo=timezone.utc) < timedelta(hours=24):
        return cached.data, {**provenance, "status": "OK", "cached": True, "fetched_at": cached.fetched_at.isoformat()}
    try:
        data = provider.lookup(reference)
    except (ProviderError, ValueError, TypeError, KeyError, AttributeError, IndexError) as exc:
        # Never include raw responses, inventory data or exception request URLs in logs/UI.
        error = str(exc) if isinstance(exc, ProviderError) else "Invalid provider response; retry later"
        return None, {**provenance, "status": "ERROR", "cached": False, "error": error}
    from sqlalchemy.dialects.postgresql import insert as pg_insert
    from sqlalchemy.dialects.sqlite import insert as sqlite_insert
    insert = pg_insert if db.get_bind().dialect.name == "postgresql" else sqlite_insert
    statement = insert(IntelligenceCache).values(key=key, fetched_at=now, data=data)
    db.execute(statement.on_conflict_do_update(index_elements=["key"], set_={"fetched_at": now, "data": data}))
    return data, {**provenance, "status": "OK", "cached": False, "fetched_at": now.isoformat()}


def enrich(db: Session, asset_id: int, evidence: dict) -> IntelligenceRun:
    nvd, nvd_source = cached_lookup(db, NVD(), evidence["reference"])
    sources = [nvd_source]
    records = nvd["records"] if nvd else []
    ids = sorted({row["cve_id"] for row in records})
    epss, kev = None, None
    if ids:
        epss, epss_source = cached_lookup(db, EPSS(), ",".join(ids))
        kev, kev_source = cached_lookup(db, KEV(), "catalog")
        if kev:
            kev_source = {**kev_source, "catalog_version": kev.get("catalog_version"), "date_released": kev.get("date_released")}
        sources.extend([epss_source, kev_source])
    candidates = []
    for row in records:
        candidates.append({**row, "assessment": "EXTERNAL_INTELLIGENCE" if row["status"] == "Rejected" else
                           "FINDING_REFERENCE" if evidence["kind"] == "CVE" else "MAY_BE_AFFECTED",
                           "confidence": evidence["confidence"], "match_reason": evidence["reason"],
                           "epss": (epss or {}).get(row["cve_id"]),
                           "kev": None if kev is None else row["cve_id"] in kev["entries"],
                           "kev_detail": None if kev is None else kev["entries"].get(row["cve_id"])})
    errors = any(source["status"] == "ERROR" for source in sources)
    status = "ERROR" if nvd is None else "PARTIAL" if errors or nvd["truncated"] else "COMPLETED"
    run = IntelligenceRun(asset_id=asset_id, status=status, evidence=evidence, result={
        "candidates": candidates, "sources": sources, "total": nvd["total"] if nvd else None,
        "truncated": nvd["truncated"] if nvd else False,
        "notice": "No confirmed findings are created. A missing match or score does not prove safety.",
    })
    db.add(run)
    db.flush()
    record_audit_event(db, action="intelligence.enriched", affected_object_type="asset", affected_object_id=str(asset_id),
                       result=status.lower(), metadata={"run_id": run.id, "reference": evidence["reference"], "count": len(candidates)})
    db.commit()
    db.refresh(run)
    return run
