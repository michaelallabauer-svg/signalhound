"""Reversibly retire legacy fingerprint-only inventory entries without service evidence.

Historical observations and jobs are retained. Never deactivate a service with
independent discovery evidence, nor infer that a real host has disappeared.
"""
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models.asset import Asset, AssetObservation
from app.models.finding import Finding
from app.models.service import Service, ServiceObservation
from app.services.audit import record_audit_event


def retire_unconfirmed_fingerprints(db: Session) -> dict[str, list[int]]:
    changed: dict[str, list[int]] = {"services": [], "assets": []}
    for service in db.scalars(select(Service).where(Service.active.is_(True)).with_for_update()):
        observations = list(db.scalars(select(ServiceObservation).where(ServiceObservation.service_id == service.id)))
        asset = db.get(Asset, service.asset_id)
        if not asset or not observations or any(observation.source != "web_fingerprint" for observation in observations):
            continue
        if any(type(observation.metadata_.get("http_status")) is int and 100 <= observation.metadata_["http_status"] <= 599 for observation in observations):
            continue
        # Only known failed collections or malformed subnet-host artifacts qualify.
        if "/" not in asset.value and not all(observation.metadata_.get("error") for observation in observations):
            continue
        service.active = False
        changed["services"].append(service.id)
        record_audit_event(db, action="service.fingerprint_artifact_retired", affected_object_type="service",
                          affected_object_id=str(service.id), result="success",
                          metadata={"previous_active": True, "active": False, "reason": "No successful fingerprint or independent service observation; history retained"})
    db.flush()
    for asset in db.scalars(select(Asset).where(Asset.active.is_(True)).with_for_update()):
        if "/" not in asset.value:
            continue
        observations = list(db.scalars(select(AssetObservation).where(AssetObservation.asset_id == asset.id)))
        if not observations or any(observation.source != "web_fingerprint" for observation in observations):
            continue
        if db.scalar(select(Service.id).where(Service.asset_id == asset.id, Service.active.is_(True)).limit(1)):
            continue
        if db.scalar(select(Finding.id).where(Finding.asset_id == asset.id).limit(1)):
            continue
        asset.active = False
        changed["assets"].append(asset.id)
        record_audit_event(db, action="asset.fingerprint_artifact_retired", affected_object_type="asset",
                          affected_object_id=str(asset.id), result="success",
                          metadata={"previous_active": True, "active": False, "reason": "Subnet incorrectly recorded as fingerprint host; history retained"})
    db.flush()
    return changed
