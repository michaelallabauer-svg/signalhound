from typing import Any

from sqlalchemy.orm import Session

from app.models.audit_log import AuditLog


def record_audit_event(
    db: Session,
    *,
    action: str,
    affected_object_type: str,
    result: str,
    actor: str | None = None,
    affected_object_id: str | None = None,
    metadata: dict[str, Any] | None = None,
) -> AuditLog:
    event = AuditLog(
        action=action,
        actor=actor,
        affected_object_type=affected_object_type,
        affected_object_id=affected_object_id,
        result=result,
        metadata_=metadata or {},
    )
    db.add(event)
    db.flush()
    return event

