from datetime import UTC, datetime
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models.finding import Finding, FindingObservation, FindingSeverity, FindingStatus


def observe_finding(
    db: Session,
    *,
    organization_id: int,
    asset_id: int,
    service_id: int | None,
    title: str,
    description: str | None,
    severity: FindingSeverity,
    source: str,
    external_reference: str | None,
    remediation: str | None,
    evidence: dict[str, Any],
) -> tuple[Finding, bool]:
    statement = (
        select(Finding)
        .where(Finding.organization_id == organization_id)
        .where(Finding.asset_id == asset_id)
        .where(Finding.source == source)
        .where(Finding.title == title)
    )
    if service_id is None:
        statement = statement.where(Finding.service_id.is_(None))
    else:
        statement = statement.where(Finding.service_id == service_id)
    if external_reference is None:
        statement = statement.where(Finding.external_reference.is_(None))
    else:
        statement = statement.where(Finding.external_reference == external_reference)
    finding = db.scalar(statement)
    created = finding is None
    now = datetime.now(UTC)

    if finding is None:
        finding = Finding(
            organization_id=organization_id,
            asset_id=asset_id,
            service_id=service_id,
            title=title,
            description=description,
            severity=severity,
            source=source,
            external_reference=external_reference,
            status=FindingStatus.NEW,
            remediation=remediation,
            evidence=evidence,
            first_seen=now,
            last_seen=now,
        )
        db.add(finding)
        db.flush()
    else:
        finding.last_seen = now
        finding.description = description or finding.description
        finding.severity = severity
        finding.remediation = remediation or finding.remediation
        finding.evidence = evidence

    db.add(FindingObservation(finding_id=finding.id, source=source, evidence=evidence))
    db.flush()
    return finding, created


def list_findings(
    db: Session,
    *,
    organization_id: int | None = None,
    asset_id: int | None = None,
    service_id: int | None = None,
    status: FindingStatus | None = None,
    severity: FindingSeverity | None = None,
) -> list[Finding]:
    statement = select(Finding).order_by(Finding.id)
    if organization_id is not None:
        statement = statement.where(Finding.organization_id == organization_id)
    if asset_id is not None:
        statement = statement.where(Finding.asset_id == asset_id)
    if service_id is not None:
        statement = statement.where(Finding.service_id == service_id)
    if status is not None:
        statement = statement.where(Finding.status == status)
    if severity is not None:
        statement = statement.where(Finding.severity == severity)
    return list(db.scalars(statement))


def get_finding(db: Session, finding_id: int) -> Finding | None:
    return db.get(Finding, finding_id)


def list_finding_observations(db: Session, finding_id: int) -> list[FindingObservation]:
    statement = (
        select(FindingObservation)
        .where(FindingObservation.finding_id == finding_id)
        .order_by(FindingObservation.observed_at, FindingObservation.id)
    )
    return list(db.scalars(statement))
