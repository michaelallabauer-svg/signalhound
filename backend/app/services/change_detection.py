from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models.asset import Asset
from app.models.change import ChangeEntityType, ChangeEvent, ChangeSet, ChangeType
from app.models.finding import Finding, FindingStatus
from app.models.service import Service
from app.repositories.changes import create_change_set


TERMINAL_FINDING_STATUSES = {FindingStatus.RESOLVED, FindingStatus.FALSE_POSITIVE}


@dataclass(frozen=True)
class SnapshotItem:
    entity_type: ChangeEntityType
    key: str
    object_id: int
    data: dict[str, Any]


def detect_changes(
    db: Session,
    *,
    organization_id: int,
    baseline_at: datetime,
    comparison_at: datetime,
) -> ChangeSet:
    baseline = _build_snapshot(db, organization_id=organization_id, as_of=baseline_at)
    comparison = _build_snapshot(db, organization_id=organization_id, as_of=comparison_at)
    events: list[ChangeEvent] = []

    for key in sorted(comparison.keys() - baseline.keys()):
        item = comparison[key]
        events.append(
            ChangeEvent(
                change_set_id=0,
                entity_type=item.entity_type,
                change_type=ChangeType.ADDED,
                entity_key=item.key,
                object_id=item.object_id,
                before=None,
                after=item.data,
            )
        )

    for key in sorted(baseline.keys() - comparison.keys()):
        item = baseline[key]
        events.append(
            ChangeEvent(
                change_set_id=0,
                entity_type=item.entity_type,
                change_type=ChangeType.REMOVED,
                entity_key=item.key,
                object_id=item.object_id,
                before=item.data,
                after=None,
            )
        )

    change_set = ChangeSet(
        organization_id=organization_id,
        baseline_at=baseline_at,
        comparison_at=comparison_at,
        summary=_summarize(events),
    )
    return create_change_set(db, change_set=change_set, events=events)


def _build_snapshot(db: Session, *, organization_id: int, as_of: datetime) -> dict[str, SnapshotItem]:
    snapshot: dict[str, SnapshotItem] = {}
    present_asset_ids: set[int] = set()

    assets = list(
        db.scalars(
            select(Asset)
            .where(Asset.organization_id == organization_id)
            .where(Asset.first_seen <= as_of)
            .order_by(Asset.id)
        )
    )
    for asset in assets:
        if not _active_as_of(asset.active, asset.updated_at, as_of):
            continue
        present_asset_ids.add(asset.id)
        key = f"ASSET:{asset.asset_type.value}:{asset.value}"
        snapshot[key] = SnapshotItem(
            entity_type=ChangeEntityType.ASSET,
            key=key,
            object_id=asset.id,
            data={
                "id": asset.id,
                "asset_type": asset.asset_type.value,
                "value": asset.value,
                "scope_id": asset.scope_id,
                "source": asset.source,
                "known_asset": asset.known_asset,
                "first_seen": asset.first_seen.isoformat(),
                "last_seen": asset.last_seen.isoformat(),
            },
        )

    services = list(
        db.scalars(
            select(Service)
            .join(Asset, Service.asset_id == Asset.id)
            .where(Asset.organization_id == organization_id)
            .where(Service.first_seen <= as_of)
            .order_by(Service.id)
        )
    )
    for service in services:
        if service.asset_id not in present_asset_ids or not _active_as_of(service.active, service.updated_at, as_of):
            continue
        key = f"SERVICE:{service.asset_id}:{service.protocol.value}:{service.port}"
        snapshot[key] = SnapshotItem(
            entity_type=ChangeEntityType.SERVICE,
            key=key,
            object_id=service.id,
            data={
                "id": service.id,
                "asset_id": service.asset_id,
                "protocol": service.protocol.value,
                "port": service.port,
                "name": service.name,
                "source": service.source,
                "first_seen": service.first_seen.isoformat(),
                "last_seen": service.last_seen.isoformat(),
            },
        )

    findings = list(
        db.scalars(
            select(Finding)
            .where(Finding.organization_id == organization_id)
            .where(Finding.first_seen <= as_of)
            .order_by(Finding.id)
        )
    )
    for finding in findings:
        if finding.asset_id not in present_asset_ids or _terminal_as_of(finding.status, finding.updated_at, as_of):
            continue
        reference = finding.external_reference or finding.title
        key = f"FINDING:{finding.asset_id}:{finding.service_id or 'asset'}:{finding.source}:{reference}"
        snapshot[key] = SnapshotItem(
            entity_type=ChangeEntityType.FINDING,
            key=key,
            object_id=finding.id,
            data={
                "id": finding.id,
                "asset_id": finding.asset_id,
                "service_id": finding.service_id,
                "title": finding.title,
                "severity": finding.severity.value,
                "source": finding.source,
                "external_reference": finding.external_reference,
                "status": finding.status.value,
                "first_seen": finding.first_seen.isoformat(),
                "last_seen": finding.last_seen.isoformat(),
            },
        )

    return snapshot


def _active_as_of(active: bool, updated_at: datetime, as_of: datetime) -> bool:
    return active or _as_utc(updated_at) > _as_utc(as_of)


def _terminal_as_of(status: FindingStatus, updated_at: datetime, as_of: datetime) -> bool:
    return status in TERMINAL_FINDING_STATUSES and _as_utc(updated_at) <= _as_utc(as_of)


def _as_utc(value: datetime) -> datetime:
    if value.tzinfo is None:
        return value.replace(tzinfo=UTC)
    return value.astimezone(UTC)


def _summarize(events: list[ChangeEvent]) -> dict[str, Any]:
    summary: dict[str, Any] = {"total": len(events), "by_entity_type": {}, "by_change_type": {}}
    for event in events:
        entity_type = event.entity_type.value
        change_type = event.change_type.value
        summary["by_entity_type"][entity_type] = summary["by_entity_type"].get(entity_type, 0) + 1
        summary["by_change_type"][change_type] = summary["by_change_type"].get(change_type, 0) + 1
    return summary
