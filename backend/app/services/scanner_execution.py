from dataclasses import asdict, replace
from datetime import UTC, datetime
import ipaddress
from typing import Any

from sqlalchemy.orm import Session

from app.models.asset import Asset, AssetType
from app.models.finding import FindingSeverity
from app.models.scanner_job import ScannerJob, ScannerJobStatus
from app.models.scope import ScanZone
from app.models.service import ServiceProtocol
from app.repositories.assets import observe_asset
from app.repositories.assets import deactivate_missing_assets
from app.repositories.findings import observe_finding
from app.repositories.scanner_jobs import set_scanner_job_status
from app.repositories.scopes import get_scope
from app.repositories.services import find_service, observe_service
from app.scanners.base import NormalizedScannerResult, PreparedScannerJob, ScannerAdapter, ScannerTarget
from app.services.audit import record_audit_event
from app.services.scope_validation import ScopeValidator


def run_scanner_job(
    db: Session,
    *,
    job: ScannerJob,
    adapter: ScannerAdapter,
    timeout_seconds: int,
) -> ScannerJob:
    if job.status != ScannerJobStatus.PREPARED:
        raise ValueError("Only PREPARED scanner jobs can be executed")
    if not adapter.execution_supported:
        raise ValueError("Scanner adapter execution is not supported")

    prepared_job = _prepare_execution_job(job=job, adapter=adapter, timeout_seconds=timeout_seconds)

    job.started_at = datetime.now(UTC)
    set_scanner_job_status(job, ScannerJobStatus.RUNNING)
    record_audit_event(
        db,
        action="scanner.started",
        affected_object_type="scanner_job",
        affected_object_id=str(job.id),
        result="started",
        metadata={"adapter_name": job.adapter_name, "target": job.target},
    )
    db.flush()

    try:
        raw_output = adapter.execute(prepared_job)
        parsed_result = adapter.parse_result(raw_output)
        normalized_result = adapter.normalize_result(parsed_result)
        import_normalized_result(db, job=job, result=normalized_result)
        reconcile_nmap_cidr_assets(db, job=job, result=normalized_result)
        job.completed_at = datetime.now(UTC)
        set_scanner_job_status(
            job,
            ScannerJobStatus.COMPLETED,
            raw_output=raw_output,
            normalized_result=asdict(normalized_result),
        )
        record_audit_event(
            db,
            action="scanner.completed",
            affected_object_type="scanner_job",
            affected_object_id=str(job.id),
            result="success",
            metadata={"adapter_name": job.adapter_name, "target": job.target},
        )
    except Exception as exc:
        job.completed_at = datetime.now(UTC)
        set_scanner_job_status(job, ScannerJobStatus.FAILED, error_message=str(exc))
        record_audit_event(
            db,
            action="scanner.failed",
            affected_object_type="scanner_job",
            affected_object_id=str(job.id),
            result="failed",
            metadata={"adapter_name": job.adapter_name, "target": job.target, "error": str(exc)},
        )

    db.flush()
    return job


def import_normalized_result(db: Session, *, job: ScannerJob, result: NormalizedScannerResult) -> None:
    imported_assets: dict[tuple[str, str], Asset] = {}

    for asset_data in result.assets:
        asset = _observe_normalized_asset(db, job=job, asset_data=asset_data)
        imported_assets[(asset.asset_type.value, asset.value)] = asset

    for service_data in result.services:
        asset_type = str(service_data.get("asset_type", "HOST"))
        asset_value = str(service_data.get("asset_value", job.target))
        asset = imported_assets.get((asset_type, asset_value))
        if asset is None:
            asset = _observe_normalized_asset(
                db,
                job=job,
                asset_data={
                    "asset_type": asset_type,
                    "value": asset_value,
                    "source": service_data.get("source", job.adapter_name),
                    "metadata": {"created_from_service_result": True},
                },
            )
            imported_assets[(asset.asset_type.value, asset.value)] = asset

        observe_service(
            db,
            asset_id=asset.id,
            protocol=ServiceProtocol(str(service_data["protocol"])),
            port=int(service_data["port"]),
            name=service_data.get("name"),
            source=str(service_data.get("source", job.adapter_name)),
            metadata=dict(service_data.get("metadata", {})),
        )

    for finding_data in result.findings:
        asset = _observe_normalized_asset(
            db,
            job=job,
            asset_data={
                "asset_type": finding_data.get("asset_type", "HOST"),
                "value": finding_data.get("asset_value", job.target),
                "source": finding_data.get("source", job.adapter_name),
                "metadata": {"created_from_finding_result": True},
            },
        )
        service_id = None
        protocol = finding_data.get("protocol")
        port = finding_data.get("port")
        if protocol is not None and port is not None:
            service = find_service(
                db,
                asset_id=asset.id,
                protocol=ServiceProtocol(str(protocol)),
                port=int(port),
            )
            service_id = service.id if service is not None else None

        observe_finding(
            db,
            organization_id=job.organization_id,
            asset_id=asset.id,
            service_id=service_id,
            title=str(finding_data["title"]),
            description=finding_data.get("description"),
            severity=FindingSeverity(str(finding_data["severity"])),
            source=str(finding_data.get("source", job.adapter_name)),
            external_reference=finding_data.get("external_reference"),
            remediation=finding_data.get("remediation"),
            evidence=dict(finding_data.get("evidence", {})),
        )


def _prepare_execution_job(*, job: ScannerJob, adapter: ScannerAdapter, timeout_seconds: int) -> PreparedScannerJob:
    prepare_job = getattr(adapter, "prepare_job", None)
    if not callable(prepare_job):
        return PreparedScannerJob(
            adapter_name=job.adapter_name,
            target=job.target,
            config=job.prepared_config,
            command=list(job.prepared_config.get("command", [])),
            timeout_seconds=timeout_seconds,
        )

    scanner_target = ScannerTarget(
        value=job.target,
        scope_id=job.scope_id,
        organization_id=job.organization_id,
    )
    prepared_job = prepare_job(scanner_target)
    stored_command = list(job.prepared_config.get("command", []))
    if prepared_job.command != stored_command:
        raise ValueError("Stored scanner command does not match adapter-prepared command")

    return replace(prepared_job, config=job.prepared_config, timeout_seconds=timeout_seconds)


def _observe_normalized_asset(db: Session, *, job: ScannerJob, asset_data: dict[str, Any]) -> Asset:
    asset_type = AssetType(str(asset_data["asset_type"]))
    value = str(asset_data["value"]).strip().lower().rstrip(".")
    validation = ScopeValidator().validate(
        db,
        organization_id=job.organization_id,
        target=value,
        scan_zone=_job_scan_zone(db, job),
    )
    in_scope = validation.allowed and validation.scope_id == job.scope_id
    asset, _ = observe_asset(
        db,
        organization_id=job.organization_id,
        asset_type=asset_type,
        value=value,
        source=str(asset_data.get("source", job.adapter_name)),
        scope_id=job.scope_id if in_scope else None,
        known_asset=in_scope,
        metadata=dict(asset_data.get("metadata", {})),
    )
    return asset


def _job_scan_zone(db: Session, job: ScannerJob) -> ScanZone:
    scope = get_scope(db, job.scope_id)
    return scope.scan_zone if scope is not None else ScanZone.EXTERNAL


def reconcile_nmap_cidr_assets(db: Session, *, job: ScannerJob, result: NormalizedScannerResult) -> None:
    if job.adapter_name != "nmap" or not _is_cidr_target(job.target):
        return
    observed_values = {str(asset["value"]).strip().lower().rstrip(".") for asset in result.assets}
    deactivated = deactivate_missing_assets(
        db,
        organization_id=job.organization_id,
        scope_id=job.scope_id,
        source=job.adapter_name,
        observed_values=observed_values,
    )
    if deactivated:
        record_audit_event(
            db,
            action="asset.reconciled",
            affected_object_type="scope",
            affected_object_id=str(job.scope_id),
            result="success",
            metadata={
                "scanner_job_id": job.id,
                "source": job.adapter_name,
                "deactivated_assets": deactivated,
            },
        )


def _is_cidr_target(value: str) -> bool:
    try:
        if "/" not in value:
            return False
        ipaddress.ip_network(value, strict=False)
        return True
    except ValueError:
        return False
