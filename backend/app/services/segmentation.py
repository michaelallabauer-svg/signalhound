"""Bounded TCP checks. No DNS, subprocesses, payloads, ranges or scanner imports."""
import ipaddress
import json
import socket
from datetime import UTC, datetime, timedelta
from typing import Literal
from pydantic import BaseModel, ConfigDict, Field, field_validator
from sqlalchemy import select
from sqlalchemy.orm import Session
from signalhound_node.probe import probe
from app.core.config import get_settings
from app.models.scope import Scope, ScanZone, ScopeTargetType
from app.models.segmentation import SegmentationRule, SegmentationCheck
from app.services.audit import record_audit_event

NOTICE = ('A TCP endpoint check is not proof of whole-zone isolation. A refusal can come from a closed service, '
          'not a firewall. Timeouts and routing errors are inconclusive. The source is the selected executor network namespace; '
          'NAT may change the address seen by the destination.')


def literal_ip(value: str) -> str:
    if '%' in value:
        raise ValueError('Scoped IPv6 addresses are not supported')
    address = ipaddress.ip_address(value)
    if address.is_unspecified or address.is_multicast or address.is_link_local or getattr(address, 'ipv4_mapped', None):
        raise ValueError('Use a unicast IP without link-local or mapped IPv6 addressing')
    if str(address) == '255.255.255.255':
        raise ValueError('Broadcast addresses are not supported')
    return str(address)


class Source(BaseModel):
    model_config = ConfigDict(extra='forbid')
    id: str = Field(min_length=1, max_length=80, pattern=r'^[a-zA-Z0-9_-]+$')
    organization_id: int = Field(gt=0)
    name: str = Field(min_length=1, max_length=160)
    bind_ip: str
    node_id: int | None = Field(default=None, gt=0)
    target_networks: dict[str, str] | None = None
    target_scope_ids: list[int] = Field(min_length=1, max_length=32)
    allowed_ports: list[int] = Field(min_length=1, max_length=16)

    @field_validator('bind_ip')
    @classmethod
    def address(cls, value):
        return literal_ip(value)

    @field_validator('target_scope_ids', 'allowed_ports')
    @classmethod
    def positive_unique(cls, values, info):
        if len(set(values)) != len(values) or any(v <= 0 or (info.field_name == 'allowed_ports' and v > 65535) for v in values):
            raise ValueError('Require distinct positive IDs or TCP ports 1–65535')
        return values


def configured_sources(organization_id: int, db: Session | None = None) -> list[Source]:
    try:
        raw = json.loads(get_settings().segmentation_sources_json)
        if not isinstance(raw, list) or len(raw) > 16:
            raise ValueError()
        sources = [Source.model_validate(value) for value in raw]
        if any(s.node_id is not None or s.target_networks is not None or s.id.startswith("node-") for s in sources):
            raise ValueError()
        if len({s.id for s in sources}) != len(sources):
            raise ValueError()
    except (ValueError, TypeError):
        raise ValueError('Invalid segmentation source configuration; ask the deployment administrator.') from None
    sources = [s for s in sources if s.organization_id == organization_id]
    if db is not None:
        from app.models.nodes import ScannerNode
        for node in db.scalars(select(ScannerNode).where(ScannerNode.organization_id == organization_id, ScannerNode.active.is_(True))):
            sources.append(Source(id=f'node-{node.id}', node_id=node.id, organization_id=organization_id,
                                  name=node.name, bind_ip=node.bind_ip, target_scope_ids=node.target_scope_ids,
                                  allowed_ports=node.allowed_ports, target_networks=node.target_networks))
    return sources


def authorized(db: Session, organization_id: int, source_id: str, scope_id: int, target: str, port: int):
    source = next((s for s in configured_sources(organization_id, db) if s.id == source_id), None)
    if source is None:
        raise ValueError('Scanner source is not authorized for this organization.')
    if scope_id not in source.target_scope_ids or port not in source.allowed_ports:
        raise ValueError('This source is not authorized for the selected target zone and TCP port.')
    scope = db.scalar(select(Scope).where(Scope.id == scope_id).with_for_update().execution_options(populate_existing=True))
    if not scope or scope.organization_id != organization_id or not scope.active or scope.scan_zone != ScanZone.INTERNAL_IT:
        raise ValueError('Target zone must be an active Internal IT scope in this organization.')
    if scope.target_type not in {ScopeTargetType.IP, ScopeTargetType.CIDR}:
        raise ValueError('Target zones must use IP or CIDR scopes; DNS resolution is not allowed.')
    if source.node_id and (source.target_networks or {}).get(str(scope_id)) != scope.target:
        raise ValueError('Node target-zone grant changed; register a new reviewed grant')
    address = ipaddress.ip_address(literal_ip(target))
    network = ipaddress.ip_network(scope.target, strict=False)
    if address not in network:
        raise ValueError('Target IP is outside the explicitly selected target zone.')
    if network.version == 4 and network.prefixlen < 31 and address in {network.network_address, network.broadcast_address}:
        raise ValueError('Network and broadcast addresses are not valid endpoints.')
    if address.version != ipaddress.ip_address(source.bind_ip).version:
        raise ValueError('Source and destination must use the same IP address family.')
    return source, {'id': scope.id, 'name': scope.name, 'target': scope.target, 'scan_zone': scope.scan_zone.value}


def verdict(expected: Literal['ALLOW', 'DENY'], observed: dict):
    state = observed['state']
    if state not in {'TCP_CONNECTED', 'TCP_REFUSED'}:
        return 'ERROR', 'ERROR'
    if expected == 'DENY' and state == 'TCP_REFUSED':
        # A closed service tells us nothing about whether the network boundary enforces denial.
        return 'ERROR', 'ERROR'
    if expected == 'DENY':
        return 'FAIL', 'UNEXPECTED_ACCESS'
    if state == 'TCP_REFUSED':
        return 'FAIL', 'UNEXPECTED_BLOCK'
    return 'PASS', 'PASS'


def check_rule(db: Session, rule: SegmentationRule):
    # Caller holds organization and rule locks; shared cooldown is cross-process on PostgreSQL.
    now = datetime.now(UTC)
    recent = db.scalar(select(SegmentationCheck.created_at).join(SegmentationRule)
                       .where(SegmentationRule.organization_id == rule.organization_id)
                       .order_by(SegmentationCheck.created_at.desc()).limit(1))
    from app.models.nodes import NodeJob, ScannerNode
    remote_started = db.scalar(select(NodeJob.started_at).join(ScannerNode)
        .where(ScannerNode.organization_id == rule.organization_id, NodeJob.started_at.is_not(None))
        .order_by(NodeJob.started_at.desc()).limit(1))
    if any(value and now - value.replace(tzinfo=UTC) < timedelta(seconds=5) for value in (recent, remote_started)):
        raise RuntimeError('Wait five seconds between checks in this organization.')
    expected = {'rule_id': rule.id, 'name': rule.name, 'source': rule.source, 'zone': rule.zone,
                'target': rule.target, 'port': rule.port, 'transport': 'TCP', 'access': rule.expected,
                'rationale': rule.rationale, 'policy_version': 'segmentation-tcp-v1'}
    reason = None
    if rule.source.get('node_id'):
        reason = 'Remote source: queue this rule for its node. Backend execution is forbidden.'
    if not rule.active:
        reason = 'Rule is archived.'
    settings = get_settings()
    if not settings.scanner_execution_enabled or not settings.segmentation_execution_enabled:
        reason = 'Execution is disabled. Both scanner and segmentation execution gates must be enabled by the administrator.'
    try:
        source, zone = authorized(db, rule.organization_id, rule.source_id, rule.scope_id, rule.target, rule.port)
        if source.model_dump(exclude_none=True) != rule.source or zone != rule.zone:
            reason = 'Source or zone configuration changed since preparation. Create a new rule after reviewing the new boundaries.'
    except ValueError as exc:
        reason = str(exc)
    if reason:
        observed = {'state': 'NOT_TESTED', 'attempted': False, 'detail': reason}
        status = outcome = 'NOT_TESTED'
    else:
        observed = probe(source.bind_ip, rule.target, rule.port)
        status, outcome = verdict(rule.expected, observed)
        if rule.expected == 'DENY' and observed['state'] == 'TCP_REFUSED':
            observed['detail'] += ' DENY remains unverified: a closed service is not proof of segmentation.'
    observed['notice'] = NOTICE
    row = SegmentationCheck(rule_id=rule.id, created_at=now, expected=expected, observed=observed, status=status, outcome=outcome)
    db.add(row)
    db.flush()
    record_audit_event(db, action='segmentation.checked', affected_object_type='segmentation_rule',
                      affected_object_id=str(rule.id), result=status,
                      metadata={'check_id': row.id, 'organization_id': rule.organization_id, 'outcome': outcome,
                                'attempted': observed['attempted']})
    db.commit()
    db.refresh(row)
    return row
