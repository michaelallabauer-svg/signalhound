"""Deployment-admin node identity; short, non-retryable pull/start/result protocol."""
import hashlib
import hmac
import json
import secrets
from datetime import UTC, datetime, timedelta
from sqlalchemy import select, func
from sqlalchemy.orm import Session
from app.core.config import get_settings
from app.models.nodes import ScannerNode, NodeJob
from app.models.organization import Organization
from app.models.scope import Scope, ScanZone, ScopeTargetType
from app.models.segmentation import SegmentationRule, SegmentationCheck
from app.services.audit import record_audit_event
from app.services.segmentation import Source, authorized, verdict, NOTICE

VERSION = '1.0.0'
CAPABILITY = 'tcp_connect_v1'
PENDING = ('QUEUED', 'LEASED', 'RUNNING')


def now(): return datetime.now(UTC)
def utc(value): return value.replace(tzinfo=UTC) if value.tzinfo is None else value.astimezone(UTC)
def digest(value): return hashlib.sha256(value.encode()).hexdigest()


def audit(db, action, node, job=None, result='success'):
    record_audit_event(db, action='node.'+action, affected_object_type='scanner_node', affected_object_id=str(node.id),
                      result=result, metadata={'organization_id':node.organization_id, 'job_id':job.id if job else None})


def register(db: Session, *, organization_id: int, name: str, bind_ip: str, scope_ids: list[int], ports: list[int]):
    if not db.scalar(select(Organization).where(Organization.id == organization_id).with_for_update()):
        raise ValueError('Organization not found')
    source = Source(id='validate', organization_id=organization_id, name=name.strip(), bind_ip=bind_ip,
                    target_scope_ids=scope_ids, allowed_ports=ports)
    networks={}
    for scope_id in source.target_scope_ids:
        scope = db.get(Scope, scope_id)
        if not scope or scope.organization_id != organization_id or not scope.active or scope.scan_zone != ScanZone.INTERNAL_IT or scope.target_type not in {ScopeTargetType.IP, ScopeTargetType.CIDR}:
            raise ValueError('Every grant must reference an active Internal IT IP/CIDR scope in this organization')
        networks[str(scope_id)]=scope.target
    if db.scalar(select(func.count(ScannerNode.id)).where(ScannerNode.organization_id == organization_id, ScannerNode.active.is_(True))) >= 16:
        raise ValueError('Maximum 16 active nodes per organization')
    token = secrets.token_urlsafe(32)
    node = ScannerNode(organization_id=organization_id, name=source.name, bind_ip=source.bind_ip,
                       target_scope_ids=source.target_scope_ids, target_networks=networks, allowed_ports=source.allowed_ports,
                       capabilities=[CAPABILITY], token_hash=digest(token), active=True,
                       reported_capabilities=[], execution_enabled=False)
    db.add(node); db.flush(); audit(db,'registered',node)
    return node, token


def locked_node(db, node_id):
    row = db.get(ScannerNode, node_id)
    if not row: raise ValueError('Node not found')
    db.scalar(select(Organization).where(Organization.id == row.organization_id).with_for_update())
    return db.scalar(select(ScannerNode).where(ScannerNode.id == node_id).with_for_update().execution_options(populate_existing=True))


def cancel_jobs(db, node, reason):
    for job in db.scalars(select(NodeJob).where(NodeJob.node_id == node.id, NodeJob.status.in_(PENDING)).with_for_update()):
        job.status = 'CANCELLED'; job.message = reason; job.completed_at = now()
        audit(db,'job.cancelled',node,job)


def revoke(db, node_id):
    node = locked_node(db,node_id)
    node.active = False; node.execution_enabled = False
    cancel_jobs(db,node,'Node revoked; any previously started network activity cannot be recalled.')
    audit(db,'revoked',node)
    return node


def rotate(db, node_id):
    node = locked_node(db,node_id)
    if not node.active: raise ValueError('Revoked identities cannot be restored; register a new node')
    token = secrets.token_urlsafe(32)
    node.token_hash = digest(token); node.credential_generation += 1
    node.last_seen_at = None; node.execution_enabled = False
    cancel_jobs(db,node,'Credentials rotated; a new heartbeat and explicit new job are required.')
    audit(db,'credentials.rotated',node)
    return node, token


def online(node):
    return bool(node.active and node.last_seen_at and now()-utc(node.last_seen_at) < timedelta(seconds=90))


def gates():
    settings=get_settings()
    return settings.node_execution_enabled and settings.scanner_execution_enabled and settings.segmentation_execution_enabled


def ready(node):
    return online(node) and node.execution_enabled and node.version == VERSION and CAPABILITY in node.capabilities and CAPABILITY in node.reported_capabilities


def effective_status(job):
    return 'EXPIRED' if job.status in PENDING and utc(job.expires_at) <= now() else job.status


def expire(db,node):
    for job in db.scalars(select(NodeJob).where(NodeJob.node_id==node.id,NodeJob.status.in_(PENDING)).with_for_update()):
        if utc(job.expires_at) <= now():
            job.status='EXPIRED'; job.completed_at=now()
            job.message='Deadline expired. Execution/result may be unknown; never automatically reassigned or retried.'
            audit(db,'job.expired',node,job)
    db.flush()  # Autoflush is disabled; expired jobs must not be selected again.


def validate_rule(db, node, rule):
    if not gates(): raise ValueError('Server execution gates are disabled')
    if not node.active: raise ValueError('Node revoked')
    if not rule or rule.organization_id != node.organization_id or not rule.active:
        raise ValueError('Rule is missing, archived or belongs to another organization')
    if rule.source.get('node_id') != node.id or rule.source_id != f'node-{node.id}':
        raise ValueError('Rule is assigned to a different execution source')
    if CAPABILITY not in node.capabilities: raise ValueError('Capability not authorized')
    source,zone=authorized(db,rule.organization_id,rule.source_id,rule.scope_id,rule.target,rule.port)
    if source.model_dump(exclude_none=True)!=rule.source or zone!=rule.zone:
        raise ValueError('Rule source or zone authorization changed; prepare a new rule')


def expected_snapshot(rule):
    return {'rule_id':rule.id,'name':rule.name,'source':rule.source,'zone':rule.zone,'target':rule.target,
            'port':rule.port,'transport':'TCP','access':rule.expected,'rationale':rule.rationale,
            'policy_version':'segmentation-tcp-v1','capability':CAPABILITY,'protocol_version':1}


def queue(db,node,rule):
    validate_rule(db,node,rule)
    expire(db,node)
    if db.scalar(select(NodeJob.id).where(NodeJob.rule_id==rule.id,NodeJob.status.in_(PENDING)).limit(1)):
        raise ValueError('This rule already has an outstanding node job')
    count=db.scalar(select(func.count(NodeJob.id)).where(NodeJob.node_id==node.id,NodeJob.status.in_(PENDING)))
    if count>=100: raise ValueError('Node queue limit reached (100 outstanding jobs)')
    job=NodeJob(node_id=node.id,rule_id=rule.id,status='QUEUED',expected=expected_snapshot(rule),created_at=now(),expires_at=now()+timedelta(minutes=10))
    db.add(job);db.flush();audit(db,'job.queued',node,job)
    return job


def pull(db,node):
    expire(db,node)
    if not gates() or not ready(node): return None
    if db.scalar(select(NodeJob.id).where(NodeJob.node_id==node.id,NodeJob.status.in_(['LEASED','RUNNING'])).limit(1)): return None
    for job in db.scalars(select(NodeJob).where(NodeJob.node_id==node.id,NodeJob.status=='QUEUED').order_by(NodeJob.id).with_for_update()):
        rule=db.get(SegmentationRule,job.rule_id)
        try: validate_rule(db,node,rule)
        except ValueError as exc:
            job.status='CANCELLED';job.message=str(exc);job.completed_at=now();audit(db,'job.cancelled',node,job)
            continue
        token=secrets.token_urlsafe(32)
        job.lease_hash=digest(token);job.status='LEASED';job.expires_at=now()+timedelta(seconds=60)
        audit(db,'job.leased',node,job)
        # No target payload here: a separate start authorization is required.
        return {'job_id':job.id,'lease_token':token,'expires_at':job.expires_at,'capability':CAPABILITY}
    return None


def leased_job(db,node,job_id,token):
    job=db.scalar(select(NodeJob).where(NodeJob.id==job_id,NodeJob.node_id==node.id).with_for_update().execution_options(populate_existing=True))
    if not job or not job.lease_hash or not hmac.compare_digest(job.lease_hash,digest(token)):
        raise ValueError('Job or lease not authorized')
    return job


def start(db,node,job):
    expire(db,node)
    if job.status!='LEASED': raise ValueError('Job is not an unexpired lease; do not retry execution')
    if not ready(node): raise ValueError('Node heartbeat, version, capability or local execution gate is not ready')
    rule=db.get(SegmentationRule,job.rule_id)
    try: validate_rule(db,node,rule)
    except ValueError as exc:
        job.status='CANCELLED';job.message=str(exc);job.completed_at=now();audit(db,'job.cancelled',node,job)
        raise
    recent=db.scalar(select(NodeJob.started_at).join(ScannerNode).where(ScannerNode.organization_id==node.organization_id,NodeJob.started_at.is_not(None)).order_by(NodeJob.started_at.desc()).limit(1))
    recent_check=db.scalar(select(SegmentationCheck.created_at).join(SegmentationRule).where(SegmentationRule.organization_id==node.organization_id).order_by(SegmentationCheck.created_at.desc()).limit(1))
    if any(value and now()-utc(value)<timedelta(seconds=5) for value in (recent,recent_check)):
        raise ValueError('Wait five seconds between checks in this organization; no execution was authorized')
    job.status='RUNNING';job.started_at=now();job.expires_at=now()+timedelta(seconds=15)
    job.expected={**job.expected,'node_version':node.version,'credential_generation':node.credential_generation}
    audit(db,'job.started',node,job)
    return {'job_id':job.id,'node_id':node.id,'expected':job.expected,'execute_within_seconds':3,
            'result_deadline':job.expires_at,'timeout_seconds':2,'protocol_version':1}


def submit(db,node,job,observation):
    result_hash=digest(json.dumps(observation,sort_keys=True,separators=(',',':')))
    if job.status=='COMPLETED':
        if job.result_hash!=result_hash: raise ValueError('Conflicting duplicate result')
        return db.get(SegmentationCheck,job.check_id)
    expire(db,node)
    if job.status!='RUNNING': raise ValueError('No active execution authorization; result rejected')
    expected=job.expected
    if observation['target']!=expected['target'] or observation['port']!=expected['port'] or observation['requested_source_ip']!=expected['source']['bind_ip']:
        raise ValueError('Result does not match the authorized endpoint/source')
    if observation['state']!='SOURCE_ERROR' and observation['actual_source_ip']!=expected['source']['bind_ip']:
        raise ValueError('Result bound source does not match authorization')
    status,outcome=verdict(expected['access'],observation)
    observed={**observation,'notice':NOTICE,'node_id':node.id,'node_job_id':job.id,
              'node_version':expected['node_version'],'provenance':'authenticated_node_report',
              'received_at':now().isoformat()}
    if expected['access']=='DENY' and observation['state']=='TCP_REFUSED':
        observed['detail']+=' DENY remains unverified; a closed service is not proof of segmentation.'
    check=SegmentationCheck(rule_id=job.rule_id,created_at=job.started_at,status=status,outcome=outcome,
                            expected=expected,observed=observed)
    db.add(check);db.flush()
    job.check_id=check.id;job.result_hash=result_hash;job.status='COMPLETED';job.completed_at=now()
    audit(db,'job.completed',node,job,status)
    return check
