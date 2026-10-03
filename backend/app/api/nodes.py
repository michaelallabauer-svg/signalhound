import hmac
import ipaddress
from typing import Literal
from fastapi import APIRouter, Depends, Header, HTTPException, Query, Request
from pydantic import BaseModel, ConfigDict, Field, model_validator
from sqlalchemy import select
from sqlalchemy.orm import Session
from app.api.segmentation import CheckRead, OrganizationRequest, organization, rule_for_org
from app.core.config import get_settings
from app.core.database import get_db
from app.models.nodes import ScannerNode, NodeJob
from app.models.organization import Organization
from app.services import nodes as service

router=APIRouter(prefix='/nodes',tags=['distributed scanner nodes'])


class Heartbeat(BaseModel):
    model_config=ConfigDict(extra='forbid')
    version:str=Field(min_length=1,max_length=40)
    capabilities:list[Literal['tcp_connect_v1']]=Field(max_length=1)
    execution_enabled:bool=Field(strict=True)


class Lease(BaseModel):
    model_config=ConfigDict(extra='forbid')
    lease_token:str=Field(min_length=40,max_length=100)


class Observation(BaseModel):
    model_config=ConfigDict(extra='forbid')
    state:Literal['TCP_CONNECTED','TCP_REFUSED','TIMEOUT','SOURCE_ERROR','NETWORK_ERROR']
    transport:Literal['TCP']
    target:str=Field(max_length=45)
    port:int=Field(ge=1,le=65535,strict=True)
    requested_source_ip:str=Field(max_length=45)
    actual_source_ip:str|None=Field(max_length=45)
    source_port:int|None=Field(ge=1,le=65535,strict=True)
    attempted:bool=Field(strict=True)
    duration_ms:int=Field(ge=0,le=10000,strict=True)
    detail:str=Field(min_length=1,max_length=500)

    @model_validator(mode='after')
    def consistent(self):
        if self.state=='SOURCE_ERROR':
            if self.attempted or self.actual_source_ip is not None or self.source_port is not None:
                raise ValueError('Source failure must not claim a connection or bound source')
        elif not self.attempted or self.actual_source_ip is None or self.source_port is None:
            raise ValueError('Connection observations require the bound source and attempted flag')
        return self


class Result(Lease):
    observation:Observation


def secure_transport(request:Request):
    if request.url.scheme=='https': return
    settings=get_settings()
    try: loopback=ipaddress.ip_address(request.client.host).is_loopback if request.client else False
    except ValueError: loopback=False
    if not(settings.node_allow_insecure_loopback and loopback and request.url.hostname in {'localhost','127.0.0.1','::1'}):
        raise HTTPException(426,'Node protocol requires HTTPS with a trusted certificate')


def authenticated(request:Request, authorization:str|None=Header(default=None), db:Session=Depends(get_db)):
    secure_transport(request)
    if not authorization or not authorization.startswith('Bearer ') or not 40<=len(authorization[7:])<=100:
        raise HTTPException(401,'Invalid node credentials')
    token_hash=service.digest(authorization[7:])
    node=db.scalar(select(ScannerNode).where(ScannerNode.token_hash==token_hash))
    if not node: raise HTTPException(401,'Invalid node credentials')
    # All mutating node paths take organization -> node -> job/rule/scope locks.
    db.scalar(select(Organization).where(Organization.id==node.organization_id).with_for_update())
    node=db.scalar(select(ScannerNode).where(ScannerNode.id==node.id).with_for_update().execution_options(populate_existing=True))
    if not node.active or not hmac.compare_digest(node.token_hash,token_hash):
        raise HTTPException(401,'Invalid node credentials')
    return node


def node_read(node):
    return {'id':node.id,'organization_id':node.organization_id,'name':node.name,'bind_ip':node.bind_ip,
            'target_scope_ids':node.target_scope_ids,'allowed_ports':node.allowed_ports,'capabilities':node.capabilities,
            'active':node.active,'credential_generation':node.credential_generation,'last_seen_at':node.last_seen_at,
            'version':node.version,'reported_capabilities':node.reported_capabilities,'execution_enabled':node.execution_enabled,
            'online':service.online(node),'ready':service.ready(node)}


def job_read(job):
    return {'id':job.id,'node_id':job.node_id,'rule_id':job.rule_id,'status':service.effective_status(job),
            'created_at':job.created_at,'expires_at':job.expires_at,'started_at':job.started_at,'completed_at':job.completed_at,
            'expected':job.expected,'check_id':job.check_id,'message':job.message or (
                'Deadline expired; execution/result may be unknown. No automatic retry.' if service.effective_status(job)=='EXPIRED' else None)}


@router.get('')
def nodes(organization_id:int=Query(gt=0),limit:int=Query(50,ge=1,le=100),offset:int=Query(0,ge=0),db:Session=Depends(get_db)):
    organization(db,organization_id)
    rows=db.scalars(select(ScannerNode).where(ScannerNode.organization_id==organization_id).order_by(ScannerNode.id.desc()).offset(offset).limit(limit))
    return {'enabled':service.gates(),'required_version':service.VERSION,'nodes':[node_read(n) for n in rows]}


@router.get('/jobs')
def jobs(organization_id:int=Query(gt=0),rule_id:int|None=None,limit:int=Query(20,ge=1,le=100),offset:int=Query(0,ge=0),db:Session=Depends(get_db)):
    organization(db,organization_id)
    statement=select(NodeJob).join(ScannerNode).where(ScannerNode.organization_id==organization_id)
    if rule_id is not None:
        rule_for_org(db,rule_id,organization_id)
        statement=statement.where(NodeJob.rule_id==rule_id)
    return [job_read(j) for j in db.scalars(statement.order_by(NodeJob.id.desc()).offset(offset).limit(limit))]


@router.post('/rules/{rule_id}/queue',status_code=201)
def queue(rule_id:int,payload:OrganizationRequest,db:Session=Depends(get_db)):
    rule=rule_for_org(db,rule_id,payload.organization_id,lock=True)
    node_id=rule.source.get('node_id')
    node=db.scalar(select(ScannerNode).where(ScannerNode.id==node_id).with_for_update()) if node_id else None
    if not node or node.organization_id!=payload.organization_id: raise HTTPException(422,'Rule is not assigned to an authorized node')
    try: job=service.queue(db,node,rule)
    except ValueError as exc:
        db.commit();raise HTTPException(409,str(exc)) from exc
    db.commit();db.refresh(job)
    return job_read(job)


@router.post('/self/heartbeat')
def heartbeat(payload:Heartbeat,node:ScannerNode=Depends(authenticated),db:Session=Depends(get_db)):
    node.last_seen_at=service.now();node.version=payload.version;node.reported_capabilities=payload.capabilities;node.execution_enabled=payload.execution_enabled
    db.commit()
    return {'node_id':node.id,'required_version':service.VERSION,'protocol_version':1,'execution_allowed':service.gates() and service.ready(node)}


@router.post('/self/pull')
def pull(node:ScannerNode=Depends(authenticated),db:Session=Depends(get_db)):
    result=service.pull(db,node);db.commit()
    return {'lease':result}


@router.post('/self/jobs/{job_id}/start')
def start(job_id:int,payload:Lease,node:ScannerNode=Depends(authenticated),db:Session=Depends(get_db)):
    try:
        job=service.leased_job(db,node,job_id,payload.lease_token)
        result=service.start(db,node,job)
    except ValueError as exc:
        db.commit();raise HTTPException(409,str(exc)) from exc
    db.commit();return result


@router.post('/self/jobs/{job_id}/result',response_model=CheckRead)
def result(job_id:int,payload:Result,node:ScannerNode=Depends(authenticated),db:Session=Depends(get_db)):
    try:
        job=service.leased_job(db,node,job_id,payload.lease_token)
        check=service.submit(db,node,job,payload.observation.model_dump())
    except ValueError as exc:
        db.commit();raise HTTPException(409,str(exc)) from exc
    db.commit();db.refresh(check);return check
