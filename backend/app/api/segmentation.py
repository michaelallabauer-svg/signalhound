from datetime import datetime
from typing import Any, Literal
from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, ConfigDict, Field, field_validator
from sqlalchemy import func, select
from sqlalchemy.orm import Session
from app.core.config import get_settings
from app.core.database import get_db
from app.models.organization import Organization
from app.models.segmentation import SegmentationRule, SegmentationCheck
from app.services.audit import record_audit_event
from app.services.segmentation import NOTICE, authorized, check_rule, configured_sources, literal_ip

router = APIRouter(prefix='/segmentation', tags=['network segmentation'])


class OrganizationRequest(BaseModel):
    model_config = ConfigDict(extra='forbid', str_strip_whitespace=True)
    organization_id: int = Field(gt=0)


class RuleCreate(OrganizationRequest):
    name: str = Field(min_length=1, max_length=160)
    source_id: str = Field(min_length=1, max_length=80)
    scope_id: int = Field(gt=0)
    target: str = Field(max_length=45)
    port: int = Field(ge=1, le=65535, strict=True)
    expected: Literal['ALLOW', 'DENY']
    rationale: str = Field(min_length=10, max_length=2000)

    @field_validator('target')
    @classmethod
    def address(cls, value):
        return literal_ip(value)


class RuleRead(RuleCreate):
    model_config = ConfigDict(from_attributes=True)
    id: int
    source: dict[str, Any]
    zone: dict[str, Any]
    active: bool
    created_at: datetime


class CheckRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: int
    rule_id: int
    created_at: datetime
    status: str
    outcome: str
    expected: dict[str, Any]
    observed: dict[str, Any]


def organization(db, organization_id, lock=False):
    statement = select(Organization).where(Organization.id == organization_id)
    if lock:
        statement = statement.with_for_update()
    if not db.scalar(statement):
        raise HTTPException(404, 'Organization not found')


def rule_for_org(db, rule_id, organization_id, lock=False):
    organization(db, organization_id, lock)
    statement = select(SegmentationRule).where(SegmentationRule.id == rule_id,
                                              SegmentationRule.organization_id == organization_id)
    if lock:
        statement = statement.with_for_update().execution_options(populate_existing=True)
    row = db.scalar(statement)
    if not row:
        raise HTTPException(404, 'Rule not found in organization')
    return row


@router.get('/config')
def config(organization_id: int = Query(gt=0), db: Session = Depends(get_db)):
    organization(db, organization_id)
    settings = get_settings()
    try:
        sources = [s.model_dump(exclude_none=True) for s in configured_sources(organization_id, db)]
        error = None
    except ValueError as exc:
        sources, error = [], str(exc)
    return {'enabled': settings.scanner_execution_enabled and settings.segmentation_execution_enabled and error is None,
            'node_execution_enabled': settings.node_execution_enabled, 'sources': sources, 'configuration_error': error, 'notice': NOTICE, 'cooldown_seconds': 5}


@router.get('/rules', response_model=list[RuleRead])
def rules(organization_id: int = Query(gt=0), limit: int = Query(50, ge=1, le=100), offset: int = Query(0, ge=0),
          db: Session = Depends(get_db)):
    organization(db, organization_id)
    return list(db.scalars(select(SegmentationRule).where(SegmentationRule.organization_id == organization_id)
                          .order_by(SegmentationRule.id.desc()).offset(offset).limit(limit)))


@router.post('/rules', response_model=RuleRead, status_code=201)
def create(payload: RuleCreate, db: Session = Depends(get_db)):
    organization(db, payload.organization_id, lock=True)
    count = db.scalar(select(func.count(SegmentationRule.id)).where(
        SegmentationRule.organization_id == payload.organization_id, SegmentationRule.active.is_(True)))
    if count >= 100:
        raise HTTPException(409, 'Maximum 100 active rules per organization; archive obsolete rules first.')
    try:
        source, zone = authorized(db, payload.organization_id, payload.source_id, payload.scope_id, payload.target, payload.port)
    except ValueError as exc:
        raise HTTPException(422, str(exc)) from exc
    rule = SegmentationRule(**payload.model_dump(), source=source.model_dump(exclude_none=True), zone=zone)
    db.add(rule)
    db.flush()
    record_audit_event(db, action='segmentation.prepared', affected_object_type='segmentation_rule',
                      affected_object_id=str(rule.id), result='success', metadata=payload.model_dump())
    db.commit()
    db.refresh(rule)
    return rule


@router.post('/rules/{rule_id}/archive', response_model=RuleRead)
def archive(rule_id: int, payload: OrganizationRequest, db: Session = Depends(get_db)):
    rule = rule_for_org(db, rule_id, payload.organization_id, lock=True)
    if rule.active:
        rule.active = False
        record_audit_event(db, action='segmentation.archived', affected_object_type='segmentation_rule',
                          affected_object_id=str(rule.id), result='success', metadata={'organization_id': payload.organization_id})
        db.commit()
        db.refresh(rule)
    return rule


@router.get('/rules/{rule_id}/checks', response_model=list[CheckRead])
def history(rule_id: int, organization_id: int = Query(gt=0), limit: int = Query(20, ge=1, le=100),
            offset: int = Query(0, ge=0), db: Session = Depends(get_db)):
    rule_for_org(db, rule_id, organization_id)
    return list(db.scalars(select(SegmentationCheck).where(SegmentationCheck.rule_id == rule_id)
                          .order_by(SegmentationCheck.id.desc()).offset(offset).limit(limit)))


@router.post('/rules/{rule_id}/checks', response_model=CheckRead, status_code=201)
def execute(rule_id: int, payload: OrganizationRequest, db: Session = Depends(get_db)):
    rule = rule_for_org(db, rule_id, payload.organization_id, lock=True)
    try:
        return check_rule(db, rule)
    except RuntimeError as exc:
        raise HTTPException(429, str(exc), headers={'Retry-After': '5'}) from exc
