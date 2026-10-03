import pytest
from sqlalchemy import func, select
from app.models.asset_context import AssetBusinessContext, AssetContextHistory, Site
from app.models.audit_log import AuditLog
from app.models.risk import RiskSnapshot
from app.models.scanner_job import ScannerJob
from tests.test_findings_api import create_asset
from tests.test_intelligence import finding


def context(client, org, asset):
    return client.get(f'/api/v1/assets/{asset}/context', params={'organization_id':org})


def patch(client, org, asset, revision, **changes):
    return client.patch(f'/api/v1/assets/{asset}/context', json={'organization_id':org,'expected_revision':revision,**changes})


def create_site(client, org, name='Main Office'):
    response=client.post('/api/v1/sites',json={'organization_id':org,'name':name,'description':'Primary office'})
    assert response.status_code==201,response.text
    return response.json()


def change_site(client, org, site, **changes):
    return client.patch(f"/api/v1/sites/{site['id']}",json={'organization_id':org,'expected_revision':site['revision'],**changes})


def test_defaults_are_unknown_and_reads_do_not_write(client,db_session):
    org,asset=create_asset(client)
    row=context(client,org,asset).json()
    assert row['criticality'] is None and row['environment']=='UNKNOWN'
    assert row['revision']==0 and row['site'] is None
    assert row['technical_owner'] is row['responsible_team'] is None
    assert db_session.scalar(select(func.count(AssetBusinessContext.asset_id)))==0
    assert db_session.scalar(select(func.count(AssetContextHistory.id)))==0


def test_patch_history_clear_noop_and_scanner_separation(client,db_session):
    org,asset=create_asset(client)
    site=create_site(client,org)
    response=patch(client,org,asset,0,criticality='HIGH',environment='PRODUCTION',technical_owner='  Technical Lead  ',
                   organizational_owner='Operations',responsible_team='Platform',site_id=site['id'],notes='Customer-facing business service')
    assert response.status_code==200,response.text
    first=response.json()
    assert first['revision']==1 and first['technical_owner']=='Technical Lead'
    second=patch(client,org,asset,1,responsible_team='SRE').json()
    assert second['technical_owner']=='Technical Lead' and second['criticality']=='HIGH'
    assert second['revision']==2
    assert patch(client,org,asset,2,responsible_team=' SRE ').json()['revision']==2
    response=client.post('/api/v1/assets',json={'organization_id':org,'asset_type':'HOST','value':'app.example.com','source':'nmap','metadata':{'criticality':'LOW','technical_owner':'scanner'}})
    assert response.status_code==201
    assert context(client,org,asset).json()==second
    cleared=patch(client,org,asset,2,criticality=None,technical_owner=' ',site_id=None,environment='UNKNOWN').json()
    assert cleared['criticality'] is None and cleared['technical_owner'] is None and cleared['site_id'] is None
    rows=client.get(f'/api/v1/assets/{asset}/context/history',params={'organization_id':org}).json()
    assert [r['revision'] for r in rows]==[3,2,1]
    assert rows[-1]['after']==first and rows[0]['before']==second
    assert rows[0]['after']==cleared
    actions=db_session.scalars(select(AuditLog).where(AuditLog.action=='asset.context.changed')).all()
    assert len(actions)==3 and actions[1].metadata_['changed_fields']==['responsible_team']
    page=client.get(f'/api/v1/assets/{asset}/context/history',params={'organization_id':org,'limit':1,'offset':2}).json()
    assert page[0]['revision']==1
    assert db_session.scalar(select(func.count(ScannerJob.id)))==0


def test_stale_edits_rejected_without_history_overwrite(client,db_session):
    org,asset=create_asset(client)
    assert patch(client,org,asset,0,technical_owner='First editor').status_code==200
    assert patch(client,org,asset,0,responsible_team='Second editor').status_code==409
    assert context(client,org,asset).json()['responsible_team'] is None
    assert db_session.scalar(select(func.count(AssetContextHistory.id)))==1


def test_site_lifecycle_unique_normalization_and_historical_labels(client,db_session):
    org,asset=create_asset(client)
    site=create_site(client,org,'  Main   Office  ')
    assert site['name']=='Main Office'
    assert client.post('/api/v1/sites',json={'organization_id':org,'name':'main office'}).status_code==409
    saved=patch(client,org,asset,0,site_id=site['id']).json()
    renamed=change_site(client,org,site,name='Headquarters').json()
    assert renamed['revision']==2
    assert context(client,org,asset).json()['site']['name']=='Headquarters'
    old=client.get(f'/api/v1/assets/{asset}/context/history',params={'organization_id':org}).json()[0]
    assert old['after']['site']['name']=='Main Office'
    archived=change_site(client,org,renamed,active=False).json()
    assert context(client,org,asset).json()['site']['active'] is False
    assert patch(client,org,asset,1,site_id=site['id'],notes='Keeping archived assignment').status_code==200
    other=client.post('/api/v1/assets',json={'organization_id':org,'asset_type':'HOST','value':'other.example.com','source':'manual'}).json()
    assert patch(client,org,other['id'],0,site_id=site['id']).status_code==422
    assert client.get('/api/v1/sites',params={'organization_id':org,'active':True}).json()==[]
    restored=change_site(client,org,archived,active=True).json()
    assert restored['active'] is True
    assert patch(client,org,other['id'],0,site_id=site['id']).status_code==200
    assert change_site(client,org,site,name='Stale overwrite').status_code==409
    assert len(db_session.scalars(select(AuditLog).where(AuditLog.action=='site.changed')).all())==3


def test_organization_isolation_and_validation(client,db_session):
    org,asset=create_asset(client)
    other=client.post('/api/v1/organizations',json={'name':'Other organization'}).json()['id']
    foreign=create_site(client,other)
    assert context(client,other,asset).status_code==404
    assert patch(client,other,asset,0,notes='Wrong org').status_code==404
    assert client.get(f'/api/v1/assets/{asset}/context/history',params={'organization_id':other}).status_code==404
    assert patch(client,org,asset,0,site_id=foreign['id']).status_code==404
    assert change_site(client,org,foreign,name='Wrong org').status_code==404
    assert client.get('/api/v1/sites',params={'organization_id':org}).json()==[]
    local=create_site(client,org) # Same name in another organization is allowed.
    assert local['id']!=foreign['id']
    for fields in [{'criticality':'UNKNOWN'},{'environment':None},{'environment':'OT'}, {'technical_owner':'x'*161}, {'site_id':-1}, {'known_asset':True}, {}]:
        assert patch(client,org,asset,0,**fields).status_code==422
    for fields in [{'name':'   '},{'name':None},{'active':None},{}]:
        assert change_site(client,org,local,**fields).status_code==422
    assert db_session.scalar(select(func.count(AssetContextHistory.id)))==0


def test_risk_inherits_current_context_but_preserves_prior_snapshots(client,db_session):
    org,asset=create_asset(client)
    finding(client,org,asset)
    path=f'/api/v1/assets/{asset}/risk'
    old=client.post(path,json={'organization_id':org}).json()
    assert old['context']['criticality']=='UNKNOWN'
    site=create_site(client,org)
    patch(client,org,asset,0,criticality='CRITICAL',environment='PRODUCTION',site_id=site['id'],responsible_team='Operations')
    inherited=client.post(path,json={'organization_id':org}).json()
    assert inherited['algorithm_version']==old['algorithm_version']=='exposure-v1.0'
    assert inherited['context']['criticality']=='CRITICAL' and inherited['context']['criticality_source']=='asset_context'
    assert inherited['context']['business_context']['revision']==1
    component=next(c for c in inherited['result']['entries'][0]['components'] if c['name']=='criticality')
    assert component['lower']==component['upper']==10 and 'revision 1' in component['source']
    override=client.post(path,json={'organization_id':org,'criticality':'LOW','rationale':'Temporary bounded what-if scenario'}).json()
    assert override['context']['criticality_source']=='snapshot_override'
    assert context(client,org,asset).json()['criticality']=='CRITICAL'
    unknown=client.post(path,json={'organization_id':org,'criticality':'UNKNOWN'}).json()
    assert unknown['context']['criticality']=='UNKNOWN' # Explicit UNKNOWN is not inheritance.
    patch(client,org,asset,1,criticality='MEDIUM')
    change_site(client,org,site,name='Renamed Location')
    assert db_session.get(RiskSnapshot,inherited['id']).context==inherited['context']
    assert db_session.get(RiskSnapshot,old['id']).context==old['context']
    assert inherited['context']['business_context']['site']['name']=='Main Office'
    assert client.post(path,json={'organization_id':org,'criticality':'HIGH'}).status_code==422


def test_site_unicode_casefold_and_nullable_clear(client):
    org,asset=create_asset(client)
    site=create_site(client,org,'Straße')
    assert client.post('/api/v1/sites',json={'organization_id':org,'name':'STRASSE'}).status_code==409
    assert change_site(client,org,site,description='   ').json()['description'] is None
    long_site=create_site(client,org,'ﬃ'*160)
    assert long_site['name']=='ﬃ'*160
