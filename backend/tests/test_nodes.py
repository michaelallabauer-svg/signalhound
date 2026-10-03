from datetime import timedelta
import pytest
from sqlalchemy import select,func
from app.core.config import get_settings
from app.models.nodes import ScannerNode,NodeJob
from app.models.scope import Scope
from app.models.segmentation import SegmentationCheck
from app.services import nodes as service
from app.services import segmentation


@pytest.fixture
def node_setup(client,db_session,monkeypatch):
    org=client.post('/api/v1/organizations',json={'name':'Node organization'}).json()['id']
    scope=client.post('/api/v1/scopes',json={'organization_id':org,'name':'Lab','target_type':'CIDR','target':'192.0.2.0/24','scan_zone':'INTERNAL_IT'}).json()['id']
    node,token=service.register(db_session,organization_id=org,name='Lab node',bind_ip='192.0.2.2',scope_ids=[scope],ports=[443]);db_session.commit()
    settings=get_settings()
    for key in ['scanner_execution_enabled','segmentation_execution_enabled','node_execution_enabled']:monkeypatch.setattr(settings,key,True)
    monkeypatch.setattr(settings,'node_allow_insecure_loopback',False);monkeypatch.setattr(settings,'segmentation_sources_json','[]')
    def no_probe(*args):raise AssertionError('Backend executed remote probe')
    monkeypatch.setattr(segmentation,'probe',no_probe)
    payload={'organization_id':org,'name':'Remote boundary','source_id':f'node-{node.id}','scope_id':scope,'target':'192.0.2.10','port':443,'expected':'DENY','rationale':'Authorized boundary must deny access'}
    response=client.post('/api/v1/segmentation/rules',json=payload)
    assert response.status_code==201,response.text
    return dict(node=node,token=token,org=org,scope=scope,rule=response.json(),payload=payload)


def call(client,s,path,payload=None,token=None,https=True):
    return client.post(('https' if https else 'http')+'://testserver/api/v1/nodes/self'+path,headers={'Authorization':'Bearer '+(token or s['token'])},json=payload or {})


def heartbeat(client,s,**changes):
    return call(client,s,'/heartbeat',dict(version=service.VERSION,capabilities=[service.CAPABILITY],execution_enabled=True)|changes)


def queue(client,s):
    return client.post(f"/api/v1/nodes/rules/{s['rule']['id']}/queue",json={'organization_id':s['org']})


def lease(client,s):
    assert heartbeat(client,s).status_code==200
    response=queue(client,s);assert response.status_code==201,response.text
    data=call(client,s,'/pull').json()['lease'];assert data
    return data


def observation():
    return dict(state='TCP_CONNECTED',transport='TCP',target='192.0.2.10',port=443,requested_source_ip='192.0.2.2',actual_source_ip='192.0.2.2',source_port=50000,attempted=True,duration_ms=1,detail='TCP accepted. No application data.')


def start(client,s,l):return call(client,s,f"/jobs/{l['job_id']}/start",{'lease_token':l['lease_token']})
def result(client,s,l,**changes):return call(client,s,f"/jobs/{l['job_id']}/result",{'lease_token':l['lease_token'],'observation':observation()|changes})


def test_lifecycle_provenance_and_idempotency(client,db_session,node_setup):
    s=node_setup;l=lease(client,s)
    assert s['node'].token_hash!=s['token'] and 'target' not in l and 'expected' not in l
    assert call(client,s,'/pull').json()['lease'] is None
    assert result(client,s,l).status_code==409
    authorization=start(client,s,l);assert authorization.status_code==200,authorization.text
    assert authorization.json()['expected']['source']['node_id']==s['node'].id
    assert start(client,s,l).status_code==409
    first=result(client,s,l);assert first.status_code==200,first.text
    assert first.json()['outcome']=='UNEXPECTED_ACCESS'
    assert first.json()['observed']['provenance']=='authenticated_node_report'
    assert result(client,s,l).json()==first.json()
    assert result(client,s,l,duration_ms=2).status_code==409
    assert db_session.scalar(select(func.count(SegmentationCheck.id)))==1
    history=client.get(f"/api/v1/segmentation/rules/{s['rule']['id']}/checks",params={'organization_id':s['org']}).json()
    assert history==[first.json()]
    public=client.get('/api/v1/nodes',params={'organization_id':s['org']}).text+client.get('/api/v1/nodes/jobs',params={'organization_id':s['org']}).text
    for secret in (s['token'],s['node'].token_hash,l['lease_token'],'lease_hash','token_hash'):assert secret not in public


@pytest.mark.parametrize('token,https,code',[('x'*43,True,401),('short',True,401),(None,False,426)])
def test_tls_and_identity(client,node_setup,token,https,code):
    assert call(client,node_setup,'/pull',token=token,https=https).status_code==code


def test_no_public_enrollment(client,node_setup):
    assert client.post('/api/v1/nodes',json={'name':'rogue'}).status_code==405
    assert client.post('/api/v1/nodes/register',json={}).status_code==404


@pytest.mark.parametrize('gate',['scanner_execution_enabled','segmentation_execution_enabled','node_execution_enabled'])
def test_server_gates(client,db_session,node_setup,monkeypatch,gate):
    s=node_setup;l=lease(client,s);monkeypatch.setattr(get_settings(),gate,False)
    assert queue(client,s).status_code==409
    assert call(client,s,'/pull').json()['lease'] is None
    assert start(client,s,l).status_code==409
    assert db_session.get(NodeJob,l['job_id']).status=='CANCELLED'


@pytest.mark.parametrize('changes',[{'version':'0.0.1'},{'capabilities':[]},{'execution_enabled':False}])
def test_node_readiness(client,node_setup,changes):
    s=node_setup;assert queue(client,s).status_code==201
    assert heartbeat(client,s,**changes).json()['execution_allowed'] is False
    assert call(client,s,'/pull').json()['lease'] is None


@pytest.mark.parametrize('stage',['QUEUED','LEASED','RUNNING'])
def test_revocation(client,db_session,node_setup,stage):
    s=node_setup
    if stage=='QUEUED':job_id=queue(client,s).json()['id']
    else:
        l=lease(client,s);job_id=l['job_id']
        if stage=='RUNNING':assert start(client,s,l).status_code==200
    service.revoke(db_session,s['node'].id);db_session.commit()
    assert call(client,s,'/pull').status_code==401
    assert db_session.get(NodeJob,job_id).status=='CANCELLED'
    assert client.get('/api/v1/segmentation/config',params={'organization_id':s['org']}).json()['sources']==[]
    if stage=='RUNNING':assert result(client,s,l).status_code==401


def test_rotation(client,db_session,node_setup):
    s=node_setup;l=lease(client,s)
    node,token=service.rotate(db_session,s['node'].id);db_session.commit()
    assert call(client,s,'/pull').status_code==401
    assert call(client,s,'/pull',token=token).json()['lease'] is None
    assert node.credential_generation==2 and node.last_seen_at is None
    assert db_session.get(NodeJob,l['job_id']).status=='CANCELLED'


@pytest.mark.parametrize('change',['scope_revoked','scope_changed','rule_archived','capability_removed'])
def test_recheck_before_start(client,db_session,node_setup,change):
    s=node_setup;l=lease(client,s)
    if change.startswith('scope'):
        scope=db_session.get(Scope,s['scope'])
        if change=='scope_revoked':scope.active=False
        else:scope.target='192.0.0.0/16'
        db_session.commit()
    elif change=='rule_archived':client.post(f"/api/v1/segmentation/rules/{s['rule']['id']}/archive",json={'organization_id':s['org']})
    else:s['node'].capabilities=[];db_session.commit()
    assert start(client,s,l).status_code==409
    assert result(client,s,l).status_code==409


@pytest.mark.parametrize('stage',['QUEUED','LEASED','RUNNING'])
def test_expiry_never_reexecutes(client,db_session,node_setup,stage):
    s=node_setup
    if stage=='QUEUED':heartbeat(client,s);job_id=queue(client,s).json()['id']
    else:
        l=lease(client,s);job_id=l['job_id']
        if stage=='RUNNING':assert start(client,s,l).status_code==200
    job=db_session.get(NodeJob,job_id);job.expires_at=service.now()-timedelta(seconds=1);db_session.commit()
    assert call(client,s,'/pull').json()['lease'] is None
    assert db_session.get(NodeJob,job_id).status=='EXPIRED'
    if stage=='RUNNING':assert result(client,s,l).status_code==409


@pytest.mark.parametrize('changes,code',[({'target':'192.0.2.11'},409),({'actual_source_ip':'192.0.2.3'},409),({'requested_source_ip':'192.0.2.3'},409),({'port':80},409),({'state':'PASS'},422),({'attempted':False},422),({'duration_ms':-1},422),({'unknown':'command'},422)])
def test_result_validation(client,node_setup,changes,code):
    s=node_setup;l=lease(client,s);assert start(client,s,l).status_code==200
    assert result(client,s,l,**changes).status_code==code


def test_isolation(client,db_session,node_setup):
    s=node_setup;l=lease(client,s)
    org=client.post('/api/v1/organizations',json={'name':'Other node org'}).json()['id']
    scope=client.post('/api/v1/scopes',json={'organization_id':org,'name':'Other lab','target_type':'IP','target':'198.51.100.1','scan_zone':'INTERNAL_IT'}).json()['id']
    _,token=service.register(db_session,organization_id=org,name='Other node',bind_ip='198.51.100.2',scope_ids=[scope],ports=[443]);db_session.commit()
    assert call(client,s,f"/jobs/{l['job_id']}/start",{'lease_token':l['lease_token']},token=token).status_code==409
    assert client.get('/api/v1/nodes/jobs',params={'organization_id':org}).json()==[]
    assert client.post(f"/api/v1/nodes/rules/{s['rule']['id']}/queue",json={'organization_id':org}).status_code==404
    assert start(client,s,l|{'lease_token':'x'*43}).status_code==409


def test_remote_never_runs_on_backend(client,node_setup):
    s=node_setup
    r=client.post(f"/api/v1/segmentation/rules/{s['rule']['id']}/checks",json={'organization_id':s['org']})
    assert r.status_code==201 and r.json()['status']=='NOT_TESTED' and not r.json()['observed']['attempted']


def test_stale_heartbeat_duplicate_queue(client,db_session,node_setup):
    s=node_setup;assert queue(client,s).status_code==201;assert queue(client,s).status_code==409
    heartbeat(client,s);s['node'].last_seen_at=service.now()-timedelta(seconds=91);db_session.commit()
    assert call(client,s,'/pull').json()['lease'] is None
    assert not client.get('/api/v1/nodes',params={'organization_id':s['org']}).json()['nodes'][0]['online']


def test_private_credential_export_is_exclusive(db_session,node_setup,tmp_path):
    import json
    from app.node_admin import write_credentials
    s=node_setup;path=tmp_path/'private.json'
    write_credentials(path,s['node'],s['token'],'https://scanner.example')
    assert path.stat().st_mode&0o777==0o600
    data=json.loads(path.read_text())
    assert data['allowed_networks']=={str(s['scope']):'192.0.2.0/24'}
    with pytest.raises(FileExistsError):write_credentials(path,s['node'],'different','https://scanner.example')
    assert json.loads(path.read_text())['token']==s['token']


def test_organization_cooldown_across_two_nodes(client,db_session,node_setup):
    s=node_setup;l=lease(client,s);assert start(client,s,l).status_code==200
    second,token=service.register(db_session,organization_id=s['org'],name='Second location',bind_ip='192.0.2.3',scope_ids=[s['scope']],ports=[443]);db_session.commit()
    response=client.post('/api/v1/segmentation/rules',json=s['payload']|{'source_id':f'node-{second.id}'})
    other=s|{'node':second,'token':token,'rule':response.json()}
    other_lease=lease(client,other)
    r=start(client,other,other_lease)
    assert r.status_code==409 and 'five seconds' in r.json()['detail']
