import json
import socket
from datetime import timedelta
import pytest
from sqlalchemy import select, func
from app.core.config import get_settings
from app.models.scope import Scope
from app.models.segmentation import SegmentationCheck, SegmentationRule
from app.models.scanner_job import ScannerJob
from app.models.audit_log import AuditLog
from app.services import segmentation as service


@pytest.fixture
def setup(client, monkeypatch):
    org = client.post('/api/v1/organizations', json={'name': 'Segmentation test'}).json()['id']
    scope = client.post('/api/v1/scopes', json={'organization_id': org, 'name': 'Application zone',
        'target_type': 'CIDR', 'target': '192.0.2.0/24', 'scan_zone': 'INTERNAL_IT'}).json()['id']
    source = {'id': 'backend-lab', 'organization_id': org, 'name': 'Lab backend', 'bind_ip': '192.0.2.2',
              'target_scope_ids': [scope], 'allowed_ports': [443]}
    settings = get_settings()
    monkeypatch.setattr(settings, 'segmentation_sources_json', json.dumps([source]))
    monkeypatch.setattr(settings, 'segmentation_execution_enabled', True)
    monkeypatch.setattr(settings, 'scanner_execution_enabled', True)
    def forbidden(*args, **kwargs):
        raise AssertionError('A test attempted unexpected network traffic')
    monkeypatch.setattr(service, 'probe', forbidden)
    return {'organization_id': org, 'name': 'Web boundary', 'source_id': source['id'], 'scope_id': scope,
            'target': '192.0.2.10', 'port': 443, 'expected': 'DENY', 'rationale': 'Approved lab boundary policy'}, source


def create(client, payload):
    response = client.post('/api/v1/segmentation/rules', json=payload)
    assert response.status_code == 201, response.text
    return response.json()


def run(client, payload, row):
    return client.post(f"/api/v1/segmentation/rules/{row['id']}/checks", json={'organization_id':payload['organization_id']})


def test_preparation_no_traffic_immutable_history_and_archive(client, db_session, setup, monkeypatch):
    payload, source = setup
    row = create(client, payload)
    assert row['source'] == source and row['zone']['target'] == '192.0.2.0/24'
    assert db_session.scalar(select(func.count(SegmentationCheck.id))) == 0
    assert client.patch(f"/api/v1/segmentation/rules/{row['id']}", json={'expected':'ALLOW'}).status_code == 404
    monkeypatch.setattr(service, 'probe', lambda *args: {'state':'TCP_CONNECTED','attempted':True,'detail':'Connected','actual_source_ip':source['bind_ip']})
    result = run(client,payload,row)
    assert result.status_code == 201, result.text
    first = result.json()
    assert (first['status'],first['outcome']) == ('FAIL','UNEXPECTED_ACCESS')
    assert first['expected']['access'] == 'DENY' and first['expected']['source'] == source
    base = f"/api/v1/segmentation/rules/{row['id']}"
    assert run(client,payload,row).status_code == 429
    assert client.post(base+'/archive',json={'organization_id':payload['organization_id']}).json()['active'] is False
    history = client.get(base+'/checks',params={'organization_id':payload['organization_id']}).json()
    assert history == [first]
    assert client.get(base+'/checks',params={'organization_id':payload['organization_id'],'offset':1}).json() == []
    saved=db_session.get(SegmentationCheck,first['id']); saved.created_at -= timedelta(seconds=10); db_session.commit()
    assert run(client,payload,row).json()['status']=='NOT_TESTED'
    assert db_session.scalar(select(func.count(ScannerJob.id))) == 0
    actions=db_session.scalars(select(AuditLog.action).where(AuditLog.action.like('segmentation.%')).order_by(AuditLog.id)).all()
    assert actions==['segmentation.prepared','segmentation.checked','segmentation.archived','segmentation.checked']


@pytest.mark.parametrize('expected,state,status,outcome', [
    ('ALLOW','TCP_CONNECTED','PASS','PASS'), ('DENY','TCP_CONNECTED','FAIL','UNEXPECTED_ACCESS'),
    ('ALLOW','TCP_REFUSED','FAIL','UNEXPECTED_BLOCK'), ('DENY','TCP_REFUSED','ERROR','ERROR'),
    ('ALLOW','TIMEOUT','ERROR','ERROR'), ('DENY','TIMEOUT','ERROR','ERROR'),
    ('DENY','NETWORK_ERROR','ERROR','ERROR'), ('ALLOW','SOURCE_ERROR','ERROR','ERROR'),
])
def test_outcomes_do_not_confuse_silence_with_isolation(client,setup,monkeypatch,expected,state,status,outcome):
    payload,_=setup
    payload['expected']=expected
    row=create(client,payload)
    monkeypatch.setattr(service,'probe',lambda *args:{'state':state,'attempted':state!='SOURCE_ERROR','detail':'Test evidence'})
    result=run(client,payload,row).json()
    assert (result['status'],result['outcome'])==(status,outcome)


@pytest.mark.parametrize('flag',['scanner_execution_enabled','segmentation_execution_enabled'])
def test_both_execution_gates_required(client,setup,monkeypatch,flag):
    payload,_=setup
    row=create(client,payload)
    monkeypatch.setattr(get_settings(),flag,False)
    result=run(client,payload,row).json()
    assert result['status']=='NOT_TESTED' and not result['observed']['attempted']


@pytest.mark.parametrize('change', ['removed_source','changed_source','removed_port','removed_zone','inactive_scope','changed_scope','broken_config'])
def test_authorization_rechecked_at_execution(client,db_session,setup,monkeypatch,change):
    payload,source=setup
    row=create(client,payload)
    if change in {'inactive_scope','changed_scope'}:
        scope=db_session.get(Scope,payload['scope_id'])
        if change=='inactive_scope': scope.active=False
        else: scope.target='198.51.100.0/24'
        db_session.commit()
    else:
        config=[source]
        if change=='removed_source': config=[]
        if change=='changed_source': source['bind_ip']='192.0.2.3'
        if change=='removed_port': source['allowed_ports']=[80]
        if change=='removed_zone': source['target_scope_ids']=[999]
        monkeypatch.setattr(get_settings(),'segmentation_sources_json','{' if change=='broken_config' else json.dumps(config))
    result=run(client,payload,row).json()
    assert result['status']=='NOT_TESTED' and not result['observed']['attempted']


@pytest.mark.parametrize('changes', [
    {'target':'example.com'}, {'target':'192.0.2.0/24'}, {'target':'192.0.2.255'}, {'target':'192.0.2.0'},
    {'target':'198.51.100.1'}, {'target':'0.0.0.0'}, {'target':'224.0.0.1'}, {'target':'169.254.169.254'},
    {'target':'::ffff:192.0.2.10'}, {'target':'fe80::1%en0'}, {'target':'2001:db8::1'},
    {'port':80}, {'port':0}, {'port':65536}, {'port':'443'}, {'ports':[443,80]}, {'source_id':'unapproved'},
    {'scope_id':999}, {'rationale':'short'}, {'name':'   '}, {'target':'192.0.2.10; id'},
])
def test_no_ranges_dns_injection_or_unauthorized_endpoints(client,setup,changes):
    payload,_=setup
    response=client.post('/api/v1/segmentation/rules',json={**payload,**changes})
    assert response.status_code==422,response.text


def test_exact_scope_and_org_boundaries(client,setup,monkeypatch,db_session):
    payload,source=setup
    row=create(client,payload)
    other=client.post('/api/v1/organizations',json={'name':'Other org'}).json()['id']
    for path in ['', '/checks']:
        if path:
            assert client.get(f"/api/v1/segmentation/rules/{row['id']}{path}",params={'organization_id':other}).status_code==404
    for path in ['/checks','/archive']:
        assert client.post(f"/api/v1/segmentation/rules/{row['id']}{path}",json={'organization_id':other}).status_code==404
    assert client.get('/api/v1/segmentation/rules',params={'organization_id':other}).json()==[]
    assert client.get('/api/v1/segmentation/config',params={'organization_id':other}).json()['sources']==[]
    # Even another active overlapping scope does not authorize this selected scope.
    wrong=client.post('/api/v1/scopes',json={'organization_id':payload['organization_id'],'name':'Other zone','target_type':'CIDR','target':'192.0.2.0/25','scan_zone':'INTERNAL_IT'}).json()['id']
    assert client.post('/api/v1/segmentation/rules',json={**payload,'scope_id':wrong}).status_code==422
    source['organization_id']=other
    monkeypatch.setattr(get_settings(),'segmentation_sources_json',json.dumps([source]))
    assert client.post('/api/v1/segmentation/rules',json={**payload,'organization_id':other}).status_code==422
    assert run(client,payload,row).json()['status']=='NOT_TESTED'


@pytest.mark.parametrize('value',['{','{}','[null]','[{"id":"bad"}]'])
def test_bad_configuration_fails_closed(client,setup,monkeypatch,value):
    payload,_=setup
    monkeypatch.setattr(get_settings(),'segmentation_sources_json',value)
    config=client.get('/api/v1/segmentation/config',params={'organization_id':payload['organization_id']}).json()
    assert not config['enabled'] and config['sources']==[] and config['configuration_error']
    assert client.post('/api/v1/segmentation/rules',json=payload).status_code==422


def test_real_loopback_tcp_no_payload_or_remote_network():
    with socket.socket() as listener:
        listener.bind(('127.0.0.1',0)); listener.listen(1); listener.settimeout(2)
        result=service.probe('127.0.0.1','127.0.0.1',listener.getsockname()[1])
        assert result['state']=='TCP_CONNECTED' and result['actual_source_ip']=='127.0.0.1'
        accepted,_=listener.accept()
        with accepted:
            accepted.settimeout(2)
            assert accepted.recv(1)==b''


@pytest.mark.parametrize('phase,error,state,attempted', [
    ('bind',OSError(49,'unavailable'),'SOURCE_ERROR',False),
    ('connect',ConnectionRefusedError(),'TCP_REFUSED',True),
    ('connect',TimeoutError(),'TIMEOUT',True),
    ('connect',OSError(113,'unreachable'),'NETWORK_ERROR',True),
])
def test_socket_failures_never_fallback(monkeypatch,phase,error,state,attempted):
    calls=[]
    class FakeSocket:
        def __enter__(self): return self
        def __exit__(self,*args): pass
        def settimeout(self,seconds): assert seconds==2
        def bind(self,address):
            calls.append(('bind',address))
            if phase=='bind': raise error
        def getsockname(self): return ('192.0.2.2',12345)
        def connect(self,address):
            calls.append(('connect',address)); raise error
    monkeypatch.setattr(service.socket,'socket',lambda *args:FakeSocket())
    result=service.probe('192.0.2.2','192.0.2.10',443)
    assert result['state']==state and result['attempted']==attempted
    assert len(calls)==(2 if attempted else 1)


@pytest.mark.parametrize('target_type,target,scan_zone', [('CIDR','192.0.2.0/24','EXTERNAL'),('HOSTNAME','app.example.com','INTERNAL_IT')])
def test_external_or_dns_scope_is_not_a_target_zone(client,setup,monkeypatch,target_type,target,scan_zone):
    payload,source=setup
    scope=client.post('/api/v1/scopes',json={'organization_id':payload['organization_id'],'name':'Wrong kind',
        'target_type':target_type,'target':target,'scan_zone':scan_zone}).json()['id']
    source['target_scope_ids']=[scope]
    monkeypatch.setattr(get_settings(),'segmentation_sources_json',json.dumps([source]))
    assert client.post('/api/v1/segmentation/rules',json={**payload,'scope_id':scope}).status_code==422


def test_rule_cap_and_history_pagination(client,db_session,setup):
    payload,_=setup
    row=create(client,payload)
    for index in range(99):
        db_session.add(SegmentationRule(**{**payload,'name':f'Boundary {index}'},source=row['source'],zone=row['zone'],active=True))
    db_session.commit()
    assert client.post('/api/v1/segmentation/rules',json=payload).status_code==409
    page=client.get('/api/v1/segmentation/rules',params={'organization_id':payload['organization_id'],'limit':1,'offset':99}).json()
    assert [r['id'] for r in page]==[row['id']]
    client.post(f"/api/v1/segmentation/rules/{row['id']}/archive",json={'organization_id':payload['organization_id']})
    assert client.post('/api/v1/segmentation/rules',json=payload).status_code==201


@pytest.mark.parametrize('kind',['duplicate_id','too_many_ports','wildcard_source','empty_ports'])
def test_deployment_authorization_is_bounded(client,setup,monkeypatch,kind):
    payload,source=setup
    configuration=[source]
    if kind=='duplicate_id': configuration=[source,source]
    if kind=='too_many_ports': source['allowed_ports']=list(range(1,18))
    if kind=='wildcard_source': source['bind_ip']='0.0.0.0'
    if kind=='empty_ports': source['allowed_ports']=[]
    monkeypatch.setattr(get_settings(),'segmentation_sources_json',json.dumps(configuration))
    assert client.post('/api/v1/segmentation/rules',json=payload).status_code==422
