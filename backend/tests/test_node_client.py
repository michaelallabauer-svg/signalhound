import socket
import subprocess
import threading
import time
import pytest
import uvicorn
from app.main import app
from app.services import nodes as service
from signalhound_node import client as agent
from tests.test_nodes import node_setup


def config():
    return dict(node_id=1,token='s'*43,url='https://localhost',bind_ip='192.0.2.2',allowed_ports=[443],allowed_scope_ids=[1],allowed_networks={'1':'192.0.2.0/24'})


def grant():
    return dict(job_id=1,node_id=1,protocol_version=1,timeout_seconds=2,execute_within_seconds=3,expected=dict(capability='tcp_connect_v1',protocol_version=1,transport='TCP',source={'node_id':1,'bind_ip':'192.0.2.2'},target='192.0.2.10',port=443,zone={'id':1}))


@pytest.mark.parametrize('url',['http://example.com','https://user:secret@example.com','https://example.com?token=x','https://example.com/path','ftp://localhost','http://localhost.evil'])
def test_client_rejects_unsafe_urls(url):
    with pytest.raises(ValueError):agent.validate_url(url,allow_loopback=True)


def test_private_files_and_no_overwrite(tmp_path):
    path=tmp_path/'credential.json';path.write_text('{}');path.chmod(0o644)
    with pytest.raises(ValueError):agent.read_private(path)
    path.chmod(0o600);assert agent.read_private(path)=={}
    symlink=tmp_path/'link';symlink.symlink_to(path)
    with pytest.raises(OSError):agent.read_private(symlink)


@pytest.mark.parametrize('mutation',['target','port','capability','source','node','scope','protocol','timeout'])
def test_client_independently_pins_grants(mutation):
    client=agent.Client(config());data=grant()
    if mutation=='target':data['expected']['target']='198.51.100.1'
    if mutation=='port':data['expected']['port']=80
    if mutation=='capability':data['expected']['capability']='shell'
    if mutation=='source':data['expected']['source']['bind_ip']='192.0.2.3'
    if mutation=='node':data['node_id']=2
    if mutation=='scope':data['expected']['zone']['id']=2
    if mutation=='protocol':data['protocol_version']=2
    if mutation=='timeout':data['timeout_seconds']=300
    with pytest.raises((agent.ProtocolError,KeyError)):client.validate_job(data,1)


def test_lost_result_retries_upload_not_probe(tmp_path,monkeypatch):
    client=agent.Client(config(),execute=True,spool=tmp_path/'pending.json')
    calls=[];probes=[];reject=[True]
    def request(path,payload):
        calls.append(path)
        if path=='/heartbeat':return {'node_id':1,'protocol_version':1,'execution_allowed':True}
        if path=='/pull':return {'lease':{'job_id':1,'capability':'tcp_connect_v1','lease_token':'l'*43}}
        if path.endswith('/start'):return grant()
        if path.endswith('/result'):
            if reject[0]:reject[0]=False;raise agent.ProtocolError('Transport lost')
            return {'id':1}
        raise AssertionError(path)
    monkeypatch.setattr(client,'request',request)
    monkeypatch.setattr(agent,'probe',lambda *args:probes.append(args) or {'state':'TCP_CONNECTED'})
    with pytest.raises(agent.ProtocolError):client.run_once()
    assert client.spool.exists() and client.spool.stat().st_mode&0o777==0o600
    assert client.run_once()=='previous result acknowledged'
    assert len(probes)==1 and calls.count('/pull')==1 and calls.count('/jobs/1/start')==1
    assert not client.spool.exists()


def test_lost_start_never_calls_probe_or_retries_start(tmp_path,monkeypatch):
    client=agent.Client(config(),execute=True,spool=tmp_path/'pending.json');calls=[]
    def request(path,payload):
        calls.append(path)
        if path=='/heartbeat':return {'node_id':1,'protocol_version':1,'execution_allowed':True}
        if path=='/pull':return {'lease':{'job_id':1,'capability':'tcp_connect_v1','lease_token':'l'*43}}
        raise agent.ProtocolError('Start response lost')
    monkeypatch.setattr(client,'request',request)
    monkeypatch.setattr(agent,'probe',lambda *args:pytest.fail('No execution after lost authorization'))
    with pytest.raises(agent.ProtocolError):client.run_once()
    assert calls.count('/jobs/1/start')==1 and not client.spool.exists()


def test_real_tls_pull_client_to_loopback_only(client,db_session,node_setup,tmp_path,monkeypatch):
    # Real TLS server and real TCP listener. Only loopback traffic; SQLite fixture holds test data.
    s=node_setup
    with socket.socket() as destination, socket.socket() as server_socket:
        destination.bind(('127.0.0.1',0));destination.listen(1);destination.settimeout(3)
        port=destination.getsockname()[1]
        scope=client.post('/api/v1/scopes',json={'organization_id':s['org'],'name':'Loopback','target_type':'IP','target':'127.0.0.1','scan_zone':'INTERNAL_IT'}).json()['id']
        node,token=service.register(db_session,organization_id=s['org'],name='TLS loopback',bind_ip='127.0.0.1',scope_ids=[scope],ports=[port]);db_session.commit()
        payload=s['payload']|{'source_id':f'node-{node.id}','scope_id':scope,'target':'127.0.0.1','port':port,'expected':'ALLOW'}
        response=client.post('/api/v1/segmentation/rules',json=payload);assert response.status_code==201,response.text
        rule=response.json()
        assert client.post(f"/api/v1/nodes/rules/{rule['id']}/queue",json={'organization_id':s['org']}).status_code==201
        cert=tmp_path/'cert.pem';key=tmp_path/'key.pem'
        subprocess.run(['openssl','req','-x509','-newkey','rsa:2048','-nodes','-keyout',str(key),'-out',str(cert),'-days','1','-subj','/CN=localhost','-addext','subjectAltName=DNS:localhost,IP:127.0.0.1'],check=True,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
        server_socket.bind(('127.0.0.1',0));server_socket.listen(10)
        server=uvicorn.Server(uvicorn.Config(app,ssl_certfile=str(cert),ssl_keyfile=str(key),log_level='critical',access_log=False))
        thread=threading.Thread(target=server.run,kwargs={'sockets':[server_socket]},daemon=True);thread.start()
        try:
            for _ in range(100):
                if server.started:break
                time.sleep(.02)
            assert server.started
            settings=dict(node_id=node.id,token=token,url=f'https://127.0.0.1:{server_socket.getsockname()[1]}',bind_ip='127.0.0.1',allowed_ports=[port],allowed_scope_ids=[scope],allowed_networks={str(scope):'127.0.0.1'})
            untrusted=agent.Client(settings,execute=True,spool=tmp_path/'untrusted.json')
            with pytest.raises(agent.ProtocolError):untrusted.run_once()
            worker=agent.Client(settings,execute=False,ca_bundle=str(cert),spool=tmp_path/'pending.json')
            assert 'heartbeat only' in worker.run_once()
            worker.execute=True
            assert 'result acknowledged' in worker.run_once()
            accepted,_=destination.accept()
            with accepted:
                accepted.settimeout(2);assert accepted.recv(1)==b''
            data=client.get(f"/api/v1/segmentation/rules/{rule['id']}/checks",params={'organization_id':s['org']}).json()
            assert len(data)==1 and data[0]['status']=='PASS' and data[0]['observed']['node_id']==node.id
            assert not worker.spool.exists()
        finally:
            server.should_exit=True;thread.join(5)
            assert not thread.is_alive()


def test_no_probe_when_evidence_storage_unavailable(tmp_path,monkeypatch):
    worker=agent.Client(config(),execute=True,spool=tmp_path/'missing'/'pending.json')
    def request(path,payload):
        if path=='/heartbeat':return {'node_id':1,'protocol_version':1,'execution_allowed':True}
        if path=='/pull':return {'lease':{'job_id':1,'capability':'tcp_connect_v1','lease_token':'l'*43}}
        return grant()
    monkeypatch.setattr(worker,'request',request)
    monkeypatch.setattr(agent,'probe',lambda *args:pytest.fail('Probe without evidence storage'))
    with pytest.raises(FileNotFoundError):worker.run_once()
