"""Outbound-only client. No inbound listener, shell execution or arbitrary scanner commands."""
import argparse
import ipaddress
import json
import os
from pathlib import Path
import ssl
import stat
import time
import urllib.error
import urllib.parse
import urllib.request
from . import VERSION, CAPABILITY
from .probe import probe


class ProtocolError(Exception): pass


def validate_url(url, allow_loopback=False):
    parsed=urllib.parse.urlsplit(url)
    if parsed.username or parsed.password or parsed.query or parsed.fragment or not parsed.hostname or parsed.path not in {'','/'}:
        raise ValueError('Use a root server URL without credentials, query, fragment or path')
    if parsed.scheme!='https' and not(allow_loopback and parsed.scheme=='http' and parsed.hostname in {'127.0.0.1','::1','localhost'}):
        raise ValueError('HTTPS is required; insecure mode is restricted to literal loopback/localhost tests')
    return url.rstrip('/')


def read_private(path):
    fd=os.open(path,os.O_RDONLY | getattr(os,'O_NOFOLLOW',0))
    with os.fdopen(fd) as stream:
        info=os.fstat(stream.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_mode & 0o077 or info.st_uid!=os.getuid():
            raise ValueError('Credential/spool files must be owned by this user and accessible only to that user (0600)')
        raw=stream.read(262145)
        if len(raw)>262144: raise ValueError('Private file too large')
        return json.loads(raw)


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self,*args,**kwargs): return None


class Client:
    def __init__(self, config, *, execute=False, ca_bundle=None, allow_loopback=False, spool=None):
        self.config=config;self.execute=execute;self.spool=Path(spool) if spool else None
        self.url=validate_url(config['url'],allow_loopback)
        if type(config.get('node_id')) is not int or not isinstance(config.get('token'),str) or not 40<=len(config['token'])<=100:
            raise ValueError('Invalid credential identity')
        context=ssl.create_default_context(cafile=ca_bundle)
        self.opener=urllib.request.build_opener(urllib.request.ProxyHandler({}),urllib.request.HTTPSHandler(context=context),NoRedirect())

    def request(self,path,payload):
        request=urllib.request.Request(self.url+'/api/v1/nodes/self'+path,data=json.dumps(payload).encode(),method='POST',
                    headers={'Content-Type':'application/json','Authorization':'Bearer '+self.config['token']})
        try:
            with self.opener.open(request,timeout=10) as response:
                raw=response.read(262145)
                if len(raw)>262144: raise ProtocolError('Response exceeds protocol limit')
                decoded=json.loads(raw)
                if not isinstance(decoded,dict): raise ProtocolError('Invalid protocol response object')
                return decoded
        except urllib.error.HTTPError as exc:
            # Never print response bodies or Authorization/lease secrets.
            raise ProtocolError(f'Node request rejected (HTTP {exc.code}); check identity, TLS, grants, gates or job state') from None
        except (urllib.error.URLError,TimeoutError,json.JSONDecodeError):
            raise ProtocolError('Node transport/response failed; no automatic execution retry') from None

    def validate_job(self,grant,job_id):
        if grant.get('job_id')!=job_id or grant.get('node_id')!=self.config['node_id'] or grant.get('protocol_version')!=1 or grant.get('timeout_seconds')!=2 or grant.get('execute_within_seconds')!=3:
            raise ProtocolError('Unsupported execution grant')
        expected=grant['expected'];source=expected['source']
        if expected.get('capability')!=CAPABILITY or expected.get('transport')!='TCP' or expected.get('protocol_version')!=1 or source.get('node_id')!=self.config['node_id'] or source.get('bind_ip')!=self.config['bind_ip']:
            raise ProtocolError('Capability or source identity differs from local grant')
        target=expected['target'];port=expected['port'];zone=expected['zone']
        if type(port) is not int or port not in self.config['allowed_ports'] or zone['id'] not in self.config['allowed_scope_ids']:
            raise ProtocolError('Endpoint outside local authorization')
        if '%' in target: raise ProtocolError('Scoped IPv6 not supported')
        address=ipaddress.ip_address(target)
        network=ipaddress.ip_network(self.config['allowed_networks'][str(zone['id'])],strict=False)
        if str(address)!=target or address not in network or address.version!=ipaddress.ip_address(self.config['bind_ip']).version:
            raise ProtocolError('Target outside pinned local network grant')
        if address.is_unspecified or address.is_multicast or address.is_link_local or getattr(address,'ipv4_mapped',None):
            raise ProtocolError('Unsupported address')
        if network.version==4 and network.prefixlen<31 and address in {network.network_address,network.broadcast_address}:
            raise ProtocolError('Network/broadcast target forbidden')
        return expected

    def upload_spool(self):
        if not self.spool or not self.spool.exists(): return False
        pending=read_private(self.spool)
        if pending['node_id']!=self.config['node_id']: raise ProtocolError('Spool belongs to another node')
        self.request(f"/jobs/{pending['job_id']}/result",pending['payload'])
        self.spool.unlink()  # Only our acknowledged private result, never the credential file.
        return True

    def run_once(self):
        heartbeat=self.request('/heartbeat',{'version':VERSION,'capabilities':[CAPABILITY],'execution_enabled':self.execute})
        if heartbeat.get('node_id')!=self.config['node_id'] or heartbeat.get('protocol_version')!=1:
            raise ProtocolError('Server identity/protocol response mismatch')
        # Retry only an already measured result, never the network probe.
        if self.upload_spool(): return 'previous result acknowledged'
        if not self.execute or not heartbeat.get('execution_allowed'): return 'heartbeat only; execution disabled or not ready'
        if not self.spool: raise ProtocolError('A private result spool path is required before execution')
        lease=self.request('/pull',{})['lease']
        if lease is None: return 'idle'
        if lease.get('capability')!=CAPABILITY: raise ProtocolError('Unsupported capability; no execution')
        job_id=lease['job_id'];token=lease['lease_token']
        if type(job_id) is not int or job_id<=0 or not isinstance(token,str) or not 40<=len(token)<=100:
            raise ProtocolError('Invalid lease identity')
        # Do not retry start if its response is lost: the server lease will expire visibly.
        started=time.monotonic()
        grant=self.request(f'/jobs/{job_id}/start',{'lease_token':token})
        expected=self.validate_job(grant,job_id)
        if time.monotonic()-started>=3: raise ProtocolError('Start authorization arrived too late; no execution')
        # Reserve durable storage before probing; an interrupted marker is not executable work.
        fd=os.open(self.spool,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
        with os.fdopen(fd,'w') as stream:
            json.dump({'node_id':self.config['node_id'],'job_id':job_id,'state':'START_AUTHORIZED_NO_RESULT'},stream)
            stream.flush();os.fsync(stream.fileno())
            if time.monotonic()-started>=3: raise ProtocolError('Start authorization expired while reserving evidence storage')
            observation=probe(self.config['bind_ip'],expected['target'],expected['port'])
            pending={'node_id':self.config['node_id'],'job_id':job_id,'payload':{'lease_token':token,'observation':observation}}
            stream.seek(0);json.dump(pending,stream);stream.truncate();stream.flush();os.fsync(stream.fileno())
        self.upload_spool()
        return f'job {job_id}: result acknowledged'


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--config',type=Path,required=True)
    parser.add_argument('--spool',type=Path,required=True,help='Private pending-result file, distinct from credentials')
    parser.add_argument('--ca-bundle');parser.add_argument('--execute',action='store_true')
    parser.add_argument('--once',action='store_true');parser.add_argument('--allow-insecure-loopback',action='store_true')
    args=parser.parse_args()
    if args.config.resolve()==args.spool.resolve(): parser.error('Credential and spool paths must differ')
    try:
        client=Client(read_private(args.config),execute=args.execute,ca_bundle=args.ca_bundle,
                      allow_loopback=args.allow_insecure_loopback,spool=args.spool)
        while True:
            print(client.run_once(),flush=True)
            if args.once: break
            time.sleep(15)
    except KeyboardInterrupt: return
    except ProtocolError as exc:
        raise SystemExit(str(exc)+'; private pending results are retained. No automatic probe retry.') from None
    except (ValueError,KeyError,TypeError,OSError):
        # Stop on authentication, policy or transport failures. No hidden reconnect/scan retry loop.
        raise SystemExit('Node stopped: configuration, authorization, transport or result acknowledgement failed. Review server status and private pending result; no automatic probe retry.') from None


if __name__=='__main__': main()
