"""Local deployment administration only. No unauthenticated enrollment API."""
import argparse
import json
import os
from pathlib import Path
from app.core.database import SessionLocal
from app.services.nodes import register, revoke, rotate


def write_credentials(path, node, token, url):
    # Reserve a new private file before committing identity changes; never overwrite an existing credential.
    descriptor=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
    with os.fdopen(descriptor,'w') as stream:
        json.dump({'node_id':node.id,'url':url.rstrip('/'),'token':token,'bind_ip':node.bind_ip,
                   'allowed_ports':node.allowed_ports,'allowed_scope_ids':node.target_scope_ids,'allowed_networks':node.target_networks},stream)
        stream.flush();os.fsync(stream.fileno())


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    commands=parser.add_subparsers(dest='command',required=True)
    create=commands.add_parser('register')
    create.add_argument('--organization',type=int,required=True);create.add_argument('--name',required=True)
    create.add_argument('--bind-ip',required=True);create.add_argument('--scope',type=int,action='append',required=True)
    create.add_argument('--port',type=int,action='append',required=True)
    for cmd in [create,commands.add_parser('rotate')]:
        cmd.add_argument('--credentials',type=Path,required=True);cmd.add_argument('--url',required=True)
        if cmd is not create: cmd.add_argument('--node',type=int,required=True)
    remove=commands.add_parser('revoke');remove.add_argument('--node',type=int,required=True)
    args=parser.parse_args()
    if args.command!='revoke':
        from signalhound_node.client import validate_url
        validate_url(args.url,allow_loopback=False)
    with SessionLocal() as db:
        if args.command=='revoke':
            node=revoke(db,args.node);db.commit();print(f'Node {node.id} revoked.');return
        if args.command=='register':
            node,token=register(db,organization_id=args.organization,name=args.name,bind_ip=args.bind_ip,scope_ids=args.scope,ports=args.port)
        else: node,token=rotate(db,args.node)
        write_credentials(args.credentials,node,token,args.url)
        db.commit()
        print(f'Node {node.id}: private credentials written to {args.credentials}. No token printed. Execution remains separately gated.')


if __name__=='__main__': main()
