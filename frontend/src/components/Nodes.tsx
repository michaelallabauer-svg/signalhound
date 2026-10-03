import { useEffect, useState } from 'react';
import { api, NodeJob, NodeList } from '../api';
import { Help } from './Help';

export function NodeJobCards({jobs}:{jobs:NodeJob[]}) {
  return <section aria-label="Node job status">
    <h4>Node jobs <Help label="Node job status help" text="QUEUED waits for a node. LEASED is reserved, not started. RUNNING has a short start authorization. COMPLETED links to a recorded result; it does not mean PASS. EXPIRED can mean a lost result, not a safe network. Jobs are never automatically retried."/></h4>
    {!jobs.length && <p>No node jobs on this page.</p>}
    {jobs.map(job=><article className="fingerprint-card" key={job.id}>
      <strong>Job #{job.id} · {job.status}</strong>
      <p>{job.expected.name} · {job.expected.source.name} → {job.expected.target}:{job.expected.port} · expected {job.expected.access}</p>
      <p>Queued {new Date(job.created_at).toLocaleString()} · deadline {new Date(job.expires_at).toLocaleString()}</p>
      {job.check_id && <p>Recorded result #{job.check_id}: open this rule in Segmentation to review evidence and verdict.</p>}
      {job.message && <p>{job.message}</p>}
    </article>)}
  </section>;
}

export function Nodes({organizationId}:{organizationId:number}) {
  const [data,setData]=useState<NodeList|null>(null);
  const [jobs,setJobs]=useState<NodeJob[]>([]);
  const [offset,setOffset]=useState(0);
  const [jobOffset,setJobOffset]=useState(0);
  const [refresh,setRefresh]=useState(0);
  const [busy,setBusy]=useState(true);
  const [error,setError]=useState<string|null>(null);
  useEffect(()=>{
    let disposed=false;setBusy(true);setError(null);
    Promise.all([api.nodes(organizationId,offset),api.nodeJobs(organizationId,undefined,jobOffset)])
      .then(([nodes,rows])=>{if(!disposed){setData(nodes);setJobs(rows);}})
      .catch(e=>{if(!disposed)setError(e.message);})
      .finally(()=>{if(!disposed)setBusy(false);});
    return()=>{disposed=true;};
  },[organizationId,offset,jobOffset,refresh]);
  return <section className="panel segmentation" aria-label="Distributed scanner nodes" aria-busy={busy}>
    <h2>Scanner nodes</h2>
    <p>A node runs approved checks from its own network location. It connects outward to SignalHound; no incoming control port is needed on the node.</p>
    <ol className="workflow-guide">
      <li>Administrator registers the node and its fixed source IP, target networks and ports.</li>
      <li>Start the node client with its private credentials and trusted HTTPS connection.</li>
      <li>In Segmentation, select the node, prepare a rule and explicitly queue a check.</li>
    </ol>
    <button disabled={busy} onClick={()=>setRefresh(v=>v+1)}>Refresh node status</button>
    {error && <p role="alert">{error}</p>}
    {busy && <p role="status">Loading node status…</p>}
    {data && <>
      {!data.enabled && <p className="notice">Distributed execution is disabled on the server. Heartbeats and historical results remain available; no jobs can start.</p>}
      {!data.nodes.length && <p>No nodes registered on this page. Registration and credential changes require the deployment administrator, not an Inventory location.</p>}
      <details><summary>Administrator setup</summary>
        <p>Use the local <code>python -m app.node_admin register</code> command with approved organization, source IP, scope IDs and ports. It writes a new private credential file and never displays the token in the browser.</p>
        <p>The standalone Python client uses validated HTTPS certificates and outbound polling. Start without <code>--execute</code> to verify heartbeat first. Execution needs the node flag plus all three server gates: scanner, segmentation and node execution.</p>
        <p>Rotate or revoke credentials with <code>app.node_admin rotate</code> / <code>revoke</code>. Revocation prevents new starts and invalidates pending jobs, but cannot undo a connection already started. Deployment guide: <code>docs/epic-16-nodes.md</code>.</p>
      </details>
      {data.nodes.map(node=><article className="fingerprint-card" key={node.id}>
        <h3>{node.name} · {node.active ? node.online ? 'Online' : 'Offline / never seen' : 'Revoked'} <Help label={`Node ${node.id} status help`} text="Online means a heartbeat within 90 seconds, not proof of correct routing. Ready additionally requires a supported version, capability and enabled client. Server gates apply separately. The source IP is pre-NAT and belongs to the node's network namespace."/></h3>
        <p>Node #{node.id} · source {node.bind_ip} · {node.ready ? 'Client ready' : 'Client not ready'}</p>
        <p>Version: {node.version ?? 'Not reported'} (required {data.required_version}) · Last heartbeat: {node.last_seen_at ? new Date(node.last_seen_at).toLocaleString() : 'Never'}</p>
        <p>Authorized capability: {node.capabilities.join(', ')} · Target scope IDs: {node.target_scope_ids.join(', ')} · TCP ports: {node.allowed_ports.join(', ')}</p>
        <p>Credential generation {node.credential_generation} · Client execution {node.execution_enabled ? 'enabled' : 'disabled'}</p>
      </article>)}
      <div className="button-row"><button disabled={busy||offset===0} onClick={()=>setOffset(offset-20)}>Previous nodes</button><button disabled={busy||data.nodes.length<20} onClick={()=>setOffset(offset+20)}>More nodes</button></div>
      <NodeJobCards jobs={jobs}/>
      <div className="button-row"><button disabled={busy||jobOffset===0} onClick={()=>setJobOffset(jobOffset-20)}>Newer node jobs</button><button disabled={busy||jobs.length<20} onClick={()=>setJobOffset(jobOffset+20)}>Older node jobs</button></div>
    </>}
  </section>;
}
