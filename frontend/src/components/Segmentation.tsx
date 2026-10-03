import { FormEvent, useEffect, useId, useState } from 'react';
import { api, Scope, NodeJob, SegmentationCheck, SegmentationConfig, SegmentationRule } from '../api';
import { Help } from './Help';
import { NodeJobCards } from './Nodes';

const outcomes: Record<string, string> = {
  PASS: 'Expected access confirmed', UNEXPECTED_ACCESS: 'Unexpected access — connection succeeded',
  UNEXPECTED_BLOCK: 'Expected access unavailable — connection refused', NOT_TESTED: 'Not tested',
  ERROR: 'Inconclusive — review evidence',
};

export function Segmentation({ organizationId, scopes }: { organizationId: number; scopes: Scope[] }) {
  const prefix = useId();
  const [config, setConfig] = useState<SegmentationConfig | null>(null);
  const [rules, setRules] = useState<SegmentationRule[]>([]);
  const [nodeJobs, setNodeJobs] = useState<NodeJob[]>([]);
  const [checks, setChecks] = useState<SegmentationCheck[]>([]);
  const [offset, setOffset] = useState(0);
  const [historyOffset, setHistoryOffset] = useState(0);
  const [selected, setSelected] = useState<number | null>(null);
  const [refresh, setRefresh] = useState(0);
  const [busy, setBusy] = useState(false);
  const [loading, setLoading] = useState(true);
  const [historyLoading, setHistoryLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const [form, setForm] = useState({name:'',source_id:'',scope_id:'',target:'',port:'',expected:'DENY',rationale:''});
  const source = config?.sources.find(s => s.id === form.source_id);
  const zones = scopes.filter(s => s.organization_id === organizationId && s.active && s.scan_zone === 'INTERNAL_IT'
    && ['IP','CIDR'].includes(s.target_type) && source?.target_scope_ids.includes(s.id));
  const rule = rules.find(r => r.id === selected);
  useEffect(() => {
    let disposed = false;
    setLoading(true);
    Promise.all([api.segmentationConfig(organizationId), api.segmentationRules(organizationId, offset)])
      .then(([configuration, rows]) => { if (!disposed) {
        setConfig(configuration); setRules(rows);
        setSelected(current => rows.some(r=>r.id===current) ? current : rows[0]?.id ?? null);
      } })
      .catch(e=>{ if(!disposed) setError(String(e.message)); })
      .finally(()=>{ if(!disposed) setLoading(false); });
    return () => { disposed = true; };
  }, [organizationId, offset, refresh]);
  useEffect(() => {
    let disposed = false;
    setChecks([]); setNodeJobs([]);
    if (selected === null) return;
    setHistoryLoading(true);
    Promise.all([api.segmentationChecks(organizationId, selected, historyOffset), rule?.source.node_id ? api.nodeJobs(organizationId, selected) : Promise.resolve([])])
      .then(([rows,jobs])=>{ if(!disposed) {setChecks(rows);setNodeJobs(jobs);} })
      .catch(e=>{ if(!disposed) setError(String(e.message)); })
      .finally(()=>{ if(!disposed) setHistoryLoading(false); });
    return () => { disposed = true; };
  }, [organizationId, selected, historyOffset, refresh, rule?.source.node_id]);
  async function action(work:()=>Promise<unknown>, message:string) {
    setBusy(true); setError(null); setNotice(null);
    try { await work(); setNotice(message); setRefresh(v=>v+1); }
    catch(e) { setError(e instanceof Error ? e.message : 'Request failed'); }
    finally { setBusy(false); }
  }
  function create(event:FormEvent) {
    event.preventDefault();
    void action(async()=>{
      const row = await api.createSegmentationRule({...form, organization_id:organizationId, scope_id:Number(form.scope_id), port:Number(form.port)});
      setOffset(0); setHistoryOffset(0); setSelected(row.id);
      setForm({...form,name:'',target:'',rationale:''});
    }, 'Rule prepared. No network connection has been attempted. Select the rule and run one check when ready.');
  }
  function label(key:string, text:string, help:string) {
    return <div><label htmlFor={`${prefix}-${key}`}>{text}</label> <Help label={`${text} help`} text={help} /></div>;
  }
  return <section className="panel segmentation" aria-label="Network segmentation" aria-busy={busy || loading}>
    <h2>Network segmentation</h2>
    <button disabled={busy || loading} onClick={()=>{setError(null);setRefresh(v=>v+1);}}>Refresh rules and configuration</button>
    <p>Compare an approved connectivity rule with one observed TCP connection. Preparing a rule does not start a check.</p>
    <ol className="workflow-guide">
      <li>Administrator authorizes a real source IP, target scopes and a small set of ports.</li>
      <li>Prepare the expected rule for one IP and one TCP port.</li>
      <li>Run one check and compare the timestamped evidence. No zone-wide safety score is inferred.</li>
    </ol>
    {error && <p role="alert" className="notice error">{error}</p>}
    {notice && <p role="status" className="notice">{notice}</p>}
    {loading && <p role="status">Loading authorized configuration…</p>}
    {config && <>
      <p className="muted">{config.notice}</p>
      {config.configuration_error && <p role="alert">{config.configuration_error}</p>}
      {!config.enabled && <p className="notice">Execution is disabled. You can prepare rules when a source is configured. No checks start automatically.</p>}
      {config.sources.length === 0 && <p className="notice">No authorized scanner source is configured for this organization. Ask the deployment administrator to configure a source before preparing rules. An Inventory location is not a scan authorization.</p>}
      <details><summary>Administrator setup and source limitations</summary>
        <p>Configure <code>SEGMENTATION_SOURCES_JSON</code> on the backend with a source ID, organization ID, real bind IP, allowed target scope IDs and up to 16 allowed TCP ports. Then enable both <code>SEGMENTATION_EXECUTION_ENABLED</code> and <code>SCANNER_EXECUTION_ENABLED</code>. Restart the backend after configuration changes.</p>
        <p>The bind IP must exist inside the backend's network namespace. Docker Desktop is not automatically a Mac or LAN scanner. NAT can change the address seen by the destination. For an authorized remote location, register a Scanner node and select it as the source here.</p>
      </details>
      <form onSubmit={create} aria-label="Prepare segmentation rule">
        <fieldset disabled={busy || loading || config.sources.length === 0} className="segmentation-fields">
          <legend>Prepare a rule</legend>
          <div className="form-grid">
            <div>{label('name','Rule name','Describe the boundary being checked, for example application host to database.')}
              <input id={`${prefix}-name`} required maxLength={160} value={form.name} onChange={e=>setForm({...form,name:e.target.value})}/></div>
            <div>{label('source','Scanner source','Server-authorized source position. The connection must bind this IP; failure will never fall back to another interface.')}
              <select id={`${prefix}-source`} required value={form.source_id} onChange={e=>setForm({...form,source_id:e.target.value,scope_id:'',port:''})}>
                <option value="">Select authorized source</option>{config.sources.map(s=><option key={s.id} value={s.id}>{s.node_id ? "Node: " : "Backend: "}{s.name} · {s.bind_ip}</option>)}
              </select></div>
            <div>{label('zone','Target zone','Only active Internal IT IP/CIDR scopes explicitly authorized for this source are offered.')}
              <select id={`${prefix}-zone`} required value={form.scope_id} onChange={e=>setForm({...form,scope_id:e.target.value})}>
                <option value="">Select target zone</option>{zones.map(s=><option key={s.id} value={s.id}>{s.name} · {s.target}</option>)}
              </select>{source && !zones.length && <small>No authorized active target zone. Review Scopes and source configuration.</small>}</div>
            <div>{label('target','Destination IP','Exactly one literal IPv4 or IPv6 address inside the selected zone. Hostnames and networks are not accepted.')}
              <input id={`${prefix}-target`} required maxLength={45} placeholder="192.0.2.10" value={form.target} onChange={e=>setForm({...form,target:e.target.value})}/></div>
            <div>{label('port','TCP port','Exactly one administrator-approved port. No port ranges, UDP probes or application payloads.')}
              <select id={`${prefix}-port`} required value={form.port} onChange={e=>setForm({...form,port:e.target.value})}>
                <option value="">Select approved port</option>{source?.allowed_ports.map(port=><option key={port} value={port}>{port}</option>)}
              </select></div>
            <div>{label('expected','Expected access','ALLOW expects a successful TCP connection. DENY detects unexpected successful access. A refusal or timeout cannot prove that a firewall enforces DENY.')}
              <select id={`${prefix}-expected`} value={form.expected} onChange={e=>setForm({...form,expected:e.target.value})}>
                <option value="DENY">DENY — access must not succeed</option><option value="ALLOW">ALLOW — connection should succeed</option>
              </select></div>
          </div>
          {label('rationale','Reason for this rule','Record the intended policy and its authorization or policy reference. At least ten characters.')}
          <textarea id={`${prefix}-rationale`} required minLength={10} maxLength={2000} value={form.rationale} onChange={e=>setForm({...form,rationale:e.target.value})}/>
          <button className="primary-button" type="submit">Prepare rule — no network traffic</button>
        </fieldset>
      </form>
    </>}
    <h3>Prepared rules</h3>
    {!rules.length && !loading && <p>No rules on this page. Prepare a rule once an authorized source is available.</p>}
    <div className="segmentation-rules">{rules.map(row=><button key={row.id} type="button" aria-pressed={selected===row.id}
      disabled={busy || loading} onClick={()=>{setSelected(row.id);setHistoryOffset(0);}}>
      <strong>{row.name}</strong> · {row.expected} · {row.source.name} → {row.target}:{row.port} {row.active ? '' : '(archived)'}
    </button>)}</div>
    <div className="button-row">
      <button disabled={busy || loading || offset===0} onClick={()=>{setOffset(offset-20);setHistoryOffset(0);}}>Previous rules</button>
      <button disabled={busy || loading || rules.length<20} onClick={()=>{setOffset(offset+20);setHistoryOffset(0);}}>More rules</button>
    </div>
    {rule && <section aria-label="Selected segmentation rule">
      <h3>{rule.name}</h3>
      <p><strong>Expected:</strong> {rule.expected} from {rule.source.name} ({rule.source.bind_ip}) to {rule.zone.name} · {rule.target}:{rule.port}/TCP</p>
      <p>{rule.rationale}</p>
      <p className="muted">Rules are immutable. To change an expectation, archive it and prepare a new rule. Previous check results stay unchanged.</p>
      <div className="button-row">
        <button className="primary-button" disabled={busy || loading || !rule.active || !config?.enabled || (!!rule.source.node_id && !config.node_execution_enabled)}
          onClick={()=>void action(async()=>{if(rule.source.node_id) await api.queueNodeRule(organizationId,rule.id);else await api.runSegmentationCheck(organizationId, rule.id);setHistoryOffset(0);}, rule.source.node_id ? 'Node job queued, not yet measured. Refresh status to see progress and results.' : 'Check recorded. Review the observed result below.')}>{rule.source.node_id ? 'Queue check on selected node' : 'Check one TCP endpoint'}</button>
        <Help label="Run check help" text="Starts one two-second TCP connection from the configured source. Authorization is checked again before execution. Wait at least five seconds between checks. Archived rules or disabled execution cannot send traffic."/>
        <button disabled={busy || loading || !rule.active} onClick={()=>void action(()=>api.archiveSegmentationRule(organizationId,rule.id),'Rule archived. History is retained.')}>Archive rule</button>
      </div>
      {rule.source.node_id && <>
        {!config?.node_execution_enabled && <p>Distributed execution is disabled on the server. Prepared rules and history remain available.</p>}
        <p>A remote check runs only when this node pulls it and receives a fresh start authorization. Queueing is not a measured result. Refresh rules and configuration for updates.</p>
        <NodeJobCards jobs={nodeJobs}/>
      </>}
      {!rule.active && <p>Archived rules cannot run checks.</p>}
      <h4>Observed results <Help label="Result interpretation help" text="PASS confirms only expected TCP access at that time. FAIL marks unexpected access or a refused required connection. ERROR is inconclusive, including DENY with refusal, timeout, routing or source binding failure. NOT_TESTED means no connection was attempted."/></h4>
      {historyLoading ? <p role="status">Loading check history…</p> : !checks.length && <p>No results on this page. Untested is not a pass.</p>}
      {checks.map(check=><article className="fingerprint-card" key={check.id}>
        <h4>{check.status} · {outcomes[check.outcome] ?? check.outcome}</h4>
        <p>{new Date(check.created_at).toLocaleString()} · Check #{check.id} · {check.outcome}</p>
        <p><strong>Expected then:</strong> {check.expected.access} · {check.expected.source.name} ({check.expected.source.bind_ip}) → {check.expected.target}:{check.expected.port}/TCP · {check.expected.zone.name}</p>
        <p><strong>Observed:</strong> {check.observed.state} · {check.observed.attempted ? 'Connection attempted' : 'No connection attempted'}</p>
        <p>{check.observed.detail}</p>
        {check.observed.node_id && <p>Authenticated report from node #{check.observed.node_id} · version {check.observed.node_version} · job #{check.observed.node_job_id}. Network evidence is node-reported.</p>}
        {check.observed.actual_source_ip && <p>Bound source: {check.observed.actual_source_ip} · {check.observed.duration_ms} ms</p>}
        <p className="muted">{check.observed.notice}</p>
      </article>)}
      <div className="button-row">
        <button disabled={busy || historyLoading || historyOffset===0} onClick={()=>setHistoryOffset(historyOffset-10)}>Newer results</button>
        <button disabled={busy || historyLoading || checks.length<10} onClick={()=>setHistoryOffset(historyOffset+10)}>Older results</button>
      </div>
    </section>}
  </section>;
}
