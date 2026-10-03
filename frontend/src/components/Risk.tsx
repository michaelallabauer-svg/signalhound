import { useEffect, useId, useState } from 'react';
import { api, type RiskHistory, type RiskSnapshot, type AssetBusinessContext } from '../api';
import { Help } from './Help';

export function Risk({ assetId, organizationId, savedContext }: { assetId: number; organizationId: number; savedContext?: AssetBusinessContext | null }) {
  const formId = useId();
  const [history, setHistory] = useState<RiskHistory | null>(null);
  const [offset, setOffset] = useState(0);
  const [exposure, setExposure] = useState('UNKNOWN');
  const [criticality, setCriticality] = useState('ASSET');
  const [rationale, setRationale] = useState('');
  const [error, setError] = useState('');
  const [busy, setBusy] = useState(false);
  const needsReason = exposure !== 'UNKNOWN' || !['UNKNOWN', 'ASSET'].includes(criticality);
  useEffect(() => {
    let active = true;
    setError(''); setHistory(null);
    api.riskHistory(assetId, organizationId, offset).then(data => { if (active) setHistory(data); })
      .catch(e => { if (active) setError(e.message); });
    return () => { active = false; };
  }, [assetId, organizationId, offset]);
  async function calculate() {
    setBusy(true); setError('');
    try {
      await api.calculateRisk(assetId, { organization_id: organizationId, exposure, criticality: criticality === 'ASSET' ? null : criticality, rationale });
      if (offset) setOffset(0);
      else setHistory(await api.riskHistory(assetId, organizationId));
    } catch (e) { setError(e instanceof Error ? e.message : 'Calculation failed'); }
    finally { setBusy(false); }
  }
  return <section className="detail-section risk" aria-label="Exposure and risk" aria-busy={busy}>
    <h3>Exposure and risk <Help label="About exposure priority" text="An explainable prioritization heuristic, not a probability of compromise. It combines technical severity, exploitation indicators, context, age and identifier confidence. A high priority never confirms vulnerability." /></h3>
    <p>Review stored findings and intelligence, add known context, then calculate. This works offline and does not start scans or public lookups.</p>
    <div className="risk-context">
      <div><label htmlFor={`${formId}-exposure`}>Exposure</label> <Help label="About exposure context" text="Unknown stays unknown. A scan zone or public IP alone does not prove internet reachability. Select Internal or Internet only with supporting context; this assumption applies to all issues in this snapshot." />
        <select id={`${formId}-exposure`} value={exposure} disabled={busy} onChange={e => setExposure(e.target.value)}>
          <option value="UNKNOWN">Unknown</option><option value="INTERNAL">Internal reachability</option><option value="INTERNET">Internet reachable</option>
        </select>
      </div>
      <div><label htmlFor={`${formId}-criticality`}>Asset criticality</label> <Help label="About criticality context" text="Use the saved asset business criticality, or override it for this snapshot with a reason. An override does not change the asset. Environment and owners do not change the scoring weights." />
        <select id={`${formId}-criticality`} value={criticality} disabled={busy} onChange={e => setCriticality(e.target.value)}>
          <option value="ASSET">Use saved asset value ({savedContext?.criticality ?? 'unclassified'})</option>
          {['UNKNOWN', 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL'].map(value => <option key={value}>{value}</option>)}
        </select>
      </div>
      <label>Context explanation {needsReason ? '(required, at least 10 characters)' : '(optional)'}
        <textarea value={rationale} maxLength={2000} disabled={busy} onChange={e => setRationale(e.target.value)} placeholder="What supports your exposure and business-importance assumptions?" />
      </label>
    </div>
    <button type="button" disabled={busy || (needsReason && rationale.trim().length < 10)} onClick={() => void calculate()}>{busy ? 'Calculating…' : 'Calculate priority'}</button>
    {error && <p role="alert">{error}</p>}
    {!history && !error && <p role="status">Loading priority history…</p>}
    {history && <>
      <p>Algorithm: {history.algorithm_version}. Saved results are point-in-time snapshots; recalculate after changes.</p>
      {!history.snapshots.length && <p>No priority snapshot yet. Calculate to see available evidence and data gaps.</p>}
      {history.snapshots.map(snapshot => <RiskCard key={snapshot.id} snapshot={snapshot} />)}
      <div className="intelligence-actions">
        {offset > 0 && <button disabled={busy} onClick={() => setOffset(Math.max(0, offset - 10))}>Newer priority snapshots</button>}
        {history.snapshots.length === 10 && <button disabled={busy} onClick={() => setOffset(offset + 10)}>Older priority snapshots</button>}
      </div>
    </>}
  </section>;
}
const componentHelp: Record<string, [string, string]> = {
  cvss: ['CVSS severity', 'Technical severity / 10 × 30 points. Missing CVSS is unknown; finding severity labels are not converted into CVSS.'],
  epss: ['EPSS probability', 'FIRST exploitation probability × 20 points. Fetches older than two days or model dates older than three days are treated as unknown.'],
  kev: ['Known exploitation (KEV)', '20 points if listed by CISA, 0 if not listed in a fresh catalog. Unknown spans 0–20; not listed does not prove safety.'],
  exposure: ['Exposure', 'Internet-reachable: 15 points. Internal reachability: 6 points. Unknown spans 0–15. This is your documented assumption, not a scan-zone inference.'],
  criticality: ['Asset criticality', 'Low / Medium / High / Critical contribute 2.5 / 5 / 7.5 / 10 points. Unknown spans 0–10.'],
  finding_age: ['Finding age (days)', 'Elapsed time since the finding was first seen, capped at 90 days: age / 90 × 5 points. Potential matches have no finding age and remain unknown.'],
  confidence: ['Match confidence', 'The additive subtotal is multiplied by High 1.0, Moderate 0.75 or Low 0.5. Unknown spans 0.5–1.0. This describes identifier linkage, not whether exploitation was confirmed.'],
};
const number = (value: number) => value.toLocaleString(undefined, { maximumFractionDigits: 2 });
function interval(lower: number | null, upper: number | null) {
  return lower === null || upper === null ? 'Not scored' : lower === upper ? `${lower} / 100` : `${lower}–${upper} / 100`;
}
function RiskCard({ snapshot }: { snapshot: RiskSnapshot }) {
  const { result } = snapshot;
  return <details className="fingerprint-card" open>
    <summary>Priority snapshot #{snapshot.id} · {new Date(snapshot.created_at).toLocaleString()} · {snapshot.algorithm_version}</summary>
    <h4>Priority range: {interval(result.lower, result.upper)} <Help label={`About priority range ${snapshot.id}`} text="Unknown components span their allowed contribution, rather than being set to zero. The range is a heuristic bound, not a statistical confidence interval. Issues sort by upper bound for review; a broad range can mean missing data, not high confirmed risk." /></h4>
    <p>Status: {result.status} · {result.notice}</p>
    <p>Context: {snapshot.context.exposure} exposure · {snapshot.context.criticality} criticality · {snapshot.context.rationale || 'No additional context supplied'}{snapshot.context.asset_active === false && ' · Asset marked inactive at calculation'}</p>
    {snapshot.context.business_context && <p>Business context at calculation: revision {snapshot.context.business_context.revision} · {snapshot.context.business_context.environment} · {snapshot.context.business_context.site?.name ?? 'Location unassigned'} · Team: {snapshot.context.business_context.responsible_team ?? 'Unassigned'} · Criticality source: {snapshot.context.criticality_source === 'asset_context' ? 'Saved asset value' : 'Snapshot override'}.</p>}
    <p>{result.aggregation}</p>
    {result.warnings.length > 0 && <ul aria-label="Priority data warnings">{result.warnings.map((w, i) => <li key={i}>{w}</li>)}</ul>}
    {result.status === 'NO_EVIDENCE' && <p>No currently scoreable evidence. This is not a zero-risk or safe result. Review findings and prepare intelligence first.</p>}
    {result.excluded.length > 0 && <p>Excluded from open priority: {result.excluded.map(x => `Finding #${x.finding_id} (${x.status})`).join(', ')}.</p>}
    {result.entries.map(row => <details key={row.key} className="intelligence-candidate">
      <summary>{row.title} · {row.kind === 'MAY_BE_AFFECTED' ? 'Potential match — unconfirmed' : `Finding #${row.finding_id} (${row.finding_status})`} · {interval(row.lower, row.upper)} · {row.band}</summary>
      <p>Evidence: {row.cve_id ?? 'No CVE enrichment'}{row.intelligence_run_id && ` · Intelligence #${row.intelligence_run_id}`}. {row.status}</p>
      <p>Formula: additive base {row.base_lower}–{row.base_upper}, then confidence multiplier. Confidence measures identifier linkage, not exploitability.</p>
      <div className="risk-components" role="list" aria-label="Score components">
        {row.components.map(c => <div key={c.name} role="listitem">
          <strong>{componentHelp[c.name]?.[0] ?? c.name}</strong> <Help label={`Explain ${c.name} for ${row.key}`} text={componentHelp[c.name]?.[1] ?? c.source} />: {c.raw === null || c.raw === undefined ? 'Unknown' : typeof c.raw === 'number' ? number(c.raw) : String(c.raw)} · {c.known ? 'Known' : 'Unknown / missing'}<br />
          {c.operation === 'multiply' ? 'Multiplier' : `Contribution (weight ${c.weight})`}: {number(c.lower)}–{number(c.upper)}<br />
          <small>{c.source}</small>
        </div>)}
      </div>
    </details>)}
  </details>;
}
