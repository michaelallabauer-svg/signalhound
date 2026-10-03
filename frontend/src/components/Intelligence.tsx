import { useEffect, useState } from 'react';
import { api, type IntelligenceData, type IntelligenceRun } from '../api';
import { Help } from './Help';

function displayTime(value?: string | null) {
  if (!value) return 'Unknown';
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? 'Unknown' : date.toLocaleString();
}

export function Intelligence({ assetId, organizationId }: { assetId: number; organizationId: number }) {
  const [data, setData] = useState<IntelligenceData | null>(null);
  const [selection, setSelection] = useState('');
  const [error, setError] = useState('');
  const [busy, setBusy] = useState(false);
  const [offset, setOffset] = useState(0);
  useEffect(() => {
    let current = true;
    setData(null); setError('');
    api.intelligence(assetId, organizationId, offset).then(result => {
      if (current) { setData(result); setSelection(result.inputs[0]?.key ?? ''); }
    }).catch(e => { if (current) setError(String(e.message)); });
    return () => { current = false; };
  }, [assetId, organizationId, offset]);
  async function lookup() {
    setBusy(true); setError('');
    try {
      await api.enrich(assetId, organizationId, selection);
      if (offset !== 0) setOffset(0);
      else setData(await api.intelligence(assetId, organizationId));
    } catch (e) { setError(e instanceof Error ? e.message : 'Lookup failed'); }
    finally { setBusy(false); }
  }
  return <section className="detail-section intelligence" aria-label="Vulnerability intelligence" aria-busy={busy}>
    <h3>Vulnerability intelligence <Help label="About vulnerability intelligence" text="Public information about vulnerabilities, not a scan result. A possible match does not confirm that this asset is vulnerable. Existing finding status and severity remain unchanged." /></h3>
    <p>1. Select observed software or a finding’s CVE. 2. Look up public intelligence. 3. Review applicability before planning an authorized check.</p>
    {error && <p role="alert">{error}</p>}
    {!data && !error && <p role="status">Loading intelligence…</p>}
    {data && <>
      <h4>Observed software <Help label="About CPE" text="CPE is a standardized product identifier. Only observed identifiers with a concrete vendor, product and version can be looked up. Server headers alone are not used to guess a CPE or operating system." /></h4>
      {data.software.length === 0 ? <p>No software identity observed. Run authorized service discovery first.</p> :
        <ul>{data.software.map(s => <li key={s.observation_id}>
          Service #{s.service_id}: {s.product ?? 'Unknown product'} {s.version ?? '(version unknown)'} · {s.source} · {displayTime(s.observed_at)}
          {s.cpes.map(cpe => <code className="cpe" key={cpe}>{cpe}</code>)}
        </li>)}</ul>}
      {!data.enabled && <p>Public lookups are disabled. Ask the operator to enable intelligence lookup. Saved results remain readable.</p>}
      {data.inputs.length === 0 ? <p>No lookup-ready evidence. A version-specific CPE from a new Nmap observation or an explicit CVE reference in a finding is required. A product name or HTTP header alone is not enough.</p> :
        <div className="intelligence-actions">
          <label>Evidence to look up
            <select value={selection} disabled={busy} onChange={e => setSelection(e.target.value)}>
              {data.inputs.map(input => <option key={input.key} value={input.key}>{input.reference} · {input.kind === 'CVE' ? `Finding #${input.finding_id}` : `Service #${input.service_id}`}</option>)}
            </select>
          </label>
          <button type="button" disabled={!data.enabled || busy || !selection} onClick={() => void lookup()}>{busy ? 'Looking up…' : 'Look up intelligence'}</button>
          <Help label="About public lookups" text="Queries NVD, FIRST EPSS and CISA KEV. Only CVE/CPE identifiers leave this application, not hostnames or IP addresses. Results are cached for 24 hours; each lookup preserves a dated snapshot. No scanner jobs are started." />
        </div>}
      <h4>Saved intelligence snapshots</h4>
      {data.runs.length === 0 && <p>No saved results. No match does not mean the asset is safe.</p>}
      {data.runs.map(run => <Snapshot key={run.id} run={run} />)}
      <div className="intelligence-actions">
        {offset > 0 && <button disabled={busy} onClick={() => setOffset(Math.max(0, offset - 20))}>Newer snapshots</button>}
        {data.runs.length === 20 && <button disabled={busy} onClick={() => setOffset(offset + 20)}>Older snapshots</button>}
      </div>
    </>}
  </section>;
}

function Snapshot({ run }: { run: IntelligenceRun }) {
  return <details className="fingerprint-card" open>
    <summary>#{run.id} · {run.evidence.reference} · {run.status} · {new Date(run.created_at).toLocaleString()}</summary>
    <p>{run.result.notice}</p>
    <p>Evidence: {run.evidence.source} · {displayTime(run.evidence.observed_at)}
      {run.evidence.finding_id && ` · Finding #${run.evidence.finding_id} (${run.evidence.finding_status} at lookup)`}
      {run.evidence.observation_id && ` · Service observation #${run.evidence.observation_id}`}</p>
    <ul>{run.result.sources.map(source => <li key={source.provider}>
      {source.provider}: {source.status === 'ERROR' ? source.error : `${source.cached ? 'Cached' : 'Fetched'} ${displayTime(source.fetched_at)}`}
    </li>)}</ul>
    {run.result.truncated && <p role="status">Partial list: showing the first {run.result.candidates.length} of {run.result.total} matches. Review the full product applicability in NVD.</p>}
    {run.result.candidates.length === 0 && <p>{run.status === 'ERROR' ? 'Lookup failed. Retry later; this is not a zero-match result.' : 'No CVE match returned. This does not prove safety.'}</p>}
    {run.result.candidates.map(c => <article className="intelligence-candidate" key={c.cve_id}>
      <h4><a href={`https://nvd.nist.gov/vuln/detail/${encodeURIComponent(c.cve_id)}`} target="_blank" rel="noreferrer">{c.cve_id}</a> · {c.assessment === 'MAY_BE_AFFECTED' ? 'May be affected — unconfirmed' : c.assessment === 'FINDING_REFERENCE' ? 'Existing finding reference — no new confirmation' : 'External intelligence — rejected CVE'}</h4>
      <p>{c.description}</p>
      <p>Provider status: {c.status} · Modified: {displayTime(c.modified)}</p>
      <dl className="detail-list">
        <div><dt>Match confidence <Help label={`About confidence ${c.cve_id}`} text="Confidence describes how the identifier was linked to the observation. It is separate from severity and does not measure exploitability or verify the installed patch level." /></dt><dd>{c.confidence} — {c.match_reason}</dd></div>
        <div><dt>CVSS <Help label={`About CVSS ${c.cve_id}`} text="Technical severity from 0 to 10, with version and scoring source. It is not your organization’s risk score and does not confirm applicability." /></dt><dd>{c.cvss?.score != null ? `${c.cvss.score}/10 · v${c.cvss.version} · ${c.cvss.source ?? 'Unknown scorer'}` : 'Unknown / not supplied'} {c.cvss?.vector}</dd></div>
        <div><dt>EPSS <Help label={`About EPSS ${c.cve_id}`} text="FIRST’s estimated probability of exploitation in the next 30 days, not evidence of exploitation on this host. The date matters. Missing data is unknown, not zero." /></dt><dd>{c.epss?.score != null ? `${(c.epss.score * 100).toFixed(2)}% · percentile ${c.epss.percentile == null ? 'unknown' : (c.epss.percentile * 100).toFixed(1)} · ${c.epss.date}` : 'Unknown / not supplied'}</dd></div>
        <div><dt>CISA KEV <Help label={`About KEV ${c.cve_id}`} text="Listed means CISA has evidence of exploitation in the wild. It does not mean this asset was attacked. Not listed is not proof of safety; unknown means the catalog could not be checked." /></dt><dd>{c.kev === null ? 'Unknown — catalog unavailable' : c.kev ? 'Listed — known exploitation in the wild' : 'Not listed in the fetched catalog'}{c.kev_detail && ` · Added ${c.kev_detail.date_added} · ${c.kev_detail.required_action}`}</dd></div>
      </dl>
    </article>)}
  </details>;
}
