import { useEffect, useId, useState } from 'react';
import { api, type AssetBusinessContext, type ContextHistory, type Site } from '../api';
import { Help } from './Help';

const empty = { criticality: '', environment: 'UNKNOWN', technical_owner: '', organizational_owner: '', responsible_team: '', site_id: '', notes: '' };
function editValues(context: AssetBusinessContext) {
  return { criticality: context.criticality ?? '', environment: context.environment,
    technical_owner: context.technical_owner ?? '', organizational_owner: context.organizational_owner ?? '',
    responsible_team: context.responsible_team ?? '', site_id: context.site_id == null ? '' : String(context.site_id), notes: context.notes ?? '' };
}
const ownerFields = [
  ['technical_owner', 'Technical owner', 'The person or role responsible for technical operation and maintenance. This is a label, not an application account or permission.'],
  ['organizational_owner', 'Business owner', 'The person or business unit accountable for the business service and its impact.'],
  ['responsible_team', 'Responsible team', 'The team that should handle this asset. Saving a team does not send notifications or create tickets.'],
] as const;

export function BusinessContext({ assetId, organizationId, onChange }: {
  assetId: number; organizationId: number; onChange: (value: AssetBusinessContext) => void;
}) {
  const formId = useId();
  const [context, setContext] = useState<AssetBusinessContext | null>(null);
  const [sites, setSites] = useState<Site[]>([]);
  const [form, setForm] = useState(empty);
  const [history, setHistory] = useState<ContextHistory[]>([]);
  const [offset, setOffset] = useState(0);
  const [reload, setReload] = useState(0);
  const [error, setError] = useState('');
  const [message, setMessage] = useState('');
  const [busy, setBusy] = useState(false);
  const [siteName, setSiteName] = useState('');
  const [siteDescription, setSiteDescription] = useState('');
  useEffect(() => {
    let current = true;
    setError('');
    Promise.all([api.businessContext(assetId, organizationId), api.sites(organizationId)]).then(([value, locations]) => {
      if (current) { setContext(value); setForm(editValues(value)); setSites(locations); onChange(value); }
    }).catch(e => { if (current) setError(e.message); });
    return () => { current = false; };
  }, [assetId, organizationId, reload, onChange]);
  useEffect(() => {
    let current = true;
    api.contextHistory(assetId, organizationId, offset).then(value => { if (current) setHistory(value); })
      .catch(e => { if (current) setError(e.message); });
    return () => { current = false; };
  }, [assetId, organizationId, offset, reload]);
  async function save() {
    if (!context) return;
    setBusy(true); setError(''); setMessage('');
    try {
      const saved = await api.saveBusinessContext(assetId, { ...form, organization_id: organizationId,
        expected_revision: context.revision, criticality: form.criticality || null,
        site_id: form.site_id ? Number(form.site_id) : null });
      setContext(saved); setForm(editValues(saved)); onChange(saved);
      if (offset) setOffset(0); else setHistory(await api.contextHistory(assetId, organizationId));
      setMessage(`Business context saved (revision ${saved.revision}). Recalculate priority to use it; old snapshots stay unchanged.`);
    } catch (e) { setError(e instanceof Error ? e.message : 'Save failed; your edits are retained.'); }
    finally { setBusy(false); }
  }
  async function refreshLocations() {
    setSites(await api.sites(organizationId));
    const value = await api.businessContext(assetId, organizationId);
    // Location labels may change, but never advance the draft's context revision silently.
    setContext(old => old && old.revision === value.revision ? { ...old, site: value.site } : old);
    onChange(value);
  }
  async function createLocation() {
    setBusy(true); setError(''); setMessage('');
    try {
      const location = await api.createSite({ organization_id: organizationId, name: siteName, description: siteDescription });
      await refreshLocations(); setSiteName(''); setSiteDescription('');
      setMessage(`Location “${location.name}” created. Select it above and save to assign it to this asset.`);
    } catch (e) { setError(e instanceof Error ? e.message : 'Location creation failed'); }
    finally { setBusy(false); }
  }
  async function changeLocation(site: Site, changes: Record<string, unknown>) {
    setBusy(true); setError(''); setMessage('');
    try {
      await api.updateSite(site.id, { organization_id: organizationId, expected_revision: site.revision, ...changes });
      await refreshLocations(); setMessage('Location updated. Existing assignments and historical snapshots are preserved.');
    } catch (e) { setError(e instanceof Error ? e.message : 'Location update failed'); }
    finally { setBusy(false); }
  }
  return <section className="detail-section business-context" aria-label="Asset business context" aria-busy={busy}>
    <h3>Asset business context <Help label="About asset business context" text="Persistent information maintained by your organization, separate from scanner observations. Scans cannot overwrite these fields. Every saved change is historized. This does not authorize a scan or grant access." /></h3>
    <p>Record business importance and responsibility here. Unknown and unassigned values remain explicit.</p>
    {error && <p role="alert">{error} Your unsaved edits are retained.</p>}
    {message && <p role="status">{message}</p>}
    {!context && !error && <p>Loading saved context…</p>}
    {context && <>
      <p>Saved revision {context.revision}{context.updated_at && ` · ${new Date(context.updated_at).toLocaleString()}`}{JSON.stringify(form) !== JSON.stringify(editValues(context)) && ' · Unsaved changes'}</p>
      <form className="business-fields" onSubmit={e => { e.preventDefault(); void save(); }}>
        <div><label htmlFor={`${formId}-criticality`}>Business criticality</label> <Help label="Help for business criticality" text="Business impact if this asset becomes unavailable or compromised: Low, Medium, High or Critical. Leave unclassified if unknown. New priority calculations can use this saved value; it does not confirm technical vulnerabilities." />
          <select id={`${formId}-criticality`} value={form.criticality} disabled={busy} onChange={e => setForm({ ...form, criticality: e.target.value })}>
            <option value="">Unclassified / unknown</option>{['LOW', 'MEDIUM', 'HIGH', 'CRITICAL'].map(value => <option key={value}>{value}</option>)}
          </select>
        </div>
        <div><label htmlFor={`${formId}-environment`}>Environment</label> <Help label="Help for environment" text="Production, Test, Development, Infrastructure or Unknown. This describes use, not reachability, scanning authorization or risk severity." />
          <select id={`${formId}-environment`} value={form.environment} disabled={busy} onChange={e => setForm({ ...form, environment: e.target.value })}>
            {['UNKNOWN', 'PRODUCTION', 'TEST', 'DEVELOPMENT', 'INFRASTRUCTURE'].map(value => <option key={value}>{value}</option>)}
          </select>
        </div>
        {ownerFields.map(([key, label, help]) => <div key={key}><label htmlFor={`${formId}-${key}`}>{label}</label> <Help label={`Help for ${label.toLowerCase()}`} text={help} />
          <input id={`${formId}-${key}`} value={form[key]} maxLength={160} disabled={busy} placeholder="Unassigned" onChange={e => setForm({ ...form, [key]: e.target.value })} />
        </div>)}
        <div><label htmlFor={`${formId}-site_id`}>Location</label> <Help label="Help for asset location" text="Select a location belonging to this organization. Manage names below. Archived locations keep existing assignments but cannot receive new ones. Unassigned does not mean external." />
          <select id={`${formId}-site_id`} value={form.site_id} disabled={busy} onChange={e => setForm({ ...form, site_id: e.target.value })}>
            <option value="">Unassigned</option>
            {sites.map(site => <option key={site.id} value={site.id} disabled={!site.active && context.site_id !== site.id}>{site.name}{!site.active && ' (archived)'}</option>)}
          </select>
        </div>
        <div><label htmlFor={`${formId}-notes`}>Context notes</label> <Help label="Help for context notes" text="Explain the business importance or responsibilities, and record useful operational context. Do not use this field for passwords or secrets." />
          <textarea id={`${formId}-notes`} value={form.notes} maxLength={2000} disabled={busy} onChange={e => setForm({ ...form, notes: e.target.value })} />
        </div>
        <button disabled={busy} type="submit">Save business context</button>
      </form>
    </>}
    <button type="button" disabled={busy} onClick={() => { setReload(n => n + 1); setMessage(''); }}>Reload saved context (discard edits)</button>
    <details className="context-locations">
      <summary>Manage organization locations</summary>
      <p>Locations are shared within this organization. Renaming changes the current label; archiving keeps assignments and history.</p>
      <form className="business-fields" onSubmit={e => { e.preventDefault(); void createLocation(); }}>
        <label>New location name<input required maxLength={160} value={siteName} disabled={busy} onChange={e => setSiteName(e.target.value)} /></label>
        <label>Location description<textarea maxLength={2000} value={siteDescription} disabled={busy} onChange={e => setSiteDescription(e.target.value)} /></label>
        <button disabled={busy || !siteName.trim()} type="submit">Create location</button>
      </form>
      {sites.length === 0 && <p>No configured locations yet.</p>}
      {sites.map(site => <LocationEditor key={`${site.id}:${site.revision}`} site={site} busy={busy} onChange={changes => changeLocation(site, changes)} />)}
    </details>
    <details>
      <summary>Business context change history</summary>
      {!history.length && <p>No recorded changes yet.</p>}
      {history.map(change => <article key={change.id} className="intelligence-candidate">
        <h4>Revision {change.revision} · {new Date(change.changed_at).toLocaleString()}</h4>
        <dl>{Object.keys(empty).filter(key => change.before[key as keyof typeof empty] !== change.after[key as keyof typeof empty]).map(key => <div key={key}>
          <dt>{key.replaceAll('_', ' ')}</dt><dd>{historyValue(change.before, key)} → {historyValue(change.after, key)}</dd>
        </div>)}</dl>
      </article>)}
      <div className="intelligence-actions">
        {offset > 0 && <button disabled={busy} onClick={() => setOffset(Math.max(0, offset - 20))}>Newer context changes</button>}
        {history.length === 20 && <button disabled={busy} onClick={() => setOffset(offset + 20)}>Older context changes</button>}
      </div>
    </details>
  </section>;
}
function historyValue(context: AssetBusinessContext, key: string) {
  if (key === 'site_id') return context.site?.name ?? 'Unassigned';
  return String(context[key as keyof AssetBusinessContext] ?? 'Unassigned');
}
function LocationEditor({ site, busy, onChange }: { site: Site; busy: boolean; onChange: (changes: Record<string, unknown>) => Promise<void> }) {
  const [name, setName] = useState(site.name);
  const [description, setDescription] = useState(site.description ?? '');
  return <details className="intelligence-candidate">
    <summary>{site.name} · {site.active ? 'Active' : 'Archived'}</summary>
    <form className="business-fields" onSubmit={e => { e.preventDefault(); void onChange({ name, description }); }}>
      <label>Location name<input required maxLength={160} disabled={busy} value={name} onChange={e => setName(e.target.value)} /></label>
      <label>Description<textarea maxLength={2000} disabled={busy} value={description} onChange={e => setDescription(e.target.value)} /></label>
      <button disabled={busy || !name.trim()} type="submit">Save location</button>
      <button disabled={busy} type="button" onClick={() => void onChange({ active: !site.active })}>{site.active ? 'Archive location' : 'Restore location'}</button>
    </form>
  </details>;
}
