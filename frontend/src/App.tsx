import {
  Activity,
  AlertTriangle,
  Box,
  BriefcaseBusiness,
  Crosshair,
  Database,
  GitCompare,
  Globe2,
  Play,
  Plus,
  Radar,
  RefreshCw,
} from "lucide-react";
import { FormEvent, useEffect, useMemo, useState } from "react";

import { api, Asset, ChangeSet, Finding, Organization, ScannerAdapter, ScannerJob, Scope, Service } from "./api";
import signalHoundLogo from "./assets/signalhound-logo.png";

type Tab = "overview" | "scopes" | "inventory" | "findings" | "scanners" | "changes";

const tabs: { id: Tab; label: string; icon: typeof Activity }[] = [
  { id: "overview", label: "Overview", icon: Activity },
  { id: "scopes", label: "Scopes", icon: Crosshair },
  { id: "scanners", label: "Scanners", icon: Radar },
  { id: "inventory", label: "Inventory", icon: Database },
  { id: "findings", label: "Findings", icon: AlertTriangle },
  { id: "changes", label: "Changes", icon: GitCompare },
];

type LoadState = {
  organizations: Organization[];
  scopes: Scope[];
  assets: Asset[];
  services: Service[];
  findings: Finding[];
  scannerAdapters: ScannerAdapter[];
  scannerJobs: ScannerJob[];
  changeSets: ChangeSet[];
  health: string;
};

type ScannerActivity = {
  jobId: number;
  adapter: string;
  target: string;
} | null;

const initialState: LoadState = {
  organizations: [],
  scopes: [],
  assets: [],
  services: [],
  findings: [],
  scannerAdapters: [],
  scannerJobs: [],
  changeSets: [],
  health: "unknown",
};

export function App() {
  const [state, setState] = useState<LoadState>(initialState);
  const [selectedOrgId, setSelectedOrgId] = useState<number | null>(null);
  const [activeTab, setActiveTab] = useState<Tab>("overview");
  const [loading, setLoading] = useState(true);
  const [notice, setNotice] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [busyAction, setBusyAction] = useState<string | null>(null);
  const [scannerActivity, setScannerActivity] = useState<ScannerActivity>(null);

  const selectedOrganization = state.organizations.find((organization) => organization.id === selectedOrgId) ?? null;

  async function refresh(preferredOrgId = selectedOrgId) {
    setLoading(true);
    setError(null);
    try {
      const [health, organizations, scannerAdapters] = await Promise.all([
        api.health(),
        api.organizations(),
        api.scannerAdapters(),
      ]);
      const organizationId = preferredOrgId ?? organizations[0]?.id ?? null;

      if (organizationId === null) {
        setState({ ...initialState, organizations, scannerAdapters, health: health.status });
        setSelectedOrgId(null);
        return;
      }

      const [scopes, assets, findings, scannerJobs, changeSets] = await Promise.all([
        api.scopes(organizationId),
        api.assets(organizationId),
        api.findings(organizationId),
        api.scannerJobs(organizationId),
        api.changeSets(organizationId),
      ]);
      const services = (await Promise.all(assets.map((asset) => api.services(asset.id)))).flat();

      setSelectedOrgId(organizationId);
      setState({
        organizations,
        scopes,
        assets,
        services,
        findings,
        scannerAdapters,
        scannerJobs,
        changeSets,
        health: health.status,
      });
    } catch (caught) {
      setError(caught instanceof Error ? caught.message : "Unknown error");
    } finally {
      setLoading(false);
    }
  }

  useEffect(() => {
    void refresh();
  }, []);

  const metrics = useMemo(() => {
    const criticalFindings = state.findings.filter((finding) => finding.severity === "CRITICAL").length;
    const highFindings = state.findings.filter((finding) => finding.severity === "HIGH").length;
    return {
      activeScopes: state.scopes.filter((scope) => scope.active).length,
      activeAssets: state.assets.filter((asset) => asset.active).length,
      activeServices: state.services.filter((service) => service.active).length,
      openFindings: state.findings.filter((finding) => !["RESOLVED", "FALSE_POSITIVE"].includes(finding.status)).length,
      criticalHigh: criticalFindings + highFindings,
      preparedJobs: state.scannerJobs.filter((job) => job.status === "PREPARED").length,
      lastChangeCount: state.changeSets[0]?.summary?.total ?? 0,
    };
  }, [state]);

  async function withAction(action: () => Promise<unknown>, success: string, progress?: string): Promise<boolean> {
    setError(null);
    setNotice(progress ?? null);
    setBusyAction(progress ?? "Working");
    try {
      await action();
      setNotice(success);
      await refresh();
      return true;
    } catch (caught) {
      setError(caught instanceof Error ? caught.message : "Unknown error");
      setNotice(null);
      await refresh();
      return false;
    } finally {
      setBusyAction(null);
    }
  }

  return (
    <div className="app-shell">
      <aside className="sidebar">
        <div className="brand">
          <img alt="SignalHound" className="brand-logo" src={signalHoundLogo} />
        </div>
        <nav className="nav-list" aria-label="Primary">
          {tabs.map((tab) => {
            const Icon = tab.icon;
            return (
              <button
                className={activeTab === tab.id ? "nav-item active" : "nav-item"}
                key={tab.id}
                onClick={() => setActiveTab(tab.id)}
                title={tab.label}
                type="button"
              >
                <Icon size={18} />
                <span>{tab.label}</span>
              </button>
            );
          })}
        </nav>
        <SidebarRunStatus activity={scannerActivity} health={state.health} />
      </aside>

      <main className="workspace">
        <header className="topbar">
          <div>
            <span className="eyebrow">Dashboard</span>
            <h1>{selectedOrganization?.name ?? "No organization selected"}</h1>
          </div>
          <div className="topbar-actions">
            <label>
              Organization
              <select
                value={selectedOrgId ?? ""}
                onChange={(event) => {
                  const id = Number(event.target.value);
                  setSelectedOrgId(id);
                  void refresh(id);
                }}
              >
                {state.organizations.map((organization) => (
                  <option key={organization.id} value={organization.id}>
                    {organization.name}
                  </option>
                ))}
              </select>
            </label>
            <button className="icon-button" onClick={() => void refresh()} title="Refresh data" type="button">
              <RefreshCw size={18} />
            </button>
          </div>
        </header>

        {busyAction && <div className="notice pending">{busyAction}</div>}
        {!busyAction && notice && <div className="notice success">{notice}</div>}
        {error && <div className="notice error">{error}</div>}

        {loading ? (
          <div className="empty-state">Loading dashboard data</div>
        ) : state.organizations.length === 0 ? (
          <EmptyOrganization onCreate={(name) => withAction(() => api.createOrganization(name), "Organization created")} />
        ) : (
          <>
            {activeTab === "overview" && <Overview metrics={metrics} state={state} />}
            {activeTab === "scopes" && selectedOrgId && (
              <ScopesTab
                organizationId={selectedOrgId}
                scopes={state.scopes}
                onCreate={(payload) => withAction(() => api.createScope(payload), "Scope created")}
              />
            )}
            {activeTab === "inventory" && selectedOrgId && (
              <InventoryTab
                organizationId={selectedOrgId}
                assets={state.assets}
                services={state.services}
                scopes={state.scopes}
                onCreateAsset={(payload) => withAction(() => api.createAsset(payload), "Asset observed")}
              />
            )}
            {activeTab === "findings" && selectedOrgId && (
              <FindingsTab
                organizationId={selectedOrgId}
                assets={state.assets}
                findings={state.findings}
                onCreate={(payload) => withAction(() => api.createFinding(payload), "Finding recorded")}
              />
            )}
            {activeTab === "scanners" && selectedOrgId && (
              <ScannersTab
                organizationId={selectedOrgId}
                scopes={state.scopes}
                adapters={state.scannerAdapters}
                jobs={state.scannerJobs}
                onPrepare={(payload) => withAction(() => api.createScannerJob(payload), "Scanner job prepared")}
                onRun={async (jobId) => {
                  setError(null);
                  try {
                    await api.runScannerJob(jobId);
                    setNotice("Scanner job finished");
                    await refresh();
                    return true;
                  } catch (caught) {
                    setError(caught instanceof Error ? caught.message : "Unknown error");
                    setNotice(null);
                    await refresh();
                    return false;
                  }
                }}
                onRunStateChange={setScannerActivity}
              />
            )}
            {activeTab === "changes" && selectedOrgId && (
              <ChangesTab
                organizationId={selectedOrgId}
                changeSets={state.changeSets}
                onCompare={(payload) => withAction(() => api.createChangeSet(payload), "Change set created")}
              />
            )}
          </>
        )}
      </main>
    </div>
  );
}

function SidebarRunStatus({ activity, health }: { activity: ScannerActivity; health: string }) {
  return (
    <div className={activity ? "sidebar-status running" : "sidebar-status"} aria-live="polite">
      <span>{activity ? "Scanner running" : "System"}</span>
      {activity ? (
        <strong>
          #{activity.jobId} {activity.adapter}
          <small>{activity.target}</small>
        </strong>
      ) : (
        <strong>
          API {health}
          <small>No active scanner job</small>
        </strong>
      )}
    </div>
  );
}

function EmptyOrganization({ onCreate }: { onCreate: (name: string) => Promise<unknown> }) {
  const [name, setName] = useState("");
  return (
    <section className="panel narrow">
      <h2>Create organization</h2>
      <form
        className="inline-form"
        onSubmit={(event) => {
          event.preventDefault();
          void onCreate(name);
          setName("");
        }}
      >
        <input onChange={(event) => setName(event.target.value)} placeholder="Example Corp" required value={name} />
        <button type="submit">
          <Plus size={16} />
          Create
        </button>
      </form>
    </section>
  );
}

function Overview({ metrics, state }: { metrics: Record<string, number>; state: LoadState }) {
  return (
    <section className="stack">
      <div className="metric-grid">
        <Metric icon={Crosshair} label="Active scopes" value={metrics.activeScopes} />
        <Metric icon={Box} label="Active assets" value={metrics.activeAssets} />
        <Metric icon={Globe2} label="Open services" value={metrics.activeServices} />
        <Metric icon={AlertTriangle} label="Open findings" value={metrics.openFindings} tone="warning" />
        <Metric icon={AlertTriangle} label="Critical / high" value={metrics.criticalHigh} tone="danger" />
        <Metric icon={Radar} label="Prepared jobs" value={metrics.preparedJobs} />
        <Metric icon={GitCompare} label="Latest changes" value={metrics.lastChangeCount} />
        <Metric icon={Activity} label="Backend" value={state.health === "ok" ? "OK" : "Check"} />
      </div>
      <div className="two-column">
        <section className="panel">
          <PanelHeader title="Recent findings" />
          <SimpleTable
            columns={["Title", "Severity", "Status"]}
            rows={state.findings.slice(0, 6).map((finding) => [finding.title, finding.severity, finding.status])}
            empty="No findings"
          />
        </section>
        <section className="panel">
          <PanelHeader title="Latest scanner jobs" />
          <SimpleTable
            columns={["Adapter", "Target", "Status"]}
            rows={state.scannerJobs.slice(0, 6).map((job) => [job.adapter_name, job.target, job.status])}
            empty="No scanner jobs"
          />
        </section>
      </div>
    </section>
  );
}

function ScopesTab({
  organizationId,
  scopes,
  onCreate,
}: {
  organizationId: number;
  scopes: Scope[];
  onCreate: (payload: Record<string, unknown>) => Promise<unknown>;
}) {
  const [form, setForm] = useState({ name: "", target_type: "DOMAIN", target: "" });
  return (
    <section className="stack">
      <section className="panel">
        <PanelHeader title="Create scope" />
        <form
          className="form-grid"
          onSubmit={(event) => {
            event.preventDefault();
            void onCreate({ organization_id: organizationId, ...form });
            setForm({ name: "", target_type: "DOMAIN", target: "" });
          }}
        >
          <Field label="Name">
            <input required value={form.name} onChange={(event) => setForm({ ...form, name: event.target.value })} />
          </Field>
          <Field label="Type">
            <select value={form.target_type} onChange={(event) => setForm({ ...form, target_type: event.target.value })}>
              <option>DOMAIN</option>
              <option>HOSTNAME</option>
              <option>IP</option>
              <option>CIDR</option>
            </select>
          </Field>
          <Field label="Target">
            <input required value={form.target} onChange={(event) => setForm({ ...form, target: event.target.value })} />
          </Field>
          <button type="submit">
            <Plus size={16} />
            Create
          </button>
        </form>
      </section>
      <section className="panel">
        <PanelHeader title="Scopes" />
        <SimpleTable
          columns={["Name", "Type", "Target", "Zone", "State"]}
          rows={scopes.map((scope) => [
            scope.name,
            scope.target_type,
            scope.target,
            scope.scan_zone,
            scope.active ? "ACTIVE" : "INACTIVE",
          ])}
          empty="No scopes"
        />
      </section>
    </section>
  );
}

function InventoryTab({
  organizationId,
  scopes,
  assets,
  services,
  onCreateAsset,
}: {
  organizationId: number;
  scopes: Scope[];
  assets: Asset[];
  services: Service[];
  onCreateAsset: (payload: Record<string, unknown>) => Promise<unknown>;
}) {
  const [form, setForm] = useState({ asset_type: "SUBDOMAIN", value: "", source: "manual", scope_id: "" });
  const assetValue = (assetId: number) => assets.find((asset) => asset.id === assetId)?.value ?? `asset:${assetId}`;
  return (
    <section className="stack">
      <section className="panel">
        <PanelHeader title="Observe asset" />
        <form
          className="form-grid"
          onSubmit={(event) => {
            event.preventDefault();
            void onCreateAsset({
              organization_id: organizationId,
              asset_type: form.asset_type,
              value: form.value,
              source: form.source,
              scope_id: form.scope_id ? Number(form.scope_id) : null,
            });
            setForm({ asset_type: "SUBDOMAIN", value: "", source: "manual", scope_id: "" });
          }}
        >
          <Field label="Type">
            <select value={form.asset_type} onChange={(event) => setForm({ ...form, asset_type: event.target.value })}>
              <option>DOMAIN</option>
              <option>SUBDOMAIN</option>
              <option>IP</option>
              <option>HOST</option>
            </select>
          </Field>
          <Field label="Value">
            <input required value={form.value} onChange={(event) => setForm({ ...form, value: event.target.value })} />
          </Field>
          <Field label="Scope">
            <select value={form.scope_id} onChange={(event) => setForm({ ...form, scope_id: event.target.value })}>
              <option value="">Unverified</option>
              {scopes.map((scope) => (
                <option key={scope.id} value={scope.id}>
                  {scope.name}
                </option>
              ))}
            </select>
          </Field>
          <button type="submit">
            <Plus size={16} />
            Record
          </button>
        </form>
      </section>
      <div className="two-column">
        <section className="panel">
          <PanelHeader title="Assets" />
          <SimpleTable
            columns={["Value", "Type", "Scope", "State"]}
            rows={assets.map((asset) => [
              asset.value,
              asset.asset_type,
              asset.scope_id ? "AUTHORIZED" : "UNVERIFIED",
              asset.active ? "ACTIVE" : "INACTIVE",
            ])}
            empty="No assets"
          />
        </section>
        <section className="panel">
          <PanelHeader title="Services" />
          <SimpleTable
            columns={["Asset", "Protocol", "Port", "Name"]}
            rows={services.map((service) => [
              assetValue(service.asset_id),
              service.protocol,
              String(service.port),
              service.name ?? "-",
            ])}
            empty="No services"
          />
        </section>
      </div>
    </section>
  );
}

function FindingsTab({
  organizationId,
  assets,
  findings,
  onCreate,
}: {
  organizationId: number;
  assets: Asset[];
  findings: Finding[];
  onCreate: (payload: Record<string, unknown>) => Promise<unknown>;
}) {
  const [form, setForm] = useState({ asset_id: "", title: "", severity: "LOW", source: "manual" });
  const scannerFindings = findings.filter((finding) => finding.source !== "manual");
  const manualFindings = findings.length - scannerFindings.length;
  return (
    <section className="stack">
      <section className="summary-strip">
        <SummaryItem label="Scanner findings" value={scannerFindings.length} />
        <SummaryItem label="Manual findings" value={manualFindings} />
        <SummaryItem label="Total findings" value={findings.length} />
      </section>
      <section className="panel">
        <PanelHeader title="Record finding" />
        <form
          className="form-grid"
          onSubmit={(event) => {
            event.preventDefault();
            void onCreate({
              organization_id: organizationId,
              asset_id: Number(form.asset_id),
              title: form.title,
              severity: form.severity,
              source: form.source,
            });
            setForm({ asset_id: "", title: "", severity: "LOW", source: "manual" });
          }}
        >
          <Field label="Asset">
            <select required value={form.asset_id} onChange={(event) => setForm({ ...form, asset_id: event.target.value })}>
              <option value="">Select asset</option>
              {assets.map((asset) => (
                <option key={asset.id} value={asset.id}>
                  {asset.value}
                </option>
              ))}
            </select>
          </Field>
          <Field label="Title">
            <input required value={form.title} onChange={(event) => setForm({ ...form, title: event.target.value })} />
          </Field>
          <Field label="Severity">
            <select value={form.severity} onChange={(event) => setForm({ ...form, severity: event.target.value })}>
              <option>INFO</option>
              <option>LOW</option>
              <option>MEDIUM</option>
              <option>HIGH</option>
              <option>CRITICAL</option>
            </select>
          </Field>
          <button type="submit">
            <Plus size={16} />
            Record
          </button>
        </form>
      </section>
      <section className="panel">
        <PanelHeader title="Findings" />
        <SimpleTable
          columns={["Title", "Severity", "Status", "Source", "Asset"]}
          rows={findings.map((finding) => [
            finding.title,
            finding.severity,
            finding.status,
            finding.source,
            assets.find((asset) => asset.id === finding.asset_id)?.value ?? String(finding.asset_id),
          ])}
          empty="No findings. Scanner findings will appear here when Nuclei imports a matched template."
        />
      </section>
    </section>
  );
}

function SummaryItem({ label, value }: { label: string; value: number }) {
  return (
    <div className="summary-item">
      <span>{label}</span>
      <strong>{value}</strong>
    </div>
  );
}

function ScannersTab({
  organizationId,
  scopes,
  adapters,
  jobs,
  onPrepare,
  onRun,
  onRunStateChange,
}: {
  organizationId: number;
  scopes: Scope[];
  adapters: ScannerAdapter[];
  jobs: ScannerJob[];
  onPrepare: (payload: Record<string, unknown>) => Promise<unknown>;
  onRun: (jobId: number) => Promise<boolean>;
  onRunStateChange: (activity: ScannerActivity) => void;
}) {
  const [form, setForm] = useState({ scope_id: "", adapter_name: "nmap", target: "" });
  const [runningJobId, setRunningJobId] = useState<number | null>(null);
  const [runOutput, setRunOutput] = useState<string>("No scanner run selected.");

  async function handleRun(jobId: number) {
    const job = jobs.find((candidate) => candidate.id === jobId);
    setRunningJobId(jobId);
    onRunStateChange({
      jobId,
      adapter: job?.adapter_name ?? "scanner",
      target: job?.target ?? "target",
    });
    setRunOutput(formatRunningOutput(jobId, job));
    const startedAt = new Date();
    try {
      const success = await onRun(jobId);
      const refreshedJob = await api.scannerJob(jobId);
      setRunOutput(formatRunOutput(refreshedJob, startedAt, success));
    } finally {
      setRunningJobId(null);
      onRunStateChange(null);
    }
  }

  return (
    <section className="stack">
      <section className="panel">
        <PanelHeader title="Prepare scanner job" />
        <form
          className="form-grid"
          onSubmit={(event) => {
            event.preventDefault();
            void onPrepare({
              organization_id: organizationId,
              scope_id: Number(form.scope_id),
              adapter_name: form.adapter_name,
              target: form.target,
            });
            setForm({ scope_id: "", adapter_name: "nmap", target: "" });
          }}
        >
          <Field label="Adapter">
            <select value={form.adapter_name} onChange={(event) => setForm({ ...form, adapter_name: event.target.value })}>
              {adapters.map((adapter) => (
                <option key={adapter.name} value={adapter.name}>
                  {adapter.display_name}
                </option>
              ))}
            </select>
          </Field>
          <Field label="Scope">
            <select required value={form.scope_id} onChange={(event) => setForm({ ...form, scope_id: event.target.value })}>
              <option value="">Select scope</option>
              {scopes
                .filter((scope) => scope.active)
                .map((scope) => (
                  <option key={scope.id} value={scope.id}>
                    {scope.name}
                  </option>
                ))}
            </select>
          </Field>
          <Field label="Target">
            <input required value={form.target} onChange={(event) => setForm({ ...form, target: event.target.value })} />
          </Field>
          <button type="submit">
            <Plus size={16} />
            Prepare
          </button>
        </form>
      </section>
      <div className="scanner-workbench">
        <section className="panel">
          <PanelHeader title="Scanner jobs" />
          <table className="scanner-jobs-table compact">
            <thead>
              <tr>
                <th>Adapter</th>
                <th>Target</th>
                <th>Status</th>
                <th>Run</th>
              </tr>
            </thead>
            <tbody>
              {jobs.map((job) => (
                <tr className={job.status === "FAILED" ? "failed-row" : undefined} key={job.id}>
                  <td>{job.adapter_name}</td>
                  <td>
                    <div className="job-target">{job.target}</div>
                    <div className="job-detail">
                      {runningJobId === job.id
                        ? "Scanner is running. Results will refresh when it finishes."
                        : formatJobDetail(job)}
                    </div>
                  </td>
                  <td>
                    <StatusPill status={runningJobId === job.id ? "RUNNING" : job.status} />
                  </td>
                  <td>
                    <button
                      className="run-button"
                      disabled={runningJobId !== null}
                      onClick={() => void handleRun(job.id)}
                      title="Run scanner job"
                      type="button"
                    >
                      <Play size={16} />
                      Run
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
          {jobs.length === 0 && <div className="empty-inline">No scanner jobs</div>}
        </section>
        <section className="panel run-output-panel">
          <PanelHeader title="Run output" />
          <pre className="run-output">{runOutput}</pre>
        </section>
      </div>
    </section>
  );
}

function formatRunningOutput(jobId: number, job: ScannerJob | undefined) {
  const command = Array.isArray(job?.prepared_config.command) ? job.prepared_config.command.join(" ") : "n/a";
  return [
    "RUN",
    `  Job: #${jobId}`,
    `  Adapter: ${job?.adapter_name ?? "scanner"}`,
    `  Target: ${job?.target ?? "target"}`,
    "  Status: running",
    "",
    "IMPORT RESULT",
    "  Waiting for scanner output.",
    "",
    "SCANNER OUTPUT",
    "  The scanner process is still running. Output will appear here when the job finishes.",
    "",
    "COMMAND",
    `  ${command}`,
  ].join("\n");
}

function StatusPill({ status }: { status: ScannerJob["status"] | "RUNNING" }) {
  return <span className={`status-pill status-${status.toLowerCase()}`}>{status}</span>;
}

function summarizeJob(job: ScannerJob) {
  if (job.status === "COMPLETED") {
    return `Completed successfully. ${formatNormalizedSummary(job)}`;
  }
  if (job.status === "PREPARED") {
    return "Ready to run";
  }
  if (job.status === "RUNNING") {
    return "Scanner is running";
  }
  if (job.status === "CANCELLED") {
    return "Cancelled";
  }
  return "-";
}

function formatJobDetail(job: ScannerJob) {
  if (!job.error_message) {
    return summarizeJob(job);
  }

  const timeoutMatch = job.error_message.match(/Command .* timed out after (\d+) seconds/);
  if (timeoutMatch) {
    return `${job.adapter_name} timed out after ${timeoutMatch[1]} seconds for ${job.target}`;
  }

  return job.error_message;
}

function formatRunOutput(job: ScannerJob, startedAt: Date, success: boolean) {
  const durationSeconds = Math.max(0, Math.round((Date.now() - startedAt.getTime()) / 1000));
  const command = Array.isArray(job.prepared_config.command) ? job.prepared_config.command.join(" ") : "n/a";
  const summary = [
    "RUN",
    `  Job: #${job.id}`,
    `  Adapter: ${job.adapter_name}`,
    `  Target: ${job.target}`,
    `  Status: ${job.status}`,
    `  Duration observed in UI: ${durationSeconds}s`,
    "",
    "IMPORT RESULT",
    `  ${formatNormalizedSummary(job)}`,
    "",
    "COMMAND",
    `  ${command}`,
  ];

  if (!success || job.status === "FAILED") {
    return [...summary, "", "FAILURE", `  ${formatJobDetail(job)}`].join("\n");
  }

  const output = job.raw_output ?? JSON.stringify(job.normalized_result ?? {}, null, 2);
  return [...summary, "", "SCANNER OUTPUT", trimOutput(output)].join("\n");
}

function formatNormalizedSummary(job: ScannerJob) {
  const result = job.normalized_result;
  const assets = countNormalizedItems(result, "assets");
  const services = countNormalizedItems(result, "services");
  const findings = countNormalizedItems(result, "findings");
  return `${assets} assets, ${services} services, ${findings} findings`;
}

function countNormalizedItems(result: Record<string, unknown> | null, key: "assets" | "services" | "findings") {
  const value = result?.[key];
  return Array.isArray(value) ? value.length : 0;
}

function trimOutput(output: string) {
  const maxLength = 6000;
  if (output.length <= maxLength) {
    return output || "No scanner output returned.";
  }
  return `${output.slice(0, maxLength)}\n\n... output truncated in UI ...`;
}

function ChangesTab({
  organizationId,
  changeSets,
  onCompare,
}: {
  organizationId: number;
  changeSets: ChangeSet[];
  onCompare: (payload: Record<string, unknown>) => Promise<unknown>;
}) {
  const [form, setForm] = useState({ baseline_at: "", comparison_at: "" });
  return (
    <section className="stack">
      <section className="panel">
        <PanelHeader title="Compare exposure state" />
        <form
          className="form-grid"
          onSubmit={(event) => {
            event.preventDefault();
            void onCompare({
              organization_id: organizationId,
              baseline_at: new Date(form.baseline_at).toISOString(),
              comparison_at: new Date(form.comparison_at).toISOString(),
            });
          }}
        >
          <Field label="Baseline">
            <input
              required
              type="datetime-local"
              value={form.baseline_at}
              onChange={(event) => setForm({ ...form, baseline_at: event.target.value })}
            />
          </Field>
          <Field label="Comparison">
            <input
              required
              type="datetime-local"
              value={form.comparison_at}
              onChange={(event) => setForm({ ...form, comparison_at: event.target.value })}
            />
          </Field>
          <button type="submit">
            <GitCompare size={16} />
            Compare
          </button>
        </form>
      </section>
      <section className="panel">
        <PanelHeader title="Change sets" />
        <SimpleTable
          columns={["Created", "Baseline", "Comparison", "Events"]}
          rows={changeSets.map((changeSet) => [
            formatDate(changeSet.created_at),
            formatDate(changeSet.baseline_at),
            formatDate(changeSet.comparison_at),
            String(changeSet.summary?.total ?? 0),
          ])}
          empty="No change sets"
        />
      </section>
    </section>
  );
}

function Metric({
  icon: Icon,
  label,
  value,
  tone,
}: {
  icon: typeof Activity;
  label: string;
  value: number | string;
  tone?: "warning" | "danger";
}) {
  return (
    <section className={tone ? `metric ${tone}` : "metric"}>
      <Icon size={19} />
      <span>{label}</span>
      <strong>{value}</strong>
    </section>
  );
}

function PanelHeader({ title }: { title: string }) {
  return (
    <header className="panel-header">
      <h2>{title}</h2>
    </header>
  );
}

function Field({ label, children }: { label: string; children: React.ReactNode }) {
  return (
    <label>
      {label}
      {children}
    </label>
  );
}

function SimpleTable({ columns, rows, empty }: { columns: string[]; rows: string[][]; empty: string }) {
  return (
    <>
      <table>
        <thead>
          <tr>
            {columns.map((column) => (
              <th key={column}>{column}</th>
            ))}
          </tr>
        </thead>
        <tbody>
          {rows.map((row, rowIndex) => (
            <tr key={`${row.join(":")}-${rowIndex}`}>
              {row.map((cell, cellIndex) => (
                <td key={`${cell}-${cellIndex}`}>{cell}</td>
              ))}
            </tr>
          ))}
        </tbody>
      </table>
      {rows.length === 0 && <div className="empty-inline">{empty}</div>}
    </>
  );
}

function formatDate(value: string) {
  return new Intl.DateTimeFormat(undefined, {
    dateStyle: "short",
    timeStyle: "short",
  }).format(new Date(value));
}
