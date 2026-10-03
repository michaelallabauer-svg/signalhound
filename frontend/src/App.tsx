import * as React from "react";
import {
  Activity,
  AlertTriangle,
  Archive,
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
import { FormEvent, useEffect, useId, useMemo, useState } from "react";

import {
  api,
  Asset,
  AssetDetail,
  AssetBusinessContext,
  AssessmentFollowup,
  AssessmentRunDetail,
  AssessmentRun,
  ChangeSet,
  Finding,
  Organization,
  ScanProfile,
  ScannerAdapter,
  ScannerJob,
  Scope,
  Service,
} from "./api";
import signalHoundLogo from "./assets/signalhound-logo.png";

import { Help, fieldHelp } from "./components/Help";
import { Nodes } from "./components/Nodes";
import { Segmentation } from "./components/Segmentation";
import { BusinessContext } from "./components/BusinessContext";
import { Risk } from "./components/Risk";
import { Intelligence } from "./components/Intelligence";
import { WebFingerprints } from "./components/WebFingerprints";

type Tab = "overview" | "scopes" | "inventory" | "findings" | "scanners" | "changes" | "segmentation" | "nodes";

const tabs: { id: Tab; label: string; icon: typeof Activity }[] = [
  { id: "overview", label: "Overview", icon: Activity },
  { id: "scopes", label: "Scopes", icon: Crosshair },
  { id: "scanners", label: "Scanners", icon: Radar },
  { id: "nodes", label: "Scanner nodes", icon: Radar },
  { id: "segmentation", label: "Segmentation", icon: Crosshair },
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
  scanProfiles: ScanProfile[];
  assessmentRuns: AssessmentRun[];
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
  scanProfiles: [],
  assessmentRuns: [],
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
  const [showArchivedAssessments, setShowArchivedAssessments] = useState(false);

  const selectedOrganization = state.organizations.find((organization) => organization.id === selectedOrgId) ?? null;

  async function refresh(preferredOrgId = selectedOrgId, showLoading = true) {
    if (showLoading) {
      setLoading(true);
    }
    setError(null);
    try {
      const [health, organizations, scannerAdapters, scanProfiles] = await Promise.all([
        api.health(),
        api.organizations(),
        api.scannerAdapters(),
        api.scanProfiles(),
      ]);
      const organizationId = preferredOrgId ?? organizations[0]?.id ?? null;

      if (organizationId === null) {
        setState({ ...initialState, organizations, scannerAdapters, scanProfiles, health: health.status });
        setSelectedOrgId(null);
        return;
      }

      const [scopes, assets, findings, scannerJobs, assessmentRuns, changeSets] = await Promise.all([
        api.scopes(organizationId),
        api.assets(organizationId),
        api.findings(organizationId),
        api.scannerJobs(organizationId),
        api.assessments(organizationId, showArchivedAssessments),
        api.changeSets(organizationId),
      ]);
      // Bound fan-out: large inventories must not exhaust the API connection pool.
      const services: Service[] = [];
      for (let offset = 0; offset < assets.length; offset += 4) {
        const batch = await Promise.all(assets.slice(offset, offset + 4).map((asset) => api.services(asset.id)));
        services.push(...batch.flat());
      }

      setSelectedOrgId(organizationId);
      setState({
        organizations,
        scopes,
        assets,
        services,
        findings,
        scannerAdapters,
        scanProfiles,
        assessmentRuns,
        scannerJobs,
        changeSets,
        health: health.status,
      });
    } catch (caught) {
      setError(caught instanceof Error ? caught.message : "Unknown error");
    } finally {
      if (showLoading) {
        setLoading(false);
      }
    }
  }

  useEffect(() => {
    void refresh();
  }, []);

  useEffect(() => {
    if (selectedOrgId !== null) {
      void refresh(selectedOrgId, false);
    }
  }, [showArchivedAssessments]);

  useEffect(() => {
    const hasActiveAssessment = state.assessmentRuns.some((run) => ["QUEUED", "RUNNING"].includes(run.status));
    if (selectedOrgId === null || !hasActiveAssessment) {
      return undefined;
    }

    const intervalId = window.setInterval(() => {
      void refresh(selectedOrgId, false);
    }, 5000);

    return () => window.clearInterval(intervalId);
  }, [selectedOrgId, state.assessmentRuns]);

  const activeAssessment =
    state.assessmentRuns.find((run) => ["RUNNING", "QUEUED"].includes(run.status)) ?? null;

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
      runningAssessments: state.assessmentRuns.filter((run) => ["QUEUED", "RUNNING"].includes(run.status)).length,
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
        <SidebarRunStatus activity={scannerActivity} assessment={activeAssessment} health={state.health} />
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
            {activeTab === "nodes" && selectedOrgId && <Nodes key={selectedOrgId} organizationId={selectedOrgId} />}
            {activeTab === "segmentation" && selectedOrgId && <Segmentation key={selectedOrgId} organizationId={selectedOrgId} scopes={state.scopes} />}
            {activeTab === "overview" && <Overview metrics={metrics} state={state} />}
            {activeTab === "scopes" && selectedOrgId && (
              <ScopesTab
                organizationId={selectedOrgId}
                scopes={state.scopes}
                onCreate={(payload) => withAction(() => api.createScope(payload), "Scope created")}
                onArchive={(scopeId) => withAction(() => api.archiveScope(scopeId), "Scope archived")}
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
                profiles={state.scanProfiles}
                jobs={state.scannerJobs}
                assessmentRuns={state.assessmentRuns}
                showArchivedAssessments={showArchivedAssessments}
                onToggleArchivedAssessments={setShowArchivedAssessments}
                onPrepare={(payload) => withAction(() => api.createScannerJob(payload), "Scanner job prepared")}
                onCreateAssessment={(payload) =>
                  withAction(
                    () => api.createAssessment(payload),
                    "Assessment queued",
                    "Assessment queued. Scanner jobs will run in the worker.",
                  )
                }
                onPrepareVulnerabilityChecks={async (assessmentRunId) => {
                  const result = await api.prepareVulnerabilityChecks(assessmentRunId);
                  await refresh(selectedOrgId, false);
                  return result;
                }}
                onPrepareWebFingerprints={async (assessmentRunId) => {
                  const result = await api.prepareWebFingerprints(assessmentRunId);
                  await refresh(selectedOrgId, false);
                  return result;
                }}
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
                onArchiveAssessment={(assessmentRunId) =>
                  withAction(() => api.archiveAssessment(assessmentRunId), "Assessment archived")
                }
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

function SidebarRunStatus({
  activity,
  assessment,
  health,
}: {
  activity: ScannerActivity;
  assessment: AssessmentRun | null;
  health: string;
}) {
  const isBusy = activity !== null || assessment !== null;
  const statusLabel = activity
    ? "Scanner running"
    : assessment?.status === "QUEUED"
      ? "Assessment queued"
      : assessment
        ? "Assessment running"
        : "System";

  return (
    <div className={isBusy ? "sidebar-status running" : "sidebar-status"} aria-live="polite">
      <span>{statusLabel}</span>
      {activity ? (
        <strong>
          #{activity.jobId} {activity.adapter}
          <small>{activity.target}</small>
        </strong>
      ) : assessment ? (
        <strong>
          #{assessment.id} {assessment.profile_name}
          <small>{assessment.target}</small>
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
  onArchive,
}: {
  organizationId: number;
  scopes: Scope[];
  onCreate: (payload: Record<string, unknown>) => Promise<unknown>;
  onArchive: (scopeId: number) => Promise<unknown>;
}) {
  const [form, setForm] = useState({ name: "", target_type: "DOMAIN", target: "", scan_zone: "EXTERNAL" });
  return (
    <section className="stack">
      <section className="panel">
        <PanelHeader title="Create scope" />
        <form
          className="form-grid"
          onSubmit={(event) => {
            event.preventDefault();
            void onCreate({ organization_id: organizationId, ...form });
            setForm({ name: "", target_type: "DOMAIN", target: "", scan_zone: "EXTERNAL" });
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
          <Field label="Zone">
            <select value={form.scan_zone} onChange={(event) => setForm({ ...form, scan_zone: event.target.value })}>
              <option value="EXTERNAL">EXTERNAL</option>
              <option value="INTERNAL_IT">INTERNAL_IT</option>
            </select>
          </Field>
          <button type="submit">
            <Plus size={16} />
            Create
          </button>
        </form>
      </section>
      <section className="panel">
        <PanelHeader title="Scopes" />
        <table>
          <thead>
            <tr>
              <th>Name</th>
              <th>Type</th>
              <th>Target</th>
              <th>Zone</th>
              <th>State</th>
              <th>Archive</th>
            </tr>
          </thead>
          <tbody>
            {scopes.map((scope) => (
              <tr key={scope.id}>
                <td>{scope.name}</td>
                <td>{scope.target_type}</td>
                <td>{scope.target}</td>
                <td>{scope.scan_zone}</td>
                <td>{scope.active ? "ACTIVE" : "ARCHIVED"}</td>
                <td>
                  <button
                    className="icon-button compact"
                    disabled={!scope.active}
                    onClick={() => void onArchive(scope.id)}
                    title="Archive scope"
                    type="button"
                  >
                    <Archive size={15} />
                  </button>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
        {scopes.length === 0 && <div className="empty-inline">No scopes</div>}
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
  const [showInactiveAssets, setShowInactiveAssets] = useState(false);
  const [selectedAssetId, setSelectedAssetId] = useState<number | null>(null);
  const [assetDetail, setAssetDetail] = useState<AssetDetail | null>(null);
  const [detailError, setDetailError] = useState<string | null>(null);
  const visibleAssets = showInactiveAssets ? assets : assets.filter((asset) => asset.active);
  const visibleAssetIds = new Set(visibleAssets.map((asset) => asset.id));
  const visibleServices = services.filter((service) => visibleAssetIds.has(service.asset_id));
  const assetValue = (assetId: number) => assets.find((asset) => asset.id === assetId)?.value ?? `asset:${assetId}`;
  const selectedAsset = visibleAssets.find((asset) => asset.id === selectedAssetId) ?? visibleAssets[0] ?? null;

  useEffect(() => {
    if (selectedAssetId !== null && visibleAssets.some((asset) => asset.id === selectedAssetId)) {
      return;
    }
    setSelectedAssetId(visibleAssets[0]?.id ?? null);
  }, [selectedAssetId, visibleAssets]);

  useEffect(() => {
    if (selectedAsset === null) {
      setAssetDetail(null);
      return;
    }

    let cancelled = false;
    setDetailError(null);
    api
      .assetDetail(selectedAsset.id)
      .then((detail) => {
        if (!cancelled) {
          setAssetDetail(detail);
        }
      })
      .catch((caught) => {
        if (!cancelled) {
          setAssetDetail(null);
          setDetailError(caught instanceof Error ? caught.message : "Failed to load asset details");
        }
      });
    return () => {
      cancelled = true;
    };
  }, [selectedAsset]);

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
          <PanelHeader
            title="Assets"
            action={
              <label className="inline-toggle">
                <input
                  checked={showInactiveAssets}
                  onChange={(event) => setShowInactiveAssets(event.target.checked)}
                  type="checkbox"
                />
                Show inactive
              </label>
            }
          />
          <SimpleTable
            columns={["Value", "Type", "Scope", "State"]}
            rows={visibleAssets.map((asset) => [
              asset.value,
              asset.asset_type,
              asset.scope_id ? "AUTHORIZED" : "UNVERIFIED",
              asset.active ? "ACTIVE" : "INACTIVE",
            ])}
            rowClassName={(rowIndex) => (visibleAssets[rowIndex]?.id === selectedAsset?.id ? "selected-row" : "")}
            onRowClick={(rowIndex) => {
              const asset = visibleAssets[rowIndex];
              if (asset) {
                setSelectedAssetId(asset.id);
              }
            }}
            empty="No assets"
          />
        </section>
        <section className="panel">
          <PanelHeader title={selectedAsset ? `Asset details: ${selectedAsset.value}` : "Asset details"} />
          {detailError && <div className="notice error compact">{detailError}</div>}
          {!detailError && selectedAsset && assetDetail?.id !== selectedAsset.id && (
            <div className="empty-inline">Loading asset details</div>
          )}
          {!detailError && selectedAsset && assetDetail?.id === selectedAsset.id && (
            <AssetDetailPanel key={assetDetail.id} detail={assetDetail} scope={scopes.find((scope) => scope.id === assetDetail.scope_id) ?? null} />
          )}
          {!selectedAsset && <div className="empty-inline">Select an asset</div>}
        </section>
      </div>
      <section className="panel">
        <PanelHeader title="Services" />
        <SimpleTable
          columns={["Asset", "Protocol", "Port", "Name"]}
          rows={visibleServices.map((service) => [
            assetValue(service.asset_id),
            service.protocol,
            String(service.port),
            service.name ?? "-",
          ])}
          empty="No services"
        />
      </section>
    </section>
  );
}

function AssetDetailPanel({ detail, scope }: { detail: AssetDetail; scope: Scope | null }) {
  const [businessContext, setBusinessContext] = useState<AssetBusinessContext | null>(null);
  const latestObservation = detail.observations.at(-1);
  const latestMetadata = latestObservation?.metadata ?? {};
  const statusReason = typeof latestMetadata.status_reason === "string" ? latestMetadata.status_reason : "-";
  const addressType = typeof latestMetadata.addrtype === "string" ? latestMetadata.addrtype : "-";

  return (
    <div className="asset-detail">
      <div className="detail-grid">
        <SummaryItem label="State" value={detail.active ? "ACTIVE" : "INACTIVE"} />
        <SummaryItem label="Scope" value={scope ? scope.name : "Unverified"} />
        <SummaryItem label="Source" value={detail.source} />
        <SummaryItem label="Known" value={detail.known_asset ? "YES" : "NO"} />
      </div>
      <dl className="detail-list">
        <div>
          <dt>First seen</dt>
          <dd>{formatDate(detail.first_seen)}</dd>
        </div>
        <div>
          <dt>Last seen</dt>
          <dd>{formatDate(detail.last_seen)}</dd>
        </div>
        <div>
          <dt>Discovery reason</dt>
          <dd>{statusReason}</dd>
        </div>
        <div>
          <dt>Address type</dt>
          <dd>{addressType}</dd>
        </div>
      </dl>
      <section className="detail-section">
        <h3>Services</h3>
        <SimpleTable
          columns={["Protocol", "Port", "Name", "State"]}
          rows={detail.services.map((service) => [
            service.protocol,
            String(service.port),
            service.name ?? "-",
            service.active ? "ACTIVE" : "INACTIVE",
          ])}
          empty="No services observed"
        />
      </section>
      <BusinessContext assetId={detail.id} organizationId={detail.organization_id} onChange={setBusinessContext} />
      <WebFingerprints detail={detail} />
      <Intelligence key={detail.id} assetId={detail.id} organizationId={detail.organization_id} />
      <Risk key={`risk-${detail.id}`} assetId={detail.id} organizationId={detail.organization_id} savedContext={businessContext} />
      <section className="detail-section">
        <h3>Findings</h3>
        <SimpleTable
          columns={["Severity", "Title", "Status"]}
          rows={detail.findings.map((finding) => [finding.severity, finding.title, finding.status])}
          empty="No findings"
        />
      </section>
      <section className="detail-section">
        <h3>Recent observations</h3>
        <SimpleTable
          columns={["Observed", "Source", "Metadata"]}
          rows={detail.observations.slice(-5).reverse().map((observation) => [
            formatDate(observation.observed_at),
            observation.source,
            compactJson(observation.metadata),
          ])}
          empty="No observations"
        />
      </section>
    </div>
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
      <p>For CVE context, open the asset in Inventory → Vulnerability intelligence. Enrichment does not change these findings.</p>
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

function SummaryItem({ label, value }: { label: string; value: number | string }) {
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
  profiles,
  jobs,
  assessmentRuns,
  showArchivedAssessments,
  onToggleArchivedAssessments,
  onPrepare,
  onCreateAssessment,
  onPrepareVulnerabilityChecks,
  onPrepareWebFingerprints,
  onRun,
  onRunStateChange,
  onArchiveAssessment,
}: {
  organizationId: number;
  scopes: Scope[];
  adapters: ScannerAdapter[];
  profiles: ScanProfile[];
  jobs: ScannerJob[];
  assessmentRuns: AssessmentRun[];
  showArchivedAssessments: boolean;
  onToggleArchivedAssessments: (show: boolean) => void;
  onPrepare: (payload: Record<string, unknown>) => Promise<unknown>;
  onCreateAssessment: (payload: Record<string, unknown>) => Promise<boolean>;
  onPrepareVulnerabilityChecks: (assessmentRunId: number) => Promise<AssessmentFollowup>;
  onPrepareWebFingerprints: (assessmentRunId: number) => Promise<AssessmentFollowup>;
  onRun: (jobId: number) => Promise<boolean>;
  onRunStateChange: (activity: ScannerActivity) => void;
  onArchiveAssessment: (assessmentRunId: number) => Promise<unknown>;
}) {
  const [form, setForm] = useState({ scope_id: "", adapter_name: "nmap", target: "" });
  const [assessmentForm, setAssessmentForm] = useState({ scope_id: "", profile_name: "external_quick", target: "" });
  const [selectedAssessmentId, setSelectedAssessmentId] = useState<number | null>(null);
  const [assessmentDetail, setAssessmentDetail] = useState<AssessmentRunDetail | null>(null);
  const [assessmentDetailError, setAssessmentDetailError] = useState<string | null>(null);
  const [assessmentSubmitError, setAssessmentSubmitError] = useState<string | null>(null);
  const [followupBusy, setFollowupBusy] = useState(false);
  const [followupError, setFollowupError] = useState<string | null>(null);
  const [followupNotice, setFollowupNotice] = useState<string | null>(null);
  const [runningJobId, setRunningJobId] = useState<number | null>(null);
  const [runOutput, setRunOutput] = useState<string>("No scanner run selected.");
  const activeScopes = useMemo(() => scopes.filter((scope) => scope.active), [scopes]);
  const selectedAssessmentScope =
    activeScopes.find((scope) => String(scope.id) === assessmentForm.scope_id) ?? null;
  const availableProfiles = useMemo(
    () =>
      selectedAssessmentScope
        ? profiles.filter((profile) => profile.scan_zone === selectedAssessmentScope.scan_zone)
        : profiles,
    [profiles, selectedAssessmentScope],
  );

  useEffect(() => {
    if (availableProfiles.length === 0) {
      return;
    }
    if (!availableProfiles.some((profile) => profile.name === assessmentForm.profile_name)) {
      setAssessmentForm((current) => ({ ...current, profile_name: availableProfiles[0].name }));
    }
  }, [availableProfiles, assessmentForm.profile_name]);

  useEffect(() => {
    if (assessmentRuns.length === 0) {
      setSelectedAssessmentId(null);
      setAssessmentDetail(null);
      return;
    }
    if (selectedAssessmentId === null || !assessmentRuns.some((run) => run.id === selectedAssessmentId)) {
      setSelectedAssessmentId(assessmentRuns[assessmentRuns.length - 1].id);
    }
  }, [assessmentRuns, selectedAssessmentId]);

  useEffect(() => {
    if (selectedAssessmentId === null) {
      setAssessmentDetail(null);
      setFollowupError(null);
      setFollowupNotice(null);
      return undefined;
    }

    let cancelled = false;
    async function loadAssessmentDetail() {
      setAssessmentDetailError(null);
      try {
        const detail = await api.assessmentDetail(selectedAssessmentId as number);
        if (!cancelled) {
          setAssessmentDetail(detail);
        }
      } catch (caught) {
        if (!cancelled) {
          setAssessmentDetailError(caught instanceof Error ? caught.message : "Could not load assessment details");
        }
      }
    }

    void loadAssessmentDetail();
    return () => {
      cancelled = true;
    };
  }, [selectedAssessmentId, assessmentRuns, jobs]);

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

  async function handlePrepareVulnerabilityChecks(assessmentRunId: number) {
    setFollowupBusy(true);
    setFollowupError(null);
    setFollowupNotice(null);
    try {
      const result = await onPrepareVulnerabilityChecks(assessmentRunId);
      setRunOutput(formatFollowupOutput(result));
      setFollowupNotice(formatFollowupNotice(result));
      const detail = await api.assessmentDetail(assessmentRunId);
      setAssessmentDetail(detail);
    } catch (caught) {
      setFollowupError(caught instanceof Error ? caught.message : "Could not prepare vulnerability checks");
    } finally {
      setFollowupBusy(false);
    }
  }

  async function handlePrepareWebFingerprints(assessmentRunId: number) {
    setFollowupBusy(true);
    setFollowupError(null);
    setFollowupNotice(null);
    try {
      const result = await onPrepareWebFingerprints(assessmentRunId);
      setRunOutput(formatAssessmentFollowupOutput(result, "WEB FINGERPRINT PREPARATION"));
      setFollowupNotice(formatAssessmentFollowupNotice(result, "web fingerprint"));
      const detail = await api.assessmentDetail(assessmentRunId);
      setAssessmentDetail(detail);
    } catch (caught) {
      setFollowupError(caught instanceof Error ? caught.message : "Could not prepare web fingerprinting");
    } finally {
      setFollowupBusy(false);
    }
  }

  function updateAssessmentScope(scopeId: string) {
    const scope = activeScopes.find((candidate) => String(candidate.id) === scopeId);
    setAssessmentSubmitError(null);
    setAssessmentForm((current) => ({
      ...current,
      scope_id: scopeId,
      target: scope?.target ?? current.target,
    }));
  }

  function updateScannerJobScope(scopeId: string) {
    const scope = activeScopes.find((candidate) => String(candidate.id) === scopeId);
    setForm((current) => ({
      ...current,
      scope_id: scopeId,
      target: scope?.target ?? current.target,
    }));
  }

  return (
    <section className="stack">
      <section className="panel">
        <PanelHeader title="Run assessment" />
        <ol className="workflow-guide" aria-label="Assessment workflow">
          <li><strong>Discover</strong><span>Select a scope and run an assessment to find hosts and services.</span></li>
          <li><strong>Identify web services</strong><span>Select a completed run below, prepare web fingerprinting, then start the prepared jobs.</span></li>
          <li><strong>Review & check</strong><span>Read fingerprints in Inventory → asset details. Prepare vulnerability checks when ready, then start those jobs.</span></li>
        </ol>
        {activeScopes.length === 0 && <p className="notice pending">First create an active scan scope in Scopes, then return here.</p>}
        <form
          className="form-grid"
          onSubmit={async (event) => {
            event.preventDefault();
            setAssessmentSubmitError(null);
            const selectedProfile = availableProfiles.find((profile) => profile.name === assessmentForm.profile_name);
            const created = await onCreateAssessment({
              organization_id: organizationId,
              scope_id: Number(assessmentForm.scope_id),
              profile_name: selectedProfile?.name ?? assessmentForm.profile_name,
              target: assessmentForm.target,
            });
            if (created) {
              setAssessmentForm({ scope_id: "", profile_name: "external_quick", target: "" });
            } else {
              setAssessmentSubmitError("Assessment could not be queued. Check the selected scope and target.");
            }
          }}
        >
          <Field label="Profile">
            <select
              value={assessmentForm.profile_name}
              onChange={(event) => setAssessmentForm({ ...assessmentForm, profile_name: event.target.value })}
            >
              {availableProfiles.map((profile) => (
                <option key={profile.name} value={profile.name}>
                  {profile.display_name}
                </option>
              ))}
            </select>
          </Field>
          <Field label="Scope">
            <select
              required
              value={assessmentForm.scope_id}
              onChange={(event) => updateAssessmentScope(event.target.value)}
            >
              <option value="">Select scope</option>
              {activeScopes.map((scope) => (
                <option key={scope.id} value={scope.id}>
                  {scope.name} ({scope.target}, {scope.scan_zone})
                </option>
              ))}
            </select>
          </Field>
          <Field label="Target">
            <input
              required
              value={assessmentForm.target}
              onChange={(event) => setAssessmentForm({ ...assessmentForm, target: event.target.value })}
            />
          </Field>
          <button type="submit">
            <Play size={16} />
            Run assessment
          </button>
        </form>
        {assessmentSubmitError && <div className="notice error">{assessmentSubmitError}</div>}
      </section>
      <section className="panel">
        <PanelHeader title="Prepare scanner job" />
        <p className="guidance">Advanced: prepare one job manually. For a guided discovery run, use Run assessment above. Preparing does not start a scan.</p>
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
            <select required value={form.scope_id} onChange={(event) => updateScannerJobScope(event.target.value)}>
              <option value="">Select scope</option>
              {activeScopes.map((scope) => (
                <option key={scope.id} value={scope.id}>
                  {scope.name} ({scope.target}, {scope.scan_zone})
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
      <section className="panel">
        <PanelHeader title="Assessment runs" />
        <label className="inline-toggle">
          <input
            checked={showArchivedAssessments}
            onChange={(event) => onToggleArchivedAssessments(event.target.checked)}
            type="checkbox"
          />
          Show archived runs
        </label>
        <table className="assessment-runs-table">
          <thead>
            <tr>
              <th>Profile</th>
              <th>Target</th>
              <th>Status</th>
              <th>Imported</th>
              <th>Archive</th>
            </tr>
          </thead>
          <tbody>
            {assessmentRuns.map((run) => (
              <tr
                className={run.id === selectedAssessmentId ? "selected-row" : undefined}
                key={run.id}
                onClick={() => setSelectedAssessmentId(run.id)}
                tabIndex={0}
                onKeyDown={(event) => { if (event.target === event.currentTarget && (event.key === "Enter" || event.key === " ")) { event.preventDefault(); setSelectedAssessmentId(run.id); } }}
              >
                <td>{run.profile_name}</td>
                <td>{run.target}</td>
                <td>
                  <StatusPill status={run.status} />
                </td>
                <td>{`${run.summary.assets ?? 0} assets, ${run.summary.services ?? 0} services, ${
                  run.summary.findings ?? 0
                } findings`}</td>
                <td>
                  <button
                    className="icon-button compact"
                    disabled={["QUEUED", "RUNNING", "ARCHIVED"].includes(run.status)}
                    onClick={(event) => {
                      event.stopPropagation();
                      void onArchiveAssessment(run.id);
                    }}
                    title="Archive assessment run"
                    type="button"
                  >
                    <Archive size={15} />
                  </button>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
        {assessmentRuns.length === 0 && <div className="empty-inline">No assessment runs</div>}
        {assessmentDetailError && <div className="notice error">{assessmentDetailError}</div>}
        {assessmentDetail && (
          <div className="assessment-detail">
            <div className="assessment-summary">
              <SummaryItem label="Jobs" value={assessmentDetail.jobs.length} />
              <SummaryItem label="Assets" value={assessmentDetail.summary.assets ?? 0} />
              <SummaryItem label="Services" value={assessmentDetail.summary.services ?? 0} />
              <SummaryItem label="Findings" value={assessmentDetail.summary.findings ?? 0} />
            </div>
            {assessmentDetail.error_message && <div className="notice error">{assessmentDetail.error_message}</div>}
            {followupError && <div className="notice error">{followupError}</div>}
            {followupNotice && <div className="notice success">{followupNotice}</div>}
            <p className="guidance" role="status">{assessmentDetail.status !== "COMPLETED"
              ? "Follow-up preparation becomes available when this assessment completes successfully. For failed runs, inspect the job output below."
              : "Next: prepare web fingerprinting, then use Run in Scanner jobs below. Once complete, view the results in Inventory → asset details."}</p>
            <div className="assessment-actions">
              <Help label="About preparing follow-ups" text="These buttons only create jobs from web services observed by this assessment. They do not run scans. Existing jobs are skipped; if no web services were found, run a new discovery assessment first." />
              <button
                disabled={assessmentDetail.status !== "COMPLETED" || followupBusy}
                onClick={() => void handlePrepareWebFingerprints(assessmentDetail.id)}
                type="button"
              >
                <Globe2 size={16} />
                {followupBusy ? "Preparing" : "Prepare web fingerprinting"}
              </button>
              <button
                disabled={assessmentDetail.status !== "COMPLETED" || followupBusy}
                onClick={() => void handlePrepareVulnerabilityChecks(assessmentDetail.id)}
                type="button"
              >
                <Radar size={16} />
                {followupBusy ? "Preparing checks" : "Prepare vulnerability checks"}
              </button>
            </div>
            <div className="assessment-job-list">
              {assessmentDetail.jobs.map((job) => (
                <button
                  className="assessment-job-button"
                  key={job.id}
                  onClick={() => setRunOutput(formatStoredJobOutput(job))}
                  type="button"
                >
                  <span>{job.adapter_name}</span>
                  <StatusPill status={job.status} />
                  <small>{formatJobDetail(job)}</small>
                </button>
              ))}
            </div>
          </div>
        )}
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
              {jobs.map((job) => {
                const canRun = job.status === "PREPARED" && runningJobId === null;
                return (
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
                        disabled={!canRun}
                        onClick={() => void handleRun(job.id)}
                        title={job.status === "PREPARED" ? "Run scanner job" : "Only prepared jobs can be run"}
                        type="button"
                      >
                        <Play size={16} />
                        {runningJobId === job.id || job.status === "RUNNING" ? "Running" : job.status === "PREPARED" ? "Run" : job.status === "COMPLETED" ? "Done" : job.status === "FAILED" ? "Failed" : "Cancelled"}
                      </button>
                    </td>
                  </tr>
                );
              })}
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

function StatusPill({ status }: { status: ScannerJob["status"] | AssessmentRun["status"] }) {
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

function formatStoredJobOutput(job: ScannerJob) {
  const command = Array.isArray(job.prepared_config.command) ? job.prepared_config.command.join(" ") : "n/a";
  const summary = [
    "RUN",
    `  Job: #${job.id}`,
    `  Adapter: ${job.adapter_name}`,
    `  Target: ${job.target}`,
    `  Status: ${job.status}`,
    "",
    "IMPORT RESULT",
    `  ${formatNormalizedSummary(job)}`,
    "",
    "COMMAND",
    `  ${command}`,
  ];

  if (job.error_message) {
    summary.push("", "FAILURE", `  ${formatJobDetail(job)}`);
  }

  const output = job.raw_output ?? JSON.stringify(job.normalized_result ?? {}, null, 2);
  return [...summary, "", "SCANNER OUTPUT", trimOutput(output)].join("\n");
}

function formatFollowupOutput(result: AssessmentFollowup) {
  return formatAssessmentFollowupOutput(result, "FOLLOW-UP CHECK PREPARATION");
}

function formatAssessmentFollowupOutput(result: AssessmentFollowup, title: string) {
  const lines = [
    title,
    `  Assessment: #${result.assessment_run_id}`,
    `  Adapter: ${result.adapter_name}`,
    "",
    "CANDIDATES",
    `  ${result.candidate_targets.length ? result.candidate_targets.join(", ") : "No web-service targets found"}`,
    "",
    "PREPARED JOBS",
    `  ${result.prepared_targets.length ? result.prepared_targets.join(", ") : "No new jobs prepared"}`,
  ];

  if (result.skipped_targets.length) {
    lines.push("", "SKIPPED EXISTING JOBS", `  ${result.skipped_targets.join(", ")}`);
  }

  if (!result.candidate_targets.length) {
    lines.push(
      "",
      "NEXT STEP",
      `  No ${result.adapter_name} jobs were prepared because this assessment did not observe web services.`,
    );
  } else if (result.prepared_targets.length) {
    lines.push("", "NEXT STEP", "  Start the prepared jobs from the Scanner jobs table.");
  }

  return lines.join("\n");
}

function formatFollowupNotice(result: AssessmentFollowup) {
  return formatAssessmentFollowupNotice(result, "vulnerability check");
}

function formatAssessmentFollowupNotice(result: AssessmentFollowup, noun: string) {
  if (result.prepared_targets.length > 0) {
    return `${result.prepared_targets.length} ${noun}${
      result.prepared_targets.length === 1 ? "" : "s"
    } prepared. Start the prepared job${result.prepared_targets.length === 1 ? "" : "s"} below.`;
  }
  if (result.skipped_targets.length > 0) {
    return `${noun[0].toUpperCase()}${noun.slice(1)}s were already prepared for the observed web services.`;
  }
  return `No ${noun}s were prepared because this assessment did not observe web services.`;
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

function PanelHeader({ title, action }: { title: string; action?: React.ReactNode }) {
  return (
    <header className="panel-header">
      <h2>{title}</h2>
      {action}
    </header>
  );
}

function Field({ label, children }: { label: string; children: React.ReactNode }) {
  const id = useId();
  return (
    <div className="form-field">
      <span className="field-heading"><label htmlFor={id}>{label}</label>{fieldHelp[label] && <Help label={`Help for ${label}`} text={fieldHelp[label]} />}</span>
      <div className="field-control">{React.isValidElement<{ id?: string }>(children) ? React.cloneElement(children, { id }) : children}</div>
    </div>
  );
}

function SimpleTable({
  columns,
  rows,
  empty,
  onRowClick,
  rowClassName,
}: {
  columns: string[];
  rows: React.ReactNode[][];
  empty: string;
  onRowClick?: (rowIndex: number) => void;
  rowClassName?: (rowIndex: number) => string;
}) {
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
            <tr
              className={[onRowClick ? "clickable-row" : "", rowClassName?.(rowIndex) ?? ""].filter(Boolean).join(" ")}
              key={`${rowIndex}-${columns.join(":")}`}
              onClick={onRowClick ? () => onRowClick(rowIndex) : undefined}
              tabIndex={onRowClick ? 0 : undefined}
              onKeyDown={onRowClick ? (event) => { if (event.key === "Enter" || event.key === " ") { event.preventDefault(); onRowClick(rowIndex); } } : undefined}
            >
              {row.map((cell, cellIndex) => (
                <td key={cellIndex}>{cell}</td>
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

function compactJson(value: Record<string, unknown>) {
  const entries = Object.entries(value).filter(([, entryValue]) => entryValue !== null && entryValue !== undefined);
  if (entries.length === 0) {
    return "-";
  }
  return entries
    .map(([key, entryValue]) => `${key}: ${String(entryValue)}`)
    .join(", ");
}
