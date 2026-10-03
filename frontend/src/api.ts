const API_BASE_URL = import.meta.env.VITE_API_BASE_URL ?? "http://localhost:8010/api/v1";

export type Organization = {
  id: number;
  name: string;
  created_at: string;
  updated_at: string;
};

export type Scope = {
  id: number;
  organization_id: number;
  name: string;
  target_type: "DOMAIN" | "HOSTNAME" | "IP" | "CIDR";
  target: string;
  scan_zone: "EXTERNAL" | "INTERNAL_IT";
  active: boolean;
};

export type Asset = {
  id: number;
  organization_id: number;
  scope_id: number | null;
  asset_type: "DOMAIN" | "SUBDOMAIN" | "IP" | "HOST";
  value: string;
  source: string;
  active: boolean;
  known_asset: boolean;
  first_seen: string;
  last_seen: string;
};

export type AssetObservation = {
  id: number;
  asset_id: number;
  observed_at: string;
  source: string;
  metadata: Record<string, unknown>;
};

export type Service = {
  id: number;
  asset_id: number;
  protocol: "TCP" | "UDP";
  port: number;
  name: string | null;
  source: string;
  active: boolean;
};

export type ServiceObservation = {
  id: number;
  service_id: number;
  observed_at: string;
  source: string;
  metadata: Record<string, unknown>;
};

export type Finding = {
  id: number;
  organization_id: number;
  asset_id: number;
  service_id: number | null;
  title: string;
  severity: "INFO" | "LOW" | "MEDIUM" | "HIGH" | "CRITICAL";
  source: string;
  status: "NEW" | "ACKNOWLEDGED" | "IN_PROGRESS" | "RESOLVED" | "ACCEPTED_RISK" | "FALSE_POSITIVE";
  first_seen: string;
  last_seen: string;
};

export type AssetDetail = Asset & {
  observations: AssetObservation[];
  services: Service[];
  service_observations: ServiceObservation[];
  findings: Finding[];
};

export type ScannerJob = {
  id: number;
  organization_id: number;
  scope_id: number;
  assessment_run_id: number | null;
  adapter_name: string;
  target: string;
  status: "PREPARED" | "RUNNING" | "COMPLETED" | "FAILED" | "CANCELLED";
  error_message: string | null;
  prepared_config: Record<string, unknown>;
  raw_output: string | null;
  normalized_result: Record<string, unknown> | null;
  requested_at: string;
};

export type ScanProfile = {
  name: string;
  display_name: string;
  description: string;
  scan_zone: "EXTERNAL" | "INTERNAL_IT";
  adapter_sequence: string[];
};

export type AssessmentRun = {
  id: number;
  organization_id: number;
  scope_id: number;
  profile_name: string;
  target: string;
  status: "QUEUED" | "RUNNING" | "COMPLETED" | "FAILED" | "CANCELLED" | "ARCHIVED";
  summary: {
    assets?: number;
    services?: number;
    findings?: number;
    job_ids?: number[];
    failed_job_ids?: number[];
    adapters?: string[];
  };
  error_message: string | null;
  requested_at: string;
  started_at: string | null;
  completed_at: string | null;
};

export type AssessmentRunDetail = AssessmentRun & {
  jobs: ScannerJob[];
};

export type AssessmentFollowup = {
  assessment_run_id: number;
  adapter_name: string;
  candidate_targets: string[];
  prepared_job_ids: number[];
  prepared_targets: string[];
  skipped_targets: string[];
};

export type ChangeSet = {
  id: number;
  organization_id: number;
  baseline_at: string;
  comparison_at: string;
  summary: {
    total?: number;
    by_entity_type?: Record<string, number>;
    by_change_type?: Record<string, number>;
  };
  created_at: string;
  events?: ChangeEvent[];
};

export type ChangeEvent = {
  id: number;
  change_set_id: number;
  entity_type: "ASSET" | "SERVICE" | "FINDING";
  change_type: "ADDED" | "REMOVED";
  entity_key: string;
  object_id: number | null;
};

export type ScannerAdapter = {
  name: string;
  display_name: string;
  supported_target_notes: string;
  execution_available: boolean;
};

async function request<T>(path: string, options?: RequestInit): Promise<T> {
  const response = await fetch(`${API_BASE_URL}${path}`, {
    ...options,
    headers: {
      "Content-Type": "application/json",
      ...options?.headers,
    },
  });

  if (!response.ok) {
    const body = await response.json().catch(() => ({}));
    const detail =
      typeof body.detail === "string"
        ? body.detail
        : body.detail
          ? JSON.stringify(body.detail)
          : `Request failed with HTTP ${response.status}`;
    throw new Error(detail);
  }

  if (response.status === 204) {
    return undefined as T;
  }
  return response.json() as Promise<T>;
}

export const api = {
  riskHistory: (assetId: number, organizationId: number, offset = 0) =>
    request<RiskHistory>(`/assets/${assetId}/risk?organization_id=${organizationId}&offset=${offset}`),
  calculateRisk: (assetId: number, payload: Record<string, unknown>) =>
    request<RiskSnapshot>(`/assets/${assetId}/risk`, post(payload)),
  intelligence: (assetId: number, organizationId: number, offset = 0) =>
    request<IntelligenceData>(`/assets/${assetId}/intelligence?organization_id=${organizationId}&offset=${offset}`),
  enrich: (assetId: number, organizationId: number, evidenceKey: string) =>
    request<IntelligenceRun>(`/assets/${assetId}/intelligence`, post({ organization_id: organizationId, evidence_key: evidenceKey })),
  health: async () => {
    const response = await fetch(`${API_BASE_URL.replace("/api/v1", "")}/health`);
    if (!response.ok) {
      throw new Error("Backend health check failed");
    }
    return response.json() as Promise<{ status: string }>;
  },
  organizations: () => request<Organization[]>("/organizations"),
  createOrganization: (name: string) => request<Organization>("/organizations", post({ name })),
  scopes: (organizationId: number) => request<Scope[]>(`/scopes?organization_id=${organizationId}`),
  createScope: (payload: Record<string, unknown>) => request<Scope>("/scopes", post(payload)),
  archiveScope: (scopeId: number) => request<void>(`/scopes/${scopeId}`, del()),
  assets: (organizationId: number) => request<Asset[]>(`/assets?organization_id=${organizationId}`),
  assetDetail: (assetId: number) => request<AssetDetail>(`/assets/${assetId}/detail`),
  createAsset: (payload: Record<string, unknown>) => request<Asset>("/assets", post(payload)),
  services: (assetId: number) => request<Service[]>(`/services?asset_id=${assetId}`),
  findings: (organizationId: number) => request<Finding[]>(`/findings?organization_id=${organizationId}`),
  createFinding: (payload: Record<string, unknown>) => request<Finding>("/findings", post(payload)),
  scannerAdapters: () => request<ScannerAdapter[]>("/scanner-adapters"),
  scanProfiles: () => request<ScanProfile[]>("/scan-profiles"),
  assessments: (organizationId: number, includeArchived = false) =>
    request<AssessmentRun[]>(`/assessments?organization_id=${organizationId}&include_archived=${includeArchived}`),
  assessmentDetail: (assessmentRunId: number) => request<AssessmentRunDetail>(`/assessments/${assessmentRunId}/detail`),
  createAssessment: (payload: Record<string, unknown>) => request<AssessmentRun>("/assessments", post(payload)),
  prepareVulnerabilityChecks: (assessmentRunId: number) =>
    request<AssessmentFollowup>(`/assessments/${assessmentRunId}/prepare-vulnerability-checks`, post({})),
  prepareWebFingerprints: (assessmentRunId: number) =>
    request<AssessmentFollowup>(`/assessments/${assessmentRunId}/prepare-web-fingerprints`, post({})),
  archiveAssessment: (assessmentRunId: number) =>
    request<AssessmentRun>(`/assessments/${assessmentRunId}/archive`, post({})),
  scannerJobs: (organizationId: number) => request<ScannerJob[]>(`/scanner-jobs?organization_id=${organizationId}`),
  scannerJob: (jobId: number) => request<ScannerJob>(`/scanner-jobs/${jobId}`),
  createScannerJob: (payload: Record<string, unknown>) => request<ScannerJob>("/scanner-jobs", post(payload)),
  runScannerJob: async (jobId: number) => {
    const job = await request<ScannerJob>(`/scanner-jobs/${jobId}/run`, post({}));
    if (job.status === "FAILED") {
      throw new Error(job.error_message ?? "Scanner job failed");
    }
    return job;
  },
  changeSets: (organizationId: number) => request<ChangeSet[]>(`/change-sets?organization_id=${organizationId}`),
  createChangeSet: (payload: Record<string, unknown>) => request<ChangeSet>("/change-sets/compare", post(payload)),
};

function post(payload: Record<string, unknown>): RequestInit {
  return {
    method: "POST",
    body: JSON.stringify(payload),
  };
}

function del(): RequestInit {
  return {
    method: "DELETE",
  };
}

export type IntelligenceEvidence = {
  key: string; reference: string; kind: string; confidence: string; reason: string;
  source: string; observed_at: string; service_id?: number; observation_id?: number;
  finding_id?: number; finding_status?: string;
};
export type IntelligenceRun = {
  id: number; asset_id: number; created_at: string; status: string; evidence: IntelligenceEvidence;
  result: {
    notice: string; total: number | null; truncated: boolean;
    sources: { provider: string; status: string; cached: boolean; fetched_at?: string; error?: string }[];
    candidates: {
      cve_id: string; description: string; assessment: string; status: string; modified: string | null;
      confidence: string; match_reason: string;
      cvss: { score: number | null; version: string | null; vector: string | null; source: string | null } | null;
      epss: { score: number | null; percentile: number | null; date: string } | null;
      kev: boolean | null; kev_detail: { date_added: string; required_action: string } | null;
    }[];
  };
};
export type IntelligenceData = {
  enabled: boolean; inputs: IntelligenceEvidence[]; runs: IntelligenceRun[];
  software: { service_id: number; observation_id: number; product: string | null; version: string | null; cpes: string[]; source: string; observed_at: string }[];
};

export type RiskSnapshot = {
  id: number; asset_id: number; created_at: string; algorithm_version: string;
  context: { exposure: string; criticality: string; rationale: string; asset_active: boolean };
  result: {
    status: string; lower: number | null; upper: number | null; notice: string; aggregation: string;
    warnings: string[]; excluded: { finding_id: number; status: string }[];
    entries: { key: string; title: string; kind: string; finding_id: number | null; finding_status: string | null;
      intelligence_run_id: number | null; cve_id: string | null; status: string; band: string;
      lower: number; upper: number; base_lower: number; base_upper: number;
      components: { name: string; raw: unknown; known: boolean; lower: number; upper: number;
        weight: number | null; operation?: string; source: string }[];
    }[];
  };
};
export type RiskHistory = { algorithm_version: string; snapshots: RiskSnapshot[] };
