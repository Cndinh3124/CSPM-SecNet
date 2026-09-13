export type Status =
  | "PASSED"
  | "FAILED"
  | "UNKNOWN"
  | string;


// ============================================================
// SCAN
// ============================================================

export interface Scan {
  id: number;

  status: string;

  provider: string;

  region: string;

  scope: string;

  requested_by?: string | null;

  total_controls: number;

  passed_controls: number;

  failed_controls: number;

  compliance_percent: number;

  created_at: string;

  started_at?: string | null;

  finished_at?: string | null;

  error_message?: string | null;
}


// ============================================================
// CONTROL
// ============================================================

export interface Control {
  control_id: string;

  status: Status;

  passed: unknown[];

  failed: unknown[];

  unknown: unknown[];

  passed_count: number;

  failed_count: number;

  unknown_count: number;

  compliance_percent: number;
}


// ============================================================
// FINDING
// ============================================================

export interface Finding {
  id?: number;

  finding_id?: string;

  control_id: string;

  title?: string;

  description?: string;

  severity?: string;

  status?: string;

  resource_id?: string;

  resource_type?: string;

  region?: string;

  source?: string;

  risk_score?: number;

  risk_level?: string;

  first_seen?: string;

  last_seen?: string;
}


// ============================================================
// RESOURCE
// ============================================================

export interface Resource {
  id?: number;

  resource_id: string;

  resource_type: string;

  service: string;

  region: string;

  status: string;

  risk_score: number;

  first_seen?: string;

  last_seen?: string;
}


// ============================================================
// SCAN DETAIL
// ============================================================

export interface ScanDetail {
  scan: Scan;

  controls: Control[];

  findings: Finding[];

  resources?: Resource[];

  resource_summary: {
    active: number;

    passed: number;

    failed: number;

    stale: number;

    unknown: number;
  };

  summary?: Record<string, unknown>;
}


// ============================================================
// REMEDIATION CANDIDATE
// ============================================================

export interface RemediationCandidate {
  control_id: string;

  resource_id?: string | null;

  resource_type?: string | null;

  remediation_type?: string | null;

  severity: string;

  description: string;

  action: string;

  scope: Record<string, unknown>;

  reason: string;
}


// ============================================================
// REMEDIATION RUN
// ============================================================

export interface RemediationRun {
  id: number;

  status: string;

  requested_by?: string | null;

  approved_by?: string | null;

  approved_at?: string | null;

  total_candidates: number;

  allowed_candidates: number;

  skipped_candidates: number;

  success_count: number;

  failed_count: number;

  created_at: string;

  executed_at?: string | null;
}


// ============================================================
// REMEDIATION EXECUTION
// ============================================================

export interface RemediationExecutionResponse {
  id: number;

  status: string;

  total_candidates: number;

  allowed_candidates: number;

  skipped_candidates: number;

  success_count: number;

  failed_count: number;

  executed_at?: string | null;
}


// ============================================================
// REMEDIATION AUDIT LOG
// ============================================================

export interface RemediationAuditLog {
  id: number;

  run_id: number;

  action: string;

  actor?: string | null;

  status: string;

  message?: string | null;

  metadata?: Record<string, unknown> | null;

  created_at: string;
}


// ============================================================
// REMEDIATION AUDIT LOG RESPONSE
// ============================================================

export interface RemediationAuditLogResponse {
  run_id: number;

  count: number;

  value: RemediationAuditLog[];
}