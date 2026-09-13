import type {
  Scan,
  ScanDetail,
  RemediationCandidate,
  RemediationRun,
  RemediationExecutionResponse,
} from "./types";

const BASE = (
  import.meta.env.VITE_API_BASE_URL ||
  "http://localhost:8000/api/v1"
).replace(/\/$/, "");

async function request<T>(
  path: string,
  init?: RequestInit,
): Promise<T> {
  const res = await fetch(`${BASE}${path}`, {
    headers: {
      "Content-Type": "application/json",
      ...(init?.headers || {}),
    },
    ...init,
  });

  if (!res.ok) {
    const text = await res.text();
    let message = text || `${res.status} ${res.statusText}`;

    try {
      const parsed = JSON.parse(text);

      if (parsed?.detail) {
        message =
          typeof parsed.detail === "string"
            ? parsed.detail
            : JSON.stringify(parsed.detail);
      }
    } catch {
      // Keep original response text.
    }

    throw new Error(message);
  }

  return res.json();
}


// ============================================================
// SCANS
// ============================================================

export async function getScans(): Promise<Scan[]> {
  const data = await request<{ value?: Scan[] } | Scan[]>("/scans");

  return Array.isArray(data)
    ? data
    : data.value || [];
}


export async function getScanDetail(
  id: number,
): Promise<ScanDetail> {
  return request<ScanDetail>(
    `/scans/${id}/detail`,
  );
}


export async function createScan(payload: {
  provider: string;
  region: string;
  scope: string;
  requested_by: string;
}): Promise<Scan> {
  return request<Scan>("/scans", {
    method: "POST",
    body: JSON.stringify(payload),
  });
}


// ============================================================
// REMEDIATION CANDIDATES
// ============================================================

export interface RemediationCandidatesResponse {
  value: RemediationCandidate[];

  count: number;

  summary: {
    total_candidates: number;
    allowed: number;
    skipped: number;
  };
}


export async function getRemediationCandidates(): Promise<
  RemediationCandidatesResponse
> {
  return request<RemediationCandidatesResponse>(
    "/remediation/candidates",
  );
}


// ============================================================
// REMEDIATION PLAN
// ============================================================

export async function createRemediationPlan(
  requestedBy: string,
): Promise<RemediationRun> {
  const params = new URLSearchParams({
    requested_by: requestedBy,
  });

  return request<RemediationRun>(
    `/remediation/plan?${params.toString()}`,
    {
      method: "POST",
    },
  );
}


// ============================================================
// REMEDIATION RUNS
// ============================================================

export interface RemediationRunsResponse {
  value: RemediationRun[];

  count: number;
}


export async function getRemediationRuns(): Promise<
  RemediationRunsResponse
> {
  return request<RemediationRunsResponse>(
    "/remediation/runs",
  );
}


export async function getRemediationRun(
  runId: number,
): Promise<RemediationRun> {
  return request<RemediationRun>(
    `/remediation/runs/${runId}`,
  );
}


// ============================================================
// REMEDIATION APPROVAL
// ============================================================

export async function approveRemediation(
  runId: number,
  approvedBy: string,
): Promise<RemediationRun> {
  return request<RemediationRun>(
    `/remediation/runs/${runId}/approve`,
    {
      method: "POST",
      body: JSON.stringify({
        approved_by: approvedBy,
      }),
    },
  );
}


// ============================================================
// REMEDIATION EXECUTION
// ============================================================

export async function executeRemediation(
  runId: number,
): Promise<RemediationExecutionResponse> {
  return request<RemediationExecutionResponse>(
    `/remediation/runs/${runId}/execute`,
    {
      method: "POST",
    },
  );
}


// ============================================================
// REMEDIATION AUDIT LOG
// ============================================================

export interface RemediationAuditLog {
  id: number;

  run_id: number;

  action: string;

  actor: string | null;

  status: string;

  message: string | null;

  metadata: Record<string, unknown> | null;

  created_at: string;
}


export interface RemediationAuditLogResponse {
  run_id: number;

  count: number;

  value: RemediationAuditLog[];
}


export async function getRemediationAudit(
  runId: number,
): Promise<RemediationAuditLogResponse> {
  return request<RemediationAuditLogResponse>(
    `/remediation/runs/${runId}/audit`,
  );
}