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


/* ============================================================
   AUTH TYPES
   ============================================================ */

export interface AuthUser {
  id: number;
  email: string;
  role: string;
}

export interface LoginResponse {
  access_token: string;
  token_type: string;
  user: AuthUser;
}


/* ============================================================
   AUTH STORAGE
   ============================================================ */

const TOKEN_KEY = "secnet_access_token";
const USER_KEY = "secnet_user";


export function getAccessToken(): string | null {
  return localStorage.getItem(TOKEN_KEY);
}


export function getStoredUser(): AuthUser | null {
  const value = localStorage.getItem(USER_KEY);

  if (!value) {
    return null;
  }

  try {
    return JSON.parse(value) as AuthUser;
  } catch {
    localStorage.removeItem(USER_KEY);
    return null;
  }
}


export function setAuthSession(
  token: string,
  user: AuthUser,
): void {
  localStorage.setItem(
    TOKEN_KEY,
    token,
  );

  localStorage.setItem(
    USER_KEY,
    JSON.stringify(user),
  );
}


export function clearAuthSession(): void {
  localStorage.removeItem(TOKEN_KEY);
  localStorage.removeItem(USER_KEY);
}


export function isAuthenticated(): boolean {
  return Boolean(
    getAccessToken(),
  );
}


/* ============================================================
   GENERIC REQUEST
   ============================================================ */

async function request<T>(
  path: string,
  init?: RequestInit,
): Promise<T> {

  const token =
    getAccessToken();

  const headers = new Headers(
    init?.headers,
  );

  if (!headers.has("Content-Type")) {
    headers.set(
      "Content-Type",
      "application/json",
    );
  }

  if (token) {
    headers.set(
      "Authorization",
      `Bearer ${token}`,
    );
  }

  const res = await fetch(
    `${BASE}${path}`,
    {
      ...init,
      headers,
    },
  );


  /* ----------------------------------------------------------
     UNAUTHORIZED
     ---------------------------------------------------------- */

  if (res.status === 401) {

    clearAuthSession();

    if (
      window.location.pathname !==
      "/login"
    ) {
      window.location.href =
        "/login";
    }

    throw new Error(
      "Phiên đăng nhập đã hết hạn. Vui lòng đăng nhập lại.",
    );
  }


  /* ----------------------------------------------------------
     OTHER ERRORS
     ---------------------------------------------------------- */

  if (!res.ok) {

    const text =
      await res.text();

    let message =
      text ||
      `${res.status} ${res.statusText}`;

    try {

      const parsed =
        JSON.parse(text);

      if (parsed?.detail) {

        message =
          typeof parsed.detail ===
          "string"
            ? parsed.detail
            : JSON.stringify(
                parsed.detail,
              );
      }

    } catch {
      // Keep original response text.
    }

    throw new Error(
      message,
    );
  }


  /* ----------------------------------------------------------
     EMPTY RESPONSE
     ---------------------------------------------------------- */

  const text =
    await res.text();

  if (!text) {
    return undefined as T;
  }

  return JSON.parse(text) as T;
}


/* ============================================================
   AUTH
   ============================================================ */

export async function login(
  email: string,
  password: string,
): Promise<LoginResponse> {

  const response =
    await request<LoginResponse>(
      "/auth/login",
      {
        method: "POST",
        body: JSON.stringify({
          email,
          password,
        }),
      },
    );

  setAuthSession(
    response.access_token,
    response.user,
  );

  return response;
}


export async function getCurrentUser(): Promise<AuthUser> {

  const user =
    await request<AuthUser>(
      "/auth/me",
    );

  localStorage.setItem(
    USER_KEY,
    JSON.stringify(user),
  );

  return user;
}


export function logout(): void {
  clearAuthSession();

  window.location.href =
    "/login";
}


/* ============================================================
   SCANS
   ============================================================ */

export async function getScans(): Promise<Scan[]> {

  const data =
    await request<
      { value?: Scan[] } | Scan[]
    >("/scans");

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


export async function createScan(
  payload: {
    provider: string;
    region: string;
    scope: string;
    requested_by?: string;
  },
): Promise<Scan> {

  return request<Scan>(
    "/scans",
    {
      method: "POST",
      body: JSON.stringify(
        payload,
      ),
    },
  );
}


/* ============================================================
   FINDINGS
   ============================================================ */

export interface Finding {
  id: number;

  finding_id: string;

  control_id: string;

  title: string;

  description: string;

  severity: string;

  status: string;

  resource_id: string | null;

  resource_type: string | null;

  region: string;

  source: string;

  risk_score: number;

  risk_level: string;

  securityhub_workflow?: string | null;

  securityhub_record_state?: string | null;

  first_seen: string;

  last_seen: string;
}


export interface FindingsResponse {
  value: Finding[];

  Count: number;
}


export interface FindingFilters {
  status?: string;

  severity?: string;

  source?: string;

  control_id?: string;
}


export async function getFindings(
  filters: FindingFilters = {},
): Promise<FindingsResponse> {

  const params =
    new URLSearchParams();

  if (filters.status) {
    params.set(
      "status",
      filters.status,
    );
  }

  if (filters.severity) {
    params.set(
      "severity",
      filters.severity,
    );
  }

  if (filters.source) {
    params.set(
      "source",
      filters.source,
    );
  }

  if (filters.control_id) {
    params.set(
      "control_id",
      filters.control_id,
    );
  }

  const query =
    params.toString();

  return request<FindingsResponse>(
    `/findings${
      query
        ? `?${query}`
        : ""
    }`,
  );
}


/* ============================================================
   REMEDIATION CANDIDATES
   ============================================================ */

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


/* ============================================================
   REMEDIATION PLAN
   ============================================================ */

export async function createRemediationPlan(
  requestedBy?: string,
): Promise<RemediationRun> {

  const params =
    new URLSearchParams();

  if (requestedBy) {
    params.set(
      "requested_by",
      requestedBy,
    );
  }

  const query =
    params.toString();

  return request<RemediationRun>(
    `/remediation/plan${
      query
        ? `?${query}`
        : ""
    }`,
    {
      method: "POST",
    },
  );
}


/* ============================================================
   REMEDIATION RUNS
   ============================================================ */

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


/* ============================================================
   REMEDIATION APPROVAL
   ============================================================ */

export async function approveRemediation(
  runId: number,
  approvedBy?: string,
): Promise<RemediationRun> {

  return request<RemediationRun>(
    `/remediation/runs/${runId}/approve`,
    {
      method: "POST",

      body: JSON.stringify({
        approved_by:
          approvedBy || "",
      }),
    },
  );
}


/* ============================================================
   REMEDIATION EXECUTION
   ============================================================ */

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


/* ============================================================
   REMEDIATION AUDIT LOG
   ============================================================ */

export interface RemediationAuditLog {
  id: number;

  run_id: number;

  action: string;

  actor: string | null;

  status: string;

  message: string | null;

  metadata:
    Record<string, unknown> | null;

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