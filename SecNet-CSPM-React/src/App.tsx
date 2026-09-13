import { useEffect, useMemo, useState } from "react";
import {
  AlertTriangle,
  Bell,
  CheckCircle2,
  ChevronRight,
  CircleGauge,
  Cloud,
  FileCheck2,
  LayoutDashboard,
  Menu,
  Play,
  RefreshCw,
  Search,
  Server,
  Settings,
  ShieldAlert,
  ShieldCheck,
  XCircle,
  Clock3,
} from "lucide-react";

import {
  NavLink,
  Route,
  Routes,
  useNavigate,
  useParams,
} from "react-router-dom";

import {
  createScan,
  getScanDetail,
  getScans,
  getRemediationCandidates,
  createRemediationPlan,
  approveRemediation,
  executeRemediation,
  getRemediationRun,
  getRemediationAudit,
} from "./api";

import type {
  Control,
  Finding,
  Scan,
  ScanDetail,
  RemediationCandidate,
  RemediationRun,
  RemediationAuditLog,
} from "./types";

/* ============================================================
   NAVIGATION
   ============================================================ */

const nav = [
  {
    to: "/",
    label: "Overview",
    icon: LayoutDashboard,
  },
  {
    to: "/findings",
    label: "Findings",
    icon: ShieldAlert,
  },
  {
    to: "/compliance",
    label: "Compliance",
    icon: FileCheck2,
  },
  {
    to: "/resources",
    label: "Resources",
    icon: Server,
  },
  {
    to: "/remediation",
    label: "Remediation",
    icon: ShieldCheck,
  },
  {
    to: "/policies",
    label: "Policies",
    icon: Settings,
  },
  {
    to: "/history",
    label: "Scan History",
    icon: Clock3,
  },
];

/* ============================================================
   APP
   ============================================================ */

function App() {
  const [scans, setScans] = useState<Scan[]>([]);
  const [detail, setDetail] = useState<ScanDetail | null>(null);

  const [loading, setLoading] = useState(true);
  const [refreshing, setRefreshing] = useState(false);

  const [error, setError] = useState("");
  const [sidebarOpen, setSidebarOpen] = useState(false);

  /* ----------------------------------------------------------
     REFRESH DATA
     ---------------------------------------------------------- */

  async function refresh(showSpinner = true) {
    try {
      if (showSpinner) {
        setRefreshing(true);
      }

      setError("");

      const list = await getScans();

      setScans(list);

      const latest = [...list].sort(
        (a, b) => b.id - a.id
      )[0];

      if (latest) {
        const latestDetail = await getScanDetail(
          latest.id
        );

        setDetail(latestDetail);
      }
    } catch (e) {
      setError(
        e instanceof Error
          ? e.message
          : "Không thể kết nối CSPM API."
      );
    } finally {
      setLoading(false);
      setRefreshing(false);
    }
  }

  /* ----------------------------------------------------------
     INITIAL LOAD
     ---------------------------------------------------------- */

  useEffect(() => {
    refresh(false);
  }, []);

  return (
    <div className="app-shell">

      {/* ======================================================
          SIDEBAR
          ====================================================== */}

      <aside
        className={`sidebar ${
          sidebarOpen ? "open" : ""
        }`}
      >
        <div className="brand">

          <div className="brand-mark">
            <ShieldCheck size={22} />
          </div>

          <div>
            <strong>SecNet</strong>
            <span>CSPM Console</span>
          </div>

        </div>

        <div className="nav-label">
          Security
        </div>

        <nav>
          {nav.map(
            ({
              to,
              label,
              icon: Icon,
            }) => (
              <NavLink
                key={to}
                to={to}
                end={to === "/"}
                onClick={() =>
                  setSidebarOpen(false)
                }
                className={({ isActive }) =>
                  `nav-item ${
                    isActive ? "active" : ""
                  }`
                }
              >
                <Icon size={18} />
                <span>{label}</span>
              </NavLink>
            )
          )}
        </nav>

        <div className="sidebar-bottom">

          <div className="env-box">

            <span className="live-dot" />

            <div>
              <b>
                AWS · ap-southeast-1
              </b>

              <small>
                Scope: LAB
              </small>
            </div>

          </div>

          <div className="version">
            SecNet CSPM · Console v1.0
          </div>

        </div>

      </aside>

      {/* ======================================================
          MAIN
          ====================================================== */}

      <main className="main">

        {/* TOPBAR */}

        <header className="topbar">

          <button
            className="icon-button mobile-only"
            onClick={() =>
              setSidebarOpen(
                (value) => !value
              )
            }
            aria-label="Menu"
          >
            <Menu size={20} />
          </button>

          <div className="top-context">

            <Cloud size={16} />

            AWS

            <span>•</span>

            ap-southeast-1

          </div>

          <div className="top-actions">

            <div className="search-box">

              <Search size={16} />

              <input
                placeholder="Search resources, controls..."
              />

            </div>

            <button
              className="icon-button"
              title="Notifications"
            >
              <Bell size={18} />
            </button>

            <button
              className="avatar"
              title="SecNet operator"
            >
              ND
            </button>

          </div>

        </header>

        {/* GLOBAL ERROR */}

        {error && (
          <div className="error-banner">

            <XCircle size={17} />

            <span>{error}</span>

            <button
              onClick={() =>
                refresh()
              }
            >
              Retry
            </button>

          </div>
        )}

        {/* CONTENT */}

        <div className="content">

          <Routes>

            {/* ==================================================
                OVERVIEW
                ================================================== */}

            <Route
              path="/"
              element={
                <Overview
                  detail={detail}
                  loading={loading}
                  refreshing={refreshing}
                  onRefresh={() =>
                    refresh()
                  }
                  onRunScan={async () => {
                    try {
                      setError("");

                      await createScan({
                        provider: "AWS",
                        region:
                          "ap-southeast-1",
                        scope: "LAB",
                        requested_by:
                          "Nguyen Cong Dinh",
                      });

                      await refresh();

                    } catch (e) {
                      setError(
                        e instanceof Error
                          ? e.message
                          : "Run Scan failed"
                      );
                    }
                  }}
                />
              }
            />

            {/* FINDINGS */}

            <Route
              path="/findings"
              element={
                <Findings
                  detail={detail}
                />
              }
            />

            {/* FINDING DETAIL */}

            <Route
              path="/findings/:control/:resourceId"
              element={
                <FindingDetail
                  detail={detail}
                />
              }
            />

            {/* COMPLIANCE */}

            <Route
              path="/compliance"
              element={
                <Compliance
                  detail={detail}
                />
              }
            />

            {/* RESOURCES */}

            <Route
              path="/resources"
              element={
                <Resources
                  detail={detail}
                />
              }
            />

            {/* REMEDIATION */}

            <Route
              path="/remediation"
              element={
                <Remediation
                  detail={detail}
                  onRefresh={() => refresh()}
                />
              }
            />

            {/* POLICIES */}

            <Route
              path="/policies"
              element={
                <Policies />
              }
            />

            {/* HISTORY */}

            <Route
              path="/history"
              element={
                <History
                  scans={scans}
                  onRefresh={() =>
                    refresh()
                  }
                />
              }
            />

            {/* HISTORY DETAIL */}

            <Route
              path="/history/:id"
              element={
                <HistoryDetail
                  scans={scans}
                />
              }
            />

          </Routes>

        </div>

      </main>

    </div>
  );
}

/* ============================================================
   PAGE HEADER
   ============================================================ */

function PageHeader({
  eyebrow,
  title,
  subtitle,
  actions,
}: {
  eyebrow: string;
  title: string;
  subtitle: string;
  actions?: React.ReactNode;
}) {
  return (
    <div className="page-header">

      <div>

        <div className="eyebrow">
          {eyebrow}
        </div>

        <h1>
          {title}
        </h1>

        <p>
          {subtitle}
        </p>

      </div>

      <div className="header-actions">
        {actions}
      </div>

    </div>
  );
}

/* ============================================================
   OVERVIEW
   ============================================================ */

function Overview({
  detail,
  loading,
  refreshing,
  onRefresh,
  onRunScan,
}: {
  detail: ScanDetail | null;
  loading: boolean;
  refreshing: boolean;
  onRefresh: () => void;
  onRunScan: () => void;
}) {
  const navigate = useNavigate();

  if (loading) {
    return <Loading />;
  }

  const scan = detail?.scan;

  const controls =
    detail?.controls || [];

  const findings = [
    ...(detail?.findings || []),
  ].sort(
    (a, b) =>
      (b.risk_score || 0) -
      (a.risk_score || 0)
  );

  const summary =
    detail?.resource_summary || {
      active: 0,
      passed: 0,
      failed: 0,
      unknown: 0,
      stale: 0,
    };

  const score =
    Number(
      scan?.compliance_percent ?? 0
    );

  return (
    <>

      <PageHeader
        eyebrow="SECNET / SECURITY POSTURE"
        title="Security Posture Overview"
        subtitle="Tổng quan rủi ro và mức độ tuân thủ của hạ tầng AWS trong phạm vi giám sát."
        actions={
          <>
            <button
              className="btn secondary"
              onClick={onRefresh}
            >
              <RefreshCw
                size={16}
                className={
                  refreshing
                    ? "spin"
                    : ""
                }
              />

              Refresh
            </button>

            <button
              className="btn primary"
              onClick={onRunScan}
            >
              <Play size={16} />

              Run Scan
            </button>
          </>
        }
      />

      <div className="scan-meta">

        <span className="live-dot" />

        Monitoring active

        <span>
          Last scan:{" "}
          {formatDate(
            scan?.finished_at ||
            scan?.created_at
          )}
        </span>

      </div>

      {/* KPI */}

      <div className="kpi-grid">

        <Kpi
          label="Security Score"
          value={`${score.toFixed(1)}%`}
          meta="CIS control compliance"
          icon={<CircleGauge />}
          tone={
            score >= 80
              ? "good"
              : score >= 60
                ? "warn"
                : "bad"
          }
        />

        <Kpi
          label="Passed Controls"
          value={String(
            scan?.passed_controls ?? 0
          )}
          meta={`of ${
            scan?.total_controls ?? 0
          } controls`}
          icon={<CheckCircle2 />}
          tone="good"
        />

        <Kpi
          label="Failed Controls"
          value={String(
            scan?.failed_controls ?? 0
          )}
          meta="Require attention"
          icon={<AlertTriangle />}
          tone="bad"
        />

        <Kpi
          label="At Risk Resources"
          value={String(
            summary.failed
          )}
          meta="Resources with findings"
          icon={<ShieldAlert />}
          tone="bad"
        />

      </div>

      {/* COMPLIANCE + RISK */}

      <div className="grid-2">

        <section className="panel">

          <PanelTitle
            title="Compliance Overview"
            subtitle="Kết quả kiểm soát theo dịch vụ AWS."
          />

          <ComplianceBars
            controls={controls}
          />

        </section>

        <section className="panel">

          <PanelTitle
            title="Risk Distribution"
            subtitle="Trạng thái tài nguyên trong scan gần nhất."
          />

          <RiskDonut
            summary={summary}
          />

        </section>

      </div>

      {/* TOP FINDINGS */}

      <section className="panel">

        <div className="panel-heading-row">

          <PanelTitle
            title="Top Security Findings"
            subtitle="Các finding có risk score cao nhất."
          />

          <button
            className="text-btn"
            onClick={() =>
              navigate("/findings")
            }
          >
            View all
            <ChevronRight size={15} />
          </button>

        </div>

        {/* =====================================================
            FIXED FINDING TABLE BLOCK
            ===================================================== */}

        <FindingTable
          findings={findings.slice(0, 5)}
          onSelect={(finding) =>
            navigate(
              `/findings/${encodeURIComponent(
                finding.control_id
              )}/${encodeURIComponent(
                finding.resource_id ||
                  String(
                    finding.id ||
                    "unknown"
                  )
              )}`
            )
          }
        />

      </section>

    </>
  );
}

/* ============================================================
   KPI
   ============================================================ */

function Kpi({
  label,
  value,
  meta,
  icon,
  tone,
}: {
  label: string;
  value: string;
  meta: string;
  icon: React.ReactNode;
  tone: string;
}) {
  return (
    <div className="kpi">

      <div
        className={`kpi-icon ${tone}`}
      >
        {icon}
      </div>

      <div className="kpi-label">
        {label}
      </div>

      <div className="kpi-value">
        {value}
      </div>

      <div className="kpi-meta">
        {meta}
      </div>

    </div>
  );
}

/* ============================================================
   PANEL TITLE
   ============================================================ */

function PanelTitle({
  title,
  subtitle,
}: {
  title: string;
  subtitle: string;
}) {
  return (
    <div className="panel-title">

      <h2>
        {title}
      </h2>

      <p>
        {subtitle}
      </p>

    </div>
  );
}

/* ============================================================
   COMPLIANCE BARS
   ============================================================ */

function ComplianceBars({
  controls,
}: {
  controls: Control[];
}) {
  const grouped =
    useMemo(() => {

      const map: Record<
        string,
        {
          p: number;
          f: number;
          u: number;
        }
      > = {};

      for (
        const control of controls
      ) {

        const group =
          control.control_id.startsWith(
            "EC2"
          )
            ? "EC2"
            : control.control_id.startsWith(
                  "S3"
                )
              ? "S3"
              : control.control_id
                    .toLowerCase()
                    .startsWith(
                      "cloudtrail"
                    )
                ? "CloudTrail"
                : "Other";

        map[group] ||= {
          p: 0,
          f: 0,
          u: 0,
        };

        map[group].p +=
          Number(
            control.passed_count || 0
          );

        map[group].f +=
          Number(
            control.failed_count || 0
          );

        map[group].u +=
          Number(
            control.unknown_count || 0
          );
      }

      return Object.entries(map);

    }, [controls]);

  return (
    <div className="bars">

      {grouped.map(
        ([name, value]) => {

          const total = Math.max(
            value.p +
              value.f +
              value.u,
            1
          );

          const passed =
            (value.p / total) *
            100;

          const failed =
            (value.f / total) *
            100;

          const unknown =
            (value.u / total) *
            100;

          return (
            <div
              className="bar-row"
              key={name}
            >

              <div className="bar-label">

                <b>
                  {name}
                </b>

                <span>
                  {Math.round(
                    passed
                  )}
                  % passed
                </span>

              </div>

              <div className="bar-track">

                <i
                  style={{
                    width: `${passed}%`,
                  }}
                />

                <em
                  style={{
                    width: `${failed}%`,
                  }}
                />

                <small
                  style={{
                    width: `${unknown}%`,
                  }}
                />

              </div>

            </div>
          );
        }
      )}

    </div>
  );
}

/* ============================================================
   RISK DONUT
   ============================================================ */

function RiskDonut({
  summary,
}: {
  summary: {
    active: number;
    passed: number;
    failed: number;
    unknown: number;
    stale?: number;
  };
}) {
  const total =
    Math.max(
      Number(summary.active || 0),
      1
    );

  const pass =
    (Number(summary.passed || 0) /
      total) *
    100;

  const risk =
    (Number(summary.failed || 0) /
      total) *
    100;

  return (
    <div className="donut-wrap">

      <div
        className="donut"
        style={{
          background: `conic-gradient(
            #18b889 ${pass}%,
            #e0445b ${pass}% ${
              pass + risk
            }%,
            #657184 ${
              pass + risk
            }% 100%
          )`,
        }}
      >

        <div>

          <strong>
            {summary.active}
          </strong>

          <span>
            Resources
          </span>

        </div>

      </div>

      <div className="legend">

        <div>

          <i className="dot good" />

          <span>
            Passed
          </span>

          <b>
            {summary.passed}
          </b>

        </div>

        <div>

          <i className="dot bad" />

          <span>
            At Risk
          </span>

          <b>
            {summary.failed}
          </b>

        </div>

        <div>

          <i className="dot unknown" />

          <span>
            Unknown
          </span>

          <b>
            {summary.unknown}
          </b>

        </div>

      </div>

    </div>
  );
}

/* ============================================================
   FINDING TABLE
   ============================================================ */

function FindingTable({
  findings,
  onSelect,
}: {
  findings: Finding[];
  onSelect: (
    finding: Finding
  ) => void;
}) {
  if (!findings.length) {

    return (
      <div className="empty">
        No findings in the current scan.
      </div>
    );
  }

  return (
    <div className="table-wrap">

      <table>

        <thead>

          <tr>
            <th>Severity</th>
            <th>Control</th>
            <th>Resource</th>
            <th>Risk</th>
            <th>Status</th>
            <th></th>
          </tr>

        </thead>

        <tbody>

          {findings.map(
            (finding, index) => (

              <tr
                key={
                  `${
                    finding.finding_id ||
                    finding.id ||
                    index
                  }`
                }
                onClick={() =>
                  onSelect(finding)
                }
                className="click-row"
              >

                <td>

                  <Severity
                    value={
                      finding.severity ||
                      finding.risk_level ||
                      "MEDIUM"
                    }
                  />

                </td>

                <td>

                  <b>
                    {finding.control_id}
                  </b>

                  <small>
                    {finding.title ||
                      "Security finding"}
                  </small>

                </td>

                <td className="mono">

                  {finding.resource_id ||
                    "UNKNOWN"}

                </td>

                <td>

                  <b>
                    {finding.risk_score ??
                      "—"}
                  </b>

                </td>

                <td>

                  <Status
                    value={
                      finding.status ||
                      "FAILED"
                    }
                  />

                </td>

                <td>

                  <ChevronRight
                    size={16}
                  />

                </td>

              </tr>

            )
          )}

        </tbody>

      </table>

    </div>
  );
}

/* ============================================================
   SEVERITY
   ============================================================ */

function Severity({
  value,
}: {
  value: string;
}) {
  const normalized =
    value.toUpperCase();

  const className =
    normalized.includes("CRIT") ||
    normalized.includes("HIGH") ||
    normalized.includes("CAO")
      ? "bad"
      : normalized.includes(
            "MED"
          ) ||
          normalized.includes(
            "TRUNG"
          )
        ? "warn"
        : "good";

  return (
    <span
      className={`pill ${className}`}
    >
      {value}
    </span>
  );
}

/* ============================================================
   STATUS
   ============================================================ */

function Status({
  value,
}: {
  value: string;
}) {
  const normalized =
    value.toUpperCase();

  const className =
    normalized === "PASSED"
      ? "good"
      : normalized === "FAILED"
        ? "bad"
        : "unknown";

  return (
    <span
      className={`status ${className}`}
    >
      {value}
    </span>
  );
}

/* ============================================================
   FINDINGS
   ============================================================ */

function Findings({
  detail,
}: {
  detail: ScanDetail | null;
}) {
  const navigate =
    useNavigate();

  const [query, setQuery] =
    useState("");

  const [severity, setSeverity] =
    useState("ALL");

  const rows =
    (detail?.findings || [])
      .filter(
        (finding) => {

          const severityMatch =
            severity === "ALL" ||
            String(
              finding.severity ||
                finding.risk_level
            ).toUpperCase() ===
              severity;

          const searchMatch =
            JSON.stringify(
              finding
            )
              .toLowerCase()
              .includes(
                query.toLowerCase()
              );

          return (
            severityMatch &&
            searchMatch
          );
        }
      )
      .sort(
        (a, b) =>
          (b.risk_score || 0) -
          (a.risk_score || 0)
      );

  return (
    <>

      <PageHeader
        eyebrow="SECNET / INVESTIGATION"
        title="Findings"
        subtitle="Điều tra và ưu tiên các vấn đề bảo mật được phát hiện."
        actions={
          <button
            className="btn secondary"
            onClick={() =>
              location.reload()
            }
          >
            <RefreshCw size={16} />
            Refresh
          </button>
        }
      />

      <div className="toolbar">

        <div className="filter-search">

          <Search size={16} />

          <input
            value={query}
            onChange={(event) =>
              setQuery(
                event.target.value
              )
            }
            placeholder="Search findings, resources, controls..."
          />

        </div>

        <select
          value={severity}
          onChange={(event) =>
            setSeverity(
              event.target.value
            )
          }
        >

          <option value="ALL">
            All severity
          </option>

          <option value="HIGH">
            HIGH
          </option>

          <option value="MEDIUM">
            MEDIUM
          </option>

          <option value="LOW">
            LOW
          </option>

        </select>

        <span className="result-count">
          {rows.length} findings
        </span>

      </div>

      <section className="panel">

        <FindingTable
          findings={rows}
          onSelect={(finding) =>
            navigate(
              `/findings/${encodeURIComponent(
                finding.control_id
              )}/${encodeURIComponent(
                finding.resource_id ||
                  String(
                    finding.id ||
                    "unknown"
                  )
              )}`
            )
          }
        />

      </section>

    </>
  );
}

/* ============================================================
   FINDING DETAIL
   ============================================================ */

function FindingDetail({
  detail,
}: {
  detail: ScanDetail | null;
}) {
  const navigate =
    useNavigate();

  const {
    control,
    resourceId,
  } = useParams();

  const decodedResourceId =
    decodeURIComponent(
      resourceId || ""
    );

  const finding =
    (detail?.findings || []).find(
      (item) =>
        item.control_id ===
          control &&
        (
          item.resource_id ===
            decodedResourceId ||
          String(item.id) ===
            decodedResourceId
        )
    );

  if (!finding) {

    return (
      <>

        <PageHeader
          eyebrow="SECNET / FINDING"
          title="Finding not found"
          subtitle="Finding không tồn tại trong scan hiện tại."
        />

        <button
          className="btn secondary"
          onClick={() =>
            navigate("/findings")
          }
        >
          ← Back to Findings
        </button>

      </>
    );
  }

  return (
    <>

      <PageHeader
        eyebrow="SECNET / FINDING INVESTIGATION"
        title={
          finding.title ||
          finding.control_id
        }
        subtitle={
          finding.description ||
          "Security posture violation detected."
        }
        actions={
          <button
            className="btn secondary"
            onClick={() =>
              navigate("/findings")
            }
          >
            ← Findings
          </button>
        }
      />

      <div className="detail-grid">

        {/* FINDING DETAILS */}

        <section className="panel">

          <PanelTitle
            title="Finding Details"
            subtitle="Thông tin từ CSPM API."
          />

          <DetailRow
            label="Control ID"
            value={
              finding.control_id
            }
          />

          <DetailRow
            label="Resource"
            value={
              finding.resource_id ||
              "UNKNOWN"
            }
            mono
          />

          <DetailRow
            label="Resource Type"
            value={
              finding.resource_type ||
              "Unknown"
            }
          />

          <DetailRow
            label="Region"
            value={
              finding.region ||
              "ap-southeast-1"
            }
          />

          <DetailRow
            label="Status"
            value={
              finding.status ||
              "FAILED"
            }
          />

          <DetailRow
            label="Severity"
            value={
              finding.severity ||
              finding.risk_level ||
              "MEDIUM"
            }
          />

          <DetailRow
            label="Risk Score"
            value={String(
              finding.risk_score ??
                "—"
            )}
          />

          <DetailRow
            label="Source"
            value={
              finding.source ||
              "CSPM Engine / Security Hub"
            }
          />

        </section>

        {/* INVESTIGATION */}

        <section className="panel">

          <PanelTitle
            title="Investigation"
            subtitle="Evidence và hướng xử lý."
          />

          <div className="callout bad">

            <ShieldAlert
              size={18}
            />

            <div>

              <b>
                Action required
              </b>

              <p>
                {finding.description ||
                  "Resource không đáp ứng yêu cầu bảo mật của control."}
              </p>

            </div>

          </div>

          <h3>
            Remediation workflow
          </h3>

          <ol className="workflow">

            <li className="done">
              Finding detected
            </li>

            <li>
              Review remediation plan
            </li>

            <li>
              Approval
            </li>

            <li>
              Execute
            </li>

            <li>
              Re-scan & verify
            </li>

          </ol>

          <button
            className="btn primary"
            onClick={() =>
              navigate(
                "/remediation"
              )
            }
          >
            Open Remediation

            <ChevronRight
              size={16}
            />

          </button>

        </section>

      </div>

    </>
  );
}

/* ============================================================
   DETAIL ROW
   ============================================================ */

function DetailRow({
  label,
  value,
  mono,
}: {
  label: string;
  value: string;
  mono?: boolean;
}) {
  return (
    <div className="detail-row">

      <span>
        {label}
      </span>

      <b
        className={
          mono ? "mono" : ""
        }
      >
        {value}
      </b>

    </div>
  );
}

/* ============================================================
   COMPLIANCE
   ============================================================ */

function Compliance({
  detail,
}: {
  detail: ScanDetail | null;
}) {
  const navigate =
    useNavigate();

  const scan =
    detail?.scan;

  const controls =
    detail?.controls ?? [];

  const compliance =
    Number(
      scan?.compliance_percent ?? 0
    );

  const passedControls =
    Number(
      scan?.passed_controls ?? 0
    );

  const failedControls =
    Number(
      scan?.failed_controls ?? 0
    );

  return (
    <>

      <PageHeader
        eyebrow="SECNET / CIS"
        title="Compliance"
        subtitle="CIS AWS Foundations controls trong scan gần nhất."
      />

      {/* COMPLIANCE KPI */}

      <div className="kpi-grid three">

        <Kpi
          label="Compliance"
          value={`${compliance.toFixed(
            1
          )}%`}
          meta="Overall control compliance"
          icon={<FileCheck2 />}
          tone={
            compliance >= 80
              ? "good"
              : compliance >= 60
                ? "warn"
                : "bad"
          }
        />

        <Kpi
          label="Passed"
          value={String(
            passedControls
          )}
          meta="Controls passed"
          icon={<CheckCircle2 />}
          tone="good"
        />

        <Kpi
          label="Failed"
          value={String(
            failedControls
          )}
          meta="Controls failed"
          icon={<AlertTriangle />}
          tone="bad"
        />

      </div>

      {/* CIS CONTROL TABLE */}

      <section className="panel">

        <div className="table-wrap">

          <table>

            <thead>

              <tr>

                <th>
                  Control
                </th>

                <th>
                  Status
                </th>

                <th>
                  Passed
                </th>

                <th>
                  Failed
                </th>

                <th>
                  Unknown
                </th>

                <th>
                  Compliance
                </th>

                <th />

              </tr>

            </thead>

            <tbody>

              {controls.length > 0 ? (

                controls.map(
                  (control) => {

                    const controlCompliance =
                      Number(
                        control.compliance_percent ??
                          0
                      );

                    const safeCompliance =
                      Math.min(
                        Math.max(
                          controlCompliance,
                          0
                        ),
                        100
                      );

                    return (
                      <tr
                        key={
                          control.control_id
                        }
                        className="click-row"
                        onClick={() =>
                          navigate(
                            `/findings?control=${encodeURIComponent(
                              control.control_id
                            )}`
                          )
                        }
                      >

                        <td>

                          <b>
                            {
                              control.control_id
                            }
                          </b>

                        </td>

                        <td>

                          <Status
                            value={
                              control.status ||
                              "UNKNOWN"
                            }
                          />

                        </td>

                        <td>

                          {Number(
                            control.passed_count ??
                              0
                          )}

                        </td>

                        <td>

                          {Number(
                            control.failed_count ??
                              0
                          )}

                        </td>

                        <td>

                          {Number(
                            control.unknown_count ??
                              0
                          )}

                        </td>

                        <td>

                          <div className="mini-progress">

                            <i
                              style={{
                                width: `${safeCompliance}%`,
                              }}
                            />

                          </div>

                          {safeCompliance.toFixed(
                            0
                          )}
                          %

                        </td>

                        <td>

                          <ChevronRight
                            size={16}
                          />

                        </td>

                      </tr>
                    );
                  }
                )

              ) : (

                <tr>

                  <td
                    colSpan={7}
                    className="empty"
                  >
                    No CIS control data
                    available for the
                    latest scan.
                  </td>

                </tr>

              )}

            </tbody>

          </table>

        </div>

      </section>

    </>
  );
}

/* ============================================================
   RESOURCES
   ============================================================ */

function Resources({
  detail,
}: {
  detail: ScanDetail | null;
}) {
  const [query, setQuery] =
    useState("");

  const resources =
    (detail?.resources || [])
      .filter((resource) =>
        JSON.stringify(
          resource
        )
          .toLowerCase()
          .includes(
            query.toLowerCase()
          )
      );

  return (
    <>

      <PageHeader
        eyebrow="SECNET / INVENTORY"
        title="Resources"
        subtitle="Tài nguyên AWS được CSPM đưa vào phạm vi quan sát."
      />

      <div className="toolbar">

        <div className="filter-search">

          <Search size={16} />

          <input
            value={query}
            onChange={(event) =>
              setQuery(
                event.target.value
              )
            }
            placeholder="Search resources..."
          />

        </div>

        <span className="result-count">
          {resources.length} resources
        </span>

      </div>

      <section className="panel">

        <div className="table-wrap">

          <table>

            <thead>

              <tr>

                <th>
                  Resource
                </th>

                <th>
                  Type
                </th>

                <th>
                  Service
                </th>

                <th>
                  Region
                </th>

                <th>
                  Status
                </th>

                <th>
                  Risk
                </th>

              </tr>

            </thead>

            <tbody>

              {resources.length ? (

                resources.map(
                  (resource) => (

                    <tr
                      key={
                        resource.resource_id
                      }
                    >

                      <td className="mono">

                        {
                          resource.resource_id
                        }

                      </td>

                      <td>
                        {
                          resource.resource_type
                        }
                      </td>

                      <td>
                        {
                          resource.service
                        }
                      </td>

                      <td>
                        {
                          resource.region
                        }
                      </td>

                      <td>

                        <Status
                          value={
                            resource.status
                          }
                        />

                      </td>

                      <td>
                        {
                          resource.risk_score
                        }
                      </td>

                    </tr>

                  )
                )

              ) : (

                <tr>

                  <td
                    colSpan={6}
                    className="empty"
                  >
                    Resource detail chưa
                    được expose trong
                    scan detail hiện tại.
                  </td>

                </tr>

              )}

            </tbody>

          </table>

        </div>

      </section>

    </>
  );
}

/* ============================================================
   REMEDIATION
   ============================================================ */

function Remediation({
  detail,
  onRefresh,
}: {
  detail: ScanDetail | null;
  onRefresh: () => void;
}) {
  const [candidates, setCandidates] = useState<RemediationCandidate[]>([]);
  const [run, setRun] = useState<RemediationRun | null>(null);
  const [auditLogs, setAuditLogs] = useState<RemediationAuditLog[]>([]);
  const [auditLoading, setAuditLoading] = useState(false);
  const [selectedCandidate, setSelectedCandidate] =
    useState<RemediationCandidate | null>(null);

  const [loading, setLoading] = useState(true);
  const [processing, setProcessing] = useState(false);
  const [error, setError] = useState("");
  const [message, setMessage] = useState("");

  async function loadCandidates() {
    try {
      setLoading(true);
      setError("");

      const response = await getRemediationCandidates();
      setCandidates(response.value || []);
    } catch (e) {
      setError(
        e instanceof Error
          ? e.message
          : "Unable to load remediation candidates."
      );
    } finally {
      setLoading(false);
    }
  }

  async function loadAuditLogs(runId: number) {
    try {
      setAuditLoading(true);

      const response = await getRemediationAudit(runId);
      setAuditLogs(response.value || []);
    } catch (e) {
      setAuditLogs([]);
      setError(
        e instanceof Error
          ? e.message
          : "Unable to load remediation audit trail."
      );
    } finally {
      setAuditLoading(false);
    }
  }

  useEffect(() => {
    loadCandidates();
  }, [detail?.scan?.id]);

  useEffect(() => {
    if (!run?.id) {
      setAuditLogs([]);
      return;
    }

    loadAuditLogs(run.id);
  }, [run?.id]);

  async function refreshRunAndAudit(runId: number) {
    const updated = await getRemediationRun(runId);
    setRun(updated);
    await loadAuditLogs(runId);
    return updated;
  }

  async function handleCreatePlan() {
    try {
      setProcessing(true);
      setError("");
      setMessage("");

      const created = await createRemediationPlan("Nguyen Cong Dinh");
      setRun(created);

      // Load immediately so PLAN_CREATED appears in the UI.
      await loadAuditLogs(created.id);

      setMessage(
        `Remediation plan #${created.id} created successfully.`
      );
    } catch (e) {
      setError(
        e instanceof Error
          ? e.message
          : "Unable to create remediation plan."
      );
    } finally {
      setProcessing(false);
    }
  }

  async function handleApprove() {
    if (!run) return;

    try {
      setProcessing(true);
      setError("");
      setMessage("");

      const approved = await approveRemediation(
        run.id,
        "Nguyen Cong Dinh"
      );

      setRun(approved);
      await loadAuditLogs(approved.id);

      setMessage(`Remediation plan #${approved.id} approved.`);
    } catch (e) {
      setError(
        e instanceof Error
          ? e.message
          : "Unable to approve remediation plan."
      );
    } finally {
      setProcessing(false);
    }
  }

  async function handleExecute() {
    if (!run) return;

    try {
      setProcessing(true);
      setError("");
      setMessage("");

      await executeRemediation(run.id);
      const updated = await refreshRunAndAudit(run.id);

      setMessage(
        `Execution completed with status: ${updated.status}.`
      );

      await loadCandidates();
    } catch (e) {
      setError(
        e instanceof Error
          ? e.message
          : "Unable to execute remediation."
      );
    } finally {
      setProcessing(false);
    }
  }

  async function handleVerify() {
    try {
      setProcessing(true);
      setError("");
      setMessage("");

      await loadCandidates();

      if (run?.id) {
        await refreshRunAndAudit(run.id);
      }

      onRefresh();

      setMessage(
        "Verification refresh completed. Review the latest CSPM findings."
      );
    } catch (e) {
      setError(
        e instanceof Error
          ? e.message
          : "Verification failed."
      );
    } finally {
      setProcessing(false);
    }
  }

  async function handleRefreshAudit() {
    if (!run?.id) return;

    try {
      setError("");
      await loadAuditLogs(run.id);
    } catch (e) {
      setError(
        e instanceof Error
          ? e.message
          : "Unable to refresh audit trail."
      );
    }
  }

  const allowedCount = candidates.filter(
    (item) => item.action === "ALLOW"
  ).length;

  const skippedCount = candidates.filter(
    (item) => item.action === "SKIP"
  ).length;

  const workflowStep =
    !run
      ? 1
      : run.status === "PLANNED"
        ? 2
        : run.status === "APPROVED"
          ? 3
          : 4;

  return (
    <>
      <PageHeader
        eyebrow="SECNET / RESPONSE"
        title="Remediation"
        subtitle="Quy trình an toàn: Plan → Approval → Execute → Verify."
        actions={
          <button
            className="btn secondary"
            onClick={handleVerify}
            disabled={processing}
          >
            <RefreshCw
              size={16}
              className={processing ? "spin" : ""}
            />
            Verify
          </button>
        }
      />

      <div className="workflow-cards">
        {[
          {
            number: "01",
            title: "Plan",
            text: "Build remediation candidates from current findings.",
          },
          {
            number: "02",
            title: "Approval",
            text: "Review scope before any AWS mutation.",
          },
          {
            number: "03",
            title: "Execute",
            text: "Run only approved remediation actions.",
          },
          {
            number: "04",
            title: "Verify",
            text: "Re-scan and confirm the control state.",
          },
        ].map((step, index) => (
          <div
            className={`workflow-card ${
              workflowStep === index + 1 ? "active" : ""
            }`}
            key={step.number}
          >
            <b>{step.number}</b>
            <h3>{step.title}</h3>
            <p>{step.text}</p>
          </div>
        ))}
      </div>

      {error && (
        <div className="callout bad">
          <XCircle size={18} />
          <div>
            <b>Remediation error</b>
            <p>{error}</p>
          </div>
        </div>
      )}

      {message && (
        <div className="callout good">
          <CheckCircle2 size={18} />
          <div>
            <b>Remediation workflow</b>
            <p>{message}</p>
          </div>
        </div>
      )}

      {run && (
        <section className="panel">
          <PanelTitle
            title={`Remediation Run #${run.id}`}
            subtitle="Current remediation workflow state."
          />

          <div className="detail-grid">
            <div>
              <DetailRow label="Status" value={run.status} />
              <DetailRow
                label="Requested by"
                value={run.requested_by || "N/A"}
              />
              <DetailRow
                label="Approved by"
                value={run.approved_by || "N/A"}
              />
            </div>

            <div>
              <DetailRow
                label="Total candidates"
                value={String(run.total_candidates)}
              />
              <DetailRow
                label="Allowed"
                value={String(run.allowed_candidates)}
              />
              <DetailRow
                label="Skipped"
                value={String(run.skipped_candidates)}
              />
            </div>
          </div>

          {run.status === "PLANNED" && (
            <div className="header-actions">
              <button
                className="btn primary"
                onClick={handleApprove}
                disabled={processing}
              >
                <ShieldCheck size={16} />
                Approve Plan
              </button>
            </div>
          )}

          {run.status === "APPROVED" && (
            <div className="header-actions">
              <button
                className="btn primary"
                onClick={handleExecute}
                disabled={processing}
              >
                <Play size={16} />
                Execute
              </button>
            </div>
          )}

          {(run.status === "NO_ACTION" ||
            run.status === "BLOCKED_FOR_EXECUTOR") && (
            <div className="callout">
              <ShieldCheck size={18} />
              <div>
                <b>Execution safety gate</b>
                <p>
                  {run.status === "NO_ACTION"
                    ? "Không có candidate nào được phép thực thi trong scope hiện tại."
                    : "Candidate đã được duyệt nhưng executor hiện tại đang ở chế độ Safe No-Op."}
                </p>
              </div>
            </div>
          )}
        </section>
      )}

      {/* =====================================================
          AUDIT TRAIL
          ===================================================== */}

      {run && (
        <section className="panel">
          <div className="panel-heading-row">
            <PanelTitle
              title="Audit Trail"
              subtitle="Lịch sử bất biến của remediation workflow: Plan → Approval → Execute."
            />

            <button
              className="btn secondary"
              onClick={handleRefreshAudit}
              disabled={auditLoading}
            >
              <RefreshCw
                size={16}
                className={auditLoading ? "spin" : ""}
              />
              Refresh Audit
            </button>
          </div>

          {auditLoading ? (
            <div className="loading">
              <RefreshCw className="spin" size={20} />
              <span>Loading audit trail...</span>
            </div>
          ) : auditLogs.length === 0 ? (
            <div className="empty">
              Chưa có audit event cho remediation run này.
            </div>
          ) : (
            <div
              className="audit-trail"
              style={{
                display: "grid",
                gap: "12px",
              }}
            >
              {auditLogs.map((audit) => {
                const status = audit.status.toUpperCase();

                const statusClass =
                  status === "SUCCESS" || status === "NO_ACTION"
                    ? "good"
                    : status === "STARTED"
                      ? "warn"
                      : "bad";

                return (
                  <div
                    key={audit.id}
                    className="audit-event"
                    style={{
                      display: "grid",
                      gridTemplateColumns: "10px minmax(0, 1fr)",
                      gap: "14px",
                      padding: "14px 16px",
                      border: "1px solid rgba(255,255,255,0.08)",
                      borderRadius: "10px",
                      background: "rgba(255,255,255,0.02)",
                    }}
                  >
                    <div
                      className={`audit-marker ${statusClass}`}
                      style={{
                        width: "8px",
                        height: "8px",
                        borderRadius: "50%",
                        marginTop: "6px",
                        background:
                          statusClass === "good"
                            ? "#18b889"
                            : statusClass === "warn"
                              ? "#d6a62e"
                              : "#e0445b",
                      }}
                    />

                    <div className="audit-content">
                      <div
                        className="audit-event-header"
                        style={{
                          display: "flex",
                          justifyContent: "space-between",
                          gap: "16px",
                          alignItems: "center",
                          flexWrap: "wrap",
                        }}
                      >
                        <div
                          style={{
                            display: "flex",
                            gap: "10px",
                            alignItems: "center",
                            flexWrap: "wrap",
                          }}
                        >
                          <strong>{audit.action}</strong>

                          <span
                            className={`status ${statusClass}`}
                          >
                            {audit.status}
                          </span>
                        </div>

                        <span
                          className="audit-time"
                          style={{
                            fontSize: "12px",
                            opacity: 0.7,
                          }}
                        >
                          {formatDate(audit.created_at)}
                        </span>
                      </div>

                      <div
                        className="audit-meta"
                        style={{
                          display: "flex",
                          gap: "18px",
                          flexWrap: "wrap",
                          marginTop: "8px",
                          fontSize: "12px",
                          opacity: 0.75,
                        }}
                      >
                        <span>
                          Actor:{" "}
                          <b>{audit.actor || "SYSTEM"}</b>
                        </span>

                        <span>
                          Run: <b>#{audit.run_id}</b>
                        </span>
                      </div>

                      {audit.message && (
                        <p
                          style={{
                            margin: "9px 0 0",
                            lineHeight: 1.5,
                          }}
                        >
                          {audit.message}
                        </p>
                      )}

                      {audit.metadata &&
                        Object.keys(audit.metadata).length > 0 && (
                          <details
                            style={{
                              marginTop: "10px",
                            }}
                          >
                            <summary
                              style={{
                                cursor: "pointer",
                                fontSize: "12px",
                                opacity: 0.8,
                              }}
                            >
                              Metadata
                            </summary>

                            <pre
                              style={{
                                marginTop: "8px",
                                padding: "10px",
                                overflowX: "auto",
                                borderRadius: "8px",
                                background: "rgba(0,0,0,0.22)",
                                fontSize: "11px",
                                lineHeight: 1.5,
                              }}
                            >
                              {JSON.stringify(
                                audit.metadata,
                                null,
                                2
                              )}
                            </pre>
                          </details>
                        )}
                    </div>
                  </div>
                );
              })}
            </div>
          )}
        </section>
      )}

      <section className="panel">
        <div className="panel-heading-row">
          <PanelTitle
            title="Current remediation candidates"
            subtitle="Các finding được kiểm tra qua Scope Validator trước khi cho phép remediation."
          />

          <button
            className="btn primary"
            onClick={handleCreatePlan}
            disabled={
              processing ||
              loading ||
              candidates.length === 0
            }
          >
            <Play size={16} />
            Create Plan
          </button>
        </div>

        <div className="kpi-grid three">
          <Kpi
            label="Candidates"
            value={String(candidates.length)}
            meta="Current failed findings"
            icon={<AlertTriangle />}
            tone={candidates.length ? "warn" : "good"}
          />

          <Kpi
            label="Allowed"
            value={String(allowedCount)}
            meta="Within approved scope"
            icon={<CheckCircle2 />}
            tone={allowedCount ? "good" : "warn"}
          />

          <Kpi
            label="Skipped"
            value={String(skippedCount)}
            meta="Blocked by scope policy"
            icon={<ShieldAlert />}
            tone={skippedCount ? "bad" : "good"}
          />
        </div>

        {loading ? (
          <Loading />
        ) : (
          <div className="candidate-list">
            {candidates.slice(0, 20).map((candidate, index) => (
              <div
                className="candidate"
                key={`${candidate.control_id}-${candidate.resource_id}-${index}`}
              >
                <Severity
                  value={candidate.severity || "MEDIUM"}
                />

                <div>
                  <b>{candidate.control_id}</b>
                  <small>
                    {candidate.resource_id || "UNKNOWN"}
                  </small>
                </div>

                <span className="candidate-risk">
                  {candidate.action === "ALLOW"
                    ? "ALLOW"
                    : "SKIP"}
                </span>

                <button
                  className="btn secondary"
                  onClick={() =>
                    setSelectedCandidate(candidate)
                  }
                >
                  Review
                </button>
              </div>
            ))}

            {!candidates.length && (
              <div className="empty">
                No remediation candidates.
              </div>
            )}
          </div>
        )}
      </section>

      {selectedCandidate && (
        <section className="panel">
          <div className="panel-heading-row">
            <PanelTitle
              title="Candidate Review"
              subtitle="Scope validation and remediation policy evaluation."
            />

            <button
              className="btn secondary"
              onClick={() => setSelectedCandidate(null)}
            >
              Close
            </button>
          </div>

          <DetailRow
            label="Control"
            value={selectedCandidate.control_id}
          />

          <DetailRow
            label="Resource"
            value={selectedCandidate.resource_id || "UNKNOWN"}
            mono
          />

          <DetailRow
            label="Resource Type"
            value={selectedCandidate.resource_type || "UNKNOWN"}
          />

          <DetailRow
            label="Remediation Type"
            value={selectedCandidate.remediation_type || "N/A"}
          />

          <DetailRow
            label="Severity"
            value={selectedCandidate.severity || "UNKNOWN"}
          />

          <DetailRow
            label="Action"
            value={selectedCandidate.action}
          />

          <DetailRow
            label="Scope Result"
            value={
              selectedCandidate.reason ||
              "No scope validation message."
            }
          />

          <div className="callout">
            <ShieldCheck size={18} />
            <div>
              <b>Safety policy</b>
              <p>
                Chỉ candidate được Scope Validator xác nhận
                mới có thể chuyển sang ALLOW. Candidate SKIP
                không được executor thực thi.
              </p>
            </div>
          </div>
        </section>
      )}
    </>
  );
}

/* ============================================================
   POLICIES
   ============================================================ */

function Policies() {
  const policies = [

    [
      "EC2.2",
      "Ensure the use of IMDSv2",
      "DONE",
    ],

    [
      "EC2.6",
      "Ensure VPC flow logging is enabled",
      "DONE",
    ],

    [
      "EC2.53",
      "Ensure no security groups allow unrestricted SSH",
      "DONE",
    ],

    [
      "S3.1",
      "Block public access to S3 buckets",
      "DONE",
    ],

    [
      "S3.5",
      "Require SSL for S3 bucket transport",
      "DONE",
    ],

    [
      "S3.22",
      "Ensure S3 MFA delete is enabled",
      "DONE",
    ],

    [
      "S3.23",
      "Ensure S3 bucket versioning is enabled",
      "DONE",
    ],

    [
      "CloudTrail.2",
      "Ensure CloudTrail log file validation is enabled",
      "DONE",
    ],

  ];

  return (
    <>

      <PageHeader
        eyebrow="SECNET / GOVERNANCE"
        title="Policies"
        subtitle="CSPM Policy Registry — control scope và remediation safety."
      />

      <section className="panel">

        <div className="policy-safety">

          <ShieldCheck size={18} />

          <div>

            <b>
              Safe remediation policy
            </b>

            <p>
              Default action: SKIP ·
              Explicit scope required ·
              Production resources not allowed.
            </p>

          </div>

        </div>

        <div className="table-wrap">

          <table>

            <thead>

              <tr>

                <th>
                  Control
                </th>

                <th>
                  Policy
                </th>

                <th>
                  Status
                </th>

              </tr>

            </thead>

            <tbody>

              {policies.map(
                (policy) => (

                  <tr
                    key={policy[0]}
                  >

                    <td>
                      <b>
                        {policy[0]}
                      </b>
                    </td>

                    <td>
                      {policy[1]}
                    </td>

                    <td>

                      <Status
                        value={
                          policy[2]
                        }
                      />

                    </td>

                  </tr>

                )
              )}

            </tbody>

          </table>

        </div>

      </section>

    </>
  );
}

/* ============================================================
   SCAN HISTORY
   ============================================================ */

function History({
  scans,
  onRefresh,
}: {
  scans: Scan[];
  onRefresh: () => void;
}) {
  const navigate =
    useNavigate();

  return (
    <>

      <PageHeader
        eyebrow="SECNET / OPERATIONS"
        title="Scan History"
        subtitle="Lịch sử các lần CSPM scan được lưu trong PostgreSQL."
        actions={
          <button
            className="btn secondary"
            onClick={onRefresh}
          >
            <RefreshCw size={16} />
            Refresh
          </button>
        }
      />

      <section className="panel">

        <div className="table-wrap">

          <table>

            <thead>

              <tr>

                <th>
                  Scan
                </th>

                <th>
                  Status
                </th>

                <th>
                  Scope
                </th>

                <th>
                  Region
                </th>

                <th>
                  Controls
                </th>

                <th>
                  Compliance
                </th>

                <th>
                  Created
                </th>

                <th />

              </tr>

            </thead>

            <tbody>

              {[
                ...scans,
              ]
                .sort(
                  (a, b) =>
                    b.id - a.id
                )
                .map(
                  (scan) => (

                    <tr
                      key={scan.id}
                      className="click-row"
                      onClick={() =>
                        navigate(
                          `/history/${scan.id}`
                        )
                      }
                    >

                      <td>

                        <b>
                          #{scan.id}
                        </b>

                      </td>

                      <td>

                        <Status
                          value={
                            scan.status
                          }
                        />

                      </td>

                      <td>
                        {scan.scope}
                      </td>

                      <td>
                        {scan.region}
                      </td>

                      <td>

                        {
                          scan.passed_controls
                        }

                        /

                        {
                          scan.total_controls
                        }

                      </td>

                      <td>

                        {Number(
                          scan.compliance_percent ||
                            0
                        ).toFixed(1)}
                        %

                      </td>

                      <td>

                        {formatDate(
                          scan.created_at
                        )}

                      </td>

                      <td>

                        <ChevronRight
                          size={16}
                        />

                      </td>

                    </tr>

                  )
                )}

            </tbody>

          </table>

        </div>

      </section>

    </>
  );
}

/* ============================================================
   HISTORY DETAIL
   ============================================================ */

function HistoryDetail({
  scans,
}: {
  scans: Scan[];
}) {
  const navigate =
    useNavigate();

  const { id } =
    useParams();

  const scan =
    scans.find(
      (item) =>
        String(item.id) ===
        String(id)
    );

  const [
    detail,
    setDetail,
  ] =
    useState<ScanDetail | null>(
      null
    );

  const [
    error,
    setError,
  ] =
    useState("");

  useEffect(() => {

    if (!scan) {
      return;
    }

    getScanDetail(
      scan.id
    )
      .then(
        setDetail
      )
      .catch(
        (e) =>
          setError(
            e instanceof Error
              ? e.message
              : "Không tải được scan detail."
          )
      );

  }, [scan]);

  if (!scan) {

    return (
      <>

        <PageHeader
          eyebrow="SECNET / SCAN"
          title="Scan not found"
          subtitle="Không tìm thấy scan trong lịch sử hiện tại."
        />

        <button
          className="btn secondary"
          onClick={() =>
            navigate(
              "/history"
            )
          }
        >
          ← Scan History
        </button>

      </>
    );
  }

  return (
    <>

      <PageHeader
        eyebrow={`SECNET / SCAN #${scan.id}`}
        title={`Scan #${scan.id}`}
        subtitle="Chi tiết một lần quét CSPM đã được lưu trong hệ thống."
        actions={
          <button
            className="btn secondary"
            onClick={() =>
              navigate(
                "/history"
              )
            }
          >
            ← Scan History
          </button>
        }
      />

      {error && (

        <div className="callout bad">

          <XCircle size={18} />

          <div>

            <b>
              Unable to load detail
            </b>

            <p>
              {error}
            </p>

          </div>

        </div>

      )}

      {/* KPI */}

      <div className="kpi-grid">

        <Kpi
          label="Status"
          value={scan.status}
          meta={scan.scope}
          icon={<Clock3 />}
          tone={
            scan.status ===
            "COMPLETED"
              ? "good"
              : "warn"
          }
        />

        <Kpi
          label="Compliance"
          value={`${Number(
            scan.compliance_percent ||
              0
          ).toFixed(1)}%`}
          meta="Control compliance"
          icon={<CircleGauge />}
          tone="warn"
        />

        <Kpi
          label="Passed Controls"
          value={String(
            scan.passed_controls
          )}
          meta={`of ${
            scan.total_controls
          }`}
          icon={<CheckCircle2 />}
          tone="good"
        />

        <Kpi
          label="Failed Controls"
          value={String(
            scan.failed_controls
          )}
          meta="Require attention"
          icon={<AlertTriangle />}
          tone="bad"
        />

      </div>

      {/* METADATA */}

      <section className="panel">

        <PanelTitle
          title="Scan metadata"
          subtitle="Thông tin execution của scan."
        />

        <DetailRow
          label="Scan ID"
          value={`#${scan.id}`}
        />

        <DetailRow
          label="Provider"
          value={scan.provider}
        />

        <DetailRow
          label="Region"
          value={scan.region}
        />

        <DetailRow
          label="Scope"
          value={scan.scope}
        />

        <DetailRow
          label="Requested by"
          value={
            scan.requested_by ||
            "N/A"
          }
        />

        <DetailRow
          label="Created"
          value={formatDate(
            scan.created_at
          )}
        />

        <DetailRow
          label="Started"
          value={formatDate(
            scan.started_at
          )}
        />

        <DetailRow
          label="Finished"
          value={formatDate(
            scan.finished_at
          )}
        />

      </section>

      {/* CONTROL RESULTS */}

      {detail && (

        <section className="panel">

          <PanelTitle
            title="Control results"
            subtitle="Kết quả thực tế của scan này."
          />

          <div className="table-wrap">

            <table>

              <thead>

                <tr>

                  <th>
                    Control
                  </th>

                  <th>
                    Status
                  </th>

                  <th>
                    Passed
                  </th>

                  <th>
                    Failed
                  </th>

                  <th>
                    Unknown
                  </th>

                  <th>
                    Compliance
                  </th>

                </tr>

              </thead>

              <tbody>

                {detail.controls.map(
                  (control) => (

                    <tr
                      key={
                        control.control_id
                      }
                    >

                      <td>

                        <b>
                          {
                            control.control_id
                          }
                        </b>

                      </td>

                      <td>

                        <Status
                          value={
                            control.status
                          }
                        />

                      </td>

                      <td>
                        {
                          control.passed_count
                        }
                      </td>

                      <td>
                        {
                          control.failed_count
                        }
                      </td>

                      <td>
                        {
                          control.unknown_count
                        }
                      </td>

                      <td>

                        {Number(
                          control.compliance_percent ||
                            0
                        ).toFixed(0)}
                        %

                      </td>

                    </tr>

                  )
                )}

              </tbody>

            </table>

          </div>

        </section>

      )}

    </>
  );
}

/* ============================================================
   LOADING
   ============================================================ */

function Loading() {
  return (
    <div className="loading">

      <RefreshCw
        className="spin"
        size={24}
      />

      <span>
        Loading CSPM posture...
      </span>

    </div>
  );
}

/* ============================================================
   DATE FORMAT
   ============================================================ */

function formatDate(
  value?: string | null
) {
  if (!value) {
    return "N/A";
  }

  try {
    return new Date(
      value
    ).toLocaleString(
      "vi-VN",
      {
        dateStyle: "short",
        timeStyle: "short",
      }
    );
  } catch {
    return value;
  }
}

/* ============================================================
   EXPORT
   ============================================================ */

export default App;