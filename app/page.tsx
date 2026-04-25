"use client";

import { useState, useRef, CSSProperties, ReactNode, ChangeEvent } from "react";

// ── Types ─────────────────────────────────────────────────────────────────────

interface XdrEvent {
  display_name?: string;
  description?: string;
}

interface AlertData {
  xdr_event?: XdrEvent;
  tenant_name?: string;
  action?: string;
  srcip?: string;
  srcip_host?: string;
  srcip_type?: string;
  dstip_host?: string;
  dstip?: string;
  actual?: number;
  typical?: number;
  run_every?: number;
  alert_type?: string;
  type?: string;
  host_ip?: string;
  "IP/name"?: string;
  ip?: string;
  connections?: number;
  count?: number;
  interval_minutes?: number;
  interval?: number;
  reputation?: string[] | string;
}

type ScannerVerdict = "false-positive" | "true-positive" | "escalate";

interface CaseAnalysis {
  isScannerAnomaly: boolean;
  tenant: string;
  ipDetail: string;
  detectionResult: string;
  actionTaken: string;
  finalStatus: string;
  verdict: ScannerVerdict;
}

interface VTResult {
  malicious:  number;
  suspicious: number;
  harmless:   number;
  undetected: number;
  reputation: number;
  country:    string;
  owner:      string;
  error?:     string;
}

interface BtnProps {
  children: ReactNode;
  onClick: () => void;
  primary?: boolean;
  green?: boolean;
  danger?: boolean;
}

// ── Security Background ───────────────────────────────────────────────────────

function SecurityBackground() {
  return (
    <>
      <style>{`
        @keyframes aurora1 {
          0%, 100% { transform: translate(0%, 0%) scale(1); opacity: 0.5; }
          33%       { transform: translate(3%, -2%) scale(1.05); opacity: 0.7; }
          66%       { transform: translate(-2%, 3%) scale(0.97); opacity: 0.4; }
        }
        @keyframes aurora2 {
          0%, 100% { transform: translate(0%, 0%) scale(1); opacity: 0.4; }
          33%       { transform: translate(-4%, 2%) scale(1.08); opacity: 0.6; }
          66%       { transform: translate(3%, -3%) scale(0.95); opacity: 0.3; }
        }
        @keyframes aurora3 {
          0%, 100% { transform: translate(0%, 0%) scale(1); opacity: 0.3; }
          50%       { transform: translate(2%, 4%) scale(1.1); opacity: 0.5; }
        }
        @keyframes shimmer {
          0%, 100% { opacity: 0.03; }
          50%       { opacity: 0.06; }
        }
      `}</style>

      <div style={{ position: "fixed", inset: 0, zIndex: 0, background: "#050d18" }} />

      <div style={{
        position: "fixed", zIndex: 1,
        top: "-20%", left: "-10%",
        width: "60vw", height: "60vh",
        borderRadius: "50%",
        background: "radial-gradient(ellipse at center, rgba(56,189,248,0.13) 0%, rgba(56,189,248,0.04) 50%, transparent 70%)",
        filter: "blur(40px)",
        animation: "aurora1 18s ease-in-out infinite",
        pointerEvents: "none",
      }} />

      <div style={{
        position: "fixed", zIndex: 1,
        top: "10%", right: "-15%",
        width: "55vw", height: "55vh",
        borderRadius: "50%",
        background: "radial-gradient(ellipse at center, rgba(99,102,241,0.1) 0%, rgba(99,102,241,0.03) 50%, transparent 70%)",
        filter: "blur(50px)",
        animation: "aurora2 22s ease-in-out infinite",
        pointerEvents: "none",
      }} />

      <div style={{
        position: "fixed", zIndex: 1,
        bottom: "-15%", left: "20%",
        width: "50vw", height: "50vh",
        borderRadius: "50%",
        background: "radial-gradient(ellipse at center, rgba(16,185,129,0.08) 0%, rgba(16,185,129,0.02) 50%, transparent 70%)",
        filter: "blur(60px)",
        animation: "aurora3 26s ease-in-out infinite",
        pointerEvents: "none",
      }} />

      <div style={{
        position: "fixed", inset: 0, zIndex: 2,
        backgroundImage: "radial-gradient(circle, rgba(148,163,184,0.07) 1px, transparent 1px)",
        backgroundSize: "24px 24px",
        pointerEvents: "none",
      }} />

      <div style={{
        position: "fixed", inset: 0, zIndex: 2,
        backgroundImage: `
          linear-gradient(rgba(56,189,248,0.04) 1px, transparent 1px),
          linear-gradient(90deg, rgba(56,189,248,0.04) 1px, transparent 1px)
        `,
        backgroundSize: "96px 96px",
        animation: "shimmer 8s ease-in-out infinite",
        pointerEvents: "none",
      }} />

      <div style={{
        position: "fixed", inset: 0, zIndex: 2,
        background: "radial-gradient(ellipse 60% 40% at 50% 0%, rgba(56,189,248,0.06) 0%, transparent 100%)",
        pointerEvents: "none",
      }} />

      <div style={{
        position: "fixed", inset: 0, zIndex: 3,
        background: "radial-gradient(ellipse at center, transparent 30%, rgba(5,13,24,0.88) 100%)",
        pointerEvents: "none",
      }} />
    </>
  );
}

// ── Data helpers ──────────────────────────────────────────────────────────────

const SAMPLE_JSON = `{
  "alert_type": "Scanner Reputation Anomaly",
  "host_ip": "199.45.154.133",
  "connections": 28,
  "typical": 1,
  "interval_minutes": 5.0,
  "reputation": ["scanner", "malicious", "brute_forcer"]
}`;

function buildMessage(d: AlertData): string {
  const displayName = d.xdr_event?.display_name ?? d.alert_type ?? d.type ?? "Unknown Alert";
  const description = d.xdr_event?.description ?? "(No description available)";
  return `We've received an alert regarding an ${displayName}.\n\n${description}`;
}

function buildFollowUp(d: AlertData): string {
  const obj = d as Record<string, unknown>;

  const get = (...keys: string[]): string => {
    for (const k of keys) {
      const v = obj[k];
      if (v !== undefined && v !== null && String(v).trim() !== "" && String(v) !== "N/A") return String(v);
    }
    return "N/A";
  };

  const getNested = (path: string): string => {
    const keys = path.split(".");
    let val: unknown = obj;
    for (const k of keys) {
      if (val && typeof val === "object") val = (val as Record<string, unknown>)[k];
      else return "N/A";
    }
    return val !== undefined && val !== null && String(val).trim() !== "" ? String(val) : "N/A";
  };

  const getGeo = (prefix: string): string => {
    const geo = obj[`${prefix}_geo`] as Record<string, unknown> | undefined;
    return (geo?.countryName as string) ?? "N/A";
  };

  const displayName = d.xdr_event?.display_name ?? d.alert_type ?? d.type ?? "Unknown Alert";
  const description = d.xdr_event?.description ?? "(No description available)";
  const alertKey    = displayName.toLowerCase();

  const rawTs  = obj.timestamp_utc as string;
  const tsDate = rawTs ? new Date(rawTs) : new Date();
  const timestamp = tsDate.toLocaleString("en-US", {
    month: "numeric", day: "numeric", year: "2-digit",
    hour: "numeric", minute: "2-digit", hour12: true,
  });

  const lines = (pairs: (string | null)[]): string =>
    pairs.filter(x => x !== null).join("\n");

  const header = lines([
    displayName, "",
    description, "",
    "Here are the other details regarding this alert.", "",
    timestamp, "",
  ]);

  let body = "";

  if (alertKey.includes("scanner reputation")) {
    body = lines(["Source IP", `${get("srcip", "srcip_host", "host_ip", "IP/name", "ip")} (Malicious)`, "", "Source Country", getGeo("srcip"), "", "Event Source", get("event_source"), "", "action", get("action"), "", "Please verify the source IP if related to your operations, as it was flagged malicious by security vendors. Thank you!"]);
  } else {
    body = "⚠ No template available for this alert type yet. Please create the follow-up details manually.";
  }

  if (!body) return "";
  return `${header}\n${body}`;
}

const SCANNER_KEYWORDS  = ["scanner anomaly", "scanner reputation"];
const REMEDIATE_ACTIONS = ["deny", "denied", "client-rst", "server-rst"];
const FORWARD_ACTIONS   = ["passed", "allowed", "pass", "allow"];

function analyzeScanner(d: AlertData): CaseAnalysis {
  const displayName      = (d.xdr_event?.display_name ?? d.alert_type ?? "").toLowerCase();
  const isScannerAnomaly = SCANNER_KEYWORDS.some(k => displayName.includes(k));
  const tenant           = d.tenant_name ?? "Unknown Tenant";
  const ip               = d.srcip_host ?? d.host_ip ?? d["IP/name"] ?? d.ip ?? "unknown";
  const ipType           = d.srcip_type ? ` (${d.srcip_type})` : "";
  const ipDetail         = `${ip}${ipType}`;
  const rawAction        = (d.action ?? "unknown").toLowerCase().trim();
  const detectionResult  = rawAction;

  let actionTaken: string;
  let finalStatus: string;
  let verdict: ScannerVerdict;

  if (REMEDIATE_ACTIONS.includes(rawAction)) {
    actionTaken = "Remediated";
    finalStatus = "False Positive – Confirmed";
    verdict     = "false-positive";
  } else if (FORWARD_ACTIONS.includes(rawAction)) {
    actionTaken = `Forwarded to ${tenant} for Blocking`;
    finalStatus = "True Positive";
    verdict     = "true-positive";
  } else {
    actionTaken = "Escalated for Manual Review";
    finalStatus = "Pending Review";
    verdict     = "escalate";
  }

  return { isScannerAnomaly, tenant, ipDetail, detectionResult, actionTaken, finalStatus, verdict };
}

// ── Aegis types & logic ───────────────────────────────────────────────────────

type CaseStatus   = "Waiting for Status" | "Resolved" | "Whitelisted" | "Confirmed";
type Verification = "To Be Confirmed" | "True Positive" | "False Positive";
type Remediation  = "Remediated" | "Not Remediated";
type RemarkKey    = "clean-not-found" | "already-blocked" | "no-remarks-confirmed" | "malicious-not-found" | "in-list-not-blocked";

function buildAegisPreset(vt: VTResult | null, verdict?: ScannerVerdict): { caseStatus: CaseStatus; verification: Verification; remediation: Remediation; remarkKey: RemarkKey } {
  const isMalicious = vt && !vt.error && vt.malicious > 0;
  if (verdict === "false-positive") {
    if (isMalicious) return { caseStatus: "Waiting for Status", verification: "True Positive", remediation: "Not Remediated", remarkKey: "malicious-not-found" };
    return { caseStatus: "Resolved", verification: "False Positive", remediation: "Remediated", remarkKey: "already-blocked" };
  }
  if (verdict === "true-positive") return { caseStatus: "Waiting for Status", verification: "True Positive", remediation: "Not Remediated", remarkKey: "malicious-not-found" };
  if (isMalicious) return { caseStatus: "Waiting for Status", verification: "True Positive", remediation: "Not Remediated", remarkKey: "malicious-not-found" };
  return { caseStatus: "Waiting for Status", verification: "To Be Confirmed", remediation: "Not Remediated", remarkKey: "clean-not-found" };
}

const REMARK_TENANT_PROJECTS: Record<string, string> = {
  "belmont": "Project Selene", "cantilan bank": "Project Atlas",
  "eton properties": "Project Titan", "mwell": "Project Chiron",
  "siycha group of companies": "Project Orion",
};

function buildRemark(key: RemarkKey, vt: VTResult | null, tenant: string, reportSent: boolean): string {
  const tenantLower = tenant.toLowerCase();
  const projectCode = Object.entries(REMARK_TENANT_PROJECTS).find(([k]) => tenantLower.includes(k))?.[1];
  const project = projectCode ?? (tenant !== "Unknown Tenant" ? `Project ${tenant}` : "Project");
  const vendors = vt?.malicious ?? 0;
  switch (key) {
    case "clean-not-found": return reportSent ? `The source IP was not found in the blocked list and was not detected as malicious. Sent a confirmation to ${project}.` : "The source IP was not found in the blocked list and was not detected as malicious.";
    case "already-blocked": return "The source IP is already blocked.";
    case "no-remarks-confirmed": return reportSent ? `Sent to ${project} for Confirmation.` : "No Remarks.";
    case "malicious-not-found": return `The source IP was not found in the blocked list but was detected as malicious by ${vendors} security vendor${vendors !== 1 ? "s" : ""}. Request for blocking sent to ${project}.`;
    case "in-list-not-blocked": return `The source IP exists in the list but is not blocked. Request for blocking sent to ${project}.`;
  }
}

// ── Pill ──────────────────────────────────────────────────────────────────────

type PillVariant = "red" | "yellow" | "green" | "gray" | "cyan";

function Pill({ children, variant = "gray" }: { children: ReactNode; variant?: PillVariant }) {
  const map: Record<PillVariant, CSSProperties> = {
    red:    { background: "rgba(239,68,68,0.12)",  color: "#f87171", border: "1px solid rgba(239,68,68,0.35)",  boxShadow: "0 0 12px rgba(239,68,68,0.1)" },
    yellow: { background: "rgba(245,158,11,0.12)", color: "#fbbf24", border: "1px solid rgba(245,158,11,0.35)", boxShadow: "0 0 12px rgba(245,158,11,0.1)" },
    green:  { background: "rgba(16,185,129,0.12)", color: "#34d399", border: "1px solid rgba(16,185,129,0.35)", boxShadow: "0 0 12px rgba(16,185,129,0.1)" },
    gray:   { background: "rgba(148,163,184,0.06)", color: "rgba(148,163,184,0.6)", border: "1px solid rgba(148,163,184,0.15)" },
    cyan:   { background: "rgba(56,189,248,0.1)",  color: "#38bdf8", border: "1px solid rgba(56,189,248,0.35)", boxShadow: "0 0 12px rgba(56,189,248,0.1)" },
  };
  return (
    <span style={{ ...map[variant], display: "inline-flex", alignItems: "center", fontFamily: "'JetBrains Mono', 'Fira Code', monospace", fontSize: 11, fontWeight: 500, letterSpacing: "0.03em", padding: "5px 10px", borderRadius: 6, whiteSpace: "nowrap" as const }}>
      {children}
    </span>
  );
}

// ── AegisDropdown ─────────────────────────────────────────────────────────────

const PILL_COLORS: Record<PillVariant, { bg: string; color: string; border: string }> = {
  red:    { bg: "rgba(239,68,68,0.12)",   color: "#f87171", border: "rgba(239,68,68,0.35)" },
  yellow: { bg: "rgba(245,158,11,0.12)",  color: "#fbbf24", border: "rgba(245,158,11,0.35)" },
  green:  { bg: "rgba(16,185,129,0.12)",  color: "#34d399", border: "rgba(16,185,129,0.35)" },
  gray:   { bg: "rgba(148,163,184,0.06)", color: "rgba(148,163,184,0.5)", border: "rgba(148,163,184,0.15)" },
  cyan:   { bg: "rgba(56,189,248,0.1)",   color: "#38bdf8", border: "rgba(56,189,248,0.35)" },
};

function AegisDropdown<T extends string>({ label, value, options, onChange, colorMap }: {
  label: string; value: T; options: T[]; onChange: (v: T) => void; colorMap: Record<T, PillVariant>;
}) {
  const c = PILL_COLORS[colorMap[value]];
  return (
    <div style={{ display: "flex", flexDirection: "column" as const, gap: 6, flex: "1 1 140px", minWidth: 0 }}>
      <span style={s.aegisColLabel}>{label}</span>
      <select
        value={value}
        onChange={e => onChange(e.target.value as T)}
        style={{
          fontFamily: "'JetBrains Mono', 'Fira Code', monospace",
          fontSize: 12, fontWeight: 500, letterSpacing: "0.02em",
          padding: "10px 14px", borderRadius: 8,
          border: `1px solid ${c.border}`,
          background: c.bg, color: c.color,
          cursor: "pointer", outline: "none",
          appearance: "none" as const, WebkitAppearance: "none" as const,
          width: "100%",
          backdropFilter: "blur(8px)",
          touchAction: "manipulation",
          minHeight: 44, // Touch target
        }}
      >
        {options.map(o => <option key={o} value={o} style={{ background: "#0f172a", color: "#e2e8f0" }}>{o}</option>)}
      </select>
    </div>
  );
}

// ── Remark presets ────────────────────────────────────────────────────────────

const REMARK_OPTIONS: { key: RemarkKey; label: string; needsReport: boolean }[] = [
  { key: "clean-not-found",      label: "Clean — Not in Blocklist",     needsReport: true  },
  { key: "already-blocked",      label: "Already Blocked",              needsReport: false },
  { key: "no-remarks-confirmed", label: "No Remarks",                   needsReport: true  },
  { key: "malicious-not-found",  label: "Malicious — Not in Blocklist", needsReport: true  },
  { key: "in-list-not-blocked",  label: "In List but Not Blocked",      needsReport: true  },
];

// ── Main Component ────────────────────────────────────────────────────────────

export default function AlertAnalyzer() {
  const [jsonInput, setJsonInput]       = useState("");
  const [output, setOutput]             = useState("");
  const [followUp, setFollowUp]         = useState("");
  const [vtIp, setVtIp]                 = useState<string | null>(null);
  const [vtResult, setVtResult]         = useState<VTResult | null>(null);
  const [vtLoading, setVtLoading]       = useState(false);
  const [showAegis, setShowAegis]       = useState(false);
  const [caseAnalysis, setCaseAnalysis] = useState<CaseAnalysis | null>(null);
  const [sendTo, setSendTo]             = useState<string | null>(null);

  const [aegisCaseStatus,   setAegisCaseStatus]   = useState<CaseStatus>("Waiting for Status");
  const [aegisVerification, setAegisVerification] = useState<Verification>("To Be Confirmed");
  const [aegisRemediation,  setAegisRemediation]  = useState<Remediation>("Not Remediated");
  const [aegisRemarkKey,    setAegisRemarkKey]    = useState<RemarkKey>("clean-not-found");
  const [aegisReportSent,   setAegisReportSent]   = useState(false);
  const [aegisTenant,       setAegisTenant]       = useState("Unknown Tenant");

  const [toast, setToast] = useState({ msg: "", show: false });
  const toastTimer = useRef<ReturnType<typeof setTimeout> | null>(null);

  const showToast = (msg: string) => {
    setToast({ msg, show: true });
    if (toastTimer.current) clearTimeout(toastTimer.current);
    toastTimer.current = setTimeout(() => setToast(t => ({ ...t, show: false })), 2200);
  };

  const applyPreset = (vt: VTResult | null, verdict?: ScannerVerdict) => {
    const p = buildAegisPreset(vt, verdict);
    setAegisCaseStatus(p.caseStatus);
    setAegisVerification(p.verification);
    setAegisRemediation(p.remediation);
    setAegisRemarkKey(p.remarkKey);
    setAegisReportSent(false);
  };

  const generate = () => {
    const raw = jsonInput.trim();
    let data: AlertData;
    if (!raw) { data = JSON.parse(SAMPLE_JSON) as AlertData; }
    else {
      try { data = JSON.parse(raw) as AlertData; }
      catch { showToast("⚠ Invalid JSON"); return; }
    }
    setOutput(buildMessage(data));
    setFollowUp(buildFollowUp(data));

    const analysis = analyzeScanner(data);
    setCaseAnalysis(analysis);
    setSendTo(data.tenant_name ?? null);
    setAegisTenant(data.tenant_name ?? "Unknown Tenant");

    const alertKey = (data.xdr_event?.display_name ?? data.alert_type ?? "").toLowerCase();
    const ip = alertKey.includes("bad source reputation")
      ? (data.srcip ?? data.srcip_host ?? null)
      : (data.srcip ?? data.srcip_host ?? data.host_ip ?? data["IP/name"] ?? data.ip ?? null);

    const isPrivateOrHostname = (val: string) =>
      /^10\./i.test(val) || /^172\.(1[6-9]|2\d|3[01])\./i.test(val) || /^192\.168\./i.test(val) || /^127\./i.test(val) || !/^\d{1,3}(\.\d{1,3}){3}$/.test(val);

    if (ip && !isPrivateOrHostname(ip)) {
      setVtIp(ip); setVtResult(null); setVtLoading(true); setShowAegis(false);
      fetch(`/api/virustotal?ip=${encodeURIComponent(ip)}`)
        .then(r => r.json())
        .then((vt: VTResult) => {
          if (vt.error && typeof vt.error !== "string") vt.error = String(vt.error);
          setVtResult(vt); setVtLoading(false);
          if (!buildFollowUp(data).includes("No template available")) { applyPreset(vt, analysis.verdict); setShowAegis(true); }
        })
        .catch(err => {
          const errVt: VTResult = { malicious: 0, suspicious: 0, harmless: 0, undetected: 0, reputation: 0, country: "Unknown", owner: "Unknown", error: String(err) };
          setVtResult(errVt); setVtLoading(false);
          if (!buildFollowUp(data).includes("No template available")) { applyPreset(null, analysis.verdict); setShowAegis(true); }
        });
    } else {
      const fu = buildFollowUp(data);
      if (!fu.includes("No template available")) { applyPreset(null, analysis.verdict); setShowAegis(true); }
    }
  };

  const clearAll = () => {
    setJsonInput(""); setOutput(""); setFollowUp(""); setVtIp(null);
    setVtResult(null); setVtLoading(false); setShowAegis(false);
    setCaseAnalysis(null); setSendTo(null);
    setAegisCaseStatus("Waiting for Status"); setAegisVerification("To Be Confirmed");
    setAegisRemediation("Not Remediated"); setAegisRemarkKey("clean-not-found");
    setAegisReportSent(false); setAegisTenant("Unknown Tenant");
  };

  const copyMsg      = () => { if (!output)   return; navigator.clipboard.writeText(output).then(() => showToast("✓ Notification copied")); };
  const copyFollowUp = () => { if (!followUp) return; navigator.clipboard.writeText(followUp).then(() => showToast("✓ Follow-up copied")); };

  const currentRemark = buildRemark(aegisRemarkKey, vtResult, aegisTenant, aegisReportSent);
  const copyRemark    = () => navigator.clipboard.writeText(currentRemark).then(() => showToast("✓ Remark copied"));

  const caseStatusColors: Record<CaseStatus, PillVariant>     = { "Waiting for Status": "yellow", "Resolved": "green", "Whitelisted": "cyan", "Confirmed": "green" };
  const verificationColors: Record<Verification, PillVariant> = { "To Be Confirmed": "yellow", "True Positive": "red", "False Positive": "green" };
  const remediationColors: Record<Remediation, PillVariant>   = { "Remediated": "green", "Not Remediated": "red" };

  const activeRemark = REMARK_OPTIONS.find(r => r.key === aegisRemarkKey);
  const needsReport  = activeRemark?.needsReport ?? true;

  const TENANT_PROJECTS: Record<string, string> = {
    "belmont": "Project Selene", "cantilan bank": "Project Atlas",
    "eton properties": "Project Titan", "mwell": "Project Chiron",
    "siycha group of companies": "Project Orion",
  };

  const tenantLower = (sendTo ?? "").toLowerCase();
  const projectName = Object.entries(TENANT_PROJECTS).find(([k]) => tenantLower.includes(k))?.[1] ?? null;

  const isRemediated = ["deny", "denied", "client-rst", "server-rst"].includes((caseAnalysis?.detectionResult ?? "").toLowerCase().trim());
  const isMwell = tenantLower.includes("mwell");
  const isNoNeedToReport = isMwell && isRemediated;

  return (
    <div style={s.root}>

      <SecurityBackground />

      {/* Top navigation bar */}
      <nav style={s.navbar}>
        <div style={s.navLeft}>
          <div style={s.navLogo}>
            <svg width="16" height="16" viewBox="0 0 24 24" fill="none">
              <path d="M12 2L2 7l10 5 10-5-10-5zM2 17l10 5 10-5M2 12l10 5 10-5" stroke="#38bdf8" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"/>
            </svg>
          </div>
          <div>
            <span style={s.navTitle}>Alert Analyzer</span>
            <span className="nav-sub-inline"> · SOC Ops</span>
          </div>
        </div>
        <div style={s.navRight}>
          <div style={s.navStatus}>
            <span style={s.navStatusDot} />
            <span style={s.navStatusText}>LIVE</span>
          </div>
          <button
            onClick={async () => { await fetch("/api/auth/logout", { method: "POST" }); window.location.href = "/login"; }}
            style={s.logoutBtn}
            onMouseEnter={e => { (e.currentTarget as HTMLButtonElement).style.background = "rgba(239,68,68,0.15)"; (e.currentTarget as HTMLButtonElement).style.borderColor = "rgba(239,68,68,0.5)"; (e.currentTarget as HTMLButtonElement).style.color = "#f87171"; }}
            onMouseLeave={e => { (e.currentTarget as HTMLButtonElement).style.background = "transparent"; (e.currentTarget as HTMLButtonElement).style.borderColor = "rgba(239,68,68,0.2)"; (e.currentTarget as HTMLButtonElement).style.color = "rgba(239,68,68,0.6)"; }}
          >
            <svg width="13" height="13" viewBox="0 0 24 24" fill="none" className="logout-icon">
              <path d="M9 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h4M16 17l5-5-5-5M21 12H9" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"/>
            </svg>
            <span className="logout-text">Logout</span>
          </button>
        </div>
      </nav>

      <div style={s.content}>

        {/* Page header */}
        <header style={s.pageHeader}>
          <div style={s.headerBadge}>THREAT INTELLIGENCE CONSOLE</div>
          <h1 style={s.h1}>Alert Analysis <span style={s.h1Accent}>Dashboard</span></h1>
          <p style={s.h1Sub}>Parse, classify, and generate structured alert reports for SOC operations</p>
        </header>

        {/* Send to banner */}
        {sendTo && (
          isNoNeedToReport ? (
            <div style={{ ...s.sendToBanner, background: "rgba(245,158,11,0.06)", borderColor: "rgba(245,158,11,0.2)", borderLeft: "3px solid rgba(245,158,11,0.5)" }}>
              <div style={{ ...s.sendToIcon, background: "rgba(245,158,11,0.12)", color: "#fbbf24" }}>⚠</div>
              <div style={{ minWidth: 0 }}>
                <div style={{ ...s.sendToLabel, color: "rgba(245,158,11,0.6)" }}>NO ACTION REQUIRED</div>
                <div style={{ ...s.sendToValue, color: "#fbbf24", wordBreak: "break-word" }}>{sendTo}{projectName && ` · ${projectName}`} — Action already {caseAnalysis?.detectionResult}</div>
              </div>
            </div>
          ) : (
            <div style={s.sendToBanner}>
              <div
                style={{
                  ...s.sendToIcon,
                  cursor: "pointer",
                  position: "relative" as const,
                  background: tenantLower.includes("belmont") ? "rgba(37,211,102,0.15)" : "rgba(126,85,196,0.15)",
                  color: tenantLower.includes("belmont") ? "#25d366" : "#7e55c4",
                  flexShrink: 0,
                }}
                onClick={() => {
                  if (tenantLower.includes("belmont")) { window.open("whatsapp://", "_blank"); showToast("✓ Opening WhatsApp..."); }
                  else { window.open("viber://", "_blank"); showToast("✓ Opening Viber..."); }
                }}
              >
                <svg width="18" height="18" viewBox="0 0 24 24" fill="none">
                  <path d="M22 2L11 13" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"/>
                  <path d="M22 2L15 22L11 13L2 9L22 2Z" fill="currentColor" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" opacity="0.8"/>
                </svg>
              </div>
              <div style={{ minWidth: 0 }}>
                <div style={s.sendToLabel}>SEND TO</div>
                <div style={{ ...s.sendToValue, wordBreak: "break-word" }}>
                  {sendTo}
                  {projectName && <span style={s.projectBadge}>{projectName}</span>}
                </div>
              </div>
            </div>
          )
        )}

        {/* Input card */}
        <Card label="JSON Input" icon="⌨" subtitle="Paste your raw alert JSON">
          <textarea
            style={s.textarea}
            value={jsonInput}
            onChange={(e: ChangeEvent<HTMLTextAreaElement>) => setJsonInput(e.target.value)}
            placeholder={`Paste your alert JSON here…\n\nExample:\n${SAMPLE_JSON}`}
          />
          <Row>
            <Btn primary onClick={generate}>
              <svg width="13" height="13" viewBox="0 0 24 24" fill="none" style={{ marginRight: 7 }}><path d="M5 3l14 9-14 9V3z" stroke="currentColor" strokeWidth="2" strokeLinejoin="round"/></svg>
              Generate Template
            </Btn>
            <Btn danger onClick={clearAll}>
              <svg width="13" height="13" viewBox="0 0 24 24" fill="none" style={{ marginRight: 7 }}><path d="M18 6L6 18M6 6l12 12" stroke="currentColor" strokeWidth="2" strokeLinecap="round"/></svg>
              Clear All
            </Btn>
          </Row>
        </Card>

        {/* Message 1 */}
        <Card label="Alert Notification" icon="📨" subtitle="Message 1 — Initial alert message">
          <textarea style={{ ...s.textarea, minHeight: 110 }} value={output} onChange={(e: ChangeEvent<HTMLTextAreaElement>) => setOutput(e.target.value)} placeholder="Alert notification will appear here…" />
          <Row>
            <Btn green onClick={copyMsg}>
              <svg width="13" height="13" viewBox="0 0 24 24" fill="none" style={{ marginRight: 7 }}><rect x="9" y="9" width="13" height="13" rx="2" stroke="currentColor" strokeWidth="2"/><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1" stroke="currentColor" strokeWidth="2"/></svg>
              Copy Notification
            </Btn>
          </Row>
        </Card>

        {/* Message 2 */}
        <Card label="Follow-up Details" icon="📋" subtitle="Message 2 — Detailed alert breakdown">
          {followUp.includes("No template available") ? (
            <div style={s.noTemplateBanner}>
              <svg width="16" height="16" viewBox="0 0 24 24" fill="none" style={{ flexShrink: 0, marginTop: 1 }}><path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0zM12 9v4M12 17h.01" stroke="#fbbf24" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"/></svg>
              <span>No template available for this alert type yet. Please create the follow-up details manually.</span>
            </div>
          ) : (
            <>
              <textarea style={{ ...s.textarea, minHeight: 240 }} value={followUp} onChange={(e: ChangeEvent<HTMLTextAreaElement>) => setFollowUp(e.target.value)} placeholder="Follow-up details will appear here…" />
              <Row>
                <Btn green onClick={copyFollowUp}>
                  <svg width="13" height="13" viewBox="0 0 24 24" fill="none" style={{ marginRight: 7 }}><rect x="9" y="9" width="13" height="13" rx="2" stroke="currentColor" strokeWidth="2"/><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1" stroke="currentColor" strokeWidth="2"/></svg>
                  Copy Follow-up
                </Btn>
              </Row>
            </>
          )}
        </Card>

        {/* VirusTotal */}
        {vtIp && (
          <Card label="VirusTotal IP Check" icon="🔍" subtitle={vtIp}>
            <div style={s.pillRow}>
              {vtLoading ? (
                <div style={s.loadingRow}>
                  {[0, 1, 2].map(i => <span key={i} style={{ ...s.dot, animationDelay: `${i * 0.25}s` }} />)}
                  <span style={s.loadingText}>Querying VirusTotal…</span>
                </div>
              ) : vtResult && (
                vtResult.error
                  ? <Pill variant="red">Error: {vtResult.error}</Pill>
                  : <>
                      <Pill variant={vtResult.malicious > 0 ? "red" : "green"}>
                        {vtResult.malicious > 0 ? "⚠ Malicious" : "✓ Clean"}
                      </Pill>
                      <Pill variant="red">Malicious: {vtResult.malicious}</Pill>
                      <Pill variant="yellow">Suspicious: {vtResult.suspicious}</Pill>
                      <Pill variant="green">Harmless: {vtResult.harmless}</Pill>
                      <Pill variant="gray">Undetected: {vtResult.undetected}</Pill>
                      <Pill variant="gray">Rep: {vtResult.reputation}</Pill>
                      <Pill variant="cyan">Owner: {vtResult.owner}</Pill>
                      <Pill variant="cyan">Country: {vtResult.country}</Pill>
                    </>
              )}
            </div>
          </Card>
        )}

        {/* Scanner Analysis */}
        {caseAnalysis?.isScannerAnomaly && (
          <Card label="Scanner Anomaly Analysis" icon="🛡" subtitle="Auto-generated detection report">
            <div style={s.analysisGrid}>
              {[
                { label: "Tenant",             value: caseAnalysis.tenant },
                { label: "IP / Alert Details", value: caseAnalysis.ipDetail, mono: true },
                { label: "Detection Result",   value: caseAnalysis.detectionResult, mono: true },
                { label: "Action Taken",       value: caseAnalysis.actionTaken },
                { label: "Final Status",       value: caseAnalysis.finalStatus, highlight: caseAnalysis.verdict },
              ].map((row, i) => (
                <div key={i} style={s.analysisRow}>
                  <span style={s.analysisLabel}>{row.label}</span>
                  <span style={{
                    ...s.analysisValue,
                    ...(row.mono ? { fontFamily: "'JetBrains Mono', monospace", fontSize: 11.5 } : {}),
                    ...(row.highlight === "false-positive" ? { color: "#34d399", fontWeight: 600 } : row.highlight === "true-positive" ? { color: "#fbbf24", fontWeight: 600 } : row.highlight === "escalate" ? { color: "#f87171", fontWeight: 600 } : {}),
                  }}>
                    {row.value}
                  </span>
                </div>
              ))}
            </div>
          </Card>
        )}

        {/* Aegis */}
        {showAegis && (
          <Card label="Aegis Case Status" icon="⚖" subtitle="Case management and remediation tracking">
            <div style={s.aegisDropdownRow}>
              <AegisDropdown label="Case Status"  value={aegisCaseStatus}  options={["Waiting for Status","Resolved","Whitelisted","Confirmed"]}  onChange={setAegisCaseStatus}  colorMap={caseStatusColors}  />
              <AegisDropdown label="Verification" value={aegisVerification} options={["To Be Confirmed","True Positive","False Positive"]}          onChange={setAegisVerification} colorMap={verificationColors} />
              <AegisDropdown label="Remediation"  value={aegisRemediation}  options={["Remediated","Not Remediated"]}                               onChange={setAegisRemediation}  colorMap={remediationColors}  />
            </div>

            <div style={s.aegisDivider} />

            <div style={s.remarkSection}>
              <span style={s.aegisColLabel}>Remarks Preset</span>
              <div style={s.remarkBtnRow}>
                {REMARK_OPTIONS.map(({ key, label }) => (
                  <button key={key} onClick={() => setAegisRemarkKey(key)} style={{ ...s.remarkBtn, ...(aegisRemarkKey === key ? s.remarkBtnActive : {}) }}>
                    {label}
                  </button>
                ))}
              </div>

              {needsReport && (
                <button onClick={() => setAegisReportSent(v => !v)} style={{ ...s.toggleBtn, ...(aegisReportSent ? s.toggleBtnOn : {}), alignSelf: "flex-start" }}>
                  {aegisReportSent ? "✓ Report Sent to Client" : "○ Report Not Yet Sent"}
                </button>
              )}

              <div style={s.remarkPreview}>
                <div style={s.remarkPreviewMeta}>
                  <span style={s.remarkPreviewLabel}>{needsReport ? "📤 Needs to be Sent to Client" : "🔒 No Need to Send to Client"}</span>
                </div>
                <p style={s.remarkText}>{currentRemark}</p>
                <div style={{ marginTop: 14 }}>
                  <Btn green onClick={copyRemark}>
                    <svg width="13" height="13" viewBox="0 0 24 24" fill="none" style={{ marginRight: 7 }}><rect x="9" y="9" width="13" height="13" rx="2" stroke="currentColor" strokeWidth="2"/><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1" stroke="currentColor" strokeWidth="2"/></svg>
                    Copy Remark
                  </Btn>
                </div>
              </div>
            </div>
          </Card>
        )}
      </div>

      {/* Toast */}
      <div style={{ ...s.toast, opacity: toast.show ? 1 : 0, transform: toast.show ? "translateY(0)" : "translateY(8px)" }}>
        {toast.msg}
      </div>

      <style>{`
        @import url('https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&family=JetBrains+Mono:wght@400;500;600&display=swap');

        @keyframes blink { 0%,80%,100%{opacity:.15} 40%{opacity:1} }
        @keyframes fadeUp { from{opacity:0;transform:translateY(16px)} to{opacity:1;transform:translateY(0)} }
        @keyframes pulse { 0%,100%{opacity:0.5;transform:scale(1)} 50%{opacity:1;transform:scale(1.15)} }

        *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }
        html, body { background: #060d1b; overscroll-behavior: none; }
        * { -webkit-tap-highlight-color: transparent; }

        ::selection { background: rgba(56,189,248,0.2); color: #38bdf8; }
        ::-webkit-scrollbar { width: 4px; }
        ::-webkit-scrollbar-track { background: rgba(15,23,42,0.5); }
        ::-webkit-scrollbar-thumb { background: rgba(56,189,248,0.2); border-radius: 3px; }

        textarea { caret-color: #38bdf8; }
        textarea:focus { outline: none !important; border-color: rgba(56,189,248,0.4) !important; box-shadow: 0 0 0 3px rgba(56,189,248,0.08) !important; }
        select option { background: #0f172a !important; color: #e2e8f0 !important; }
        button { transition: all 0.18s ease !important; }
        button:active:not(:disabled) { transform: scale(0.97) !important; }

        /* Subtle inline subtitle in navbar */
        .nav-sub-inline {
          font-size: 11.5px;
          color: rgba(148,163,184,0.45);
          letter-spacing: 0.02em;
        }
        .logout-text { display: inline; }
        .logout-icon { margin-right: 6px; }

        /* Hover — non-touch only */
        @media (hover: hover) {
          button:hover:not(:disabled) { opacity: 0.9; }
        }

        /* ── Mobile ── */
        @media (max-width: 600px) {
          .nav-sub-inline { display: none; }
          .logout-text { display: none; }
          .logout-icon { margin-right: 0 !important; }
        }

        /* Analysis rows — stack on small screens */
        @media (max-width: 480px) {
          .analysis-row-inner {
            flex-direction: column !important;
            align-items: flex-start !important;
            gap: 4px !important;
          }
          .analysis-value-cell {
            text-align: left !important;
          }
        }
      `}</style>
    </div>
  );
}

// ── Sub-components ────────────────────────────────────────────────────────────

function Card({ label, children, icon, subtitle }: { label: string; children: ReactNode; icon?: string; subtitle?: string }) {
  return (
    <div style={s.card}>
      <div style={s.cardHeader}>
        <div style={s.cardHeaderLeft}>
          {icon && <span style={s.cardIcon}>{icon}</span>}
          <div style={{ minWidth: 0 }}>
            <div style={s.label}>{label}</div>
            {subtitle && <div style={{ ...s.cardSubtitle, wordBreak: "break-all" }}>{subtitle}</div>}
          </div>
        </div>
      </div>
      <div style={s.cardBody}>{children}</div>
    </div>
  );
}

function Row({ children }: { children: ReactNode }) {
  return <div style={s.btnRow}>{children}</div>;
}

function Btn({ children, onClick, primary, green, danger }: BtnProps) {
  const extra: CSSProperties = primary
    ? { color: "#38bdf8", borderColor: "rgba(56,189,248,0.35)", background: "rgba(56,189,248,0.08)" }
    : green
    ? { color: "#34d399", borderColor: "rgba(16,185,129,0.35)", background: "rgba(16,185,129,0.08)" }
    : danger
    ? { color: "rgba(239,68,68,0.7)", borderColor: "rgba(239,68,68,0.2)", background: "transparent" }
    : { color: "rgba(148,163,184,0.7)", borderColor: "rgba(148,163,184,0.2)", background: "transparent" };
  return (
    <button style={{ ...s.btn, ...extra }} onClick={onClick}>
      {children}
    </button>
  );
}

// ── Styles ────────────────────────────────────────────────────────────────────

const s: Record<string, CSSProperties> = {
  // Root
  root: {
    fontFamily: "'Inter', sans-serif",
    minHeight: "100vh",
    position: "relative",
    overflow: "hidden",
    background: "#060d1b",
  },

  // Navbar — fixed, collapses gracefully on mobile
  navbar: {
    position: "fixed", top: 0, left: 0, right: 0, zIndex: 100,
    height: 52,
    display: "flex", alignItems: "center", justifyContent: "space-between",
    padding: "0 clamp(12px, 4vw, 24px)",
    background: "rgba(6,13,27,0.88)",
    backdropFilter: "blur(20px)",
    WebkitBackdropFilter: "blur(20px)",
    borderBottom: "1px solid rgba(56,189,248,0.08)",
  },
  navLeft:  { display: "flex", alignItems: "center", gap: 10, minWidth: 0 },
  navLogo:  {
    width: 30, height: 30, borderRadius: 8,
    background: "rgba(56,189,248,0.1)", border: "1px solid rgba(56,189,248,0.2)",
    display: "flex", alignItems: "center", justifyContent: "center",
    flexShrink: 0,
  },
  navTitle: { fontSize: 13, fontWeight: 600, color: "#f1f5f9", letterSpacing: "-0.01em", whiteSpace: "nowrap" },
  navRight: { display: "flex", alignItems: "center", gap: 8, flexShrink: 0 },
  navStatus: {
    display: "flex", alignItems: "center", gap: 5,
    padding: "4px 8px", borderRadius: 20,
    background: "rgba(16,185,129,0.08)", border: "1px solid rgba(16,185,129,0.2)",
  },
  navStatusDot:  { width: 5, height: 5, borderRadius: "50%", background: "#34d399", animation: "pulse 2s ease-in-out infinite" },
  navStatusText: { fontSize: 9, fontWeight: 600, color: "#34d399", letterSpacing: "0.1em" },
  logoutBtn: {
    fontFamily: "'Inter', sans-serif", fontSize: 12, fontWeight: 500,
    padding: "0 10px", height: 32, borderRadius: 7, cursor: "pointer",
    background: "transparent", color: "rgba(239,68,68,0.6)",
    border: "1px solid rgba(239,68,68,0.2)",
    display: "flex", alignItems: "center",
    touchAction: "manipulation",
    minWidth: 32,
  },

  // Content — safe area under nav, responsive padding
  content: {
    position: "relative", zIndex: 10,
    maxWidth: 860, margin: "0 auto",
    padding: "clamp(68px, 10vw, 88px) clamp(12px, 4vw, 24px) 80px",
  },

  // Page header
  pageHeader: { marginBottom: 24, animation: "fadeUp 0.6s ease both" },
  headerBadge: {
    display: "inline-block", fontSize: "clamp(9px, 2.5vw, 10px)", fontWeight: 600,
    letterSpacing: "0.1em", color: "#38bdf8",
    background: "rgba(56,189,248,0.1)", border: "1px solid rgba(56,189,248,0.2)",
    padding: "3px 10px", borderRadius: 20, marginBottom: 12,
  },
  h1:       { fontSize: "clamp(20px, 5vw, 30px)", fontWeight: 700, color: "#f1f5f9", letterSpacing: "-0.03em", lineHeight: 1.2, marginBottom: 8 },
  h1Accent: { color: "#38bdf8" },
  h1Sub:    { fontSize: "clamp(12px, 3.5vw, 14px)", color: "rgba(148,163,184,0.6)", lineHeight: 1.6, fontWeight: 400 },

  // Send to banner
  sendToBanner: {
    display: "flex", alignItems: "center", gap: 12,
    background: "rgba(56,189,248,0.05)", border: "1px solid rgba(56,189,248,0.15)",
    borderLeft: "3px solid rgba(56,189,248,0.5)",
    borderRadius: 10, padding: "12px 14px", marginBottom: 14,
    animation: "fadeUp 0.4s ease both",
  },
  sendToIcon: {
    width: 34, height: 34, minWidth: 34, borderRadius: 8,
    background: "rgba(56,189,248,0.1)", color: "#38bdf8",
    display: "flex", alignItems: "center", justifyContent: "center",
  },
  sendToLabel: { fontSize: 10, fontWeight: 600, letterSpacing: "0.1em", color: "rgba(56,189,248,0.5)", marginBottom: 3 },
  sendToValue: { fontSize: "clamp(12px, 3.5vw, 13.5px)", fontWeight: 600, color: "#38bdf8", letterSpacing: "-0.01em" },
  projectBadge: {
    marginLeft: 8, fontSize: 10, fontWeight: 500, color: "#fbbf24",
    background: "rgba(245,158,11,0.1)", border: "1px solid rgba(245,158,11,0.25)",
    padding: "2px 8px", borderRadius: 20, whiteSpace: "nowrap" as const,
  },

  // Cards
  card: {
    background: "rgba(10,18,38,0.75)", backdropFilter: "blur(20px)", WebkitBackdropFilter: "blur(20px)",
    border: "1px solid rgba(56,189,248,0.08)", borderRadius: 14, marginBottom: 12, overflow: "hidden",
    boxShadow: "0 4px 32px rgba(0,0,0,0.35), 0 1px 0 rgba(56,189,248,0.05) inset",
    animation: "fadeUp 0.5s ease both",
  },
  cardHeader:     { display: "flex", alignItems: "center", justifyContent: "space-between", padding: "14px 16px 0" },
  cardHeaderLeft: { display: "flex", alignItems: "flex-start", gap: 10 },
  cardIcon:       { fontSize: 15, marginTop: 1, flexShrink: 0 },
  label:          { fontSize: 11, fontWeight: 600, letterSpacing: "0.04em", color: "rgba(148,163,184,0.7)", textTransform: "uppercase" as const },
  cardSubtitle:   { fontSize: 11, color: "rgba(100,116,139,0.6)", marginTop: 2, fontWeight: 400 },
  cardBody:       { padding: "12px 14px 16px" },

  // Textarea — font-size: 16px prevents iOS auto-zoom
  textarea: {
    width: "100%", minHeight: 140,
    fontFamily: "'JetBrains Mono', monospace",
    fontSize: 13, lineHeight: 1.85,
    color: "#e2e8f0", background: "rgba(2,8,23,0.6)",
    border: "1px solid rgba(56,189,248,0.1)", borderRadius: 10,
    padding: "12px 14px", resize: "vertical" as const, transition: "all 0.2s",
    WebkitAppearance: "none",
  },

  // Buttons
  btnRow: { display: "flex", gap: 8, marginTop: 12, flexWrap: "wrap" as const },
  btn: {
    fontFamily: "'Inter', sans-serif", fontSize: 12.5, fontWeight: 500,
    letterSpacing: "0.01em", padding: "10px 16px",
    minHeight: 42, // Touch target
    borderRadius: 8, border: "1px solid", cursor: "pointer",
    display: "flex", alignItems: "center", justifyContent: "center",
    touchAction: "manipulation",
  },

  // Pills
  pillRow:     { display: "flex", flexWrap: "wrap" as const, gap: 6, padding: "4px 0", alignItems: "center" },
  loadingRow:  { display: "flex", alignItems: "center", gap: 8, padding: "4px 0" },
  loadingText: { fontSize: 12, color: "rgba(148,163,184,0.5)", fontFamily: "'JetBrains Mono', monospace" },
  dot:         { display: "inline-block", width: 7, height: 7, borderRadius: "50%", background: "#38bdf8", animation: "blink 1.2s ease-in-out infinite", boxShadow: "0 0 8px rgba(56,189,248,0.6)" },

  // No template
  noTemplateBanner: {
    display: "flex", alignItems: "flex-start", gap: 10,
    background: "rgba(245,158,11,0.06)", border: "1px solid rgba(245,158,11,0.2)",
    borderLeft: "3px solid rgba(245,158,11,0.5)", borderRadius: 10,
    padding: "14px 14px", fontSize: 13, color: "#fbbf24",
    lineHeight: 1.6, fontFamily: "'Inter', sans-serif",
  },

  // Analysis grid — rows wrap on small screens via className
  analysisGrid:  { border: "1px solid rgba(56,189,248,0.08)", borderRadius: 10, overflow: "hidden" },
  analysisRow:   {
    display: "flex", justifyContent: "space-between", alignItems: "flex-start",
    gap: 12, padding: "10px 14px",
    borderBottom: "1px solid rgba(56,189,248,0.05)",
    background: "rgba(2,8,23,0.3)",
    flexWrap: "wrap" as const, // Allows wrapping on very small screens
  },
  analysisLabel: { fontSize: 10.5, fontWeight: 500, letterSpacing: "0.08em", textTransform: "uppercase" as const, color: "rgba(100,116,139,0.7)", flexShrink: 0 },
  analysisValue: { fontFamily: "'JetBrains Mono', monospace", fontSize: 12, color: "rgba(226,232,240,0.85)", textAlign: "right" as const, wordBreak: "break-all" },

  // Aegis — dropdowns wrap naturally with flex
  aegisDropdownRow: { display: "flex", gap: 12, flexWrap: "wrap" as const, alignItems: "flex-end" },
  aegisColLabel:    { fontFamily: "'Inter', sans-serif", fontSize: 10, fontWeight: 600, letterSpacing: "0.08em", textTransform: "uppercase" as const, color: "rgba(100,116,139,0.7)", display: "block", marginBottom: 6 },
  aegisDivider:     { borderTop: "1px solid rgba(56,189,248,0.07)", margin: "16px 0" },
  remarkSection:    { display: "flex", flexDirection: "column" as const, gap: 10 },
  remarkBtnRow:     { display: "flex", flexWrap: "wrap" as const, gap: 6 },
  remarkBtn: {
    fontFamily: "'Inter', sans-serif", fontSize: 11.5, fontWeight: 500,
    padding: "8px 12px", borderRadius: 8, cursor: "pointer",
    border: "1px solid rgba(56,189,248,0.1)",
    background: "rgba(56,189,248,0.03)", color: "rgba(148,163,184,0.5)",
    touchAction: "manipulation", minHeight: 36,
  },
  remarkBtnActive: { background: "rgba(56,189,248,0.1)", color: "#38bdf8", border: "1px solid rgba(56,189,248,0.3)", boxShadow: "0 0 14px rgba(56,189,248,0.1)" },
  toggleBtn: {
    fontFamily: "'Inter', sans-serif", fontSize: 12, fontWeight: 500,
    padding: "9px 14px", borderRadius: 8, cursor: "pointer",
    border: "1px solid rgba(56,189,248,0.12)",
    background: "transparent", color: "rgba(148,163,184,0.5)",
    touchAction: "manipulation", minHeight: 38,
  },
  toggleBtnOn: { background: "rgba(56,189,248,0.1)", color: "#38bdf8", border: "1px solid rgba(56,189,248,0.3)" },
  remarkPreview:     { background: "rgba(2,8,23,0.5)", border: "1px solid rgba(56,189,248,0.1)", borderLeft: "3px solid rgba(56,189,248,0.3)", borderRadius: 10, padding: "14px 16px" },
  remarkPreviewMeta: { marginBottom: 10 },
  remarkPreviewLabel:{ fontSize: 10, fontWeight: 600, letterSpacing: "0.08em", color: "rgba(100,116,139,0.6)", textTransform: "uppercase" as const },
  remarkText:        { fontFamily: "'JetBrains Mono', monospace", fontSize: 12.5, lineHeight: 1.85, color: "rgba(226,232,240,0.8)", marginTop: 6, wordBreak: "break-word" },

  // Toast — bottom-center on mobile, bottom-right on desktop
  toast: {
    position: "fixed",
    bottom: "clamp(16px, 4vw, 24px)",
    right: "clamp(12px, 4vw, 24px)",
    background: "rgba(10,18,38,0.95)", backdropFilter: "blur(20px)", WebkitBackdropFilter: "blur(20px)",
    color: "#34d399",
    border: "1px solid rgba(16,185,129,0.3)",
    boxShadow: "0 8px 32px rgba(0,0,0,0.4), 0 0 0 1px rgba(16,185,129,0.1)",
    borderRadius: 10, padding: "10px 18px",
    fontFamily: "'Inter', sans-serif", fontSize: 13, fontWeight: 500, letterSpacing: "0.01em",
    transition: "all 0.25s ease", pointerEvents: "none" as const, zIndex: 200,
    maxWidth: "calc(100vw - 24px)",
  },
};