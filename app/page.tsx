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

      {/* Base */}
      <div style={{ position: "fixed", inset: 0, zIndex: 0, background: "#050d18" }} />

      {/* Aurora blob 1 — cyan/blue top left */}
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

      {/* Aurora blob 2 — indigo right */}
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

      {/* Aurora blob 3 — emerald bottom */}
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

      {/* Fine dot grid */}
      <div style={{
        position: "fixed", inset: 0, zIndex: 2,
        backgroundImage: "radial-gradient(circle, rgba(148,163,184,0.07) 1px, transparent 1px)",
        backgroundSize: "24px 24px",
        pointerEvents: "none",
      }} />

      {/* Shimmer grid lines */}
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

      {/* Center glow */}
      <div style={{
        position: "fixed", inset: 0, zIndex: 2,
        background: "radial-gradient(ellipse 60% 40% at 50% 0%, rgba(56,189,248,0.06) 0%, transparent 100%)",
        pointerEvents: "none",
      }} />

      {/* Vignette */}
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

  if (alertKey.includes("application usage")) {
    const threshold = get("threshold") !== "N/A" ? get("threshold") : getNested("stellar.threshold") !== "N/A" ? getNested("stellar.threshold") : get("typical");
    body = lines(["App", get("appid_name"), "", "App ID", get("appid"), "", "Actual", get("actual"), "", "Threshold", threshold, "", "Source Host", get("srcip_host"), "", "Source Country", getGeo("srcip"), "", "Destination Host", get("dstip_host"), "", "Please verify if the app is part of your operations. Thank you."]);
  } else if (alertKey.includes("bad source reputation")) {
    body = lines(["Source IP", get("srcip"), "", "Action", get("action"), "", "Destination IP", get("dstip_host", "dstip"), "", "Could you please confirm if this is a recognized malicious source IP within your network or used by your team? Thank you."]);
  } else if (alertKey.includes("data ingestion")) {
    const device = obj.device as Record<string, unknown> | undefined;
    const sensorName = (device?.name as string) ?? get("sensor_name", "engid_name");
    body = lines(["Sensor", sensorName, "", "Please confirm if this activity is expected and authorized on your end. Thank you."]);
  } else if (alertKey.includes("eset protect")) {
    body = lines(["Host Name", get("device_name", "engid_name"), "", "Source IP", `${get("srcip")} (Malicious)`, "", "Destination IP", get("dstip_hostg", "dstip"), "", "Source Port", get("srcport"), "", "Destination Port", get("dstport"), "", "Please verify if the source IP is related to your operations. If not, we suggest blocking the IP on your end and informing us, as it was flagged as malicious by security vendors."]);
  } else if (alertKey.includes("exploited c") || alertKey.includes("c&c")) {
    body = lines(["Source IP", `${get("srcip")} (Malicious)`, "", "Source Host", get("srcip_host"), "", "Source Port", get("srcport"), "", "Destination IP", get("dstip_host", "dstip"), "", "Destination Host", get("dstip_host", "dstip"), "", "Destination Port", get("dstport"), "", "Please confirm if this communication is expected and authorized for your systems. Thank you."]);
  } else if (alertKey.includes("external account login failure")) {
    const totalFailed = getNested("event_summary.total_failed") !== "N/A"
      ? getNested("event_summary.total_failed")
      : get("actual", "count");
    body = lines(["Source IP", get("srcip", "srcip_host"), "", "Destination IP", get("dstip", "dstip_host"), "", "Action", get("action"), "", "Please verify the source IP if related to your operations, Thank you!"]);
  } else if (alertKey.includes("external handshake failure")) {
    body = lines(["Source IP", get("srcip", "srcip_host"), "", "Destination IP", get("dstip", "dstip_host"), "", "Please confirm if this connection attempt is expected, or if any of this source IP should not be communicating with your public servers."]);
  } else if (alertKey.includes("external ip") || alertKey.includes("external ip / port scan")) {
    body = lines(["Source IP", get("srcip", "srcip_host"), "", "Destination IP", get("dstip", "dstip_host"), "", "App", get("appid_name", "proto_name"), "", "We detected that your internal host generated multiple failed outbound connection attempts to external IPs across several ports within a short period. This activity triggered a port scan anomaly due to its scanning-like pattern. Please confirm if this behavior is expected on your end. Thank you!"]);
  } else if (alertKey.includes("external pua")) {
    body = lines(["IDS Signature", getNested("ids.signature"), "", "Source Host", get("srcip_host"), "", "Destination IP", get("dstip", "dstip_host"), "", "Destination Host", get("dstip_host", "dstip"), "", "IDS Action", getNested("ids.action"), "", "Could you confirm if this is expected on your end? Thank you."]);
  } else if (alertKey.includes("internal account login failure")) {
    body = lines(["Source Username", get("srcip_username"), "", "Total Number Failed", getNested("event_summary.total_failed") !== "N/A" ? getNested("event_summary.total_failed") : get("actual"), "", "Total Number Successful", getNested("event_summary.total_successful") !== "N/A" ? getNested("event_summary.total_successful") : get("num_successful"), "", "Login Type", get("login_type"), "", "Source IP", get("srcip", "srcip_host"), "", "Please confirm whether these login failure attempts are legitimate or not. Thank you!"]);
  } else if (alertKey.includes("external firewall policy")) {
    body = lines(["Source IP", get("srcip", "srcip_host"), "", "Source Port", get("srcport"), "", "Destination IP", get("dstip", "dstip_host"), "", "Destination Port", get("dstport"), "", "Device Type", get("dev_type"), "", "Firewall Policy", get("fw_policy_id"), "", "Please verify if this firewall policy activity is part of your operations. Thank you."]);
  } else if (alertKey.includes("external firewall denial")) {
    body = lines(["Source IP", get("srcip", "srcip_host"), "", "Destination IP", get("dstip", "dstip_host"), "", "Action", get("action"), "", "Please verify the source IP if related to your operations, Thank you!"]);
  } else if (alertKey.includes("encrypted phishing")) {
    body = lines(["Source IP", get("srcip", "srcip_host"), "", "Destination IP", get("dstip", "dstip_host"), "", "Destination Host", get("dstip_host", "dstip"), "", "Destination Country", getGeo("dstip"), "", "Please confirm if this activity is expected or legitimate. If not, we recommend blocking the destination host and avoiding access to this site. Thank you."]);
  } else if (alertKey.includes("external protocol account login failure")) {
    const totalFailed = getNested("event_summary.total_failed") !== "N/A" ? getNested("event_summary.total_failed") : get("num_failed", "actual");
    body = lines(["Source IP", get("srcip", "srcip_host"), "", "Source Host", get("srcip_host"), "", "Source Port", get("srcport"), "", "Destination IP", get("dstip", "dstip_host"), "", "Destination Host", get("dstip_host", "dstip"), "", "Destination Port", get("dstport"), "", `We detected SMB login failures from internal host ${get("srcip_host")} using the account "${get("smb_username", "srcip_username")}" against external IP ${get("dstip", "dstip")}. A total of ${totalFailed} failed attempts were observed with no successful authentication.`, "", "Kindly confirm if this SMB access to an external system is authorized. Thank you."]);
  } else if (alertKey.includes("external scanner behavior")) {
    const src = get("srcip", "srcip_host"), dst = get("dstip", "dstip_host");
    body = lines(["Source Host", src, "", "Destination IP", dst, "", "IDS Signature", getNested("ids.signature"), "", "IDS Action", getNested("ids.action"), "", "Source Port", get("srcport"), "", "Destination Port", get("dstport"), "", `Unusual traffic detected from ${src} to ${dst}. Please confirm that the external scanning activity is expected and part of your operations right now. Thank you!`]);
  } else if (alertKey.includes("external user login failure")) {
    const srcIp = get("srcip", "srcip_host", "remote_ip");
    const dstIp = get("dstip");
    const dstHost = get("dstip_host");
    const rawFail = getNested("event_summary.total_fail_ratio") !== "N/A" ? getNested("event_summary.total_fail_ratio") : get("percent_failed", "failure_percent", "actual");
    const failPct = rawFail !== "N/A" ? (() => { const val = parseFloat(rawFail) * 100; return val === 100 ? "100%" : `${val.toFixed(2)}%`; })() : "N/A";
    body = lines(["Source IP", srcIp, "", "Destination IP", dstIp, "", "Destination Host", dstHost, "", "Total Fail Percentage", failPct, "", "Destination Port", get("dstport"), "", "Source Port", get("srcport"), "", `Please confirm if this repeated failed VPN authentication activity from the external source IP to the destination IP on port ${get("dstport")} is expected or authorized on your end. Thank you!`]);
  } else if (alertKey.includes("impossible travel")) {
    body = lines(["Source User ID", get("srcip_usersid", "user_id"), "", "Source IP", get("srcip", "srcip_host"), "", "Source IP 2", get("srcip2", "src_ip2"), "", "Source Country", getGeo("srcip"), "", "Distance Deviation (Miles)", get("distance_deviation", "dist_deviation"), "", "The following source IP for this specific alert is not on the whitelisted list. May we confirm if this activity is expected on your end?"]);
  } else if (alertKey.includes("internal credential stuffing")) {
    body = lines(["Source IP", get("srcip", "srcip_host"), "", "Destination IP", get("dstip", "dstip_host"), "", "Host Name", get("engid_name", "device_name"), "", "Source Username", get("srcip_username"), "", "Please verify this activity involving the user. Thank you."]);
  } else if (alertKey.includes("internal firewall denial")) {
    body = lines(["Source IP", get("srcip", "srcip_host"), "", "Source Port", get("srcport"), "", "Destination IP", get("dstip", "dstip_host"), "", "Destination Port", get("dstport"), "", "Please verify if the Source IP is authorized or used on your operations."]);
  } else if (alertKey.includes("internal handshake failure")) {
    body = lines(["Source IP", get("srcip", "srcip_host"), "", "Source Host", get("srcip_host"), "", "Destination IP", get("dstip", "dstip_host"), "", "Destination Host", get("dstip_host", "dstip"), "", "Please confirm if this is expected. Thank you."]);
  } else if (alertKey.includes("internal ip") || alertKey.includes("internal ip / port scan")) {
    body = lines(["Source IP", get("srcip","srcip_host"), "", "Source Port", get("srcport"), "", "Destination IP", get("dstip_host", "dstip"), "", "Destination Host", get("dstip_host", "dstip"), "", "Destination Port", get("dstport"), "", "Can you confirm that the internal host performing a block port scan across your internal subnets was an authorized activity?"]);
  } else if (alertKey.includes("external non-standard port")) {
    body = lines(["Source IP", get("srcip"), "", "Destination IP", get("dstip"), "", "Destination Host", get("dstip_host"), "", "App", get("appid_name"), "", "Destination Port", get("dstport"), "", "Source Port", get("srcport"), "", "A rarely seen connection from a source IP to a destination IP using a specific application on a non-standard port was observed after several days of inactivity. Please confirm if this activity is expected or legitimate. Thank you."]);
  } else if (alertKey.includes("internal non-standard port") || alertKey.includes("non-standard port")) {
    body = lines(["Source IP", get("srcip", "srcip_host"), "", "Source Host", get("srcip_host"), "", "Source Port", get("srcport"), "", "Destination IP", get("dstip_host", "dstip"), "", "Destination Host", get("dstip_host", "dstip"), "", "Destination Port", get("dstport"), "", `Can you confirm whether the traffic from ${get("srcip", "srcip_host")} to the internal host ${get("dstip_host", "dstip")} on non-standard port ${get("dstport")} is an expected and authorized activity?`]);
  } else if (alertKey.includes("plain text password")) {
    body = lines(["Source IP", get("srcip", "srcip_host"), "", "Destination IP", get("dstip_host", "dstip"), "", "Destination Host", get("dstip_host"), "", "App", get("appid_name", "proto_name"), "", "Destination Port", get("dstport"), "", "Source Port", get("srcport"), "", "Please verify if this detection is expected and confirm whether the activity is legitimate. Thank you."]);
  } else if (alertKey.includes("internal protocol account login fail")) {
    body = lines(["Account Name", get("smb_username", "srcip_username", "account_name"), "", "Total Number Failed", getNested("event_summary.total_failed") !== "N/A" ? getNested("event_summary.total_failed") : get("actual", "num_failed"), "", "Total Number Successful", getNested("event_summary.total_successful") !== "N/A" ? getNested("event_summary.total_successful") : get("num_successful"), "", "Login Type", get("login_type", "proto_name"), "", "Source Host", get("srcip_host"), "", "Source IP", get("srcip_host"), "", "Please confirm whether these SMB login failure attempts were initiated by a legitimate user activity or not. Thank you."]);
  } else if (alertKey.includes("external smb read")) {
    body = lines(["Source IP", get("srcip", "srcip_host"), "", "Destination Host", get("dstip_host", "dstip"), "", "SMB Username", get("smb_username", "srcip_username", "smb_username_count"), "", "Destination Port", get("dstport"), "", "Even though the said destination host is not detected as malicious, the team would like to confirm this just in case. May we confirm if this activity is expected or part of system operations? Thank you."]);
  } else if (alertKey.includes("microsoft 365")) {
    const user = get("srcip_username", "username");
    body = lines(["Source", getNested("office365.Source"), "", "Threat Name", getNested("office365.Name"), "", "Severity", getNested("office365.Severity"), "", "Alert Entity List", (() => { const entityList = obj.event_summary as Record<string, unknown> | undefined; const list = entityList?.alert_entity_list as Array<{entity_type: string, alert_entity_id: string}> | undefined; if (list && list.length > 0) { return list.map(e => `EntityType: ${e.entity_type}\nAlertEntityId: ${e.alert_entity_id}`).join("\n"); } return `EntityType: User\nAlertEntityId: ${user}`; })(), "", "User Name", user, "", `We observed that a user (${user}) reported an email message as phishing/malware in Microsoft 365 Security & Compliance. Please confirm whether this activity is legitimate. Thank you!`]);
  } else if (alertKey.includes("internal other malware")) {
    body = lines(["Source IP", get("srcip", "srcip_host"), "", "Destination IP", get("dstip", "dstip_host"), "", "IDS Signature", getNested("ids.signature"), "", "Source Port", get("srcport"), "", "Destination Port", get("dstport"), "", "We detected suspicious internal traffic that matched a known malware IDS signature. Kindly verify the affected endpoint and confirm whether this activity is expected. Thank you!"]);
  } else if (alertKey.includes("internal protocol account login")) {
    body = lines(["Account Name", get("srcip_username", "account_name"), "", "Total Number Failed", get("actual", "total_failed"), "", "Total Number Successful", get("total_success", "total_successful"), "", "Login Type", get("login_type", "proto_name"), "", "Source Host", get("srcip_host"), "", "Source IP", get("srcip_host"), "", "Please confirm whether these SMB login attempts were initiated by a legitimate user activity or not. Thank you."]);
  } else if (alertKey.includes("internal scanner behavior")) {
    body = lines(["Source IP", get("srcip", "srcip_host"), "", "Source Port", get("srcport"), "", "Destination IP", get("dstip", "dstip_host"), "", "Destination Host", get("dstip_host"), "", "Destination Port", get("dstport"), "", "Please confirm if it is expected. Thank you."]);
  } else if (alertKey.includes("internal smb read")) {
    body = lines(["Source IP", get("srcip", "srcip_host"), "", "Source Host", get("srcip_host"), "", "Source Port", get("srcport"), "", "Destination IP", get("dstip_host", "dstip"), "", "Destination Host", get("dstip_host"), "", "Destination Port", get("dstport"), "", "May we confirm if this activity is expected or part of system operations? Thank you."]);
  } else if (alertKey.includes("internal smb write")) {
    body = lines(["Source Host", get("srcip_host"), "", "Destination Host", get("dstip_host", "dstip"), "", "Source Port", get("srcport"), "", "Destination Port", get("dstport"), "", "May we confirm if this activity is expected or part of system operations? Thank you."]);
  } else if (alertKey.includes("internal user login failure")) {
    const totalFailed = getNested("event_summary.total_failed") !== "N/A" ? getNested("event_summary.total_failed") : get("num_failed", "actual", "count");
    body = lines(["Source IP", get("srcip_host"), "", "Source Username", get("srcip_username", "username"), "", "Destination IP", get("dstip", "hostip"), "", "Destination Host", get("dstip_host", "engid_name"), "", "Total Number Failed", totalFailed, "", "Login Type", get("login_type", "proto_name"), "", "Please verify whether these login failure attempts are part of legitimate user activity. Thank you!"]);
  } else if (alertKey.includes("login attempt location count")) {
    const username = get("srcip_username");
    body = lines(["Source User ID", get("srcip_usersid", "user_id"), "", "Source Username", username, "", "Source IP", get("srcip_host"), "", "Actual Locations", get("actual"), "", "Typical Locations", get("typical"), "", `We detected multiple failed login attempts for the account ${username} originating from several geographically diverse locations within a short period. Please confirm whether these attempts are legitimate. Thank you!`]);
  } else if (alertKey.includes("login time anomaly")) {
    const desc = d.xdr_event?.description ?? "";
    const actualMatch  = desc.match(/abnormal time range\s+([\d:]+[-][\d:]+\s+UTC[+\-][\d:]+)/i);
    const typicalMatch = desc.match(/typical login time range:\s+([\d:]+[-][\d:]+\s+UTC[+\-][\d:]+)/i);
    const actualTimeRange = get("login_time_range", "actual_time_range", "abnormal_time_range", "actual_range") !== "N/A" ? get("login_time_range", "actual_time_range", "abnormal_time_range", "actual_range") : actualMatch ? actualMatch[1] : get("actual");
    const typicalTimeRange = get("typical_time_range", "typical_login_time_range", "typical_range") !== "N/A" ? get("typical_time_range", "typical_login_time_range", "typical_range") : typicalMatch ? typicalMatch[1] : get("typical");
    const sourceHost = get("srcip", "hostip", "srcip_host");
    const srcCountry1 = getGeo("srcip");
    const srcCountry2 = getGeo("hostip");
    const sourceCountry = srcCountry1 !== "N/A" ? srcCountry1 : srcCountry2 !== "N/A" ? srcCountry2 : "N/A";
    const deviceObj    = obj.device as Record<string, unknown> | undefined;
    const office365Obj = obj.office365 as Record<string, unknown> | undefined;
    const deviceProps  = office365Obj?.device_properties as Record<string, unknown> | undefined;
    const osFromO365   = deviceProps?.OS as string | undefined;
    const deviceFinal  = (deviceObj?.name as string) ?? osFromO365 ?? get("engid_name", "agent.computer_name", "device_name");
    const loginResult  = get("login_result", "event.outcome", "action");
    body = lines(["Source User ID", get("srcip_usersid", "user_id"), "", "Source Username", get("srcip_username", "username", "user.email"), "", "Source Host", sourceHost, "", "Source Country", sourceCountry, "", "Actual Login Time Range", actualTimeRange, "", "Typical Login Time Range", typicalTimeRange, "", "Device", deviceFinal, "", "Login Result", loginResult, "", "Please confirm if this login activity is expected and legitimate at this time. Thank you!"]);
  } else if (alertKey.includes("office 365 file sharing")) {
    body = lines(["Source IP", get("srcip_host"), "", "Source Host", get("srcip_host"), "", "Source Country", getGeo("srcip"), "", "User ID", getNested("office365.UserId"), "", "Shared File", getNested("office365.SourceFileName"), "", "Object ID", getNested("office365.ObjectId"), "", "Please verify whether this file-sharing activity was authorized and aligned with current business operations."]);
  } else if (alertKey.includes("office 365 sharing policy")) {
    body = lines(["Windows Organization ID", get("service_id"), "", "User ID", getNested("office365.UserId"), "", "Object ID", getNested("office365.ObjectId"), "", "Please verify if this account is authorized to make changes to the 365 Sharing Policy. Thank you!"]);
  } else if (alertKey.includes("office 365 multiple files restored")) {
    body = lines(["Source IP", get("srcip_host"), "", "User ID", getNested("office365.UserId"), "", "File Name", getNested("office365.SourceFileName"), "", "Object ID", getNested("office365.ObjectId"), "", "Please confirm whether this file restore activity by the user is authorized. Thank you."]);
  } else if (alertKey.includes("outbound destination country")) {
    body = lines(["Source IP", get("srcip"), "", "Destination IP", get("dstip"), "", "Source Port", get("srcport"), "", "Destination Port", get("dstport"), "", "Destination Host", get("dstip_host"), "", "Destination Country", getGeo("dstip"), "", "Can you please confirm if this new outbound connection is expected and legitimate for this host?"]);
  } else if (alertKey.includes("outbytes anomaly")) {
    body = lines(["Source IP", get("srcip", "srcip_host"), "", "Destination Host", get("dstip_host"), "", "Actual", get("actual"), "", "Typical", get("typical"), "", "Please verify if this outbound data transfer is part of your operations as of this moment or not. Thank you!"]);
  } else if (alertKey.includes("private to public exploit")) {
    const idsSignature = get("ids_signature", "ids_name") !== "N/A" ? get("ids_signature", "ids_name") : getNested("ids.signature");
    body = lines(["IDS Signature", idsSignature, "", "Source IP", get("srcip", "srcip_host"), "", "Destination IP", get("dstip", "dstip_host"), "", "Source Port", get("srcport"), "", "Destination Port", get("dstport"), "", "Please confirm if this communication is expected and authorized for your systems."]);
  } else if (alertKey.includes("public to private exploit")) {
    const idsSignature = get("ids_signature", "ids_name") !== "N/A" ? get("ids_signature", "ids_name") : getNested("ids.signature");
    const dstHost = get("dstip_host");
    const dstIp   = get("dstip");
    const dstLine = dstHost !== "N/A" && dstIp !== "N/A" && dstHost !== dstIp ? lines(["Destination Host", dstHost, "", "Destination IP", dstIp]) : dstHost !== "N/A" ? lines(["Destination Host", dstHost]) : lines(["Destination IP", dstIp]);
    body = lines(["IDS Signature", idsSignature, "", "Source IP", `${get("srcip_host")} (malicious)`, "", dstLine, "", "Source Port", get("srcport"), "", "Destination Port", get("dstport"), "", "Please confirm if this communication is expected and authorized for your systems as it is associated with a malicious IP. Thank you."]);
  } else if (alertKey.includes("scanner reputation")) {
    body = lines(["Source IP", `${get("srcip", "srcip_host", "host_ip", "IP/name", "ip")} (Malicious)`, "", "Source Country", getGeo("srcip"), "", "Event Source", get("event_source"), "", "action", get("action"), "", "Please verify the source IP if related to your operations, as it was flagged malicious by security vendors. Thank you!"]);
  } else if (alertKey.includes("sensitive windows active directory") || alertKey.includes("active directory attribute")) {
    body = lines(["Host IP", get("srcip_host"), "", "Host Name", get("engid_name", "device_name"), "", "Event Outcome", get("event_outcome", "state"), "", "Please confirm whether this Active Directory attribute modification was an authorized and expected activity. Thank you."]);
  } else if (alertKey.includes("sensor status")) {
    const EXPECTED_AFTER_HOURS: Record<string, number> = { "belmont": 17, "siycha": 21 };
    const NOT_EXPECTED_SENSORS = ["modular", "stellarmodularsensor", "awsmds", "mds"];
    const phHour    = (new Date(rawTs ?? Date.now()).getUTCHours() + 8) % 24;
    const tenantKey = (d.tenant_name ?? "").toLowerCase();
    const sensorName = get("engid_name", "sensor_name");
    const sensorKey  = sensorName.toLowerCase();
    const sensorId   = get("engid", "sensor_id");
    const afterHourThreshold = Object.entries(EXPECTED_AFTER_HOURS).find(([k]) => tenantKey.includes(k))?.[1];
    const isAfterHours    = afterHourThreshold !== undefined && phHour >= afterHourThreshold;
    const isNeverExpected = NOT_EXPECTED_SENSORS.some(s => sensorKey.includes(s));
    if (isAfterHours && !isNeverExpected) {
      body = lines(["Sensor ID", sensorId, "", "Sensor", sensorName, "", "This sensor disconnection is within the expected after-hours window for this tenant.", "", "Remarks: Normal Behavior"]);
    } else if (isNeverExpected) {
      body = lines(["Sensor ID", sensorId, "", "Sensor", sensorName, "", "⚠ This sensor is not expected to disconnect at any time. Please investigate immediately and confirm if this disconnection is authorized. Thank you."]);
    } else {
      body = lines(["Sensor ID", sensorId, "", "Sensor", sensorName, "", "Please verify if this disconnection is expected to happen at this time. Thank you."]);
    }
  } else if (alertKey.includes("suspicious lsass")) {
    body = lines(["Source IP", get("srcip_host"), "", "Source Host", get("srcip_host"), "", "Can you confirm that the process accessing LSASS on this source host was an authorized and expected action?"]);
  } else if (alertKey.includes("uncommon application")) {
    body = lines(["Source IP", get("srcip_host"), "", "Destination IP", get("dstip"), "", "App", get("appid_name", "proto_name"), "", "Days Silent", get("days_silent"), "", "Please verify if this app is part of your operations. Thank you."]);
  } else if (alertKey.includes("command & control reputation") || alertKey.includes("command and control reputation")) {
    body = lines(["Source IP", get("srcip_host"), "", "Destination IP", get("dstip"), "", "Destination Host", get("dstip_host", "dstip"), "", "Destination Reputation", get("dstip_reputation"), "", "App", get("appid_name", "proto_name"), "", "We detected repeated outbound connections to a destination classified as command-and-control. Please confirm if this activity is expected or legitimate. Thank you!"]);
  } else if (alertKey.includes("rdp suspicious logon")) {
    body = lines(["Host IP", get("hostip"), "", "Host Name", get("host.name", "engid_name", "computer_name"),"","Source IP", get("srcip"), "", "Destination IP", get("dstip"), "", "Target Domain Name",  getNested("event_data.TargetDomainName"), "", "Target Username", getNested("event_data.TargetUserName"),"", "Please confirm if this logon is expected or part of any scheduled task, maintenance activity, or legitimate administrative process. Thanks!"]);
  } else if (alertKey.includes("emerging threat")) {
    body = lines(["Source IP", get("srcip"), "", "Destination IP", get("dstip"), "", "Destination Host", get("dstip_host"), "", "Action", get("action"), "", "Destination Reputation", get("dstip_reputation"), "", "Please confirm whether this activity is expected. Thank you."]);
  } else if (alertKey.includes("uncommon file access")) {
    body = lines(["Windows Organization ID", getNested("office365.OrganizationId"), "", "User ID", getNested("office365.UserId"), "", "Object ID", getNested("office365.ObjectId"), "", "Please verify if this account is authorized to make changes to the 365 Sharing Policy. Thank you!"]);
  } else if (alertKey.includes("bad destination reputation")) {
    body = lines(["Source IP", get("srcip"), "", "Destination Host", get("dstip_host"), "", "Destination Reputation", getNested("dstip_reputation"), "", "App", get("appid_name"), "", "Please confirm if this traffic is expected or part of any authorized activity on your network. Thanks!"]);
  } else if (alertKey.includes("uncommon process")) {
    body = lines(["Host IP", getNested("host.ip"), "", "Host Name", get("engid_name", "device_name"), "", "Process Name", get("process_name"), "", "User Name", get("srcip_username"), "", "Days Silent", get("days_silent"), "", "Event Outcome", getNested("event.outcome"), "", `Can you confirm whether the execution of ${get("process_name")} was an authorized and expected activity?`]);
  } else if (alertKey.includes("user asset access")) {
    body = lines(["Source Host", get("srcip_host"), "", "Target Username", get("smb_username", "srcip_username", "target_username"), "", "Event Data Servicename", getNested("event_data.ServiceName"), "", "Child Count", get("child_count"), "", "We observed an unusual asset access activity. Can you confirm this activity is expected and authorized?"]);
  } else if (alertKey.includes("user login location")) {
    body = lines(["Source Username", get("srcip_username"), "", "Source IP", get("srcip_host"), "", "Source Country", getGeo("srcip"), "", "Login Result", get("login_result", "action"), "", "Please confirm if this login from an unusual location is expected and authorized. Thank you."]);
  } else if (alertKey.includes("long app session")) {
    body = lines(["Source IP", get("srcip"), "", "Destination IP", get("dstip"), "", "Source Port", get("srcport"), "", "Destination Port", get("dstport"), "", "App", get("appid_name", "proto_name"), "", "Please confirm if this activity is done in your end, thank you"]);
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
    if (isMalicious) { return { caseStatus: "Waiting for Status", verification: "True Positive", remediation: "Not Remediated", remarkKey: "malicious-not-found" }; }
    return { caseStatus: "Resolved", verification: "False Positive", remediation: "Remediated", remarkKey: "already-blocked" };
  }
  if (verdict === "true-positive") { return { caseStatus: "Waiting for Status", verification: "True Positive", remediation: "Not Remediated", remarkKey: "malicious-not-found" }; }
  if (isMalicious) { return { caseStatus: "Waiting for Status", verification: "True Positive", remediation: "Not Remediated", remarkKey: "malicious-not-found" }; }
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
    <span style={{ ...map[variant], display: "inline-flex", alignItems: "center", fontFamily: "'JetBrains Mono', 'Fira Code', monospace", fontSize: 11.5, fontWeight: 500, letterSpacing: "0.03em", padding: "5px 13px", borderRadius: 6, whiteSpace: "nowrap" as const }}>
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
    <div style={{ display: "flex", flexDirection: "column" as const, gap: 6 }}>
      <span style={s.aegisColLabel}>{label}</span>
      <select
        value={value}
        onChange={e => onChange(e.target.value as T)}
        style={{ fontFamily: "'JetBrains Mono', 'Fira Code', monospace", fontSize: 12, fontWeight: 500, letterSpacing: "0.02em", padding: "8px 16px", borderRadius: 8, border: `1px solid ${c.border}`, background: c.bg, color: c.color, cursor: "pointer", outline: "none", appearance: "none" as const, WebkitAppearance: "none" as const, minWidth: 180, backdropFilter: "blur(8px)" }}
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
      : alertKey.includes("outbound destination country") || alertKey.includes("uncommon application") || alertKey.includes("encrypted phishing") || alertKey.includes("external smb read") || alertKey.includes("command & control reputation") || alertKey.includes("command and control reputation") || alertKey.includes("private to public exploit") || alertKey.includes("external protocol account login failure")
      ? (data.dstip ?? data.dstip_host ?? null)
      : (data.srcip ?? data.srcip_host ?? data.host_ip ?? data["IP/name"] ?? data.ip ?? null);

    const isPrivateOrHostname = (val: string) =>
      /^10\./i.test(val) || /^172\.(1[6-9]|2\d|3[01])\./i.test(val) || /^192\.168\./i.test(val) || /^127\./i.test(val) || !/^\d{1,3}(\.\d{1,3}){3}$/.test(val);

    if (ip && !isPrivateOrHostname(ip)) {
      setVtIp(ip); setVtResult(null); setVtLoading(true); setShowAegis(false);
      fetch(`/api/virustotal?ip=${encodeURIComponent(ip)}`)
        .then(r => r.json())
        .then((vt: VTResult) => {
          if (vt.error && typeof vt.error !== "string") vt.error = String(vt.error);
          setVtResult(vt);
          setVtLoading(false);
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

       {/* Background */}
  <SecurityBackground />


      {/* Top navigation bar */}
      <nav style={s.navbar}>
        <div style={s.navLeft}>
          <div style={s.navLogo}>
            <svg width="18" height="18" viewBox="0 0 24 24" fill="none">
              <path d="M12 2L2 7l10 5 10-5-10-5zM2 17l10 5 10-5M2 12l10 5 10-5" stroke="#38bdf8" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"/>
            </svg>
          </div>
          <span style={s.navTitle}>Alert Analyzer</span>
          <div style={s.navDivider} />
          <span style={s.navSub}>Stellar Cyber · SOC Operations</span>
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
            <svg width="13" height="13" viewBox="0 0 24 24" fill="none" style={{ marginRight: 6 }}>
              <path d="M9 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h4M16 17l5-5-5-5M21 12H9" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"/>
            </svg>
            Logout
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
              <div>
                <div style={{ ...s.sendToLabel, color: "rgba(245,158,11,0.6)" }}>NO ACTION REQUIRED</div>
                <div style={{ ...s.sendToValue, color: "#fbbf24" }}>{sendTo}{projectName && ` · ${projectName}`} — Action already {caseAnalysis?.detectionResult}</div>
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
  }}
 onClick={() => {
  if (tenantLower.includes("belmont")) {
    navigator.clipboard.writeText(output);
    window.open("whatsapp://?t=" + Date.now(), "_blank");
    showToast("✓ Copied & Opening WhatsApp...");
  } else {
    navigator.clipboard.writeText(output);
    window.open("viber://forward?number=0&t=" + Date.now(), "_blank");
    showToast("✓ Copied & Opening Viber...");
  }
}}
  onMouseEnter={e => {
    const tip = (e.currentTarget as HTMLElement).querySelector(".tip") as HTMLElement;
    if (tip) { tip.style.opacity = "1"; tip.style.transform = "translateX(-50%) translateY(0px)"; }
  }}
  onMouseLeave={e => {
    const tip = (e.currentTarget as HTMLElement).querySelector(".tip") as HTMLElement;
    if (tip) { tip.style.opacity = "0"; tip.style.transform = "translateX(-50%) translateY(4px)"; }
  }}
>
  <div className="tip" style={{
    position: "absolute" as const,
    bottom: "calc(100% + 12px)",
    left: "50%",
    transform: "translateX(-50%) translateY(4px)",
    background: "rgba(6, 13, 27, 0.95)",
    backdropFilter: "blur(16px)",
    border: `1px solid ${tenantLower.includes("belmont") ? "rgba(37,211,102,0.5)" : "rgba(126,85,196,0.5)"}`,
    borderRadius: 10,
    padding: "8px 16px",
    fontSize: 12,
    fontWeight: 600,
    letterSpacing: "0.05em",
    color: tenantLower.includes("belmont") ? "#25d366" : "#a78bfa",
    whiteSpace: "nowrap" as const,
    opacity: 0,
    transition: "all 0.2s cubic-bezier(0.34, 1.56, 0.64, 1)",
    pointerEvents: "none" as const,
    zIndex: 100,
    boxShadow: `0 8px 24px rgba(0,0,0,0.4), 0 0 0 1px ${tenantLower.includes("belmont") ? "rgba(37,211,102,0.1)" : "rgba(126,85,196,0.1)"} inset`,
  }}>
    {tenantLower.includes("belmont") ? "Open WhatsApp" : "Open Viber"}
    <div style={{
      position: "absolute" as const,
      top: "100%", left: "50%",
      transform: "translateX(-50%)",
      width: 0, height: 0,
      borderLeft: "6px solid transparent",
      borderRight: "6px solid transparent",
      borderTop: `6px solid ${tenantLower.includes("belmont") ? "rgba(37,211,102,0.5)" : "rgba(126,85,196,0.5)"}`,
    }} />
  </div>
  <svg width="18" height="18" viewBox="0 0 24 24" fill="none">
    <path d="M22 2L11 13" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"/>
    <path d="M22 2L15 22L11 13L2 9L22 2Z" fill="currentColor" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" opacity="0.8"/>
    <path d="M22 2L11 13V20L14.5 16.5" fill="currentColor" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round" opacity="0.4"/>
  </svg>
</div>
              <div>
                <div style={s.sendToLabel}>SEND TO</div>
                <div style={s.sendToValue}>
                  {sendTo}
                  {projectName && <span style={s.projectBadge}>{projectName}</span>}
                </div>
              </div>
            </div>
          )
        )}

        {/* Input card */}
        <Card label="JSON Input" icon="⌨" subtitle="Paste your raw alert JSON">
          <textarea style={s.textarea} value={jsonInput} onChange={(e: ChangeEvent<HTMLTextAreaElement>) => setJsonInput(e.target.value)} placeholder={`Paste your alert JSON here…\n\nExample:\n${SAMPLE_JSON}`} />
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
          <Row><Btn green onClick={copyMsg}><svg width="13" height="13" viewBox="0 0 24 24" fill="none" style={{ marginRight: 7 }}><rect x="9" y="9" width="13" height="13" rx="2" stroke="currentColor" strokeWidth="2"/><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1" stroke="currentColor" strokeWidth="2"/></svg>Copy Notification</Btn></Row>
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
              <textarea style={{ ...s.textarea, minHeight: 280 }} value={followUp} onChange={(e: ChangeEvent<HTMLTextAreaElement>) => setFollowUp(e.target.value)} placeholder="Follow-up details will appear here…" />
              <Row><Btn green onClick={copyFollowUp}><svg width="13" height="13" viewBox="0 0 24 24" fill="none" style={{ marginRight: 7 }}><rect x="9" y="9" width="13" height="13" rx="2" stroke="currentColor" strokeWidth="2"/><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1" stroke="currentColor" strokeWidth="2"/></svg>Copy Follow-up</Btn></Row>
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
                    ...(row.mono ? { fontFamily: "'JetBrains Mono', monospace", fontSize: 12 } : {}),
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
              <AegisDropdown label="Case Status"   value={aegisCaseStatus}   options={["Waiting for Status","Resolved","Whitelisted","Confirmed"]}     onChange={setAegisCaseStatus}   colorMap={caseStatusColors}   />
              <AegisDropdown label="Verification"  value={aegisVerification}  options={["To Be Confirmed","True Positive","False Positive"]}             onChange={setAegisVerification}  colorMap={verificationColors}  />
              <AegisDropdown label="Remediation"   value={aegisRemediation}   options={["Remediated","Not Remediated"]}                                  onChange={setAegisRemediation}   colorMap={remediationColors}   />
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
                  <Btn green onClick={copyRemark}><svg width="13" height="13" viewBox="0 0 24 24" fill="none" style={{ marginRight: 7 }}><rect x="9" y="9" width="13" height="13" rx="2" stroke="currentColor" strokeWidth="2"/><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1" stroke="currentColor" strokeWidth="2"/></svg>Copy Remark</Btn>
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
        * { box-sizing: border-box; margin: 0; padding: 0; }
        ::selection { background: rgba(56,189,248,0.2); color: #38bdf8; }
        ::-webkit-scrollbar { width: 5px; }
        ::-webkit-scrollbar-track { background: rgba(15,23,42,0.5); }
        ::-webkit-scrollbar-thumb { background: rgba(56,189,248,0.2); border-radius: 3px; }
        ::-webkit-scrollbar-thumb:hover { background: rgba(56,189,248,0.35); }
        textarea { caret-color: #38bdf8; }
        textarea:focus { outline: none !important; border-color: rgba(56,189,248,0.4) !important; box-shadow: 0 0 0 3px rgba(56,189,248,0.08) !important; }
        select option { background: #0f172a !important; color: #e2e8f0 !important; }
        button { transition: all 0.18s ease !important; }
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
          <div>
            <div style={s.label}>{label}</div>
            {subtitle && <div style={s.cardSubtitle}>{subtitle}</div>}
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
  return <button style={{ ...s.btn, ...extra }} onClick={onClick}>{children}</button>;
}

// ── Styles ────────────────────────────────────────────────────────────────────

const s: Record<string, CSSProperties> = {
  // Root & Background
  root:       { fontFamily: "'Inter', sans-serif", minHeight: "100vh", position: "relative", overflow: "hidden", background: "#060d1b" },

  // Navbar
  navbar:       { position: "fixed", top: 0, left: 0, right: 0, zIndex: 100, height: 56, display: "flex", alignItems: "center", justifyContent: "space-between", padding: "0 24px", background: "rgba(6,13,27,0.8)", backdropFilter: "blur(20px)", borderBottom: "1px solid rgba(56,189,248,0.08)" },
  navLeft:      { display: "flex", alignItems: "center", gap: 12 },
  navLogo:      { width: 32, height: 32, borderRadius: 8, background: "rgba(56,189,248,0.1)", border: "1px solid rgba(56,189,248,0.2)", display: "flex", alignItems: "center", justifyContent: "center" },
  navTitle:     { fontFamily: "'Inter', sans-serif", fontSize: 14, fontWeight: 600, color: "#f1f5f9", letterSpacing: "-0.01em" },
  navDivider:   { width: 1, height: 16, background: "rgba(148,163,184,0.15)", margin: "0 4px" },
  navSub:       { fontSize: 11.5, color: "rgba(148,163,184,0.45)", letterSpacing: "0.02em" },
  navRight:     { display: "flex", alignItems: "center", gap: 12 },
  navStatus:    { display: "flex", alignItems: "center", gap: 6, padding: "4px 10px", borderRadius: 20, background: "rgba(16,185,129,0.08)", border: "1px solid rgba(16,185,129,0.2)" },
  navStatusDot: { width: 6, height: 6, borderRadius: "50%", background: "#34d399", animation: "pulse 2s ease-in-out infinite" },
  navStatusText:{ fontSize: 10, fontWeight: 600, color: "#34d399", letterSpacing: "0.1em" },
  logoutBtn:    { fontFamily: "'Inter', sans-serif", fontSize: 12, fontWeight: 500, padding: "6px 14px", borderRadius: 7, cursor: "pointer", background: "transparent", color: "rgba(239,68,68,0.6)", border: "1px solid rgba(239,68,68,0.2)", display: "flex", alignItems: "center", letterSpacing: "0.01em" },

  // Content
  content:    { position: "relative", zIndex: 10, maxWidth: 860, margin: "0 auto", padding: "88px 24px 80px" },

  // Page header
  pageHeader: { marginBottom: 32, animation: "fadeUp 0.6s ease both" },
  headerBadge:{ display: "inline-block", fontSize: 10, fontWeight: 600, letterSpacing: "0.12em", color: "#38bdf8", background: "rgba(56,189,248,0.1)", border: "1px solid rgba(56,189,248,0.2)", padding: "4px 12px", borderRadius: 20, marginBottom: 14 },
  h1:         { fontSize: 30, fontWeight: 700, color: "#f1f5f9", letterSpacing: "-0.03em", lineHeight: 1.2, marginBottom: 10 },
  h1Accent:   { color: "#38bdf8" },
  h1Sub:      { fontSize: 14, color: "rgba(148,163,184,0.6)", lineHeight: 1.6, fontWeight: 400 },

  // Send to banner
  sendToBanner: { display: "flex", alignItems: "center", gap: 14, background: "rgba(56,189,248,0.05)", border: "1px solid rgba(56,189,248,0.15)", borderLeft: "3px solid rgba(56,189,248,0.5)", borderRadius: 10, padding: "14px 18px", marginBottom: 16, animation: "fadeUp 0.4s ease both" },
sendToIcon: { 
  width: 34, height: 34, borderRadius: 8, 
  background: "rgba(56,189,248,0.1)", 
  color: "#38bdf8",                    
  display: "flex", alignItems: "center", 
  justifyContent: "center", flexShrink: 0 
},
  sendToLabel:  { fontSize: 10, fontWeight: 600, letterSpacing: "0.1em", color: "rgba(56,189,248,0.5)", marginBottom: 3 },
  sendToValue:  { fontSize: 13.5, fontWeight: 600, color: "#38bdf8", letterSpacing: "-0.01em" },
  projectBadge: { marginLeft: 10, fontSize: 11, fontWeight: 500, color: "#fbbf24", background: "rgba(245,158,11,0.1)", border: "1px solid rgba(245,158,11,0.25)", padding: "2px 10px", borderRadius: 20 },

  // Cards
  card:           { background: "rgba(10,18,38,0.75)", backdropFilter: "blur(20px)", border: "1px solid rgba(56,189,248,0.08)", borderRadius: 14, marginBottom: 14, overflow: "hidden", boxShadow: "0 4px 32px rgba(0,0,0,0.35), 0 1px 0 rgba(56,189,248,0.05) inset", animation: "fadeUp 0.5s ease both" },
  cardHeader:     { display: "flex", alignItems: "center", justifyContent: "space-between", padding: "16px 20px 0" },
  cardHeaderLeft: { display: "flex", alignItems: "flex-start", gap: 12 },
  cardIcon:       { fontSize: 16, marginTop: 1 },
  label:          { fontSize: 12, fontWeight: 600, letterSpacing: "0.04em", color: "rgba(148,163,184,0.7)", textTransform: "uppercase" as const },
  cardSubtitle:   { fontSize: 11.5, color: "rgba(100,116,139,0.6)", marginTop: 2, fontWeight: 400 },
  cardBody:       { padding: "14px 20px 20px" },

  // Textarea
  textarea:   { width: "100%", minHeight: 160, fontFamily: "'JetBrains Mono', monospace", fontSize: 12.5, lineHeight: 1.85, color: "#e2e8f0", background: "rgba(2,8,23,0.6)", border: "1px solid rgba(56,189,248,0.1)", borderRadius: 10, padding: "14px 16px", resize: "vertical" as const, transition: "all 0.2s" },

  // Buttons
  btnRow: { display: "flex", gap: 10, marginTop: 14, flexWrap: "wrap" as const },
  btn:    { fontFamily: "'Inter', sans-serif", fontSize: 12.5, fontWeight: 500, letterSpacing: "0.01em", padding: "9px 18px", borderRadius: 8, border: "1px solid", cursor: "pointer", display: "flex", alignItems: "center" },

  // Pills
  pillRow:     { display: "flex", flexWrap: "wrap" as const, gap: 8, padding: "6px 0", alignItems: "center" },
  loadingRow:  { display: "flex", alignItems: "center", gap: 8, padding: "4px 0" },
  loadingText: { fontSize: 12, color: "rgba(148,163,184,0.5)", fontFamily: "'JetBrains Mono', monospace" },
  dot:         { display: "inline-block", width: 7, height: 7, borderRadius: "50%", background: "#38bdf8", animation: "blink 1.2s ease-in-out infinite", boxShadow: "0 0 8px rgba(56,189,248,0.6)" },

  // No template
  noTemplateBanner: { display: "flex", alignItems: "flex-start", gap: 10, background: "rgba(245,158,11,0.06)", border: "1px solid rgba(245,158,11,0.2)", borderLeft: "3px solid rgba(245,158,11,0.5)", borderRadius: 10, padding: "14px 16px", fontSize: 13, color: "#fbbf24", lineHeight: 1.6, fontFamily: "'Inter', sans-serif" },

  // Analysis grid
  analysisGrid:  { border: "1px solid rgba(56,189,248,0.08)", borderRadius: 10, overflow: "hidden" },
  analysisRow:   { display: "flex", justifyContent: "space-between", alignItems: "center", gap: 16, padding: "11px 16px", borderBottom: "1px solid rgba(56,189,248,0.05)", background: "rgba(2,8,23,0.3)" },
  analysisLabel: { fontSize: 11, fontWeight: 500, letterSpacing: "0.08em", textTransform: "uppercase" as const, color: "rgba(100,116,139,0.7)", flexShrink: 0 },
  analysisValue: { fontFamily: "'JetBrains Mono', monospace", fontSize: 12.5, color: "rgba(226,232,240,0.85)", textAlign: "right" as const },

  // Aegis
  aegisDropdownRow: { display: "flex", gap: 18, flexWrap: "wrap" as const, alignItems: "flex-end" },
  aegisColLabel:    { fontFamily: "'Inter', sans-serif", fontSize: 10.5, fontWeight: 600, letterSpacing: "0.08em", textTransform: "uppercase" as const, color: "rgba(100,116,139,0.7)", display: "block", marginBottom: 6 },
  aegisDivider:     { borderTop: "1px solid rgba(56,189,248,0.07)", margin: "20px 0" },
  remarkSection:    { display: "flex", flexDirection: "column" as const, gap: 12 },
  remarkBtnRow:     { display: "flex", flexWrap: "wrap" as const, gap: 8 },
  remarkBtn:        { fontFamily: "'Inter', sans-serif", fontSize: 11.5, fontWeight: 500, padding: "7px 14px", borderRadius: 8, cursor: "pointer", border: "1px solid rgba(56,189,248,0.1)", background: "rgba(56,189,248,0.03)", color: "rgba(148,163,184,0.5)", letterSpacing: "0.01em" },
  remarkBtnActive:  { background: "rgba(56,189,248,0.1)", color: "#38bdf8", border: "1px solid rgba(56,189,248,0.3)", boxShadow: "0 0 14px rgba(56,189,248,0.1)" },
  toggleBtn:        { fontFamily: "'Inter', sans-serif", fontSize: 12, fontWeight: 500, padding: "8px 16px", borderRadius: 8, cursor: "pointer", border: "1px solid rgba(56,189,248,0.12)", background: "transparent", color: "rgba(148,163,184,0.5)" },
  toggleBtnOn:      { background: "rgba(56,189,248,0.1)", color: "#38bdf8", border: "1px solid rgba(56,189,248,0.3)" },
  remarkPreview:    { background: "rgba(2,8,23,0.5)", border: "1px solid rgba(56,189,248,0.1)", borderLeft: "3px solid rgba(56,189,248,0.3)", borderRadius: 10, padding: "16px 18px" },
  remarkPreviewMeta:{ marginBottom: 10 },
  remarkPreviewLabel:{ fontSize: 10.5, fontWeight: 600, letterSpacing: "0.08em", color: "rgba(100,116,139,0.6)", textTransform: "uppercase" as const },
  remarkText:       { fontFamily: "'JetBrains Mono', monospace", fontSize: 12.5, lineHeight: 1.85, color: "rgba(226,232,240,0.8)", marginTop: 6 },

  // Toast
  toast: { position: "fixed", bottom: 24, right: 24, background: "rgba(10,18,38,0.95)", backdropFilter: "blur(20px)", color: "#34d399", border: "1px solid rgba(16,185,129,0.3)", boxShadow: "0 8px 32px rgba(0,0,0,0.4), 0 0 0 1px rgba(16,185,129,0.1)", borderRadius: 10, padding: "11px 20px", fontFamily: "'Inter', sans-serif", fontSize: 13, fontWeight: 500, letterSpacing: "0.01em", transition: "all 0.25s ease", pointerEvents: "none" as const, zIndex: 200 },
};