"use client";

import { useState, useRef, useEffect, CSSProperties, ReactNode, ChangeEvent } from "react";

// ── Types ─────────────────────────────────────────────────────────────────────

interface XdrEvent {
  display_name?: string;
  description?: string;
}

interface AlertData {
  xdr_event?: XdrEvent;
  tenant_name?: string;
  action?: string;
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
}

// ── Plasma WebGL Background ───────────────────────────────────────────────────

const VERT_SRC = `#version 300 es
in vec2 position;
void main() {
  gl_Position = vec4(position, 0.0, 1.0);
}`;

// spell-checker: disable
const FRAG_SRC = `#version 300 es
precision highp float;
uniform vec2  iResolution;
uniform float iTime;
uniform float uSpeed;
uniform float uOpacity;
uniform vec2  uMouse;
out vec4 fragColor;

bool finite1(float x) { return !(isnan(x) || isinf(x)); }
vec3 sanitize(vec3 c) {
  return vec3(
    finite1(c.r) ? c.r : 0.0,
    finite1(c.g) ? c.g : 0.0,
    finite1(c.b) ? c.b : 0.0
  );
}

void main() {
  vec2 C = gl_FragCoord.xy;
  vec2 center = iResolution.xy * 0.5;
  vec2 mouseOffset = (uMouse - center) * 0.0002;
  C += mouseOffset * length(C - center);

  float T = iTime * uSpeed;
  float i = 0.0, d = 0.0, z = 0.0;
  vec3 O = vec3(0.0);

  for (int n = 0; n < 60; n++) {
    i += 1.0;
    vec2 r = iResolution.xy;
    vec3 p = z * normalize(vec3(C - 0.5 * r, r.y));
    p.z -= 4.0;
    vec3 S = p;
    d = p.y - T;
    p.x += 0.4 * (1.0 + p.y) * sin(d + p.x * 0.1) * cos(0.34 * d + p.x * 0.05);
    float cy = cos(p.y - T);
    float sy = sin(p.y - T);
    vec2 Q2 = mat2(cy, -sy, sy, cy) * p.xz;
    p.xz = Q2;
    float dl = abs(sqrt(dot(Q2, Q2)) - 0.25 * (5.0 + S.y)) / 3.0 + 8e-4;
    z += dl;
    d = dl;
    vec4 o2 = 1.0 + sin(S.y + p.z * 0.5 + S.z - length(S - p) + vec4(2.0, 1.0, 0.0, 8.0));
    O += o2.w / d * o2.xyz;
  }

  vec3 rgb = sanitize(tanh(O / 1e4));
  fragColor = vec4(rgb, uOpacity);
}`;
// spell-checker: enable

function PlasmaCanvas({ speed = 0.6, opacity = 0.82 }: { speed?: number; opacity?: number }) {
  const canvasRef = useRef<HTMLCanvasElement>(null);
  const mouseRef  = useRef<[number, number]>([0, 0]);
  const rafRef    = useRef<number>(0);

  useEffect(() => {
    const canvas = canvasRef.current;
    if (!canvas) return;
    const gl = canvas.getContext("webgl2", { alpha: true, antialias: false }) as WebGL2RenderingContext | null;
    if (!gl) return;

    const compile = (type: number, src: string) => {
      const s = gl.createShader(type)!;
      gl.shaderSource(s, src);
      gl.compileShader(s);
      return s;
    };
    const prog = gl.createProgram()!;
    gl.attachShader(prog, compile(gl.VERTEX_SHADER, VERT_SRC));
    gl.attachShader(prog, compile(gl.FRAGMENT_SHADER, FRAG_SRC));
    gl.linkProgram(prog);
    gl.useProgram(prog);

    const buf = gl.createBuffer();
    gl.bindBuffer(gl.ARRAY_BUFFER, buf);
    gl.bufferData(gl.ARRAY_BUFFER, new Float32Array([-1, -1, 3, -1, -1, 3]), gl.STATIC_DRAW);
    const posLoc = gl.getAttribLocation(prog, "position");
    gl.enableVertexAttribArray(posLoc);
    gl.vertexAttribPointer(posLoc, 2, gl.FLOAT, false, 0, 0);

    const uTime   = gl.getUniformLocation(prog, "iTime");
    const uRes    = gl.getUniformLocation(prog, "iResolution");
    const uSpeedU = gl.getUniformLocation(prog, "uSpeed");
    const uOpacU  = gl.getUniformLocation(prog, "uOpacity");
    const uMouseU = gl.getUniformLocation(prog, "uMouse");

    gl.uniform1f(uSpeedU, speed * 0.4);
    gl.uniform1f(uOpacU, opacity);

    const resize = () => {
      if (!canvasRef.current) return;
      const { width, height } = canvasRef.current.getBoundingClientRect();
      canvasRef.current.width  = Math.floor(width  * Math.min(devicePixelRatio, 2));
      canvasRef.current.height = Math.floor(height * Math.min(devicePixelRatio, 2));
      gl.viewport(0, 0, canvasRef.current.width, canvasRef.current.height);
      gl.uniform2f(uRes, canvasRef.current.width, canvasRef.current.height);
    };
    const ro = new ResizeObserver(resize);
    ro.observe(canvas);
    resize();

    const parent = canvas.parentElement;
    const onMove = (e: MouseEvent) => {
      if (!canvasRef.current) return;
      const r = canvasRef.current.getBoundingClientRect();
      const scaleX = canvasRef.current.width  / r.width;
      const scaleY = canvasRef.current.height / r.height;
      mouseRef.current = [
        (e.clientX - r.left) * scaleX,
        canvasRef.current.height - (e.clientY - r.top) * scaleY,
      ];
    };
    parent?.addEventListener("mousemove", onMove);

    const t0 = performance.now();
    const loop = (now: number) => {
      gl.uniform1f(uTime, (now - t0) * 0.001);
      gl.uniform2f(uMouseU, mouseRef.current[0], mouseRef.current[1]);
      gl.drawArrays(gl.TRIANGLES, 0, 3);
      rafRef.current = requestAnimationFrame(loop);
    };
    rafRef.current = requestAnimationFrame(loop);

    return () => {
      cancelAnimationFrame(rafRef.current);
      ro.disconnect();
      parent?.removeEventListener("mousemove", onMove);
    };
  }, [speed, opacity]);

  return (
    <canvas
      ref={canvasRef}
      style={{ position: "absolute", inset: 0, width: "100%", height: "100%", display: "block" }}
    />
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
    "Below are the other details for this alert.", "",
    timestamp, "",
  ]);

  let body = "";

  if (alertKey.includes("application usage")) {
    body = lines(["App", get("appid_name"), "", "App ID", get("appid"), "", "Actual", get("actual"), "", "Threshold", get("threshold", "typical"), "", "Source Host", get("srcip_host"), "", "Source Country", getGeo("srcip"), "", "Destination Host", get("dstip_host"), "", "Please verify if the app is part of your operations. Thank you."]);
  } else if (alertKey.includes("bad source reputation")) {
    body = lines(["Source IP", get("srcip_host"), "", "Action", get("action"), "", "Destination IP", get("dstip_host", "dstip"), "", "Could you please confirm if this is a recognized malicious source IP within your network or used by your team? Thank you."]);
  } else if (alertKey.includes("data ingestion")) {
    const device = obj.device as Record<string, unknown> | undefined;
    const sensorName = (device?.name as string) ?? get("sensor_name", "engid_name");
    body = lines(["Sensor", sensorName, "", "Please confirm if this activity is expected and authorized on your end. Thank you."]);
  } else if (alertKey.includes("eset protect")) {
    body = lines(["Host Name", get("device_name", "engid_name"), "", "Source IP", `${get("srcip_host")} (Malicious)`, "", "Destination IP", get("dstip_host", "dstip"), "", "Source Port", get("srcport"), "", "Destination Port", get("dstport"), "", "Please verify if the source IP is related to your operations. If not, we suggest blocking the IP on your end and informing us, as it was flagged as malicious by security vendors."]);
  } else if (alertKey.includes("exploited c") || alertKey.includes("c&c")) {
    body = lines(["Source IP", `${get("srcip_host")} (Malicious)`, "", "Source Host", get("srcip_host"), "", "Source Port", get("srcport"), "", "Destination IP", get("dstip_host", "dstip"), "", "Destination Host", get("dstip_host", "dstip"), "", "Destination Port", get("dstport"), "", "Please confirm if this communication is expected and authorized for your systems. Thank you."]);
  } else if (alertKey.includes("external account login failure")) {
    body = lines(["Source Username", get("srcip_username"), "", "Source User ID", get("srcip_usersid"), "", "Source IP", get("srcip_host"), "", "Login Type", get("login_type", "proto_name"), "", "Total Number Failed", get("actual", "count"), "", "Please confirm if these login attempts are expected or part of any authorized activity?"]);
  } else if (alertKey.includes("external firewall denial")) {
    body = lines(["Source IP", get("srcip_host"), "", "Destination IP", get("dstip_host", "dstip"), "", "Action", get("action"), "", "Please verify the source IP if related to your operations, Thank you!"]);
  } else if (alertKey.includes("external handshake failure")) {
    body = lines(["Source IP", get("srcip_host"), "", "Destination IP", get("dstip_host", "dstip"), "", "Please confirm if this connection attempt is expected, or if any of this source IP should not be communicating with your public servers."]);
  } else if (alertKey.includes("external ip") || alertKey.includes("external ip / port scan")) {
    body = lines(["Source IP", get("srcip_host"), "", "Destination IP", get("dstip_host", "dstip"), "", "App", get("appid_name", "proto_name"), "", "We detected that your internal host generated multiple failed outbound connection attempts to external IPs across several ports within a short period. This activity triggered a port scan anomaly due to its scanning-like pattern. Please confirm if this behavior is expected on your end. Thank you!"]);
  } else if (alertKey.includes("external pua")) {
    body = lines(["IDS Signature", get("ids_signature", "ids_name"), "", "Source Host", get("srcip_host"), "", "Destination IP", get("dstip_host", "dstip"), "", "Destination Host", get("dstip_host"), "", "IDS Action", get("action", "ids_action"), "", "Could you confirm if this is expected on your end? Thank you."]);
  } else if (alertKey.includes("external scanner behavior")) {
    const src = get("srcip_host"), dst = get("dstip_host", "dstip");
    body = lines(["Source Host", src, "", "Destination IP", dst, "", "IDS Action", get("action", "ids_action"), "", "Source Port", get("srcport"), "", "Destination Port", get("dstport"), "", `Unusual traffic detected from ${src} to ${dst}. Please confirm that the external scanning activity is expected and part of your operations right now. Thank you!`]);
  } else if (alertKey.includes("external user login failure")) {
    const srcIp = get("srcip_host");
    body = lines(["Source IP", srcIp, "", "Total Fail Percentage", get("failure_percent", "actual") !== "N/A" ? `${get("failure_percent", "actual")}%` : "N/A", "", `Kindly confirm whether the repeated VPN login failures from external IP ${srcIp} (Fortinet FortiGate) are expected or unauthorized.`]);
  } else if (alertKey.includes("impossible travel")) {
    body = lines(["Source User ID", get("srcip_usersid", "user_id"), "", "Source IP", get("srcip_host"), "", "Source IP 2", get("srcip2", "src_ip2"), "", "Source Country", getGeo("srcip"), "", "Distance Deviation (Miles)", get("distance_deviation", "dist_deviation"), "", "The following source IP for this specific alert is not on the whitelisted list. May we confirm if this activity is expected on your end?"]);
  } else if (alertKey.includes("internal credential stuffing")) {
    body = lines(["Source IP", get("srcip_host"), "", "Destination IP", get("dstip_host", "dstip"), "", "Host Name", get("engid_name", "device_name"), "", "Source Username", get("srcip_username"), "", "Please verify this activity involving the user. Thank you."]);
  } else if (alertKey.includes("internal firewall denial")) {
    body = lines(["Source IP", get("srcip_host"), "", "Source Port", get("srcport"), "", "Destination IP", get("dstip_host", "dstip"), "", "Destination Port", get("dstport"), "", "Please verify if the Source IP is authorized or used on your operations."]);
  } else if (alertKey.includes("internal handshake failure")) {
    body = lines(["Source IP", get("srcip_host"), "", "Source Host", get("srcip_host"), "", "Destination IP", get("dstip_host", "dstip"), "", "Destination Host", get("dstip_host", "dstip"), "", "Please confirm if this is expected. Thank you."]);
  } else if (alertKey.includes("internal ip") || alertKey.includes("internal ip / port scan")) {
    body = lines(["Source IP", get("srcip_host"), "", "Source Port", get("srcport"), "", "Destination IP", get("dstip_host", "dstip"), "", "Destination Host", get("dstip_host", "dstip"), "", "Destination Port", get("dstport"), "", "Can you confirm that the internal host performing a block port scan across your internal subnets was an authorized activity?"]);
  } else if (alertKey.includes("internal non-standard port") || alertKey.includes("non-standard port")) {
    body = lines(["Source IP", get("srcip_host"), "", "Source Host", get("srcip_host"), "", "Source Port", get("srcport"), "", "Destination IP", get("dstip_host", "dstip"), "", "Destination Host", get("dstip_host", "dstip"), "", "Destination Port", get("dstport"), "", `Can you confirm whether the traffic from ${get("srcip_host")} to the internal host ${get("dstip_host", "dstip")} on non-standard port ${get("dstport")} is an expected and authorized activity?`]);
  } else if (alertKey.includes("plain text password")) {
    body = lines(["Source IP", get("srcip_host"), "", "Destination IP", get("dstip_host", "dstip"), "", "Destination Host", get("dstip_host"), "", "App", get("appid_name", "proto_name"), "", "Destination Port", get("dstport"), "", "Source Port", get("srcport"), "", "Please verify if this detection is expected and confirm whether the activity is legitimate. Thank you."]);
  } else if (alertKey.includes("internal protocol account login fail")) {
    body = lines(["Account Name", get("srcip_username", "account_name"), "", "Total Number Failed", get("actual", "total_failed"), "", "Total Number Successful", get("total_success", "total_successful"), "", "Login Type", get("login_type", "proto_name"), "", "Source Host", get("srcip_host"), "", "Source IP", get("srcip_host"), "", "Please confirm whether these SMB login failure attempts were initiated by a legitimate user activity or not. Thank you."]);
  } else if (alertKey.includes("internal protocol account login")) {
    body = lines(["Account Name", get("srcip_username", "account_name"), "", "Total Number Failed", get("actual", "total_failed"), "", "Total Number Successful", get("total_success", "total_successful"), "", "Login Type", get("login_type", "proto_name"), "", "Source Host", get("srcip_host"), "", "Source IP", get("srcip_host"), "", "Please confirm whether these SMB login attempts were initiated by a legitimate user activity or not. Thank you."]);
  } else if (alertKey.includes("internal scanner behavior")) {
    body = lines(["Source IP", get("srcip_host"), "", "Source Port", get("srcport"), "", "Destination IP", get("dstip_host", "dstip"), "", "Destination Host", get("dstip_host"), "", "Destination Port", get("dstport"), "", "Please confirm if it is expected. Thank you."]);
  } else if (alertKey.includes("internal smb read")) {
    body = lines(["Source IP", get("srcip_host"), "", "Source Host", get("srcip_host"), "", "Source Port", get("srcport"), "", "Destination IP", get("dstip_host", "dstip"), "", "Destination Host", get("dstip_host"), "", "Destination Port", get("dstport"), "", "May we confirm if this activity is expected or part of system operations? Thank you."]);
  } else if (alertKey.includes("internal smb write")) {
    body = lines(["Source Host", get("srcip_host"), "", "Destination Host", get("dstip_host", "dstip"), "", "Source Port", get("srcport"), "", "Destination Port", get("dstport"), "", "May we confirm if this activity is expected or part of system operations? Thank you."]);
  } else if (alertKey.includes("internal user login failure")) {
    body = lines(["Source Host", get("srcip_host"), "", "Destination IP", get("dstip_host", "dstip"), "", "Total Number Failed", get("actual", "count"), "", "Login Type", get("login_type", "proto_name"), "", "Please verify whether these SMB login failure attempts are part of legitimate user activity, thanks!"]);
  } else if (alertKey.includes("login attempt location count")) {
    const username = get("srcip_username");
    body = lines(["Source User ID", get("srcip_usersid", "user_id"), "", "Source Username", username, "", "Source IP", get("srcip_host"), "", "Actual Locations", get("actual"), "", "Typical Locations", get("typical"), "", `We detected multiple failed login attempts for the account ${username} originating from several geographically diverse locations within a short period. Please confirm whether these attempts are legitimate. Thank you!`]);
  } else if (alertKey.includes("login time anomaly")) {
    const desc = d.xdr_event?.description ?? "";
    const actualMatch  = desc.match(/abnormal time range\s+([\d:]+[-][\d:]+\s+UTC[+\-][\d:]+)/i);
    const typicalMatch = desc.match(/typical login time range:\s+([\d:]+[-][\d:]+\s+UTC[+\-][\d:]+)/i);
    const actualTimeRange  = get("login_time_range", "actual_time_range", "abnormal_time_range", "actual_range") !== "N/A" ? get("login_time_range", "actual_time_range", "abnormal_time_range", "actual_range") : actualMatch ? actualMatch[1] : get("actual");
    const typicalTimeRange = get("typical_time_range", "typical_login_time_range", "typical_range") !== "N/A" ? get("typical_time_range", "typical_login_time_range", "typical_range") : typicalMatch ? typicalMatch[1] : get("typical");
    const deviceVal    = get("device_name", "os_type", "device");
    const deviceObj    = obj.device as Record<string, unknown> | undefined;
    const office365Obj = obj.office365 as Record<string, unknown> | undefined;
    const deviceProps  = office365Obj?.device_properties as Record<string, unknown> | undefined;
    const osFromO365   = deviceProps?.OS as string | undefined;
    const deviceFinal  = deviceObj?.name as string ?? osFromO365 ?? deviceVal;
    body = lines(["Source User ID", get("srcip_usersid", "user_id"), "", "Source Username", get("srcip_username"), "", "Source Host", get("srcip_host"), "", "Source Country", getGeo("srcip"), "", "Actual Login Time Range", actualTimeRange, "", "Typical Login Time Range", typicalTimeRange, "", "Device", deviceFinal, "", "Login Result", get("login_result", "action"), "", "Please confirm if this login activity is expected and legitimate at this time. Thank you!"]);
  } else if (alertKey.includes("office 365 file sharing")) {
    body = lines(["Source IP", get("srcip_host"), "", "Source Host", get("srcip_host"), "", "Source Country", getGeo("srcip"), "", "User ID", get("srcip_username", "user_id"), "", "Shared File", get("file_name", "object_id"), "", "Please verify whether this file-sharing activity was authorized and aligned with current business operations."]);
  } else if (alertKey.includes("office 365 multiple files restored")) {
    body = lines(["Windows Event Source", get("event_source", "msg_origin"), "", "Source IP", get("srcip_host"), "", "User ID", get("srcip_username"), "", "File Name", get("file_name", "object_id"), "", "Please confirm whether this file restore activity by the user is authorized. Thank you."]);
  } else if (alertKey.includes("outbound destination country")) {
    body = lines(["Source IP", get("srcip_host"), "", "Destination IP", get("dstip_host", "dstip"), "", "Source Port", get("srcport"), "", "Destination Port", get("dstport"), "", "Destination Host", get("dstip_host"), "", "Destination Country", getGeo("dstip"), "", "Can you please confirm if this new outbound connection is expected and legitimate for this host?"]);
  } else if (alertKey.includes("outbytes anomaly")) {
    body = lines(["Source IP", get("srcip_host"), "", "Destination Host", get("dstip_host"), "", "Actual", get("actual"), "", "Typical", get("typical"), "", "Please verify if this outbound data transfer is part of your operations as of this moment or not. Thank you!"]);
  } else if (alertKey.includes("private to public exploit")) {
    const idsSignature = get("ids_signature", "ids_name") !== "N/A"
      ? get("ids_signature", "ids_name")
      : getNested("ids.signature");

    body = lines(["IDS Signature", idsSignature, "", "Source IP", get("srcip_host"), "", "Destination IP", get("dstip_host", "dstip"), "", "Source Port", get("srcport"), "", "Destination Port", get("dstport"), "", "Please confirm if this communication is expected and authorized for your systems."]);
 } else if (alertKey.includes("public to private exploit")) {
  const idsSignature = get("ids_signature", "ids_name") !== "N/A"
    ? get("ids_signature", "ids_name")
    : getNested("ids.signature");

  const dstHost = get("dstip_host");
  const dstIp   = get("dstip");
  const dstLine = dstHost !== "N/A" && dstIp !== "N/A" && dstHost !== dstIp
    ? lines(["Destination Host", dstHost, "", "Destination IP", dstIp])
    : dstHost !== "N/A"
    ? lines(["Destination Host", dstHost])
    : lines(["Destination IP", dstIp]);

  body = lines([
    "IDS Signature", idsSignature, "",
    "Source IP", `${get("srcip_host")} (malicious)`, "",
    dstLine, "",
    "Source Port", get("srcport"), "",
    "Destination Port", get("dstport"), "",
    "Please confirm if this communication is expected and authorized for your systems as it is associated with a malicious IP. Thank you."
  ]);
  } else if (alertKey.includes("scanner reputation")) {
    body = lines(["Source IP", `${get("srcip_host", "host_ip", "IP/name", "ip")} (Malicious)`, "", "Please verify the source IP if related to your operations, as it was flagged malicious by security vendors. Thank you!"]);
  } else if (alertKey.includes("sensitive windows active directory") || alertKey.includes("active directory attribute")) {
    body = lines(["Host IP", get("srcip_host"), "", "Host Name", get("engid_name", "device_name"), "", "Event Outcome", get("event_outcome", "state"), "", "Please confirm whether this Active Directory attribute modification was an authorized and expected activity. Thank you."]);
  } else if (alertKey.includes("sensor status")) {
    body = lines(["Sensor ID", get("engid", "sensor_id"), "", "Sensor", get("engid_name", "sensor_name"), "", "Please verify if this disconnection is expected to happen at this time. Thank you."]);
  } else if (alertKey.includes("suspicious lsass")) {
    body = lines(["Source IP", get("srcip_host"), "", "Source Host", get("srcip_host"), "", "Can you confirm that the process accessing LSASS on this source host was an authorized and expected action?"]);
  } else if (alertKey.includes("uncommon application")) {
    body = lines(["Source IP", get("srcip_host"), "", "Destination IP", get("dstip_host", "dstip"), "", "App", get("appid_name", "proto_name"), "", "Days Silent", get("days_silent"), "", "Please verify if this app is part of your operations. Thank you."]);
  } else if (alertKey.includes("uncommon process")) {
    body = lines(["Host IP", get("srcip_host"), "", "Host Name", get("engid_name", "device_name"), "", "Process Name", get("process_name"), "", "User Name", get("srcip_username"), "", "Days Silent", get("days_silent"), "", "Event Outcome", get("event_outcome", "state"), "", `Can you confirm whether the execution of ${get("process_name")} was an authorized and expected activity?`]);
  } else if (alertKey.includes("user asset access")) {
    body = lines(["Source Host", get("srcip_host"), "", "Target Username", get("srcip_username", "target_username"), "", "Service Name", get("service_name", "event_data_servicename"), "", "We observed a Kerberos service ticket request — can you confirm this activity is expected and authorized?"]);
  } else if (alertKey.includes("user login location")) {
    body = lines(["Source Username", get("srcip_username"), "", "Source IP", get("srcip_host"), "", "Source Country", getGeo("srcip"), "", "Login Result", get("login_result", "action"), "", "Please confirm if this login from an unusual location is expected and authorized. Thank you."]);
  } else if (alertKey.includes("long app session")) {
    body = lines(["Source IP", get("srcip"), "", "Destination IP", get("dstip"), "", "Source Port", get("srcport"), "", "Destination Port", get("dstport"), "", "App", get("appid_name", "proto_name"), "", "Please confirm if this activity is done in your end, thank you"]);
  } else {
    body = lines(["Source IP", get("srcip_host"), "", "Destination IP", get("dstip_host", "dstip"), "", "Source Port", get("srcport"), "", "Destination Port", get("dstport"), "", "Action", get("action"), "", "Please confirm if this activity is expected and authorized on your end. Thank you."]);
  }


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

function buildAegisPreset(
  vt: VTResult | null,
  verdict?: ScannerVerdict
): { caseStatus: CaseStatus; verification: Verification; remediation: Remediation; remarkKey: RemarkKey } {
  // Scanner verdict takes priority over VT result
  if (verdict === "false-positive") {
    return {
      caseStatus:   "Resolved",
      verification: "False Positive",
      remediation:  "Remediated",
      remarkKey:    "already-blocked",
    };
  }
  if (verdict === "true-positive") {
    return {
      caseStatus:   "Waiting for Status",
      verification: "True Positive",
      remediation:  "Not Remediated",
      remarkKey:    "malicious-not-found",
    };
  }
  // Fallback: use VT result
  if (vt && !vt.error && vt.malicious > 0) {
    return {
      caseStatus:   "Waiting for Status",
      verification: "True Positive",
      remediation:  "Not Remediated",
      remarkKey:    "malicious-not-found",
    };
  }
  return {
    caseStatus:   "Waiting for Status",
    verification: "To Be Confirmed",
    remediation:  "Not Remediated",
    remarkKey:    "clean-not-found",
  };
}

function buildRemark(key: RemarkKey, vt: VTResult | null, tenant: string, reportSent: boolean): string {
  const project = tenant !== "Unknown Tenant" ? `Project ${tenant}` : "Project";
  const vendors = vt?.malicious ?? 0;
  switch (key) {
    case "clean-not-found":
      return reportSent
        ? "The source IP was not found in the blocked list and was not detected as malicious. Sent a confirmation to the client."
        : "The source IP was not found in the blocked list and was not detected as malicious.";
    case "already-blocked":
      return "The source IP is already blocked.";
    case "no-remarks-confirmed":
      return reportSent ? "Sent to Client for Confirmation." : "No Remarks.";
    case "malicious-not-found":
      return `The source IP was not found in the blocked list but was detected as malicious by ${vendors} security vendor${vendors !== 1 ? "s" : ""}. Request for blocking sent to ${project}.`;
    case "in-list-not-blocked":
      return `The source IP exists in the list but is not blocked. Request for blocking sent to ${project}.`;
  }
}

// ── Pill ──────────────────────────────────────────────────────────────────────

type PillVariant = "red" | "yellow" | "green" | "gray" | "cyan";

function Pill({ children, variant = "gray" }: { children: ReactNode; variant?: PillVariant }) {
  const map: Record<PillVariant, CSSProperties> = {
    red:    { background: "rgba(160,30,50,0.35)",   color: "#ff6b7a", border: "1px solid rgba(220,60,80,0.5)" },
    yellow: { background: "rgba(160,110,20,0.35)",  color: "#ffc84a", border: "1px solid rgba(220,160,40,0.5)" },
    green:  { background: "rgba(30,110,60,0.35)",   color: "#4fd87a", border: "1px solid rgba(50,180,90,0.5)" },
    gray:   { background: "rgba(255,255,255,0.08)", color: "rgba(255,255,255,0.5)", border: "1px solid rgba(255,255,255,0.18)" },
    cyan:   { background: "rgba(20,120,140,0.3)",   color: "#4dd9ec", border: "1px solid rgba(40,180,200,0.45)" },
  };
  return (
    <span style={{ ...map[variant], display: "inline-flex", alignItems: "center", fontFamily: "'DM Mono', monospace", fontSize: 11.5, fontWeight: 500, letterSpacing: "0.04em", padding: "5px 14px", borderRadius: 20, whiteSpace: "nowrap" as const }}>
      {children}
    </span>
  );
}

// ── AegisDropdown ─────────────────────────────────────────────────────────────

const PILL_COLORS: Record<PillVariant, { bg: string; color: string; border: string }> = {
  red:    { bg: "rgba(160,30,50,0.35)",   color: "#ff6b7a", border: "rgba(220,60,80,0.5)" },
  yellow: { bg: "rgba(160,110,20,0.35)",  color: "#ffc84a", border: "rgba(220,160,40,0.5)" },
  green:  { bg: "rgba(30,110,60,0.35)",   color: "#4fd87a", border: "rgba(50,180,90,0.5)" },
  gray:   { bg: "rgba(255,255,255,0.08)", color: "rgba(255,255,255,0.5)", border: "rgba(255,255,255,0.18)" },
  cyan:   { bg: "rgba(20,120,140,0.3)",   color: "#4dd9ec", border: "rgba(40,180,200,0.45)" },
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
        style={{ fontFamily: "'DM Mono', monospace", fontSize: 12, fontWeight: 500, letterSpacing: "0.04em", padding: "6px 14px", borderRadius: 20, border: `1px solid ${c.border}`, background: c.bg, color: c.color, cursor: "pointer", outline: "none", appearance: "none" as const, WebkitAppearance: "none" as const, minWidth: 170 }}
      >
        {options.map(o => <option key={o} value={o} style={{ background: "#1a1e2a", color: "#fff" }}>{o}</option>)}
      </select>
    </div>
  );
}

// ── Remark presets ────────────────────────────────────────────────────────────

const REMARK_OPTIONS: { key: RemarkKey; label: string; needsReport: boolean }[] = [
  { key: "clean-not-found",      label: "Clean — Not in Blocklist",        needsReport: true  },
  { key: "already-blocked",      label: "Already Blocked",                 needsReport: false },
  { key: "no-remarks-confirmed", label: "No Remarks",                      needsReport: true  },
  { key: "malicious-not-found",  label: "Malicious — Not in Blocklist",    needsReport: true  },
  { key: "in-list-not-blocked",  label: "In List but Not Blocked",         needsReport: true  },
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

  // Aegis
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

    // Compute analysis synchronously so we can pass verdict to applyPreset
    // without depending on the async state update of setCaseAnalysis
    const analysis = analyzeScanner(data);
    setCaseAnalysis(analysis);
    setSendTo(data.tenant_name ?? null);
    setAegisTenant(data.tenant_name ?? "Unknown Tenant");

    const alertKey = (data.xdr_event?.display_name ?? data.alert_type ?? "").toLowerCase();
    const ip = alertKey.includes("outbound destination country")
      ? (data.dstip_host ?? data.dstip ?? null)
      : (data.srcip_host ?? data.host_ip ?? data["IP/name"] ?? data.ip ?? null);

    const isPrivateOrHostname = (val: string) =>
  /^10\./i.test(val) ||
  /^172\.(1[6-9]|2\d|3[01])\./i.test(val) ||
  /^192\.168\./i.test(val) ||
  /^127\./i.test(val) ||
  !/^\d{1,3}(\.\d{1,3}){3}$/.test(val); // not a plain IPv4

if (ip && !isPrivateOrHostname(ip)) {
  setVtIp(ip); setVtResult(null); setVtLoading(true); setShowAegis(false);
  fetch(`/api/virustotal?ip=${encodeURIComponent(ip)}`)
        .then(r => r.json())
        .then((vt: VTResult) => {

            if (vt.error && typeof vt.error !== "string") {
    vt.error = String(vt.error);
  }

          setVtResult(vt);
          setVtLoading(false);
          applyPreset(vt, analysis.verdict);
          setShowAegis(true);
        })
        .catch(err => {
          const errVt: VTResult = {
            malicious: 0, suspicious: 0, harmless: 0, undetected: 0,
            reputation: 0, country: "Unknown", owner: "Unknown", error: String(err),
          };
          setVtResult(errVt);
          setVtLoading(false);
          applyPreset(null, analysis.verdict);
          setShowAegis(true);
        });
    } else {
      applyPreset(null, analysis.verdict);
      setShowAegis(true);
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

  const copyMsg      = () => { if (!output)   return; navigator.clipboard.writeText(output).then(() => showToast("Notification copied!")); };
  const copyFollowUp = () => { if (!followUp) return; navigator.clipboard.writeText(followUp).then(() => showToast("Follow-up copied!")); };

  const currentRemark = buildRemark(aegisRemarkKey, vtResult, aegisTenant, aegisReportSent);
  const copyRemark    = () => navigator.clipboard.writeText(currentRemark).then(() => showToast("Remark copied!"));

  const caseStatusColors: Record<CaseStatus, PillVariant>     = { "Waiting for Status": "yellow", "Resolved": "green", "Whitelisted": "cyan", "Confirmed": "green" };
  const verificationColors: Record<Verification, PillVariant> = { "To Be Confirmed": "yellow", "True Positive": "red", "False Positive": "green" };
  const remediationColors: Record<Remediation, PillVariant>   = { "Remediated": "green", "Not Remediated": "red" };

  const activeRemark = REMARK_OPTIONS.find(r => r.key === aegisRemarkKey);
  const needsReport  = activeRemark?.needsReport ?? true;

  // Determine if MWELL + denied/remediated → no need to report
  const isMwellNoReport =
    sendTo?.toUpperCase() === "MWELL" &&
    caseAnalysis?.verdict === "false-positive";

  return (
    <div style={s.root}>
      <div style={s.plasmaWrap}><PlasmaCanvas speed={0.6} opacity={0.82} /></div>
      <div style={s.overlay} />
      <div style={s.content}>
        <header style={s.header}>
          <h1 style={s.h1}>Alert Analyzer</h1>
          <span style={s.sub}>Threat Intelligence Console</span>
        </header>
        <hr style={s.hr} />

        {/* ── SEND TO / NO NEED TO REPORT banner ── */}
        {sendTo && (
          isMwellNoReport ? (
            <div style={{ ...s.sendToBanner, borderColor: "rgba(220,160,40,0.45)", background: "rgba(100,70,10,0.28)" }}>
              <span style={{ ...s.sendToLabel, color: "rgba(255,200,74,0.65)" }}>⚠ NO NEED TO REPORT:</span>
              <span style={{ ...s.sendToValue, color: "#ffc84a" }}>
                {sendTo} — action is already denied / remediated
              </span>
            </div>
          ) : (
            <div style={s.sendToBanner}>
              <span style={s.sendToLabel}>SEND TO:</span>
              <span style={s.sendToValue}>{sendTo}</span>
            </div>
          )
        )}

        <Card label="Input — Alert JSON">
          <textarea style={s.textarea} value={jsonInput} onChange={(e: ChangeEvent<HTMLTextAreaElement>) => setJsonInput(e.target.value)} placeholder={`Paste your alert JSON here…\n\n${SAMPLE_JSON}`} />
          <Row><Btn primary onClick={generate}>Generate Template</Btn><Btn onClick={clearAll}>Clear All</Btn></Row>
        </Card>

        <Card label="Message 1 — Alert Notification">
          <textarea style={{ ...s.textarea, minHeight: 100 }} value={output} onChange={(e: ChangeEvent<HTMLTextAreaElement>) => setOutput(e.target.value)} placeholder="Alert notification will appear here…" />
          <Row><Btn green onClick={copyMsg}>Copy Notification</Btn></Row>
        </Card>

        <Card label="Message 2 — Follow-up Details">
          <textarea style={{ ...s.textarea, minHeight: 260 }} value={followUp} onChange={(e: ChangeEvent<HTMLTextAreaElement>) => setFollowUp(e.target.value)} placeholder="Follow-up details will appear here…" />
          <Row><Btn green onClick={copyFollowUp}>Copy Follow-up</Btn></Row>
        </Card>

        {vtIp && (
          <Card label={`VIRUSTOTAL — IP CHECK: ${vtIp}`}>
            <div style={s.pillRow}>
              {vtLoading ? [0, 0.3, 0.6].map((_, i) => (
                <span key={i} style={{ ...s.dot, animationDelay: `${[0, 0.3, 0.6][i]}s` }} />
              )) : vtResult && (
                vtResult.error
                  ? <Pill variant="red">● Error: {vtResult.error}</Pill>
                  : <>
                      <Pill variant={vtResult.malicious > 0 ? "red" : "green"}>
                        {vtResult.malicious > 0 ? "● Verdict: Malicious" : "✓ Verdict: Clean"}
                      </Pill>
                      <Pill variant="red">✕ Malicious: {vtResult.malicious}</Pill>
                      <Pill variant="yellow">△ Suspicious: {vtResult.suspicious}</Pill>
                      <Pill variant="green">✓ Harmless: {vtResult.harmless}</Pill>
                      <Pill variant="gray">— Undetected: {vtResult.undetected}</Pill>
                      <Pill variant="gray">⊙ Rep Score: {vtResult.reputation}</Pill>
                      <Pill variant="gray">⊙ Owner: {vtResult.owner}</Pill>
                      <Pill variant="gray">⊙ Country: {vtResult.country}</Pill>
                    </>
              )}
            </div>
          </Card>
        )}

        {caseAnalysis?.isScannerAnomaly && (
          <Card label="Scanner Anomaly — Auto Analysis">
            <div style={s.analysisGrid}>
              <AnalysisRow label="Tenant"             value={caseAnalysis.tenant} />
              <AnalysisRow label="IP / Alert Details" value={caseAnalysis.ipDetail} />
              <AnalysisRow label="Detection Result"   value={caseAnalysis.detectionResult} mono />
              <AnalysisRow label="Action Taken"       value={caseAnalysis.actionTaken} />
              <AnalysisRow label="Final Status"       value={caseAnalysis.finalStatus} highlight={caseAnalysis.verdict} />
            </div>
          </Card>
        )}

        {/* ── Aegis Case Status ── */}
        {showAegis && (
          <Card label="AEGIS CASE STATUS">

            {/* 3 colour-coded dropdowns */}
            <div style={s.aegisDropdownRow}>
              <AegisDropdown
                label="Case Status"
                value={aegisCaseStatus}
                options={["Waiting for Status", "Resolved", "Whitelisted", "Confirmed"]}
                onChange={setAegisCaseStatus}
                colorMap={caseStatusColors}
              />
              <AegisDropdown
                label="Verification"
                value={aegisVerification}
                options={["To Be Confirmed", "True Positive", "False Positive"]}
                onChange={setAegisVerification}
                colorMap={verificationColors}
              />
              <AegisDropdown
                label="Remediation"
                value={aegisRemediation}
                options={["Remediated", "Not Remediated"]}
                onChange={setAegisRemediation}
                colorMap={remediationColors}
              />
            </div>

            <div style={s.aegisDivider} />

            {/* Remark preset chips */}
            <div style={s.remarkSection}>
              <span style={s.aegisColLabel}>Auto Remarks Preset</span>
              <div style={s.remarkBtnRow}>
                {REMARK_OPTIONS.map(({ key, label }) => (
                  <button
                    key={key}
                    onClick={() => setAegisRemarkKey(key)}
                    style={{ ...s.remarkBtn, ...(aegisRemarkKey === key ? s.remarkBtnActive : {}) }}
                  >
                    {label}
                  </button>
                ))}
              </div>

              {/* Report sent toggle — only for presets that need client report */}
              {needsReport && (
                <div style={{ marginTop: 4 }}>
                  <button
                    onClick={() => setAegisReportSent(v => !v)}
                    style={{ ...s.toggleBtn, ...(aegisReportSent ? s.toggleBtnOn : {}) }}
                  >
                    {aegisReportSent ? "✓ Report Sent to Client" : "○ Report Not Yet Sent"}
                  </button>
                </div>
              )}

              {/* Remark preview box */}
              <div style={s.remarkPreview}>
                <div style={s.remarkPreviewHeader}>
                  <span style={s.remarkPreviewLabel}>
                    {needsReport ? "📤 Needs to be Sent to Client" : "🔒 No Need to Send to Client"}
                  </span>
                </div>
                <p style={s.remarkText}>{currentRemark}</p>
                <div style={{ marginTop: 10 }}>
                  <Btn green onClick={copyRemark}>Copy Remark</Btn>
                </div>
              </div>
            </div>

          </Card>
        )}
      </div>

      <div style={{ ...s.toast, opacity: toast.show ? 1 : 0, transform: toast.show ? "translateY(0)" : "translateY(6px)" }}>
        {toast.msg}
      </div>

      <style>{`
        @import url('https://fonts.googleapis.com/css2?family=DM+Serif+Display&family=DM+Mono:wght@300;400&family=DM+Sans:wght@300;400;500&display=swap');
        @keyframes blink { 0%,80%,100%{opacity:.2} 40%{opacity:1} }
        select option { background: #1a1e2a !important; color: #fff !important; }
      `}</style>
    </div>
  );
}

// ── Sub-components ────────────────────────────────────────────────────────────

function Card({ label, children }: { label: string; children: ReactNode }) {
  return <div style={s.card}><div style={s.label}>{label}</div>{children}</div>;
}
function Row({ children }: { children: ReactNode }) {
  return <div style={s.btnRow}>{children}</div>;
}
function Btn({ children, onClick, primary, green }: BtnProps) {
  const extra: CSSProperties = primary
    ? { background: "rgba(85,107,130,0.18)", color: "#a8d0ec", borderColor: "rgba(168,188,208,0.35)" }
    : green
    ? { background: "rgba(107,143,113,0.18)", color: "#8fcf9b", borderColor: "rgba(181,206,185,0.35)" }
    : { background: "rgba(255,255,255,0.07)", color: "rgba(255,255,255,0.55)" };
  return <button style={{ ...s.btn, ...extra }} onClick={onClick}>{children}</button>;
}
function AnalysisRow({ label, value, mono, highlight }: { label: string; value: string; mono?: boolean; highlight?: ScannerVerdict }) {
  const c: CSSProperties =
    highlight === "false-positive" ? { color: "#4fd87a", fontWeight: 500 } :
    highlight === "true-positive"  ? { color: "#ffc84a", fontWeight: 500 } :
    highlight === "escalate"       ? { color: "#ff6b7a", fontWeight: 500 } : {};
  return (
    <div style={s.analysisRow}>
      <span style={s.analysisLabel}>{label}</span>
      <span style={{ ...s.analysisValue, ...(mono ? { fontFamily: "'DM Mono', monospace", fontSize: 12 } : {}), ...c }}>{value}</span>
    </div>
  );
}

// ── Styles ────────────────────────────────────────────────────────────────────

const s: Record<string, CSSProperties> = {
  root:       { fontFamily: "'DM Sans', sans-serif", minHeight: "100vh", position: "relative", overflow: "hidden", background: "#0a0c12" },
  plasmaWrap: { position: "fixed", inset: 0, zIndex: 0 },
  overlay:    { position: "fixed", inset: 0, zIndex: 1, background: "linear-gradient(to bottom, rgba(8,10,18,0.55) 0%, rgba(8,10,18,0.4) 60%, rgba(8,10,18,0.65) 100%)", backdropFilter: "blur(1px)", WebkitBackdropFilter: "blur(1px)" },
  content:    { position: "relative", zIndex: 2, maxWidth: 780, margin: "0 auto", padding: "40px 20px 60px" },
  header:     { display: "flex", alignItems: "baseline", gap: 12, marginBottom: 28 },
  h1:         { fontFamily: "'DM Serif Display', serif", fontSize: 28, fontWeight: 400, color: "rgba(255,255,255,0.92)", letterSpacing: -0.4, margin: 0 },
  sub:        { fontSize: 11, fontFamily: "'DM Mono', monospace", color: "rgba(255,255,255,0.35)", letterSpacing: "0.08em", textTransform: "uppercase" },
  hr:         { border: "none", borderTop: "1px solid rgba(255,255,255,0.1)", marginBottom: 24 },
  sendToBanner: { display: "flex", alignItems: "center", gap: 12, background: "rgba(0,0,0,0.3)", border: "1px solid rgba(40,180,200,0.28)", borderRadius: 8, padding: "10px 16px", marginBottom: 16 },
  sendToLabel:  { fontFamily: "'DM Mono', monospace", fontSize: 10.5, letterSpacing: "0.14em", color: "rgba(77,217,236,0.55)", textTransform: "uppercase" as const, flexShrink: 0 },
  sendToValue:  { fontFamily: "'DM Mono', monospace", fontSize: 13, color: "#4dd9ec", fontWeight: 500, letterSpacing: "0.03em" },
  card:       { background: "rgba(255,255,255,0.06)", backdropFilter: "blur(20px)", WebkitBackdropFilter: "blur(20px)", border: "1px solid rgba(255,255,255,0.12)", borderRadius: 12, padding: 20, marginBottom: 16 },
  label:      { fontFamily: "'DM Mono', monospace", fontSize: 10.5, letterSpacing: "0.12em", textTransform: "uppercase", color: "rgba(255,255,255,0.35)", marginBottom: 10 },
  textarea:   { width: "100%", minHeight: 160, fontFamily: "'DM Mono', monospace", fontSize: 12.5, lineHeight: 1.7, color: "rgba(255,255,255,0.82)", background: "rgba(0,0,0,0.25)", border: "1px solid rgba(255,255,255,0.1)", borderRadius: 8, padding: "14px 16px", resize: "vertical", boxSizing: "border-box", transition: "border-color 0.2s" },
  btnRow:     { display: "flex", gap: 10, marginTop: 14, flexWrap: "wrap" },
  btn:        { fontFamily: "'DM Sans', sans-serif", fontSize: 13, fontWeight: 500, letterSpacing: "0.02em", padding: "9px 20px", borderRadius: 8, border: "1px solid rgba(255,255,255,0.15)", transition: "all 0.15s", cursor: "pointer" },
  pillRow:    { display: "flex", flexWrap: "wrap", gap: 8, marginTop: 4, alignItems: "center" },
  dot:        { display: "inline-block", width: 7, height: 7, borderRadius: "50%", background: "rgba(168,188,220,0.7)", margin: "0 2px", animation: "blink 1.2s ease-in-out infinite" },
  analysisGrid:  { display: "flex", flexDirection: "column" as const, gap: 10, marginTop: 4 },
  analysisRow:   { display: "flex", justifyContent: "space-between", alignItems: "baseline", gap: 12, borderBottom: "1px solid rgba(255,255,255,0.06)", paddingBottom: 8 },
  analysisLabel: { fontFamily: "'DM Mono', monospace", fontSize: 10.5, letterSpacing: "0.08em", textTransform: "uppercase" as const, color: "rgba(255,255,255,0.35)", whiteSpace: "nowrap" as const, flexShrink: 0 },
  analysisValue: { fontSize: 13, color: "rgba(255,255,255,0.82)", textAlign: "right" as const },
  // ── Aegis ──
  aegisDropdownRow:    { display: "flex", gap: 20, flexWrap: "wrap", alignItems: "flex-end" },
  aegisColLabel:       { fontFamily: "'DM Mono', monospace", fontSize: 10, letterSpacing: "0.12em", textTransform: "uppercase" as const, color: "rgba(255,255,255,0.3)", display: "block", marginBottom: 4 },
  aegisDivider:        { borderTop: "1px solid rgba(255,255,255,0.07)", margin: "18px 0" },
  remarkSection:       { display: "flex", flexDirection: "column" as const, gap: 12 },
  remarkBtnRow:        { display: "flex", flexWrap: "wrap", gap: 8 },
  remarkBtn:           { fontFamily: "'DM Mono', monospace", fontSize: 11, fontWeight: 500, padding: "6px 14px", borderRadius: 20, cursor: "pointer", border: "1px solid rgba(255,255,255,0.15)", background: "rgba(255,255,255,0.06)", color: "rgba(255,255,255,0.45)", transition: "all 0.15s" },
  remarkBtnActive:     { background: "rgba(77,217,236,0.15)", color: "#4dd9ec", border: "1px solid rgba(40,180,200,0.4)" },
  toggleBtn:           { fontFamily: "'DM Mono', monospace", fontSize: 11.5, fontWeight: 500, padding: "7px 16px", borderRadius: 20, cursor: "pointer", border: "1px solid rgba(255,255,255,0.15)", background: "rgba(255,255,255,0.06)", color: "rgba(255,255,255,0.4)", transition: "all 0.15s" },
  toggleBtnOn:         { background: "rgba(30,110,60,0.3)", color: "#4fd87a", border: "1px solid rgba(50,180,90,0.4)" },
  remarkPreview:       { background: "rgba(0,0,0,0.2)", border: "1px solid rgba(255,255,255,0.08)", borderRadius: 8, padding: "14px 16px" },
  remarkPreviewHeader: { marginBottom: 6 },
  remarkPreviewLabel:  { fontFamily: "'DM Mono', monospace", fontSize: 10, letterSpacing: "0.1em", textTransform: "uppercase" as const, color: "rgba(255,255,255,0.3)" },
  remarkText:          { fontFamily: "'DM Mono', monospace", fontSize: 12.5, lineHeight: 1.7, color: "rgba(255,255,255,0.8)", margin: "8px 0 0" },
  toast:               { position: "fixed", bottom: 24, right: 24, background: "rgba(30,40,55,0.9)", color: "#8fcf9b", border: "1px solid rgba(130,180,140,0.35)", borderRadius: 8, padding: "10px 18px", fontSize: 13, fontWeight: 500, transition: "all 0.25s", pointerEvents: "none", zIndex: 100, backdropFilter: "blur(10px)" },
};