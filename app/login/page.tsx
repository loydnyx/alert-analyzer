"use client";
import { useState } from "react";
import { useRouter } from "next/navigation";

export default function LoginPage() {
  const [user, setUser] = useState("");
  const [pass, setPass] = useState("");
  const [error, setError] = useState(false);
  const [loading, setLoading] = useState(false);
  const router = useRouter();

  const handleLogin = async () => {
    setLoading(true);
    setError(false);
    const res = await fetch("/api/auth", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ user, pass }),
    });
    if (res.ok) {
      router.push("/");
      router.refresh();
    } else {
      setError(true);
      setLoading(false);
    }
  };

  return (
    <div style={{
      minHeight: "100vh", background: "#03050c", display: "flex",
      alignItems: "center", justifyContent: "center",
      fontFamily: "'Share Tech Mono', monospace",
      backgroundImage: "linear-gradient(rgba(0,255,157,0.03) 1px, transparent 1px), linear-gradient(90deg, rgba(0,255,157,0.03) 1px, transparent 1px)",
      backgroundSize: "40px 40px",
    }}>
      <div style={{
        background: "rgba(0,12,6,0.95)", border: "1px solid rgba(0,255,157,0.2)",
        borderLeft: "3px solid #00ff9d", borderRadius: 4, padding: "40px 36px",
        width: "100%", maxWidth: 400,
        boxShadow: "0 0 40px rgba(0,255,157,0.05)",
      }}>
        <div style={{ marginBottom: 32 }}>
          <h1 style={{
            fontFamily: "'Orbitron', monospace", fontSize: 20, fontWeight: 900,
            color: "#00ff9d", letterSpacing: "0.12em", margin: "0 0 6px",
            textTransform: "uppercase" as const,
            textShadow: "0 0 20px rgba(0,255,157,0.4)",
          }}>
            Alert Analyzer
          </h1>
          <p style={{ fontSize: 10, color: "rgba(0,255,157,0.35)", letterSpacing: "0.2em", margin: 0, textTransform: "uppercase" as const }}>
            ◈ SOC Operations · Secured Access
          </p>
        </div>

        <div style={{ display: "flex", flexDirection: "column" as const, gap: 14 }}>
          <div>
            <label style={{ fontSize: 9.5, letterSpacing: "0.18em", textTransform: "uppercase" as const, color: "rgba(0,255,157,0.35)", display: "block", marginBottom: 6 }}>
              Username
            </label>
            <input
              type="text"
              value={user}
              onChange={e => setUser(e.target.value)}
              onKeyDown={e => e.key === "Enter" && handleLogin()}
              style={{
                width: "100%", padding: "10px 14px", background: "rgba(0,8,4,0.8)",
                border: `1px solid ${error ? "rgba(255,42,74,0.4)" : "rgba(0,255,157,0.15)"}`,
                borderRadius: 3, color: "#fff", fontSize: 13,
                fontFamily: "'Share Tech Mono', monospace", outline: "none",
                boxSizing: "border-box" as const,
              }}
            />
          </div>

          <div>
            <label style={{ fontSize: 9.5, letterSpacing: "0.18em", textTransform: "uppercase" as const, color: "rgba(0,255,157,0.35)", display: "block", marginBottom: 6 }}>
              Password
            </label>
            <input
              type="password"
              value={pass}
              onChange={e => setPass(e.target.value)}
              onKeyDown={e => e.key === "Enter" && handleLogin()}
              style={{
                width: "100%", padding: "10px 14px", background: "rgba(0,8,4,0.8)",
                border: `1px solid ${error ? "rgba(255,42,74,0.4)" : "rgba(0,255,157,0.15)"}`,
                borderRadius: 3, color: "#fff", fontSize: 13,
                fontFamily: "'Share Tech Mono', monospace", outline: "none",
                boxSizing: "border-box" as const,
              }}
            />
          </div>

          {error && (
            <p style={{ color: "#ff2a4a", fontSize: 11, letterSpacing: "0.08em", margin: 0 }}>
              ✕ Invalid credentials. Access denied.
            </p>
          )}

          <button
            onClick={handleLogin}
            disabled={loading}
            style={{
              marginTop: 8, padding: "11px 22px", background: "transparent",
              border: "1px solid rgba(0,255,157,0.4)", borderRadius: 3,
              color: "#00ff9d", fontSize: 12, fontFamily: "'Share Tech Mono', monospace",
              letterSpacing: "0.1em", textTransform: "uppercase" as const,
              cursor: "pointer", boxShadow: "0 0 12px rgba(0,255,157,0.08)",
            }}
          >
            {loading ? "Authenticating..." : "[ Access System ]"}
          </button>
        </div>
      </div>
      <style>{`@import url('https://fonts.googleapis.com/css2?family=Orbitron:wght@900&family=Share+Tech+Mono&display=swap');`}</style>
    </div>
  );
}