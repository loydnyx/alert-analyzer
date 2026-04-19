"use client";
import { useState, useEffect } from "react";
import { useRouter } from "next/navigation";

export default function LoginPage() {
  const [user, setUser] = useState("");
  const [pass, setPass] = useState("");
  const [showPass, setShowPass] = useState(false);
  const [userFocus, setUserFocus] = useState(false);
  const [passFocus, setPassFocus] = useState(false);
  const [error, setError] = useState(false);
  const [loading, setLoading] = useState(false);
  const [returning, setReturning] = useState(false);
  const router = useRouter();

  useEffect(() => {
    const saved = localStorage.getItem("soc_user");
    if (saved) { setUser(saved); setReturning(true); }
  }, []);

  const handleLogin = async () => {
    setLoading(true);
    setError(false);
    const res = await fetch("/api/auth", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ user, pass }),
    });
    if (res.ok) {
      localStorage.setItem("soc_user", user);
      router.push("/");
      router.refresh();
    } else {
      setError(true);
      setLoading(false);
    }
  };

  const floatLabel = (focused: boolean, value: string) =>
    focused || value.length > 0;

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
        {/* Header */}
        <div style={{ marginBottom: 36 }}>
          <h1 style={{
            fontFamily: "'Orbitron', monospace", fontSize: 20, fontWeight: 900,
            color: "#00ff9d", letterSpacing: "0.12em", margin: "0 0 6px",
            textTransform: "uppercase" as const,
            textShadow: "0 0 20px rgba(0,255,157,0.4)",
          }}>Alert Analyzer</h1>
          <p style={{ fontSize: 10, color: "rgba(0,255,157,0.35)", letterSpacing: "0.2em", margin: 0, textTransform: "uppercase" as const }}>
            ◈ SOC Operations · Secured Access
          </p>
        </div>

        <div style={{ display: "flex", flexDirection: "column" as const, gap: 24 }}>

          {/* Username field */}
          {returning ? (
            <div style={{
              padding: "10px 14px",
              background: "rgba(0,255,157,0.03)",
              border: "1px solid rgba(0,255,157,0.08)",
              borderRadius: 3, color: "rgba(0,255,157,0.5)", fontSize: 13,
              display: "flex", justifyContent: "space-between", alignItems: "center",
            }}>
              <div>
                <div style={{ fontSize: 9, color: "rgba(0,255,157,0.35)", letterSpacing: "0.18em", textTransform: "uppercase" as const, marginBottom: 2 }}>Username</div>
                <div>{user}</div>
              </div>
              <span
                onClick={() => { setReturning(false); setUser(""); localStorage.removeItem("soc_user"); }}
                style={{ fontSize: 10, color: "rgba(255,42,74,0.5)", cursor: "pointer" }}
              >change</span>
            </div>
          ) : (
            <div style={{ position: "relative" as const }}>
              <label style={{
                position: "absolute" as const,
                left: 14,
                top: floatLabel(userFocus, user) ? -9 : "50%",
                transform: floatLabel(userFocus, user) ? "translateY(0)" : "translateY(-50%)",
                fontSize: floatLabel(userFocus, user) ? 9.5 : 13,
                color: floatLabel(userFocus, user) ? (userFocus ? "#00ff9d" : "rgba(0,255,157,0.4)") : "rgba(0,255,157,0.25)",
                letterSpacing: "0.18em",
                textTransform: "uppercase" as const,
                transition: "all 0.2s ease",
                pointerEvents: "none" as const,
                background: floatLabel(userFocus, user) ? "#03050c" : "transparent",
                padding: floatLabel(userFocus, user) ? "0 4px" : "0",
              }}>Username</label>
              <input
                type="text"
                value={user}
                onChange={e => setUser(e.target.value)}
                onFocus={() => setUserFocus(true)}
                onBlur={() => setUserFocus(false)}
                onKeyDown={e => e.key === "Enter" && handleLogin()}
                autoFocus
                style={{
                  width: "100%", padding: "12px 14px",
                  background: "rgba(0,8,4,0.8)",
                  border: `1px solid ${error ? "rgba(255,42,74,0.4)" : userFocus ? "rgba(0,255,157,0.4)" : "rgba(0,255,157,0.15)"}`,
                  borderRadius: 3, color: "#fff", fontSize: 13,
                  fontFamily: "'Share Tech Mono', monospace", outline: "none",
                  boxSizing: "border-box" as const,
                  transition: "border-color 0.2s",
                }}
              />
            </div>
          )}

          {/* Password field */}
          <div style={{ position: "relative" as const }}>
            <label style={{
              position: "absolute" as const,
              left: 14,
              top: floatLabel(passFocus, pass) ? -9 : "50%",
              transform: floatLabel(passFocus, pass) ? "translateY(0)" : "translateY(-50%)",
              fontSize: floatLabel(passFocus, pass) ? 9.5 : 13,
              color: floatLabel(passFocus, pass) ? (passFocus ? "#00ff9d" : "rgba(0,255,157,0.4)") : "rgba(0,255,157,0.25)",
              letterSpacing: "0.18em",
              textTransform: "uppercase" as const,
              transition: "all 0.2s ease",
              pointerEvents: "none" as const,
              background: floatLabel(passFocus, pass) ? "#03050c" : "transparent",
              padding: floatLabel(passFocus, pass) ? "0 4px" : "0",
              zIndex: 1,
            }}>Password</label>
            <input
              type={showPass ? "text" : "password"}
              value={pass}
              onChange={e => setPass(e.target.value)}
              onFocus={() => setPassFocus(true)}
              onBlur={() => setPassFocus(false)}
              onKeyDown={e => e.key === "Enter" && handleLogin()}
              autoFocus={returning}
              style={{
                width: "100%", padding: "12px 44px 12px 14px",
                background: "rgba(0,8,4,0.8)",
                border: `1px solid ${error ? "rgba(255,42,74,0.4)" : passFocus ? "rgba(0,255,157,0.4)" : "rgba(0,255,157,0.15)"}`,
                borderRadius: 3, color: "#fff", fontSize: 13,
                fontFamily: "'Share Tech Mono', monospace", outline: "none",
                boxSizing: "border-box" as const,
                transition: "border-color 0.2s",
              }}
            />
            {/* Eye toggle */}
            <button
              type="button"
              onClick={() => setShowPass(v => !v)}
              style={{
                position: "absolute" as const, right: 12, top: "50%",
                transform: "translateY(-50%)",
                background: "transparent", border: "none", cursor: "pointer",
                padding: 0, display: "flex", alignItems: "center",
              }}
            >
              {showPass ? (
                <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="rgba(10, 10, 10, 0.6)" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                  <path d="M17.94 17.94A10.07 10.07 0 0 1 12 20c-7 0-11-8-11-8a18.45 18.45 0 0 1 5.06-5.94"/>
                  <path d="M9.9 4.24A9.12 9.12 0 0 1 12 4c7 0 11 8 11 8a18.5 18.5 0 0 1-2.16 3.19"/>
                  <line x1="1" y1="1" x2="23" y2="23"/>
                </svg>
              ) : (
                <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="rgba(10, 10, 10, 0.6)" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                  <path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"/>
                  <circle cx="12" cy="12" r="3"/>
                </svg>
              )}
            </button>
          </div>

          {error && (
            <p style={{ color: "#ff2a4a", fontSize: 11, letterSpacing: "0.08em", margin: "-10px 0 0" }}>
              ✕ Invalid credentials. Access denied.
            </p>
          )}

          <button
            onClick={handleLogin}
            disabled={loading}
            style={{
              width: "100%", padding: "11px 22px", background: "transparent",
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
     <style>{`
  @import url('https://fonts.googleapis.com/css2?family=Orbitron:wght@900&family=Share+Tech+Mono&display=swap');
  input::-ms-reveal,
  input::-ms-clear { display: none; }
  input::-webkit-credentials-auto-fill-button { display: none; }
`}</style>
    </div>
  );
}