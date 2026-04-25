"use client";
import { useState, useEffect, useRef } from "react";
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
  const [mounted, setMounted] = useState(false);
  const canvasRef = useRef<HTMLCanvasElement>(null);
  const router = useRouter();

  useEffect(() => {
    setMounted(true);
    document.title = "Alert Analyzer";
    const saved = localStorage.getItem("soc_user");
    if (saved) { setUser(saved); setReturning(true); }
  }, []);

  // Particle canvas
  useEffect(() => {
    const canvas = canvasRef.current;
    if (!canvas) return;
    const ctx = canvas.getContext("2d");
    if (!ctx) return;

    const resize = () => {
      canvas.width = window.innerWidth;
      canvas.height = window.innerHeight;
    };
    resize();
    window.addEventListener("resize", resize);

    // Fewer particles on mobile for performance
    const isMobile = window.innerWidth < 640;
    const count = isMobile ? 40 : 80;

    const particles: { x: number; y: number; vx: number; vy: number; size: number; opacity: number; pulse: number }[] = [];
    for (let i = 0; i < count; i++) {
      particles.push({
        x: Math.random() * window.innerWidth,
        y: Math.random() * window.innerHeight,
        vx: (Math.random() - 0.5) * 0.4,
        vy: (Math.random() - 0.5) * 0.4,
        size: Math.random() * 1.5 + 0.5,
        opacity: Math.random() * 0.5 + 0.1,
        pulse: Math.random() * Math.PI * 2,
      });
    }

    let raf: number;
    const draw = () => {
      ctx.clearRect(0, 0, canvas.width, canvas.height);
      particles.forEach(p => {
        p.x += p.vx;
        p.y += p.vy;
        p.pulse += 0.02;
        if (p.x < 0) p.x = canvas.width;
        if (p.x > canvas.width) p.x = 0;
        if (p.y < 0) p.y = canvas.height;
        if (p.y > canvas.height) p.y = 0;

        const op = p.opacity * (0.7 + 0.3 * Math.sin(p.pulse));
        ctx.beginPath();
        ctx.arc(p.x, p.y, p.size, 0, Math.PI * 2);
        ctx.fillStyle = `rgba(56,189,248,${op})`;
        ctx.fill();
      });

      for (let i = 0; i < particles.length; i++) {
        for (let j = i + 1; j < particles.length; j++) {
          const dx = particles[i].x - particles[j].x;
          const dy = particles[i].y - particles[j].y;
          const dist = Math.sqrt(dx * dx + dy * dy);
          if (dist < 100) {
            ctx.beginPath();
            ctx.moveTo(particles[i].x, particles[i].y);
            ctx.lineTo(particles[j].x, particles[j].y);
            ctx.strokeStyle = `rgba(56,189,248,${0.08 * (1 - dist / 100)})`;
            ctx.lineWidth = 0.5;
            ctx.stroke();
          }
        }
      }

      raf = requestAnimationFrame(draw);
    };
    draw();

    return () => {
      cancelAnimationFrame(raf);
      window.removeEventListener("resize", resize);
    };
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

  const floatLabel = (focused: boolean, value: string) => focused || value.length > 0;

  return (
    <div className="login-root" style={{
      background: "#060d1b",
      position: "relative" as const,
    }}>

      {/* Particle canvas */}
      <canvas ref={canvasRef} style={{ position: "fixed", inset: 0, zIndex: 0, pointerEvents: "none" }} />

      {/* Grid */}
      <div style={{
        position: "fixed", inset: 0, zIndex: 1,
        backgroundImage: "linear-gradient(rgba(56,189,248,0.03) 1px, transparent 1px), linear-gradient(90deg, rgba(56,189,248,0.03) 1px, transparent 1px)",
        backgroundSize: "48px 48px",
        pointerEvents: "none",
      }} />

      {/* Top glow */}
      <div style={{
        position: "fixed", top: "-10%", left: "50%",
        transform: "translateX(-50%)",
        width: "min(700px, 100vw)", height: 400,
        background: "radial-gradient(ellipse, rgba(56,189,248,0.07) 0%, transparent 70%)",
        pointerEvents: "none", zIndex: 1,
      }} />

      {/* Scanning line */}
      <div style={{ position: "fixed", inset: 0, zIndex: 2, pointerEvents: "none", overflow: "hidden" }}>
        <div style={{
          position: "absolute", left: 0, right: 0, height: 1,
          background: "linear-gradient(90deg, transparent, rgba(56,189,248,0.15), transparent)",
          animation: "scanLine 6s linear infinite",
        }} />
      </div>

      {/* Card */}
      <div style={{
        position: "relative" as const,
        zIndex: 10,
        background: "rgba(10,18,38,0.85)",
        backdropFilter: "blur(24px)",
        WebkitBackdropFilter: "blur(24px)", // Safari support
        border: "1px solid rgba(56,189,248,0.12)",
        borderRadius: 18,
        padding: "clamp(28px, 6vw, 44px) clamp(20px, 6vw, 40px)",
        width: "100%",
        maxWidth: 420,
        boxShadow: "0 8px 48px rgba(0,0,0,0.6), 0 1px 0 rgba(56,189,248,0.06) inset, 0 0 80px rgba(56,189,248,0.03)",
        opacity: mounted ? 1 : 0,
        transform: mounted ? "translateY(0)" : "translateY(24px)",
        transition: "opacity 0.7s ease, transform 0.7s ease",
      }}>

        {/* Corner accents */}
        {[
          { top: 12, left: 12, borderTop: "1.5px solid rgba(56,189,248,0.4)", borderLeft: "1.5px solid rgba(56,189,248,0.4)", borderRadius: "2px 0 0 0" },
          { top: 12, right: 12, borderTop: "1.5px solid rgba(56,189,248,0.4)", borderRight: "1.5px solid rgba(56,189,248,0.4)", borderRadius: "0 2px 0 0" },
          { bottom: 12, left: 12, borderBottom: "1.5px solid rgba(56,189,248,0.2)", borderLeft: "1.5px solid rgba(56,189,248,0.2)", borderRadius: "0 0 0 2px" },
          { bottom: 12, right: 12, borderBottom: "1.5px solid rgba(56,189,248,0.2)", borderRight: "1.5px solid rgba(56,189,248,0.2)", borderRadius: "0 0 2px 0" },
        ].map((style, i) => (
          <div key={i} style={{ position: "absolute" as const, width: 16, height: 16, ...style }} />
        ))}

        {/* Header */}
        <div style={{ marginBottom: "clamp(24px, 5vw, 36px)", display: "flex", flexDirection: "column" as const, alignItems: "center", gap: 10 }}>
          <div style={{
            width: 48, height: 48, borderRadius: 14,
            background: "rgba(56,189,248,0.08)",
            border: "1px solid rgba(56,189,248,0.2)",
            display: "flex", alignItems: "center", justifyContent: "center",
            marginBottom: 4,
            animation: "iconPulse 3s ease-in-out infinite",
            flexShrink: 0,
          }}>
            <svg width="22" height="22" viewBox="0 0 24 24" fill="none">
              <path d="M12 2L2 7l10 5 10-5-10-5zM2 17l10 5 10-5M2 12l10 5 10-5" stroke="#38bdf8" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"/>
            </svg>
          </div>
          <div style={{ textAlign: "center" as const }}>
            <div style={{
              fontSize: "clamp(9px, 2.5vw, 10px)", fontWeight: 600,
              letterSpacing: "0.12em", color: "#38bdf8",
              background: "rgba(56,189,248,0.08)",
              border: "1px solid rgba(56,189,248,0.15)",
              padding: "3px 12px", borderRadius: 20,
              marginBottom: 10, display: "inline-block",
            }}>
              THREAT INTELLIGENCE CONSOLE
            </div>
            <h1 style={{
              fontSize: "clamp(20px, 5vw, 24px)", fontWeight: 700,
              color: "#f1f5f9", letterSpacing: "-0.02em",
              margin: "0 0 4px",
            }}>
              Alert <span style={{ color: "#38bdf8" }}>Analyzer</span>
            </h1>
            <p style={{ fontSize: "clamp(11px, 3vw, 12px)", color: "rgba(148,163,184,0.45)", letterSpacing: "0.04em", margin: 0 }}>
              Stellar Cyber · SOC Operations
            </p>
          </div>
        </div>

        <div style={{ display: "flex", flexDirection: "column" as const, gap: 20 }}>

          {/* Username */}
          {returning ? (
            <div style={{
              padding: "12px 16px",
              background: "rgba(56,189,248,0.04)",
              border: "1px solid rgba(56,189,248,0.1)",
              borderRadius: 10, fontSize: 13,
              display: "flex", justifyContent: "space-between", alignItems: "center",
            }}>
              <div>
                <div style={{ fontSize: 10, color: "rgba(56,189,248,0.5)", letterSpacing: "0.12em", textTransform: "uppercase" as const, marginBottom: 3, fontWeight: 600 }}>Username</div>
                <div style={{ color: "#f1f5f9", fontWeight: 500 }}>{user}</div>
              </div>
              <span
                onClick={() => { setReturning(false); setUser(""); localStorage.removeItem("soc_user"); }}
                style={{ fontSize: 11, color: "rgba(239,68,68,0.6)", cursor: "pointer", fontWeight: 500, padding: "8px 4px", touchAction: "manipulation" }}
              >
                change
              </span>
            </div>
          ) : (
            <div style={{ position: "relative" as const }}>
              <label style={{
                position: "absolute" as const, left: 14,
                top: floatLabel(userFocus, user) ? -9 : "50%",
                transform: floatLabel(userFocus, user) ? "translateY(0)" : "translateY(-50%)",
                fontSize: floatLabel(userFocus, user) ? 10 : 13,
                color: floatLabel(userFocus, user) ? (userFocus ? "#38bdf8" : "rgba(56,189,248,0.5)") : "rgba(148,163,184,0.3)",
                letterSpacing: "0.1em", textTransform: "uppercase" as const, fontWeight: 600,
                transition: "all 0.2s ease", pointerEvents: "none" as const,
                background: floatLabel(userFocus, user) ? "#060d1b" : "transparent",
                padding: floatLabel(userFocus, user) ? "0 4px" : "0",
              }}>Username</label>
              <input
                type="text" value={user}
                onChange={e => setUser(e.target.value)}
                onFocus={() => setUserFocus(true)}
                onBlur={() => setUserFocus(false)}
                onKeyDown={e => e.key === "Enter" && handleLogin()}
                autoComplete="username"
                autoCapitalize="none"
                autoCorrect="off"
                autoFocus
                style={{
                  width: "100%", padding: "14px 16px",
                  background: "rgba(2,8,23,0.6)",
                  border: `1px solid ${error ? "rgba(239,68,68,0.4)" : userFocus ? "rgba(56,189,248,0.4)" : "rgba(56,189,248,0.1)"}`,
                  borderRadius: 10, color: "#f1f5f9",
                  fontSize: 16, // 16px prevents iOS auto-zoom on focus
                  fontFamily: "'Inter', sans-serif", outline: "none",
                  boxSizing: "border-box" as const, transition: "all 0.2s",
                  WebkitAppearance: "none",
                  touchAction: "manipulation",
                }}
              />
            </div>
          )}

          {/* Password */}
          <div style={{ position: "relative" as const }}>
            <label style={{
              position: "absolute" as const, left: 14,
              top: floatLabel(passFocus, pass) ? -9 : "50%",
              transform: floatLabel(passFocus, pass) ? "translateY(0)" : "translateY(-50%)",
              fontSize: floatLabel(passFocus, pass) ? 10 : 13,
              color: floatLabel(passFocus, pass) ? (passFocus ? "#38bdf8" : "rgba(56,189,248,0.5)") : "rgba(148,163,184,0.3)",
              letterSpacing: "0.1em", textTransform: "uppercase" as const, fontWeight: 600,
              transition: "all 0.2s ease", pointerEvents: "none" as const,
              background: floatLabel(passFocus, pass) ? "#060d1b" : "transparent",
              padding: floatLabel(passFocus, pass) ? "0 4px" : "0", zIndex: 1,
            }}>Password</label>
            <input
              type={showPass ? "text" : "password"} value={pass}
              onChange={e => setPass(e.target.value)}
              onFocus={() => setPassFocus(true)}
              onBlur={() => setPassFocus(false)}
              onKeyDown={e => e.key === "Enter" && handleLogin()}
              autoComplete="current-password"
              autoFocus={returning}
              style={{
                width: "100%", padding: "14px 48px 14px 16px",
                background: "rgba(2,8,23,0.6)",
                border: `1px solid ${error ? "rgba(239,68,68,0.4)" : passFocus ? "rgba(56,189,248,0.4)" : "rgba(56,189,248,0.1)"}`,
                borderRadius: 10, color: "#f1f5f9",
                fontSize: 16, // 16px prevents iOS auto-zoom on focus
                fontFamily: "'Inter', sans-serif", outline: "none",
                boxSizing: "border-box" as const, transition: "all 0.2s",
                WebkitAppearance: "none",
                touchAction: "manipulation",
              }}
            />
            <button
              type="button"
              onClick={() => setShowPass(v => !v)}
              style={{
                position: "absolute" as const, right: 0, top: 0, bottom: 0,
                width: 48,
                background: "transparent", border: "none", cursor: "pointer",
                display: "flex", alignItems: "center", justifyContent: "center",
                touchAction: "manipulation",
              }}
            >
              {showPass ? (
                <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="#38bdf8" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                  <path d="M17.94 17.94A10.07 10.07 0 0 1 12 20c-7 0-11-8-11-8a18.45 18.45 0 0 1 5.06-5.94"/>
                  <path d="M9.9 4.24A9.12 9.12 0 0 1 12 4c7 0 11 8 11 8a18.5 18.5 0 0 1-2.16 3.19"/>
                  <line x1="1" y1="1" x2="23" y2="23"/>
                </svg>
              ) : (
                <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="#38bdf8" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                  <path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"/>
                  <circle cx="12" cy="12" r="3"/>
                </svg>
              )}
            </button>
          </div>

          {error && (
            <p style={{ color: "#f87171", fontSize: 12, letterSpacing: "0.04em", margin: "-8px 0 0", fontWeight: 500 }}>
              ✕ Invalid credentials. Access denied.
            </p>
          )}

          {/* Login button — tall for touch targets */}
          <button
            onClick={handleLogin}
            disabled={loading}
            style={{
              width: "100%",
              padding: "15px 22px", // Taller touch target (min 44px)
              background: loading ? "rgba(56,189,248,0.05)" : "rgba(56,189,248,0.08)",
              border: "1px solid rgba(56,189,248,0.35)",
              borderRadius: 10, color: "#38bdf8",
              fontSize: "clamp(12px, 3.5vw, 13px)",
              fontFamily: "'Inter', sans-serif", fontWeight: 600,
              letterSpacing: "0.08em", textTransform: "uppercase" as const,
              cursor: loading ? "not-allowed" : "pointer",
              transition: "all 0.2s",
              position: "relative" as const,
              overflow: "hidden",
              touchAction: "manipulation",
              WebkitTapHighlightColor: "transparent",
            }}
          >
            {loading ? (
              <span style={{ display: "flex", alignItems: "center", justifyContent: "center", gap: 8 }}>
                {[0, 0.2, 0.4].map((delay, i) => (
                  <span key={i} style={{
                    width: 7, height: 7, borderRadius: "50%",
                    background: "#38bdf8", display: "inline-block",
                    animation: `blink 1.2s ease-in-out ${delay}s infinite`,
                  }} />
                ))}
              </span>
            ) : "Access System"}
          </button>

          {/* Status */}
          <div style={{ display: "flex", alignItems: "center", justifyContent: "center", gap: 6 }}>
            <span style={{
              width: 6, height: 6, borderRadius: "50%",
              background: "#34d399", display: "inline-block",
              animation: "statusPulse 2s ease-in-out infinite",
              flexShrink: 0,
            }} />
            <span style={{ fontSize: "clamp(10px, 3vw, 11px)", color: "rgba(148,163,184,0.35)", letterSpacing: "0.06em" }}>
              Secure connection established
            </span>
          </div>
        </div>
      </div>

      <style>{`
        @import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&display=swap');

        *, *::before, *::after { box-sizing: border-box; }

        /* min-height with dvh fallback — avoids duplicate TS property error */
        .login-root {
          min-height: 100vh;
          min-height: 100dvh;
          display: flex;
          align-items: center;
          justify-content: center;
          font-family: 'Inter', sans-serif;
          position: relative;
          overflow: hidden;
          padding: 16px;
        }

        /* Prevent iOS overscroll bounce from showing white */
        html, body { background: #060d1b; overscroll-behavior: none; }

        /* Remove iOS input styling */
        input { -webkit-appearance: none; appearance: none; border-radius: 0; }
        input::placeholder { color: transparent; }
        input:focus { box-shadow: 0 0 0 3px rgba(56,189,248,0.08) !important; }

        /* Remove tap highlight on mobile */
        * { -webkit-tap-highlight-color: transparent; }

        @keyframes scanLine {
          0% { top: -2px; }
          100% { top: 100vh; }
        }
        @keyframes iconPulse {
          0%, 100% { box-shadow: 0 0 0 0 rgba(56,189,248,0); }
          50% { box-shadow: 0 0 0 8px rgba(56,189,248,0.06); }
        }
        @keyframes statusPulse {
          0%, 100% { opacity: 0.5; transform: scale(1); }
          50% { opacity: 1; transform: scale(1.2); }
        }
        @keyframes blink {
          0%, 80%, 100% { opacity: 0.15; }
          40% { opacity: 1; }
        }

        /* Hover only on non-touch devices */
        @media (hover: hover) {
          button:hover:not(:disabled) {
            background: rgba(56,189,248,0.14) !important;
            box-shadow: 0 0 24px rgba(56,189,248,0.12) !important;
          }
        }

        /* Active state for touch feedback */
        button:active:not(:disabled) {
          background: rgba(56,189,248,0.18) !important;
          transform: scale(0.99);
        }

        /* Small phones */
        @media (max-width: 360px) {
          input { font-size: 15px !important; }
        }

        /* Landscape mobile — ensure card fits */
        @media (max-height: 600px) and (orientation: landscape) {
          .login-card { padding: 20px 24px !important; }
        }
      `}</style>
    </div>
  );
}