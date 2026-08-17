"use client";

import { useState, useEffect, useCallback } from "react";
import { useRouter } from "next/navigation";

interface SessionState {
  authenticated: boolean;
  user?: { name: string; email: string; role: string };
  session?: { id: string; expiresAt: string; createdAt: string };
  authorization?: {
    active: boolean;
    tokenId?: string;
    expiresAt?: string;
    ttlSeconds?: number;
  };
  csrfToken?: string;
}

interface AuditEntry {
  id: string;
  eventType: string;
  outcome: string;
  ipAddress: string;
  createdAt: string;
  metadata: Record<string, unknown>;
}

export default function DashboardPage() {
  const router = useRouter();
  const [session, setSession] = useState<SessionState | null>(null);
  const [isConnecting, setIsConnecting] = useState(false);
  const [isLaunching, setIsLaunching] = useState(false);
  const [connectError, setConnectError] = useState<string | null>(null);
  const [countdown, setCountdown] = useState<number>(0);
  const [auditLogs, setAuditLogs] = useState<AuditEntry[]>([]);
  const [time, setTime] = useState("");
  const [sessionTimeLeft, setSessionTimeLeft] = useState("");

  // Live ZULU clock
  useEffect(() => {
    const tick = () => setTime(new Date().toISOString().slice(11, 19) + " ZULU");
    tick();
    const i = setInterval(tick, 1000);
    return () => clearInterval(i);
  }, []);

  // Fetch session state
  const fetchSession = useCallback(async () => {
    try {
      const res = await fetch("/api/auth/session");
      const data: SessionState = await res.json();
      if (!data.authenticated) { router.replace("/"); return; }
      setSession(data);
      if (data.authorization?.active && data.authorization.ttlSeconds) {
        setCountdown(data.authorization.ttlSeconds);
      }
    } catch {
      router.replace("/");
    }
  }, [router]);

  useEffect(() => { fetchSession(); }, [fetchSession]);

  // Authorization countdown
  useEffect(() => {
    if (countdown <= 0) return;
    const t = setTimeout(() => {
      setCountdown((p) => {
        if (p <= 1) { fetchSession(); return 0; }
        return p - 1;
      });
    }, 1000);
    return () => clearTimeout(t);
  }, [countdown, fetchSession]);

  // Session time remaining
  useEffect(() => {
    if (!session?.session?.expiresAt) return;
    const tick = () => {
      const remaining = new Date(session.session!.expiresAt).getTime() - Date.now();
      if (remaining <= 0) { router.replace("/"); return; }
      const days = Math.floor(remaining / 86400000);
      const hours = Math.floor((remaining % 86400000) / 3600000);
      const mins = Math.floor((remaining % 3600000) / 60000);
      setSessionTimeLeft(`${days}D ${String(hours).padStart(2, "0")}H ${String(mins).padStart(2, "0")}M`);
    };
    tick();
    const i = setInterval(tick, 30000);
    return () => clearInterval(i);
  }, [session, router]);

  // Fetch recent connect logs
  const fetchLogs = useCallback(async () => {
    try {
      const res = await fetch("/api/admin/audit-logs?stream=CONNECT&limit=10", {
        headers: { "X-Admin-Secret": "dev-admin-secret" },
      });
      const data = await res.json();
      setAuditLogs(data.logs ?? []);
    } catch {}
  }, []);

  useEffect(() => { fetchLogs(); }, [fetchLogs]);

  const handleConnect = async () => {
    setIsConnecting(true);
    setConnectError(null);
    try {
      const res = await fetch("/api/connect", {
        method: "POST",
        headers: session?.csrfToken ? { "x-csrf-token": session.csrfToken } : {},
      });
      const data = await res.json();
      if (res.status === 403) {
        setConnectError("SECURITY CHECK FAILED. REFRESH AND TRY AGAIN.");
        return;
      }
      if (res.status === 429) {
        setConnectError("RATE LIMIT EXCEEDED. TRY AGAIN LATER.");
        return;
      }
      if (!res.ok) {
        setConnectError(data.error ?? "CONNECTION DENIED");
        return;
      }
      if (data.granted) {
        setCountdown(data.ttlSeconds);
        await fetchSession();
        await fetchLogs();
      }
    } catch {
      setConnectError("CONNECTION FAILED — CHECK SYSTEM STATUS");
    } finally {
      setIsConnecting(false);
    }
  };

  const handleLaunchOperationsDesk = async () => {
    setIsLaunching(true);
    setConnectError(null);
    try {
      const res = await fetch("/api/authz/code", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ targetApp: "operations-desk" }),
      });
      const data = await res.json();
      if (data.success && data.targetUrl) {
        window.location.href = data.targetUrl;
      } else {
        setConnectError(data.error ?? "FAILED TO ISSUE GATEWAY CODE");
      }
    } catch {
      setConnectError("GATEWAY COMMUNICATION FAILURE");
    } finally {
      setIsLaunching(false);
    }
  };

  const handleLogout = async () => {
    await fetch("/api/auth/logout", { method: "POST" });
    router.replace("/");
  };

  const isAuthorized = session?.authorization?.active && countdown > 0;
  const formatCountdown = (s: number) =>
    `${String(Math.floor(s / 60)).padStart(2, "0")}:${String(s % 60).padStart(2, "0")}`;

  if (!session) {
    return (
      <div className="h-screen w-screen bg-background flex items-center justify-center text-primary font-data-mono text-sm">
        <span className="animate-pulse">&gt; LOADING SYSTEM...</span>
      </div>
    );
  }

  return (
    <div className="h-screen w-screen overflow-auto flex flex-col bg-background text-primary relative">
      <div className="absolute inset-0 scanlines z-50 mix-blend-screen opacity-20 pointer-events-none" />

      {/* Instrument strip header */}
      <header
        className="w-full h-12 border-b border-outline-variant bg-surface flex justify-between items-center px-4 shrink-0 font-status-code text-xs text-on-surface-variant z-40 sticky top-0"
        style={{ boxShadow: "0 0 15px rgba(0,230,57,0.2)" }}
      >
        <div className="flex items-center gap-6">
          <span className="font-display-lg text-lg font-bold text-primary tracking-widest uppercase">GATEZERO</span>
          <span className="flex items-center gap-2">
            <span className="w-2 h-2 rounded-full bg-primary animate-pulse" style={{ boxShadow: "0 0 8px #00ff41" }} />
            SYS.ONLINE
          </span>
          <span>UPLINK: STABLE</span>
        </div>
        <div className="flex items-center gap-6">
          <span>OP: {session.user?.name.toUpperCase().replace(" ", "_")}</span>
          <span>SESSION: {sessionTimeLeft}</span>
          <span className="text-primary font-bold">{time}</span>
          <button
            onClick={handleLogout}
            className="text-on-surface-variant hover:text-error transition-colors"
          >
            [LOGOUT]
          </button>
        </div>
      </header>

      {/* Main content */}
      <div className="flex-1 flex flex-col gap-6 p-6 max-w-6xl mx-auto w-full">

        {/* Row 1: Barrier status + Connect panel */}
        <div className="flex flex-col lg:flex-row gap-6">

          {/* Barrier Status */}
          <div className="industrial-grid flex-1">
            <div className="panel-recessed p-6 flex flex-col relative h-full min-h-[280px]">
              <div className="flex justify-between items-start mb-6 border-b border-primary/20 pb-4">
                <div className="font-data-mono text-sm text-primary">BARRIER STATUS</div>
                <div className="flex items-center gap-2">
                  <span className={`w-2 h-2 ${isAuthorized ? "bg-primary animate-pulse" : "bg-on-surface-variant"}`}
                    style={isAuthorized ? { boxShadow: "0 0 8px #00ff41" } : {}} />
                  <span className={`font-status-code text-xs font-bold ${isAuthorized ? "text-primary" : "text-on-surface-variant"}`}>
                    {isAuthorized ? "GRANTED // OPEN" : "IDLE // LOCKED"}
                  </span>
                </div>
              </div>

              {/* Barrier visualization */}
              <div className={`w-full flex-1 relative border-2 flex items-center justify-center overflow-hidden barrier-container ${isAuthorized ? "granted" : ""}`}
                style={isAuthorized
                  ? { borderColor: "#00ff41", boxShadow: "0 0 30px rgba(0,255,65,0.15)" }
                  : { borderColor: "#1a1a1a", boxShadow: "inset 0 0 20px rgba(0,255,65,0.08)" }}>
                {isAuthorized && (
                  <div className="absolute inset-0 flex flex-col items-center justify-center"
                    style={{ background: "radial-gradient(ellipse at center, rgba(0,255,65,0.2) 0%, transparent 70%)" }}>
                    <span className="font-data-mono text-2xl text-primary animate-pulse font-bold"
                      style={{ textShadow: "0 0 10px #00ff41" }}>ACCESS GRANTED</span>
                    <span className="font-data-mono text-sm text-primary mt-2">
                      DOOR SECURES IN {formatCountdown(countdown)}
                    </span>
                  </div>
                )}
                <div className={`absolute w-full h-1/2 top-0 bg-surface border-b-2 leaf-top flex items-end justify-center pb-2 barrier-leaf z-10 ${isAuthorized ? "border-primary" : "barrier-glow-idle"}`}
                  style={isAuthorized ? { boxShadow: "0 4px 20px rgba(0,255,65,0.4)" } : {}}>
                  <div className="w-24 h-3 rounded-sm flex items-center justify-center bg-primary"
                    style={{ boxShadow: isAuthorized ? "0 0 15px #00ff41" : "0 0 10px #00ff41" }}>
                    <div className="w-1/2 h-[1px] bg-background" />
                  </div>
                </div>
                <div className={`absolute w-full h-1/2 bottom-0 bg-surface border-t-2 leaf-bottom flex items-start justify-center pt-2 barrier-leaf z-10 ${isAuthorized ? "border-primary" : "barrier-glow-idle"}`}
                  style={isAuthorized ? { boxShadow: "0 -4px 20px rgba(0,255,65,0.4)" } : {}}>
                  <div className="w-24 h-3 bg-primary rounded-sm flex items-center justify-center"
                    style={{ boxShadow: "0 0 10px #00ff41" }}>
                    <div className="w-1/2 h-[1px] bg-background" />
                  </div>
                </div>
                {!isAuthorized && (
                  <div className="absolute z-20 pointer-events-none">
                    <span className="material-symbols-outlined text-4xl text-primary m-icon-fill"
                      style={{ textShadow: "0 0 10px #00ff41" }}>door_front</span>
                  </div>
                )}
              </div>
            </div>
          </div>

          {/* Connect + Auth panel */}
          <div className="industrial-grid lg:w-88">
            <div className="panel-recessed p-6 flex flex-col gap-4">
              <div className="font-data-mono text-sm text-primary border-b border-primary/20 pb-3">
                GATE CONTROL
              </div>

              {/* Session info */}
              <div className="border border-outline-variant p-3 flex flex-col gap-1">
                <div className="font-status-code text-xs text-on-surface-variant">OPERATOR</div>
                <div className="font-data-mono text-sm text-primary">{session.user?.email}</div>
                <div className="font-status-code text-xs text-on-surface-variant mt-1">SESSION EXPIRES</div>
                <div className="font-data-mono text-sm text-primary">{sessionTimeLeft}</div>
                <div className="font-status-code text-xs text-on-surface-variant mt-1">ROLE</div>
                <div className="font-data-mono text-sm text-primary">{session.user?.role}</div>
              </div>

              {/* Launch Website 2 Button */}
              <button
                onClick={handleLaunchOperationsDesk}
                disabled={isLaunching}
                className="w-full py-3 px-4 border-2 border-emerald-400 bg-emerald-950/40 hover:bg-emerald-900/60 transition-colors text-emerald-300 font-data-mono text-xs tracking-wider font-bold rounded flex items-center justify-center gap-2 shadow-lg disabled:opacity-50"
              >
                <span>{isLaunching ? "GENERATING GATEWAY HANDSHAKE..." : "🚀 [LAUNCH THE OPERATIONS DESK :3002] →"}</span>
              </button>

              {/* Connect button for barrier simulation */}
              <button
                onClick={handleConnect}
                disabled={isConnecting}
                className="w-full h-10 border border-primary/50 bg-graphite hover:bg-primary/10 transition-colors text-primary font-data-mono text-xs tracking-widest relative overflow-hidden group disabled:opacity-50"
              >
                <span className="relative z-10">
                  {isConnecting ? "REQUESTING..." : "[SIMULATE BARRIER PASS]"}
                </span>
                <div className="absolute bottom-0 left-0 w-full h-[2px] bg-primary scale-x-0 group-hover:scale-x-100 transition-transform origin-left" />
              </button>

              {connectError && (
                <div className="p-2 border border-error/50 bg-error/5 text-error font-status-code text-xs">
                  &gt; ERR: {connectError}
                </div>
              )}

              {/* Revocation info */}
              <p className="font-status-code text-[11px] text-on-surface-variant/60">
                GATEZERO TOKEN TTL: 5M // PER-REQUEST INTROSPECTION ENFORCED
              </p>
            </div>
          </div>
        </div>

        {/* Row 2: Access Log Manifest */}
        <div className="industrial-grid">
          <div className="panel-recessed flex flex-col h-64">
            <div className="p-3 border-b border-primary/30 font-data-mono text-sm text-primary flex justify-between bg-primary/5">
              <span>ACCESS LOG MANIFEST</span>
              <span className="text-on-surface-variant text-xs">GATEWAY AUDIT STREAM</span>
            </div>
            <div className="flex-1 overflow-auto p-4 flex flex-col font-data-mono text-xs">
              {auditLogs.length === 0 ? (
                <div className="flex-1 flex items-center justify-center text-primary/40 tracking-widest uppercase">
                  NO RECENT ACTIVITY DETECTED
                </div>
              ) : (
                auditLogs.map((log) => (
                  <div key={log.id} className="flex justify-between py-1 border-b border-primary/10 hover:bg-primary/5 px-2">
                    <span className="text-on-surface-variant font-data-mono">
                      [{new Date(log.createdAt).toISOString().slice(11, 19)}]
                    </span>
                    <span className="text-primary font-bold">{log.eventType}</span>
                    <span className="text-on-surface-variant">{log.ipAddress}</span>
                    <span className={log.outcome === "SUCCESS" ? "text-primary" : "text-error"}>
                      {log.outcome}
                    </span>
                  </div>
                ))
              )}
            </div>
          </div>
        </div>

      </div>

      <footer className="w-full h-8 flex justify-between items-center px-4 bg-surface-container-lowest border-t border-outline-variant text-on-surface-variant font-status-code text-xs">
        <div>© GATEZERO v1.0.0 — ZERO TRUST ACCESS GATEWAY</div>
        <div>UPLINK: ENCRYPTED // PORT 3000</div>
      </footer>
    </div>
  );
}
