"use client";

import { useState, useEffect, useCallback } from "react";
import { useRouter } from "next/navigation";
import {
  createDeviceKey,
  getDeviceKey,
  signChallenge,
  detectHardwareBacking,
} from "@/lib/device/client";

interface DeviceState {
  registered: boolean;
  credentialId?: string;
  label?: string;
  assurance?: string;
  hardwareBacked?: boolean;
  usable?: boolean;
  rotationDue?: boolean;
  pendingApproval?: { id: string; label: string } | null;
}

interface SessionState {
  authenticated: boolean;
  user?: { name: string; email: string; role: string; accessRevoked?: boolean };
  session?: {
    id: string;
    expiresAt: string;
    createdAt: string;
    stepUpRequired?: boolean;
    mfaOverridden?: boolean;
    connectCooldownSeconds?: number;
  };
  device?: DeviceState;
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
  const [isEnrolling, setIsEnrolling] = useState(false);
  const [deviceNotice, setDeviceNotice] = useState<string | null>(null);
  const [stepUpCode, setStepUpCode] = useState("");
  const [stepUpBusy, setStepUpBusy] = useState(false);

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

  // Device enrolment (website-2-defense.md 4, 6)
  //
  // The private key is generated here with extractable:false and stored in
  // IndexedDB. It never leaves the browser - not to this page, not to the
  // server. What is sent is the public key plus a signature over the server's
  // own challenge, which proves the device actually holds the private half.
  const handleEnrolDevice = async () => {
    setIsEnrolling(true);
    setDeviceNotice(null);
    setConnectError(null);
    try {
      const key = await createDeviceKey();

      const challengeRes = await fetch("/api/device/challenge", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ purpose: "REGISTRATION" }),
      });
      if (!challengeRes.ok) {
        setConnectError("COULD NOT START DEVICE ENROLMENT");
        return;
      }
      const { nonce } = await challengeRes.json();
      const signature = await signChallenge(key, "website-1", "REGISTRATION", nonce);

      const res = await fetch("/api/device", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          ...(session?.csrfToken ? { "x-csrf-token": session.csrfToken } : {}),
        },
        body: JSON.stringify({
          label: (navigator.platform || "BROWSER") + " " + new Date().toISOString().slice(0, 10),
          publicKeySpki: key.publicKeySpki,
          hardwareBacked: await detectHardwareBacking(),
          nonce,
          signature,
        }),
      });

      const data = await res.json();
      if (!res.ok) {
        setConnectError(data.error ?? "DEVICE ENROLMENT REFUSED");
        return;
      }

      setDeviceNotice(
        data.status === "ACTIVE"
          ? "DEVICE ENROLLED AND ACTIVE."
          : "DEVICE ENROLLED. AWAITING ADMINISTRATOR APPROVAL."
      );
      await fetchSession();
    } catch {
      setConnectError("DEVICE ENROLMENT FAILED IN THIS BROWSER");
    } finally {
      setIsEnrolling(false);
    }
  };

  // Connect (website-1-defense.md 4, 8)
  //
  // Connect now carries a device proof. The nonce is fetched fresh from the
  // server and signed with the non-extractable device key, so a Connect request
  // cannot be replayed and cannot be issued by a browser that merely holds a
  // stolen session cookie.
  const handleConnect = async () => {
    setIsConnecting(true);
    setConnectError(null);
    try {
      const key = await getDeviceKey();
      if (!key) {
        setConnectError("NO DEVICE CREDENTIAL IN THIS BROWSER - ENROL THIS DEVICE FIRST");
        return;
      }

      const challengeRes = await fetch("/api/device/challenge", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ purpose: "CONNECT" }),
      });
      if (!challengeRes.ok) {
        setConnectError("COULD NOT OBTAIN A DEVICE CHALLENGE");
        return;
      }
      const { nonce } = await challengeRes.json();
      const signature = await signChallenge(key, "website-1", "CONNECT", nonce);

      const res = await fetch("/api/connect", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          ...(session?.csrfToken ? { "x-csrf-token": session.csrfToken } : {}),
        },
        body: JSON.stringify({ nonce, signature }),
      });
      const data = await res.json();

      if (res.status === 401 && data.code === "SESSION_TERMINATED_RISK") {
        router.replace("/");
        return;
      }
      if (res.status === 403 && data.code === "STEP_UP_MFA_REQUIRED") {
        setConnectError("FRESH MFA REQUIRED - COMPLETE STEP-UP BELOW");
        await fetchSession();
        return;
      }
      if (res.status === 403) {
        setConnectError(data.error ?? "SECURITY CHECK FAILED");
        await fetchSession();
        return;
      }
      if (res.status === 429) {
        setConnectError("RATE LIMITED OR IN COOLDOWN. TRY AGAIN LATER.");
        await fetchSession();
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
      setConnectError("CONNECTION FAILED - CHECK SYSTEM STATUS");
    } finally {
      setIsConnecting(false);
    }
  };

  // Step-up MFA (7 MEDIUM risk, 15 override)
  const handleStepUpSend = async () => {
    setStepUpBusy(true);
    setConnectError(null);
    try {
      await fetch("/api/auth/step-up", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ action: "send" }),
      });
      setDeviceNotice("VERIFICATION CODE SENT TO YOUR REGISTERED EMAIL.");
    } catch {
      setConnectError("COULD NOT SEND VERIFICATION CODE");
    } finally {
      setStepUpBusy(false);
    }
  };

  const handleStepUpVerify = async () => {
    setStepUpBusy(true);
    setConnectError(null);
    try {
      const res = await fetch("/api/auth/step-up", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ code: stepUpCode }),
      });
      const data = await res.json();
      if (!res.ok || !data.success) {
        setConnectError(data.error ?? "VERIFICATION FAILED");
        return;
      }
      setStepUpCode("");
      setDeviceNotice("VERIFIED. CONNECT IS AVAILABLE AGAIN.");
      await fetchSession();
    } catch {
      setConnectError("VERIFICATION FAILED");
    } finally {
      setStepUpBusy(false);
    }
  };

  const handleLaunchOperationsDesk = async () => {
    setIsLaunching(true);
    setConnectError(null);
    try {
      const res = await fetch("/api/authz/code", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          ...(session?.csrfToken ? { "x-csrf-token": session.csrfToken } : {}),
        },
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
  const device = session?.device;
  const stepUpRequired = Boolean(session?.session?.stepUpRequired);
  const cooldownSeconds = session?.session?.connectCooldownSeconds ?? 0;
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

              {/* Device credential state (website-1-defense.md 8) */}
              <div className="border border-outline-variant p-3 flex flex-col gap-2">
                <div className="font-status-code text-xs text-on-surface-variant">
                  DEVICE CREDENTIAL
                </div>

                {device?.registered ? (
                  <>
                    <div className="font-data-mono text-sm text-primary break-all">
                      {device.label}
                    </div>
                    <div className="font-status-code text-[11px] text-on-surface-variant">
                      ASSURANCE: {device.assurance}
                      {device.hardwareBacked ? " // HARDWARE-BACKED" : " // SOFTWARE-PROTECTED"}
                    </div>
                    {device.rotationDue && (
                      <div className="font-status-code text-[11px] text-amber-400">
                        ROTATION DUE - RE-ATTEST BEFORE THE GRACE PERIOD ENDS
                      </div>
                    )}
                    {!device.usable && (
                      <div className="font-status-code text-[11px] text-error">
                        CREDENTIAL NOT USABLE - CONNECT WILL BE REFUSED
                      </div>
                    )}
                  </>
                ) : (
                  <>
                    <div className="font-data-mono text-sm text-error">NOT ENROLLED</div>
                    <p className="font-status-code text-[11px] text-on-surface-variant/70">
                      A device key is required before Connect can issue an authorization.
                      The private key is generated in this browser and never leaves it.
                    </p>
                    {device?.pendingApproval && (
                      <div className="font-status-code text-[11px] text-amber-400">
                        AWAITING ADMINISTRATOR APPROVAL
                      </div>
                    )}
                    <button
                      onClick={handleEnrolDevice}
                      disabled={isEnrolling}
                      className="w-full h-9 border border-primary/50 bg-graphite hover:bg-primary/10 transition-colors text-primary font-data-mono text-xs tracking-widest disabled:opacity-50"
                    >
                      {isEnrolling ? "ENROLLING..." : "[ENROL THIS DEVICE]"}
                    </button>
                  </>
                )}
              </div>

              {/* Step-up MFA gate (7 MEDIUM risk, 15 override) */}
              {stepUpRequired && (
                <div className="border border-amber-500/50 bg-amber-500/5 p-3 flex flex-col gap-2">
                  <div className="font-status-code text-xs text-amber-400">
                    FRESH MFA REQUIRED BEFORE CONNECT
                  </div>
                  <p className="font-status-code text-[11px] text-on-surface-variant/70">
                    {session.session?.mfaOverridden
                      ? "This session was created through an administrative MFA override."
                      : "A security check flagged this session."}{" "}
                    Your portal session is still active - only Connect is gated.
                  </p>
                  <div className="flex gap-2">
                    <button
                      onClick={handleStepUpSend}
                      disabled={stepUpBusy}
                      className="flex-1 h-9 border border-amber-500/50 text-amber-300 font-data-mono text-xs tracking-widest disabled:opacity-50"
                    >
                      [SEND CODE]
                    </button>
                    <input
                      value={stepUpCode}
                      onChange={(e) => setStepUpCode(e.target.value.replace(/\D/g, "").slice(0, 6))}
                      placeholder="000000"
                      inputMode="numeric"
                      className="w-24 h-9 bg-graphite border border-outline-variant text-primary font-data-mono text-sm text-center tracking-widest"
                    />
                    <button
                      onClick={handleStepUpVerify}
                      disabled={stepUpBusy || stepUpCode.length !== 6}
                      className="flex-1 h-9 border border-primary/50 text-primary font-data-mono text-xs tracking-widest disabled:opacity-50"
                    >
                      [VERIFY]
                    </button>
                  </div>
                </div>
              )}

              {cooldownSeconds > 0 && (
                <div className="p-2 border border-error/50 bg-error/5 text-error font-status-code text-xs">
                  &gt; CONNECT COOLDOWN ACTIVE: {cooldownSeconds}S REMAINING
                </div>
              )}

              {deviceNotice && (
                <div className="p-2 border border-primary/40 bg-primary/5 text-primary font-status-code text-xs">
                  &gt; {deviceNotice}
                </div>
              )}

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
                disabled={
                  isConnecting || !device?.usable || stepUpRequired || cooldownSeconds > 0
                }
                className="w-full h-10 border border-primary/50 bg-graphite hover:bg-primary/10 transition-colors text-primary font-data-mono text-xs tracking-widest relative overflow-hidden group disabled:opacity-50"
              >
                <span className="relative z-10">
                  {isConnecting ? "REQUESTING..." : "[CONNECT - REQUEST AUTHORIZATION]"}
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
                AUTHORIZATION: 5M // ONE-TIME // DEVICE-BOUND
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
