"use client";

import { useState, useEffect, useCallback } from "react";
import { useRouter } from "next/navigation";

const ADMIN_SECRET = "dev-admin-secret";

interface Session {
  id: string;
  status: string;
  user: { email: string; name: string; role: string };
  ipAddress: string;
  createdAt: string;
  expiresAt: string;
  activeAuthorizations: number;
}

interface AuditLog {
  id: string;
  stream: string;
  eventType: string;
  user?: { email: string };
  sessionId?: string;
  authzId?: string;
  ipAddress: string;
  outcome: string;
  metadata: Record<string, unknown>;
  createdAt: string;
}

export default function AdminPage() {
  const router = useRouter();
  const [sessions, setSessions] = useState<Session[]>([]);
  const [logs, setLogs] = useState<AuditLog[]>([]);
  const [logStream, setLogStream] = useState<"LOGIN" | "CONNECT">("LOGIN");
  const [isLoading, setIsLoading] = useState(true);
  const [time, setTime] = useState("");
  const [actionMsg, setActionMsg] = useState<string | null>(null);

  useEffect(() => {
    const tick = () => setTime(new Date().toISOString().slice(11, 19) + " ZULU");
    tick();
    const i = setInterval(tick, 1000);
    return () => clearInterval(i);
  }, []);

  const fetchData = useCallback(async () => {
    setIsLoading(true);
    try {
      const [sessRes, logRes] = await Promise.all([
        fetch("/api/admin/sessions", { headers: { "X-Admin-Secret": ADMIN_SECRET } }),
        fetch(`/api/admin/audit-logs?stream=${logStream}&limit=50`, {
          headers: { "X-Admin-Secret": ADMIN_SECRET },
        }),
      ]);
      if (sessRes.status === 403) { router.replace("/"); return; }
      setSessions((await sessRes.json()).sessions ?? []);
      setLogs((await logRes.json()).logs ?? []);
    } catch {
      router.replace("/");
    } finally {
      setIsLoading(false);
    }
  }, [logStream, router]);

  useEffect(() => { fetchData(); }, [fetchData]);

  const revokeSession = async (sessionId: string) => {
    try {
      await fetch("/api/admin/sessions", {
        method: "DELETE",
        headers: { "Content-Type": "application/json", "X-Admin-Secret": ADMIN_SECRET },
        body: JSON.stringify({ sessionId }),
      });
      setActionMsg(`SESSION ${sessionId.slice(0, 8)}... REVOKED`);
      fetchData();
    } catch { setActionMsg("REVOKE FAILED"); }
  };

  const revokeAuthz = async (tokenId: string) => {
    try {
      await fetch("/api/authz/revoke", {
        method: "POST",
        headers: { "Content-Type": "application/json", "X-Admin-Secret": ADMIN_SECRET },
        body: JSON.stringify({ tokenId }),
      });
      setActionMsg(`AUTHZ TOKEN ${tokenId.slice(0, 8)}... REVOKED`);
      fetchData();
    } catch { setActionMsg("REVOKE FAILED"); }
  };

  return (
    <div className="min-h-screen bg-background text-primary relative">
      <div className="absolute inset-0 scanlines z-50 mix-blend-screen opacity-20 pointer-events-none" />

      {/* Header */}
      <header className="w-full h-12 border-b border-outline-variant bg-surface flex justify-between items-center px-4 font-status-code text-xs text-on-surface-variant z-40 sticky top-0">
        <div className="flex items-center gap-6">
          <span className="font-display-lg text-lg font-bold text-primary tracking-widest uppercase">GATEZERO</span>
          <span className="text-error font-bold">ADMIN CONSOLE</span>
        </div>
        <div className="flex items-center gap-6">
          <a href="/dashboard" className="hover:text-primary transition-colors">[DASHBOARD]</a>
          <span className="text-primary">{time}</span>
        </div>
      </header>

      <div className="max-w-7xl mx-auto p-6 flex flex-col gap-6">

        {/* Action message */}
        {actionMsg && (
          <div className="border border-primary/50 bg-primary/5 p-3 font-data-mono text-sm text-primary flex justify-between">
            <span>&gt; {actionMsg}</span>
            <button onClick={() => setActionMsg(null)} className="text-on-surface-variant hover:text-primary">✕</button>
          </div>
        )}

        {/* Active Sessions */}
        <div className="industrial-grid">
          <div className="panel-recessed flex flex-col">
            <div className="p-3 border-b border-primary/30 font-data-mono text-sm text-primary flex justify-between bg-primary/5">
              <span>ACTIVE SESSIONS ({sessions.length})</span>
              <button onClick={fetchData} className="font-status-code text-xs text-on-surface-variant hover:text-primary transition-colors">[REFRESH]</button>
            </div>
            <div className="overflow-auto">
              {sessions.length === 0 ? (
                <div className="p-8 text-center text-primary/40 font-data-mono text-sm">NO ACTIVE SESSIONS</div>
              ) : (
                <table className="w-full font-data-mono text-xs border-collapse">
                  <thead>
                    <tr className="border-b border-outline-variant text-on-surface-variant">
                      <th className="text-left p-3">SESSION_ID</th>
                      <th className="text-left p-3">USER</th>
                      <th className="text-left p-3">STATUS</th>
                      <th className="text-left p-3">IP</th>
                      <th className="text-left p-3">EXPIRES</th>
                      <th className="text-left p-3">AUTH</th>
                      <th className="text-left p-3">ACTION</th>
                    </tr>
                  </thead>
                  <tbody>
                    {sessions.map((s) => (
                      <tr key={s.id} className="border-b border-outline-variant hover:bg-primary/5 transition-colors">
                        <td className="p-3 text-primary/70">{s.id.slice(0, 12)}...</td>
                        <td className="p-3">{s.user.email}</td>
                        <td className="p-3">
                          <span className={`px-2 py-1 text-xs font-bold ${s.status === "ACTIVE" ? "bg-primary/10 text-primary" : "bg-warning-amber/10 text-warning-amber"}`}>
                            {s.status}
                          </span>
                        </td>
                        <td className="p-3 text-on-surface-variant">{s.ipAddress}</td>
                        <td className="p-3 text-on-surface-variant">{new Date(s.expiresAt).toLocaleDateString()}</td>
                        <td className="p-3">
                          <span className={s.activeAuthorizations > 0 ? "text-primary" : "text-on-surface-variant"}>
                            {s.activeAuthorizations} ACTIVE
                          </span>
                        </td>
                        <td className="p-3">
                          <button
                            onClick={() => revokeSession(s.id)}
                            className="border border-error/50 bg-error/5 hover:bg-error/20 text-error px-2 py-1 font-label-caps text-xs transition-colors"
                          >
                            REVOKE
                          </button>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              )}
            </div>
          </div>
        </div>

        {/* Audit Logs */}
        <div className="industrial-grid">
          <div className="panel-recessed flex flex-col">
            <div className="p-3 border-b border-primary/30 font-data-mono text-sm text-primary flex justify-between bg-primary/5">
              <div className="flex gap-4">
                <span>AUDIT LOG:</span>
                <button
                  onClick={() => setLogStream("LOGIN")}
                  className={`font-label-caps text-xs px-2 py-1 transition-colors ${logStream === "LOGIN" ? "bg-primary text-background" : "text-on-surface-variant hover:text-primary"}`}
                >
                  LOGIN
                </button>
                <button
                  onClick={() => setLogStream("CONNECT")}
                  className={`font-label-caps text-xs px-2 py-1 transition-colors ${logStream === "CONNECT" ? "bg-primary text-background" : "text-on-surface-variant hover:text-primary"}`}
                >
                  CONNECT
                </button>
              </div>
              <span className="font-status-code text-xs text-on-surface-variant">{logs.length} RECORDS</span>
            </div>
            <div className="overflow-auto max-h-96">
              {logs.length === 0 ? (
                <div className="p-8 text-center text-primary/40 font-data-mono text-sm">NO LOG ENTRIES</div>
              ) : (
                <table className="w-full font-data-mono text-xs border-collapse">
                  <thead>
                    <tr className="border-b border-outline-variant text-on-surface-variant">
                      <th className="text-left p-3">TIME</th>
                      <th className="text-left p-3">EVENT</th>
                      <th className="text-left p-3">USER</th>
                      <th className="text-left p-3">IP</th>
                      <th className="text-left p-3">OUTCOME</th>
                      {logStream === "CONNECT" && <th className="text-left p-3">AUTHZ</th>}
                    </tr>
                  </thead>
                  <tbody>
                    {logs.map((log) => (
                      <tr key={log.id} className={`border-b border-outline-variant hover:bg-primary/5 transition-colors ${log.outcome === "FAILURE" || log.outcome === "DENIED" ? "text-error/80" : "text-primary"}`}>
                        <td className="p-3 text-on-surface-variant">{new Date(log.createdAt).toISOString().slice(11, 19)}</td>
                        <td className="p-3">{log.eventType}</td>
                        <td className="p-3 text-on-surface-variant">{log.user?.email ?? "—"}</td>
                        <td className="p-3 text-on-surface-variant">{log.ipAddress}</td>
                        <td className="p-3">
                          <span className={`font-bold ${log.outcome === "SUCCESS" ? "text-primary" : log.outcome === "DENIED" ? "text-error" : "text-warning-amber"}`}>
                            {log.outcome}
                          </span>
                        </td>
                        {logStream === "CONNECT" && (
                          <td className="p-3">
                            {log.authzId ? (
                              <button
                                onClick={() => revokeAuthz(log.authzId!)}
                                className="border border-error/30 hover:border-error/80 text-error/70 hover:text-error px-2 py-1 font-status-code text-xs transition-colors"
                              >
                                REVOKE
                              </button>
                            ) : "—"}
                          </td>
                        )}
                      </tr>
                    ))}
                  </tbody>
                </table>
              )}
            </div>
          </div>
        </div>
      </div>

      <footer className="w-full h-8 flex justify-between items-center px-4 bg-surface-container-lowest border-t border-outline-variant text-on-surface-variant font-status-code text-xs mt-6">
        <div>© GATEZERO INDUSTRIAL v1.0.0</div>
        <div>ADMIN CONSOLE — DEV MODE</div>
      </footer>
    </div>
  );
}
