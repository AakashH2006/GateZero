"use client";

import { useState, useEffect, Suspense } from "react";
import { useRouter, useSearchParams } from "next/navigation";

function LoginContent() {
  const router = useRouter();
  const searchParams = useSearchParams();
  const [isConnecting, setIsConnecting] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [time, setTime] = useState("");
  const [activeUser, setActiveUser] = useState<{ name?: string; email?: string } | null>(null);
  const [uiMode, setUiMode] = useState<"stealth" | "terminal">("stealth");
  
  // Interactive Navigation State
  const [activeTab, setActiveTab] = useState<"overview" | "services" | "telemetry" | "docs">("overview");
  const [activeModal, setActiveModal] = useState<"privacy" | "terms" | null>(null);

  // Live clock
  useEffect(() => {
    const tick = () => {
      const now = new Date();
      setTime(now.toISOString().slice(11, 19) + " UTC");
    };
    tick();
    const interval = setInterval(tick, 1000);
    return () => clearInterval(interval);
  }, []);

  // Show errors from query params
  useEffect(() => {
    const err = searchParams.get("error");
    if (err) {
      const messages: Record<string, string> = {
        sso_failed: "SSO authentication failed. Please try again.",
        invalid_state: "Security state mismatch. Please try again.",
        token_exchange_failed: "Identity verification failed. Please try again.",
        missing_verifier: "Session data missing. Please try again.",
        mfa_timeout: "MFA challenge timed out. Please sign in again.",
      };
      setError(messages[err] ?? "An error occurred. Please try again.");
    }
  }, [searchParams]);

  // Check if authenticated
  useEffect(() => {
    fetch("/api/auth/session")
      .then((r) => r.json())
      .then((data) => {
        if (data.authenticated && data.user) {
          setActiveUser({ name: data.user.name, email: data.user.email });
        }
      })
      .catch(() => {});
  }, []);

  const handleLogin = () => {
    setIsConnecting(true);
    window.location.href = "/api/auth/login";
  };

  const handleGoToDashboard = () => {
    router.push("/dashboard");
  };

  // ── 1. STEALTH / CAMOUFLAGE UI MODE ─────────────────────────────────────────
  if (uiMode === "stealth") {
    return (
      <div className="min-h-screen w-full bg-[#06080d] text-slate-100 font-sans flex flex-col justify-between relative overflow-x-hidden selection:bg-blue-600 selection:text-white">
        
        {/* Ambient background glow effects */}
        <div className="absolute top-0 left-1/4 w-[600px] h-[600px] bg-blue-600/10 rounded-full blur-[140px] pointer-events-none" />
        <div className="absolute bottom-0 right-1/4 w-[500px] h-[500px] bg-indigo-600/10 rounded-full blur-[120px] pointer-events-none" />
        <div className="absolute top-1/2 right-10 w-[300px] h-[300px] bg-emerald-500/5 rounded-full blur-[100px] pointer-events-none" />

        {/* Top Navbar */}
        <header className="w-full h-20 border-b border-slate-800/80 bg-[#080b12]/80 backdrop-blur-xl flex justify-between items-center px-6 md:px-16 sticky top-0 z-50 shadow-lg shadow-black/40">
          <div className="flex items-center gap-10">
            <div 
              onClick={() => setActiveTab("overview")}
              className="flex items-center gap-3 group cursor-pointer"
            >
              <div className="w-10 h-10 rounded-xl bg-gradient-to-tr from-blue-600 to-indigo-500 flex items-center justify-center font-bold text-white shadow-lg shadow-blue-500/25 group-hover:scale-105 transition-transform">
                N
              </div>
              <div className="flex flex-col">
                <span className="font-bold text-lg tracking-tight text-white flex items-center gap-1">
                  Nexus<span className="text-blue-500">Dynamics</span>
                </span>
                <span className="text-[10px] text-slate-400 font-mono tracking-wider">ENTERPRISE PLATFORM</span>
              </div>
            </div>

            {/* Interactive Navigation Bar Tabs */}
            <nav className="hidden md:flex items-center gap-8 text-sm font-medium">
              <button
                onClick={() => setActiveTab("overview")}
                className={`transition-all py-1 border-b-2 ${
                  activeTab === "overview"
                    ? "text-white font-semibold border-blue-500"
                    : "text-slate-400 border-transparent hover:text-slate-200"
                }`}
              >
                Overview
              </button>
              <button
                onClick={() => setActiveTab("services")}
                className={`transition-all py-1 border-b-2 ${
                  activeTab === "services"
                    ? "text-white font-semibold border-blue-500"
                    : "text-slate-400 border-transparent hover:text-slate-200"
                }`}
              >
                Services
              </button>
              <button
                onClick={() => setActiveTab("telemetry")}
                className={`transition-all py-1 border-b-2 ${
                  activeTab === "telemetry"
                    ? "text-white font-semibold border-blue-500"
                    : "text-slate-400 border-transparent hover:text-slate-200"
                }`}
              >
                Telemetry Mesh
              </button>
              <button
                onClick={() => setActiveTab("docs")}
                className={`transition-all py-1 border-b-2 ${
                  activeTab === "docs"
                    ? "text-white font-semibold border-blue-500"
                    : "text-slate-400 border-transparent hover:text-slate-200"
                }`}
              >
                Documentation
              </button>
            </nav>
          </div>

          <div className="flex items-center gap-5 text-xs font-mono">
            <div className="hidden sm:flex items-center gap-2 px-3 py-1.5 rounded-full bg-emerald-950/40 border border-emerald-500/30 text-emerald-400 shadow-sm">
              <span className="w-2 h-2 rounded-full bg-emerald-400 animate-pulse shadow-[0_0_8px_#10b981]" />
              <span>All Systems Operational</span>
            </div>
            <div className="text-slate-400 bg-slate-900/60 px-3 py-1.5 rounded-lg border border-slate-800">
              {time}
            </div>
          </div>
        </header>

        {/* Main Content Area — Renders based on activeTab */}
        <main className="flex-1 flex flex-col items-center justify-center px-6 md:px-16 py-12 max-w-7xl mx-auto w-full z-10">
          
          {/* Active Session Alert Banner */}
          {activeUser && (
            <div className="w-full mb-8 p-4 rounded-2xl bg-gradient-to-r from-blue-950/60 via-indigo-950/40 to-slate-900/60 border border-blue-500/30 backdrop-blur-md flex flex-col sm:flex-row items-center justify-between gap-4 shadow-xl">
              <div className="flex items-center gap-3 text-left">
                <div className="w-3 h-3 rounded-full bg-emerald-400 animate-ping" />
                <div>
                  <span className="text-xs text-blue-400 font-mono uppercase tracking-wider block">Active Session Detected</span>
                  <span className="text-sm font-medium text-white">Signed in as {activeUser.name} ({activeUser.email})</span>
                </div>
              </div>
              <div className="flex items-center gap-3 w-full sm:w-auto">
                <button
                  onClick={handleGoToDashboard}
                  className="w-full sm:w-auto px-5 py-2 rounded-xl bg-blue-600 hover:bg-blue-500 text-white font-medium text-xs transition-all shadow-md shadow-blue-500/20"
                >
                  Go to Operations Dashboard →
                </button>
              </div>
            </div>
          )}

          {/* TAB 1: OVERVIEW */}
          {activeTab === "overview" && (
            <div className="w-full grid grid-cols-1 lg:grid-cols-12 gap-12 items-center">
              
              {/* Left Column — Hero Text & Metrics */}
              <div className="lg:col-span-7 flex flex-col gap-6 text-left">
                <div className="inline-flex items-center gap-2 px-3.5 py-1.5 rounded-full bg-blue-500/10 border border-blue-500/20 text-blue-400 text-xs font-mono w-fit backdrop-blur-md">
                  <span className="w-1.5 h-1.5 rounded-full bg-blue-400" />
                  <span>Enterprise Resource Portal v4.18.2</span>
                </div>
                
                <h1 className="text-4xl sm:text-5xl font-extrabold tracking-tight text-white leading-[1.15]">
                  Next-Generation Infrastructure &amp;{" "}
                  <span className="bg-gradient-to-r from-blue-400 via-indigo-300 to-emerald-400 bg-clip-text text-transparent">
                    Service Mesh Control
                  </span>
                </h1>
                
                <p className="text-slate-400 text-base sm:text-lg leading-relaxed max-w-2xl">
                  Unified telemetry, automated service discovery, and multi-cloud environment access for Nexus Dynamics engineering and operation teams.
                </p>

                {/* Live Metric Cards */}
                <div className="grid grid-cols-2 sm:grid-cols-3 gap-4 pt-4 border-t border-slate-800/80">
                  <div 
                    onClick={() => setActiveTab("telemetry")}
                    className="bg-[#0b0f19]/80 backdrop-blur-md p-4 rounded-2xl border border-slate-800/80 shadow-lg hover:border-slate-700/80 transition-colors cursor-pointer group"
                  >
                    <div className="text-xs text-slate-400 mb-1 flex items-center justify-between">
                      <span>API Mesh Latency</span>
                      <span className="w-2 h-2 rounded-full bg-emerald-400 group-hover:scale-125 transition-transform" />
                    </div>
                    <div className="text-lg font-bold font-mono text-emerald-400">3.8 ms</div>
                    <div className="text-[10px] text-slate-500 mt-1">Edge Nodes Active →</div>
                  </div>

                  <div 
                    onClick={() => setActiveTab("services")}
                    className="bg-[#0b0f19]/80 backdrop-blur-md p-4 rounded-2xl border border-slate-800/80 shadow-lg hover:border-slate-700/80 transition-colors cursor-pointer group"
                  >
                    <div className="text-xs text-slate-400 mb-1 flex items-center justify-between">
                      <span>Cluster Health</span>
                      <span className="w-2 h-2 rounded-full bg-blue-400 group-hover:scale-125 transition-transform" />
                    </div>
                    <div className="text-lg font-bold font-mono text-slate-100">24 / 24</div>
                    <div className="text-[10px] text-slate-500 mt-1">Services List →</div>
                  </div>

                  <div 
                    onClick={() => setActiveTab("docs")}
                    className="bg-[#0b0f19]/80 backdrop-blur-md p-4 rounded-2xl border border-slate-800/80 shadow-lg hover:border-slate-700/80 transition-colors col-span-2 sm:col-span-1 cursor-pointer group"
                  >
                    <div className="text-xs text-slate-400 mb-1 flex items-center justify-between">
                      <span>Monthly SLA</span>
                      <span className="w-2 h-2 rounded-full bg-indigo-400 group-hover:scale-125 transition-transform" />
                    </div>
                    <div className="text-lg font-bold font-mono text-blue-400">99.998%</div>
                    <div className="text-[10px] text-slate-500 mt-1">Read SLA Docs →</div>
                  </div>
                </div>
              </div>

              {/* Right Column — SSO Sign-In Card */}
              <div className="lg:col-span-5 w-full">
                <div className="bg-[#0c1019]/90 border border-slate-800/90 rounded-3xl p-8 sm:p-10 shadow-2xl shadow-black/90 backdrop-blur-2xl flex flex-col gap-6 relative overflow-hidden group hover:border-slate-700/90 transition-all">
                  
                  {/* Top Glowing Gradient Accent line */}
                  <div className="absolute top-0 left-0 w-full h-1 bg-gradient-to-r from-blue-600 via-indigo-500 to-emerald-400" />

                  <div className="flex flex-col gap-2 text-left">
                    <div className="flex items-center justify-between">
                      <h2 className="text-2xl font-bold text-white">Employee Sign-In</h2>
                      <span className="px-2.5 py-1 rounded-md bg-blue-500/10 border border-blue-500/20 text-blue-400 text-[10px] font-mono">SSO + MFA</span>
                    </div>
                    <p className="text-xs text-slate-400 leading-relaxed">
                      Authenticate using your corporate Single Sign-On (SSO) identity provider.
                    </p>
                  </div>

                  {error && (
                    <div className="p-3.5 rounded-xl bg-rose-950/40 border border-rose-800/60 text-rose-300 text-xs font-mono text-left flex items-center gap-2">
                      <span>⚠️</span>
                      <span>{error}</span>
                    </div>
                  )}

                  <div className="flex flex-col gap-4">
                    <button
                      onClick={handleLogin}
                      disabled={isConnecting}
                      className="w-full py-4 px-6 rounded-2xl bg-gradient-to-r from-blue-600 to-indigo-600 hover:from-blue-500 hover:to-indigo-500 active:from-blue-700 active:to-indigo-700 text-white font-semibold text-sm transition-all shadow-xl shadow-blue-600/30 flex items-center justify-center gap-3 group/btn hover:scale-[1.01] disabled:opacity-50 disabled:cursor-not-allowed"
                    >
                      <span>{isConnecting ? "Redirecting to Identity Gateway..." : "Sign In via Corporate SSO"}</span>
                      <span className="group-hover/btn:translate-x-1 transition-transform">→</span>
                    </button>

                    <div className="flex items-center justify-center gap-2 text-[11px] text-slate-500 font-mono">
                      <span className="w-1.5 h-1.5 rounded-full bg-emerald-500" />
                      <span>Protected by PKCE OAuth2 &amp; Multi-Factor Auth</span>
                    </div>
                  </div>

                  <div className="border-t border-slate-800/80 pt-5 flex flex-col gap-2.5 text-left">
                    <div className="text-xs text-slate-400 flex justify-between items-center">
                      <span>Identity Provider:</span>
                      <span className="font-mono text-slate-200 bg-slate-900 px-2 py-0.5 rounded border border-slate-800">zerogate.internal</span>
                    </div>
                    <div className="text-xs text-slate-400 flex justify-between items-center">
                      <span>Encryption Level:</span>
                      <span className="font-mono text-emerald-400">TLS 1.3 / AES-256</span>
                    </div>
                  </div>
                </div>
              </div>

            </div>
          )}

          {/* TAB 2: SERVICES DIRECTORY */}
          {activeTab === "services" && (
            <div className="w-full flex flex-col gap-8 text-left animate-fadeIn">
              <div className="flex flex-col gap-2 border-b border-slate-800/80 pb-6">
                <h2 className="text-3xl font-bold text-white">Internal Microservices Directory</h2>
                <p className="text-slate-400 text-sm">
                  Authorized enterprise utility nodes and API proxies running on Nexus Dynamics infrastructure.
                </p>
              </div>

              <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                
                {/* Service 1 */}
                <div className="bg-[#0b0f19]/90 border border-slate-800 p-6 rounded-2xl flex flex-col justify-between gap-4 hover:border-slate-700 transition-colors">
                  <div className="flex flex-col gap-2">
                    <div className="flex justify-between items-center">
                      <span className="font-mono text-xs text-blue-400 font-semibold">svc-auth-gateway-v2</span>
                      <span className="px-2 py-0.5 rounded bg-emerald-950/60 text-emerald-400 text-[10px] font-mono border border-emerald-500/30">ONLINE</span>
                    </div>
                    <h3 className="text-lg font-bold text-white">Identity &amp; Authentication Gateway</h3>
                    <p className="text-xs text-slate-400 leading-relaxed">
                      Handles PKCE code exchanges, iron-session encryption, and multi-factor push challenge verification.
                    </p>
                  </div>
                  <button 
                    onClick={handleLogin}
                    className="w-full py-2.5 rounded-xl bg-slate-900 hover:bg-blue-600 text-white font-medium text-xs border border-slate-800 hover:border-blue-500 transition-all flex items-center justify-center gap-2"
                  >
                    <span>Authenticate to Access Service</span>
                    <span>→</span>
                  </button>
                </div>

                {/* Service 2 */}
                <div className="bg-[#0b0f19]/90 border border-slate-800 p-6 rounded-2xl flex flex-col justify-between gap-4 hover:border-slate-700 transition-colors">
                  <div className="flex flex-col gap-2">
                    <div className="flex justify-between items-center">
                      <span className="font-mono text-xs text-indigo-400 font-semibold">svc-gatekeeper-proxy</span>
                      <span className="px-2 py-0.5 rounded bg-emerald-950/60 text-emerald-400 text-[10px] font-mono border border-emerald-500/30">ONLINE</span>
                    </div>
                    <h3 className="text-lg font-bold text-white">Zero-Trust Access Control Matrix</h3>
                    <p className="text-xs text-slate-400 leading-relaxed">
                      Evaluates HMAC-signed authorization tokens and enforces sliding-window rate limit checks.
                    </p>
                  </div>
                  <button 
                    onClick={handleLogin}
                    className="w-full py-2.5 rounded-xl bg-slate-900 hover:bg-blue-600 text-white font-medium text-xs border border-slate-800 hover:border-blue-500 transition-all flex items-center justify-center gap-2"
                  >
                    <span>Authenticate to Access Service</span>
                    <span>→</span>
                  </button>
                </div>

                {/* Service 3 */}
                <div className="bg-[#0b0f19]/90 border border-slate-800 p-6 rounded-2xl flex flex-col justify-between gap-4 hover:border-slate-700 transition-colors">
                  <div className="flex flex-col gap-2">
                    <div className="flex justify-between items-center">
                      <span className="font-mono text-xs text-emerald-400 font-semibold">svc-audit-stream-log</span>
                      <span className="px-2 py-0.5 rounded bg-emerald-950/60 text-emerald-400 text-[10px] font-mono border border-emerald-500/30">ONLINE</span>
                    </div>
                    <h3 className="text-lg font-bold text-white">Dual-Stream Security Audit Logger</h3>
                    <p className="text-xs text-slate-400 leading-relaxed">
                      Records immutable LOGIN and CONNECT security audit manifests for compliance inspections.
                    </p>
                  </div>
                  <button 
                    onClick={handleLogin}
                    className="w-full py-2.5 rounded-xl bg-slate-900 hover:bg-blue-600 text-white font-medium text-xs border border-slate-800 hover:border-blue-500 transition-all flex items-center justify-center gap-2"
                  >
                    <span>Authenticate to Access Service</span>
                    <span>→</span>
                  </button>
                </div>

                {/* Service 4 */}
                <div className="bg-[#0b0f19]/90 border border-slate-800 p-6 rounded-2xl flex flex-col justify-between gap-4 hover:border-slate-700 transition-colors">
                  <div className="flex flex-col gap-2">
                    <div className="flex justify-between items-center">
                      <span className="font-mono text-xs text-purple-400 font-semibold">svc-telemetry-ingest</span>
                      <span className="px-2 py-0.5 rounded bg-emerald-950/60 text-emerald-400 text-[10px] font-mono border border-emerald-500/30">ONLINE</span>
                    </div>
                    <h3 className="text-lg font-bold text-white">Edge Cluster Telemetry Processor</h3>
                    <p className="text-xs text-slate-400 leading-relaxed">
                      Processes real-time node health, memory pressure, and edge cluster latency metrics across regions.
                    </p>
                  </div>
                  <button 
                    onClick={handleLogin}
                    className="w-full py-2.5 rounded-xl bg-slate-900 hover:bg-blue-600 text-white font-medium text-xs border border-slate-800 hover:border-blue-500 transition-all flex items-center justify-center gap-2"
                  >
                    <span>Authenticate to Access Service</span>
                    <span>→</span>
                  </button>
                </div>

              </div>
            </div>
          )}

          {/* TAB 3: TELEMETRY MESH */}
          {activeTab === "telemetry" && (
            <div className="w-full flex flex-col gap-8 text-left animate-fadeIn">
              <div className="flex flex-col gap-2 border-b border-slate-800/80 pb-6">
                <h2 className="text-3xl font-bold text-white">Edge Node Telemetry Mesh</h2>
                <p className="text-slate-400 text-sm">
                  Live latency metrics and regional edge cluster status across Nexus Dynamics infrastructure.
                </p>
              </div>

              <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
                
                {/* Node 1 */}
                <div className="bg-[#0b0f19]/90 border border-slate-800 p-6 rounded-2xl flex flex-col gap-4">
                  <div className="flex justify-between items-center">
                    <span className="text-xs font-mono text-blue-400">US-East (Virginia)</span>
                    <span className="w-2 h-2 rounded-full bg-emerald-400 animate-pulse" />
                  </div>
                  <div className="text-3xl font-mono font-bold text-white">3.8 <span className="text-sm font-normal text-slate-400">ms</span></div>
                  <div className="w-full bg-slate-900 rounded-full h-2 overflow-hidden border border-slate-800">
                    <div className="bg-emerald-500 h-full w-[24%]" />
                  </div>
                  <div className="flex justify-between text-[11px] font-mono text-slate-400">
                    <span>Node Load: 24%</span>
                    <span>Status: Optimal</span>
                  </div>
                </div>

                {/* Node 2 */}
                <div className="bg-[#0b0f19]/90 border border-slate-800 p-6 rounded-2xl flex flex-col gap-4">
                  <div className="flex justify-between items-center">
                    <span className="text-xs font-mono text-indigo-400">EU-West (Frankfurt)</span>
                    <span className="w-2 h-2 rounded-full bg-emerald-400 animate-pulse" />
                  </div>
                  <div className="text-3xl font-mono font-bold text-white">12.4 <span className="text-sm font-normal text-slate-400">ms</span></div>
                  <div className="w-full bg-slate-900 rounded-full h-2 overflow-hidden border border-slate-800">
                    <div className="bg-blue-500 h-full w-[31%]" />
                  </div>
                  <div className="flex justify-between text-[11px] font-mono text-slate-400">
                    <span>Node Load: 31%</span>
                    <span>Status: Optimal</span>
                  </div>
                </div>

                {/* Node 3 */}
                <div className="bg-[#0b0f19]/90 border border-slate-800 p-6 rounded-2xl flex flex-col gap-4">
                  <div className="flex justify-between items-center">
                    <span className="text-xs font-mono text-emerald-400">AP-South (Mumbai)</span>
                    <span className="w-2 h-2 rounded-full bg-emerald-400 animate-pulse" />
                  </div>
                  <div className="text-3xl font-mono font-bold text-white">24.1 <span className="text-sm font-normal text-slate-400">ms</span></div>
                  <div className="w-full bg-slate-900 rounded-full h-2 overflow-hidden border border-slate-800">
                    <div className="bg-indigo-500 h-full w-[18%]" />
                  </div>
                  <div className="flex justify-between text-[11px] font-mono text-slate-400">
                    <span>Node Load: 18%</span>
                    <span>Status: Optimal</span>
                  </div>
                </div>

              </div>

              <div className="p-6 rounded-2xl bg-[#0d1117] border border-slate-800 flex flex-col sm:flex-row items-center justify-between gap-4">
                <div className="text-left">
                  <h4 className="text-base font-bold text-white">Detailed Telemetry Inspection</h4>
                  <p className="text-xs text-slate-400">Sign in with employee SSO credentials to inspect full packet traces and log stream manifests.</p>
                </div>
                <button
                  onClick={handleLogin}
                  className="px-6 py-3 rounded-xl bg-blue-600 hover:bg-blue-500 text-white font-medium text-xs whitespace-nowrap shadow-lg shadow-blue-600/20"
                >
                  Sign In to Inspect Mesh →
                </button>
              </div>
            </div>
          )}

          {/* TAB 4: DOCUMENTATION */}
          {activeTab === "docs" && (
            <div className="w-full flex flex-col gap-8 text-left animate-fadeIn">
              <div className="flex flex-col gap-2 border-b border-slate-800/80 pb-6">
                <h2 className="text-3xl font-bold text-white">Nexus SDK &amp; API Developer Docs</h2>
                <p className="text-slate-400 text-sm">
                  Technical specifications for integrating enterprise applications with the Nexus Gateway.
                </p>
              </div>

              <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
                
                <div className="bg-[#0b0f19]/90 border border-slate-800 p-6 rounded-2xl flex flex-col gap-3">
                  <div className="w-8 h-8 rounded-lg bg-blue-600/20 border border-blue-500/30 text-blue-400 flex items-center justify-center font-bold text-sm">🔑</div>
                  <h3 className="text-base font-bold text-white">PKCE OAuth2 Flow</h3>
                  <p className="text-xs text-slate-400 leading-relaxed">
                    Uses SHA-256 code challenge verification to prevent code interception attacks on public clients.
                  </p>
                </div>

                <div className="bg-[#0b0f19]/90 border border-slate-800 p-6 rounded-2xl flex flex-col gap-3">
                  <div className="w-8 h-8 rounded-lg bg-emerald-600/20 border border-emerald-500/30 text-emerald-400 flex items-center justify-center font-bold text-sm">🛡️</div>
                  <h3 className="text-base font-bold text-white">Authorization Tokens</h3>
                  <p className="text-xs text-slate-400 leading-relaxed">
                    HMAC-SHA256 signed access tokens with 5-minute sliding-window lifetimes and rate-limit enforcement.
                  </p>
                </div>

                <div className="bg-[#0b0f19]/90 border border-slate-800 p-6 rounded-2xl flex flex-col gap-3">
                  <div className="w-8 h-8 rounded-lg bg-indigo-600/20 border border-indigo-500/30 text-indigo-400 flex items-center justify-center font-bold text-sm">📱</div>
                  <h3 className="text-base font-bold text-white">MFA Integration</h3>
                  <p className="text-xs text-slate-400 leading-relaxed">
                    Supports 6-digit TOTP validation and Duo/Okta simulated push notification challenge triggers.
                  </p>
                </div>

              </div>

              <div className="p-6 rounded-2xl bg-[#0d1117] border border-slate-800 flex flex-col sm:flex-row items-center justify-between gap-4">
                <div className="text-left">
                  <h4 className="text-base font-bold text-white">Need Full API Reference &amp; Postman Collection?</h4>
                  <p className="text-xs text-slate-400">Authenticate via corporate SSO to access private endpoint schemas and SDK libraries.</p>
                </div>
                <button
                  onClick={handleLogin}
                  className="px-6 py-3 rounded-xl bg-blue-600 hover:bg-blue-500 text-white font-medium text-xs whitespace-nowrap shadow-lg shadow-blue-600/20"
                >
                  Log In to Access Full Docs →
                </button>
              </div>
            </div>
          )}

        </main>

        {/* Footer with active modal triggers */}
        <footer className="w-full py-6 px-6 md:px-16 border-t border-slate-800/80 bg-[#080b12]/80 backdrop-blur-xl flex flex-col sm:flex-row justify-between items-center gap-4 text-xs text-slate-500 z-10">
          <div>© 2026 Nexus Dynamics Corp. All rights reserved.</div>
          <div className="flex items-center gap-6">
            <button
              onClick={() => setUiMode("terminal")}
              className="text-slate-400 hover:text-emerald-400 text-xs font-mono underline decoration-dotted transition-colors flex items-center gap-1.5"
              title="Switch to GateZero Industrial Terminal View"
            >
              <span>⚡</span>
              <span>[Switch View: Terminal Mode]</span>
            </button>
            <button 
              onClick={() => setActiveModal("privacy")}
              className="hover:text-slate-300 transition-colors"
            >
              Privacy Policy
            </button>
            <button 
              onClick={() => setActiveModal("terms")}
              className="hover:text-slate-300 transition-colors"
            >
              Terms of Service
            </button>
          </div>
        </footer>

        {/* PRIVACY POLICY & TERMS MODALS */}
        {activeModal && (
          <div className="fixed inset-0 bg-black/80 backdrop-blur-md z-50 flex items-center justify-center p-4">
            <div className="bg-[#0d1117] border border-slate-800 rounded-3xl p-8 max-w-lg w-full text-left relative flex flex-col gap-4 shadow-2xl">
              <div className="flex justify-between items-center border-b border-slate-800 pb-4">
                <h3 className="text-xl font-bold text-white">
                  {activeModal === "privacy" ? "Privacy Policy" : "Terms of Service"}
                </h3>
                <button
                  onClick={() => setActiveModal(null)}
                  className="text-slate-400 hover:text-white font-mono text-lg"
                >
                  ✕
                </button>
              </div>

              {activeModal === "privacy" ? (
                <div className="text-xs text-slate-400 space-y-3 leading-relaxed max-h-60 overflow-y-auto pr-2">
                  <p>Nexus Dynamics Enterprise Portal respects user privacy and complies with enterprise identity security protocols.</p>
                  <p><strong>Data Collection:</strong> Session identifiers, hashed User-Agent strings, and client IP addresses are recorded strictly for security audit logging and authorization rate-limiting.</p>
                  <p><strong>Encryption:</strong> All transit communications are protected via TLS 1.3. Authorization tokens are signed using HMAC-SHA256 secrets.</p>
                </div>
              ) : (
                <div className="text-xs text-slate-400 space-y-3 leading-relaxed max-h-60 overflow-y-auto pr-2">
                  <p>By accessing the Nexus Dynamics Enterprise Gateway, you agree to comply with internal IT security guidelines.</p>
                  <p><strong>Authorized Use:</strong> Access is restricted strictly to authorized employees and service accounts with valid SSO clearance.</p>
                  <p><strong>Session Revocation:</strong> Sessions may be revoked by network administrators at any time upon detecting anomaly thresholds.</p>
                </div>
              )}

              <button
                onClick={() => setActiveModal(null)}
                className="w-full py-2.5 rounded-xl bg-blue-600 hover:bg-blue-500 text-white font-medium text-xs transition-colors mt-2"
              >
                Close Window
              </button>
            </div>
          </div>
        )}

      </div>
    );
  }

  // ── 2. CYBERPUNK TERMINAL MODE (GateZero View) ──────────────────────────────
  return (
    <div className="h-screen w-screen overflow-hidden flex flex-col bg-background text-primary relative">
      {/* Scanlines overlay */}
      <div className="absolute inset-0 scanlines z-50 mix-blend-screen opacity-30 pointer-events-none" />

      {/* Instrument strip header */}
      <header
        className="w-full h-12 border-b border-outline-variant bg-surface flex justify-between items-center px-4 shrink-0 font-status-code text-xs text-on-surface-variant z-40 sticky top-0"
        style={{ boxShadow: "0 0 15px rgba(0,230,57,0.15)" }}
      >
        <div className="flex items-center gap-6">
          <span className="font-display-lg text-lg font-bold text-primary tracking-widest uppercase">
            GATEZERO
          </span>
          <span className="flex items-center gap-2">
            <span className="w-2 h-2 rounded-full bg-primary animate-pulse" style={{ boxShadow: "0 0 8px #00ff41" }} />
            SYS.ONLINE
          </span>
          <span>UPLINK: STABLE</span>
        </div>
        <div className="flex items-center gap-6">
          <span>SECTOR: 7G</span>
          <span className="text-primary font-bold">{time}</span>
        </div>
      </header>

      {/* Main login panel */}
      <div className="flex-1 flex items-center justify-center p-4">
        <div className="industrial-grid w-full max-w-md">
          <div className="flex flex-col items-center p-8 text-center panel-recessed relative overflow-hidden">
            {/* Top accent line */}
            <div className="absolute top-0 left-0 w-full h-[2px] bg-primary/50" style={{ boxShadow: "0 0 10px #00ff41" }} />

            {/* Logo */}
            <div className="mb-8">
              <span className="font-display-lg text-4xl font-bold text-primary tracking-widest"
                style={{ textShadow: "0 0 8px rgba(0,255,65,0.5)" }}>
                GATEZERO
              </span>
            </div>

            {/* Barrier visualization — idle state */}
            <div className="w-full h-24 mb-8 relative border-2 border-outline-variant bg-graphite flex items-center justify-center overflow-hidden barrier-container"
              style={{ boxShadow: "inset 0 0 20px rgba(0,255,65,0.08)" }}>
              <div className="absolute w-full h-1/2 top-0 bg-surface border-b-2 barrier-glow-idle leaf-top flex items-end justify-center pb-1 barrier-leaf z-10">
                <div className="w-16 h-2 bg-primary rounded-sm" style={{ boxShadow: "0 0 10px #00ff41" }} />
              </div>
              <div className="absolute w-full h-1/2 bottom-0 bg-surface border-t-2 barrier-glow-idle leaf-bottom flex items-start justify-center pt-1 barrier-leaf z-10">
                <div className="w-16 h-2 bg-primary rounded-sm" style={{ boxShadow: "0 0 10px #00ff41" }} />
              </div>
              <div className="absolute z-20 pointer-events-none flex items-center justify-center w-full h-full">
                <span className="material-symbols-outlined text-4xl text-primary m-icon-fill"
                  style={{ textShadow: "0 0 10px #00ff41" }}>door_front</span>
              </div>
            </div>

            {/* Error display */}
            {error && (
              <div className="w-full mb-4 p-3 border border-error/50 bg-error/5 text-error font-status-code text-xs text-left">
                &gt; ERR: {error}
              </div>
            )}

            {/* Login button */}
            <div className="w-full flex flex-col gap-4">
              <button
                onClick={handleLogin}
                disabled={isConnecting}
                className="w-full h-12 flex items-center justify-center border border-primary/50 bg-graphite hover:bg-primary/10 transition-colors text-primary font-data-mono text-sm tracking-widest relative overflow-hidden group disabled:opacity-50 disabled:cursor-not-allowed"
                style={{ boxShadow: "0 0 10px rgba(0,255,65,0.1)" }}
              >
                <span className="relative z-10">
                  {isConnecting ? "CONNECTING..." : "[ENTER CREDENTIALS]"}
                </span>
                <div className="absolute bottom-0 left-0 w-full h-[2px] bg-primary scale-x-0 group-hover:scale-x-100 transition-transform origin-left" />
              </button>

              {activeUser && (
                <button
                  onClick={handleGoToDashboard}
                  className="w-full py-2 border border-blue-500/50 bg-blue-950/20 text-blue-400 font-status-code text-xs hover:bg-blue-900/30 transition-colors"
                >
                  &gt; GO TO DASHBOARD ({activeUser.email})
                </button>
              )}

              <p className="font-status-code text-xs text-primary/70 animate-pulse text-left">
                &gt; {isConnecting ? "REDIRECTING TO AUTH GATEWAY..." : "AWAITING INPUT_"}
              </p>

              <div className="border-t border-outline-variant pt-3 text-left">
                <p className="font-status-code text-xs text-on-surface-variant/60">
                  AUTHENTICATION PROTOCOL: SSO+MFA
                </p>
                <p className="font-status-code text-xs text-on-surface-variant/60">
                  SESSION TTL: 7D // TOKEN TTL: 5M
                </p>
              </div>
            </div>
          </div>
        </div>
      </div>

      {/* Footer */}
      <footer className="w-full h-8 flex justify-between items-center px-4 bg-surface-container-lowest border-t border-outline-variant text-on-surface-variant font-status-code text-xs">
        <div>© GATEZERO INDUSTRIAL v1.0.0</div>
        <div className="flex items-center gap-4">
          <button
            onClick={() => setUiMode("stealth")}
            className="text-primary hover:underline text-xs"
          >
            [Switch View: Stealth Mode]
          </button>
          <span>DEV MODE: ON</span>
        </div>
      </footer>
    </div>
  );
}

export default function LoginPage() {
  return (
    <Suspense fallback={
      <div className="h-screen w-screen bg-background flex items-center justify-center text-primary font-data-mono text-sm">
        <span className="animate-pulse">&gt; LOADING CHECKPOINT...</span>
      </div>
    }>
      <LoginContent />
    </Suspense>
  );
}
