"use client";

import { useState, useEffect, useRef } from "react";
import { useRouter } from "next/navigation";

export default function MFAPage() {
  const router = useRouter();
  const [code, setCode] = useState<string[]>(["", "", "", "", "", ""]);
  const [isSubmitting, setIsSubmitting] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [timeLeft, setTimeLeft] = useState(300);
  const [time, setTime] = useState("");
  const [emailStatus, setEmailStatus] = useState<string | null>(null);
  const [isSendingEmail, setIsSendingEmail] = useState(false);
  const [userEmail, setUserEmail] = useState<string>("");
  const [copyPasteBlockedNotice, setCopyPasteBlockedNotice] = useState(false);
  const inputRefs = useRef<(HTMLInputElement | null)[]>([]);

  // Live ZULU clock
  useEffect(() => {
    const tick = () => setTime(new Date().toISOString().slice(11, 19) + " ZULU");
    tick();
    const i = setInterval(tick, 1000);
    return () => clearInterval(i);
  }, []);

  // MFA countdown timer
  useEffect(() => {
    if (timeLeft <= 0) {
      router.replace("/?error=mfa_timeout");
      return;
    }
    const t = setTimeout(() => setTimeLeft((p) => p - 1), 1000);
    return () => clearTimeout(t);
  }, [timeLeft, router]);

  // Fetch session user info
  useEffect(() => {
    fetch("/api/auth/session")
      .then((r) => r.json())
      .then((data) => {
        if (data.authenticated) router.replace("/dashboard");
        if (data.user?.email) setUserEmail(data.user.email);
      })
      .catch(() => {});
  }, [router]);

  // Handle Send Email OTP
  const handleSendEmailOTP = async () => {
    setIsSendingEmail(true);
    setError(null);
    setEmailStatus(null);
    try {
      const res = await fetch("/api/auth/mfa", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ action: "send_email" }),
      });
      const data = await res.json();
      if (data.success) {
        setEmailStatus(`✓ Verification code sent to ${data.email}`);
        inputRefs.current[0]?.focus();
      } else {
        setError(data.error ?? "Failed to send verification email.");
      }
    } catch {
      setError("Failed to connect to email service.");
    } finally {
      setIsSendingEmail(false);
    }
  };

  const handleDigitInput = (index: number, value: string) => {
    if (!/^\d?$/.test(value)) return;
    const next = [...code];
    next[index] = value;
    setCode(next);
    if (value && index < 5) {
      inputRefs.current[index + 1]?.focus();
    }
  };

  const handleKeyDown = (index: number, e: React.KeyboardEvent) => {
    if (e.key === "Backspace" && !code[index] && index > 0) {
      inputRefs.current[index - 1]?.focus();
    }
  };

  const handlePreventPaste = (e: React.ClipboardEvent) => {
    e.preventDefault();
    setCopyPasteBlockedNotice(true);
    setTimeout(() => setCopyPasteBlockedNotice(false), 4000);
  };

  const handlePreventCopy = (e: React.ClipboardEvent) => {
    e.preventDefault();
    setCopyPasteBlockedNotice(true);
    setTimeout(() => setCopyPasteBlockedNotice(false), 4000);
  };

  const handleSubmitOTP = async () => {
    const otp = code.join("");
    if (otp.length !== 6) { setError("Enter all 6 digits"); return; }
    setIsSubmitting(true);
    setError(null);
    try {
      const res = await fetch("/api/auth/mfa", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ method: "email", code: otp }),
      });
      const data = await res.json();
      if (data.success) {
        router.push("/dashboard");
      } else {
        setError(data.error ?? "Invalid code. Try again.");
        setCode(["", "", "", "", "", ""]);
        inputRefs.current[0]?.focus();
      }
    } catch {
      setError("Connection error.");
    } finally {
      setIsSubmitting(false);
    }
  };

  const formatTimer = (s: number) =>
    `T-MINUS ${String(Math.floor(s / 60)).padStart(2, "0")}:${String(s % 60).padStart(2, "0")}`;

  return (
    <div className="h-screen w-screen overflow-hidden flex flex-col bg-background text-primary relative select-none">
      <div className="absolute inset-0 scanlines z-50 mix-blend-screen opacity-30 pointer-events-none" />

      {/* Header */}
      <header className="w-full h-12 border-b border-outline-variant bg-surface flex justify-between items-center px-4 shrink-0 font-status-code text-xs text-on-surface-variant z-40">
        <div className="flex items-center gap-6">
          <span className="font-display-lg text-lg font-bold text-primary tracking-widest uppercase">GATEZERO</span>
          <span className="flex items-center gap-2 text-warning-amber">
            <span className="w-2 h-2 bg-warning-amber animate-ping" />
            MFA CHALLENGE ACTIVE
          </span>
        </div>
        <div className="flex items-center gap-6">
          <span className={`font-bold ${timeLeft <= 10 ? "text-error animate-pulse" : "text-warning-amber"}`}>
            {formatTimer(timeLeft)}
          </span>
          <span className="text-primary">{time}</span>
        </div>
      </header>

      {/* MFA Panel */}
      <div className="flex-1 flex items-center justify-center p-4">
        <div className="industrial-grid w-full max-w-md">
          <div className="flex flex-col p-6 panel-recessed relative">
            {/* Pending amber top bar */}
            <div className="absolute top-0 left-0 w-full h-[2px] animate-pulse" style={{ background: "#FFB59C" }} />

            {/* Header row */}
            <div className="flex justify-between items-center border-b border-primary/20 pb-3 mb-4">
              <span className="font-data-mono text-sm text-primary uppercase">MULTI-FACTOR VERIFICATION</span>
              <span className="font-status-code text-xs text-tertiary">{formatTimer(timeLeft)}</span>
            </div>

            {/* Security policy badge */}
            <div className="mb-4 py-1.5 px-3 border border-amber-500/30 bg-amber-950/30 rounded text-[11px] font-status-code text-amber-400 flex items-center justify-between">
              <span className="flex items-center gap-1.5">
                <span>🔒</span>
                <span>COPY & PASTE DISABLED</span>
              </span>
              <span className="text-[10px] text-amber-500/70">MANUAL ENTRY REQUIRED</span>
            </div>

            {/* Copy paste blocked warning */}
            {copyPasteBlockedNotice && (
              <div className="mb-4 p-2 border border-red-500/60 bg-red-950/60 text-red-300 font-status-code text-xs rounded animate-bounce text-center">
                ⛔ COPY & PASTE BLOCKED! PLEASE TYPE DIGITS MANUALLY.
              </div>
            )}

            {/* Email OTP Section */}
            <div className="mb-5 p-3 border border-blue-500/30 bg-blue-950/20 text-left flex flex-col gap-2">
              <div className="flex justify-between items-center">
                <span className="font-status-code text-xs text-blue-400 font-bold">📧 EMAIL VERIFICATION</span>
                {userEmail && <span className="font-status-code text-[10px] text-slate-400">{userEmail}</span>}
              </div>

              {emailStatus ? (
                <div className="flex flex-col gap-1">
                  <div className="text-emerald-400 font-status-code text-xs">{emailStatus}</div>
                  <div className="text-slate-400 text-[11px] font-status-code">Check your email inbox and enter the 6-digit code below.</div>
                  <button
                    onClick={handleSendEmailOTP}
                    disabled={isSendingEmail}
                    className="mt-1 py-1 border border-blue-500/30 bg-blue-900/20 hover:bg-blue-800/30 transition-colors text-blue-300 font-data-mono text-[10px] tracking-wider disabled:opacity-50"
                  >
                    {isSendingEmail ? "RESENDING..." : "RESEND CODE"}
                  </button>
                </div>
              ) : (
                <button
                  onClick={handleSendEmailOTP}
                  disabled={isSendingEmail}
                  className="w-full py-2 border border-blue-500/50 bg-blue-900/30 hover:bg-blue-800/40 transition-colors text-blue-300 font-data-mono text-xs tracking-wider flex items-center justify-center gap-2 disabled:opacity-50"
                >
                  <span>{isSendingEmail ? "SENDING..." : "[SEND VERIFICATION CODE]"}</span>
                </button>
              )}
            </div>

            {/* OTP digit input */}
            <div className="flex gap-2 justify-center mb-4">
              {code.map((digit, i) => (
                <div key={i} className={`w-11 h-14 border border-primary/30 bg-graphite flex items-center justify-center font-data-mono text-xl border-b-2 ${digit ? "text-tertiary border-b-tertiary" : "text-on-surface-variant border-b-outline-variant"}`}
                  style={digit ? { boxShadow: "0 0 10px rgba(255,181,156,0.2)" } : {}}>
                  <input
                    ref={(el) => { inputRefs.current[i] = el; }}
                    type="text"
                    inputMode="numeric"
                    maxLength={1}
                    value={digit}
                    onChange={(e) => handleDigitInput(i, e.target.value)}
                    onKeyDown={(e) => handleKeyDown(i, e)}
                    onPaste={handlePreventPaste}
                    onCopy={handlePreventCopy}
                    onCut={handlePreventCopy}
                    onContextMenu={(e) => e.preventDefault()}
                    autoComplete="off"
                    className="w-full h-full bg-transparent text-center outline-none text-inherit font-inherit text-xl select-none"
                  />
                </div>
              ))}
            </div>

            {/* Submit OTP */}
            <button
              onClick={handleSubmitOTP}
              disabled={isSubmitting || code.join("").length !== 6}
              className="w-full h-11 mb-4 border border-primary/50 bg-graphite hover:bg-primary/10 transition-colors text-primary font-data-mono text-sm tracking-widest relative overflow-hidden group disabled:opacity-40 disabled:cursor-not-allowed"
            >
              <span className="relative z-10">{isSubmitting ? "VERIFYING..." : "[SUBMIT VERIFICATION CODE]"}</span>
              <div className="absolute bottom-0 left-0 w-full h-[2px] bg-primary scale-x-0 group-hover:scale-x-100 transition-transform origin-left" />
            </button>

            {/* Error display */}
            {error && (
              <div className="mt-2 p-3 border border-error/50 bg-error/5 text-error font-status-code text-xs text-left">
                &gt; ERR: {error}
              </div>
            )}

            {/* Back link */}
            <button
              onClick={() => { fetch("/api/auth/logout", { method: "POST" }); router.push("/"); }}
              className="mt-4 text-on-surface-variant hover:text-primary font-status-code text-xs transition-colors text-left"
            >
              &lt; ABORT / RETURN TO LOGIN
            </button>
          </div>
        </div>
      </div>

      <footer className="w-full h-8 flex justify-between items-center px-4 bg-surface-container-lowest border-t border-outline-variant text-on-surface-variant font-status-code text-xs">
        <div>© GATEZERO v1.0.0</div>
        <div>CHALLENGE: ACTIVE</div>
      </footer>
    </div>
  );
}
