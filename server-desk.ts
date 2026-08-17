/**
 * server-desk.ts
 * ═══════════════════════════════════════════════════════════════════════════════
 * WEBSITE 2: THE OPERATIONS DESK
 * ═══════════════════════════════════════════════════════════════════════════════
 *
 * Standalone company operations & dispatch application running on PORT 3002.
 * Gated strictly by Website 1 (GateZero Access Gateway at PORT 3000) via:
 *   1. OIDC-Style Exchange Code Handshake (/api/auth/callback?code=...)
 *   2. Live Per-Request Token Introspection (/api/authz/verify on PORT 3000)
 *   3. Neutral Enterprise Gateway Intercept Screen on unauthorized access
 */

import express, { Request, Response, NextFunction } from "express";
import cookieParser from "cookie-parser";
import { prisma } from "./lib/db";

const app = express();
const PORT = 3002;
const HOST = process.env.HOST || "127.0.0.1";
const GATEWAY_URL = process.env.NEXT_PUBLIC_APP_URL || "http://localhost:3000";

// Security Headers Middleware
app.use((req, res, next) => {
  res.setHeader("X-Content-Type-Options", "nosniff");
  res.setHeader("X-Frame-Options", "DENY");
  res.setHeader("Referrer-Policy", "strict-origin-when-cross-origin");
  res.setHeader("Permissions-Policy", "camera=(), microphone=(), geolocation=()");
  res.setHeader("X-XSS-Protection", "1; mode=block");
  next();
});

app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser());

// Extend express Request to include verified user claims
interface AuthRequest extends Request {
  user?: {
    id: string;
    email: string;
    name: string;
    role: string;
  };
  tokenId?: string;
}

// ─────────────────────────────────────────────────────────────────────────────
// 1. Live Gateway Verification Middleware (Per-Request Introspection)
// ─────────────────────────────────────────────────────────────────────────────
async function requireGatewayAuth(req: AuthRequest, res: Response, next: NextFunction) {
  const tokenId = req.cookies?.desk_tokenId || (req.headers.authorization?.replace(/^Bearer\s+/i, ""));

  if (!tokenId) {
    if (req.path.startsWith("/api/")) {
      return res.status(401).json({ error: "GATEWAY_AUTH_REQUIRED", reason: "MISSING_TOKEN" });
    }
    return res.status(401).send(renderNeutralInterceptScreen("NO_ACTIVE_TOKEN"));
  }

  try {
    const clientUA = (req.headers["user-agent"] as string) || "unknown-ua";
    const clientIP = req.ip || "127.0.0.1";

    // Perform LIVE introspection check against Website 1 Gateway on EVERY request
    const response = await fetch(`${GATEWAY_URL}/api/authz/verify`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "X-Client-User-Agent": clientUA,
        "X-Client-IP": clientIP,
      },
      body: JSON.stringify({ tokenId, userAgent: clientUA, ipAddress: clientIP }),
    });

    if (!response.ok) {
      const data = await response.json().catch(() => ({}));
      res.clearCookie("desk_tokenId");
      if (req.path.startsWith("/api/")) {
        return res.status(401).json({ error: "GATEWAY_REVOKED", reason: data.reason || "TOKEN_INVALID" });
      }
      return res.status(401).send(renderNeutralInterceptScreen(data.reason || "TOKEN_REVOKED_OR_EXPIRED"));
    }

    const verification = await response.json();
    if (!verification.valid || !verification.user) {
      res.clearCookie("desk_tokenId");
      if (req.path.startsWith("/api/")) {
        return res.status(401).json({ error: "GATEWAY_DENIED", reason: verification.reason });
      }
      return res.status(401).send(renderNeutralInterceptScreen(verification.reason || "VERIFICATION_FAILED"));
    }

    req.user = verification.user;
    req.tokenId = tokenId;
    next();
  } catch (err: any) {
    console.error("[Gatekeeper] Failed to verify token with Gateway:", err?.message || err);
    if (req.path.startsWith("/api/")) {
      return res.status(503).json({ error: "GATEWAY_UNAVAILABLE" });
    }
    return res.status(503).send(renderNeutralInterceptScreen("GATEWAY_CONNECTION_ERROR"));
  }
}

// ─────────────────────────────────────────────────────────────────────────────
// 2. Handshake Callback Endpoint (Back-Channel Code Exchange)
// ─────────────────────────────────────────────────────────────────────────────
app.get("/api/auth/callback", async (req: Request, res: Response) => {
  const code = req.query.code as string;

  if (!code) {
    return res.status(400).send(renderNeutralInterceptScreen("MISSING_EXCHANGE_CODE"));
  }

  try {
    const clientUA = (req.headers["user-agent"] as string) || "unknown-ua";
    const clientIP = req.ip || "127.0.0.1";

    // Back-channel exchange with Website 1 Gateway
    const exchangeRes = await fetch(`${GATEWAY_URL}/api/authz/exchange`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "X-Client-User-Agent": clientUA,
        "X-Client-IP": clientIP,
      },
      body: JSON.stringify({ code, userAgent: clientUA, ipAddress: clientIP }),
    });

    const data = await exchangeRes.json();

    if (!exchangeRes.ok || !data.success || !data.tokenId) {
      return res.status(401).send(renderNeutralInterceptScreen(data.error || "EXCHANGE_CODE_FAILED"));
    }

    // Set secure HttpOnly session cookie
    res.cookie("desk_tokenId", data.tokenId, {
      httpOnly: true,
      sameSite: "lax",
      maxAge: (data.ttlSeconds || 300) * 1000,
    });

    return res.redirect("/");
  } catch (err: any) {
    console.error("[Callback] Code exchange error:", err?.message || err);
    return res.status(500).send(renderNeutralInterceptScreen("HANDSHAKE_NETWORK_ERROR"));
  }
});

// Logout endpoint
app.all("/api/auth/logout", (req: Request, res: Response) => {
  res.clearCookie("desk_tokenId");
  return res.redirect(`${GATEWAY_URL}/dashboard`);
});

// ─────────────────────────────────────────────────────────────────────────────
// 3. REST API Endpoints (Protected by Live Gateway Verification)
// ─────────────────────────────────────────────────────────────────────────────

// Overview Stats
app.get("/api/desk/stats", requireGatewayAuth, async (req: AuthRequest, res: Response) => {
  const [activeAssignments, totalStaff, onDutyStaff, todayShifts, wireCount] = await Promise.all([
    prisma.assignment.count({ where: { status: { in: ["TODO", "IN_PROGRESS"] } } }),
    prisma.staffMember.count(),
    prisma.staffMember.count({ where: { status: "ON_DUTY" } }),
    prisma.calendarShift.count(),
    prisma.wireBulletin.count(),
  ]);

  res.json({
    activeAssignments,
    totalStaff,
    onDutyStaff,
    todayShifts,
    wireCount,
    user: req.user,
  });
});

// Assignments (CRUD)
app.get("/api/desk/assignments", requireGatewayAuth, async (req: AuthRequest, res: Response) => {
  const assignments = await prisma.assignment.findMany({
    orderBy: { createdAt: "desc" },
  });
  res.json({ assignments });
});

app.post("/api/desk/assignments", requireGatewayAuth, async (req: AuthRequest, res: Response) => {
  const { title, description, department, status, priority, assigneeName, assigneeEmail, deadline } = req.body;
  if (!title) return res.status(400).json({ error: "Title is required" });

  const randomRotation = (Math.random() * 3 - 1.5); // between -1.5deg and +1.5deg

  const item = await prisma.assignment.create({
    data: {
      title,
      description: description || "",
      department: department || "OPERATIONS",
      status: status || "TODO",
      priority: priority || "STANDARD",
      assigneeName: assigneeName || req.user?.name || "Staff Member",
      assigneeEmail: assigneeEmail || req.user?.email || "staff@company.internal",
      deadline: deadline || "1700 HRS",
      rotation: parseFloat(randomRotation.toFixed(2)),
    },
  });

  res.json({ success: true, assignment: item });
});

app.patch("/api/desk/assignments/:id", requireGatewayAuth, async (req: AuthRequest, res: Response) => {
  const id = req.params.id as string;
  const { status, priority, title, description } = req.body;

  const updated = await prisma.assignment.update({
    where: { id },
    data: {
      ...(status && { status }),
      ...(priority && { priority }),
      ...(title && { title }),
      ...(description && { description }),
    },
  });

  res.json({ success: true, assignment: updated });
});

app.delete("/api/desk/assignments/:id", requireGatewayAuth, async (req: AuthRequest, res: Response) => {
  const id = req.params.id as string;
  await prisma.assignment.delete({ where: { id } });
  res.json({ success: true });
});

// Wire Bulletins
app.get("/api/desk/wire", requireGatewayAuth, async (req: AuthRequest, res: Response) => {
  const bulletins = await prisma.wireBulletin.findMany({
    orderBy: { createdAt: "desc" },
    take: 25,
  });
  res.json({ bulletins });
});

app.post("/api/desk/wire", requireGatewayAuth, async (req: AuthRequest, res: Response) => {
  const { headline, body, category, urgency } = req.body;
  if (!headline) return res.status(400).json({ error: "Headline is required" });

  const now = new Date();
  const timestamp = String(now.getHours()).padStart(2, "0") + String(now.getMinutes()).padStart(2, "0");

  const item = await prisma.wireBulletin.create({
    data: {
      timestamp,
      category: category || "OPERATIONS",
      headline,
      body: body || "",
      urgency: urgency || "NORMAL",
    },
  });

  res.json({ success: true, bulletin: item });
});

// Staff Roster
app.get("/api/desk/roster", requireGatewayAuth, async (req: AuthRequest, res: Response) => {
  const staff = await prisma.staffMember.findMany({
    orderBy: [{ status: "asc" }, { department: "asc" }],
  });
  res.json({ staff });
});

app.patch("/api/desk/roster/:id", requireGatewayAuth, async (req: AuthRequest, res: Response) => {
  const id = req.params.id as string;
  const { status } = req.body;

  const updated = await prisma.staffMember.update({
    where: { id },
    data: { ...(status && { status }) },
  });

  res.json({ success: true, staff: updated });
});

// Ledger
app.get("/api/desk/ledger", requireGatewayAuth, async (req: AuthRequest, res: Response) => {
  const records = await prisma.ledgerRecord.findMany({
    orderBy: { entryDate: "desc" },
  });

  const totalDebits = records.filter(r => r.type === "DEBIT").reduce((acc: number, r) => acc + r.amount, 0);
  const totalCredits = records.filter(r => r.type === "CREDIT").reduce((acc: number, r) => acc + r.amount, 0);

  res.json({
    records,
    summary: {
      totalDebits,
      totalCredits,
      netBalance: totalCredits - totalDebits,
    },
  });
});

app.post("/api/desk/ledger", requireGatewayAuth, async (req: AuthRequest, res: Response) => {
  const { description, category, amount, type } = req.body;
  if (!description || !amount) return res.status(400).json({ error: "Description and amount required" });

  const count = await prisma.ledgerRecord.count();
  const refNumber = `LED-${8840 + count + 1}`;
  const entryDate = new Date().toISOString().slice(0, 10);

  const item = await prisma.ledgerRecord.create({
    data: {
      refNumber,
      entryDate,
      description,
      category: category || "OPERATIONS",
      amount: parseFloat(amount),
      type: type || "DEBIT",
      authorizedBy: req.user?.name || "Staff Lead",
    },
  });

  res.json({ success: true, record: item });
});

// Archive
app.get("/api/desk/archive", requireGatewayAuth, async (req: AuthRequest, res: Response) => {
  const { department, search } = req.query as { department?: string; search?: string };

  const records = await prisma.archiveRecord.findMany({
    where: {
      ...(department && department !== "ALL" && { department }),
      ...(search && {
        OR: [
          { title: { contains: search } },
          { summary: { contains: search } },
          { tags: { contains: search } },
        ],
      }),
    },
    orderBy: { filingDate: "desc" },
  });

  res.json({ records });
});

app.post("/api/desk/archive", requireGatewayAuth, async (req: AuthRequest, res: Response) => {
  const { title, department, summary, tags } = req.body;
  if (!title) return res.status(400).json({ error: "Title required" });

  const count = await prisma.archiveRecord.count();
  const recordNumber = `REC-2026-${String(count + 1).padStart(3, "0")}`;
  const filingDate = new Date().toISOString().slice(0, 10);

  const item = await prisma.archiveRecord.create({
    data: {
      recordNumber,
      title,
      department: department || "OPERATIONS",
      filingDate,
      summary: summary || "",
      tags: tags || "General, Operations",
      filedBy: req.user?.name || "Operations Lead",
    },
  });

  res.json({ success: true, record: item });
});

// Messages
app.get("/api/desk/messages", requireGatewayAuth, async (req: AuthRequest, res: Response) => {
  const messages = await prisma.deskMessage.findMany({
    orderBy: { createdAt: "desc" },
  });
  res.json({ messages });
});

app.post("/api/desk/messages", requireGatewayAuth, async (req: AuthRequest, res: Response) => {
  const { subject, content, urgent, recipientEmail } = req.body;
  if (!subject || !content) return res.status(400).json({ error: "Subject and content required" });

  const item = await prisma.deskMessage.create({
    data: {
      senderName: req.user?.name || "Desk Operator",
      senderEmail: req.user?.email || "desk@company.internal",
      recipientEmail: recipientEmail || "desk@company.internal",
      subject,
      content,
      urgent: Boolean(urgent),
      read: false,
    },
  });

  res.json({ success: true, message: item });
});

// Calendar
app.get("/api/desk/calendar", requireGatewayAuth, async (req: AuthRequest, res: Response) => {
  const shifts = await prisma.calendarShift.findMany({
    orderBy: [{ date: "asc" }, { startTime: "asc" }],
  });
  res.json({ shifts });
});

// ─────────────────────────────────────────────────────────────────────────────
// 4. Main HTML Page (Tactile Paper-and-Ink Interface)
// ─────────────────────────────────────────────────────────────────────────────
app.get("/", requireGatewayAuth, (req: AuthRequest, res: Response) => {
  res.send(renderOperationsDeskApp(req.user));
});

// ─────────────────────────────────────────────────────────────────────────────
// 5. Neutral Gateway Intercept Screen Template
// ─────────────────────────────────────────────────────────────────────────────
function renderNeutralInterceptScreen(reason: string) {
  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Gateway Access Required — The Operations Desk</title>
  <script src="https://cdn.tailwindcss.com"></script>
  <link rel="preconnect" href="https://fonts.googleapis.com">
  <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
  <link href="https://fonts.googleapis.com/css2?family=Public+Sans:wght@400;600;700&family=IBM+Plex+Mono:wght@500;600&display=swap" rel="stylesheet">
  <style>
    body { font-family: 'Public Sans', sans-serif; background-color: #0f141f; color: #e2e8f0; }
    .mono { font-family: 'IBM Plex Mono', monospace; }
  </style>
</head>
<body class="min-h-screen flex flex-col justify-between p-6">
  <header class="w-full max-w-4xl mx-auto flex justify-between items-center py-4 border-b border-slate-800">
    <div class="flex items-center gap-3">
      <div class="w-3 h-3 bg-amber-500 rounded-sm"></div>
      <span class="font-bold tracking-wider text-slate-200 uppercase text-sm">CORPORATE ACCESS GATEWAY</span>
    </div>
    <span class="mono text-xs text-slate-400">NODE: DESK-UPSTREAM-3002</span>
  </header>

  <main class="w-full max-w-lg mx-auto my-12 bg-slate-900 border border-slate-700/80 rounded-xl p-8 shadow-2xl">
    <div class="flex items-center gap-3 text-amber-400 mb-4">
      <svg class="w-6 h-6 shrink-0" fill="none" stroke="currentColor" viewBox="0 0 24 24">
        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 15v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8z"/>
      </svg>
      <h1 class="text-lg font-bold tracking-wide uppercase">Gateway Access Required</h1>
    </div>

    <p class="text-sm text-slate-300 leading-relaxed mb-6">
      This enterprise application (<strong class="text-slate-100">The Operations Desk</strong>) is protected by the corporate Zero-Trust Access Gateway. An authenticated single-use token or active gateway session is required for access.
    </p>

    <div class="bg-slate-950 border border-slate-800 rounded-lg p-4 mb-6 mono text-xs space-y-2">
      <div class="flex justify-between text-slate-400">
        <span>GATEWAY STATUS:</span>
        <span class="text-amber-400 font-bold">ACCESS_DENIED</span>
      </div>
      <div class="flex justify-between text-slate-400">
        <span>INTERCEPT REASON:</span>
        <span class="text-slate-200">${reason.replace(/_/g, " ")}</span>
      </div>
      <div class="flex justify-between text-slate-400">
        <span>AUTH PROVIDER:</span>
        <span class="text-slate-300">GateZero Gateway (Port 3000)</span>
      </div>
    </div>

    <div class="space-y-3">
      <a href="${GATEWAY_URL}/dashboard" class="block w-full py-3 px-4 bg-blue-600 hover:bg-blue-500 text-white font-bold text-center text-xs rounded-lg transition-colors tracking-wider uppercase shadow-md">
        Authorize via GateZero Portal (Port 3000) →
      </a>
      <a href="${GATEWAY_URL}" class="block w-full py-2 px-4 bg-slate-800 hover:bg-slate-700 text-slate-300 text-center text-xs rounded-lg transition-colors">
        Return to Gateway Login Screen
      </a>
    </div>
  </main>

  <footer class="w-full max-w-4xl mx-auto py-4 border-t border-slate-800 flex justify-between items-center text-xs text-slate-500 mono">
    <span>© 2026 ENTERPRISE SECURITY GATEWAY</span>
    <span>ZERO-TRUST ENFORCEMENT ACTIVE</span>
  </footer>
</body>
</html>`;
}

// ─────────────────────────────────────────────────────────────────────────────
// 6. Complete Tactile Operations Desk Frontend Interface Template
// ─────────────────────────────────────────────────────────────────────────────
function renderOperationsDeskApp(user?: { name: string; email: string; role: string }) {
  return `<!DOCTYPE html>
<html lang="en" id="html-root" class="light">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>The Operations Desk — Corporate Operations & Dispatch Hub</title>
  <script src="https://cdn.tailwindcss.com"></script>
  <link rel="preconnect" href="https://fonts.googleapis.com">
  <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
  <link href="https://fonts.googleapis.com/css2?family=Bitter:ital,wght@0,400..900;1,400..900&family=IBM+Plex+Mono:ital,wght@0,400..700;1,400..700&family=Public+Sans:ital,wght@0,300..900;1,300..900&display=swap" rel="stylesheet">
  <link href="https://fonts.googleapis.com/css2?family=Material+Symbols+Outlined:wght,FILL@100..700,0..1&display=swap" rel="stylesheet">
  <script>
    tailwind.config = {
      darkMode: "class",
      theme: {
        extend: {
          colors: {
            "paper-base": "#E8E2D0",
            "paper-card": "#DED5BC",
            "ink-primary": "#21283B",
            "ink-secondary": "#5B6178",
            "accent-brass": "#B08D3E",
            "signal-progress": "#3B6EA5",
            "signal-done": "#3E7C6B",
            "signal-urgent": "#B4463A",
            "night-base": "#141721",
            "night-card": "#1e2230",
            "night-ink": "#e5e9f0",
            "night-sub": "#8a94a6",
          },
          fontFamily: {
            "masthead": ["Bitter", "serif"],
            "body": ["Public Sans", "sans-serif"],
            "mono": ["IBM Plex Mono", "monospace"],
          }
        }
      }
    }
  </script>
  <style>
    /* Paper & Ink Aesthetics */
    .paper-desk { background-color: #E8E2D0; color: #21283B; }
    .dark .paper-desk { background-color: #141721; color: #e5e9f0; }
    
    .card-surface { background-color: #DED5BC; border: 1px solid #c2b89d; box-shadow: 2px 3px 0px rgba(33, 40, 59, 0.15); }
    .dark .card-surface { background-color: #1e2230; border: 1px solid #2f364a; box-shadow: 2px 3px 0px rgba(0, 0, 0, 0.4); }

    .ink-rule { border-bottom: 2px solid #21283B; }
    .dark .ink-rule { border-bottom: 2px solid #e5e9f0; }

    .brass-pin {
      width: 14px; height: 14px;
      background: radial-gradient(circle at 35% 35%, #e6cb85, #B08D3E 70%, #73591f);
      border-radius: 50%;
      box-shadow: 1px 2px 3px rgba(0,0,0,0.35);
    }
    .urgent-pin {
      width: 14px; height: 14px;
      background: radial-gradient(circle at 35% 35%, #ff8578, #B4463A 70%, #6e1c14);
      border-radius: 50%;
      box-shadow: 1px 2px 3px rgba(0,0,0,0.35);
    }

    .tab-active {
      border-bottom: 3px solid #B08D3E !important;
      font-weight: 700;
      color: #21283B;
    }
    .dark .tab-active {
      color: #e5e9f0;
    }

    .folder-tab {
      clip-path: polygon(0% 0%, 85% 0%, 100% 100%, 0% 100%);
    }
  </style>
</head>
<body class="paper-desk font-body min-h-screen flex flex-col antialiased selection:bg-accent-brass selection:text-white">

  <!-- MASTHEAD & TOP NAVIGATION -->
  <header class="bg-paper-base dark:bg-night-base border-b-[3px] border-ink-primary dark:border-night-ink sticky top-0 z-40">
    <div class="max-w-[1440px] mx-auto px-6 pt-5 pb-0 flex flex-col">
      <div class="flex justify-between items-end mb-3">
        <div class="flex items-baseline gap-4">
          <h1 class="font-masthead text-2xl font-black tracking-widest text-ink-primary dark:text-night-ink uppercase">THE OPERATIONS DESK</h1>
          <span class="font-mono text-xs text-ink-secondary dark:text-night-sub hidden sm:inline">CENTRAL LOGISTICS &amp; FIELD HUB</span>
        </div>
        
        <div class="flex items-center gap-5 font-mono text-xs">
          <!-- Gateway Status Badge -->
          <div class="flex items-center gap-2 bg-emerald-950/20 dark:bg-emerald-950/40 border border-emerald-700/50 px-2.5 py-1 rounded text-emerald-800 dark:text-emerald-300 font-bold">
            <span class="w-2 h-2 rounded-full bg-emerald-600 animate-pulse"></span>
            <span>GATEZERO VERIFIED</span>
          </div>

          <!-- Operator Info -->
          <div class="hidden md:flex items-center gap-2 text-ink-secondary dark:text-night-sub">
            <span class="material-symbols-outlined text-base">badge</span>
            <span>${user?.name || "Operator"} (${user?.email || "staff@company.internal"})</span>
          </div>

          <!-- Desk Mode (Day / Night) Toggle -->
          <button onclick="toggleTheme()" class="px-2 py-1 border border-ink-secondary/40 rounded hover:bg-black/5 dark:hover:bg-white/5 transition flex items-center gap-1">
            <span id="theme-icon" class="material-symbols-outlined text-sm">dark_mode</span>
            <span id="theme-text" class="text-[11px] font-bold">NIGHT DESK</span>
          </button>

          <!-- GateZero Return / Logout -->
          <a href="/api/auth/logout" class="text-ink-secondary hover:text-signal-urgent dark:text-night-sub transition font-bold">
            [EXIT GATEWAY]
          </a>
        </div>
      </div>

      <!-- Section Navigation Tabs -->
      <nav class="flex gap-8 overflow-x-auto no-scrollbar pt-2">
        <button onclick="switchTab('overview')" id="tab-overview" class="pb-2.5 font-masthead text-sm tracking-wider uppercase transition tab-active">OVERVIEW</button>
        <button onclick="switchTab('assignments')" id="tab-assignments" class="pb-2.5 font-masthead text-sm tracking-wider uppercase text-ink-secondary dark:text-night-sub hover:text-ink-primary transition">ASSIGNMENTS</button>
        <button onclick="switchTab('wire')" id="tab-wire" class="pb-2.5 font-masthead text-sm tracking-wider uppercase text-ink-secondary dark:text-night-sub hover:text-ink-primary transition">THE WIRE</button>
        <button onclick="switchTab('roster')" id="tab-roster" class="pb-2.5 font-masthead text-sm tracking-wider uppercase text-ink-secondary dark:text-night-sub hover:text-ink-primary transition">ROSTER</button>
        <button onclick="switchTab('ledger')" id="tab-ledger" class="pb-2.5 font-masthead text-sm tracking-wider uppercase text-ink-secondary dark:text-night-sub hover:text-ink-primary transition">LEDGER</button>
        <button onclick="switchTab('archive')" id="tab-archive" class="pb-2.5 font-masthead text-sm tracking-wider uppercase text-ink-secondary dark:text-night-sub hover:text-ink-primary transition">ARCHIVE</button>
        <button onclick="switchTab('messages')" id="tab-messages" class="pb-2.5 font-masthead text-sm tracking-wider uppercase text-ink-secondary dark:text-night-sub hover:text-ink-primary transition">MEMOS</button>
        <button onclick="switchTab('calendar')" id="tab-calendar" class="pb-2.5 font-masthead text-sm tracking-wider uppercase text-ink-secondary dark:text-night-sub hover:text-ink-primary transition">SCHEDULE</button>
      </nav>
    </div>
  </header>

  <!-- MAIN APPLICATION CONTENT CONTAINER -->
  <main class="flex-grow max-w-[1440px] w-full mx-auto p-6">
    
    <!-- 1. OVERVIEW VIEW -->
    <section id="view-overview" class="space-y-6">
      <!-- Lead Summary Card -->
      <div class="card-surface p-6 relative rounded-sm">
        <div class="absolute -top-2 left-1/2 -translate-x-1/2 brass-pin"></div>
        <div class="flex justify-between items-start mb-3">
          <h2 class="font-masthead text-xl font-bold uppercase tracking-wider text-ink-primary dark:text-night-ink">CENTRAL DISPATCH &amp; OPERATIONS STATUS</h2>
          <span class="font-mono text-xs text-accent-brass font-bold bg-black/5 dark:bg-white/5 px-2 py-0.5 rounded">STATION 01 // NOMINAL</span>
        </div>
        <p class="text-sm text-ink-secondary dark:text-night-sub leading-relaxed max-w-4xl">
          Primary operations center coordinating enterprise logistics, network infrastructure, regional customer support escalation, and departmental facilities. All units report standard cadence. Check the live wire feed and assignments corkboard for active dispatches.
        </p>
        <div class="mt-4 pt-3 border-t border-dashed border-ink-secondary/30 flex flex-wrap justify-between items-center font-mono text-xs text-ink-secondary dark:text-night-sub gap-4">
          <span>OPERATIONAL UPTIME: <strong class="text-signal-done">99.98%</strong></span>
          <span>DISPATCH TELEMETRY: <strong class="text-ink-primary dark:text-night-ink">STABLE</strong></span>
          <span>GATEWAY TUNNEL: <strong class="text-accent-brass">ENCRYPTED (PORT 3000)</strong></span>
        </div>
      </div>

      <!-- KPI Summary Cards -->
      <div class="grid grid-cols-2 sm:grid-cols-4 gap-4" id="kpi-grid">
        <div class="card-surface p-4 text-center">
          <span class="font-mono text-xs text-ink-secondary dark:text-night-sub uppercase">Active Tasks</span>
          <div id="stat-tasks" class="font-mono text-2xl font-bold text-ink-primary dark:text-night-ink mt-1">--</div>
        </div>
        <div class="card-surface p-4 text-center">
          <span class="font-mono text-xs text-ink-secondary dark:text-night-sub uppercase">Staff On Duty</span>
          <div id="stat-staff" class="font-mono text-2xl font-bold text-signal-done mt-1">--</div>
        </div>
        <div class="card-surface p-4 text-center">
          <span class="font-mono text-xs text-ink-secondary dark:text-night-sub uppercase">Today Shifts</span>
          <div id="stat-shifts" class="font-mono text-2xl font-bold text-signal-progress mt-1">--</div>
        </div>
        <div class="card-surface p-4 text-center">
          <span class="font-mono text-xs text-ink-secondary dark:text-night-sub uppercase">Wire Bulletins</span>
          <div id="stat-wire" class="font-mono text-2xl font-bold text-accent-brass mt-1">--</div>
        </div>
      </div>

      <!-- Split Column: Latest Wire & Urgent Tasks -->
      <div class="grid grid-cols-1 lg:grid-cols-12 gap-6">
        <!-- Live Wire Digest -->
        <div class="lg:col-span-6 card-surface p-5">
          <div class="flex justify-between items-center border-b border-ink-primary/20 pb-2 mb-3">
            <span class="font-masthead font-bold text-sm uppercase">LATEST WIRE BULLETINS</span>
            <button onclick="switchTab('wire')" class="font-mono text-xs text-accent-brass hover:underline font-bold">VIEW ALL WIRE →</button>
          </div>
          <div id="overview-wire-list" class="space-y-3 font-mono text-xs">
            <div class="animate-pulse text-ink-secondary">Loading wire feed...</div>
          </div>
        </div>

        <!-- Urgent Assignments Digest -->
        <div class="lg:col-span-6 card-surface p-5">
          <div class="flex justify-between items-center border-b border-ink-primary/20 pb-2 mb-3">
            <span class="font-masthead font-bold text-sm uppercase">PINNED TASKS &amp; DELIVERABLES</span>
            <button onclick="switchTab('assignments')" class="font-mono text-xs text-accent-brass hover:underline font-bold">OPEN CORKBOARD →</button>
          </div>
          <div id="overview-assignments-list" class="space-y-3">
            <div class="animate-pulse text-ink-secondary font-mono text-xs">Loading tasks...</div>
          </div>
        </div>
      </div>
    </section>

    <!-- 2. ASSIGNMENTS CORKBOARD VIEW -->
    <section id="view-assignments" class="hidden space-y-6">
      <div class="flex justify-between items-center">
        <div>
          <h2 class="font-masthead text-xl font-bold uppercase tracking-wider text-ink-primary dark:text-night-ink">OPERATIONAL ASSIGNMENTS BOARD</h2>
          <p class="text-xs font-mono text-ink-secondary dark:text-night-sub">Tactile task cards pinned with active priority indicators.</p>
        </div>
        <button onclick="openNewTaskModal()" class="px-4 py-2 bg-ink-primary text-paper-base dark:bg-night-card dark:text-night-ink border border-accent-brass hover:bg-accent-brass hover:text-white transition font-mono text-xs font-bold uppercase flex items-center gap-2">
          <span>+ PIN NEW ASSIGNMENT</span>
        </button>
      </div>

      <!-- Corkboard 3-Column Grid -->
      <div class="grid grid-cols-1 md:grid-cols-3 gap-6">
        <!-- Column 1: TO DO -->
        <div class="bg-black/5 dark:bg-white/5 p-4 rounded border border-ink-secondary/20 min-h-[500px]">
          <div class="flex justify-between items-center border-b-2 border-ink-secondary/40 pb-2 mb-4">
            <span class="font-masthead font-bold text-sm uppercase tracking-wider text-ink-secondary dark:text-night-sub">TO DO / DISPATCHED</span>
            <span id="count-todo" class="font-mono text-xs bg-ink-secondary/20 px-2 py-0.5 rounded font-bold">0</span>
          </div>
          <div id="col-todo" class="space-y-4"></div>
        </div>

        <!-- Column 2: IN PROGRESS -->
        <div class="bg-black/5 dark:bg-white/5 p-4 rounded border border-signal-progress/30 min-h-[500px]">
          <div class="flex justify-between items-center border-b-2 border-signal-progress pb-2 mb-4">
            <span class="font-masthead font-bold text-sm uppercase tracking-wider text-signal-progress">IN PROGRESS / ACTIVE</span>
            <span id="count-progress" class="font-mono text-xs bg-signal-progress/20 text-signal-progress px-2 py-0.5 rounded font-bold">0</span>
          </div>
          <div id="col-progress" class="space-y-4"></div>
        </div>

        <!-- Column 3: COMPLETED -->
        <div class="bg-black/5 dark:bg-white/5 p-4 rounded border border-signal-done/30 min-h-[500px]">
          <div class="flex justify-between items-center border-b-2 border-signal-done pb-2 mb-4">
            <span class="font-masthead font-bold text-sm uppercase tracking-wider text-signal-done">COMPLETED / FILED</span>
            <span id="count-completed" class="font-mono text-xs bg-signal-done/20 text-signal-done px-2 py-0.5 rounded font-bold">0</span>
          </div>
          <div id="col-completed" class="space-y-4"></div>
        </div>
      </div>
    </section>

    <!-- 3. THE WIRE VIEW -->
    <section id="view-wire" class="hidden space-y-6">
      <div class="flex justify-between items-center">
        <div>
          <h2 class="font-masthead text-xl font-bold uppercase tracking-wider text-ink-primary dark:text-night-ink">THE WIRE — REAL-TIME DISPATCH FEED</h2>
          <p class="text-xs font-mono text-ink-secondary dark:text-night-sub">Chronological operational announcements &amp; system status logs.</p>
        </div>
        <button onclick="openNewWireModal()" class="px-4 py-2 bg-ink-primary text-paper-base dark:bg-night-card dark:text-night-ink border border-accent-brass hover:bg-accent-brass hover:text-white transition font-mono text-xs font-bold uppercase">
          + BROADCAST WIRE BULLETIN
        </button>
      </div>

      <div class="card-surface p-6 font-mono text-xs space-y-4" id="wire-full-feed">
        <div class="animate-pulse text-ink-secondary">Connecting to operations wire...</div>
      </div>
    </section>

    <!-- 4. ROSTER VIEW -->
    <section id="view-roster" class="hidden space-y-6">
      <div class="flex justify-between items-center">
        <div>
          <h2 class="font-masthead text-xl font-bold uppercase tracking-wider text-ink-primary dark:text-night-ink">COMPANY STAFF &amp; OPERATIONS ROSTER</h2>
          <p class="text-xs font-mono text-ink-secondary dark:text-night-sub">Active personnel, duty statuses, desk stations, and departmental units.</p>
        </div>
      </div>

      <div class="card-surface overflow-hidden">
        <div class="overflow-x-auto">
          <table class="w-full text-left font-mono text-xs">
            <thead class="bg-ink-primary text-paper-base dark:bg-night-card dark:text-night-ink">
              <tr>
                <th class="p-3">NAME &amp; CONTACT</th>
                <th class="p-3">ROLE</th>
                <th class="p-3">DEPARTMENT</th>
                <th class="p-3">STATION</th>
                <th class="p-3">DUTY STATUS</th>
                <th class="p-3 text-right">ACTION</th>
              </tr>
            </thead>
            <tbody id="roster-table-body" class="divide-y divide-ink-secondary/20">
              <tr><td colspan="6" class="p-4 text-center animate-pulse">Loading staff roster...</td></tr>
            </tbody>
          </table>
        </div>
      </div>
    </section>

    <!-- 5. LEDGER VIEW -->
    <section id="view-ledger" class="hidden space-y-6">
      <div class="flex justify-between items-center">
        <div>
          <h2 class="font-masthead text-xl font-bold uppercase tracking-wider text-ink-primary dark:text-night-ink">DISPATCH &amp; OPERATIONS LEDGER</h2>
          <p class="text-xs font-mono text-ink-secondary dark:text-night-sub">Operational expenditures, vendor procurement, and logistical cost tracking.</p>
        </div>
        <button onclick="openNewLedgerModal()" class="px-4 py-2 bg-ink-primary text-paper-base dark:bg-night-card dark:text-night-ink border border-accent-brass hover:bg-accent-brass hover:text-white transition font-mono text-xs font-bold uppercase">
          + RECORD LEDGER ENTRY
        </button>
      </div>

      <!-- Ledger Balance Summary Cards -->
      <div class="grid grid-cols-1 sm:grid-cols-3 gap-4">
        <div class="card-surface p-4 font-mono text-xs">
          <span class="text-ink-secondary dark:text-night-sub">TOTAL DEBITS</span>
          <div id="ledger-debits" class="text-xl font-bold text-signal-urgent mt-1">$0.00</div>
        </div>
        <div class="card-surface p-4 font-mono text-xs">
          <span class="text-ink-secondary dark:text-night-sub">TOTAL CREDITS</span>
          <div id="ledger-credits" class="text-xl font-bold text-signal-done mt-1">$0.00</div>
        </div>
        <div class="card-surface p-4 font-mono text-xs">
          <span class="text-ink-secondary dark:text-night-sub">NET OPERATIONAL BALANCE</span>
          <div id="ledger-net" class="text-xl font-bold text-ink-primary dark:text-night-ink mt-1">$0.00</div>
        </div>
      </div>

      <div class="card-surface overflow-hidden">
        <div class="overflow-x-auto">
          <table class="w-full text-left font-mono text-xs">
            <thead class="bg-ink-primary text-paper-base dark:bg-night-card dark:text-night-ink">
              <tr>
                <th class="p-3">REF #</th>
                <th class="p-3">DATE</th>
                <th class="p-3">DESCRIPTION</th>
                <th class="p-3">CATEGORY</th>
                <th class="p-3">AUTHORIZED BY</th>
                <th class="p-3 text-right">AMOUNT</th>
              </tr>
            </thead>
            <tbody id="ledger-table-body" class="divide-y divide-ink-secondary/20">
              <tr><td colspan="6" class="p-4 text-center animate-pulse">Loading ledger entries...</td></tr>
            </tbody>
          </table>
        </div>
      </div>
    </section>

    <!-- 6. ARCHIVE VIEW -->
    <section id="view-archive" class="hidden space-y-6">
      <div class="flex flex-col sm:flex-row justify-between sm:items-center gap-4">
        <div>
          <h2 class="font-masthead text-xl font-bold uppercase tracking-wider text-ink-primary dark:text-night-ink">COMPANY ARCHIVE &amp; RECORDS</h2>
          <p class="text-xs font-mono text-ink-secondary dark:text-night-sub">Indexed historical filings, compliance documentation, and project post-mortems.</p>
        </div>
        <button onclick="openNewArchiveModal()" class="px-4 py-2 bg-ink-primary text-paper-base dark:bg-night-card dark:text-night-ink border border-accent-brass hover:bg-accent-brass hover:text-white transition font-mono text-xs font-bold uppercase shrink-0">
          + FILE NEW RECORD
        </button>
      </div>

      <!-- Search & Filter Controls -->
      <div class="card-surface p-4 flex flex-col sm:flex-row gap-4 font-mono text-xs">
        <input type="text" id="archive-search" oninput="loadArchive()" placeholder="Search archive by keyword, tag, or title..." class="flex-1 p-2 bg-paper-base dark:bg-night-base border border-ink-secondary/40 outline-none text-inherit">
        <select id="archive-filter-dept" onchange="loadArchive()" class="p-2 bg-paper-base dark:bg-night-base border border-ink-secondary/40 outline-none text-inherit font-mono">
          <option value="ALL">ALL DEPARTMENTS</option>
          <option value="OPERATIONS">OPERATIONS</option>
          <option value="LOGISTICS">LOGISTICS</option>
          <option value="ENGINEERING">ENGINEERING</option>
          <option value="FACILITIES">FACILITIES</option>
          <option value="SUPPORT">SUPPORT</option>
          <option value="FINANCE">FINANCE</option>
        </select>
      </div>

      <div id="archive-grid" class="grid grid-cols-1 md:grid-cols-2 gap-6"></div>
    </section>

    <!-- 7. MEMOS (MESSAGES) VIEW -->
    <section id="view-messages" class="hidden space-y-6">
      <div class="flex justify-between items-center">
        <div>
          <h2 class="font-masthead text-xl font-bold uppercase tracking-wider text-ink-primary dark:text-night-ink">DEPARTMENTAL COMMS &amp; MEMOS</h2>
          <p class="text-xs font-mono text-ink-secondary dark:text-night-sub">Inter-departmental communications and urgent priority dispatches.</p>
        </div>
        <button onclick="openNewMessageModal()" class="px-4 py-2 bg-ink-primary text-paper-base dark:bg-night-card dark:text-night-ink border border-accent-brass hover:bg-accent-brass hover:text-white transition font-mono text-xs font-bold uppercase">
          + COMPOSE MEMO
        </button>
      </div>

      <div id="messages-list" class="space-y-4"></div>
    </section>

    <!-- 8. SCHEDULE (CALENDAR) VIEW -->
    <section id="view-calendar" class="hidden space-y-6">
      <div>
        <h2 class="font-masthead text-xl font-bold uppercase tracking-wider text-ink-primary dark:text-night-ink">OPERATIONAL SHIFT &amp; ON-CALL SCHEDULE</h2>
        <p class="text-xs font-mono text-ink-secondary dark:text-night-sub">Weekly shift rotations, desk coverage, and scheduled maintenance windows.</p>
      </div>

      <div id="calendar-shifts-grid" class="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-6"></div>
    </section>

  </main>

  <!-- MODALS CONTAINER -->
  <div id="modal-backdrop" class="fixed inset-0 bg-black/60 backdrop-blur-sm z-50 hidden flex items-center justify-center p-4">
    <div id="modal-content" class="card-surface p-6 max-w-lg w-full rounded-sm relative border-2 border-accent-brass"></div>
  </div>

  <!-- FOOTER INSTRUMENT STRIP -->
  <footer class="bg-paper-card dark:bg-night-card border-t border-ink-secondary/30 py-3 px-6 text-xs font-mono flex flex-wrap justify-between items-center text-ink-secondary dark:text-night-sub mt-12">
    <div>THE OPERATIONS DESK — v1.0.0 (PORT 3002)</div>
    <div class="flex items-center gap-4">
      <span>SECURED BY: GATEZERO ZERO-TRUST GATEWAY</span>
      <span class="text-signal-done font-bold">● LIVE VERIFIED</span>
    </div>
  </footer>

  <!-- CLIENT-SIDE CONTROLLER SCRIPT -->
  <script>
    let currentTab = 'overview';

    // HTML Entity Sanitizer (XSS Defense)
    function escapeHtml(str) {
      if (str === null || str === undefined) return '';
      return String(str)
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&#39;');
    }

    // Theme Toggle
    function toggleTheme() {
      const html = document.getElementById('html-root');
      const isDark = html.classList.toggle('dark');
      document.getElementById('theme-icon').textContent = isDark ? 'light_mode' : 'dark_mode';
      document.getElementById('theme-text').textContent = isDark ? 'DAY DESK' : 'NIGHT DESK';
    }

    // Navigation Switcher
    function switchTab(tabId) {
      currentTab = tabId;
      document.querySelectorAll('main > section').forEach(sec => sec.classList.add('hidden'));
      document.querySelectorAll('nav button').forEach(btn => {
        btn.classList.remove('tab-active');
        btn.classList.add('text-ink-secondary', 'dark:text-night-sub');
      });

      const targetSec = document.getElementById('view-' + tabId);
      const targetBtn = document.getElementById('tab-' + tabId);
      if (targetSec) targetSec.classList.remove('hidden');
      if (targetBtn) {
        targetBtn.classList.add('tab-active');
        targetBtn.classList.remove('text-ink-secondary', 'dark:text-night-sub');
      }

      // Load tab-specific data
      if (tabId === 'overview') loadOverview();
      if (tabId === 'assignments') loadAssignments();
      if (tabId === 'wire') loadWire();
      if (tabId === 'roster') loadRoster();
      if (tabId === 'ledger') loadLedger();
      if (tabId === 'archive') loadArchive();
      if (tabId === 'messages') loadMessages();
      if (tabId === 'calendar') loadCalendar();
    }

    // Modal Helpers
    function closeModal() {
      document.getElementById('modal-backdrop').classList.add('hidden');
    }

    // 1. Overview Loader
    async function loadOverview() {
      try {
        const [statsRes, wireRes, tasksRes] = await Promise.all([
          fetch('/api/desk/stats'),
          fetch('/api/desk/wire'),
          fetch('/api/desk/assignments')
        ]);
        const stats = await statsRes.json();
        const wire = await wireRes.json();
        const tasks = await tasksRes.json();

        document.getElementById('stat-tasks').textContent = stats.activeAssignments ?? 0;
        document.getElementById('stat-staff').textContent = (stats.onDutyStaff ?? 0) + ' / ' + (stats.totalStaff ?? 0);
        document.getElementById('stat-shifts').textContent = stats.todayShifts ?? 0;
        document.getElementById('stat-wire').textContent = stats.wireCount ?? 0;

        // Render mini wire
        const wireEl = document.getElementById('overview-wire-list');
        wireEl.innerHTML = (wire.bulletins || []).slice(0, 4).map(b => \`
          <div class="border-b border-dotted border-ink-secondary/20 pb-2">
            <div class="flex items-center gap-2">
              <span class="text-accent-brass font-bold">[\${escapeHtml(b.timestamp)}]</span>
              <span class="font-bold \${b.urgency === 'FLASH' ? 'text-signal-urgent' : 'text-ink-primary dark:text-night-ink'}">\${escapeHtml(b.headline)}</span>
            </div>
            <p class="text-ink-secondary dark:text-night-sub mt-0.5 text-[11px]">\${escapeHtml(b.body)}</p>
          </div>
        \`).join('') || '<div class="text-ink-secondary">No active wire bulletins</div>';

        // Render mini tasks
        const tasksEl = document.getElementById('overview-assignments-list');
        tasksEl.innerHTML = (tasks.assignments || []).slice(0, 4).map(t => \`
          <div class="p-3 bg-black/5 dark:bg-white/5 border border-ink-secondary/20 flex justify-between items-center">
            <div>
              <div class="font-bold text-xs \${t.priority === 'URGENT' ? 'text-signal-urgent' : 'text-ink-primary dark:text-night-ink'}">\${escapeHtml(t.title)}</div>
              <div class="font-mono text-[10px] text-ink-secondary dark:text-night-sub">\${escapeHtml(t.department)} // \${escapeHtml(t.assigneeName)} // DUE \${escapeHtml(t.deadline)}</div>
            </div>
            <span class="font-mono text-[10px] px-2 py-0.5 rounded font-bold \${t.status === 'COMPLETED' ? 'bg-signal-done/20 text-signal-done' : t.status === 'IN_PROGRESS' ? 'bg-signal-progress/20 text-signal-progress' : 'bg-ink-secondary/20 text-ink-secondary'}">\${escapeHtml(t.status.replace('_', ' '))}</span>
          </div>
        \`).join('') || '<div class="text-ink-secondary">No active tasks</div>';
      } catch (err) {
        console.error(err);
      }
    }

    // 2. Assignments Loader
    async function loadAssignments() {
      const res = await fetch('/api/desk/assignments');
      const data = await res.json();
      const items = data.assignments || [];

      const todo = items.filter(i => i.status === 'TODO');
      const progress = items.filter(i => i.status === 'IN_PROGRESS');
      const completed = items.filter(i => i.status === 'COMPLETED');

      document.getElementById('count-todo').textContent = todo.length;
      document.getElementById('count-progress').textContent = progress.length;
      document.getElementById('count-completed').textContent = completed.length;

      const renderCard = (t) => \`
        <div class="card-surface p-4 relative rounded-sm group transition-transform hover:scale-[1.02]" style="transform: rotate(\${Number(t.rotation) || 0}deg);">
          <div class="absolute -top-2 left-1/2 -translate-x-1/2 \${t.priority === 'URGENT' ? 'urgent-pin' : 'brass-pin'}"></div>
          
          <div class="flex justify-between items-start mb-2 pt-1">
            <span class="font-mono text-[10px] font-bold text-ink-secondary dark:text-night-sub">\${escapeHtml(t.department)}</span>
            <span class="font-mono text-[10px] font-bold \${t.priority === 'URGENT' ? 'text-signal-urgent' : 'text-accent-brass'}">\${escapeHtml(t.priority)}</span>
          </div>

          <h3 class="font-bold text-sm text-ink-primary dark:text-night-ink mb-1.5 leading-snug">\${escapeHtml(t.title)}</h3>
          <p class="text-xs text-ink-secondary dark:text-night-sub mb-3 leading-relaxed">\${escapeHtml(t.description || '')}</p>

          <div class="pt-2 border-t border-dotted border-ink-secondary/30 flex justify-between items-center font-mono text-[10px] text-ink-secondary dark:text-night-sub">
            <span>\${escapeHtml(t.assigneeName)}</span>
            <span class="font-bold">DUE \${escapeHtml(t.deadline)}</span>
          </div>

          <!-- Quick Move Dropdown -->
          <div class="mt-3 flex justify-between items-center pt-2 border-t border-ink-secondary/10">
            <select onchange="updateAssignmentStatus('\${escapeHtml(t.id)}', this.value)" class="bg-paper-base dark:bg-night-base text-[10px] font-mono p-1 border border-ink-secondary/30 rounded outline-none">
              <option value="TODO" \${t.status === 'TODO' ? 'selected' : ''}>→ TO DO</option>
              <option value="IN_PROGRESS" \${t.status === 'IN_PROGRESS' ? 'selected' : ''}>→ IN PROGRESS</option>
              <option value="COMPLETED" \${t.status === 'COMPLETED' ? 'selected' : ''}>→ COMPLETED</option>
            </select>
            <button onclick="deleteAssignment('\${escapeHtml(t.id)}')" class="text-signal-urgent hover:underline font-mono text-[10px]">✕ DELETE</button>
          </div>
        </div>
      \`;

      document.getElementById('col-todo').innerHTML = todo.map(renderCard).join('') || '<div class="text-center text-xs font-mono text-ink-secondary py-8">No tasks in queue</div>';
      document.getElementById('col-progress').innerHTML = progress.map(renderCard).join('') || '<div class="text-center text-xs font-mono text-ink-secondary py-8">No active tasks</div>';
      document.getElementById('col-completed').innerHTML = completed.map(renderCard).join('') || '<div class="text-center text-xs font-mono text-ink-secondary py-8">No completed tasks</div>';
    }

    async function updateAssignmentStatus(id, newStatus) {
      await fetch('/api/desk/assignments/' + encodeURIComponent(id), {
        method: 'PATCH',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ status: newStatus })
      });
      loadAssignments();
    }

    async function deleteAssignment(id) {
      if (!confirm('Remove this pinned assignment from board?')) return;
      await fetch('/api/desk/assignments/' + encodeURIComponent(id), { method: 'DELETE' });
      loadAssignments();
    }

    function openNewTaskModal() {
      const modal = document.getElementById('modal-content');
      modal.innerHTML = \`
        <div class="flex justify-between items-center border-b border-ink-primary/20 pb-3 mb-4">
          <h3 class="font-masthead font-bold text-lg uppercase">PIN NEW ASSIGNMENT</h3>
          <button onclick="closeModal()" class="text-ink-secondary hover:text-ink-primary font-mono text-sm">✕</button>
        </div>
        <form onsubmit="submitNewTask(event)" class="space-y-3 font-mono text-xs">
          <div>
            <label class="block text-ink-secondary dark:text-night-sub mb-1">TASK TITLE *</label>
            <input type="text" name="title" required class="w-full p-2 bg-paper-base dark:bg-night-base border border-ink-secondary/40 outline-none">
          </div>
          <div>
            <label class="block text-ink-secondary dark:text-night-sub mb-1">DESCRIPTION</label>
            <textarea name="description" rows="3" class="w-full p-2 bg-paper-base dark:bg-night-base border border-ink-secondary/40 outline-none"></textarea>
          </div>
          <div class="grid grid-cols-2 gap-3">
            <div>
              <label class="block text-ink-secondary dark:text-night-sub mb-1">DEPARTMENT</label>
              <select name="department" class="w-full p-2 bg-paper-base dark:bg-night-base border border-ink-secondary/40 outline-none">
                <option value="OPERATIONS">OPERATIONS</option>
                <option value="LOGISTICS">LOGISTICS</option>
                <option value="ENGINEERING">ENGINEERING</option>
                <option value="SUPPORT">SUPPORT</option>
                <option value="FACILITIES">FACILITIES</option>
                <option value="FINANCE">FINANCE</option>
              </select>
            </div>
            <div>
              <label class="block text-ink-secondary dark:text-night-sub mb-1">PRIORITY</label>
              <select name="priority" class="w-full p-2 bg-paper-base dark:bg-night-base border border-ink-secondary/40 outline-none">
                <option value="STANDARD">STANDARD (BRASS PIN)</option>
                <option value="URGENT">URGENT (RED PIN)</option>
              </select>
            </div>
          </div>
          <div class="grid grid-cols-2 gap-3">
            <div>
              <label class="block text-ink-secondary dark:text-night-sub mb-1">ASSIGNEE NAME</label>
              <input type="text" name="assigneeName" value="Marcus Vance" class="w-full p-2 bg-paper-base dark:bg-night-base border border-ink-secondary/40 outline-none">
            </div>
            <div>
              <label class="block text-ink-secondary dark:text-night-sub mb-1">DEADLINE / TIME</label>
              <input type="text" name="deadline" value="1700 HRS" class="w-full p-2 bg-paper-base dark:bg-night-base border border-ink-secondary/40 outline-none">
            </div>
          </div>
          <div class="flex justify-end gap-3 pt-3">
            <button type="button" onclick="closeModal()" class="px-4 py-2 border border-ink-secondary/40">Cancel</button>
            <button type="submit" class="px-4 py-2 bg-ink-primary text-paper-base dark:bg-night-card dark:text-night-ink border border-accent-brass font-bold">Pin Task Card →</button>
          </div>
        </form>
      \`;
      document.getElementById('modal-backdrop').classList.remove('hidden');
    }

    async function submitNewTask(e) {
      e.preventDefault();
      const formData = new FormData(e.target);
      const data = Object.fromEntries(formData.entries());
      await fetch('/api/desk/assignments', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(data)
      });
      closeModal();
      loadAssignments();
    }

    // 3. Wire Loader
    async function loadWire() {
      const res = await fetch('/api/desk/wire');
      const data = await res.json();
      const el = document.getElementById('wire-full-feed');
      el.innerHTML = (data.bulletins || []).map(b => \`
        <div class="p-4 border-l-4 \${b.urgency === 'FLASH' ? 'border-signal-urgent bg-signal-urgent/5' : 'border-accent-brass bg-black/5 dark:bg-white/5'}">
          <div class="flex justify-between items-center mb-1">
            <div class="flex items-center gap-2">
              <span class="text-accent-brass font-bold">[\${escapeHtml(b.timestamp)} HRS]</span>
              <span class="px-1.5 py-0.2 bg-ink-secondary/20 rounded font-bold text-[10px]">\${escapeHtml(b.category)}</span>
              \${b.urgency === 'FLASH' ? '<span class="text-signal-urgent font-bold animate-pulse">● FLASH PRIORITY</span>' : ''}
            </div>
            <span class="text-ink-secondary dark:text-night-sub text-[10px]">\${new Date(b.createdAt).toLocaleDateString()}</span>
          </div>
          <h4 class="font-bold text-sm text-ink-primary dark:text-night-ink mb-1">\${escapeHtml(b.headline)}</h4>
          <p class="text-ink-secondary dark:text-night-sub leading-relaxed">\${escapeHtml(b.body)}</p>
        </div>
      \`).join('') || '<div class="text-center py-6 text-ink-secondary">Wire buffer empty</div>';
    }

    function openNewWireModal() {
      const modal = document.getElementById('modal-content');
      modal.innerHTML = \`
        <div class="flex justify-between items-center border-b border-ink-primary/20 pb-3 mb-4">
          <h3 class="font-masthead font-bold text-lg uppercase">BROADCAST WIRE BULLETIN</h3>
          <button onclick="closeModal()" class="text-ink-secondary hover:text-ink-primary font-mono text-sm">✕</button>
        </div>
        <form onsubmit="submitNewWire(event)" class="space-y-3 font-mono text-xs">
          <div>
            <label class="block text-ink-secondary dark:text-night-sub mb-1">BULLETIN HEADLINE *</label>
            <input type="text" name="headline" required class="w-full p-2 bg-paper-base dark:bg-night-base border border-ink-secondary/40 outline-none">
          </div>
          <div>
            <label class="block text-ink-secondary dark:text-night-sub mb-1">CONTENT BODY *</label>
            <textarea name="body" rows="3" required class="w-full p-2 bg-paper-base dark:bg-night-base border border-ink-secondary/40 outline-none"></textarea>
          </div>
          <div class="grid grid-cols-2 gap-3">
            <div>
              <label class="block text-ink-secondary dark:text-night-sub mb-1">CATEGORY</label>
              <select name="category" class="w-full p-2 bg-paper-base dark:bg-night-base border border-ink-secondary/40 outline-none">
                <option value="OPERATIONS">OPERATIONS</option>
                <option value="SYSTEM_STATUS">SYSTEM STATUS</option>
                <option value="LOGISTICS">LOGISTICS</option>
                <option value="FACILITY">FACILITY</option>
                <option value="ANNOUNCEMENT">ANNOUNCEMENT</option>
              </select>
            </div>
            <div>
              <label class="block text-ink-secondary dark:text-night-sub mb-1">URGENCY LEVEL</label>
              <select name="urgency" class="w-full p-2 bg-paper-base dark:bg-night-base border border-ink-secondary/40 outline-none">
                <option value="NORMAL">NORMAL</option>
                <option value="FLASH">FLASH PRIORITY</option>
              </select>
            </div>
          </div>
          <div class="flex justify-end gap-3 pt-3">
            <button type="button" onclick="closeModal()" class="px-4 py-2 border border-ink-secondary/40">Cancel</button>
            <button type="submit" class="px-4 py-2 bg-ink-primary text-paper-base dark:bg-night-card dark:text-night-ink border border-accent-brass font-bold">Transmit to Wire →</button>
          </div>
        </form>
      \`;
      document.getElementById('modal-backdrop').classList.remove('hidden');
    }

    async function submitNewWire(e) {
      e.preventDefault();
      const formData = new FormData(e.target);
      const data = Object.fromEntries(formData.entries());
      await fetch('/api/desk/wire', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(data)
      });
      closeModal();
      loadWire();
    }

    // 4. Roster Loader
    async function loadRoster() {
      const res = await fetch('/api/desk/roster');
      const data = await res.json();
      const tbody = document.getElementById('roster-table-body');
      tbody.innerHTML = (data.staff || []).map(s => \`
        <tr class="hover:bg-black/5 dark:hover:bg-white/5 transition">
          <td class="p-3">
            <div class="font-bold text-ink-primary dark:text-night-ink">\${escapeHtml(s.name)}</div>
            <div class="text-[11px] text-ink-secondary dark:text-night-sub">\${escapeHtml(s.email)} • \${escapeHtml(s.extension)}</div>
          </td>
          <td class="p-3 text-ink-secondary dark:text-night-sub">\${escapeHtml(s.role)}</td>
          <td class="p-3 font-bold">\${escapeHtml(s.department)}</td>
          <td class="p-3 text-ink-secondary dark:text-night-sub">\${escapeHtml(s.deskLocation)}</td>
          <td class="p-3">
            <span class="px-2 py-0.5 rounded font-bold text-[10px] \${s.status === 'ON_DUTY' ? 'bg-signal-done/20 text-signal-done' : s.status === 'REMOTE' ? 'bg-signal-progress/20 text-signal-progress' : s.status === 'ON_CALL' ? 'bg-accent-brass/20 text-accent-brass' : 'bg-ink-secondary/20 text-ink-secondary'}">\${escapeHtml(s.status.replace('_', ' '))}</span>
          </td>
          <td class="p-3 text-right">
            <select onchange="updateStaffStatus('\${escapeHtml(s.id)}', this.value)" class="bg-paper-base dark:bg-night-base text-[10px] p-1 border border-ink-secondary/30 rounded outline-none font-mono">
              <option value="ON_DUTY" \${s.status === 'ON_DUTY' ? 'selected' : ''}>ON DUTY</option>
              <option value="REMOTE" \${s.status === 'REMOTE' ? 'selected' : ''}>REMOTE</option>
              <option value="ON_CALL" \${s.status === 'ON_CALL' ? 'selected' : ''}>ON CALL</option>
              <option value="OFF_DUTY" \${s.status === 'OFF_DUTY' ? 'selected' : ''}>OFF DUTY</option>
            </select>
          </td>
        </tr>
      \`).join('');
    }

    async function updateStaffStatus(id, newStatus) {
      await fetch('/api/desk/roster/' + encodeURIComponent(id), {
        method: 'PATCH',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ status: newStatus })
      });
      loadRoster();
    }

    // 5. Ledger Loader
    async function loadLedger() {
      const res = await fetch('/api/desk/ledger');
      const data = await res.json();
      
      document.getElementById('ledger-debits').textContent = '$' + (data.summary?.totalDebits || 0).toLocaleString('en-US', { minimumFractionDigits: 2 });
      document.getElementById('ledger-credits').textContent = '$' + (data.summary?.totalCredits || 0).toLocaleString('en-US', { minimumFractionDigits: 2 });
      document.getElementById('ledger-net').textContent = '$' + (data.summary?.netBalance || 0).toLocaleString('en-US', { minimumFractionDigits: 2 });

      const tbody = document.getElementById('ledger-table-body');
      tbody.innerHTML = (data.records || []).map(r => \`
        <tr class="hover:bg-black/5 dark:hover:bg-white/5 transition">
          <td class="p-3 font-bold text-accent-brass">\${escapeHtml(r.refNumber)}</td>
          <td class="p-3 text-ink-secondary dark:text-night-sub">\${escapeHtml(r.entryDate)}</td>
          <td class="p-3 font-bold text-ink-primary dark:text-night-ink">\${escapeHtml(r.description)}</td>
          <td class="p-3"><span class="px-2 py-0.5 bg-ink-secondary/15 rounded text-[10px]">\${escapeHtml(r.category)}</span></td>
          <td class="p-3 text-ink-secondary dark:text-night-sub">\${escapeHtml(r.authorizedBy)}</td>
          <td class="p-3 text-right font-bold \${r.type === 'DEBIT' ? 'text-signal-urgent' : 'text-signal-done'}">
            \${r.type === 'DEBIT' ? '-' : '+'}$ \${Number(r.amount).toLocaleString('en-US', { minimumFractionDigits: 2 })}
          </td>
        </tr>
      \`).join('');
    }

    function openNewLedgerModal() {
      const modal = document.getElementById('modal-content');
      modal.innerHTML = \`
        <div class="flex justify-between items-center border-b border-ink-primary/20 pb-3 mb-4">
          <h3 class="font-masthead font-bold text-lg uppercase">RECORD LEDGER ENTRY</h3>
          <button onclick="closeModal()" class="text-ink-secondary hover:text-ink-primary font-mono text-sm">✕</button>
        </div>
        <form onsubmit="submitNewLedger(event)" class="space-y-3 font-mono text-xs">
          <div>
            <label class="block text-ink-secondary dark:text-night-sub mb-1">TRANSACTION DESCRIPTION *</label>
            <input type="text" name="description" required class="w-full p-2 bg-paper-base dark:bg-night-base border border-ink-secondary/40 outline-none">
          </div>
          <div class="grid grid-cols-2 gap-3">
            <div>
              <label class="block text-ink-secondary dark:text-night-sub mb-1">AMOUNT ($) *</label>
              <input type="number" step="0.01" name="amount" required class="w-full p-2 bg-paper-base dark:bg-night-base border border-ink-secondary/40 outline-none">
            </div>
            <div>
              <label class="block text-ink-secondary dark:text-night-sub mb-1">ENTRY TYPE</label>
              <select name="type" class="w-full p-2 bg-paper-base dark:bg-night-base border border-ink-secondary/40 outline-none">
                <option value="DEBIT">DEBIT (EXPENSE / OUTFLOW)</option>
                <option value="CREDIT">CREDIT (INFLOW / REIMBURSE)</option>
              </select>
            </div>
          </div>
          <div>
            <label class="block text-ink-secondary dark:text-night-sub mb-1">CATEGORY</label>
            <select name="category" class="w-full p-2 bg-paper-base dark:bg-night-base border border-ink-secondary/40 outline-none">
              <option value="PROCUREMENT">PROCUREMENT</option>
              <option value="INFRASTRUCTURE">INFRASTRUCTURE</option>
              <option value="VENDOR_PAYMENT">VENDOR PAYMENT</option>
              <option value="SUPPLIES">SUPPLIES</option>
              <option value="TRAVEL">TRAVEL</option>
            </select>
          </div>
          <div class="flex justify-end gap-3 pt-3">
            <button type="button" onclick="closeModal()" class="px-4 py-2 border border-ink-secondary/40">Cancel</button>
            <button type="submit" class="px-4 py-2 bg-ink-primary text-paper-base dark:bg-night-card dark:text-night-ink border border-accent-brass font-bold">Post Entry →</button>
          </div>
        </form>
      \`;
      document.getElementById('modal-backdrop').classList.remove('hidden');
    }

    async function submitNewLedger(e) {
      e.preventDefault();
      const formData = new FormData(e.target);
      const data = Object.fromEntries(formData.entries());
      await fetch('/api/desk/ledger', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(data)
      });
      closeModal();
      loadLedger();
    }

    // 6. Archive Loader
    async function loadArchive() {
      const search = document.getElementById('archive-search')?.value || '';
      const dept = document.getElementById('archive-filter-dept')?.value || 'ALL';
      const res = await fetch(\`/api/desk/archive?department=\${dept}&search=\${encodeURIComponent(search)}\`);
      const data = await res.json();
      
      const grid = document.getElementById('archive-grid');
      grid.innerHTML = (data.records || []).map(r => \`
        <div class="card-surface p-5 relative border-l-4 border-accent-brass">
          <div class="flex justify-between items-start mb-2">
            <span class="font-mono text-xs font-bold text-accent-brass">\${escapeHtml(r.recordNumber)}</span>
            <span class="font-mono text-[10px] text-ink-secondary dark:text-night-sub">FILED: \${escapeHtml(r.filingDate)}</span>
          </div>
          <h3 class="font-masthead font-bold text-base text-ink-primary dark:text-night-ink mb-2">\${escapeHtml(r.title)}</h3>
          <p class="text-xs text-ink-secondary dark:text-night-sub mb-4 leading-relaxed">\${escapeHtml(r.summary)}</p>
          <div class="pt-3 border-t border-dotted border-ink-secondary/30 flex justify-between items-center font-mono text-[10px]">
            <span class="bg-black/5 dark:bg-white/5 px-2 py-0.5 rounded font-bold">\${escapeHtml(r.department)}</span>
            <span class="text-ink-secondary dark:text-night-sub">\${escapeHtml(r.tags)}</span>
          </div>
        </div>
      \`).join('') || '<div class="col-span-2 text-center py-8 font-mono text-xs text-ink-secondary">No matching archive records found</div>';
    }

    function openNewArchiveModal() {
      const modal = document.getElementById('modal-content');
      modal.innerHTML = \`
        <div class="flex justify-between items-center border-b border-ink-primary/20 pb-3 mb-4">
          <h3 class="font-masthead font-bold text-lg uppercase">FILE NEW ARCHIVE RECORD</h3>
          <button onclick="closeModal()" class="text-ink-secondary hover:text-ink-primary font-mono text-sm">✕</button>
        </div>
        <form onsubmit="submitNewArchive(event)" class="space-y-3 font-mono text-xs">
          <div>
            <label class="block text-ink-secondary dark:text-night-sub mb-1">RECORD TITLE *</label>
            <input type="text" name="title" required class="w-full p-2 bg-paper-base dark:bg-night-base border border-ink-secondary/40 outline-none">
          </div>
          <div>
            <label class="block text-ink-secondary dark:text-night-sub mb-1">DEPARTMENT</label>
            <select name="department" class="w-full p-2 bg-paper-base dark:bg-night-base border border-ink-secondary/40 outline-none">
              <option value="OPERATIONS">OPERATIONS</option>
              <option value="LOGISTICS">LOGISTICS</option>
              <option value="ENGINEERING">ENGINEERING</option>
              <option value="FACILITIES">FACILITIES</option>
              <option value="SUPPORT">SUPPORT</option>
              <option value="FINANCE">FINANCE</option>
            </select>
          </div>
          <div>
            <label class="block text-ink-secondary dark:text-night-sub mb-1">SUMMARY / RECORD DETAILS *</label>
            <textarea name="summary" rows="3" required class="w-full p-2 bg-paper-base dark:bg-night-base border border-ink-secondary/40 outline-none"></textarea>
          </div>
          <div>
            <label class="block text-ink-secondary dark:text-night-sub mb-1">TAGS (COMMA SEPARATED)</label>
            <input type="text" name="tags" value="Audit, 2026, Operations" class="w-full p-2 bg-paper-base dark:bg-night-base border border-ink-secondary/40 outline-none">
          </div>
          <div class="flex justify-end gap-3 pt-3">
            <button type="button" onclick="closeModal()" class="px-4 py-2 border border-ink-secondary/40">Cancel</button>
            <button type="submit" class="px-4 py-2 bg-ink-primary text-paper-base dark:bg-night-card dark:text-night-ink border border-accent-brass font-bold">Archive Document →</button>
          </div>
        </form>
      \`;
      document.getElementById('modal-backdrop').classList.remove('hidden');
    }

    async function submitNewArchive(e) {
      e.preventDefault();
      const formData = new FormData(e.target);
      const data = Object.fromEntries(formData.entries());
      await fetch('/api/desk/archive', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(data)
      });
      closeModal();
      loadArchive();
    }

    // 7. Messages Loader
    async function loadMessages() {
      const res = await fetch('/api/desk/messages');
      const data = await res.json();
      const el = document.getElementById('messages-list');
      el.innerHTML = (data.messages || []).map(m => \`
        <div class="card-surface p-5 font-mono text-xs border-l-4 \${m.urgent ? 'border-signal-urgent' : 'border-ink-secondary/40'}">
          <div class="flex justify-between items-start mb-2">
            <div>
              <span class="font-bold text-sm text-ink-primary dark:text-night-ink">\${escapeHtml(m.subject)}</span>
              <div class="text-[11px] text-ink-secondary dark:text-night-sub mt-0.5">FROM: \${escapeHtml(m.senderName)} (\${escapeHtml(m.senderEmail)}) • TO: \${escapeHtml(m.recipientEmail)}</div>
            </div>
            <span class="text-ink-secondary dark:text-night-sub text-[10px]">\${new Date(m.createdAt).toLocaleDateString()}</span>
          </div>
          <p class="mt-2 text-ink-secondary dark:text-night-sub leading-relaxed">\${escapeHtml(m.content)}</p>
        </div>
      \`).join('') || '<div class="text-center py-8 font-mono text-xs text-ink-secondary">No messages in inbox</div>';
    }

    function openNewMessageModal() {
      const modal = document.getElementById('modal-content');
      modal.innerHTML = \`
        <div class="flex justify-between items-center border-b border-ink-primary/20 pb-3 mb-4">
          <h3 class="font-masthead font-bold text-lg uppercase">COMPOSE DEPARTMENTAL MEMO</h3>
          <button onclick="closeModal()" class="text-ink-secondary hover:text-ink-primary font-mono text-sm">✕</button>
        </div>
        <form onsubmit="submitNewMessage(event)" class="space-y-3 font-mono text-xs">
          <div>
            <label class="block text-ink-secondary dark:text-night-sub mb-1">MEMO SUBJECT *</label>
            <input type="text" name="subject" required class="w-full p-2 bg-paper-base dark:bg-night-base border border-ink-secondary/40 outline-none">
          </div>
          <div>
            <label class="block text-ink-secondary dark:text-night-sub mb-1">MESSAGE CONTENT *</label>
            <textarea name="content" rows="4" required class="w-full p-2 bg-paper-base dark:bg-night-base border border-ink-secondary/40 outline-none"></textarea>
          </div>
          <div class="flex items-center gap-2">
            <input type="checkbox" name="urgent" id="memo-urgent" class="accent-signal-urgent">
            <label for="memo-urgent" class="font-bold text-signal-urgent">MARK AS FLASH / URGENT PRIORITY</label>
          </div>
          <div class="flex justify-end gap-3 pt-3">
            <button type="button" onclick="closeModal()" class="px-4 py-2 border border-ink-secondary/40">Cancel</button>
            <button type="submit" class="px-4 py-2 bg-ink-primary text-paper-base dark:bg-night-card dark:text-night-ink border border-accent-brass font-bold">Dispatch Memo →</button>
          </div>
        </form>
      \`;
      document.getElementById('modal-backdrop').classList.remove('hidden');
    }

    async function submitNewMessage(e) {
      e.preventDefault();
      const formData = new FormData(e.target);
      const data = {
        subject: formData.get('subject'),
        content: formData.get('content'),
        urgent: formData.get('urgent') === 'on'
      };
      await fetch('/api/desk/messages', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(data)
      });
      closeModal();
      loadMessages();
    }

    // 8. Calendar Loader
    async function loadCalendar() {
      const res = await fetch('/api/desk/calendar');
      const data = await res.json();
      const el = document.getElementById('calendar-shifts-grid');
      el.innerHTML = (data.shifts || []).map(s => \`
        <div class="card-surface p-4 font-mono text-xs relative border-t-4 border-accent-brass">
          <div class="text-[10px] text-ink-secondary dark:text-night-sub mb-1">\${escapeHtml(s.date)}</div>
          <h4 class="font-bold text-sm text-ink-primary dark:text-night-ink mb-1">\${escapeHtml(s.title)}</h4>
          <div class="text-accent-brass font-bold mb-2">[\${escapeHtml(s.startTime)} - \${escapeHtml(s.endTime)} HRS]</div>
          <div class="pt-2 border-t border-dotted border-ink-secondary/30 text-[11px] text-ink-secondary dark:text-night-sub">
            <strong>STAFF:</strong> \${escapeHtml(s.assignedStaff)}
          </div>
        </div>
      \`).join('') || '<div class="col-span-4 text-center py-8 font-mono text-xs text-ink-secondary">No shifts scheduled</div>';
    }

    // Initial Load
    loadOverview();

    // Auto-refresh wire every 20 seconds
    setInterval(() => {
      if (currentTab === 'overview') loadOverview();
      if (currentTab === 'wire') loadWire();
    }, 20000);
  </script>
</body>
</html>`;
}

// ─────────────────────────────────────────────────────────────────────────────
// Start Standalone Website 2 Server on Port 3002 (Bound to Localhost / 127.0.0.1)
// ─────────────────────────────────────────────────────────────────────────────
app.listen(PORT, HOST, () => {
  console.log(`\n=======================================================`);
  console.log(` 📰 THE OPERATIONS DESK (WEBSITE 2) ACTIVE`);
  console.log(` URL: http://${HOST}:${PORT}`);
  console.log(` Gated by GateZero Gateway: ${GATEWAY_URL}`);
  console.log(` Live Per-Request Introspection: ACTIVE`);
  console.log(` Security Headers: ENFORCED`);
  console.log(`=======================================================\n`);
});

export default app;
