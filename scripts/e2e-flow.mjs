/**
 * End-to-end walk of the real HTTP flow, acting as a browser.
 *
 * Website 1 (:3000) and Website 2 (:3002) must both be running.
 * Generates a real ECDSA P-256 key and signs the server's challenges the same
 * way the browser does, so this exercises the actual verification path.
 */

import crypto from "crypto";

const W1 = "http://localhost:3000";
const W2 = "http://127.0.0.1:3002";
const UA = "E2E-Runner/1.0";

const jar = new Map();

function saveCookies(res) {
  const raw = res.headers.getSetCookie?.() ?? [];
  for (const line of raw) {
    const [pair] = line.split(";");
    const idx = pair.indexOf("=");
    jar.set(pair.slice(0, idx).trim(), pair.slice(idx + 1).trim());
  }
}

function cookieHeader() {
  return [...jar.entries()].map(([k, v]) => `${k}=${v}`).join("; ");
}

async function go(url, options = {}) {
  const res = await fetch(url, {
    ...options,
    redirect: "manual",
    headers: {
      "user-agent": UA,
      cookie: cookieHeader(),
      ...(options.headers ?? {}),
    },
  });
  saveCookies(res);
  return res;
}

/** Follow redirects manually so cookies are carried across hops. */
async function follow(url, max = 10) {
  let current = url;
  for (let i = 0; i < max; i++) {
    const res = await go(current);
    if (res.status >= 300 && res.status < 400) {
      const location = res.headers.get("location");
      current = new URL(location, current).toString();
      continue;
    }
    return { res, url: current };
  }
  throw new Error("too many redirects");
}

function b64u(buf) {
  return Buffer.from(buf).toString("base64").replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

const { privateKey, publicKey } = crypto.generateKeyPairSync("ec", { namedCurve: "prime256v1" });
const publicKeySpki = b64u(publicKey.export({ format: "der", type: "spki" }));

function sign(issuer, purpose, nonce) {
  return b64u(
    crypto.sign("sha256", Buffer.from(`gatezero:v1:${issuer}:${purpose}:${nonce}`, "utf8"), {
      key: privateKey,
      dsaEncoding: "ieee-p1363",
    })
  );
}

const results = [];
function check(label, ok, detail = "") {
  results.push({ label, ok, detail });
  console.log(`${ok ? "PASS" : "FAIL"}  ${label}${detail ? "  — " + detail : ""}`);
}

async function main() {
  const email = `e2e-${Date.now()}@zerogate.internal`;

  // ── 1. SSO ────────────────────────────────────────────────────────────────
  const loginRes = await go(`${W1}/api/auth/login`);
  const idpUrl = new URL(loginRes.headers.get("location"));
  idpUrl.searchParams.set("custom_email", email);
  idpUrl.searchParams.set("custom_name", "E2E Runner");

  await follow(idpUrl.toString());

  let session = await (await go(`${W1}/api/auth/session`)).json();
  check("SSO completes but session is not yet ACTIVE (MFA pending)", session.authenticated !== true);

  // ── 2. MFA ────────────────────────────────────────────────────────────────
  const mfaRes = await go(`${W1}/api/auth/mfa`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ method: "totp", code: "123456" }),
  });
  check("MFA verification succeeds", mfaRes.ok, `status ${mfaRes.status}`);

  session = await (await go(`${W1}/api/auth/session`)).json();
  check("Session is ACTIVE after MFA", session.authenticated === true);
  check("Session reports no registered device yet", session.device?.registered === false);

  const csrf = session.csrfToken;

  // ── 3. Connect must be refused without a device ──────────────────────────
  const noDeviceChallenge = await go(`${W1}/api/device/challenge`, {
    method: "POST",
    headers: { "content-type": "application/json", "x-csrf-token": csrf },
    body: JSON.stringify({ purpose: "CONNECT" }),
  });
  const ndc = await noDeviceChallenge.json();
  const connectNoDevice = await go(`${W1}/api/connect`, {
    method: "POST",
    headers: { "content-type": "application/json", "x-csrf-token": csrf },
    body: JSON.stringify({ nonce: ndc.nonce, signature: sign("website-1", "CONNECT", ndc.nonce) }),
  });
  const noDeviceBody = await connectNoDevice.json();
  check(
    "Connect is refused before any device is registered",
    connectNoDevice.status === 403 && noDeviceBody.code === "DEVICE_PROOF_REQUIRED",
    `status ${connectNoDevice.status} code=${noDeviceBody.code}`
  );

  // Having no enrolled device is an enrolment problem, not evidence of
  // compromise, so it must refuse Connect WITHOUT tearing down the session.
  const stillSignedIn = await (await go(`${W1}/api/auth/session`)).json();
  check(
    "Refusing an unenrolled device does not terminate the Website 1 session",
    stillSignedIn.authenticated === true
  );

  const csrf2 = stillSignedIn.csrfToken;

  // ── 4. Device enrolment ──────────────────────────────────────────────────
  const regChallenge = await (
    await go(`${W1}/api/device/challenge`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ purpose: "REGISTRATION" }),
    })
  ).json();

  const regRes = await go(`${W1}/api/device`, {
    method: "POST",
    headers: { "content-type": "application/json", "x-csrf-token": csrf2 },
    body: JSON.stringify({
      label: "E2E device",
      publicKeySpki,
      hardwareBacked: false,
      nonce: regChallenge.nonce,
      signature: sign("website-1", "REGISTRATION", regChallenge.nonce),
    }),
  });
  const reg = await regRes.json();
  check("Device registers successfully", regRes.ok, `status=${reg.status}`);
  check(
    "Registration lands PENDING_APPROVAL (admin approval required, W2 §6)",
    reg.status === "PENDING_APPROVAL",
    `got ${reg.status}`
  );

  // Approve it the way an administrator would.
  const approveOut = await import("node:child_process").then(({ execSync }) =>
    execSync(
      `npx tsx -e "import{prisma}from './lib/db';(async()=>{await prisma.deviceCredential.update({where:{id:'${reg.credentialId}'},data:{status:'ACTIVE',approvedByAdminId:'e2e-admin',approvedAt:new Date()}});console.log('approved');process.exit(0)})()"`,
      { encoding: "utf8", env: { ...process.env, DATABASE_URL: process.env.DATABASE_URL } }
    )
  );
  check("Administrator approves the device", approveOut.includes("approved"));

  // ── 5. Connect with a valid device proof ─────────────────────────────────
  const connChallenge = await (
    await go(`${W1}/api/device/challenge`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ purpose: "CONNECT" }),
    })
  ).json();

  const connectRes = await go(`${W1}/api/connect`, {
    method: "POST",
    headers: { "content-type": "application/json", "x-csrf-token": csrf2 },
    body: JSON.stringify({
      nonce: connChallenge.nonce,
      signature: sign("website-1", "CONNECT", connChallenge.nonce),
    }),
  });
  const connect = await connectRes.json();
  check("Connect grants a 5-minute authorization", connectRes.ok && connect.granted === true,
    `ttl=${connect.ttlSeconds}`);
  check("Authorization TTL is 5 minutes", connect.ttlSeconds === 300, `got ${connect.ttlSeconds}`);

  // A replayed Connect nonce must not work.
  const replayRes = await go(`${W1}/api/connect`, {
    method: "POST",
    headers: { "content-type": "application/json", "x-csrf-token": csrf2 },
    body: JSON.stringify({
      nonce: connChallenge.nonce,
      signature: sign("website-1", "CONNECT", connChallenge.nonce),
    }),
  });
  check("A replayed Connect challenge is refused", !replayRes.ok, `status ${replayRes.status}`);

  // ── 6. Launch: handoff code -> Website 2 ─────────────────────────────────
  const codeRes = await go(`${W1}/api/authz/code`, {
    method: "POST",
    headers: { "content-type": "application/json", "x-csrf-token": csrf2 },
    body: JSON.stringify({ targetApp: "operations-desk" }),
  });
  const code = await codeRes.json();
  check("Gateway issues a handoff code and resolves the target", codeRes.ok && !!code.targetUrl,
    code.targetUrl);

  const callbackRes = await go(code.targetUrl);
  check("Website 2 accepts the handoff and asks for a device proof",
    callbackRes.ok, `status ${callbackRes.status}`);

  // ── 7. Website 2's own device verification (W1 §8.1) ─────────────────────
  const w2Challenge = await (
    await go(`${W2}/api/auth/device-challenge`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: "{}",
    })
  ).json();
  check("Website 2 issues its OWN challenge nonce", !!w2Challenge.nonce);

  // A Website 1 signature must not satisfy Website 2's checkpoint.
  const crossIssuer = await go(`${W2}/api/auth/device-proof`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({
      nonce: w2Challenge.nonce,
      signature: sign("website-1", "W2_SESSION", w2Challenge.nonce),
    }),
  });
  check("A Website 1 signature is refused at Website 2's checkpoint",
    !crossIssuer.ok, `status ${crossIssuer.status}`);

  const w2Challenge2 = await (
    await go(`${W2}/api/auth/device-challenge`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: "{}",
    })
  ).json();

  const proofRes = await go(`${W2}/api/auth/device-proof`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({
      nonce: w2Challenge2.nonce,
      signature: sign("website-2", "W2_SESSION", w2Challenge2.nonce),
    }),
  });
  check("Website 2 verifies the device and establishes a session",
    proofRes.ok, `status ${proofRes.status}`);

  // ── 8. Website 2 access ──────────────────────────────────────────────────
  const statsRes = await go(`${W2}/api/desk/stats`);
  check("Website 2 API is now reachable", statsRes.ok, `status ${statsRes.status}`);

  const sessionInfo = await (await go(`${W2}/api/desk/session`)).json();
  check("Website 2 session reports its own independent limits",
    !!sessionInfo.session?.absoluteExpiresAt,
    `orgMode=${sessionInfo.orgMode} absolute=${sessionInfo.session?.absoluteExpiresAt}`);

  // ── 9. The authorization is spent ────────────────────────────────────────
  const replayHandoff = await go(code.targetUrl);
  check("The handoff code cannot be replayed", !replayHandoff.ok,
    `status ${replayHandoff.status}`);

  const w1Session = await (await go(`${W1}/api/auth/session`)).json();
  check("Website 1 no longer offers the consumed authorization as active",
    w1Session.authorization?.active === false);

  // ── 10. §14: a stolen session identifier is not sufficient ───────────────
  //
  // Force the verification window to lapse, then act as an attacker who has
  // the desk_session cookie but no device private key.
  const deskCookie = jar.get("desk_session");
  await import("node:child_process").then(({ execSync }) =>
    execSync(
      `npx tsx -e "import{prisma}from './lib/db';(async()=>{await prisma.deskSession.updateMany({where:{id:'${deskCookie}'},data:{deviceVerifiedAt:new Date(Date.now()-3600000)}});console.log('aged');process.exit(0)})()"`,
      { encoding: "utf8" }
    )
  );

  const thiefRes = await fetch(`${W2}/api/desk/stats`, {
    headers: { "user-agent": UA, cookie: `desk_session=${deskCookie}` },
  });
  const thiefBody = await thiefRes.json().catch(() => ({}));
  check(
    "A stolen session cookie alone is refused once the device proof is stale",
    thiefRes.status === 401 && thiefBody.error === "DEVICE_REVERIFICATION_REQUIRED",
    `status ${thiefRes.status} ${thiefBody.error ?? ""}`
  );

  // The legitimate browser holds the key, so it re-proves and carries on.
  const reChallenge = await (
    await go(`${W2}/api/auth/device-challenge`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: "{}",
    })
  ).json();

  const reverifyRes = await go(`${W2}/api/auth/device-reverify`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({
      nonce: reChallenge.nonce,
      signature: sign("website-2", "W2_SESSION", reChallenge.nonce),
    }),
  });
  check("The real device re-proves possession and continues",
    reverifyRes.ok, `status ${reverifyRes.status}`);

  const rotatedCookie = jar.get("desk_session");
  check("§16: the session identifier is rotated on re-verification",
    rotatedCookie !== deskCookie,
    `${String(deskCookie).slice(0, 8)}… -> ${String(rotatedCookie).slice(0, 8)}…`);

  const oldIdRes = await fetch(`${W2}/api/desk/stats`, {
    headers: { "user-agent": UA, cookie: `desk_session=${deskCookie}` },
  });
  check("§16: the pre-rotation identifier no longer resolves",
    oldIdRes.status === 401, `status ${oldIdRes.status}`);

  const afterReverify = await go(`${W2}/api/desk/stats`);
  check("Website 2 is reachable again after re-verification",
    afterReverify.ok, `status ${afterReverify.status}`);

  // ── 11. Logout affects Website 2 only (W2 §20) ───────────────────────────
  await go(`${W2}/api/auth/logout`);
  const afterLogout = await go(`${W2}/api/desk/stats`);
  check("Website 2 logout ends the Desk session", !afterLogout.ok, `status ${afterLogout.status}`);

  const w1AfterLogout = await (await go(`${W1}/api/auth/session`)).json();
  check("Website 1 remains signed in after Website 2 logout",
    w1AfterLogout.authenticated === true);

  const failed = results.filter((r) => !r.ok);
  console.log(`\n${results.length - failed.length}/${results.length} checks passed`);
  process.exit(failed.length === 0 ? 0 : 1);
}

main().catch((err) => {
  console.error("E2E ERROR:", err);
  process.exit(1);
});
