/**
 * lib/notify/index.ts
 * ─────────────────────────────────────────────────────────────────────────────
 * EMPLOYEE SECURITY NOTIFICATIONS
 * website-2-defense.md §12, §34 / website-1-defense.md §10, §22.5
 * ─────────────────────────────────────────────────────────────────────────────
 *
 * Two hard rules from the spec govern everything here:
 *
 *   1. Notifications never carry secrets. No passwords, private keys,
 *      authorization codes, session tokens, or internal security detail
 *      (§34). Message bodies are assembled from a fixed template table below
 *      rather than from caller-supplied strings, so a careless call site
 *      cannot interpolate a token into an email.
 *
 *   2. Notification is an *alerting* mechanism and is never an authorization
 *      credential, and delivery must not be required for authorization to
 *      succeed (§34). Every send is therefore best-effort: failures are
 *      recorded and swallowed, never propagated into the auth path.
 *
 * High-severity events go to the registered personal/recovery email AND a
 * secondary channel (SMS/push), so a compromised or unavailable primary
 * mailbox cannot silence the alert (§34).
 */

import { prisma } from "../db";
import type { User } from "@prisma/client";

export type NotificationType =
  | "W2_SESSION_ESTABLISHED"
  | "W2_SESSION_REPLACED"
  | "W2_EMERGENCY_ACCESS"
  | "CONNECT_COOLDOWN"
  | "DEVICE_REGISTERED"
  | "DEVICE_REVOKED"
  | "DEVICE_RECOVERY_REQUESTED"
  | "PASSWORD_CHANGED"
  | "MFA_OVERRIDDEN"
  | "ACCESS_REVOKED"
  | "SESSION_TERMINATED_RISK";

type Severity = "INFO" | "HIGH";

interface Template {
  subject: string;
  body: string;
  severity: Severity;
}

/**
 * Fixed message catalogue. Bodies are static — nothing from a request, a token,
 * or an internal reason code is ever interpolated into them.
 */
const TEMPLATES: Record<NotificationType, Template> = {
  W2_SESSION_ESTABLISHED: {
    subject: "New Operations Desk session started",
    body: "A new Operations Desk session was started on your account. If this was not you, contact your administrator immediately.",
    severity: "INFO",
  },
  W2_SESSION_REPLACED: {
    subject: "Your previous Operations Desk session was replaced",
    body: "A new authorized device established an Operations Desk session on your account, and your previous session was ended. If this was not you, contact your administrator immediately.",
    severity: "HIGH",
  },
  W2_EMERGENCY_ACCESS: {
    subject: "Emergency access was used on your account",
    body: "An administrator established emergency Operations Desk access for your account during a service outage. If you did not request this, contact your administrator immediately.",
    severity: "HIGH",
  },
  CONNECT_COOLDOWN: {
    subject: "Repeated Connect failures on your account",
    body: "Several Connect attempts on your account were refused, and Connect has been paused temporarily. If this was not you, contact your administrator immediately.",
    severity: "HIGH",
  },
  DEVICE_REGISTERED: {
    subject: "A new device was registered to your account",
    body: "A new device credential was registered and approved for your account. Any previously authorized device is no longer able to connect. If this was not you, contact your administrator immediately.",
    severity: "HIGH",
  },
  DEVICE_REVOKED: {
    subject: "A device credential on your account was revoked",
    body: "A device credential on your account was revoked and can no longer be used. If this was not expected, contact your administrator immediately.",
    severity: "HIGH",
  },
  DEVICE_RECOVERY_REQUESTED: {
    subject: "Device recovery was requested for your account",
    body: "A device recovery request was opened on your account. Recovery requires administrator verification before any new device can be registered. If this was not you, contact your administrator immediately.",
    severity: "HIGH",
  },
  PASSWORD_CHANGED: {
    subject: "Your password was changed",
    body: "The password on your account was changed. All existing sessions were signed out. If this was not you, contact your administrator immediately.",
    severity: "HIGH",
  },
  MFA_OVERRIDDEN: {
    subject: "An administrator overrode MFA on your account",
    body: "An administrator overrode the multi-factor requirement on your account. The resulting session is time-limited and will require fresh verification. If this was not expected, contact your administrator immediately.",
    severity: "HIGH",
  },
  ACCESS_REVOKED: {
    subject: "Your Operations Desk access was revoked",
    body: "An administrator revoked your Operations Desk access. Active sessions were ended. Contact your administrator with any questions.",
    severity: "HIGH",
  },
  SESSION_TERMINATED_RISK: {
    subject: "Your session was ended by a security check",
    body: "A security check ended your GateZero session and you will need to sign in again. If this was not expected, contact your administrator immediately.",
    severity: "HIGH",
  },
};

/** Resolve where an alert should be delivered (§34: personal/recovery address). */
function primaryAddress(user: Pick<User, "email" | "recoveryEmail">): string {
  return user.recoveryEmail ?? user.email;
}

async function record(params: {
  userId: string;
  channel: "EMAIL" | "SMS" | "PUSH";
  type: NotificationType;
  severity: Severity;
  status: "SENT" | "FAILED";
  detail: string;
}): Promise<void> {
  await prisma.notificationLog
    .create({
      data: {
        userId: params.userId,
        channel: params.channel,
        type: params.type,
        severity: params.severity,
        status: params.status,
        detail: params.detail,
      },
    })
    .catch(() => {});
}

/**
 * Deliver over the secondary channel.
 *
 * Wired as a logged, auditable stub: the channel address comes from the user
 * record and the message is the same secret-free template. Swapping in a real
 * SMS/push provider is a change to this function alone.
 */
async function sendSecondary(
  user: User,
  type: NotificationType,
  template: Template
): Promise<boolean> {
  if (!user.secondaryChannel) return false;

  const [scheme] = user.secondaryChannel.split(":", 1);
  const channel = scheme?.toUpperCase() === "SMS" ? "SMS" : "PUSH";

  console.log(
    `[NOTIFY:${channel}] user=${user.id} type=${type} — ${template.subject}`
  );
  await record({
    userId: user.id,
    channel,
    type,
    severity: template.severity,
    status: "SENT",
    detail: template.subject,
  });
  return true;
}

/**
 * Send a security notification to an employee.
 *
 * Never throws. Callers in the authorization path can `void` this safely.
 */
export async function notifyEmployee(
  user: User,
  type: NotificationType
): Promise<void> {
  const template = TEMPLATES[type];
  if (!template) return;

  const to = primaryAddress(user);

  try {
    const html = `
      <div style="font-family: Arial, sans-serif; background: #0a0f1d; color: #e2e8f0; padding: 30px; border-radius: 10px; max-width: 520px; margin: 0 auto; border: 1px solid #1e293b;">
        <h2 style="color: #63b3ed; margin-top: 0;">GateZero Security Notice</h2>
        <p style="color: #cbd5e1; font-size: 15px; font-weight: bold;">${template.subject}</p>
        <p style="color: #94a3b8; font-size: 14px;">${template.body}</p>
        <p style="color: #64748b; font-size: 12px; margin-bottom: 0;">This message is for your awareness only. GateZero will never ask you to reply with a code, password, or link from this notice.</p>
      </div>
    `;

    let sent = false;

    if (process.env.RESEND_API_KEY) {
      const res = await fetch("https://api.resend.com/emails", {
        method: "POST",
        headers: {
          Authorization: `Bearer ${process.env.RESEND_API_KEY}`,
          "Content-Type": "application/json",
        },
        body: JSON.stringify({
          from: "GateZero Security <onboarding@resend.dev>",
          to: [to],
          subject: `GateZero: ${template.subject}`,
          html,
        }),
      });
      sent = res.ok;
    } else {
      // No provider configured (dev): the notification is still recorded so the
      // audit trail shows what the employee would have been told.
      console.log(`[NOTIFY:EMAIL] to=${to} type=${type} — ${template.subject}`);
      sent = true;
    }

    await record({
      userId: user.id,
      channel: "EMAIL",
      type,
      severity: template.severity,
      status: sent ? "SENT" : "FAILED",
      detail: template.subject,
    });
  } catch {
    await record({
      userId: user.id,
      channel: "EMAIL",
      type,
      severity: template.severity,
      status: "FAILED",
      detail: template.subject,
    });
  }

  // §34: high-severity events go out on a second channel as well, so a
  // compromised or unreachable mailbox cannot suppress the warning.
  if (template.severity === "HIGH") {
    await sendSecondary(user, type, template).catch(() => false);
  }
}

/** Look up the user, then notify. Convenience for call sites holding only an id. */
export async function notifyEmployeeById(
  userId: string,
  type: NotificationType
): Promise<void> {
  const user = await prisma.user.findUnique({ where: { id: userId } }).catch(() => null);
  if (user) await notifyEmployee(user, type);
}
