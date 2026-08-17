/**
 * lib/auth/email-mfa.ts
 * Email Multi-Factor Authentication (Email OTP) System.
 *
 * Sends 6-digit MFA codes TO the user's email address via Resend API,
 * Gmail SMTP, or custom SMTP.
 */

import nodemailer from "nodemailer";
import { prisma } from "../db";

// In-memory store for Email OTP codes (Session ID -> Code & Expiry)
const emailOtpStore = new Map<string, { code: string; expiresAt: Date }>();

/**
 * Generate and send a 6-digit Email OTP verification code to the user's email.
 */
export async function sendEmailOTP(
  sessionId: string,
  recipientEmail: string
): Promise<{ success: boolean; error?: string }> {
  const code = Math.floor(100000 + Math.random() * 900000).toString();
  const expiresAt = new Date(Date.now() + 5 * 60 * 1000); // 5 minutes TTL

  emailOtpStore.set(sessionId, { code, expiresAt });

  // Update session record in DB
  await prisma.session.update({
    where: { id: sessionId },
    data: { mfaExpiry: expiresAt },
  }).catch(() => {});

  console.log(`\n[EMAIL MFA] Dispatching code to ${recipientEmail}\n`);

  const emailHtml = `
    <div style="font-family: Arial, sans-serif; background: #0a0f1d; color: #e2e8f0; padding: 30px; border-radius: 10px; max-width: 500px; margin: 0 auto; border: 1px solid #1e293b;">
      <h2 style="color: #63b3ed; margin-top: 0;">🛡️ GateZero Security Verification</h2>
      <p style="color: #94a3b8; font-size: 14px;">Use the following 6-digit verification code to complete your sign in:</p>
      <div style="background: rgba(99, 179, 237, 0.1); border: 1px solid #3182ce; padding: 15px; text-align: center; border-radius: 8px; margin: 20px 0;">
        <span style="font-size: 28px; font-weight: bold; letter-spacing: 8px; color: #63b3ed; font-family: monospace;">${code}</span>
      </div>
      <p style="color: #64748b; font-size: 12px; margin-bottom: 0;">This code is valid for 5 minutes. If you did not request this code, please ignore this email.</p>
    </div>
  `;

  try {
    // 1. Resend API (preferred)
    if (process.env.RESEND_API_KEY) {
      const res = await fetch("https://api.resend.com/emails", {
        method: "POST",
        headers: {
          "Authorization": `Bearer ${process.env.RESEND_API_KEY}`,
          "Content-Type": "application/json",
        },
        body: JSON.stringify({
          from: "GateZero Security <onboarding@resend.dev>",
          to: [recipientEmail],
          subject: "GateZero MFA Verification Code",
          html: emailHtml,
        }),
      });

      if (res.ok) {
        console.log(`[EMAIL MFA] ✅ Sent via Resend API to ${recipientEmail}`);
        return { success: true };
      }
      const errBody = await res.text();
      console.error(`[EMAIL MFA] Resend API error: ${errBody}`);
    }

    // 2. Gmail SMTP
    let transporter: nodemailer.Transporter;
    if (process.env.GMAIL_USER && process.env.GMAIL_PASS) {
      transporter = nodemailer.createTransport({
        service: "gmail",
        auth: { user: process.env.GMAIL_USER, pass: process.env.GMAIL_PASS },
      });
    }
    // 3. Custom SMTP
    else if (process.env.SMTP_HOST && process.env.SMTP_USER) {
      transporter = nodemailer.createTransport({
        host: process.env.SMTP_HOST,
        port: parseInt(process.env.SMTP_PORT || "587"),
        secure: process.env.SMTP_SECURE === "true",
        auth: { user: process.env.SMTP_USER, pass: process.env.SMTP_PASS },
      });
    } else {
      console.error("[EMAIL MFA] No email provider configured (RESEND_API_KEY, GMAIL_USER, or SMTP_HOST)");
      return { success: false, error: "Email service not configured" };
    }

    const senderEmail = process.env.GMAIL_USER || process.env.SMTP_USER || "security@gatezero.io";

    const info = await transporter.sendMail({
      from: `"GateZero Security" <${senderEmail}>`,
      to: recipientEmail,
      subject: "GateZero MFA Verification Code",
      text: `Your GateZero verification code is: ${code}. Valid for 5 minutes.`,
      html: emailHtml,
    });

    console.log(`[EMAIL MFA] ✅ Sent via SMTP to ${recipientEmail} (ID: ${info.messageId})`);
    return { success: true };
  } catch (err: any) {
    console.error("[EMAIL MFA] Error sending email:", err?.message || err);
    return { success: false, error: "Failed to send verification email" };
  }
}

/**
 * Verify an Email OTP code for a given session.
 */
export async function verifyEmailOTP(
  sessionId: string,
  inputCode: string
): Promise<{ valid: boolean; reason?: string }> {
  if (!/^\d{6}$/.test(inputCode)) {
    return { valid: false, reason: "Code must be exactly 6 digits" };
  }

  const record = emailOtpStore.get(sessionId);

  if (record) {
    if (record.expiresAt < new Date()) {
      emailOtpStore.delete(sessionId);
      return { valid: false, reason: "Code expired. Please request a new one." };
    }

    if (record.code !== inputCode) {
      return { valid: false, reason: "Incorrect code. Check your email and try again." };
    }

    emailOtpStore.delete(sessionId);
    return { valid: true };
  }

  return { valid: false, reason: "No active code. Please send a verification code first." };
}
