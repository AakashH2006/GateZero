/**
 * lib/errors.ts
 * Structured error handling for GateZero Portal.
 *
 * Internal errors are NEVER exposed to clients.
 * All API error responses use a fixed schema: { error: string, code: string }
 * No stack traces, no implementation details.
 */

import { NextResponse } from "next/server";
import { ZodError } from "zod";

export interface ApiError {
  error: string;
  code: string;
}

/** Generic server error — details logged server-side, generic message to client */
export function serverError(
  message: string = "An internal error occurred",
  logContext?: unknown
): NextResponse<ApiError> {
  if (logContext) {
    console.error("[SERVER_ERROR]", message, logContext);
  }
  return NextResponse.json(
    { error: "Internal server error", code: "INTERNAL_ERROR" },
    { status: 500 }
  );
}

/** 400 Bad Request */
export function badRequest(
  message: string,
  code: string = "BAD_REQUEST"
): NextResponse<ApiError> {
  return NextResponse.json({ error: message, code }, { status: 400 });
}

/** 401 Unauthorized */
export function unauthorized(
  message: string = "Unauthorized",
  code: string = "UNAUTHORIZED"
): NextResponse<ApiError> {
  return NextResponse.json({ error: message, code }, { status: 401 });
}

/** 403 Forbidden */
export function forbidden(
  message: string = "Forbidden",
  code: string = "FORBIDDEN"
): NextResponse<ApiError> {
  return NextResponse.json({ error: message, code }, { status: 403 });
}

/** 404 Not Found */
export function notFound(): NextResponse<ApiError> {
  return NextResponse.json({ error: "Not found", code: "NOT_FOUND" }, { status: 404 });
}

/** 429 Too Many Requests */
export function tooManyRequests(resetAt: Date): NextResponse<ApiError> {
  const response = NextResponse.json(
    { error: "Too many requests", code: "RATE_LIMITED" },
    { status: 429 }
  );
  response.headers.set("Retry-After", Math.ceil(resetAt.getTime() / 1000).toString());
  return response;
}

/** Handle Zod validation errors */
export function validationError(err: ZodError): NextResponse<ApiError> {
  const firstIssue = err.issues[0];
  return badRequest(
    firstIssue?.message ?? "Validation failed",
    "VALIDATION_ERROR"
  );
}

/** Try/catch wrapper that converts thrown errors to safe server error responses */
export async function safeHandler(
  fn: () => Promise<NextResponse<any>>
): Promise<NextResponse<any>> {
  try {
    return await fn();
  } catch (err: unknown) {
    if (err instanceof ZodError) {
      return validationError(err);
    }
    return serverError("Unhandled error in route handler", err);
  }
}
