/**
 * lib/auth/mock-idp-store.ts
 * In-memory code store singleton for Mock IdP.
 * Attached to globalThis to survive Next.js module hot-reloads and route bundle isolation.
 */

export interface AuthCodeData {
  codeChallenge: string;
  redirectUri: string;
  nonce?: string;
  expiresAt: number;
  user?: {
    sub: string;
    email: string;
    name: string;
    email_verified: boolean;
  };
}

const globalForMockIdp = globalThis as unknown as {
  __mockIdpCodeStore: Map<string, AuthCodeData> | undefined;
};

export const mockIdpCodeStore =
  globalForMockIdp.__mockIdpCodeStore ?? new Map<string, AuthCodeData>();

if (process.env.NODE_ENV !== "production") {
  globalForMockIdp.__mockIdpCodeStore = mockIdpCodeStore;
}
