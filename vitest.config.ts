import { defineConfig } from "vitest/config";
import path from "path";

export default defineConfig({
  test: {
    environment: "node",
    globals: true,
    fileParallelism: false,
    hookTimeout: 60000,
    // Load test env variables
    env: {
      DATABASE_URL: "file:./prisma/test.db",
      DEV_MODE: "true",
      SESSION_SECRET: "test-secret-min-32-chars-xxxxxxxxxxxxxxxxx",
      AUTHZ_SIGNING_SECRET: "test-authz-secret-min-32-chars-xxxxxxxxxxx",
      AUTHZ_TTL_SECONDS: "300",
      RATE_LIMIT_MAX: "5",
      RATE_LIMIT_WINDOW_SECONDS: "60",
      ADMIN_SECRET: "test-admin-secret",
      MOCK_IDP_CLIENT_ID: "zerogate-dev-client",
      MOCK_IDP_CLIENT_SECRET: "mock-client-secret",
      NEXT_PUBLIC_APP_URL: "http://localhost:3000",
    },
    setupFiles: ["__tests__/setup.ts"],
  },
  resolve: {
    alias: {
      "@": path.resolve(__dirname, "./"),
    },
  },
});
