/**
 * prisma/seed.ts
 * Seeds the database with a demo user for local development.
 *
 * Run with: npm run db:seed
 *
 * Demo credentials:
 *   SSO Subject: mock-idp|demo-user-001
 *   Email: demo@zerogate.internal
 *   Role: EMPLOYEE
 *
 * Admin user:
 *   SSO Subject: mock-idp|admin-user-001
 *   Email: admin@zerogate.internal
 *   Role: ADMIN
 */

// Load environment variables from .env
import "dotenv/config";

import { prisma } from "../lib/db";
import { UserRole } from "@prisma/client";

async function main() {
  console.log("🌱 Seeding GateZero database...");

  const demoUser = await prisma.user.upsert({
    where: { idpSubject: "mock-idp|demo-user-001" },
    update: {},
    create: {
      idpSubject: "mock-idp|demo-user-001",
      email: "demo@zerogate.internal",
      name: "Demo Employee",
      role: UserRole.EMPLOYEE,
    },
  });

  const adminUser = await prisma.user.upsert({
    where: { idpSubject: "mock-idp|admin-user-001" },
    update: {},
    create: {
      idpSubject: "mock-idp|admin-user-001",
      email: "admin@zerogate.internal",
      name: "Admin User",
      role: UserRole.ADMIN,
    },
  });

  console.log(`✅ Demo user: ${demoUser.email} (${demoUser.id})`);
  console.log(`✅ Admin user: ${adminUser.email} (${adminUser.id})`);
  console.log("\n🎯 Full flow test:");
  console.log("  1. Visit http://localhost:3000");
  console.log("  2. Click 'Sign in with SSO'");
  console.log("  3. On mock IdP page, click 'Approve'");
  console.log("  4. On MFA page: click 'Simulate Approve' OR enter any 6-digit code");
  console.log("  5. Dashboard → click 'Connect'");
  console.log("  6. Access mock Website 2 via the link in dashboard");
  console.log("\n🔑 Admin access (DEV_MODE):");
  console.log("  Add header: X-Admin-Secret: dev-admin-secret");
}

main()
  .catch((err) => {
    console.error(err);
    process.exit(1);
  })
  .finally(() => prisma.$disconnect());
