/**
 * prisma/seed-dispatch.ts
 * Seeds realistic corporate company operations data for Website 2 (The Operations Desk).
 * Clean enterprise vocabulary (Operations, Logistics, Engineering, Support, Facilities, Finance).
 */

import { prisma } from "../lib/db";

export async function seedOperationsDesk() {
  console.log("Seeding The Operations Desk corporate data...");

  // 1. Assignments
  await prisma.assignment.deleteMany({});
  await prisma.assignment.createMany({
    data: [
      {
        title: "Q3 Data Center Hardware Refresh",
        description: "Coordinate rack installation, PSU redundancy testing, and cable management in DC-North Floor 2.",
        department: "ENGINEERING",
        status: "IN_PROGRESS",
        priority: "URGENT",
        assigneeName: "Marcus Vance",
        assigneeEmail: "m.vance@company.internal",
        deadline: "1600 HRS",
        rotation: -1.2,
      },
      {
        title: "Logistics Fleet Maintenance Inspection",
        description: "Bi-weekly dispatch vehicle telemetry review and brake rotor servicing for delivery units 04 through 12.",
        department: "LOGISTICS",
        status: "TODO",
        priority: "STANDARD",
        assigneeName: "Elena Rostova",
        assigneeEmail: "e.rostova@company.internal",
        deadline: "1830 HRS",
        rotation: 0.8,
      },
      {
        title: "HVAC System Calibration — Main Plant",
        description: "Calibrate building automation sensors across zones A, B, and C following seasonal maintenance schedule.",
        department: "FACILITIES",
        status: "COMPLETED",
        priority: "STANDARD",
        assigneeName: "Thomas Wright",
        assigneeEmail: "t.wright@company.internal",
        deadline: "1100 HRS",
        rotation: -0.5,
      },
      {
        title: "Tier-2 Customer Escalation Runbook Review",
        description: "Update resolution SLAs and internal escalation matrices for APAC regional support queues.",
        department: "SUPPORT",
        status: "IN_PROGRESS",
        priority: "STANDARD",
        assigneeName: "Devon Chen",
        assigneeEmail: "d.chen@company.internal",
        deadline: "1400 HRS",
        rotation: 1.4,
      },
      {
        title: "Monthly Operational Budget Reconciliation",
        description: "Verify procurement invoices against vendor ledger accounts for June/July equipment acquisitions.",
        department: "FINANCE",
        status: "TODO",
        priority: "URGENT",
        assigneeName: "Sarah Jenkins",
        assigneeEmail: "s.jenkins@company.internal",
        deadline: "1730 HRS",
        rotation: -1.0,
      },
      {
        title: "Fiber Loop Failover Simulation",
        description: "Execute scheduled secondary fiber uplink transition to verify seamless packet failover under load.",
        department: "OPERATIONS",
        status: "COMPLETED",
        priority: "STANDARD",
        assigneeName: "Liam O'Connor",
        assigneeEmail: "l.oconnor@company.internal",
        deadline: "0900 HRS",
        rotation: 0.6,
      },
    ],
  });

  // 2. Wire Bulletins
  await prisma.wireBulletin.deleteMany({});
  await prisma.wireBulletin.createMany({
    data: [
      {
        timestamp: "0847",
        category: "OPERATIONS",
        headline: "Morning Dispatch Handover Completed",
        body: "All regional logistics corridors reporting green status. Fleet capacity at 94.2%. Central routing active.",
        urgency: "NORMAL",
      },
      {
        timestamp: "0915",
        category: "SYSTEM_STATUS",
        headline: "Primary Core Switch Switchover Successful",
        body: "Redundant core router switchover completed during scheduled 0900 maintenance window. Zero packet loss.",
        urgency: "NORMAL",
      },
      {
        timestamp: "1032",
        category: "FACILITY",
        headline: "Building B Loading Bay Restocked",
        body: "Freight shipment received and logged into storage ledger. Forklift bay clear for standard transit.",
        urgency: "NORMAL",
      },
      {
        timestamp: "1104",
        category: "ANNOUNCEMENT",
        headline: "All-Hands Quarterly Operations Briefing",
        body: "Operations leadership all-hands briefing scheduled for 1500 HRS in Main Auditorium and video bridge.",
        urgency: "NORMAL",
      },
      {
        timestamp: "1220",
        category: "LOGISTICS",
        headline: "Weather Advisory — Coastal Highway Corridor",
        body: "Rain warning for Western Logistics Route 9. Drivers advised to maintain 45mph ceiling and log checkpoints.",
        urgency: "FLASH",
      },
    ],
  });

  // 3. Staff Roster
  await prisma.staffMember.deleteMany({});
  await prisma.staffMember.createMany({
    data: [
      {
        name: "Marcus Vance",
        email: "m.vance@company.internal",
        role: "Lead Systems Engineer",
        department: "ENGINEERING",
        status: "ON_DUTY",
        deskLocation: "Desk 4A — Floor 3",
        extension: "x4102",
      },
      {
        name: "Elena Rostova",
        email: "e.rostova@company.internal",
        role: "Fleet Logistics Dispatcher",
        department: "LOGISTICS",
        status: "ON_DUTY",
        deskLocation: "Desk 1B — Floor 1",
        extension: "x1120",
      },
      {
        name: "Devon Chen",
        email: "d.chen@company.internal",
        role: "Senior Support Operations Specialist",
        department: "SUPPORT",
        status: "REMOTE",
        deskLocation: "Remote (APAC Hub)",
        extension: "x8841",
      },
      {
        name: "Sarah Jenkins",
        email: "s.jenkins@company.internal",
        role: "Operations Controller & Finance",
        department: "FINANCE",
        status: "ON_DUTY",
        deskLocation: "Desk 6C — Floor 4",
        extension: "x6305",
      },
      {
        name: "Thomas Wright",
        email: "t.wright@company.internal",
        role: "Facilities Maintenance Supervisor",
        department: "FACILITIES",
        status: "ON_CALL",
        deskLocation: "Plant Control Room",
        extension: "x2004",
      },
      {
        name: "Liam O'Connor",
        email: "l.oconnor@company.internal",
        role: "Network Operations Center Lead",
        department: "OPERATIONS",
        status: "ON_DUTY",
        deskLocation: "NOC Station 2",
        extension: "x9011",
      },
      {
        name: "Priya Sharma",
        email: "p.sharma@company.internal",
        role: "Quality Assurance Analyst",
        department: "OPERATIONS",
        status: "OFF_DUTY",
        deskLocation: "Desk 3F — Floor 2",
        extension: "x3309",
      },
    ],
  });

  // 4. Ledger Records
  await prisma.ledgerRecord.deleteMany({});
  await prisma.ledgerRecord.createMany({
    data: [
      {
        refNumber: "LED-8841",
        entryDate: "2026-08-15",
        description: "Server Chassis Replacement Hardware (Order #4920)",
        category: "INFRASTRUCTURE",
        amount: 4250.0,
        type: "DEBIT",
        authorizedBy: "M. Vance",
      },
      {
        refNumber: "LED-8842",
        entryDate: "2026-08-15",
        description: "Regional Courier Contract Monthly Settlement",
        category: "VENDOR_PAYMENT",
        amount: 1875.5,
        type: "DEBIT",
        authorizedBy: "E. Rostova",
      },
      {
        refNumber: "LED-8843",
        entryDate: "2026-08-14",
        description: "Surplus Component Hardware Disposal Credit",
        category: "PROCUREMENT",
        amount: 890.0,
        type: "CREDIT",
        authorizedBy: "S. Jenkins",
      },
      {
        refNumber: "LED-8844",
        entryDate: "2026-08-14",
        description: "Facility Generator Fuel Resupply (600 Gallons)",
        category: "SUPPLIES",
        amount: 2460.0,
        type: "DEBIT",
        authorizedBy: "T. Wright",
      },
      {
        refNumber: "LED-8845",
        entryDate: "2026-08-13",
        description: "Operations Staff Field Transit Reimbursements",
        category: "TRAVEL",
        amount: 640.25,
        type: "DEBIT",
        authorizedBy: "S. Jenkins",
      },
    ],
  });

  // 5. Archive Records
  await prisma.archiveRecord.deleteMany({});
  await prisma.archiveRecord.createMany({
    data: [
      {
        recordNumber: "REC-2026-001",
        title: "Q2 Enterprise Operations Post-Mortem & Capacity Report",
        department: "OPERATIONS",
        filingDate: "2026-07-02",
        summary: "Quarterly review of peak throughput, regional dispatch bottlenecks, and server reliability metrics.",
        tags: "Q2, Performance, Operations, Audit",
        filedBy: "S. Jenkins",
      },
      {
        recordNumber: "REC-2026-002",
        title: "Annual Logistics Fleet Safety Certification",
        department: "LOGISTICS",
        filingDate: "2026-06-18",
        summary: "Full compliance audit covering all 24 transit vans, driver training hours, and telematics calibration.",
        tags: "Compliance, Fleet, Safety",
        filedBy: "E. Rostova",
      },
      {
        recordNumber: "REC-2026-003",
        title: "Primary Data Center Power Distribution Redesign",
        department: "ENGINEERING",
        filingDate: "2026-05-30",
        summary: "Schematic blueprints and circuit breaker loads for Floor 2 battery backup modernization.",
        tags: "Engineering, DataCenter, Power",
        filedBy: "M. Vance",
      },
      {
        recordNumber: "REC-2026-004",
        title: "Standard Operating Procedures: Inclement Weather Protocol",
        department: "FACILITIES",
        filingDate: "2026-04-12",
        summary: "Operational guidelines for building safety, loading dock protocols, and remote work activation.",
        tags: "SOP, Facilities, Emergency",
        filedBy: "T. Wright",
      },
    ],
  });

  // 6. Desk Messages
  await prisma.deskMessage.deleteMany({});
  await prisma.deskMessage.createMany({
    data: [
      {
        senderName: "Marcus Vance",
        senderEmail: "m.vance@company.internal",
        recipientEmail: "desk@company.internal",
        subject: "Fiber maintenance scheduled for 2200 HRS tonight",
        content: "Please ensure all automated backup jobs are initiated prior to 2130 HRS. Expect brief 2-minute latency jitter.",
        urgent: true,
        read: false,
      },
      {
        senderName: "Sarah Jenkins",
        senderEmail: "s.jenkins@company.internal",
        recipientEmail: "desk@company.internal",
        subject: "Expense receipts submission deadline is Friday 1700 HRS",
        content: "Reminder to submit all travel and hardware expense receipts for July billing cycle before end-of-week.",
        urgent: false,
        read: true,
      },
      {
        senderName: "Elena Rostova",
        senderEmail: "e.rostova@company.internal",
        recipientEmail: "desk@company.internal",
        subject: "Unit 07 back in service after tire replacement",
        content: "Logistics van 07 passed inspection and is back on the standard dispatch schedule.",
        urgent: false,
        read: true,
      },
    ],
  });

  // 7. Calendar Shifts
  await prisma.calendarShift.deleteMany({});
  await prisma.calendarShift.createMany({
    data: [
      {
        title: "Morning Operations Shift",
        date: "2026-08-16",
        startTime: "0700",
        endTime: "1530",
        shiftType: "MORNING_SHIFT",
        assignedStaff: "Marcus Vance, Elena Rostova",
      },
      {
        title: "Day Dispatch & Support Desk",
        date: "2026-08-16",
        startTime: "0900",
        endTime: "1730",
        shiftType: "DAY_SHIFT",
        assignedStaff: "Devon Chen, Sarah Jenkins",
      },
      {
        title: "Night Operations & NOC Standby",
        date: "2026-08-16",
        startTime: "1700",
        endTime: "0130",
        shiftType: "NIGHT_DESK",
        assignedStaff: "Liam O'Connor",
      },
      {
        title: "Weekend Facilities On-Call",
        date: "2026-08-17",
        startTime: "0800",
        endTime: "2000",
        shiftType: "ON_CALL",
        assignedStaff: "Thomas Wright",
      },
    ],
  });

  console.log("Operations Desk database successfully populated with clean corporate data!");
}

// Execute if run directly
if (require.main === module) {
  seedOperationsDesk()
    .catch((e) => {
      console.error(e);
      process.exit(1);
    })
    .finally(async () => {
      await prisma.$disconnect();
    });
}
