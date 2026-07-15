import { PrismaClient } from "../src/lib/prisma-client/client";
import * as bcrypt from "bcryptjs";

const prisma = new PrismaClient();

async function main() {
  console.log("Seeding database...");

  const admin = await prisma.user.upsert({
    where: { username: "admin" },
    update: {},
    create: {
      username: "admin",
      displayName: "Administrator",
      passwordHash: bcrypt.hashSync("admin123", 12),
      role: "admin",
    },
  });
  console.log(`  User: ${admin.username}`);

  const devices = [
    { mac: "00:11:22:33:44:01", ip: "192.168.1.10", hostname: "cam-front", vendor: "Hikvision", type: "Camera", os: "Linux", fw: "V5.7.1", ports: "80,443,554,23", svc: '{"80":"http","443":"https","554":"rtsp","23":"telnet"}' },
    { mac: "00:11:22:33:44:02", ip: "192.168.1.1", hostname: "router", vendor: "ASUS", type: "Router", os: "ASUSWRT", fw: "3.0.0.4.386", ports: "80,443,22,53", svc: '{"80":"http","443":"https","22":"ssh","53":"dns"}' },
    { mac: "00:11:22:33:44:03", ip: "192.168.1.20", hostname: "nest-hall", vendor: "Google", type: "Thermostat", os: "Nest OS", fw: "6.2", ports: "80,443", svc: '{"80":"http","443":"https"}' },
    { mac: "00:11:22:33:44:04", ip: "192.168.1.30", hostname: "echo-kitchen", vendor: "Amazon", type: "Speaker", os: "FireOS", fw: "7.1.2", ports: "443", svc: '{"443":"https"}' },
    { mac: "00:11:22:33:44:05", ip: "192.168.1.40", hostname: "plug-living", vendor: "TP-Link", type: "Smart Plug", os: "RTOS", fw: "1.0.1", ports: "80,443,9999", svc: '{"80":"http","443":"https","9999":"unknown"}' },
  ];

  for (const d of devices) {
    await prisma.device.upsert({
      where: { macAddress: d.mac },
      update: {},
      create: {
        macAddress: d.mac,
        ipAddress: d.ip,
        hostname: d.hostname,
        vendor: d.vendor,
        deviceType: d.type,
        osName: d.os,
        firmwareVer: d.fw,
        openPorts: d.ports,
        services: d.svc,
      },
    });
  }
  console.log(`  Devices: ${devices.length}`);

  const vulns = [
    { cve: "CVE-2024-1234", cvss: 9.1, sev: "Critical", desc: "Hikvision camera backdoor allows unauthenticated remote code execution via telnet", cpe: "cpe:2.3:h:hikvision:ds-2cd2xx3", remediation: "Update firmware to V5.7.2+ and disable telnet" },
    { cve: "CVE-2024-5678", cvss: 8.5, sev: "High", desc: "ASUS router buffer overflow in httpd allows arbitrary code execution", cpe: "cpe:2.3:h:asus:rt-ac68u", remediation: "Update to firmware 3.0.0.4.386_51665" },
    { cve: "CVE-2024-9012", cvss: 7.3, sev: "High", desc: "TP-Link Smart Plug command injection via crafted HTTP request", cpe: "cpe:2.3:h:tp-link:hs100", remediation: "Disable remote management and update to latest firmware" },
    { cve: "CVE-2024-3456", cvss: 6.2, sev: "Medium", desc: "Google Nest Thermostat information disclosure via unauthenticated endpoint", cpe: "cpe:2.3:h:google:nest_thermostat", remediation: "Update to Nest OS 6.3+" },
    { cve: "CVE-2024-7890", cvss: 4.5, sev: "Medium", desc: "Amazon Echo improper certificate validation allows MITM on local network", cpe: "cpe:2.3:h:amazon:echo_dot", remediation: "Apply latest FireOS security patches" },
    { cve: "CVE-2024-2468", cvss: 9.8, sev: "Critical", desc: "Multiple IoT devices use default credentials - Mirai botnet targets", cpe: "cpe:2.3:h:generic:iot_device", remediation: "Change all default passwords immediately" },
  ];

  for (const v of vulns) {
    await prisma.vulnerability.upsert({
      where: { cveId: v.cve },
      update: {},
      create: {
        cveId: v.cve,
        cvssScore: v.cvss,
        severity: v.sev,
        description: v.desc,
        affectedCpe: v.cpe,
        remediation: v.remediation,
        publishedDate: new Date("2024-06-01"),
      },
    });
  }
  console.log(`  Vulnerabilities: ${vulns.length}`);

  const alertRules = [
    { name: "Critical Vulnerability Alert", event: "critical_vuln", threshold: 8.0, channels: '["in-app"]' },
    { name: "New Device Detected", event: "new_device", channels: '["in-app"]' },
    { name: "High Risk Device", event: "high_risk", threshold: 6.0, channels: '["in-app"]' },
  ];

  for (const rule of alertRules) {
    await prisma.alertRule.create({
      data: {
        name: rule.name,
        eventType: rule.event,
        threshold: rule.threshold ?? null,
        channels: rule.channels,
      },
    });
  }
  console.log(`  Alert rules: ${alertRules.length}`);

  const allDevices = await prisma.device.findMany();
  const allVulns = await prisma.vulnerability.findMany();

  const scanJob = await prisma.scanJob.create({
    data: {
      userId: admin.userId,
      scanType: "full",
      status: "completed",
      progress: 100,
      deviceCount: allDevices.length,
      startedAt: new Date(Date.now() - 60000),
      completedAt: new Date(),
    },
  });

  for (const device of allDevices) {
    const devicePorts = (device.openPorts || "").split(",").filter(Boolean).map(Number);
    const hasTelnet = devicePorts.includes(23);
    const hasFTP = devicePorts.includes(21);
    const highRiskPorts = devicePorts.filter(p => [23, 21, 3389, 445, 135].includes(p));

    for (const vuln of allVulns) {
      if (Math.random() > 0.5) continue;
      await prisma.scanResult.create({
        data: {
          scanId: scanJob.scanId,
          deviceId: device.deviceId,
          vulnId: vuln.vulnId,
          port: devicePorts[Math.floor(Math.random() * devicePorts.length)] || null,
          protocol: "tcp",
          service: "http",
          riskLevel: vuln.severity,
          detail: vuln.description,
        },
      });
    }

    const cveScore = Math.min(10, allVulns.filter(v => Math.random() > 0.5).reduce((s, v) => s + (v.cvssScore || 0) / 3, 0));
    const exposureScore = Math.min(10, (hasTelnet ? 4 : 0) + highRiskPorts.length * 1.5);
    const credScore = device.deviceType === "Camera" || device.deviceType === "Router" ? 5 : device.deviceType === "Smart Plug" ? 3 : 1;
    const netScore = device.deviceType === "Router" ? 7 : device.deviceType === "Camera" ? 5 : 2;

    const composite = Math.round((cveScore * 0.4 + exposureScore * 0.25 + credScore * 0.2 + netScore * 0.15) * 10) / 10;

    let recommendation = "Monitor device regularly.";
    if (composite >= 8) recommendation = "Immediate action required. Isolate device and apply patches.";
    else if (composite >= 6) recommendation = "Prioritize remediation. Update firmware and change credentials.";
    else if (composite >= 3) recommendation = "Schedule review of open ports and services.";

    await prisma.riskAssessment.create({
      data: {
        deviceId: device.deviceId,
        scanId: scanJob.scanId,
        compositeScore: Math.min(10, composite),
        cveScore: Math.round(cveScore * 10) / 10,
        exposureScore: Math.round(exposureScore * 10) / 10,
        credentialScore: Math.min(10, credScore),
        networkScore: Math.min(10, netScore),
        recommendation,
      },
    });
  }

  const criticalDevices = await prisma.riskAssessment.findMany({
    where: { compositeScore: { gte: 6 } },
    include: { device: true },
    take: 3,
  });
  for (const ra of criticalDevices) {
    await prisma.notification.create({
      data: {
        deviceId: ra.deviceId,
        message: `${ra.device.hostname || ra.device.ipAddress} scored ${ra.compositeScore}/10 - ${ra.compositeScore >= 8 ? "Critical" : "High"} risk`,
        severity: ra.compositeScore >= 8 ? "Critical" : "High",
      },
    });
  }

  console.log("  Seed complete!");
}

main()
  .catch((e) => {
    console.error("Seed error:", e);
    process.exit(1);
  })
  .finally(() => prisma.$disconnect());
