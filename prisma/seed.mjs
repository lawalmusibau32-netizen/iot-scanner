import { PrismaClient } from '../src/lib/prisma-client/client.js';
import bcrypt from 'bcryptjs';

const prisma = new PrismaClient();

async function main() {
  console.log("Seeding database...");

  const admin = await prisma.user.upsert({
    where: { username: "admin" },
    update: {},
    create: { username: "admin", displayName: "Administrator", passwordHash: bcrypt.hashSync("admin123", 12), role: "admin" },
  });
  console.log(`  User: ${admin.username}`);

  const devices = [
    { mac: "00:11:22:33:44:01", ip: "192.168.1.10", host: "cam-front", vendor: "Hikvision", type: "Camera", os: "Linux", fw: "V5.7.1", ports: "80,443,554,23", svc: '{"80":"http","443":"https","554":"rtsp","23":"telnet"}' },
    { mac: "00:11:22:33:44:02", ip: "192.168.1.1", host: "router", vendor: "ASUS", type: "Router", os: "ASUSWRT", fw: "3.0.0.4.386", ports: "80,443,22,53", svc: '{"80":"http","443":"https","22":"ssh","53":"dns"}' },
    { mac: "00:11:22:33:44:03", ip: "192.168.1.20", host: "nest-hall", vendor: "Google", type: "Thermostat", os: "Nest OS", fw: "6.2", ports: "80,443", svc: '{"80":"http","443":"https"}' },
    { mac: "00:11:22:33:44:04", ip: "192.168.1.30", host: "echo-kitchen", vendor: "Amazon", type: "Speaker", os: "FireOS", fw: "7.1.2", ports: "443", svc: '{"443":"https"}' },
    { mac: "00:11:22:33:44:05", ip: "192.168.1.40", host: "plug-living", vendor: "TP-Link", type: "Smart Plug", os: "RTOS", fw: "1.0.1", ports: "80,443,9999", svc: '{"80":"http","443":"https","9999":"unknown"}' },
  ];

  for (const d of devices) {
    await prisma.device.upsert({
      where: { macAddress: d.mac },
      update: {},
      create: { macAddress: d.mac, ipAddress: d.ip, hostname: d.host, vendor: d.vendor, deviceType: d.type, osName: d.os, firmwareVer: d.fw, openPorts: d.ports, services: d.svc },
    });
  }
  console.log(`  Devices: ${devices.length}`);

  const vulns = [
    { cve: "CVE-2024-1234", cvss: 9.1, sev: "Critical", desc: "Hikvision camera backdoor - unauthenticated RCE via telnet", cpe: "cpe:2.3:h:hikvision:ds-2cd2xx3", fix: "Update firmware to V5.7.2+, disable telnet" },
    { cve: "CVE-2024-5678", cvss: 8.5, sev: "High", desc: "ASUS router buffer overflow in httpd", cpe: "cpe:2.3:h:asus:rt-ac68u", fix: "Update to firmware 3.0.0.4.386_51665" },
    { cve: "CVE-2024-9012", cvss: 7.3, sev: "High", desc: "TP-Link Smart Plug command injection via HTTP", cpe: "cpe:2.3:h:tp-link:hs100", fix: "Disable remote management" },
    { cve: "CVE-2024-3456", cvss: 6.2, sev: "Medium", desc: "Nest Thermostat information disclosure", cpe: "cpe:2.3:h:google:nest_thermostat", fix: "Update to Nest OS 6.3+" },
    { cve: "CVE-2024-7890", cvss: 4.5, sev: "Medium", desc: "Amazon Echo improper cert validation - MITM risk", cpe: "cpe:2.3:h:amazon:echo_dot", fix: "Apply latest FireOS patches" },
    { cve: "CVE-2024-2468", cvss: 9.8, sev: "Critical", desc: "Default credentials on IoT devices - Mirai botnet target", cpe: "cpe:2.3:h:generic:iot_device", fix: "Change all default passwords" },
  ];

  for (const v of vulns) {
    await prisma.vulnerability.upsert({
      where: { cveId: v.cve },
      update: {},
      create: { cveId: v.cve, cvssScore: v.cvss, severity: v.sev, description: v.desc, affectedCpe: v.cpe, remediation: v.fix, publishedDate: new Date("2024-06-01") },
    });
  }
  console.log(`  Vulnerabilities: ${vulns.length}`);

  for (const rule of [{ n: "Critical Vuln Alert", e: "critical_vuln", t: 8.0 }, { n: "New Device", e: "new_device" }, { n: "High Risk", e: "high_risk", t: 6.0 }]) {
    await prisma.alertRule.create({ data: { name: rule.n, eventType: rule.e, threshold: rule.t ?? null, channels: '["in-app"]' } });
  }

  const allDevices = await prisma.device.findMany();
  const allVulns = await prisma.vulnerability.findMany();

  const job = await prisma.scanJob.create({
    data: { userId: admin.userId, scanType: "full", status: "completed", progress: 100, deviceCount: allDevices.length, startedAt: new Date(Date.now() - 60000), completedAt: new Date() },
  });

  for (const device of allDevices) {
    const ports = (device.openPorts || "").split(",").filter(Boolean).map(Number);
    for (const vuln of allVulns) {
      if (Math.random() > 0.5) continue;
      await prisma.scanResult.create({ data: { scanId: job.scanId, deviceId: device.deviceId, vulnId: vuln.vulnId, port: ports.length > 0 ? ports[Math.floor(Math.random() * ports.length)] : null, service: "http", riskLevel: vuln.severity, detail: vuln.description } });
    }

    const cveS = Math.min(10, allVulns.filter(() => Math.random() > 0.5).reduce((s, v) => s + (v.cvssScore || 0) / 3, 0));
    const expS = Math.min(10, (ports.includes(23) ? 4 : 0) + ports.filter(p => [23, 21, 3389, 445].includes(p)).length * 1.5);
    const credS = device.deviceType === "Camera" || device.deviceType === "Router" ? 5 : device.deviceType === "Smart Plug" ? 3 : 1;
    const netS = device.deviceType === "Router" ? 7 : device.deviceType === "Camera" ? 5 : 2;
    const comp = Math.round((cveS * 0.4 + expS * 0.25 + credS * 0.2 + netS * 0.15) * 10) / 10;

    let rec = "Monitor regularly.";
    if (comp >= 8) rec = "Isolate device and apply patches immediately.";
    else if (comp >= 6) rec = "Prioritize - update firmware and change credentials.";
    else if (comp >= 3) rec = "Review open ports and disable unnecessary services.";

    await prisma.riskAssessment.create({ data: { deviceId: device.deviceId, scanId: job.scanId, compositeScore: Math.min(10, comp), cveScore: Math.round(cveS * 10) / 10, exposureScore: Math.round(expS * 10) / 10, credentialScore: Math.min(10, credS), networkScore: Math.min(10, netS), recommendation: rec } });
  }

  const crit = await prisma.riskAssessment.findMany({ where: { compositeScore: { gte: 6 } }, include: { device: true }, take: 3 });
  for (const r of crit) {
    await prisma.notification.create({ data: { deviceId: r.deviceId, message: `${r.device.hostname || r.device.ipAddress} scored ${r.compositeScore}/10 - ${r.compositeScore >= 8 ? "Critical" : "High"} risk`, severity: r.compositeScore >= 8 ? "Critical" : "High" } });
  }

  console.log("  Seed complete!");
}

main().catch(e => { console.error("Seed error:", e); process.exit(1); }).finally(() => prisma.$disconnect());
