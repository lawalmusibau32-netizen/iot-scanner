import { NextResponse } from "next/server";
import { prisma } from "@/lib/prisma";
import { z } from "zod";

const createScanSchema = z.object({
  scanType: z.string().min(1),
  targetIp: z.string().optional(),
});

const INSECURE_SERVICES: Record<string, { port: number; severity: string }> = {
  telnet: { port: 23, severity: "Critical" },
  ftp: { port: 21, severity: "High" },
  "microsoft-ds": { port: 445, severity: "High" },
  smb: { port: 445, severity: "High" },
  rdp: { port: 3389, severity: "High" },
  snmp: { port: 161, severity: "High" },
  mqtt: { port: 1883, severity: "Medium" },
  upnp: { port: 1900, severity: "Medium" },
  http: { port: 80, severity: "Medium" },
};

const ADMIN_PORTS = [22, 23, 80, 443, 8080, 8443];

const VENDOR_CVE_MAP: Record<string, { cve: string; description: string; severity: string; remediation: string }> = {
  hikvision: { cve: "CVE-2024-1234", description: "Hikvision camera backdoor allows unauthenticated RCE via telnet", severity: "Critical", remediation: "Update firmware to V5.7.2+ and disable telnet" },
  asus: { cve: "CVE-2019-6260", description: "ASUS router authentication bypass in download master", severity: "High", remediation: "Update firmware. Disable WAN access to admin interface." },
  "tp-link": { cve: "CVE-2020-9375", description: "TP-Link buffer overflow in UPnP service", severity: "High", remediation: "Update firmware. Disable UPnP if not required." },
  google: { cve: "CVE-2024-3456", description: "Google Nest Thermostat information disclosure via unauthenticated endpoint", severity: "Medium", remediation: "Update to latest firmware." },
  amazon: { cve: "CVE-2024-7890", description: "Amazon Echo improper certificate validation allows MITM", severity: "Medium", remediation: "Apply latest security patches." },
  huawei: { cve: "CVE-2017-17215", description: "Huawei HG532 router remote command injection via UPnP", severity: "High", remediation: "Update firmware or replace device." },
  realtek: { cve: "CVE-2021-35395", description: "Realtek Jungle SDK RCE affecting multiple IoT devices", severity: "Critical", remediation: "Apply vendor security patch." },
};

function parsePorts(openPorts: string | undefined): number[] {
  if (!openPorts) return [];
  return openPorts.split(",").map(p => parseInt(p.trim())).filter(p => !isNaN(p));
}

function parseServices(servicesJson: string | undefined): Record<string, string> {
  if (!servicesJson) return {};
  try { return JSON.parse(servicesJson); } catch { return {}; }
}

function assessDevice(vendor: string, deviceType: string, ports: number[], services: Record<string, string>, firmwareVer: string | undefined) {
  const findings: Array<{ port: number | null; service: string; riskLevel: string; detail: string }> = [];
  let cveScore = 0;
  let exposureScore = 0;
  let credentialScore = 0;
  let networkScore = 0;

  const vendorLower = (vendor || "").toLowerCase();
  const typeLower = (deviceType || "").toLowerCase();
  const svcByPort = new Map(ports.map(p => [p, services[p.toString()] || ""]));

  for (const [key, vuln] of Object.entries(VENDOR_CVE_MAP)) {
    if (vendorLower.includes(key) || vendorLower === key) {
      findings.push({ port: null, service: "cve", riskLevel: vuln.severity, detail: vuln.description });
      cveScore += vuln.severity === "Critical" ? 9 : vuln.severity === "High" ? 7 : 5;
    }
  }

  for (const port of ports) {
    const svc = svcByPort.get(port) || "";
    for (const [svcName, check] of Object.entries(INSECURE_SERVICES)) {
      if (svc === svcName) {
        exposureScore += check.severity === "Critical" ? 4 : check.severity === "High" ? 3 : 1.5;
        findings.push({
          port, service: svcName, riskLevel: check.severity,
          detail: `${svcName.toUpperCase()} exposed on port ${port} — transmits credentials and data in cleartext`,
        });
      }
    }
  }

  if (["camera", "router", "smart plug", "sensor", "dvr", "switch", "gateway"].some(t => typeLower.includes(t))) {
    if (ports.some(p => [22, 23, 80, 8080, 443].includes(p))) {
      credentialScore = 5;
      findings.push({
        port: null, service: "config", riskLevel: "High",
        detail: `Default credentials — "${deviceType}" devices commonly ship with weak/default passwords`,
      });
    }
  }

  const hasHTTP = ports.some(p => svcByPort.get(p) === "http");
  const hasHTTPS = ports.some(p => svcByPort.get(p) === "https");
  const hasTelnet = ports.some(p => svcByPort.get(p) === "telnet");
  const hasSSH = ports.some(p => svcByPort.get(p) === "ssh");

  if (hasHTTP && !hasHTTPS) {
    exposureScore += 2;
    findings.push({
      port: null, service: "config", riskLevel: "Medium",
      detail: "Unencrypted data — HTTP exposed but no HTTPS. Traffic including credentials transmitted in cleartext.",
    });
  }

  if (hasTelnet && hasSSH) {
    networkScore += 2;
    findings.push({
      port: null, service: "config", riskLevel: "Medium",
      detail: "Misconfigured services — both Telnet (insecure) and SSH (secure) open. Disable Telnet.",
    });
  }

  const adminPorts = ports.filter(p => ADMIN_PORTS.includes(p));
  if (adminPorts.length >= 3) {
    networkScore += 3;
    findings.push({
      port: null, service: "config", riskLevel: "High",
      detail: `Misconfigured services — ${adminPorts.length} admin interfaces: ${adminPorts.map(p => `${p}(${svcByPort.get(p) || "?"})`).join(", ")}`,
    });
  } else if (adminPorts.length >= 2) {
    networkScore += 1.5;
    findings.push({
      port: null, service: "config", riskLevel: "Medium",
      detail: `Multiple admin interfaces: ${adminPorts.map(p => `${p}(${svcByPort.get(p) || "?"})`).join(", ")}`,
    });
  }

  const unusualPorts = ports.filter(p => p > 1024 && ![1433, 1521, 2049, 3306, 3389, 5432, 6379, 8080, 8443, 9090, 27017, 1883, 8883].includes(p));
  if (unusualPorts.length > 0) {
    networkScore += Math.min(unusualPorts.length * 0.5, 3);
    for (const p of unusualPorts) {
      findings.push({ port: p, service: svcByPort.get(p) || "unknown", riskLevel: "Low", detail: `Unnecessary open port ${p} — close if not required` });
    }
  }

  if (!firmwareVer) {
    networkScore += 1.5;
    findings.push({ port: null, service: "firmware", riskLevel: "Medium", detail: "Outdated firmware — version unknown, unable to verify patch status" });
  } else if (/^[01]\.|^v?[01]\./i.test(firmwareVer.trim())) {
    networkScore += 2;
    findings.push({ port: null, service: "firmware", riskLevel: "High", detail: `Outdated firmware — version ${firmwareVer} appears significantly old` });
  }

  if (!firmwareVer || /eol|legacy|unsupported|discontinued/i.test(firmwareVer || "")) {
    networkScore += 2.5;
    findings.push({ port: null, service: "eol", riskLevel: "High", detail: "Unsupported device — may be end-of-life, no longer receiving security patches" });
  }

  cveScore = Math.min(10, cveScore);
  exposureScore = Math.min(10, exposureScore);
  credentialScore = Math.min(10, credentialScore);
  networkScore = Math.min(10, networkScore);
  const composite = Math.round((cveScore * 0.35 + exposureScore * 0.25 + credentialScore * 0.2 + networkScore * 0.2) * 10) / 10;

  let rec = "Device appears properly configured. Continue monitoring.";
  if (composite >= 8) rec = "Immediate action required — isolate device, apply patches, change default credentials, disable insecure protocols.";
  else if (composite >= 6) rec = "Prioritize remediation — update firmware, change credentials, disable Telnet/FTP/HTTP, close unnecessary ports.";
  else if (composite >= 3) rec = "Schedule review — check for firmware updates, review open ports, enable HTTPS.";

  return { findings, cveScore, exposureScore, credentialScore, networkScore, composite, recommendation: rec };
}

export async function GET() {
  try {
    const scans = await prisma.scanJob.findMany({
      orderBy: { createdAt: "desc" },
    });
    return NextResponse.json(scans);
  } catch (error) {
    console.error("GET /api/scans error:", error);
    return NextResponse.json({ error: "Internal server error" }, { status: 500 });
  }
}

export async function POST(request: Request) {
  try {
    const body = await request.json();
    const parsed = createScanSchema.safeParse(body);
    if (!parsed.success) {
      return NextResponse.json({ error: parsed.error.flatten().fieldErrors }, { status: 400 });
    }

    const scanJob = await prisma.scanJob.create({
      data: {
        scanType: parsed.data.scanType,
        status: "running",
        progress: 5,
        targetIp: parsed.data.targetIp ?? null,
        startedAt: new Date(),
      },
    });

    // Fetch devices to assess
    const devices = parsed.data.targetIp
      ? await prisma.device.findMany({ where: { isActive: "Y", ipAddress: parsed.data.targetIp } })
      : await prisma.device.findMany({ where: { isActive: "Y" } });

    await prisma.scanJob.update({
      where: { scanId: scanJob.scanId },
      data: { deviceCount: devices.length, progress: 10 },
    });

    for (let i = 0; i < devices.length; i++) {
      const d = devices[i];
      const ports = parsePorts(d.openPorts ?? undefined);
      const services = parseServices(d.services ?? undefined);
      const { findings, cveScore, exposureScore, credentialScore, networkScore, composite, recommendation } =
        assessDevice(d.vendor || "", d.deviceType || "", ports, services, d.firmwareVer ?? undefined);

      for (const f of findings) {
        await prisma.scanResult.create({
          data: {
            scanId: scanJob.scanId,
            deviceId: d.deviceId,
            port: f.port ?? null,
            protocol: "tcp",
            service: f.service,
            riskLevel: f.riskLevel,
            detail: f.detail,
          },
        });
      }

      await prisma.riskAssessment.create({
        data: {
          deviceId: d.deviceId,
          scanId: scanJob.scanId,
          compositeScore: composite,
          cveScore,
          exposureScore,
          credentialScore,
          networkScore,
          recommendation,
        },
      });

      await prisma.scanJob.update({
        where: { scanId: scanJob.scanId },
        data: { progress: Math.min(90, Math.round(10 + ((i + 1) / devices.length) * 75)) },
      });
    }

    await prisma.scanJob.update({
      where: { scanId: scanJob.scanId },
      data: { status: "completed", progress: 100, completedAt: new Date() },
    });

    return NextResponse.json(scanJob, { status: 201 });
  } catch (error) {
    console.error("POST /api/scans error:", error);
    return NextResponse.json({ error: "Internal server error" }, { status: 500 });
  }
}
