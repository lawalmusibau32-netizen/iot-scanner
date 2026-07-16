import { NextResponse } from "next/server";
import { prisma } from "@/lib/prisma";
import { z } from "zod";

const createDeviceSchema = z.object({
  macAddress: z.string().min(1),
  ipAddress: z.string().min(1),
  hostname: z.string().optional(),
  vendor: z.string().optional(),
  deviceType: z.string().optional(),
  osName: z.string().optional(),
  osVersion: z.string().optional(),
  firmwareVer: z.string().optional(),
  openPorts: z.string().optional(),
  services: z.string().optional(),
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
  const findings: Array<{
    port: number | null;
    service: string;
    riskLevel: string;
    detail: string;
  }> = [];
  let cveScore = 0;
  let exposureScore = 0;
  let credentialScore = 0;
  let networkScore = 0;

  const vendorLower = (vendor || "").toLowerCase();
  const typeLower = (deviceType || "").toLowerCase();

  // 1. Known CVE matches by vendor
  for (const [key, vuln] of Object.entries(VENDOR_CVE_MAP)) {
    if (vendorLower.includes(key) || vendorLower === key) {
      findings.push({ port: null, service: "cve", riskLevel: vuln.severity, detail: vuln.description });
      cveScore += vuln.severity === "Critical" ? 9 : vuln.severity === "High" ? 7 : 5;
    }
  }

  // 2. Insecure service checks
  for (const port of ports) {
    const svc = services[port.toString()] || "";
    for (const [svcName, check] of Object.entries(INSECURE_SERVICES)) {
      if (svc === svcName) {
        exposureScore += check.severity === "Critical" ? 4 : check.severity === "High" ? 3 : 1.5;
        findings.push({
          port,
          service: svcName,
          riskLevel: check.severity,
          detail: `${svcName.toUpperCase()} exposed on port ${port} — ${check.severity === "Critical" ? "credentials and data in cleartext" : "increases attack surface"}`,
        });
      }
    }
  }

  // 3. Default credential risk for certain device types
  if (["camera", "router", "smart plug", "sensor", "dvr"].some(t => typeLower.includes(t))) {
    const telnetOrHttp = ports.some(p => services[p.toString()] === "telnet" || services[p.toString()] === "http");
    if (telnetOrHttp || ports.some(p => [80, 8080, 23].includes(p))) {
      credentialScore = 5;
      findings.push({
        port: null,
        service: "http",
        riskLevel: "High",
        detail: `Device type "${deviceType}" commonly ships with default credentials — verify and change immediately`,
      });
    }
  }

  // 4. Multiple admin interfaces
  const adminPorts = ports.filter(p => ADMIN_PORTS.includes(p));
  if (adminPorts.length >= 2) {
    networkScore += 2;
    findings.push({
      port: null,
      service: "config",
      riskLevel: "Medium",
      detail: `Multiple admin interfaces exposed: ${adminPorts.map(p => `${p}(${services[p.toString()] || "?"})`).join(", ")}`,
    });
  }

  // 5. Unnecessary/unknown high ports
  const unusualPorts = ports.filter(p => p > 1024 && ![1433, 1521, 2049, 3306, 3389, 5432, 6379, 8080, 8443, 9090, 27017].includes(p));
  if (unusualPorts.length > 0) {
    networkScore += unusualPorts.length * 0.5;
    for (const p of unusualPorts) {
      findings.push({
        port: p,
        service: services[p.toString()] || "unknown",
        riskLevel: "Low",
        detail: `Unusual port ${p} open — may indicate custom service or backdoor`,
      });
    }
  }

  // 6. No firmware version
  if (!firmwareVer) {
    networkScore += 1;
    findings.push({
      port: null,
      service: "firmware",
      riskLevel: "Medium",
      detail: "Firmware version not provided — device may be running outdated software",
    });
  }

  cveScore = Math.min(10, cveScore);
  exposureScore = Math.min(10, exposureScore);
  credentialScore = Math.min(10, credentialScore);
  networkScore = Math.min(10, networkScore);
  const composite = Math.round((cveScore * 0.35 + exposureScore * 0.3 + credentialScore * 0.2 + networkScore * 0.15) * 10) / 10;

  let recommendation = "Device appears properly configured. Continue monitoring.";
  if (composite >= 8) recommendation = "Immediate action required. Isolate device, apply patches, change credentials.";
  else if (composite >= 6) recommendation = "Prioritize remediation. Update firmware, change credentials, close unnecessary ports.";
  else if (composite >= 3) recommendation = "Schedule review of open ports and disabled insecure services.";

  return { findings, cveScore, exposureScore, credentialScore, networkScore, composite, recommendation };
}

export async function GET() {
  try {
    const devices = await prisma.device.findMany({
      where: { isActive: "Y" },
      orderBy: { lastSeen: "desc" },
    });
    return NextResponse.json(devices);
  } catch (error) {
    console.error("GET /api/devices error:", error);
    return NextResponse.json({ error: "Internal server error" }, { status: 500 });
  }
}

export async function POST(request: Request) {
  try {
    const body = await request.json();
    const parsed = createDeviceSchema.safeParse(body);
    if (!parsed.success) {
      return NextResponse.json({ error: parsed.error.flatten().fieldErrors }, { status: 400 });
    }
    const device = await prisma.device.create({ data: parsed.data });

    // Run vulnerability assessment inline
    const ports = parsePorts(parsed.data.openPorts);
    const services = parseServices(parsed.data.services);
    const { findings, cveScore, exposureScore, credentialScore, networkScore, composite, recommendation } =
      assessDevice(parsed.data.vendor || "", parsed.data.deviceType || "", ports, services, parsed.data.firmwareVer);

    // Create a scan job to track this assessment
    const scanJob = await prisma.scanJob.create({
      data: {
        scanType: "targeted",
        status: "completed",
        progress: 100,
        deviceCount: 1,
        targetIp: device.ipAddress,
        startedAt: new Date(),
        completedAt: new Date(),
      },
    });

    // Create scan results for each finding
    for (const f of findings) {
      await prisma.scanResult.create({
        data: {
          scanId: scanJob.scanId,
          deviceId: device.deviceId,
          port: f.port ?? null,
          protocol: "tcp",
          service: f.service,
          riskLevel: f.riskLevel,
          detail: f.detail,
        },
      });
    }

    // Create risk assessment
    await prisma.riskAssessment.create({
      data: {
        deviceId: device.deviceId,
        scanId: scanJob.scanId,
        compositeScore: composite,
        cveScore,
        exposureScore,
        credentialScore,
        networkScore,
        recommendation,
      },
    });

    // Create notification for high/critical findings
    const criticalFindings = findings.filter(f => f.riskLevel === "Critical" || f.riskLevel === "High");
    if (criticalFindings.length > 0) {
      await prisma.notification.create({
        data: {
          deviceId: device.deviceId,
          message: `${device.hostname || device.ipAddress} scored ${composite}/10 — ${criticalFindings.length} high/critical findings`,
          severity: composite >= 8 ? "Critical" : "High",
        },
      });
    }

    return NextResponse.json({
      ...device,
      assessment: {
        compositeScore: composite,
        severity: composite >= 8 ? "Critical" : composite >= 6 ? "High" : composite >= 3 ? "Medium" : "Low",
        findings: findings.length,
        criticalCount: findings.filter(f => f.riskLevel === "Critical").length,
        highCount: findings.filter(f => f.riskLevel === "High").length,
        mediumCount: findings.filter(f => f.riskLevel === "Medium").length,
        lowCount: findings.filter(f => f.riskLevel === "Low").length,
        recommendation,
      },
    }, { status: 201 });
  } catch (error) {
    console.error("POST /api/devices error:", error);
    return NextResponse.json({ error: "Internal server error" }, { status: 500 });
  }
}
