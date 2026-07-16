import { NextResponse } from "next/server";
import { prisma } from "@/lib/prisma";

function generateReport(device: any, results: any[], risk: any | null) {
  const now = new Date().toISOString().split("T")[0];
  const ports = (device.openPorts || "").split(",").filter(Boolean);
  let services: Record<string, string> = {};
  try { services = JSON.parse(device.services || "{}"); } catch {}

  const criticalFindings = results.filter((r: any) => r.riskLevel === "Critical");
  const highFindings = results.filter((r: any) => r.riskLevel === "High");
  const mediumFindings = results.filter((r: any) => r.riskLevel === "Medium");
  const lowFindings = results.filter((r: any) => r.riskLevel === "Low");

  const severityLabel = risk
    ? risk.compositeScore >= 8 ? "Critical"
      : risk.compositeScore >= 6 ? "High"
      : risk.compositeScore >= 3 ? "Medium" : "Low"
    : "Unknown";

  return {
    title: `Security Assessment Report — ${device.hostname || device.ipAddress}`,
    generatedAt: now,
    summary: {
      deviceName: device.hostname || "Unnamed Device",
      ipAddress: device.ipAddress,
      macAddress: device.macAddress,
      vendor: device.vendor || "Unknown",
      deviceType: device.deviceType || "Unknown",
      osInfo: device.osName ? `${device.osName} ${device.osVersion || ""}`.trim() : "Not specified",
      firmware: device.firmwareVer || "Not specified",
      overallRisk: `${risk?.compositeScore.toFixed(1) || "N/A"}/10 — ${severityLabel}`,
      totalFindings: results.length,
      criticalCount: criticalFindings.length,
      highCount: highFindings.length,
      mediumCount: mediumFindings.length,
      lowCount: lowFindings.length,
    },
    narrative: generateNarrative(device, results, risk, {
      criticalFindings, highFindings, mediumFindings, lowFindings, severityLabel, ports, services,
    }),
    findings: results.map((r: any) => ({
      port: r.port,
      service: r.service,
      riskLevel: r.riskLevel,
      detail: r.detail,
      detectedAt: r.createdAt,
    })),
    riskScores: risk ? {
      composite: risk.compositeScore,
      cveScore: risk.cveScore,
      exposureScore: risk.exposureScore,
      credentialScore: risk.credentialScore,
      networkScore: risk.networkScore,
      recommendation: risk.recommendation,
    } : null,
    openPorts: ports.map((p: string) => ({
      port: parseInt(p),
      service: services[p] || "unknown",
    })),
  };
}

function generateNarrative(device: any, results: any[], risk: any | null, ctx: any) {
  const { severityLabel, ports, services, criticalFindings, highFindings, mediumFindings } = ctx;
  const sections: string[] = [];

  // 1. Executive Summary
  sections.push(
    `**Executive Summary**\n\n` +
    `This report details the security assessment of ${device.hostname || device.ipAddress}, ` +
    `a ${device.deviceType || "network"} device ${device.vendor ? `manufactured by ${device.vendor}` : ""}. ` +
    `The assessment identified ${results.length} potential security issue${results.length !== 1 ? "s" : ""} ` +
    `across ${ports.length} open port${ports.length !== 1 ? "s" : ""}. ` +
    `The overall risk rating is **${severityLabel}** ` +
    `(${risk?.compositeScore.toFixed(1) || "N/A"}/10), indicating that ` +
    (ctx.severityLabel === "Critical" ? "immediate remediation is required to prevent likely compromise." :
     ctx.severityLabel === "High" ? "prompt attention is needed to mitigate significant security exposure." :
     ctx.severityLabel === "Medium" ? "moderate security concerns exist and should be addressed in the near term." :
     "the device presents a low immediate risk but should continue to be monitored.")
  );

  // 2. Device Profile
  const osStr = device.osName ? `${device.osName} ${device.osVersion || ""}`.trim() : "not available";
  sections.push(
    `**Device Profile**\n\n` +
    `${device.hostname || device.ipAddress} is classified as a ${device.deviceType || "generic network"} device. ` +
    `It is assigned IP address ${device.ipAddress} with MAC ${device.macAddress}. ` +
    `${device.vendor ? `The device is manufactured by ${device.vendor}. ` : ""}` +
    `The operating system is reported as ${osStr}, ` +
    `and the firmware version is ${device.firmwareVer || "not specified"}. ` +
    `${!device.firmwareVer ? "The absence of firmware version information is itself a concern, as it prevents verification of patch status." : ""}`
  );

  // 3. Port Analysis
  if (ports.length > 0) {
    const portLines = ports.map((p: string) => {
      const svc = services[p] || "unknown";
      const isInsecure = p === "23" || p === "21" || p === "445" || p === "3389";
      return `${p}/${svc}${isInsecure ? " ⚠" : ""}`;
    });
    sections.push(
      `**Port Exposure Analysis**\n\n` +
      `The device exposes ${ports.length} network port${ports.length !== 1 ? "s" : ""}: ` +
      `${portLines.join(", ")}. ` +
      `${ports.includes("23") ? "Port 23 (Telnet) is particularly concerning as it transmits all data, including credentials, in cleartext. " : ""}` +
      `${ports.includes("21") ? "Port 21 (FTP) similarly exposes file transfers and authentication without encryption. " : ""}` +
      `${ports.includes("445") ? "Port 445 (SMB) exposes the device to potential credential harvesting and ransomware attacks. " : ""}` +
      `${ports.includes("3389") ? "Port 3389 (RDP) is a high-value target for brute force attacks. " : ""}` +
      `Each open port represents an additional entry point that could be exploited if the associated service contains vulnerabilities.`
    );
  }

  // 4. Vulnerability Findings
  if (results.length > 0) {
    let vulnNarrative = `**Vulnerability Findings**\n\n`;
    vulnNarrative += `The scan identified ${results.length} finding${results.length !== 1 ? "s" : ""}: `;
    vulnNarrative += `${criticalFindings.length} critical, ${highFindings.length} high, ${mediumFindings.length} medium, and ${ctx.lowFindings.length} low severity.\n\n`;

    if (criticalFindings.length > 0) {
      vulnNarrative += `**Critical Findings (${criticalFindings.length}):**\n`;
      criticalFindings.forEach((f: any) => {
        vulnNarrative += `- ${f.detail || `Issue detected on port ${f.port} (${f.service})`}\n`;
      });
      vulnNarrative += `\nCritical findings represent an active threat that can lead to device compromise without any additional conditions. Immediate action is required.\n\n`;
    }

    if (highFindings.length > 0) {
      vulnNarrative += `**High Severity Findings (${highFindings.length}):**\n`;
      highFindings.forEach((f: any) => {
        vulnNarrative += `- ${f.detail || `Security issue on port ${f.port} (${f.service})`}\n`;
      });
      vulnNarrative += `\nHigh severity findings indicate significant security weaknesses that should be prioritized for remediation.\n\n`;
    }

    if (mediumFindings.length > 0) {
      vulnNarrative += `**Medium Severity Findings (${mediumFindings.length}):**\n`;
      mediumFindings.forEach((f: any) => {
        vulnNarrative += `- ${f.detail || `Moderate concern on port ${f.port} (${f.service})`}\n`;
      });
      vulnNarrative += `\nMedium severity findings should be addressed during the next maintenance cycle.\n\n`;
    }

    sections.push(vulnNarrative);
  }

  // 5. Risk Score Breakdown
  if (risk) {
    sections.push(
      `**Risk Score Analysis**\n\n` +
      `The composite risk score of ${risk.compositeScore.toFixed(1)}/10 is calculated from four weighted factors:\n\n` +
      `- CVE Score (${risk.cveScore.toFixed(1)}/10): Represents known Common Vulnerabilities and Exposures associated with this device's vendor and type. ${risk.cveScore >= 5 ? "This score is elevated, indicating known exploits exist for this class of device." : "No significant CVE associations were identified."}\n` +
      `- Exposure Score (${risk.exposureScore.toFixed(1)}/10): Measures the risk from open ports and exposed services. ${risk.exposureScore >= 5 ? "The device exposes multiple services, significantly increasing its attack surface." : "Port exposure is limited, reducing the overall attack surface."}\n` +
      `- Credential Score (${risk.credentialScore.toFixed(1)}/10): Assesses the likelihood of default or weak credentials. ${risk.credentialScore >= 5 ? "This device type is commonly deployed with default credentials, representing a significant risk." : "No default credential indicators were flagged."}\n` +
      `- Network Score (${risk.networkScore.toFixed(1)}/10): Evaluates network-level security posture including unusual ports and configuration issues. ${risk.networkScore >= 5 ? "Network configuration concerns were identified." : "Network configuration appears standard."}\n\n` +
      `**Recommendation:** ${risk.recommendation}`
    );
  }

  // 6. Remediation Summary
  sections.push(
    `**Remediation Actions**\n\n` +
    `Based on the assessment findings, the following actions are recommended in order of priority:\n\n` +
    `${criticalFindings.length > 0 ? `1. **Immediate:** Address ${criticalFindings.length} critical finding${criticalFindings.length !== 1 ? "s" : ""}. Apply security patches, disable vulnerable services, or isolate the device.\n` : ""}` +
    `${highFindings.length > 0 ? `${criticalFindings.length > 0 ? "2" : "1"}. **Short-term:** Remediate ${highFindings.length} high-severity issue${highFindings.length !== 1 ? "s" : ""}. Update credentials, disable insecure protocols.\n` : ""}` +
    `${mediumFindings.length > 0 ? `${criticalFindings.length > 0 && highFindings.length > 0 ? "3" : criticalFindings.length > 0 || highFindings.length > 0 ? "2" : "1"}. **Medium-term:** Resolve ${mediumFindings.length} medium-severity concern${mediumFindings.length !== 1 ? "s" : ""} during next maintenance.\n` : ""}` +
    `${!device.firmwareVer ? `${criticalFindings.length + highFindings.length + mediumFindings.length > 0 ? criticalFindings.length + highFindings.length + mediumFindings.length + 1 : "1"}. **Ongoing:** Establish firmware version tracking and regular update cadence.\n` : ""}` +
    `\n**Final Note:** Security is an ongoing process. Regular assessments and prompt remediation of identified issues are essential to maintaining a strong security posture for IoT devices on the network.`
  );

  return sections.join("\n\n");
}

export async function GET(_request: Request, { params }: { params: Promise<{ id: string }> }) {
  try {
    const { id } = await params;
    const deviceId = parseInt(id, 10);
    if (isNaN(deviceId)) {
      return NextResponse.json({ error: "Invalid device ID" }, { status: 400 });
    }

    const device = await prisma.device.findUnique({
      where: { deviceId },
    });
    if (!device) {
      return NextResponse.json({ error: "Device not found" }, { status: 404 });
    }

    const results = await prisma.scanResult.findMany({
      where: { deviceId },
      orderBy: [{ riskLevel: "asc" }, { createdAt: "desc" }],
    });

    const risk = await prisma.riskAssessment.findFirst({
      where: { deviceId },
      orderBy: { createdAt: "desc" },
    });

    const report = generateReport(device, results, risk);

    return NextResponse.json(report);
  } catch (error) {
    console.error("GET /api/reports/[id] error:", error);
    return NextResponse.json({ error: "Internal server error" }, { status: 500 });
  }
}
