import { NextResponse } from "next/server";
import { prisma } from "@/lib/prisma";

export async function GET() {
  try {
    const [
      totalDevices,
      totalVulnerabilities,
      completedScans,
      criticalRisks,
      highRisks,
      mediumRisks,
      lowRisks,
    ] = await Promise.all([
      prisma.device.count({ where: { isActive: "Y" } }),
      prisma.vulnerability.count(),
      prisma.scanJob.count({ where: { status: "completed" } }),
      prisma.riskAssessment.count({
        where: { compositeScore: { gte: 8 }, device: { isActive: "Y" } },
      }),
      prisma.riskAssessment.count({
        where: { compositeScore: { gte: 6, lt: 8 }, device: { isActive: "Y" } },
      }),
      prisma.riskAssessment.count({
        where: { compositeScore: { gte: 3, lt: 6 }, device: { isActive: "Y" } },
      }),
      prisma.riskAssessment.count({
        where: { compositeScore: { lt: 3 }, device: { isActive: "Y" } },
      }),
    ]);

    return NextResponse.json({
      totalDevices,
      totalVulnerabilities,
      scanCount: completedScans,
      criticalCount: criticalRisks,
      highCount: highRisks,
      mediumCount: mediumRisks,
      lowCount: lowRisks,
    });
  } catch (error) {
    console.error("GET /api/stats error:", error);
    return NextResponse.json({ error: "Internal server error" }, { status: 500 });
  }
}
