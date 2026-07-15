import { NextResponse } from "next/server";
import { prisma } from "@/lib/prisma";

export async function GET() {
  try {
    const latestAssessments = await prisma.riskAssessment.findMany({
      where: {
        assessmentId: {
          in: (
            await prisma.riskAssessment.groupBy({
              by: ["deviceId"],
              _max: { assessmentId: true },
              where: { device: { isActive: "Y" } },
            })
          ).map((g) => g._max.assessmentId as number),
        },
      },
      include: { device: true },
    });
    return NextResponse.json(latestAssessments);
  } catch (error) {
    console.error("GET /api/risk error:", error);
    return NextResponse.json({ error: "Internal server error" }, { status: 500 });
  }
}
