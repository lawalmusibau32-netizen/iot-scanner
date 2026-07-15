import { NextResponse } from "next/server";
import { prisma } from "@/lib/prisma";

export async function GET(request: Request) {
  try {
    const { searchParams } = new URL(request.url);
    const search = searchParams.get("search");
    const severity = searchParams.get("severity");

    const where: Record<string, unknown> = {};
    if (search) {
      where.OR = [
        { cveId: { contains: search, mode: "insensitive" } },
        { description: { contains: search, mode: "insensitive" } },
      ];
    }
    if (severity) {
      where.severity = severity;
    }

    const vulnerabilities = await prisma.vulnerability.findMany({
      where,
      orderBy: { cvssScore: "desc" },
    });
    return NextResponse.json(vulnerabilities);
  } catch (error) {
    console.error("GET /api/vulnerabilities error:", error);
    return NextResponse.json({ error: "Internal server error" }, { status: 500 });
  }
}
