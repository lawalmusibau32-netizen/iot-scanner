import { NextResponse } from "next/server";
import { prisma } from "@/lib/prisma";
import { z } from "zod";

const createScanSchema = z.object({
  scanType: z.string().min(1),
  targetIp: z.string().optional(),
});

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
    const scan = await prisma.scanJob.create({
      data: { scanType: parsed.data.scanType, status: "pending", targetIp: parsed.data.targetIp ?? null },
    });
    return NextResponse.json(scan, { status: 201 });
  } catch (error) {
    console.error("POST /api/scans error:", error);
    return NextResponse.json({ error: "Internal server error" }, { status: 500 });
  }
}
