import { NextResponse } from "next/server";
import { prisma } from "@/lib/prisma";
import { z } from "zod";

const resultItemSchema = z.object({
  deviceId: z.number(),
  port: z.number().optional(),
  protocol: z.string().optional(),
  service: z.string().optional(),
  banner: z.string().optional(),
  riskLevel: z.string().optional(),
  vulnId: z.number().optional(),
  detail: z.string().optional(),
});

const riskItemSchema = z.object({
  deviceId: z.number(),
  compositeScore: z.number(),
  cveScore: z.number(),
  exposureScore: z.number(),
  credentialScore: z.number(),
  networkScore: z.number(),
  recommendation: z.string().optional(),
});

const ingestSchema = z.object({
  results: z.array(resultItemSchema).optional(),
  risks: z.array(riskItemSchema).optional(),
});

export async function POST(request: Request, { params }: { params: Promise<{ id: string }> }) {
  try {
    const { id } = await params;
    const scanId = Number(id);
    const existing = await prisma.scanJob.findUnique({ where: { scanId } });
    if (!existing) {
      return NextResponse.json({ error: "Scan not found" }, { status: 404 });
    }

    const body = await request.json();
    const parsed = ingestSchema.safeParse(body);
    if (!parsed.success) {
      return NextResponse.json({ error: parsed.error.flatten().fieldErrors }, { status: 400 });
    }

    const { results, risks } = parsed.data;
    let createdResults = 0;
    let createdRisks = 0;

    if (results && results.length > 0) {
      const data = results.map((r) => ({ ...r, scanId }));
      await prisma.scanResult.createMany({ data });
      createdResults = results.length;
    }

    if (risks && risks.length > 0) {
      const data = risks.map((r) => ({ ...r, scanId }));
      await prisma.riskAssessment.createMany({ data });
      createdRisks = risks.length;
    }

    return NextResponse.json({ createdResults, createdRisks }, { status: 201 });
  } catch (error) {
    console.error("POST /api/scans/[id]/results error:", error);
    return NextResponse.json({ error: "Internal server error" }, { status: 500 });
  }
}
