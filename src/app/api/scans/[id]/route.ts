import { NextResponse } from "next/server";
import { prisma } from "@/lib/prisma";
import { z } from "zod";

export async function GET(_request: Request, { params }: { params: Promise<{ id: string }> }) {
  try {
    const { id } = await params;
    const scan = await prisma.scanJob.findUnique({
      where: { scanId: Number(id) },
      include: { scanResults: { include: { device: true } } },
    });
    if (!scan) {
      return NextResponse.json({ error: "Scan not found" }, { status: 404 });
    }
    return NextResponse.json(scan);
  } catch (error) {
    console.error("GET /api/scans/[id] error:", error);
    return NextResponse.json({ error: "Internal server error" }, { status: 500 });
  }
}

export async function PUT(request: Request, { params }: { params: Promise<{ id: string }> }) {
  try {
    const { id } = await params;
    const existing = await prisma.scanJob.findUnique({ where: { scanId: Number(id) } });
    if (!existing) {
      return NextResponse.json({ error: "Scan not found" }, { status: 404 });
    }
    const body = await request.json();
    const { status, progress, errorLog, startedAt, completedAt } = body;
    const updateData: Record<string, unknown> = {};
    if (status !== undefined) updateData.status = status;
    if (progress !== undefined) updateData.progress = progress;
    if (errorLog !== undefined) updateData.errorLog = errorLog;
    if (startedAt !== undefined) updateData.startedAt = new Date(startedAt);
    if (completedAt !== undefined) updateData.completedAt = new Date(completedAt);

    const scan = await prisma.scanJob.update({
      where: { scanId: Number(id) },
      data: updateData,
    });
    return NextResponse.json(scan);
  } catch (error) {
    console.error("PUT /api/scans/[id] error:", error);
    return NextResponse.json({ error: "Internal server error" }, { status: 500 });
  }
}
