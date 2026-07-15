import { NextResponse } from "next/server";
import { prisma } from "@/lib/prisma";
import { z } from "zod";

const alertSchema = z.object({
  alertType: z.string().optional(),
  severity: z.string().optional(),
  message: z.string().min(1),
  deviceId: z.number().optional().nullable(),
  ruleId: z.number().optional().nullable(),
  srcIp: z.string().optional().nullable(),
  dstIp: z.string().optional().nullable(),
  signatureId: z.number().optional().nullable(),
  timestamp: z.number().optional(),
});

const batchSchema = z.object({
  alerts: z.array(alertSchema),
});

export async function GET() {
  try {
    const notifications = await prisma.notification.findMany({
      orderBy: { sentAt: "desc" },
      take: 100,
    });
    return NextResponse.json(notifications);
  } catch (error) {
    console.error("GET /api/alerts error:", error);
    return NextResponse.json({ error: "Internal server error" }, { status: 500 });
  }
}

export async function POST(request: Request) {
  try {
    const body = await request.json();

    if (body.alerts && Array.isArray(body.alerts)) {
      const parsed = batchSchema.safeParse(body);
      if (!parsed.success) {
        return NextResponse.json({ error: parsed.error.flatten().fieldErrors }, { status: 400 });
      }

      const created = await prisma.$transaction(
        parsed.data.alerts.map((a) =>
          prisma.notification.create({
            data: {
              message: a.message,
              severity: a.severity ?? "Medium",
              deviceId: a.deviceId ?? null,
              ruleId: a.ruleId ?? null,
            },
          })
        )
      );

      return NextResponse.json({ count: created.length }, { status: 201 });
    }

    const parsed = alertSchema.safeParse(body);
    if (!parsed.success) {
      return NextResponse.json({ error: parsed.error.flatten().fieldErrors }, { status: 400 });
    }

    const notification = await prisma.notification.create({
      data: {
        message: parsed.data.message,
        severity: parsed.data.severity ?? "Medium",
        deviceId: parsed.data.deviceId ?? null,
        ruleId: parsed.data.ruleId ?? null,
      },
    });
    return NextResponse.json(notification, { status: 201 });
  } catch (error) {
    console.error("POST /api/alerts error:", error);
    return NextResponse.json({ error: "Internal server error" }, { status: 500 });
  }
}
