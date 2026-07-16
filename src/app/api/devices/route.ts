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

    // Auto-create a scan job targeting this device
    await prisma.scanJob.create({
      data: {
        scanType: "targeted",
        status: "pending",
        targetIp: device.ipAddress,
      },
    });

    return NextResponse.json(device, { status: 201 });
  } catch (error) {
    console.error("POST /api/devices error:", error);
    return NextResponse.json({ error: "Internal server error" }, { status: 500 });
  }
}
