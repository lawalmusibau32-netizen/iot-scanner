import { NextResponse } from "next/server";
import { prisma } from "@/lib/prisma";

export async function GET(_request: Request, { params }: { params: Promise<{ id: string }> }) {
  try {
    const { id } = await params;
    const device = await prisma.device.findUnique({ where: { deviceId: Number(id) } });
    if (!device) {
      return NextResponse.json({ error: "Device not found" }, { status: 404 });
    }
    return NextResponse.json(device);
  } catch (error) {
    console.error("GET /api/devices/[id] error:", error);
    return NextResponse.json({ error: "Internal server error" }, { status: 500 });
  }
}

export async function PUT(request: Request, { params }: { params: Promise<{ id: string }> }) {
  try {
    const { id } = await params;
    const existing = await prisma.device.findUnique({ where: { deviceId: Number(id) } });
    if (!existing) {
      return NextResponse.json({ error: "Device not found" }, { status: 404 });
    }
    const body = await request.json();
    const device = await prisma.device.update({
      where: { deviceId: Number(id) },
      data: { ...body, updatedAt: new Date() },
    });
    return NextResponse.json(device);
  } catch (error) {
    console.error("PUT /api/devices/[id] error:", error);
    return NextResponse.json({ error: "Internal server error" }, { status: 500 });
  }
}

export async function DELETE(request: Request, { params }: { params: Promise<{ id: string }> }) {
  try {
    const role = request.headers.get("x-user-role");
    if (role !== "admin") {
      return NextResponse.json({ error: "Forbidden" }, { status: 403 });
    }
    const { id } = await params;
    const existing = await prisma.device.findUnique({ where: { deviceId: Number(id) } });
    if (!existing) {
      return NextResponse.json({ error: "Device not found" }, { status: 404 });
    }
    await prisma.device.update({
      where: { deviceId: Number(id) },
      data: { isActive: "N", updatedAt: new Date() },
    });
    return NextResponse.json({ message: "Device deleted" });
  } catch (error) {
    console.error("DELETE /api/devices/[id] error:", error);
    return NextResponse.json({ error: "Internal server error" }, { status: 500 });
  }
}
