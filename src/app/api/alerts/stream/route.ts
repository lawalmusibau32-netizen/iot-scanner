import { prisma } from "@/lib/prisma";
import { NextResponse } from "next/server";

export async function GET() {
  try {
    const since = await prisma.notification.findFirst({ orderBy: { sentAt: "desc" }, take: 1 });
    const latest = since?.sentAt ?? new Date(0);
    const count = await prisma.notification.count();
    const unread = await prisma.notification.count({ where: { isRead: "N" } });
    const bySeverity = await prisma.notification.groupBy({
      by: ["severity"],
      _count: true,
    });

    return NextResponse.json({
      total: count,
      unread,
      latestAlert: latest.toISOString(),
      bySeverity: Object.fromEntries(bySeverity.map((s) => [s.severity, s._count])),
    });
  } catch {
    return NextResponse.json({ error: "Internal server error" }, { status: 500 });
  }
}
