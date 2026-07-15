import Link from "next/link";
import { prisma } from "@/lib/prisma";
import { PageHeader } from "@/components/shared/page-header";
import { DevicesTable } from "@/components/devices/devices-table";
import { Button } from "@/components/ui/button";
import { Plus } from "lucide-react";

export default async function DevicesPage() {
  const devices = await prisma.device.findMany({
    where: { isActive: "Y" },
    orderBy: { createdAt: "desc" },
  });

  const latestRisks = await prisma.riskAssessment.findMany({
    distinct: ["deviceId"],
    orderBy: [{ deviceId: "asc" }, { createdAt: "desc" }],
    select: { deviceId: true, compositeScore: true },
  });

  const riskMap = new Map(latestRisks.map((r) => [r.deviceId, r.compositeScore]));

  const enriched = devices.map((d) => ({
    id: d.deviceId.toString(),
    macAddress: d.macAddress,
    ipAddress: d.ipAddress,
    hostname: d.hostname,
    vendor: d.vendor,
    deviceType: d.deviceType,
    status: d.isActive === "Y" ? "Active" : "Inactive",
    riskScore: riskMap.has(d.deviceId)
      ? Math.round((riskMap.get(d.deviceId)! / 10) * 100)
      : null,
  }));

  return (
    <div className="animate-fade-in space-y-6">
      <PageHeader
        title="Devices"
        description="All discovered IoT devices on your network"
        actions={
          <Button asChild>
            <Link href="/devices/new">
              <Plus className="h-4 w-4" />
              Add Device
            </Link>
          </Button>
        }
      />
      <div className="animate-slide-up">
        <DevicesTable devices={enriched} />
      </div>
    </div>
  );
}
