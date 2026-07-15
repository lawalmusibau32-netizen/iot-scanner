export const dynamic = 'force-dynamic';

import { notFound, redirect } from "next/navigation";
import { prisma } from "@/lib/prisma";
import { getCurrentUser } from "@/lib/auth";
import { DeviceForm } from "@/components/devices/device-form";

export default async function EditDevicePage(props: { params: Promise<{ id: string }> }) {
  const user = await getCurrentUser();
  if (!user) redirect("/login");

  const { id } = await props.params;
  const deviceId = parseInt(id, 10);
  if (isNaN(deviceId)) notFound();

  const device = await prisma.device.findUnique({ where: { deviceId } });
  if (!device) notFound();

  const deviceData = {
    id: device.deviceId.toString(),
    macAddress: device.macAddress,
    ipAddress: device.ipAddress,
    hostname: device.hostname,
    vendor: device.vendor,
    deviceType: device.deviceType,
    osName: device.osName,
    osVersion: device.osVersion,
    firmwareVersion: device.firmwareVer,
    openPorts: device.openPorts,
    services: device.services,
  };

  return (
    <div className="animate-fade-in">
      <div className="max-w-2xl mx-auto">
        <DeviceForm action="Edit" device={deviceData} />
      </div>
    </div>
  );
}
