import { redirect } from "next/navigation";
import { getCurrentUser } from "@/lib/auth";
import { DeviceForm } from "@/components/devices/device-form";

export default async function NewDevicePage() {
  const user = await getCurrentUser();
  if (!user) redirect("/login");

  return (
    <div className="animate-fade-in">
      <div className="max-w-2xl mx-auto">
        <DeviceForm action="Create" />
      </div>
    </div>
  );
}
