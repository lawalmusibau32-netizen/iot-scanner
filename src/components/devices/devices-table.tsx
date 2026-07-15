import Link from "next/link"
import { cn } from "@/lib/utils"
import {
  Table,
  TableHeader,
  TableBody,
  TableRow,
  TableHead,
  TableCell,
} from "@/components/ui/table"
import { Badge } from "@/components/ui/badge"
import { Button } from "@/components/ui/button"

interface Device {
  id: string
  macAddress: string
  ipAddress: string
  hostname?: string | null
  vendor?: string | null
  deviceType?: string | null
  status?: string | null
  riskScore?: number | null
}

interface DevicesTableProps {
  devices: Device[]
}

function riskColor(score: number | null | undefined) {
  if (score == null) return "text-zinc-400 dark:text-zinc-500"
  if (score >= 70) return "text-red-600 dark:text-red-400"
  if (score >= 40) return "text-amber-600 dark:text-amber-400"
  return "text-emerald-600 dark:text-emerald-400"
}

export function DevicesTable({ devices }: DevicesTableProps) {
  return (
    <Table>
      <TableHeader>
        <TableRow>
          <TableHead>MAC</TableHead>
          <TableHead>IP</TableHead>
          <TableHead>Hostname</TableHead>
          <TableHead>Vendor</TableHead>
          <TableHead>Type</TableHead>
          <TableHead>Status</TableHead>
          <TableHead>Risk Score</TableHead>
          <TableHead>Actions</TableHead>
        </TableRow>
      </TableHeader>
      <TableBody>
        {devices.length === 0 && (
          <TableRow>
            <TableCell colSpan={8} className="py-12 text-center text-sm text-zinc-400 dark:text-zinc-500">
              No devices found.
            </TableCell>
          </TableRow>
        )}
        {devices.map((device) => (
          <TableRow key={device.id}>
            <TableCell className="font-mono text-xs">{device.macAddress}</TableCell>
            <TableCell className="font-mono text-xs">{device.ipAddress}</TableCell>
            <TableCell className="font-medium">{device.hostname ?? "—"}</TableCell>
            <TableCell>{device.vendor ?? "—"}</TableCell>
            <TableCell>{device.deviceType ?? "—"}</TableCell>
            <TableCell>
              <Badge variant={device.status === "Active" ? "success" : "default"}>
                {device.status ?? "Unknown"}
              </Badge>
            </TableCell>
            <TableCell>
              <span className={cn("font-semibold", riskColor(device.riskScore))}>
                {device.riskScore != null ? `${device.riskScore}%` : "—"}
              </span>
            </TableCell>
            <TableCell>
              <Button variant="outline" size="sm" asChild>
                <Link href={`/devices/${device.id}`}>View</Link>
              </Button>
            </TableCell>
          </TableRow>
        ))}
      </TableBody>
    </Table>
  )
}
