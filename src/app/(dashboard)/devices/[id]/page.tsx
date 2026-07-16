export const dynamic = 'force-dynamic';

import Link from "next/link";
import { notFound } from "next/navigation";
import { prisma } from "@/lib/prisma";
import { formatDateTime, formatTimestamp } from "@/lib/utils";
import { PageHeader } from "@/components/shared/page-header";
import { Card, CardHeader, CardTitle, CardContent } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import {
  Table,
  TableHeader,
  TableBody,
  TableRow,
  TableHead,
  TableCell,
} from "@/components/ui/table";
import { Edit, Monitor, Globe, Shield, Cpu, Wifi, FileText } from "lucide-react";
import { cn } from "@/lib/utils";

export default async function DeviceDetailPage(props: { params: Promise<{ id: string }> }) {
  const { id } = await props.params;
  const deviceId = parseInt(id, 10);
  if (isNaN(deviceId)) notFound();

  const device = await prisma.device.findUnique({
    where: { deviceId },
    include: {
      scanResults: {
        orderBy: { createdAt: "desc" },
        take: 20,
      },
      riskAssessments: {
        orderBy: { createdAt: "desc" },
        take: 1,
      },
    },
  });

  if (!device) notFound();

  const latestRisk = device.riskAssessments[0] ?? null;

  const ports = (() => {
    try {
      return device.openPorts
        ? device.openPorts.split(",").map((p) => p.trim()).filter(Boolean)
        : [];
    } catch { return []; }
  })();

  const servicesMap = (() => {
    try {
      return device.services ? JSON.parse(device.services) as Record<string, string> : {};
    } catch { return {}; }
  })();

  return (
    <div className="animate-fade-in space-y-6">
      <PageHeader
        title={device.hostname ?? device.ipAddress}
        description={`Device details and assessment`}
        actions={
          <div className="flex items-center gap-2">
            <Button variant="default" asChild>
              <Link href={`/devices/${id}/report`}>
                <FileText className="h-4 w-4" />
                Generate Report
              </Link>
            </Button>
            <Button variant="outline" asChild>
              <Link href={`/devices/${id}/edit`}>
                <Edit className="h-4 w-4" />
                Edit
              </Link>
            </Button>
          </div>
        }
      />

      <div className="grid gap-6 lg:grid-cols-3">
        <Card className="lg:col-span-2 animate-slide-up">
          <CardHeader>
            <div className="flex items-center gap-2">
              <Monitor className="h-5 w-5 text-violet-500" />
              <CardTitle>Device Information</CardTitle>
            </div>
          </CardHeader>
          <CardContent>
            <div className="grid grid-cols-2 gap-4 text-sm">
              <div>
                <p className="text-zinc-500 dark:text-zinc-400">MAC Address</p>
                <p className="font-mono text-zinc-900 dark:text-zinc-50">{device.macAddress}</p>
              </div>
              <div>
                <p className="text-zinc-500 dark:text-zinc-400">IP Address</p>
                <p className="font-mono text-zinc-900 dark:text-zinc-50">{device.ipAddress}</p>
              </div>
              <div>
                <p className="text-zinc-500 dark:text-zinc-400">Hostname</p>
                <p className="text-zinc-900 dark:text-zinc-50">{device.hostname ?? "—"}</p>
              </div>
              <div>
                <p className="text-zinc-500 dark:text-zinc-400">Vendor</p>
                <p className="text-zinc-900 dark:text-zinc-50">{device.vendor ?? "—"}</p>
              </div>
              <div>
                <p className="text-zinc-500 dark:text-zinc-400">Device Type</p>
                <p className="text-zinc-900 dark:text-zinc-50">{device.deviceType ?? "—"}</p>
              </div>
              <div>
                <p className="text-zinc-500 dark:text-zinc-400">Status</p>
                <Badge variant={device.isActive === "Y" ? "success" : "default"}>
                  {device.isActive === "Y" ? "Active" : "Inactive"}
                </Badge>
              </div>
              <div>
                <p className="text-zinc-500 dark:text-zinc-400">Operating System</p>
                <p className="text-zinc-900 dark:text-zinc-50">
                  {device.osName ? `${device.osName} ${device.osVersion ?? ""}` : "—"}
                </p>
              </div>
              <div>
                <p className="text-zinc-500 dark:text-zinc-400">Firmware Version</p>
                <p className="text-zinc-900 dark:text-zinc-50">{device.firmwareVer ?? "—"}</p>
              </div>
              <div>
                <p className="text-zinc-500 dark:text-zinc-400">First Seen</p>
                <p className="text-zinc-900 dark:text-zinc-50">{formatTimestamp(device.firstSeen)}</p>
              </div>
              <div>
                <p className="text-zinc-500 dark:text-zinc-400">Last Seen</p>
                <p className="text-zinc-900 dark:text-zinc-50">{formatTimestamp(device.lastSeen)}</p>
              </div>
            </div>
          </CardContent>
        </Card>

        <Card className="animate-slide-up" style={{ animationDelay: "0.1s" }}>
          <CardHeader>
            <div className="flex items-center gap-2">
              <Shield className="h-5 w-5 text-violet-500" />
              <CardTitle>Risk Score</CardTitle>
            </div>
          </CardHeader>
          <CardContent>
            {latestRisk ? (
              <div className="space-y-4">
                <div className="text-center">
                  <span className={cn(
                    "text-5xl font-bold",
                    latestRisk.compositeScore >= 8 ? "text-red-400" :
                    latestRisk.compositeScore >= 6 ? "text-amber-400" :
                    latestRisk.compositeScore >= 3 ? "text-blue-400" :
                    "text-emerald-400"
                  )}>
                    {latestRisk.compositeScore.toFixed(1)}
                  </span>
                  <p className="text-sm text-zinc-500 mt-1">/ 10</p>
                </div>
                <div className="space-y-2 text-sm">
                  <div className="flex justify-between">
                    <span className="text-zinc-500">CVE Score</span>
                    <span className="font-medium">{latestRisk.cveScore.toFixed(1)}</span>
                  </div>
                  <div className="flex justify-between">
                    <span className="text-zinc-500">Exposure</span>
                    <span className="font-medium">{latestRisk.exposureScore.toFixed(1)}</span>
                  </div>
                  <div className="flex justify-between">
                    <span className="text-zinc-500">Credentials</span>
                    <span className="font-medium">{latestRisk.credentialScore.toFixed(1)}</span>
                  </div>
                  <div className="flex justify-between">
                    <span className="text-zinc-500">Network</span>
                    <span className="font-medium">{latestRisk.networkScore.toFixed(1)}</span>
                  </div>
                </div>
                {latestRisk.recommendation && (
                  <div className="rounded-lg bg-zinc-100 dark:bg-zinc-800 px-3 py-2 text-xs text-zinc-700 dark:text-zinc-300">
                    {latestRisk.recommendation}
                  </div>
                )}
              </div>
            ) : (
              <p className="text-sm text-zinc-500 text-center py-6">No risk assessment yet.</p>
            )}
          </CardContent>
        </Card>
      </div>

      {ports.length > 0 && (
        <Card className="animate-slide-up" style={{ animationDelay: "0.2s" }}>
          <CardHeader>
            <div className="flex items-center gap-2">
              <Globe className="h-5 w-5 text-violet-500" />
              <CardTitle>Open Ports &amp; Services</CardTitle>
            </div>
          </CardHeader>
          <CardContent>
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Port</TableHead>
                  <TableHead>Service</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {ports.map((port, i) => {
                  const svc = servicesMap[port] || "—";
                  return (
                    <TableRow key={i}>
                      <TableCell className="font-mono">{port}</TableCell>
                      <TableCell>{svc}</TableCell>
                    </TableRow>
                  );
                })}
              </TableBody>
            </Table>
          </CardContent>
        </Card>
      )}

      {device.scanResults.length > 0 && (
        <Card className="animate-slide-up" style={{ animationDelay: "0.3s" }}>
          <CardHeader>
            <div className="flex items-center gap-2">
              <Wifi className="h-5 w-5 text-violet-500" />
              <CardTitle>Recent Scan Results</CardTitle>
            </div>
          </CardHeader>
          <CardContent>
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Port</TableHead>
                  <TableHead>Protocol</TableHead>
                  <TableHead>Service</TableHead>
                  <TableHead>Risk Level</TableHead>
                  <TableHead>Detected</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {device.scanResults.map((r) => (
                  <TableRow key={r.resultId}>
                    <TableCell className="font-mono">{r.port ?? "—"}</TableCell>
                    <TableCell>{r.protocol ?? "—"}</TableCell>
                    <TableCell>{r.service ?? "—"}</TableCell>
                    <TableCell>
                      <Badge variant={
                        r.riskLevel === "critical" ? "destructive" :
                        r.riskLevel === "high" ? "warning" :
                        r.riskLevel === "medium" ? "info" : "default"
                      }>
                        {r.riskLevel ?? "—"}
                      </Badge>
                    </TableCell>
                    <TableCell className="text-xs">{formatDateTime(r.createdAt)}</TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </CardContent>
        </Card>
      )}
    </div>
  );
}
