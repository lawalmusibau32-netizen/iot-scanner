export const dynamic = 'force-dynamic';

import Link from "next/link";
import { notFound } from "next/navigation";
import { prisma } from "@/lib/prisma";
import { formatDateTime } from "@/lib/utils";
import { PageHeader } from "@/components/shared/page-header";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Edit, Monitor, Globe, Shield, FileText, Bug, Wifi, Clock, Server, Cpu, Network, AlertTriangle } from "lucide-react";
import { cn } from "@/lib/utils";

function scoreColor(score: number) {
  return score >= 8 ? "text-red-400" : score >= 6 ? "text-amber-400" : score >= 3 ? "text-blue-400" : "text-emerald-400";
}

function scoreBg(score: number) {
  return score >= 8 ? "bg-red-500/10" : score >= 6 ? "bg-amber-500/10" : score >= 3 ? "bg-blue-500/10" : "bg-emerald-500/10";
}

function severityLabel(score: number) {
  return score >= 8 ? "Critical" : score >= 6 ? "High" : score >= 3 ? "Medium" : "Low";
}

export default async function DeviceDetailPage(props: { params: Promise<{ id: string }> }) {
  const { id } = await props.params;
  const deviceId = parseInt(id, 10);
  if (isNaN(deviceId)) notFound();

  const device = await prisma.device.findUnique({
    where: { deviceId },
    include: {
      scanResults: { orderBy: { createdAt: "desc" }, take: 20 },
      riskAssessments: { orderBy: { createdAt: "desc" }, take: 1 },
    },
  });

  if (!device) notFound();

  const latestRisk = device.riskAssessments[0] ?? null;

  const ports = (() => {
    try { return device.openPorts ? device.openPorts.split(",").map(p => p.trim()).filter(Boolean) : []; }
    catch { return []; }
  })();

  const servicesMap = (() => {
    try { return device.services ? JSON.parse(device.services) as Record<string, string> : {}; }
    catch { return {}; }
  })();

  const criticalCount = device.scanResults.filter(r => r.riskLevel?.toLowerCase() === "critical").length;
  const highCount = device.scanResults.filter(r => r.riskLevel?.toLowerCase() === "high").length;
  const mediumCount = device.scanResults.filter(r => r.riskLevel?.toLowerCase() === "medium").length;

  const riskyPorts = ports.filter(p => ["23", "21", "445", "3389"].includes(p));

  return (
    <div className="space-y-6 pb-12">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div>
          <h1 className="text-2xl font-bold text-foreground flex items-center gap-2">
            {device.hostname ?? device.ipAddress}
            <Badge variant={device.isActive === "Y" ? "success" : "default"} className="text-[10px]">
              {device.isActive === "Y" ? "Active" : "Inactive"}
            </Badge>
          </h1>
          <p className="text-sm text-muted-foreground mt-0.5">{device.deviceType ?? "Device"} · {device.vendor ?? "Unknown vendor"}</p>
        </div>
        <div className="flex items-center gap-2">
          <Button asChild className="gap-1.5">
            <Link href={`/devices/${id}/report`}>
              <FileText className="h-4 w-4" />
              Generate Report
            </Link>
          </Button>
          <Button variant="outline" asChild className="gap-1.5">
            <Link href={`/devices/${id}/edit`}>
              <Edit className="h-4 w-4" />
              Edit
            </Link>
          </Button>
        </div>
      </div>

      {/* Summary cards */}
      <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
        {[
          { icon: Shield, label: "Risk Score", value: latestRisk ? `${latestRisk.compositeScore.toFixed(1)}/10` : "—", color: latestRisk ? scoreColor(latestRisk.compositeScore) : "text-muted-foreground", bg: latestRisk ? scoreBg(latestRisk.compositeScore) : "bg-muted" },
          { icon: Bug, label: "Findings", value: device.scanResults.length, color: criticalCount > 0 ? "text-red-400" : highCount > 0 ? "text-amber-400" : "text-primary" },
          { icon: Globe, label: "Open Ports", value: ports.length, color: riskyPorts.length > 0 ? "text-red-400" : "text-primary" },
          { icon: Wifi, label: "Last Scanned", value: device.lastSeen ? formatDateTime(device.lastSeen).split(",")[0] : "Never", color: "text-primary" },
        ].map((s, i) => (
          <Card key={i} className="animate-slide-up" style={{ animationDelay: `${i * 0.08}s` }}>
            <CardContent className="p-5">
              <div className="flex items-center gap-3">
                <div className={`p-2.5 rounded-xl ${s.bg || "bg-primary/10"}`}>
                  <s.icon className={`h-5 w-5 ${s.color}`} />
                </div>
                <div>
                  <p className={`text-2xl font-bold ${s.color}`}>{s.value}</p>
                  <p className="text-xs text-muted-foreground">{s.label}</p>
                </div>
              </div>
            </CardContent>
          </Card>
        ))}
      </div>

      <div className="grid gap-6 lg:grid-cols-3">
        {/* Device info */}
        <Card className="lg:col-span-2 animate-slide-up glass-card">
          <CardHeader>
            <CardTitle className="flex items-center gap-2 text-sm">
              <Monitor className="h-4 w-4 text-primary" />
              Device Information
            </CardTitle>
          </CardHeader>
          <CardContent>
            <div className="grid grid-cols-2 gap-x-8 gap-y-4 text-sm">
              {[
                { icon: Globe, label: "IP Address", value: device.ipAddress, mono: true },
                { icon: Wifi, label: "MAC Address", value: device.macAddress, mono: true },
                { icon: Server, label: "Hostname", value: device.hostname },
                { icon: Cpu, label: "Vendor", value: device.vendor },
                { icon: Monitor, label: "Device Type", value: device.deviceType },
                { icon: Cpu, label: "Operating System", value: device.osName ? `${device.osName} ${device.osVersion ?? ""}`.trim() : "—" },
                { icon: Shield, label: "Firmware", value: device.firmwareVer },
                { icon: Clock, label: "First Seen", value: formatDateTime(device.firstSeen) },
              ].map((f, i) => (
                <div key={i} className="space-y-0.5">
                  <p className="text-xs text-muted-foreground flex items-center gap-1">
                    <f.icon className="h-3 w-3" /> {f.label}
                  </p>
                  <p className={`font-medium text-foreground ${f.mono ? "font-mono text-xs" : ""}`}>{f.value || "—"}</p>
                </div>
              ))}
            </div>
          </CardContent>
        </Card>

        {/* Risk card */}
        <Card className="animate-slide-up glass-card" style={{ animationDelay: "0.1s" }}>
          <CardHeader>
            <CardTitle className="flex items-center gap-2 text-sm">
              <Shield className="h-4 w-4 text-primary" />
              Risk Assessment
            </CardTitle>
          </CardHeader>
          <CardContent>
            {latestRisk ? (
              <div className="space-y-5">
                <div className="text-center py-2">
                  <div className={`inline-flex items-center justify-center w-20 h-20 rounded-full ${scoreBg(latestRisk.compositeScore)} border-4 ${scoreColor(latestRisk.compositeScore).replace("text", "border")}/30`}>
                    <span className={`text-3xl font-black ${scoreColor(latestRisk.compositeScore)}`}>{latestRisk.compositeScore.toFixed(1)}</span>
                  </div>
                  <div className="flex items-center justify-center gap-1 mt-3">
                    <Badge variant={
                      latestRisk.compositeScore >= 8 ? "destructive" :
                      latestRisk.compositeScore >= 6 ? "warning" :
                      latestRisk.compositeScore >= 3 ? "info" : "default"
                    }>{severityLabel(latestRisk.compositeScore)}</Badge>
                  </div>
                </div>

                <div className="space-y-3">
                  {[
                    { label: "CVE Score", value: latestRisk.cveScore },
                    { label: "Exposure", value: latestRisk.exposureScore },
                    { label: "Credentials", value: latestRisk.credentialScore },
                    { label: "Network", value: latestRisk.networkScore },
                  ].map((s, i) => (
                    <div key={i} className="space-y-1">
                      <div className="flex justify-between text-xs">
                        <span className="text-muted-foreground">{s.label}</span>
                        <span className="font-medium text-foreground">{s.value.toFixed(1)}</span>
                      </div>
                      <div className="h-1.5 rounded-full bg-zinc-200 dark:bg-zinc-700 overflow-hidden">
                        <div className="h-full rounded-full transition-all" style={{
                          width: `${Math.min(100, s.value * 10)}%`,
                          background: s.value >= 8 ? "oklch(0.58 0.22 25)" : s.value >= 6 ? "oklch(0.7 0.2 75)" : "oklch(0.55 0.26 265)",
                        }} />
                      </div>
                    </div>
                  ))}
                </div>

                {latestRisk.recommendation && (
                  <div className="rounded-xl bg-amber-500/5 border border-amber-500/20 p-3 text-xs text-muted-foreground leading-relaxed">
                    <p className="font-medium text-amber-600 dark:text-amber-400 mb-0.5">Recommendation</p>
                    {latestRisk.recommendation}
                  </div>
                )}
              </div>
            ) : (
              <div className="py-10 text-center">
                <Shield className="h-8 w-8 text-muted-foreground/30 mx-auto mb-2" />
                <p className="text-sm text-muted-foreground">No assessment yet</p>
              </div>
            )}
          </CardContent>
        </Card>
      </div>

      {/* Open Ports */}
      {ports.length > 0 && (
        <Card className="animate-slide-up glass-card">
          <CardHeader>
            <CardTitle className="flex items-center gap-2 text-sm">
              <Globe className="h-4 w-4 text-primary" />
              Open Ports & Services ({ports.length})
            </CardTitle>
          </CardHeader>
          <CardContent>
            <div className="flex flex-wrap gap-2">
              {ports.map((port, i) => {
                const svc = servicesMap[port] || "?";
                const isRisky = ["23", "21", "445", "3389"].includes(port);
                return (
                  <div key={i} className={`inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-mono border ${isRisky ? "border-red-500/30 bg-red-500/10 text-red-400" : "border-zinc-200 dark:border-zinc-700 bg-zinc-50 dark:bg-zinc-800/50 text-muted-foreground"}`}>
                    <span className={`w-1.5 h-1.5 rounded-full ${isRisky ? "bg-red-400 animate-pulse" : "bg-zinc-300 dark:bg-zinc-600"}`} />
                    {port}/{svc}
                    {isRisky && <AlertTriangle className="h-3 w-3 ml-0.5" />}
                  </div>
                );
              })}
            </div>
          </CardContent>
        </Card>
      )}

      {/* Scan Results */}
      {device.scanResults.length > 0 && (
        <Card className="animate-slide-up glass-card">
          <CardHeader>
            <CardTitle className="flex items-center gap-2 text-sm">
              <Bug className="h-4 w-4 text-primary" />
              Scan Results ({device.scanResults.length})
            </CardTitle>
          </CardHeader>
          <CardContent className="p-0">
            <div className="divide-y divide-border">
              {device.scanResults.map((r) => (
                <div key={r.resultId} className="flex items-center gap-3 px-6 py-3 text-sm">
                  <Badge variant={
                    r.riskLevel?.toLowerCase() === "critical" ? "destructive" :
                    r.riskLevel?.toLowerCase() === "high" ? "warning" :
                    r.riskLevel?.toLowerCase() === "medium" ? "info" : "default"
                  } className="shrink-0 text-[10px]">{r.riskLevel ?? "—"}</Badge>
                  <span className="font-mono text-xs text-muted-foreground shrink-0">{r.port ? `:${r.port}` : "—"}</span>
                  <span className="text-xs text-muted-foreground shrink-0">{r.service ?? "—"}</span>
                  <span className="text-xs text-muted-foreground/70 truncate">{r.detail ?? ""}</span>
                  <span className="text-[10px] text-muted-foreground/40 ml-auto shrink-0">{formatDateTime(r.createdAt)}</span>
                </div>
              ))}
            </div>
          </CardContent>
        </Card>
      )}
    </div>
  );
}
