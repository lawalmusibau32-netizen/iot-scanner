export const dynamic = 'force-dynamic';

import { prisma } from "@/lib/prisma";
import { formatDateTime, cn } from "@/lib/utils";
import { Card, CardHeader, CardTitle, CardContent } from "@/components/ui/card";
import { PageHeader } from "@/components/shared/page-header";
import { StatsCard } from "@/components/shared/stats-card";
import { Badge } from "@/components/ui/badge";
import {
  Table,
  TableHeader,
  TableBody,
  TableRow,
  TableHead,
  TableCell,
} from "@/components/ui/table";
import { ScanNowButton } from "@/components/dashboard/scan-now-button";
import { Shield, Wifi, Activity, AlertTriangle } from "lucide-react";

export default async function DashboardPage() {
  const [
    deviceCount,
    vulnCount,
    completedScans,
    criticalAssessments,
    recentAssessments,
    recentNotifications,
  ] = await Promise.all([
    prisma.device.count({ where: { isActive: "Y" } }),
    prisma.vulnerability.count(),
    prisma.scanJob.count({ where: { status: "completed" } }),
    prisma.riskAssessment.count({ where: { compositeScore: { gte: 8 } } }),
    prisma.riskAssessment.findMany({
      take: 3,
      orderBy: { createdAt: "desc" },
      include: {
        device: { select: { hostname: true, ipAddress: true } },
      },
    }),
    prisma.notification.findMany({
      take: 5,
      orderBy: { sentAt: "desc" },
    }),
  ]);

  const severityBadge = (severity: string | null) => {
    switch (severity?.toLowerCase()) {
      case "critical": return <Badge variant="destructive">Critical</Badge>;
      case "high": return <Badge variant="warning">High</Badge>;
      case "medium": return <Badge variant="info">Medium</Badge>;
      case "low": return <Badge variant="default">Low</Badge>;
      default: return <Badge variant="outline">{severity ?? "—"}</Badge>;
    }
  };

  return (
    <div className="animate-fade-in space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-3xl font-bold tracking-tight">
            <span className="text-gradient">Dashboard</span>
          </h1>
          <p className="text-sm text-zinc-500 dark:text-zinc-400 mt-1">
            Overview of your IoT network security posture
          </p>
        </div>
        <ScanNowButton />
      </div>

      <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-4">
        <div className="animate-slide-up">
          <StatsCard label="Total Devices" value={deviceCount} tone="info" />
        </div>
        <div className="animate-slide-up" style={{ animationDelay: "0.1s" }}>
          <StatsCard label="Vulnerabilities" value={vulnCount} tone={vulnCount > 0 ? "warning" : "success"} />
        </div>
        <div className="animate-slide-up" style={{ animationDelay: "0.2s" }}>
          <StatsCard label="Scans Completed" value={completedScans} tone="success" />
        </div>
        <div className="animate-slide-up" style={{ animationDelay: "0.3s" }}>
          <StatsCard
            label="Critical Risks"
            value={criticalAssessments}
            tone={criticalAssessments > 0 ? "warning" : "success"}
          />
        </div>
      </div>

      <div className="grid gap-6 lg:grid-cols-2">
        <Card className="animate-slide-up" style={{ animationDelay: "0.2s" }}>
          <CardHeader>
            <div className="flex items-center gap-2">
              <Shield className="h-5 w-5 text-violet-500" />
              <CardTitle>Recent Risk Assessments</CardTitle>
            </div>
          </CardHeader>
          <CardContent>
            {recentAssessments.length === 0 ? (
              <p className="text-sm text-zinc-500 dark:text-zinc-400 py-6 text-center">
                No risk assessments yet.
              </p>
            ) : (
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead>Device</TableHead>
                    <TableHead>Score</TableHead>
                    <TableHead>Severity</TableHead>
                    <TableHead>Date</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {recentAssessments.map((a) => (
                    <TableRow key={a.assessmentId}>
                      <TableCell className="font-medium">
                        {a.device.hostname ?? a.device.ipAddress}
                      </TableCell>
                      <TableCell>
                        <span className={cn(
                          "font-semibold",
                          a.compositeScore >= 8 ? "text-red-400" :
                          a.compositeScore >= 6 ? "text-amber-400" :
                          a.compositeScore >= 3 ? "text-blue-400" :
                          "text-emerald-400"
                        )}>
                          {a.compositeScore.toFixed(1)}
                        </span>
                      </TableCell>
                      <TableCell>{severityBadge(
                        a.compositeScore >= 8 ? "Critical" :
                        a.compositeScore >= 6 ? "High" :
                        a.compositeScore >= 3 ? "Medium" : "Low"
                      )}</TableCell>
                      <TableCell className="text-xs text-zinc-500">
                        {formatDateTime(a.createdAt)}
                      </TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            )}
          </CardContent>
        </Card>

        <Card className="animate-slide-up" style={{ animationDelay: "0.3s" }}>
          <CardHeader>
            <div className="flex items-center gap-2">
              <AlertTriangle className="h-5 w-5 text-amber-500" />
              <CardTitle>Recent Alerts</CardTitle>
            </div>
          </CardHeader>
          <CardContent className="space-y-3">
            {recentNotifications.length === 0 ? (
              <p className="text-sm text-zinc-500 dark:text-zinc-400 py-6 text-center">
                No alerts yet.
              </p>
            ) : (
              recentNotifications.map((n) => (
                <div
                  key={n.notifId}
                  className="flex items-start gap-3 rounded-lg border border-zinc-200 dark:border-zinc-800 p-3"
                >
                  <div className="mt-0.5">
                    {severityBadge(n.severity)}
                  </div>
                  <div className="flex-1 min-w-0">
                    <p className="text-sm text-zinc-800 dark:text-zinc-200 truncate">
                      {n.message}
                    </p>
                    <p className="text-xs text-zinc-500 mt-1">
                      {formatDateTime(n.sentAt)}
                    </p>
                  </div>
                  {n.isRead === "N" && (
                    <span className="h-2 w-2 rounded-full bg-violet-500 shrink-0 mt-2" />
                  )}
                </div>
              ))
            )}
          </CardContent>
        </Card>
      </div>
    </div>
  );
}
