export const dynamic = 'force-dynamic';

import Link from "next/link";
import { prisma } from "@/lib/prisma";
import { cn, formatDateTime } from "@/lib/utils";
import { PageHeader } from "@/components/shared/page-header";
import { StatsCard } from "@/components/shared/stats-card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent } from "@/components/ui/card";
import {
  Table,
  TableHeader,
  TableBody,
  TableRow,
  TableHead,
  TableCell,
} from "@/components/ui/table";
import { NewScanButton } from "@/components/scans/new-scan-button";
import { Eye } from "lucide-react";

function statusBadge(status: string) {
  switch (status) {
    case "completed": return <Badge variant="success">Completed</Badge>;
    case "running": return <Badge variant="info">Running</Badge>;
    case "failed": return <Badge variant="destructive">Failed</Badge>;
    default: return <Badge variant="default">Pending</Badge>;
  }
}

function typeBadge(type: string) {
  switch (type) {
    case "full": return <Badge variant="info">Full</Badge>;
    case "quick": return <Badge variant="default">Quick</Badge>;
    case "targeted": return <Badge variant="warning">Targeted</Badge>;
    default: return <Badge variant="outline">{type}</Badge>;
  }
}

export default async function ScansPage() {
  const [scans, total, completed, failed] = await Promise.all([
    prisma.scanJob.findMany({
      orderBy: { createdAt: "desc" },
    }),
    prisma.scanJob.count(),
    prisma.scanJob.count({ where: { status: "completed" } }),
    prisma.scanJob.count({ where: { status: "failed" } }),
  ]);

  const totalDevices = scans.reduce((sum, s) => sum + s.deviceCount, 0);

  return (
    <div className="animate-fade-in space-y-6">
      <PageHeader
        title="Scan History"
        description="Past and current network scans"
        actions={<NewScanButton />}
      />

      <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-4">
        <div className="animate-slide-up">
          <StatsCard label="Total Scans" value={total} tone="info" />
        </div>
        <div className="animate-slide-up" style={{ animationDelay: "0.1s" }}>
          <StatsCard label="Completed" value={completed} tone="success" />
        </div>
        <div className="animate-slide-up" style={{ animationDelay: "0.2s" }}>
          <StatsCard label="Failed" value={failed} tone={failed > 0 ? "warning" : "default"} />
        </div>
        <div className="animate-slide-up" style={{ animationDelay: "0.3s" }}>
          <StatsCard label="Devices Found" value={totalDevices} tone="primary" />
        </div>
      </div>

      <Card className="animate-slide-up" style={{ animationDelay: "0.2s" }}>
        <CardContent className="p-0">
          {scans.length === 0 ? (
            <div className="py-16 text-center text-sm text-zinc-500 dark:text-zinc-400">
              No scans have been run yet.
            </div>
          ) : (
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Scan ID</TableHead>
                  <TableHead>Type</TableHead>
                  <TableHead>Status</TableHead>
                  <TableHead>Devices Found</TableHead>
                  <TableHead>Progress</TableHead>
                  <TableHead>Started</TableHead>
                  <TableHead>Completed</TableHead>
                  <TableHead>Actions</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {scans.map((s) => (
                  <TableRow key={s.scanId}>
                    <TableCell className="font-mono text-xs">#{s.scanId}</TableCell>
                    <TableCell>{typeBadge(s.scanType)}</TableCell>
                    <TableCell>{statusBadge(s.status)}</TableCell>
                    <TableCell>{s.deviceCount}</TableCell>
                    <TableCell>
                      <div className="flex items-center gap-2">
                        <div className="h-2 w-24 rounded-full bg-zinc-200 dark:bg-zinc-700 overflow-hidden">
                          <div
                            className={cn(
                              "h-full rounded-full transition-all",
                              s.status === "failed" ? "bg-red-500" :
                              s.progress === 100 ? "bg-emerald-500" : "bg-violet-500"
                            )}
                            style={{ width: `${s.progress}%` }}
                          />
                        </div>
                        <span className="text-xs text-zinc-500">{s.progress}%</span>
                      </div>
                    </TableCell>
                    <TableCell className="text-xs text-zinc-500">
                      {s.startedAt ? formatDateTime(s.startedAt) : "—"}
                    </TableCell>
                    <TableCell className="text-xs text-zinc-500">
                      {s.completedAt ? formatDateTime(s.completedAt) : "—"}
                    </TableCell>
                    <TableCell>
                      <Button variant="outline" size="sm" asChild>
                        <Link href={`/scans/${s.scanId}`}>
                          <Eye className="h-3.5 w-3.5" />
                          View
                        </Link>
                      </Button>
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          )}
        </CardContent>
      </Card>
    </div>
  );
}


