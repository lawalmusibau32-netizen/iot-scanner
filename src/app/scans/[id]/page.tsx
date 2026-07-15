import { notFound } from "next/navigation";
import { prisma } from "@/lib/prisma";
import { formatDateTime, cn } from "@/lib/utils";
import { PageHeader } from "@/components/shared/page-header";
import { Card, CardHeader, CardTitle, CardContent } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import {
  Table,
  TableHeader,
  TableBody,
  TableRow,
  TableHead,
  TableCell,
} from "@/components/ui/table";
import { Scan, Wifi, AlertTriangle, Clock } from "lucide-react";

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

export default async function ScanDetailPage(props: { params: Promise<{ id: string }> }) {
  const { id } = await props.params;
  const scanId = parseInt(id, 10);
  if (isNaN(scanId)) notFound();

  const scan = await prisma.scanJob.findUnique({
    where: { scanId },
    include: {
      scanResults: {
        include: {
          device: { select: { hostname: true, ipAddress: true, macAddress: true } },
          vulnerability: { select: { cveId: true, cvssScore: true, severity: true } },
        },
        orderBy: { createdAt: "desc" },
      },
      riskAssessments: {
        include: {
          device: { select: { hostname: true, ipAddress: true } },
        },
        orderBy: { compositeScore: "desc" },
      },
      user: { select: { username: true, displayName: true } },
    },
  });

  if (!scan) notFound();

  const deviceCount = new Set(scan.scanResults.map((r) => r.deviceId)).size;
  const criticalFindings = scan.riskAssessments.filter((r) => r.compositeScore >= 8).length;
  const highFindings = scan.riskAssessments.filter((r) => r.compositeScore >= 6 && r.compositeScore < 8).length;

  return (
    <div className="animate-fade-in space-y-6">
      <PageHeader
        title={`Scan #${scan.scanId}`}
        description={scan.scanType === "full" ? "Full network scan" : `${scan.scanType} scan`}
      />

      <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-4">
        <Card>
          <CardContent className="pt-6">
            <div className="flex items-center gap-3">
              <Wifi className="h-5 w-5 text-violet-500" />
              <div>
                <p className="text-xs font-medium uppercase tracking-wider text-zinc-500">Devices Found</p>
                <p className="text-2xl font-bold text-zinc-900 dark:text-zinc-50">{scan.deviceCount}</p>
              </div>
            </div>
          </CardContent>
        </Card>
        <Card>
          <CardContent className="pt-6">
            <div className="flex items-center gap-3">
              <Scan className="h-5 w-5 text-violet-500" />
              <div>
                <p className="text-xs font-medium uppercase tracking-wider text-zinc-500">Status</p>
                <div className="mt-1">{statusBadge(scan.status)}</div>
              </div>
            </div>
          </CardContent>
        </Card>
        <Card>
          <CardContent className="pt-6">
            <div className="flex items-center gap-3">
              <AlertTriangle className="h-5 w-5 text-amber-500" />
              <div>
                <p className="text-xs font-medium uppercase tracking-wider text-zinc-500">Critical / High</p>
                <p className="text-2xl font-bold text-zinc-900 dark:text-zinc-50">
                  {criticalFindings}<span className="text-sm font-normal text-zinc-400"> / {highFindings}</span>
                </p>
              </div>
            </div>
          </CardContent>
        </Card>
        <Card>
          <CardContent className="pt-6">
            <div className="flex items-center gap-3">
              <Clock className="h-5 w-5 text-violet-500" />
              <div>
                <p className="text-xs font-medium uppercase tracking-wider text-zinc-500">Duration</p>
                <p className="text-2xl font-bold text-zinc-900 dark:text-zinc-50">
                  {scan.startedAt && scan.completedAt
                    ? `${Math.round((scan.completedAt.getTime() - scan.startedAt.getTime()) / 1000)}s`
                    : "—"}
                </p>
              </div>
            </div>
          </CardContent>
        </Card>
      </div>

      <Card>
        <CardHeader>
          <div className="flex items-center gap-2">
            <Scan className="h-5 w-5 text-violet-500" />
            <CardTitle>Scan Details</CardTitle>
          </div>
        </CardHeader>
        <CardContent>
          <div className="grid grid-cols-2 md:grid-cols-3 gap-4 text-sm">
            <div>
              <p className="text-zinc-500">Scan Type</p>
              <p className="font-medium">{typeBadge(scan.scanType)}</p>
            </div>
            <div>
              <p className="text-zinc-500">Triggered By</p>
              <p className="font-medium">{scan.user?.displayName ?? scan.user?.username ?? "—"}</p>
            </div>
            <div>
              <p className="text-zinc-500">Progress</p>
              <div className="flex items-center gap-2 mt-1">
                <div className="h-2 w-24 rounded-full bg-zinc-200 dark:bg-zinc-700 overflow-hidden">
                  <div
                    className={cn(
                      "h-full rounded-full transition-all",
                      scan.status === "failed" ? "bg-red-500" :
                      scan.progress === 100 ? "bg-emerald-500" : "bg-violet-500"
                    )}
                    style={{ width: `${scan.progress}%` }}
                  />
                </div>
                <span className="text-xs text-zinc-500">{scan.progress}%</span>
              </div>
            </div>
            <div>
              <p className="text-zinc-500">Started</p>
              <p className="font-medium text-zinc-900 dark:text-zinc-50">
                {scan.startedAt ? formatDateTime(scan.startedAt) : "—"}
              </p>
            </div>
            <div>
              <p className="text-zinc-500">Completed</p>
              <p className="font-medium text-zinc-900 dark:text-zinc-50">
                {scan.completedAt ? formatDateTime(scan.completedAt) : "—"}
              </p>
            </div>
            <div>
              <p className="text-zinc-500">Error Log</p>
              <p className="font-medium">{scan.errorLog ?? "None"}</p>
            </div>
          </div>
        </CardContent>
      </Card>

      {scan.riskAssessments.length > 0 && (
        <Card>
          <CardHeader>
            <div className="flex items-center gap-2">
              <AlertTriangle className="h-5 w-5 text-violet-500" />
              <CardTitle>Risk Assessments</CardTitle>
            </div>
          </CardHeader>
          <CardContent className="p-0">
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Device</TableHead>
                  <TableHead>Composite</TableHead>
                  <TableHead>CVE</TableHead>
                  <TableHead>Exposure</TableHead>
                  <TableHead>Credentials</TableHead>
                  <TableHead>Network</TableHead>
                  <TableHead>Severity</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {scan.riskAssessments.map((r) => (
                  <TableRow key={r.assessmentId}>
                    <TableCell className="font-medium">
                      {r.device.hostname ?? r.device.ipAddress}
                    </TableCell>
                    <TableCell>
                      <span className={cn(
                        "font-semibold",
                        r.compositeScore >= 8 ? "text-red-400" :
                        r.compositeScore >= 6 ? "text-amber-400" :
                        r.compositeScore >= 3 ? "text-blue-400" : "text-emerald-400"
                      )}>
                        {r.compositeScore.toFixed(1)}
                      </span>
                    </TableCell>
                    <TableCell>{r.cveScore.toFixed(1)}</TableCell>
                    <TableCell>{r.exposureScore.toFixed(1)}</TableCell>
                    <TableCell>{r.credentialScore.toFixed(1)}</TableCell>
                    <TableCell>{r.networkScore.toFixed(1)}</TableCell>
                    <TableCell>
                      <Badge variant={
                        r.compositeScore >= 8 ? "destructive" :
                        r.compositeScore >= 6 ? "warning" :
                        r.compositeScore >= 3 ? "info" : "default"
                      }>
                        {r.compositeScore >= 8 ? "Critical" :
                         r.compositeScore >= 6 ? "High" :
                         r.compositeScore >= 3 ? "Medium" : "Low"}
                      </Badge>
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </CardContent>
        </Card>
      )}

      {scan.scanResults.length > 0 && (
        <Card>
          <CardHeader>
            <div className="flex items-center gap-2">
              <Wifi className="h-5 w-5 text-violet-500" />
              <CardTitle>Scan Results ({scan.scanResults.length})</CardTitle>
            </div>
          </CardHeader>
          <CardContent className="p-0">
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Device</TableHead>
                  <TableHead>IP</TableHead>
                  <TableHead>Port</TableHead>
                  <TableHead>Protocol</TableHead>
                  <TableHead>Service</TableHead>
                  <TableHead>CVE</TableHead>
                  <TableHead>Risk Level</TableHead>
                  <TableHead>Detected</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {scan.scanResults.map((r) => (
                  <TableRow key={r.resultId}>
                    <TableCell className="font-medium">
                      {r.device.hostname ?? "—"}
                    </TableCell>
                    <TableCell className="font-mono text-xs">{r.device.ipAddress}</TableCell>
                    <TableCell className="font-mono">{r.port ?? "—"}</TableCell>
                    <TableCell>{r.protocol ?? "—"}</TableCell>
                    <TableCell>{r.service ?? "—"}</TableCell>
                    <TableCell className="font-mono text-xs text-violet-600 dark:text-violet-400">
                      {r.vulnerability?.cveId ?? "—"}
                    </TableCell>
                    <TableCell>
                      <Badge variant={
                        r.riskLevel === "Critical" ? "destructive" :
                        r.riskLevel === "High" ? "warning" :
                        r.riskLevel === "Medium" ? "info" : "default"
                      }>
                        {r.riskLevel ?? "—"}
                      </Badge>
                    </TableCell>
                    <TableCell className="text-xs text-zinc-500">
                      {formatDateTime(r.createdAt)}
                    </TableCell>
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
