export const dynamic = 'force-dynamic';

import { prisma } from "@/lib/prisma";
import { formatDateTime, cn } from "@/lib/utils";
import { PageHeader } from "@/components/shared/page-header";
import { StatsCard } from "@/components/shared/stats-card";
import { Badge } from "@/components/ui/badge";
import { Card, CardContent } from "@/components/ui/card";
import {
  Table,
  TableHeader,
  TableBody,
  TableRow,
  TableHead,
  TableCell,
} from "@/components/ui/table";

function severityFromScore(score: number) {
  if (score >= 8) return { label: "Critical", variant: "destructive" as const };
  if (score >= 6) return { label: "High", variant: "warning" as const };
  if (score >= 3) return { label: "Medium", variant: "info" as const };
  return { label: "Low", variant: "default" as const };
}

function scoreColor(score: number) {
  if (score >= 8) return "text-red-500 dark:text-red-400";
  if (score >= 6) return "text-amber-500 dark:text-amber-400";
  if (score >= 3) return "text-blue-500 dark:text-blue-400";
  return "text-emerald-500 dark:text-emerald-400";
}

export default async function RiskPage() {
  const assessments = await prisma.riskAssessment.findMany({
    distinct: ["deviceId"],
    orderBy: [{ deviceId: "asc" }, { createdAt: "desc" }],
    include: {
      device: { select: { hostname: true, ipAddress: true } },
    },
  });

  const sorted = assessments.sort((a, b) => b.compositeScore - a.compositeScore);

  const avgScore = assessments.length
    ? assessments.reduce((s, a) => s + a.compositeScore, 0) / assessments.length
    : 0;
  const atRisk = assessments.filter((a) => a.compositeScore >= 6).length;

  return (
    <div className="animate-fade-in space-y-6">
      <PageHeader
        title="Risk Overview"
        description="Security risk assessment for all devices"
      />

      <div className="grid gap-4 sm:grid-cols-3">
        <div className="animate-slide-up">
          <StatsCard
            label="Network Risk Score"
            value={avgScore ? avgScore.toFixed(1) + " / 10" : "—"}
            tone={avgScore >= 6 ? "warning" : avgScore >= 3 ? "info" : "success"}
          />
        </div>
        <div className="animate-slide-up" style={{ animationDelay: "0.1s" }}>
          <StatsCard
            label="Devices at Risk"
            value={atRisk}
            tone={atRisk > 0 ? "warning" : "success"}
          />
        </div>
        <div className="animate-slide-up" style={{ animationDelay: "0.2s" }}>
          <StatsCard label="Devices Assessed" value={assessments.length} tone="info" />
        </div>
      </div>

      <Card className="animate-slide-up" style={{ animationDelay: "0.2s" }}>
        <CardContent className="p-0">
          {sorted.length === 0 ? (
            <div className="py-16 text-center text-sm text-zinc-500 dark:text-zinc-400">
              No risk assessments available. Run a scan to generate risk data.
            </div>
          ) : (
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Device</TableHead>
                  <TableHead>Composite Score</TableHead>
                  <TableHead>CVE Score</TableHead>
                  <TableHead>Exposure</TableHead>
                  <TableHead>Credentials</TableHead>
                  <TableHead>Network</TableHead>
                  <TableHead>Severity</TableHead>
                  <TableHead>Recommendation</TableHead>
                  <TableHead>Last Assessed</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {sorted.map((a) => {
                  const sv = severityFromScore(a.compositeScore);
                  return (
                    <TableRow key={a.assessmentId}>
                      <TableCell className="font-medium">
                        {a.device.hostname ?? a.device.ipAddress}
                      </TableCell>
                      <TableCell>
                        <span className={cn("font-bold text-base", scoreColor(a.compositeScore))}>
                          {a.compositeScore.toFixed(1)}
                        </span>
                      </TableCell>
                      <TableCell>{a.cveScore.toFixed(1)}</TableCell>
                      <TableCell>{a.exposureScore.toFixed(1)}</TableCell>
                      <TableCell>{a.credentialScore.toFixed(1)}</TableCell>
                      <TableCell>{a.networkScore.toFixed(1)}</TableCell>
                      <TableCell>
                        <Badge variant={sv.variant}>{sv.label}</Badge>
                      </TableCell>
                      <TableCell className="max-w-[200px] text-xs text-zinc-600 dark:text-zinc-400 truncate">
                        {a.recommendation ?? "—"}
                      </TableCell>
                      <TableCell className="text-xs text-zinc-500">
                        {formatDateTime(a.createdAt)}
                      </TableCell>
                    </TableRow>
                  );
                })}
              </TableBody>
            </Table>
          )}
        </CardContent>
      </Card>
    </div>
  );
}
