export const dynamic = 'force-dynamic';

import { prisma } from "@/lib/prisma";
import { formatDate } from "@/lib/utils";
import { PageHeader } from "@/components/shared/page-header";
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
import { cn } from "@/lib/utils";

function cvssBadge(score: number | null) {
  if (score == null) return <Badge variant="outline">N/A</Badge>;
  if (score >= 9) return <Badge variant="destructive">Critical</Badge>;
  if (score >= 7) return <Badge variant="warning">High</Badge>;
  if (score >= 4) return <Badge variant="info">Medium</Badge>;
  return <Badge variant="success">Low</Badge>;
}

function cvssColor(score: number | null) {
  if (score == null) return "text-zinc-400";
  if (score >= 9) return "text-red-500 dark:text-red-400";
  if (score >= 7) return "text-amber-500 dark:text-amber-400";
  if (score >= 4) return "text-blue-500 dark:text-blue-400";
  return "text-emerald-500 dark:text-emerald-400";
}

export default async function VulnerabilitiesPage() {
  const vulns = await prisma.vulnerability.findMany({
    orderBy: { cvssScore: "desc" },
  });

  return (
    <div className="animate-fade-in space-y-6">
      <PageHeader
        title="Vulnerability Database"
        description="Known CVEs affecting IoT devices"
      />

      <Card className="animate-slide-up">
        <CardContent className="p-0">
          {vulns.length === 0 ? (
            <div className="py-16 text-center text-sm text-zinc-500 dark:text-zinc-400">
              No vulnerabilities found.
            </div>
          ) : (
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>CVE ID</TableHead>
                  <TableHead>CVSS Score</TableHead>
                  <TableHead>Severity</TableHead>
                  <TableHead>Description</TableHead>
                  <TableHead>Affected CPE</TableHead>
                  <TableHead>Published</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {vulns.map((v) => (
                  <TableRow key={v.vulnId}>
                    <TableCell className="font-mono text-xs font-medium text-violet-600 dark:text-violet-400">
                      {v.cveId}
                    </TableCell>
                    <TableCell>
                      <span className={cn("font-bold text-base", cvssColor(v.cvssScore))}>
                        {v.cvssScore?.toFixed(1) ?? "—"}
                      </span>
                    </TableCell>
                    <TableCell>{cvssBadge(v.cvssScore)}</TableCell>
                    <TableCell className="max-w-xs truncate text-zinc-600 dark:text-zinc-400">
                      {v.description ?? "—"}
                    </TableCell>
                    <TableCell className="max-w-[180px] truncate font-mono text-xs">
                      {v.affectedCpe ?? "—"}
                    </TableCell>
                    <TableCell className="text-xs text-zinc-500">
                      {formatDate(v.publishedDate)}
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
