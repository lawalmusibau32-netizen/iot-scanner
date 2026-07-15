import { prisma } from "@/lib/prisma";
import { formatDateTime } from "@/lib/utils";
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
import { Bell } from "lucide-react";
import { cn } from "@/lib/utils";

function severityBadge(severity: string | null) {
  switch (severity?.toLowerCase()) {
    case "critical": return <Badge variant="destructive">Critical</Badge>;
    case "high": return <Badge variant="warning">High</Badge>;
    case "medium": return <Badge variant="info">Medium</Badge>;
    case "low": return <Badge variant="default">Low</Badge>;
    default: return <Badge variant="outline">{severity ?? "—"}</Badge>;
  }
}

export default async function AlertsPage() {
  const notifications = await prisma.notification.findMany({
    orderBy: { sentAt: "desc" },
  });

  return (
    <div className="animate-fade-in space-y-6">
      <PageHeader
        title="Alerts &amp; Notifications"
        description="Security events and system notifications"
      />

      <Card className="animate-slide-up">
        <CardContent className="p-0">
          {notifications.length === 0 ? (
            <div className="py-16 text-center">
              <Bell className="h-12 w-12 mx-auto text-zinc-300 dark:text-zinc-600 mb-3" />
              <p className="text-sm text-zinc-500 dark:text-zinc-400">No alerts yet.</p>
            </div>
          ) : (
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Severity</TableHead>
                  <TableHead>Message</TableHead>
                  <TableHead>Device</TableHead>
                  <TableHead>Sent At</TableHead>
                  <TableHead>Status</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {notifications.map((n) => (
                  <TableRow key={n.notifId}>
                    <TableCell>{severityBadge(n.severity)}</TableCell>
                    <TableCell className="max-w-md text-zinc-800 dark:text-zinc-200">
                      {n.message}
                    </TableCell>
                    <TableCell className="text-sm text-zinc-500">
                      {n.deviceId ?? "—"}
                    </TableCell>
                    <TableCell className="text-xs text-zinc-500">
                      {formatDateTime(n.sentAt)}
                    </TableCell>
                    <TableCell>
                      {n.isRead === "Y" ? (
                        <span className="text-xs text-zinc-500">Read</span>
                      ) : (
                        <span className="inline-flex items-center gap-1.5 text-xs font-medium text-violet-600 dark:text-violet-400">
                          <span className="h-2 w-2 rounded-full bg-violet-500" />
                          New
                        </span>
                      )}
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
