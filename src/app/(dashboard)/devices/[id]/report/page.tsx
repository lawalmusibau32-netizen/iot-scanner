"use client";

import { useEffect, useState, use } from "react";
import { useRouter } from "next/navigation";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { ArrowLeft, Download, Loader2, Shield, Bug, Wifi, FileText } from "lucide-react";

interface ReportData {
  title: string;
  generatedAt: string;
  summary: {
    deviceName: string;
    ipAddress: string;
    macAddress: string;
    vendor: string;
    deviceType: string;
    osInfo: string;
    firmware: string;
    overallRisk: string;
    totalFindings: number;
    criticalCount: number;
    highCount: number;
    mediumCount: number;
    lowCount: number;
  };
  narrative: string;
  findings: Array<{
    port: number | null;
    service: string;
    riskLevel: string;
    detail: string;
    detectedAt: string;
  }>;
  riskScores: {
    composite: number;
    cveScore: number;
    exposureScore: number;
    credentialScore: number;
    networkScore: number;
    recommendation: string;
  } | null;
  openPorts: Array<{ port: number; service: string }>;
}

function riskBadge(level: string) {
  switch (level) {
    case "Critical": return <Badge variant="destructive">Critical</Badge>;
    case "High": return <Badge variant="warning">High</Badge>;
    case "Medium": return <Badge variant="info">Medium</Badge>;
    default: return <Badge variant="default">Low</Badge>;
  }
}

export default function DeviceReportPage({ params }: { params: Promise<{ id: string }> }) {
  const { id } = use(params);
  const router = useRouter();
  const [report, setReport] = useState<ReportData | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");

  useEffect(() => {
    fetch(`/api/reports/${id}`)
      .then(r => r.json())
      .then(data => {
        if (data.error) { setError(data.error); setLoading(false); return; }
        setReport(data);
        setLoading(false);
      })
      .catch(() => { setError("Failed to generate report"); setLoading(false); });
  }, [id]);

  function renderNarrative(text: string) {
    return text.split("\n\n").map((section, i) => {
      const isHeading = section.startsWith("**") && section.includes("**\n\n");
      if (isHeading) {
        const [head, ...body] = section.split("\n\n");
        const title = head.replace(/\*\*/g, "");
        return (
          <div key={i} className="mb-6">
            <h3 className="text-lg font-semibold text-zinc-900 dark:text-zinc-100 mb-3">{title}</h3>
            <div className="text-sm text-zinc-600 dark:text-zinc-400 leading-relaxed whitespace-pre-line">
              {body.join("\n\n").split(/\*\*(.*?)\*\*/).map((part: string, j: number) =>
                j % 2 === 1 ? <strong key={j} className="text-zinc-800 dark:text-zinc-200">{part}</strong> : part
              )}
            </div>
          </div>
        );
      }
      return (
        <p key={i} className="text-sm text-zinc-600 dark:text-zinc-400 leading-relaxed mb-4 whitespace-pre-line">
          {section.split(/\*\*(.*?)\*\*/).map((part: string, j: number) =>
            j % 2 === 1 ? <strong key={j} className="text-zinc-800 dark:text-zinc-200">{part}</strong> : part
          )}
        </p>
      );
    });
  }

  if (loading) {
    return (
      <div className="flex items-center justify-center h-64">
        <Loader2 className="h-8 w-8 animate-spin text-violet-500" />
      </div>
    );
  }

  if (error || !report) {
    return (
      <div className="text-center py-16">
        <p className="text-zinc-500">{error || "Report not found"}</p>
        <Button variant="outline" className="mt-4" onClick={() => router.back()}>Go Back</Button>
      </div>
    );
  }

  const sevColor = report.summary.criticalCount > 0 ? "text-red-400" :
    report.summary.highCount > 0 ? "text-amber-400" :
    report.summary.mediumCount > 0 ? "text-blue-400" : "text-emerald-400";

  return (
    <div className="animate-fade-in max-w-4xl mx-auto space-y-6">
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-3">
          <Button variant="ghost" size="sm" onClick={() => router.back()}>
            <ArrowLeft className="h-4 w-4 mr-1" /> Back
          </Button>
          <div>
            <h1 className="text-xl font-bold text-zinc-900 dark:text-zinc-50">Security Report</h1>
            <p className="text-xs text-zinc-500">Generated {report.generatedAt}</p>
          </div>
        </div>
        <div className="flex gap-2">
          <Button variant="outline" size="sm" onClick={() => window.print()}>
            <Download className="h-4 w-4 mr-1" /> Export PDF
          </Button>
        </div>
      </div>

      {/* Header Card */}
      <Card className="border-violet-200 dark:border-violet-800">
        <CardContent className="pt-6">
          <div className="flex items-start justify-between">
            <div className="space-y-1">
              <h2 className="text-2xl font-bold text-zinc-900 dark:text-zinc-50">{report.summary.deviceName}</h2>
              <p className="text-sm text-zinc-500">{report.summary.ipAddress} · {report.summary.macAddress}</p>
              <p className="text-sm text-zinc-500">{report.summary.vendor} · {report.summary.deviceType}</p>
            </div>
            <div className="text-right">
              <p className={`text-4xl font-bold ${sevColor}`}>
                {report.summary.criticalCount > 0 ? "Critical" :
                 report.summary.highCount > 0 ? "High" :
                 report.summary.mediumCount > 0 ? "Medium" : "Low"}
              </p>
              <p className="text-xs text-zinc-500">Risk Level</p>
            </div>
          </div>
        </CardContent>
      </Card>

      {/* Stats Grid */}
      <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
        <Card>
          <CardContent className="pt-4 text-center">
            <Shield className="h-5 w-5 mx-auto text-violet-500 mb-1" />
            <p className="text-2xl font-bold text-zinc-900 dark:text-zinc-50">{report.riskScores?.composite.toFixed(1) ?? "N/A"}</p>
            <p className="text-xs text-zinc-500">Risk Score</p>
          </CardContent>
        </Card>
        <Card>
          <CardContent className="pt-4 text-center">
            <Bug className="h-5 w-5 mx-auto text-red-400 mb-1" />
            <p className="text-2xl font-bold text-zinc-900 dark:text-zinc-50">{report.summary.totalFindings}</p>
            <p className="text-xs text-zinc-500">Findings</p>
          </CardContent>
        </Card>
        <Card>
          <CardContent className="pt-4 text-center">
            <Wifi className="h-5 w-5 mx-auto text-violet-500 mb-1" />
            <p className="text-2xl font-bold text-zinc-900 dark:text-zinc-50">{report.openPorts.length}</p>
            <p className="text-xs text-zinc-500">Open Ports</p>
          </CardContent>
        </Card>
        <Card>
          <CardContent className="pt-4 text-center">
            <FileText className="h-5 w-5 mx-auto text-violet-500 mb-1" />
            <p className="text-2xl font-bold text-zinc-900 dark:text-zinc-50">{report.riskScores ? "Active" : "N/A"}</p>
            <p className="text-xs text-zinc-500">Assessment</p>
          </CardContent>
        </Card>
      </div>

      {/* Narrative Report */}
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <FileText className="h-5 w-5 text-violet-500" />
            Assessment Narrative
          </CardTitle>
        </CardHeader>
        <CardContent className="prose prose-sm dark:prose-invert max-w-none">
          {renderNarrative(report.narrative)}
        </CardContent>
      </Card>

      {/* Finding Details */}
      {report.findings.length > 0 && (
        <Card>
          <CardHeader>
            <CardTitle className="flex items-center gap-2">
              <Bug className="h-5 w-5 text-violet-500" />
              Detailed Findings ({report.findings.length})
            </CardTitle>
          </CardHeader>
          <CardContent className="space-y-3">
            {report.findings.map((f, i) => (
              <div key={i} className="flex items-start gap-3 rounded-lg border border-zinc-200 dark:border-zinc-800 p-3">
                <div className="shrink-0 mt-0.5">{riskBadge(f.riskLevel)}</div>
                <div className="flex-1 min-w-0">
                  <p className="text-sm font-medium text-zinc-900 dark:text-zinc-100">
                    {f.port ? `Port ${f.port}/${f.service}` : f.service === "cve" ? "Known CVE" : f.service}
                  </p>
                  <p className="text-xs text-zinc-500 mt-1">{f.detail}</p>
                </div>
              </div>
            ))}
          </CardContent>
        </Card>
      )}

      {/* Recommendation */}
      {report.riskScores?.recommendation && (
        <Card className="border-amber-200 dark:border-amber-800">
          <CardHeader>
            <CardTitle className="flex items-center gap-2 text-amber-600 dark:text-amber-400">
              <Shield className="h-5 w-5" />
              Recommendation
            </CardTitle>
          </CardHeader>
          <CardContent>
            <p className="text-sm text-zinc-700 dark:text-zinc-300 leading-relaxed">
              {report.riskScores.recommendation}
            </p>
          </CardContent>
        </Card>
      )}

      <p className="text-[10px] text-zinc-400 text-center pb-4">
        IoT Scanner · Security Assessment Report · Generated {report.generatedAt}
      </p>
    </div>
  );
}
