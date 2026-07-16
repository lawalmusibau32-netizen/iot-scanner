"use client";

import { useEffect, useState, use } from "react";
import { useRouter } from "next/navigation";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { ArrowLeft, Download, Loader2, Shield, Bug, Wifi, FileText, AlertTriangle, Server, Globe, Terminal, Lock, Cpu, Network, ChevronRight, ExternalLink } from "lucide-react";

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

const severityConfig: Record<string, { color: string; bg: string; border: string; icon: any; label: string }> = {
  Critical: { color: "text-red-400", bg: "bg-red-500/10", border: "border-red-500/30", icon: AlertTriangle, label: "Critical" },
  High: { color: "text-amber-400", bg: "bg-amber-500/10", border: "border-amber-500/30", icon: Shield, label: "High" },
  Medium: { color: "text-blue-400", bg: "bg-blue-500/10", border: "border-blue-500/30", icon: Bug, label: "Medium" },
  Low: { color: "text-emerald-400", bg: "bg-emerald-500/10", border: "border-emerald-500/30", icon: Wifi, label: "Low" },
};

function scoreBar(value: number, max: number = 10) {
  const pct = Math.min(100, (value / max) * 100);
  const hue = value >= 8 ? "oklch(0.58 0.22 25)" : value >= 6 ? "oklch(0.7 0.2 75)" : value >= 3 ? "oklch(0.55 0.2 240)" : "oklch(0.6 0.15 160)";
  return (
    <div className="h-1.5 rounded-full bg-zinc-200 dark:bg-zinc-700 overflow-hidden">
      <div className="h-full rounded-full transition-all duration-1000 ease-out" style={{ width: `${pct}%`, background: hue }} />
    </div>
  );
}

export default function DeviceReportPage({ params }: { params: Promise<{ id: string }> }) {
  const { id } = use(params);
  const router = useRouter();
  const [report, setReport] = useState<ReportData | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");

  useEffect(() => {
    const timer = setTimeout(() => {
      fetch(`/api/reports/${id}`)
        .then(r => r.json())
        .then(data => {
          if (data.error) { setError(data.error); setLoading(false); return; }
          setReport(data);
          setLoading(false);
        })
        .catch(() => { setError("Failed to generate report"); setLoading(false); });
    }, 300);
    return () => clearTimeout(timer);
  }, [id]);

  const overallSev = report
    ? report.summary.criticalCount > 0 ? "Critical"
      : report.summary.highCount > 0 ? "High"
      : report.summary.mediumCount > 0 ? "Medium" : "Low"
    : "";

  const sev = severityConfig[overallSev] || severityConfig.Low;
  const SevIcon = sev.icon;

  if (loading) {
    return (
      <div className="min-h-[60vh] flex flex-col items-center justify-center gap-4">
        <div className="relative">
          <Loader2 className="h-10 w-10 animate-spin text-primary/60" />
          <div className="absolute inset-0 animate-ping rounded-full bg-primary/5" />
        </div>
        <p className="text-sm text-muted-foreground animate-pulse">Generating security report...</p>
      </div>
    );
  }

  if (error || !report) {
    return (
      <div className="min-h-[60vh] flex flex-col items-center justify-center gap-4">
        <div className="p-4 rounded-full bg-destructive/10">
          <AlertTriangle className="h-8 w-8 text-destructive" />
        </div>
        <p className="text-muted-foreground">{error || "Report not found"}</p>
        <Button variant="outline" onClick={() => router.back()}>Go Back</Button>
      </div>
    );
  }

  const risk = report.riskScores;

  return (
    <div className="max-w-4xl mx-auto space-y-6 pb-12">
      {/* Top bar */}
      <div className="flex items-center justify-between no-print">
        <Button variant="ghost" size="sm" onClick={() => router.back()} className="text-muted-foreground hover:text-foreground">
          <ArrowLeft className="h-4 w-4 mr-1.5" /> Back
        </Button>
        <Button variant="outline" size="sm" onClick={() => window.print()} className="gap-1.5">
          <Download className="h-4 w-4" /> Export
        </Button>
      </div>

      {/* Hero header */}
      <div className={`relative overflow-hidden rounded-2xl border ${sev.border} ${sev.bg} p-8 animate-scale-in`}>
        <div className="absolute top-0 right-0 w-64 h-64 bg-gradient-to-bl from-primary/5 to-transparent rounded-full blur-3xl -translate-y-1/2 translate-x-1/2" />
        <div className="relative z-10 flex items-start justify-between flex-wrap gap-6">
          <div className="space-y-3">
            <div className="flex items-center gap-2 text-xs text-muted-foreground uppercase tracking-widest font-medium">
              <FileText className="h-3.5 w-3.5" />
              Security Assessment Report
            </div>
            <h1 className="text-3xl font-bold text-foreground">{report.summary.deviceName}</h1>
            <div className="flex flex-wrap items-center gap-x-4 gap-y-1 text-sm text-muted-foreground">
              <span className="font-mono">{report.summary.ipAddress}</span>
              <span className="w-1 h-1 rounded-full bg-muted-foreground/30" />
              <span className="font-mono text-xs">{report.summary.macAddress}</span>
              <span className="w-1 h-1 rounded-full bg-muted-foreground/30" />
              <span>{report.summary.vendor}</span>
              <span className="w-1 h-1 rounded-full bg-muted-foreground/30" />
              <span>{report.summary.deviceType}</span>
            </div>
          </div>
          <div className="text-right">
            <div className={`text-5xl font-black ${sev.color} leading-none`}>{risk?.composite.toFixed(1) ?? "?"}</div>
            <div className="flex items-center gap-1.5 justify-end mt-2">
              <SevIcon className={`h-4 w-4 ${sev.color}`} />
              <span className={`text-sm font-semibold ${sev.color}`}>{overallSev}</span>
            </div>
            <p className="text-[10px] text-muted-foreground/60 mt-1">out of 10</p>
          </div>
        </div>
      </div>

      {/* Stats grid */}
      <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
        {[
          { icon: Bug, label: "Total Findings", value: report.summary.totalFindings, color: "text-primary" },
          { icon: AlertTriangle, label: "Critical", value: report.summary.criticalCount, color: "text-red-400" },
          { icon: Shield, label: "High", value: report.summary.highCount, color: "text-amber-400" },
          { icon: Wifi, label: "Open Ports", value: report.openPorts.length, color: "text-primary" },
        ].map((s, i) => (
          <div key={i} className="glass-card rounded-xl p-5 animate-slide-up" style={{ animationDelay: `${i * 0.08}s` }}>
            <div className="flex items-center gap-3">
              <div className={`p-2 rounded-lg ${s.color.replace("text", "bg")}/10`}>
                <s.icon className={`h-4.5 w-4.5 ${s.color}`} />
              </div>
              <div>
                <p className="text-2xl font-bold text-foreground">{s.value}</p>
                <p className="text-xs text-muted-foreground">{s.label}</p>
              </div>
            </div>
          </div>
        ))}
      </div>

      {/* Score breakdown */}
      {risk && (
        <div className="glass-card rounded-xl p-6 animate-slide-up">
          <h3 className="text-sm font-semibold text-foreground mb-5 flex items-center gap-2">
            <Shield className="h-4 w-4 text-primary" />
            Risk Score Breakdown
          </h3>
          <div className="grid sm:grid-cols-2 gap-x-8 gap-y-4">
            {[
              { label: "CVE Score", value: risk.cveScore, icon: Bug, desc: "Known vulnerabilities for this vendor/type" },
              { label: "Exposure", value: risk.exposureScore, icon: Globe, desc: "Open ports and insecure services" },
              { label: "Credentials", value: risk.credentialScore, icon: Lock, desc: "Default or weak password risk" },
              { label: "Network", value: risk.networkScore, icon: Network, desc: "Configuration and misconfigurations" },
            ].map((s, i) => (
              <div key={i} className="space-y-1.5">
                <div className="flex items-center justify-between text-sm">
                  <span className="flex items-center gap-1.5 text-muted-foreground">
                    <s.icon className="h-3.5 w-3.5" />
                    {s.label}
                  </span>
                  <span className="font-semibold text-foreground">{s.value.toFixed(1)}</span>
                </div>
                {scoreBar(s.value)}
                <p className="text-[10px] text-muted-foreground/60">{s.desc}</p>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Narrative */}
      <div className="glass-card rounded-xl p-6 animate-slide-up space-y-5">
        <h3 className="text-sm font-semibold text-foreground flex items-center gap-2">
          <FileText className="h-4 w-4 text-primary" />
          Assessment Narrative
        </h3>
        <div className="text-sm text-muted-foreground leading-relaxed space-y-5">
          {report.narrative.split("\n\n").map((section, i) => {
            const heading = section.startsWith("**") ? section.match(/^\*\*(.*?)\*\*/)?.[1] : null;
            const body = heading ? section.replace(/^\*\*.*?\*\*/, "").trim() : section;
            if (!body && !heading) return null;
            return (
              <div key={i}>
                {heading && <h4 className="text-foreground font-semibold mb-2 text-sm">{heading}</h4>}
                <div className="whitespace-pre-line">
                  {body.split(/\*\*(.*?)\*\*/).map((part, j) =>
                    j % 2 === 1 ? <strong key={j} className="text-foreground/80 font-semibold">{part}</strong> : part
                  )}
                </div>
              </div>
            );
          })}
        </div>
      </div>

      {/* Open ports */}
      {report.openPorts.length > 0 && (
        <div className="glass-card rounded-xl p-6 animate-slide-up">
          <h3 className="text-sm font-semibold text-foreground flex items-center gap-2 mb-4">
            <Globe className="h-4 w-4 text-primary" />
            Open Ports ({report.openPorts.length})
          </h3>
          <div className="flex flex-wrap gap-2">
            {report.openPorts.map((p, i) => {
              const risky = [21, 23, 445, 3389].includes(p.port);
              return (
                <div key={i} className={`inline-flex items-center gap-1.5 px-3 py-1.5 rounded-full text-xs font-mono border ${risky ? "border-red-500/30 bg-red-500/10 text-red-400" : "border-zinc-200 dark:border-zinc-700 bg-zinc-50 dark:bg-zinc-800/50 text-muted-foreground"}`}>
                  <span className={`w-1.5 h-1.5 rounded-full ${risky ? "bg-red-400 animate-pulse" : "bg-zinc-300 dark:bg-zinc-600"}`} />
                  {p.port}/{p.service}
                </div>
              );
            })}
          </div>
        </div>
      )}

      {/* Findings */}
      {report.findings.length > 0 && (
        <div className="glass-card rounded-xl p-6 animate-slide-up">
          <h3 className="text-sm font-semibold text-foreground flex items-center gap-2 mb-4">
            <Bug className="h-4 w-4 text-primary" />
            Detailed Findings ({report.findings.length})
          </h3>
          <div className="space-y-2">
            {report.findings.map((f, i) => {
              const sev = severityConfig[f.riskLevel] || severityConfig.Low;
              const SevIcon = sev.icon;
              return (
                <div key={i} className={`group rounded-xl border ${sev.border} ${sev.bg} p-4 transition-all hover:scale-[1.01]`}>
                  <div className="flex items-start gap-3">
                    <div className={`p-1.5 rounded-lg shrink-0 ${sev.bg}`}>
                      <SevIcon className={`h-4 w-4 ${sev.color}`} />
                    </div>
                    <div className="flex-1 min-w-0">
                      <div className="flex items-center gap-2 flex-wrap">
                        <span className={`text-[10px] font-semibold uppercase tracking-wider ${sev.color}`}>{f.riskLevel}</span>
                        <span className="text-xs font-medium text-foreground/80">
                          {f.port ? `Port ${f.port}` : f.service === "cve" ? "Known CVE" : f.service === "eol" ? "End of Life" : f.service === "config" ? "Configuration" : f.service}
                        </span>
                      </div>
                      <p className="text-xs text-muted-foreground mt-1 leading-relaxed">{f.detail}</p>
                    </div>
                    <ChevronRight className="h-4 w-4 text-muted-foreground/30 group-hover:text-muted-foreground/60 transition-colors shrink-0 mt-1" />
                  </div>
                </div>
              );
            })}
          </div>
        </div>
      )}

      {/* Recommendation */}
      {risk?.recommendation && (
        <div className="glass-card rounded-xl p-6 border-l-4 border-l-amber-500 animate-slide-up">
          <div className="flex items-start gap-3">
            <div className="p-2 rounded-lg bg-amber-500/10 shrink-0">
              <Shield className="h-5 w-5 text-amber-400" />
            </div>
            <div>
              <h3 className="text-sm font-semibold text-foreground mb-1">Recommended Actions</h3>
              <p className="text-sm text-muted-foreground leading-relaxed">{risk.recommendation}</p>
            </div>
          </div>
        </div>
      )}

      <p className="text-[10px] text-muted-foreground/40 text-center">
        IoT Scanner · Security Assessment · Generated {report.generatedAt}
      </p>
    </div>
  );
}
