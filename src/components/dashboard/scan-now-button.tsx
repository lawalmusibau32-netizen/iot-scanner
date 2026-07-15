"use client";

import { useState, useEffect } from "react";
import { useRouter } from "next/navigation";
import { Scan, Loader2, ChevronDown, Wifi, Crosshair, Notebook, ArrowRight } from "lucide-react";
import { Button } from "@/components/ui/button";

export function ScanNowButton() {
  const router = useRouter();
  const [open, setOpen] = useState(false);
  const [type, setType] = useState("full");
  const [loading, setLoading] = useState(false);
  const [latestScan, setLatestScan] = useState<{ id: number; status: string; progress: number } | null>(null);

  useEffect(() => {
    fetch("/api/scans")
      .then((r) => r.json())
      .then((scans) => {
        if (Array.isArray(scans) && scans.length > 0) {
          const latest = scans[0];
          setLatestScan({ id: latest.scanId, status: latest.status, progress: latest.progress ?? 0 });
        }
      })
      .catch(() => {});
  }, []);

  async function handleScan() {
    setLoading(true);
    try {
      const res = await fetch("/api/scans", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ scanType: type }),
      });
      if (!res.ok) throw new Error("Failed");
      const data = await res.json();
      setOpen(false);
      router.push(`/scans/${data.scanId}`);
    } catch {
      setLoading(false);
    }
  }

  const types = [
    { value: "full", label: "Full Network Scan", icon: Wifi, desc: "All common ports, all devices" },
    { value: "quick", label: "Quick Scan", icon: Notebook, desc: "Essential ports only, fast" },
  ];

  return (
    <div className="relative">
      <Button
        size="lg"
        onClick={() => setOpen(!open)}
        disabled={loading}
        className="relative bg-violet-600 hover:bg-violet-500 text-white shadow-lg shadow-violet-500/25 hover:shadow-violet-500/40 transition-all px-6 py-6 text-base font-semibold rounded-xl"
      >
        {loading ? (
          <Loader2 className="h-5 w-5 animate-spin mr-2" />
        ) : (
          <Scan className="h-5 w-5 mr-2" />
        )}
        {loading ? "Starting Scan..." : "Scan Network Now"}
        <ChevronDown className="h-4 w-4 ml-2 opacity-70" />
      </Button>

      {latestScan && (
        <div className="text-xs text-zinc-500 dark:text-zinc-400 mt-2 text-right">
          Last scan: {latestScan.status} ({latestScan.progress}%)
        </div>
      )}

      {open && (
        <>
          <div className="fixed inset-0 z-40" onClick={() => setOpen(false)} />
          <div className="absolute right-0 top-full mt-2 z-50 w-80 rounded-xl border border-zinc-200 dark:border-zinc-800 bg-white dark:bg-zinc-950 shadow-xl p-4 space-y-3">
            <p className="text-sm font-semibold text-zinc-900 dark:text-zinc-100 px-1">Select Scan Type</p>
            {types.map((t) => {
              const Icon = t.icon;
              return (
                <button
                  key={t.value}
                  onClick={() => setType(t.value)}
                  className={`w-full flex items-start gap-3 rounded-lg border p-3 text-left text-sm transition-colors ${
                    type === t.value
                      ? "border-violet-500 bg-violet-50 dark:bg-violet-900/20"
                      : "border-zinc-200 dark:border-zinc-800 hover:bg-zinc-50 dark:hover:bg-zinc-900"
                  }`}
                >
                  <Icon className={`h-5 w-5 mt-0.5 shrink-0 ${
                    type === t.value ? "text-violet-600 dark:text-violet-400" : "text-zinc-400"
                  }`} />
                  <div className="flex-1">
                    <p className="font-medium text-zinc-900 dark:text-zinc-100">{t.label}</p>
                    <p className="text-xs text-zinc-500">{t.desc}</p>
                  </div>
                  {type === t.value && (
                    <ArrowRight className="h-4 w-4 text-violet-500 mt-1" />
                  )}
                </button>
              );
            })}
            <div className="flex gap-2 pt-1">
              <Button variant="outline" size="sm" className="flex-1" onClick={() => setOpen(false)}>Cancel</Button>
              <Button size="sm" className="flex-1 bg-violet-600 hover:bg-violet-500" onClick={handleScan} disabled={loading}>
                {loading ? "Starting..." : "Start Scan"}
              </Button>
            </div>
          </div>
        </>
      )}
    </div>
  );
}
