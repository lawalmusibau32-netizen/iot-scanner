"use client";

import { useState } from "react";
import { useRouter } from "next/navigation";
import { Plus, Loader2, Scan, Wifi, Crosshair } from "lucide-react";
import { Button } from "@/components/ui/button";
import {
  Select,
  SelectTrigger,
  SelectValue,
  SelectContent,
  SelectItem,
} from "@/components/ui/select";

const SCAN_TYPES = [
  { value: "full", label: "Full Scan", icon: Scan, desc: "All ports, all protocols" },
  { value: "quick", label: "Quick Scan", icon: Wifi, desc: "Common ports only" },
  { value: "targeted", label: "Targeted Scan", icon: Crosshair, desc: "Specific device or subnet" },
];

export function NewScanButton() {
  const router = useRouter();
  const [open, setOpen] = useState(false);
  const [type, setType] = useState("full");
  const [loading, setLoading] = useState(false);

  async function handleNewScan() {
    setLoading(true);
    try {
      const res = await fetch("/api/scans", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ scanType: type }),
      });
      if (!res.ok) throw new Error("Failed to create scan");
      const data = await res.json();
      setOpen(false);
      router.push(`/scans/${data.scanId}`);
    } catch {
      setLoading(false);
    }
  }

  return (
    <div className="relative">
      <Button onClick={() => setOpen(!open)} disabled={loading}>
        {loading ? <Loader2 className="h-4 w-4 animate-spin" /> : <Plus className="h-4 w-4" />}
        New Scan
      </Button>

      {open && (
        <>
          <div className="fixed inset-0 z-40" onClick={() => setOpen(false)} />
          <div className="absolute right-0 top-full mt-2 z-50 w-72 rounded-xl border border-zinc-200 dark:border-zinc-800 bg-white dark:bg-zinc-950 shadow-xl p-4 space-y-3">
            <p className="text-sm font-medium text-zinc-900 dark:text-zinc-100">Scan Type</p>
            <div className="space-y-2">
              {SCAN_TYPES.map((t) => {
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
                    <Icon className={`h-5 w-5 mt-0.5 ${
                      type === t.value ? "text-violet-600 dark:text-violet-400" : "text-zinc-400"
                    }`} />
                    <div>
                      <p className="font-medium text-zinc-900 dark:text-zinc-100">{t.label}</p>
                      <p className="text-xs text-zinc-500">{t.desc}</p>
                    </div>
                  </button>
                );
              })}
            </div>
            <div className="flex gap-2 pt-1">
              <Button variant="outline" size="sm" className="flex-1" onClick={() => setOpen(false)}>Cancel</Button>
              <Button size="sm" className="flex-1" onClick={handleNewScan} disabled={loading}>
                {loading ? "Starting..." : "Start Scan"}
              </Button>
            </div>
          </div>
        </>
      )}
    </div>
  );
}
