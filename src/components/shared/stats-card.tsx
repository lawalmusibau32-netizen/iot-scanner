import { cn } from "@/lib/utils"

interface StatsCardProps {
  label: string
  value: string | number
  tone?: "default" | "success" | "warning" | "info" | "primary"
  className?: string
}

const accentMap = {
  default: "border-l-zinc-400 dark:border-l-zinc-500",
  success: "border-l-emerald-500 dark:border-l-emerald-400",
  warning: "border-l-amber-500 dark:border-l-amber-400",
  info: "border-l-blue-500 dark:border-l-blue-400",
  primary: "border-l-violet-500 dark:border-l-violet-400",
}

export function StatsCard({ label, value, tone = "default", className }: StatsCardProps) {
  return (
    <div
      className={cn(
        "rounded-xl border border-zinc-200 bg-white px-5 py-4 shadow-sm dark:border-zinc-800 dark:bg-zinc-950",
        "border-l-4",
        accentMap[tone],
        className,
      )}
    >
      <p className="text-xs font-medium uppercase tracking-wider text-zinc-500 dark:text-zinc-400">
        {label}
      </p>
      <p className="mt-1 text-2xl font-bold tracking-tight text-zinc-900 dark:text-zinc-50">
        {value}
      </p>
    </div>
  )
}
