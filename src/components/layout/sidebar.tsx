"use client"

import Link from "next/link"
import { usePathname } from "next/navigation"
import { cn } from "@/lib/utils"
import {
  LayoutDashboard,
  Monitor,
  Bug,
  Scan,
  Shield,
  Bell,
} from "lucide-react"

const navItems = [
  { label: "Dashboard", href: "/dashboard", icon: LayoutDashboard },
  { label: "Devices", href: "/devices", icon: Monitor },
  { label: "Vulnerabilities", href: "/vulnerabilities", icon: Bug },
  { label: "Scan History", href: "/scans", icon: Scan },
  { label: "Risk Overview", href: "/risk", icon: Shield },
  { label: "Alerts", href: "/alerts", icon: Bell },
]

export function Sidebar() {
  const pathname = usePathname()

  return (
    <aside className="glass-sidebar flex h-screen w-64 flex-col border-r border-zinc-200/60 bg-white/70 backdrop-blur-xl dark:border-zinc-700/40 dark:bg-zinc-950/70">
      <div className="flex h-16 items-center gap-2.5 border-b border-zinc-200/50 px-6 dark:border-zinc-700/30">
        <Monitor className="h-6 w-6 text-violet-600 dark:text-violet-400" />
        <span className="text-lg font-bold tracking-tight text-zinc-900 dark:text-zinc-50">
          IoT Scanner
        </span>
      </div>

      <nav className="flex flex-1 flex-col gap-1 p-3">
        {navItems.map((item) => {
          const isActive = pathname === item.href
          const Icon = item.icon
          return (
            <Link
              key={item.href}
              href={item.href}
              className={cn(
                "flex items-center gap-3 rounded-lg px-3 py-2.5 text-sm font-medium transition-colors",
                isActive
                  ? "bg-violet-100 text-violet-800 dark:bg-violet-900/30 dark:text-violet-300"
                  : "text-zinc-600 hover:bg-zinc-100 hover:text-zinc-900 dark:text-zinc-400 dark:hover:bg-zinc-800/60 dark:hover:text-zinc-100",
              )}
            >
              <Icon className="h-4.5 w-4.5 shrink-0" />
              {item.label}
            </Link>
          )
        })}
      </nav>

      <div className="border-t border-zinc-200/50 px-6 py-4 dark:border-zinc-700/30">
        <p className="text-xs text-zinc-400 dark:text-zinc-500">
          IoT Scanner v0.1.0
        </p>
      </div>
    </aside>
  )
}
