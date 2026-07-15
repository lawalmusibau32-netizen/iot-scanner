"use client"

import { useRouter } from "next/navigation"
import { LogOut } from "lucide-react"
import { cn } from "@/lib/utils"
import { Button } from "@/components/ui/button"

interface TopbarProps {
  userName: string
  role: string
  className?: string
}

export function Topbar({ userName, role, className }: TopbarProps) {
  const router = useRouter()

  async function handleLogout() {
    await fetch("/api/auth/logout", { method: "POST" })
    router.push("/login")
    router.refresh()
  }

  return (
    <header
      className={cn(
        "flex h-16 items-center justify-end gap-4 border-b border-zinc-200/60 bg-white/70 px-6 backdrop-blur-xl dark:border-zinc-700/40 dark:bg-zinc-950/70",
        className,
      )}
    >
      <div className="flex items-center gap-3">
        <div className="text-right">
          <p className="text-sm font-medium text-zinc-900 dark:text-zinc-50">
            {userName}
          </p>
          <p className="text-xs text-zinc-500 capitalize dark:text-zinc-400">
            {role}
          </p>
        </div>
        <div className="flex h-9 w-9 items-center justify-center rounded-full bg-violet-100 text-sm font-semibold text-violet-700 dark:bg-violet-900/40 dark:text-violet-300">
          {userName.charAt(0).toUpperCase()}
        </div>
      </div>

      <Button variant="ghost" size="sm" onClick={handleLogout} className="text-zinc-500 hover:text-red-600 dark:text-zinc-400 dark:hover:text-red-400">
        <LogOut className="h-4 w-4" />
        Logout
      </Button>
    </header>
  )
}
