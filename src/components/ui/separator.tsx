import { forwardRef, type HTMLAttributes } from "react"
import { cn } from "@/lib/utils"

const Separator = forwardRef<HTMLHRElement, HTMLAttributes<HTMLHRElement>>(
  ({ className, ...props }, ref) => (
    <hr
      ref={ref}
      className={cn("my-4 border-t border-zinc-200 dark:border-zinc-800", className)}
      {...props}
    />
  ),
)
Separator.displayName = "Separator"

export { Separator }
