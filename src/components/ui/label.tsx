"use client"

import { forwardRef, type LabelHTMLAttributes } from "react"
import { cn } from "@/lib/utils"

const Label = forwardRef<HTMLLabelElement, LabelHTMLAttributes<HTMLLabelElement>>(
  ({ className, ...props }, ref) => (
    <label
      ref={ref}
      className={cn(
        "text-sm font-medium leading-none text-zinc-700 peer-disabled:cursor-not-allowed peer-disabled:opacity-50 dark:text-zinc-300",
        className,
      )}
      {...props}
    />
  ),
)
Label.displayName = "Label"

export { Label }
