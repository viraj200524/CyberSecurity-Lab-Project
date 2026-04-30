import { type ReactNode } from "react";

type Variant = "default" | "success" | "warning" | "danger" | "accent" | "muted";

const variantClass: Record<Variant, string> = {
  default:  "bg-[var(--bg-tertiary)] text-[var(--text-primary)] border-[var(--border)]",
  success:  "bg-[var(--success)]/15 text-[var(--success)] border-[var(--success)]/30",
  warning:  "bg-[var(--warning)]/15 text-[var(--warning)] border-[var(--warning)]/35",
  danger:   "bg-[var(--danger)]/15 text-[var(--danger)] border-[var(--danger)]/30",
  accent:   "bg-[var(--accent-primary)]/15 text-[var(--accent-primary)] border-[var(--accent-primary)]/30",
  muted:    "bg-transparent text-[var(--text-muted)] border-[var(--border)]",
};

type Props = {
  children: ReactNode;
  variant?: Variant;
  className?: string;
};

export function Badge({ children, variant = "default", className = "" }: Props) {
  return (
    <span
      className={`inline-flex items-center gap-1 rounded border px-2 py-0.5 font-[family-name:var(--font-space)] text-xs font-medium uppercase tracking-wide ${variantClass[variant]} ${className}`}
    >
      {children}
    </span>
  );
}
