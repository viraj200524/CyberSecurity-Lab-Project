import { type ReactNode, type ButtonHTMLAttributes } from "react";

type Variant = "primary" | "secondary" | "danger" | "ghost";
type Size    = "sm" | "md" | "lg";

const variantClass: Record<Variant, string> = {
  primary:   "bg-[var(--accent-primary)] text-[var(--bg-primary)] hover:brightness-110 focus-visible:ring-[var(--accent-primary)]",
  secondary: "bg-[var(--bg-tertiary)] text-[var(--text-primary)] border border-[var(--border)] hover:border-[var(--accent-primary)]/50 focus-visible:ring-[var(--accent-primary)]",
  danger:    "bg-[var(--danger)]/20 text-[var(--danger)] border border-[var(--danger)]/40 hover:bg-[var(--danger)]/30 focus-visible:ring-[var(--danger)]",
  ghost:     "bg-transparent text-[var(--text-muted)] hover:text-[var(--text-primary)] hover:bg-[var(--bg-tertiary)] focus-visible:ring-[var(--accent-primary)]",
};

const sizeClass: Record<Size, string> = {
  sm: "h-7  px-3 text-xs gap-1.5",
  md: "h-9  px-4 text-sm gap-2",
  lg: "h-11 px-5 text-sm gap-2",
};

type Props = ButtonHTMLAttributes<HTMLButtonElement> & {
  variant?: Variant;
  size?: Size;
  loading?: boolean;
  children: ReactNode;
};

export function Button({ variant = "primary", size = "md", loading = false, disabled, className = "", children, ...rest }: Props) {
  return (
    <button
      disabled={disabled || loading}
      className={`inline-flex items-center justify-center rounded font-[family-name:var(--font-space)] font-medium transition-all focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-offset-2 focus-visible:ring-offset-[var(--bg-primary)] disabled:pointer-events-none disabled:opacity-50 ${variantClass[variant]} ${sizeClass[size]} ${className}`}
      {...rest}
    >
      {loading && (
        <span className="h-3.5 w-3.5 animate-spin rounded-full border-2 border-current border-t-transparent" aria-hidden />
      )}
      {children}
    </button>
  );
}
