type Size = "sm" | "md" | "lg";

const sizeClass: Record<Size, string> = {
  sm: "h-4 w-4 border-2",
  md: "h-6 w-6 border-2",
  lg: "h-8 w-8 border-[3px]",
};

type Props = {
  size?: Size;
  className?: string;
  label?: string;
};

export function Spinner({ size = "md", className = "", label = "Loading…" }: Props) {
  return (
    <span role="status" aria-label={label} className={`inline-block ${className}`}>
      <span
        className={`block animate-spin rounded-full border-[var(--accent-primary)] border-t-transparent ${sizeClass[size]}`}
        aria-hidden
      />
    </span>
  );
}
