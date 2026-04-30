import { type ReactNode } from "react";

type Props = {
  children: ReactNode;
  className?: string;
  glow?: boolean;
};

export function Card({ children, className = "", glow = false }: Props) {
  return (
    <div
      className={`rounded-lg border border-[var(--border)] bg-[var(--bg-secondary)] ${glow ? "shadow-[0_0_20px_rgba(0,212,255,0.05)]" : ""} ${className}`}
    >
      {children}
    </div>
  );
}

export function CardHeader({ children, className = "" }: { children: ReactNode; className?: string }) {
  return (
    <div className={`border-b border-[var(--border)] px-4 py-3 ${className}`}>
      {children}
    </div>
  );
}

export function CardBody({ children, className = "" }: { children: ReactNode; className?: string }) {
  return <div className={`px-4 py-4 ${className}`}>{children}</div>;
}

export function CardFooter({ children, className = "" }: { children: ReactNode; className?: string }) {
  return (
    <div className={`border-t border-[var(--border)] px-4 py-3 ${className}`}>
      {children}
    </div>
  );
}
