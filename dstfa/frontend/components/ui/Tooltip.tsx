"use client";

import { useState, type ReactNode } from "react";

type Props = {
  content: ReactNode;
  children: ReactNode;
  className?: string;
};

export function Tooltip({ content, children, className = "" }: Props) {
  const [visible, setVisible] = useState(false);

  return (
    <span
      className={`relative inline-flex ${className}`}
      onMouseEnter={() => setVisible(true)}
      onMouseLeave={() => setVisible(false)}
      onFocus={() => setVisible(true)}
      onBlur={() => setVisible(false)}
    >
      {children}
      {visible && (
        <span
          role="tooltip"
          className="pointer-events-none absolute bottom-full left-1/2 z-50 mb-2 -translate-x-1/2 rounded border border-[var(--border)] bg-[var(--bg-tertiary)] px-2.5 py-1.5 text-xs text-[var(--text-primary)] shadow-lg whitespace-nowrap"
        >
          {content}
          <span className="absolute left-1/2 top-full -translate-x-1/2 border-4 border-transparent border-t-[var(--border)]" aria-hidden />
        </span>
      )}
    </span>
  );
}
