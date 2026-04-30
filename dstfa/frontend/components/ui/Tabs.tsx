"use client";

import { createContext, useContext, type ReactNode } from "react";

type TabsCtx = { active: string; setActive: (id: string) => void };
const Ctx = createContext<TabsCtx>({ active: "", setActive: () => {} });

type TabsProps = {
  active: string;
  onChange: (id: string) => void;
  children: ReactNode;
  className?: string;
};

export function Tabs({ active, onChange, children, className = "" }: TabsProps) {
  return (
    <Ctx.Provider value={{ active, setActive: onChange }}>
      <div className={className}>{children}</div>
    </Ctx.Provider>
  );
}

export function TabList({ children, className = "" }: { children: ReactNode; className?: string }) {
  return (
    <div role="tablist" className={`flex gap-1 overflow-x-auto ${className}`}>
      {children}
    </div>
  );
}

type TabProps = {
  id: string;
  children: ReactNode;
  className?: string;
};

export function Tab({ id, children, className = "" }: TabProps) {
  const { active, setActive } = useContext(Ctx);
  const isActive = active === id;
  return (
    <button
      role="tab"
      aria-selected={isActive}
      aria-controls={`tabpanel-${id}`}
      id={`tab-${id}`}
      onClick={() => setActive(id)}
      className={`whitespace-nowrap rounded px-3 py-1.5 font-[family-name:var(--font-space)] text-xs uppercase tracking-wide transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-[var(--accent-primary)] ${
        isActive
          ? "border-l-2 border-[var(--accent-primary)] bg-[var(--bg-tertiary)] text-[var(--accent-primary)]"
          : "text-[var(--text-muted)] hover:text-[var(--text-primary)]"
      } ${className}`}
    >
      {children}
    </button>
  );
}

type PanelProps = {
  id: string;
  children: ReactNode;
  className?: string;
};

export function TabPanel({ id, children, className = "" }: PanelProps) {
  const { active } = useContext(Ctx);
  if (active !== id) return null;
  return (
    <div
      role="tabpanel"
      id={`tabpanel-${id}`}
      aria-labelledby={`tab-${id}`}
      className={className}
    >
      {children}
    </div>
  );
}
