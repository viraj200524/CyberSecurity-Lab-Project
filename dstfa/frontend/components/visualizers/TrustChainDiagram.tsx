"use client";

import dynamic from "next/dynamic";
import type { ComponentType } from "react";
import { useMemo } from "react";

type MermaidProps = { name?: string; chart?: string; config?: Record<string, unknown> };

const Mermaid = dynamic(
  () => import("react-mermaid2").then((m) => (m as { default: ComponentType<MermaidProps> }).default),
  { ssr: false },
);

const MERMAID_UI_CONFIG = {
  theme: "dark" as const,
  themeVariables: {
    primaryColor: "#1a2340",
    primaryTextColor: "#e8eaf0",
    lineColor: "#00d4ff",
    secondaryColor: "#0f1629",
    tertiaryColor: "#1e2d4a",
    clusterBkg: "#0a0e1a",
    edgeLabelBackground: "#1a2340",
  },
  flowchart: {
    htmlLabels: true,
    curve: "basis",
  },
  securityLevel: "loose" as const,
};

export type TrustChainDiagramProps = {
  /** Raw Mermaid source (`graph TD` …) from `trust_chain.mermaid_diagram`. */
  chart: string | null | undefined;
  /** Unique chart name for Mermaid when multiple instances mount. */
  name?: string;
};

export function TrustChainDiagram({ chart, name = "dstfa-trust-chain" }: TrustChainDiagramProps) {
  const trimmed = (chart ?? "").trim();
  const safeChart = useMemo(() => {
    if (!trimmed) return "";
    return trimmed.startsWith("graph") ? trimmed : `graph TD\n${trimmed}`;
  }, [trimmed]);

  if (!safeChart) {
    return (
      <div className="rounded-lg border border-dashed border-[var(--border)] bg-[var(--bg-tertiary)] px-4 py-10 text-center text-sm text-[var(--text-muted)]">
        No trust-chain diagram yet. Upload an email and run analysis — the diagram appears when authentication and
        signature data are available.
      </div>
    );
  }

  return (
    <div className="max-h-[min(70vh,720px)] overflow-auto rounded-lg border border-[var(--border)] bg-[var(--terminal-bg)] p-4">
      <div className="min-w-[320px] text-[var(--text-primary)] [&_.mermaid]:flex [&_.mermaid]:justify-center">
        <Mermaid name={name} chart={safeChart} config={MERMAID_UI_CONFIG} />
      </div>
    </div>
  );
}
