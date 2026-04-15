"use client";

import { AlertTriangle, BookOpen, CheckCircle2, XCircle } from "lucide-react";

import { TrustChainDiagram } from "@/components/visualizers/TrustChainDiagram";

function readString(obj: unknown, key: string): string {
  if (!obj || typeof obj !== "object") return "";
  const v = (obj as Record<string, unknown>)[key];
  return typeof v === "string" ? v : "";
}

function readBool(obj: unknown, key: string): boolean {
  if (!obj || typeof obj !== "object") return false;
  const v = (obj as Record<string, unknown>)[key];
  return v === true;
}

function readStringList(obj: unknown, key: string): string[] {
  if (!obj || typeof obj !== "object") return [];
  const v = (obj as Record<string, unknown>)[key];
  if (!Array.isArray(v)) return [];
  return v.filter((x): x is string => typeof x === "string");
}

export type TrustChainTabProps = {
  trustChain?: Record<string, unknown> | null;
};

export function TrustChainTab({ trustChain }: TrustChainTabProps) {
  const diagram = readString(trustChain, "mermaid_diagram");
  const chainValid = readBool(trustChain, "chain_valid");
  const weakPoints = readStringList(trustChain, "weak_points");
  const summary = readString(trustChain, "summary");
  const hasPayload = Boolean(diagram || summary || weakPoints.length);

  return (
    <section className="mt-8 rounded-xl border border-[var(--border)] bg-[var(--bg-secondary)] p-4">
      <div className="mb-4 flex flex-wrap items-center justify-between gap-3 border-b border-[var(--border)] pb-3">
        <h2 className="font-[family-name:var(--font-space)] text-lg font-semibold text-[var(--text-primary)]">
          Trust chain
        </h2>
        {!hasPayload && (
          <span className="rounded-full bg-[var(--bg-tertiary)] px-2 py-0.5 text-xs text-[var(--text-muted)]">
            No data
          </span>
        )}
      </div>

      <div className="flex flex-col gap-6 lg:flex-row">
        <aside className="shrink-0 rounded-lg border border-[var(--border)] bg-[var(--bg-tertiary)] p-3 lg:w-52">
          <div className="flex items-start gap-2">
            <BookOpen className="mt-0.5 h-4 w-4 shrink-0 text-[var(--accent-primary)]" aria-hidden />
            <div>
              <p className="text-xs font-semibold uppercase tracking-wide text-[var(--accent-primary)]">Syllabus</p>
              <p className="mt-1 text-xs leading-snug text-[var(--text-muted)]">
                Unit 6 — Chain of trust / PKI: how X.509, S/MIME, DKIM, SPF, and DMARC relate to the message.
              </p>
            </div>
          </div>
        </aside>

        <div className="min-w-0 flex-1 space-y-4">
          <TrustChainDiagram chart={diagram} />

          <div
            className={[
              "flex items-center gap-3 rounded-lg border px-4 py-3 text-sm",
              chainValid
                ? "border-[var(--success)]/40 bg-[var(--success)]/10 text-[var(--success)]"
                : "border-[var(--danger)]/40 bg-[var(--danger)]/10 text-[var(--danger)]",
            ].join(" ")}
            role="status"
          >
            {chainValid ? (
              <CheckCircle2 className="h-5 w-5 shrink-0" aria-hidden />
            ) : (
              <XCircle className="h-5 w-5 shrink-0" aria-hidden />
            )}
            <div>
              <p className="font-medium">{chainValid ? "Chain status: consistent" : "Chain status: issues detected"}</p>
              {summary ? (
                <p className="mt-1 text-[var(--text-primary)] opacity-90">{summary}</p>
              ) : (
                <p className="mt-1 text-[var(--text-muted)]">No summary returned for this analysis.</p>
              )}
            </div>
          </div>

          {weakPoints.length > 0 ? (
            <div>
              <h3 className="mb-2 text-sm font-medium text-[var(--warning)]">Weak points</h3>
              <ul className="space-y-2">
                {weakPoints.map((w, i) => (
                  <li
                    key={`${i}-${w.slice(0, 24)}`}
                    className="flex gap-2 rounded-lg border border-[var(--warning)]/35 bg-[var(--warning)]/8 px-3 py-2 text-sm text-[var(--text-primary)]"
                  >
                    <AlertTriangle className="mt-0.5 h-4 w-4 shrink-0 text-[var(--warning)]" aria-hidden />
                    <span>{w}</span>
                  </li>
                ))}
              </ul>
            </div>
          ) : (
            hasPayload && (
              <p className="text-xs text-[var(--text-muted)]">No explicit weak points listed for this message.</p>
            )
          )}
        </div>
      </div>
    </section>
  );
}
