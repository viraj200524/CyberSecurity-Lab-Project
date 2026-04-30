"use client";

import { useMemo, useState } from "react";

import type { HeadersResult } from "@/lib/types";

type Props = {
  headers: HeadersResult;
};

type SubTab = "parsed" | "raw";

export function HeadersTab({ headers }: Props) {
  const [sub, setSub] = useState<SubTab>("parsed");
  const lines = useMemo(() => headers.raw.split(/\r?\n/), [headers.raw]);

  return (
    <section className="rounded-xl border border-[var(--border)] bg-[var(--bg-secondary)] p-4">
      <div className="mb-4 flex gap-2 border-b border-[var(--border)] pb-3">
        {(["parsed", "raw"] as const).map((t) => (
          <button
            key={t}
            type="button"
            onClick={() => setSub(t)}
            className={[
              "rounded-md px-3 py-1.5 text-sm font-medium",
              sub === t
                ? "border-l-2 border-[var(--accent-primary)] bg-[var(--bg-tertiary)] text-[var(--accent-primary)] shadow-[0_0_12px_rgba(0,212,255,0.12)]"
                : "text-[var(--text-muted)] hover:text-[var(--text-primary)]",
            ].join(" ")}
          >
            {t === "parsed" ? "Parsed View" : "Raw View"}
          </button>
        ))}
      </div>

      {sub === "parsed" ? (
        <div className="space-y-2">
          {headers.parsed.map((h, i) => (
            <details
              key={`${h.name}-${i}`}
              className="group rounded-lg border border-[var(--border)] bg-[var(--bg-tertiary)] px-3 py-2"
            >
              <summary className="cursor-pointer list-none font-[family-name:var(--font-jetbrains)] text-sm text-[var(--text-primary)]">
                <span className="text-[var(--accent-primary)]">{h.name}</span>
                {h.suspicious && (
                  <span
                    className="ml-2 text-[var(--warning)]"
                    title={h.explanation || "Flagged as suspicious"}
                  >
                    ⚠
                  </span>
                )}
                <span className="ml-2 text-[var(--text-muted)]">▸</span>
              </summary>
              <p className="mt-2 whitespace-pre-wrap break-words text-sm text-[var(--text-muted)]">{h.value}</p>
              {h.suspicious && h.explanation && (
                <p className="mt-1 text-xs text-[var(--warning)]">{h.explanation}</p>
              )}
            </details>
          ))}
        </div>
      ) : (
        <pre className="max-h-[480px] overflow-auto rounded-lg bg-[var(--terminal-bg)] p-4 font-[family-name:var(--font-jetbrains)] text-xs leading-relaxed text-[var(--terminal-text)]">
          {lines.map((line, idx) => (
            <div key={idx} className="flex">
              <span className="mr-3 w-8 shrink-0 select-none text-right text-[var(--text-muted)]">{idx + 1}</span>
              <span>{line}</span>
            </div>
          ))}
        </pre>
      )}

      {headers.received_chain.length > 0 && (
        <div className="mt-8">
          <h3 className="mb-3 font-[family-name:var(--font-space)] text-sm text-[var(--text-muted)]">
            Received chain (oldest → newest)
          </h3>
          <div className="flex flex-wrap gap-3">
            {headers.received_chain.map((hop, i) => (
              <div key={i} className="flex items-center gap-2">
                <div className="min-w-[140px] rounded-lg border border-[var(--border)] bg-[var(--bg-tertiary)] px-3 py-2 text-xs">
                  <div className="text-[var(--accent-primary)]">from</div>
                  <div className="break-all text-[var(--text-primary)]">{hop.from || "—"}</div>
                  <div className="mt-1 text-[var(--accent-secondary)]">by</div>
                  <div className="break-all text-[var(--text-primary)]">{hop.by || "—"}</div>
                  <div className="mt-1 text-[var(--text-muted)]">{hop.timestamp}</div>
                  {hop.delay_seconds > 0 && (
                    <div className="mt-1 text-[var(--warning)]">+{hop.delay_seconds}s</div>
                  )}
                </div>
                {i < headers.received_chain.length - 1 && (
                  <span className="text-lg text-[var(--text-muted)]" aria-hidden>
                    →
                  </span>
                )}
              </div>
            ))}
          </div>
        </div>
      )}
    </section>
  );
}
