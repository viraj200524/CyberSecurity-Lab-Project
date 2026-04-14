"use client";

import type { AnalysisResult } from "@/lib/types";

type Props = {
  result: AnalysisResult;
};

export function OverviewPanel({ result }: Props) {
  const s = result.input_summary;
  const cards = [
    { label: "Subject", value: s.subject || "—" },
    { label: "From", value: s.from || "—" },
    { label: "To", value: (s.to && s.to.length ? s.to.join(", ") : "—") as string },
    { label: "Date", value: s.date || "—" },
    { label: "Message-ID", value: s.message_id || "—" },
    { label: "MIME parts", value: String(s.mime_parts ?? 0) },
  ];

  return (
    <section className="mb-8 grid gap-4 sm:grid-cols-2 lg:grid-cols-3">
      {cards.map((c) => (
        <div
          key={c.label}
          className="rounded-xl border border-[var(--border)] bg-[var(--bg-secondary)] p-4 shadow-[0_0_20px_rgba(0,212,255,0.05)]"
        >
          <p className="mb-1 text-xs uppercase tracking-wide text-[var(--text-muted)]">{c.label}</p>
          <p className="break-words text-sm text-[var(--text-primary)]">{c.value}</p>
        </div>
      ))}
    </section>
  );
}
