"use client";

import { useEffect, useMemo, useState } from "react";
import { motion } from "framer-motion";
import { AlertTriangle, BookOpen, Copy, Loader2, MapPin, RefreshCw } from "lucide-react";
import { toast } from "sonner";

type EntityExtraction = {
  senders?: string[];
  ips?: string[];
  domains?: string[];
  bitcoin_addresses?: string[];
  urls?: string[];
  iocs?: string[];
};

export type LLMInsightsShape = {
  model_used?: string;
  timestamp?: string;
  forensic_summary?: string;
  key_findings?: string[];
  threat_justification?: string;
  entity_extraction?: EntityExtraction;
  attack_vectors_detected?: string[];
  threat_level?: string;
  syllabus_links?: Array<{ concept?: string; unit?: string; explanation?: string; evidence_field?: string }>;
  timeline_reconstruction?: Array<{ timestamp?: string; event?: string; source?: string }>;
  chain_of_custody_log?: Record<string, unknown>;
};

function readInsights(raw: Record<string, unknown> | null | undefined): LLMInsightsShape {
  if (!raw || typeof raw !== "object") return {};
  return raw as LLMInsightsShape;
}

function threatEmoji(level: string): string {
  const l = level.toLowerCase();
  if (l === "critical") return "🔴";
  if (l === "high") return "🟠";
  if (l === "medium") return "🟡";
  return "🟢";
}

function findingIcon(text: string): string {
  const t = text.toLowerCase();
  if (/phish|spoof|reply-to|malicious/i.test(t)) return "🎣";
  if (/dkim|spf|dmarc|auth|arc/i.test(t)) return "🔑";
  if (/hash|md5|sha|merkle|crypto/i.test(t)) return "🔒";
  if (/ip|received|route|network/i.test(t)) return "📍";
  return "📌";
}

async function copyText(label: string, text: string) {
  try {
    await navigator.clipboard.writeText(text);
    toast.success(`Copied ${label}`);
  } catch {
    toast.error("Copy failed");
  }
}

export type LLMInsightsTabProps = {
  llmInsights: Record<string, unknown> | null | undefined;
  llmError: string | null | undefined;
  loading: boolean;
  runLlmRequested: boolean;
  onRetry: () => void;
};

export function LLMInsightsTab({
  llmInsights,
  llmError,
  loading,
  runLlmRequested,
  onRetry,
}: LLMInsightsTabProps) {
  const ins = useMemo(() => readInsights(llmInsights ?? undefined), [llmInsights]);
  const [dots, setDots] = useState("");

  useEffect(() => {
    if (!loading || !runLlmRequested) return;
    const id = setInterval(() => {
      setDots((d) => (d.length >= 3 ? "" : d + "."));
    }, 400);
    return () => clearInterval(id);
  }, [loading, runLlmRequested]);

  if (!runLlmRequested) {
    return (
      <section className="rounded-xl border border-[var(--border)] bg-[var(--bg-secondary)] p-6 text-center text-sm text-[var(--text-muted)]">
        <p>Turn on <strong className="text-[var(--text-primary)]">AI insights (Gemini)</strong> above, then analysis will include this tab.</p>
      </section>
    );
  }

  if (loading) {
    return (
      <section className="flex flex-col items-center justify-center gap-4 rounded-xl border border-[var(--border)] bg-[var(--bg-secondary)] px-6 py-16">
        <Loader2 className="h-10 w-10 animate-spin text-[var(--accent-primary)]" aria-hidden />
        <motion.p
          className="font-[family-name:var(--font-space)] text-sm text-[var(--accent-primary)]"
          animate={{ opacity: [0.6, 1, 0.6] }}
          transition={{ duration: 1.6, repeat: Infinity }}
        >
          Analyzing with Gemini 2.0 Flash{dots}
        </motion.p>
        <p className="max-w-md text-center text-xs text-[var(--text-muted)]">
          Structured forensic JSON is sent to the model; results are parsed into entities, threat level, and syllabus
          links.
        </p>
      </section>
    );
  }

  if (llmError) {
    return (
      <section className="rounded-xl border border-[var(--danger)]/40 bg-[var(--danger)]/10 p-6">
        <div className="flex flex-wrap items-start justify-between gap-4">
          <div>
            <h3 className="font-[family-name:var(--font-space)] text-lg text-[var(--danger)]">LLM analysis unavailable</h3>
            <p className="mt-2 font-[family-name:var(--font-jetbrains)] text-sm text-[var(--text-primary)]">{llmError}</p>
          </div>
          <button
            type="button"
            onClick={onRetry}
            className="inline-flex items-center gap-2 rounded-lg border border-[var(--border)] bg-[var(--bg-tertiary)] px-3 py-2 text-sm text-[var(--accent-primary)] hover:border-[var(--accent-primary)]"
          >
            <RefreshCw className="h-4 w-4" aria-hidden />
            Retry
          </button>
        </div>
      </section>
    );
  }

  if (!llmInsights || Object.keys(llmInsights).length === 0) {
    return (
      <section className="rounded-xl border border-[var(--border)] bg-[var(--bg-secondary)] p-6 text-center text-sm text-[var(--text-muted)]">
        No AI insights in this response.
      </section>
    );
  }

  const entities = ins.entity_extraction || {};
  const pills: { label: string; items: string[]; className: string }[] = [
    { label: "IPs", items: entities.ips || [], className: "bg-sky-500/15 text-sky-300 border-sky-500/30" },
    { label: "Domains", items: entities.domains || [], className: "bg-violet-500/15 text-violet-200 border-violet-500/30" },
    { label: "URLs", items: entities.urls || [], className: "bg-teal-500/15 text-teal-200 border-teal-500/30" },
    { label: "IoCs", items: entities.iocs || [], className: "bg-[var(--danger)]/15 text-[var(--danger)] border-[var(--danger)]/30" },
    {
      label: "Senders",
      items: entities.senders || [],
      className: "bg-[var(--bg-tertiary)] text-[var(--text-primary)] border-[var(--border)]",
    },
  ];

  const chain = ins.chain_of_custody_log || {};
  const promptHash = typeof chain.prompt_hash === "string" ? chain.prompt_hash : "";
  const hashShort = promptHash ? `${promptHash.slice(0, 8)}` : "—";

  return (
    <section className="space-y-8">
      <div className="rounded-xl border border-[var(--border)] bg-[var(--bg-secondary)] p-5">
        <div className="mb-3 flex flex-wrap items-center gap-3">
          <h3 className="font-[family-name:var(--font-space)] text-lg text-[var(--text-primary)]">Forensic summary</h3>
          <span className="rounded-md border border-[var(--border)] bg-[var(--bg-tertiary)] px-2 py-0.5 text-xs font-medium uppercase text-[var(--text-muted)]">
            {threatEmoji(ins.threat_level || "low")} {(ins.threat_level || "low").toUpperCase()}
          </span>
        </div>
        <p className="whitespace-pre-wrap text-sm leading-relaxed text-[var(--text-primary)]">{ins.forensic_summary || "—"}</p>
        {ins.threat_justification ? (
          <p className="mt-3 border-t border-[var(--border)] pt-3 text-xs italic text-[var(--text-muted)]">{ins.threat_justification}</p>
        ) : null}
      </div>

      {ins.key_findings && ins.key_findings.length > 0 && (
        <div>
          <h3 className="mb-3 font-[family-name:var(--font-space)] text-sm uppercase tracking-wide text-[var(--text-muted)]">
            Key findings
          </h3>
          <ol className="space-y-2">
            {ins.key_findings.map((f, i) => (
              <li
                key={i}
                className="flex gap-3 rounded-lg border border-[var(--border)] bg-[var(--bg-tertiary)] px-3 py-2 text-sm text-[var(--text-primary)]"
              >
                <span className="select-none text-lg" aria-hidden>
                  {findingIcon(f)}
                </span>
                <span>{f}</span>
              </li>
            ))}
          </ol>
        </div>
      )}

      <div>
        <h3 className="mb-3 font-[family-name:var(--font-space)] text-sm uppercase tracking-wide text-[var(--text-muted)]">
          Entity extraction
        </h3>
        <div className="flex flex-wrap gap-2">
          {pills.flatMap((group) =>
            group.items.map((item) => (
              <button
                key={`${group.label}-${item}`}
                type="button"
                onClick={() => void copyText(group.label, item)}
                className={`inline-flex max-w-full items-center gap-1 rounded-full border px-2.5 py-1 text-xs font-[family-name:var(--font-jetbrains)] ${group.className}`}
              >
                <span className="truncate">{item}</span>
                <Copy className="h-3 w-3 shrink-0 opacity-60" aria-hidden />
              </button>
            )),
          )}
          {entities.bitcoin_addresses?.map((b) => (
            <button
              key={b}
              type="button"
              onClick={() => void copyText("BTC", b)}
              className="inline-flex items-center gap-1 rounded-full border border-amber-500/30 bg-amber-500/10 px-2.5 py-1 text-xs text-amber-200"
            >
              {b}
              <Copy className="h-3 w-3 opacity-60" aria-hidden />
            </button>
          ))}
        </div>
      </div>

      {ins.attack_vectors_detected && ins.attack_vectors_detected.length > 0 && (
        <div>
          <h3 className="mb-3 font-[family-name:var(--font-space)] text-sm uppercase tracking-wide text-[var(--text-muted)]">
            Attack vectors
          </h3>
          <div className="space-y-2">
            {ins.attack_vectors_detected.map((v, i) => (
              <div
                key={i}
                className="flex gap-2 rounded-lg border border-[var(--warning)]/35 bg-[var(--warning)]/10 px-3 py-2 text-sm text-[var(--text-primary)]"
              >
                <AlertTriangle className="mt-0.5 h-4 w-4 shrink-0 text-[var(--warning)]" aria-hidden />
                {v}
              </div>
            ))}
          </div>
        </div>
      )}

      {ins.syllabus_links && ins.syllabus_links.length > 0 && (
        <div>
          <h3 className="mb-3 flex items-center gap-2 font-[family-name:var(--font-space)] text-sm uppercase tracking-wide text-[var(--text-muted)]">
            <BookOpen className="h-4 w-4 text-[var(--accent-primary)]" aria-hidden />
            Syllabus connections
          </h3>
          <div className="space-y-2">
            {ins.syllabus_links.map((link, i) => (
              <details
                key={i}
                className="group rounded-lg border border-[var(--border)] bg-[var(--bg-tertiary)] px-3 py-2"
              >
                <summary className="cursor-pointer list-none font-medium text-[var(--text-primary)]">
                  <span className="text-[var(--accent-secondary)]">{link.concept || "Concept"}</span>
                  {link.unit ? (
                    <span className="ml-2 rounded bg-[var(--accent-primary)]/15 px-1.5 py-0.5 text-[10px] text-[var(--accent-primary)]">
                      {link.unit}
                    </span>
                  ) : null}
                </summary>
                <p className="mt-2 text-sm text-[var(--text-muted)]">{link.explanation}</p>
                {link.evidence_field ? (
                  <code className="mt-2 block rounded bg-[var(--terminal-bg)] px-2 py-1 font-[family-name:var(--font-jetbrains)] text-xs text-[var(--terminal-text)]">
                    {link.evidence_field}
                  </code>
                ) : null}
              </details>
            ))}
          </div>
        </div>
      )}

      {ins.timeline_reconstruction && ins.timeline_reconstruction.length > 0 && (
        <div>
          <h3 className="mb-3 font-[family-name:var(--font-space)] text-sm uppercase tracking-wide text-[var(--text-muted)]">
            Timeline
          </h3>
          <ul className="relative space-y-4 border-l border-[var(--border)] pl-6">
            {ins.timeline_reconstruction.map((ev, i) => (
              <li key={i} className="relative">
                <span className="absolute -left-[9px] top-1.5 h-3 w-3 rounded-full bg-[var(--accent-primary)] ring-4 ring-[var(--bg-primary)]" />
                <div className="rounded-lg border border-[var(--border)] bg-[var(--bg-secondary)] p-3">
                  <p className="font-[family-name:var(--font-jetbrains)] text-xs text-[var(--accent-primary)]">
                    {ev.timestamp || "—"}
                  </p>
                  <p className="mt-1 text-sm text-[var(--text-primary)]">{ev.event || "—"}</p>
                  {ev.source ? (
                    <p className="mt-1 text-xs text-[var(--text-muted)]">
                      <MapPin className="mr-1 inline h-3 w-3" aria-hidden />
                      {ev.source}
                    </p>
                  ) : null}
                </div>
              </li>
            ))}
          </ul>
        </div>
      )}

      <footer className="rounded-lg border border-[var(--border)] bg-[var(--bg-tertiary)] px-4 py-3 text-xs text-[var(--text-muted)]">
        <p className="font-[family-name:var(--font-jetbrains)]">
          Chain of custody — model: <span className="text-[var(--text-primary)]">{ins.model_used || "—"}</span>
          {" · "}
          timestamp: <span className="text-[var(--text-primary)]">{ins.timestamp || "—"}</span>
          {" · "}
          prompt SHA-256: <span className="text-[var(--accent-primary)]">{hashShort}</span>
        </p>
        {typeof chain.confidence_note === "string" && chain.confidence_note ? (
          <p className="mt-2 text-[11px] leading-snug opacity-90">{chain.confidence_note}</p>
        ) : null}
      </footer>
    </section>
  );
}
