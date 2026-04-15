"use client";

import type { ReactNode } from "react";
import { useMemo, useState } from "react";

export type MerkleDamgardBlock = {
  block_index: number;
  block_hex: string;
  input_chaining_vars: string[];
  output_chaining_vars: string[];
  rounds_summary: string;
};

export type MerkleDamgardSteps = {
  algorithm: string;
  original_message_length: number;
  padded_message_length: number;
  padding_explanation: string;
  blocks: MerkleDamgardBlock[];
  final_hash: string;
};

type Props = {
  steps: MerkleDamgardSteps | null | undefined;
  syllabusMode?: boolean;
};

function hexFromBlocks(blocks: MerkleDamgardBlock[]): Uint8Array {
  const out: number[] = [];
  for (const b of blocks) {
    const hex = b.block_hex.replace(/\s+/g, "");
    for (let i = 0; i < hex.length; i += 2) {
      out.push(parseInt(hex.slice(i, i + 2), 16));
    }
  }
  return new Uint8Array(out);
}

function chunkHex(hex: string, group = 16): string[] {
  const clean = hex.replace(/\s+/g, "");
  const lines: string[] = [];
  for (let i = 0; i < clean.length; i += group) {
    lines.push(clean.slice(i, i + group));
  }
  return lines;
}

/** First `maxBytes` of padded message as hex token spans with highlight classes. */
function PaddedPreview({
  padded,
  origByteLen,
  maxBytes = 32,
}: {
  padded: Uint8Array;
  origByteLen: number;
  maxBytes?: number;
}) {
  const n = Math.min(maxBytes, padded.length);
  const lenStart = Math.max(0, padded.length - 8);
  const cells: ReactNode[] = [];
  for (let i = 0; i < n; i++) {
    const hx = padded[i].toString(16).padStart(2, "0");
    let cls = "text-[var(--terminal-text)]";
    if (i === origByteLen) {
      cls = "text-[var(--accent-primary)] font-semibold";
    } else if (i >= lenStart) {
      cls = "text-[var(--warning)] font-semibold";
    }
    cells.push(
      <span key={i} className={cls}>
        {hx}
        {i + 1 < n ? " " : ""}
      </span>,
    );
  }
  return (
    <code className="font-[family-name:var(--font-jetbrains)] text-[11px] leading-relaxed break-all">{cells}</code>
  );
}

export function MerkleDamgardViz({ steps, syllabusMode = false }: Props) {
  const [accordionOpen, setAccordionOpen] = useState(false);

  const padded = useMemo(() => (steps?.blocks?.length ? hexFromBlocks(steps.blocks) : null), [steps]);

  const isMd5 = steps?.algorithm?.toUpperCase().includes("MD5");

  if (!steps || !steps.blocks.length || !padded) {
    return (
      <p className="text-sm text-[var(--text-muted)]">
        No Merkle–Damgård trace (empty body or steps not computed).
      </p>
    );
  }

  const origBytes = steps.original_message_length;
  const charNote =
    origBytes > 0 ? ` (${origBytes} UTF-8 code units if body was stored as UTF-8 text)` : "";

  return (
    <div className="relative flex gap-0 overflow-hidden rounded-xl border border-[var(--border)] bg-[var(--bg-tertiary)]">
      <div className="min-w-0 flex-1 p-4">
        <details
          open={accordionOpen}
          onToggle={(e) => setAccordionOpen(e.currentTarget.open)}
          className="group"
        >
          <summary className="mb-3 cursor-pointer list-none font-[family-name:var(--font-space)] text-sm font-semibold text-[var(--accent-primary)]">
            Show Merkle-Damgård Construction Step by Step
            <span className="ml-2 text-[var(--text-muted)]">▸</span>
          </summary>

          <div className="space-y-4">
            <article className="rounded-lg border border-[var(--border)] bg-[var(--bg-secondary)] p-3">
              <h4 className="mb-1 text-xs font-semibold uppercase tracking-wide text-[var(--text-muted)]">
                Step 0 — Original message
              </h4>
              <p className="text-sm text-[var(--text-primary)]">
                <span className="font-[family-name:var(--font-jetbrains)] text-[var(--accent-secondary)]">
                  {origBytes}
                </span>{" "}
                bytes long
                <span className="text-[var(--text-muted)]">{charNote}</span>
              </p>
            </article>

            <article className="rounded-lg border border-[var(--border)] bg-[var(--bg-secondary)] p-3">
              <h4 className="mb-1 text-xs font-semibold uppercase tracking-wide text-[var(--text-muted)]">
                Step 1 — Padding
              </h4>
              <p className="mb-2 text-xs leading-relaxed text-[var(--text-muted)]">{steps.padding_explanation}</p>
              <p className="mb-1 text-[10px] font-medium uppercase text-[var(--text-muted)]">
                First 32 bytes of padded message (hex)
              </p>
              <div className="rounded-md bg-[var(--terminal-bg)] p-2">
                <PaddedPreview padded={padded} origByteLen={origBytes} maxBytes={32} />
              </div>
              <p className="mt-2 text-[10px] text-[var(--text-muted)]">
                <span className="text-[var(--accent-primary)]">Cyan</span>: 0x80 delimiter ·{" "}
                <span className="text-[var(--warning)]">Amber</span>: 64-bit length suffix (may extend past this
                preview)
              </p>
            </article>

            <div className="space-y-3">
              <h4 className="text-xs font-semibold uppercase tracking-wide text-[var(--text-muted)]">
                Compression blocks
              </h4>
              {steps.blocks.map((b) => {
                const isSha256 = b.input_chaining_vars.length === 8;
                return (
                  <article
                    key={b.block_index}
                    className="rounded-lg border border-[var(--border)] bg-[var(--bg-secondary)] p-3"
                  >
                    <div className="mb-2 flex flex-wrap items-center gap-2">
                      <span className="rounded-md bg-[var(--bg-tertiary)] px-2 py-0.5 font-[family-name:var(--font-jetbrains)] text-xs text-[var(--accent-secondary)]">
                        Block {b.block_index}
                      </span>
                      <span className="text-[10px] text-[var(--text-muted)]">512-bit input</span>
                    </div>

                    <div className="mb-3 max-h-32 overflow-auto rounded-md bg-[var(--terminal-bg)] p-2">
                      <pre className="font-[family-name:var(--font-jetbrains)] text-[10px] leading-snug text-[var(--terminal-text)]">
                        {chunkHex(b.block_hex, 32).join("\n")}
                      </pre>
                    </div>

                    <div className="flex flex-col gap-3 lg:flex-row lg:items-stretch lg:justify-between">
                      <div className="min-w-0 flex-1 rounded-md border border-[var(--border)] bg-[var(--bg-primary)] p-2">
                        <p className="mb-1 text-[10px] font-medium text-[var(--text-muted)]">Input chaining</p>
                        <div
                          className={`grid gap-1 ${isSha256 ? "grid-cols-4 sm:grid-cols-8" : "grid-cols-2 sm:grid-cols-4"}`}
                        >
                          {b.input_chaining_vars.map((v, i) => (
                            <code
                              key={`in-${i}`}
                              className="break-all font-[family-name:var(--font-jetbrains)] text-[10px] text-[var(--text-primary)]"
                            >
                              {v}
                            </code>
                          ))}
                        </div>
                      </div>

                      <div className="flex shrink-0 items-center justify-center px-2 text-[var(--text-muted)]">
                        <span className="hidden lg:inline" aria-hidden>
                          →
                        </span>
                        <span className="lg:hidden" aria-hidden>
                          ↓
                        </span>
                      </div>

                      <div
                        className="shrink-0 rounded-md border border-[var(--border)] bg-[var(--bg-tertiary)] px-3 py-2 text-center"
                        title={b.rounds_summary}
                      >
                        <p className="text-[10px] font-semibold uppercase text-[var(--text-muted)]">Compression</p>
                        <p className="mt-1 max-w-[140px] text-[10px] leading-snug text-[var(--text-primary)]">
                          {isSha256 ? "SHA-256 mix" : "MD5 mix"}
                        </p>
                      </div>

                      <div className="flex shrink-0 items-center justify-center px-2 text-[var(--text-muted)]">
                        <span className="hidden lg:inline" aria-hidden>
                          →
                        </span>
                        <span className="lg:hidden" aria-hidden>
                          ↓
                        </span>
                      </div>

                      <div className="min-w-0 flex-1 rounded-md border border-[var(--border)] bg-[var(--bg-primary)] p-2">
                        <p className="mb-1 text-[10px] font-medium text-[var(--text-muted)]">Output chaining</p>
                        <div
                          className={`grid gap-1 ${isSha256 ? "grid-cols-4 sm:grid-cols-8" : "grid-cols-2 sm:grid-cols-4"}`}
                        >
                          {b.output_chaining_vars.map((v, i) => (
                            <code
                              key={`out-${i}`}
                              className="break-all font-[family-name:var(--font-jetbrains)] text-[10px] text-[var(--accent-primary)]"
                            >
                              {v}
                            </code>
                          ))}
                        </div>
                      </div>
                    </div>

                    <p className="mt-2 text-[10px] text-[var(--text-muted)]">{b.rounds_summary}</p>
                  </article>
                );
              })}
            </div>

            <footer className="rounded-lg border border-[var(--border)] bg-[var(--bg-primary)] px-3 py-3">
              <span className="text-xs text-[var(--text-muted)]">Final digest </span>
              <code
                className={`break-all font-[family-name:var(--font-jetbrains)] text-sm ${isMd5 ? "text-[var(--danger)]" : "text-[var(--success)]"}`}
              >
                {steps.final_hash}
              </code>
            </footer>
          </div>
        </details>
      </div>

      {syllabusMode ? (
        <aside
          className="hidden w-10 shrink-0 border-l border-[var(--accent-primary)] bg-[var(--bg-primary)] shadow-[inset_0_0_12px_rgba(0,212,255,0.08)] sm:flex sm:items-center sm:justify-center sm:px-1"
          aria-label="Syllabus context"
        >
          <span className="select-none font-[family-name:var(--font-space)] text-[9px] font-semibold uppercase leading-tight tracking-widest text-[var(--accent-primary)] [writing-mode:vertical-rl]">
            Unit 4 — Merkle-Damgård Construction
          </span>
        </aside>
      ) : null}
    </div>
  );
}
