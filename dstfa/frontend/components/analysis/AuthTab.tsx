"use client";

import { useMemo, useState } from "react";

type Props = {
  authentication: Record<string, unknown>;
};

function asString(v: unknown): string {
  return typeof v === "string" ? v : "";
}

function asBool(v: unknown): boolean {
  return typeof v === "boolean" ? v : false;
}

function asNum(v: unknown): number {
  return typeof v === "number" && !Number.isNaN(v) ? v : 0;
}

function asRecord(v: unknown): Record<string, unknown> {
  return v && typeof v === "object" && !Array.isArray(v) ? (v as Record<string, unknown>) : {};
}

type Tone = "pass" | "fail" | "warn" | "muted";

function spfTone(result: string): Tone {
  const r = result.toLowerCase();
  if (r === "pass") return "pass";
  if (r === "fail") return "fail";
  if (r === "softfail" || r === "permerror" || r === "temperror") return "warn";
  return "muted";
}

function dkimTone(result: string): Tone {
  const r = result.toLowerCase();
  if (r === "pass") return "pass";
  if (r === "fail") return "fail";
  if (r === "temperror" || r === "permerror") return "warn";
  return "muted";
}

function dmarcTone(result: string): Tone {
  const r = result.toLowerCase();
  if (r === "pass") return "pass";
  if (r === "fail") return "fail";
  return "muted";
}

/** ARC: pass when absent (nothing to validate) or seals present and cryptographically valid. */
function arcTone(present: boolean, chainValid: boolean): Tone {
  if (!present) return "muted";
  if (chainValid) return "pass";
  return "fail";
}

function arcResultLabel(present: boolean, chainValid: boolean): string {
  if (!present) return "none";
  return chainValid ? "pass" : "fail";
}

function badgeClasses(tone: Tone): string {
  if (tone === "pass") return "border-emerald-500/60 bg-emerald-500/10 text-emerald-300";
  if (tone === "fail") return "border-rose-500/60 bg-rose-500/10 text-rose-300";
  if (tone === "warn") return "border-[var(--warning)]/60 bg-[var(--warning)]/10 text-[var(--warning)]";
  return "border-[var(--border)] bg-[var(--bg-tertiary)] text-[var(--text-muted)]";
}

function keySizeTone(bits: number): Tone {
  if (bits >= 2048) return "pass";
  if (bits >= 1024) return "warn";
  if (bits > 0) return "fail";
  return "muted";
}

function DetailRow({ k, v }: { k: string; v: string }) {
  return (
    <div className="flex justify-between gap-3 border-b border-[var(--border)]/60 py-1.5 text-xs last:border-0">
      <span className="text-[var(--text-muted)]">{k}</span>
      <span className="max-w-[65%] break-all text-right font-[family-name:var(--font-jetbrains)] text-[var(--text-primary)]">
        {v || "—"}
      </span>
    </div>
  );
}

function ResultBadge({ label, tone }: { label: string; tone: Tone }) {
  const pulse = tone === "pass" || tone === "fail";
  return (
    <span
      className={`inline-flex items-center gap-2 rounded-full border px-3 py-1 text-xs font-semibold uppercase tracking-wide ${badgeClasses(tone)}`}
    >
      <span
        className={`h-2 w-2 rounded-full ${tone === "pass" ? "bg-emerald-400" : tone === "fail" ? "bg-rose-400" : "bg-[var(--text-muted)]"} ${pulse ? "animate-pulse" : ""}`}
        aria-hidden
      />
      {label}
    </span>
  );
}

export function AuthTab({ authentication }: Props) {
  const spf = asRecord(authentication.spf);
  const dkim = asRecord(authentication.dkim);
  const dmarc = asRecord(authentication.dmarc);
  const arc = asRecord(authentication.arc);

  const [openSpf, setOpenSpf] = useState(false);
  const [openDkim, setOpenDkim] = useState(false);
  const [openDmarc, setOpenDmarc] = useState(false);
  const [openArc, setOpenArc] = useState(false);

  const spfResult = asString(spf.result) || "none";
  const dkimResult = asString(dkim.result) || "none";
  const dmarcResult = asString(dmarc.result) || "none";
  const arcPresent = asBool(arc.present);
  const arcChainValid = asBool(arc.chain_valid);
  const arcLabel = arcResultLabel(arcPresent, arcChainValid);

  const summary = useMemo(() => {
    let passed = 0;
    const total = 4;
    if (spfResult === "pass") passed += 1;
    if (dkimResult === "pass") passed += 1;
    if (dmarcResult === "pass") passed += 1;
    if (!arcPresent || arcChainValid) passed += 1;
    const pct = Math.round((passed / total) * 100);
    return { passed, total, pct };
  }, [spfResult, dkimResult, dmarcResult, arcPresent, arcChainValid]);

  const barColor =
    summary.passed === summary.total
      ? "bg-emerald-500/80"
      : summary.passed === 0
        ? "bg-rose-500/70"
        : "bg-[var(--warning)]/80";

  const dkimBits = asNum(dkim.key_size_bits);
  const algo = asString(dkim.algorithm);

  return (
    <section className="space-y-6">
      <div className="rounded-xl border border-[var(--border)] bg-[var(--bg-secondary)] p-4">
        <div className="mb-2 flex flex-wrap items-center justify-between gap-2">
          <h2 className="font-[family-name:var(--font-space)] text-sm font-semibold text-[var(--text-primary)]">
            Authentication summary
          </h2>
          <span className="font-[family-name:var(--font-jetbrains)] text-xs text-[var(--text-muted)]">
            {summary.passed}/{summary.total} checks passed
          </span>
        </div>
        <div className="h-2 w-full overflow-hidden rounded-full bg-[var(--bg-tertiary)]">
          <div className={`h-full rounded-full transition-all ${barColor}`} style={{ width: `${summary.pct}%` }} />
        </div>
      </div>

      <div className="grid gap-4 sm:grid-cols-2">
        {/* SPF */}
        <div className="rounded-xl border border-[var(--border)] bg-[var(--bg-secondary)] p-4 shadow-[0_0_20px_rgba(0,212,255,0.04)]">
          <div className="mb-3 flex flex-wrap items-center justify-between gap-2">
            <h3 className="text-xs font-semibold uppercase tracking-wide text-[var(--accent-primary)]">SPF</h3>
            <ResultBadge label={spfResult} tone={spfTone(spfResult)} />
          </div>
          <p className="mb-1 font-[family-name:var(--font-jetbrains)] text-xs text-[var(--text-primary)]">
            <span className="text-[var(--text-muted)]">Domain </span>
            {asString(spf.domain) || "—"}
          </p>
          <p className="mb-2 font-[family-name:var(--font-jetbrains)] text-xs text-[var(--text-primary)]">
            <span className="text-[var(--text-muted)]">IP </span>
            {asString(spf.ip) || "—"}
          </p>
          <button
            type="button"
            onClick={() => setOpenSpf((o) => !o)}
            className="mb-2 text-xs text-[var(--accent-primary)] hover:underline"
          >
            {openSpf ? "Hide details" : "Details"}
          </button>
          {openSpf && (
            <div className="mb-2 rounded-lg border border-[var(--border)] bg-[var(--bg-tertiary)] p-2">
              <DetailRow k="result" v={spfResult} />
              <DetailRow k="domain" v={asString(spf.domain)} />
              <DetailRow k="ip" v={asString(spf.ip)} />
            </div>
          )}
          <p className="text-sm italic leading-relaxed text-[var(--text-muted)]">{asString(spf.explanation)}</p>
        </div>

        {/* DKIM */}
        <div className="rounded-xl border border-[var(--border)] bg-[var(--bg-secondary)] p-4 shadow-[0_0_20px_rgba(0,212,255,0.04)]">
          <div className="mb-3 flex flex-wrap items-center justify-between gap-2">
            <h3 className="text-xs font-semibold uppercase tracking-wide text-[var(--accent-primary)]">DKIM</h3>
            <ResultBadge label={dkimResult} tone={dkimTone(dkimResult)} />
          </div>
          <div className="mb-2 flex flex-wrap gap-2">
            {algo ? (
              <span
                className={`rounded-md border px-2 py-0.5 font-[family-name:var(--font-jetbrains)] text-[10px] uppercase ${badgeClasses(algo.toLowerCase().includes("sha1") ? "warn" : "muted")}`}
              >
                {algo}
              </span>
            ) : null}
            {dkimBits > 0 ? (
              <span className={`rounded-md border px-2 py-0.5 font-[family-name:var(--font-jetbrains)] text-[10px] ${badgeClasses(keySizeTone(dkimBits))}`}>
                {dkimBits} bits
              </span>
            ) : null}
          </div>
          <p className="mb-1 font-[family-name:var(--font-jetbrains)] text-xs text-[var(--text-primary)]">
            <span className="text-[var(--text-muted)]">d= </span>
            {asString(dkim.domain) || "—"}
          </p>
          <p className="mb-2 font-[family-name:var(--font-jetbrains)] text-xs text-[var(--text-primary)]">
            <span className="text-[var(--text-muted)]">s= </span>
            {asString(dkim.selector) || "—"}
          </p>
          <button
            type="button"
            onClick={() => setOpenDkim((o) => !o)}
            className="mb-2 text-xs text-[var(--accent-primary)] hover:underline"
          >
            {openDkim ? "Hide details" : "Details"}
          </button>
          {openDkim && (
            <div className="mb-2 rounded-lg border border-[var(--border)] bg-[var(--bg-tertiary)] p-2">
              <DetailRow k="body_hash (bh)" v={asString(dkim.body_hash)} />
              <DetailRow k="signature_valid" v={String(asBool(dkim.signature_valid))} />
              <DetailRow k="key_size_bits" v={String(dkimBits)} />
            </div>
          )}
          <p className="text-sm italic leading-relaxed text-[var(--text-muted)]">{asString(dkim.explanation)}</p>
        </div>

        {/* DMARC */}
        <div className="rounded-xl border border-[var(--border)] bg-[var(--bg-secondary)] p-4 shadow-[0_0_20px_rgba(0,212,255,0.04)]">
          <div className="mb-3 flex flex-wrap items-center justify-between gap-2">
            <h3 className="text-xs font-semibold uppercase tracking-wide text-[var(--accent-primary)]">DMARC</h3>
            <ResultBadge label={dmarcResult} tone={dmarcTone(dmarcResult)} />
          </div>
          <p className="mb-1 font-[family-name:var(--font-jetbrains)] text-xs text-[var(--text-primary)]">
            <span className="text-[var(--text-muted)]">Policy </span>
            {asString(dmarc.policy) || "none"}
          </p>
          <p className="mb-2 text-xs text-[var(--text-muted)]">
            SPF align: <span className="text-[var(--text-primary)]">{asString(dmarc.alignment_spf) || "—"}</span>
            {" · "}
            DKIM align: <span className="text-[var(--text-primary)]">{asString(dmarc.alignment_dkim) || "—"}</span>
          </p>
          <button
            type="button"
            onClick={() => setOpenDmarc((o) => !o)}
            className="mb-2 text-xs text-[var(--accent-primary)] hover:underline"
          >
            {openDmarc ? "Hide details" : "Details"}
          </button>
          {openDmarc && (
            <div className="mb-2 rounded-lg border border-[var(--border)] bg-[var(--bg-tertiary)] p-2">
              <DetailRow k="result" v={dmarcResult} />
              <DetailRow k="policy" v={asString(dmarc.policy)} />
              <DetailRow k="alignment_spf" v={asString(dmarc.alignment_spf)} />
              <DetailRow k="alignment_dkim" v={asString(dmarc.alignment_dkim)} />
            </div>
          )}
          <p className="text-sm italic leading-relaxed text-[var(--text-muted)]">{asString(dmarc.explanation)}</p>
        </div>

        {/* ARC */}
        <div className="rounded-xl border border-[var(--border)] bg-[var(--bg-secondary)] p-4 shadow-[0_0_20px_rgba(0,212,255,0.04)]">
          <div className="mb-3 flex flex-wrap items-center justify-between gap-2">
            <h3 className="text-xs font-semibold uppercase tracking-wide text-[var(--accent-primary)]">ARC</h3>
            <div className="flex flex-wrap items-center gap-2">
              <span className="rounded-full border border-[var(--border)] bg-[var(--bg-tertiary)] px-2 py-0.5 font-[family-name:var(--font-jetbrains)] text-[10px] text-[var(--text-primary)]">
                instances: {asNum(arc.instance_count)}
              </span>
              <span
                className={`text-lg leading-none ${arcChainValid ? "text-emerald-400" : arcPresent ? "text-rose-400" : "text-[var(--text-muted)]"}`}
                title={arcChainValid ? "ARC chain valid" : arcPresent ? "ARC chain invalid" : "No ARC chain"}
                aria-hidden
              >
                {arcChainValid ? "✓" : arcPresent ? "✗" : "—"}
              </span>
              <ResultBadge label={arcLabel} tone={arcTone(arcPresent, arcChainValid)} />
            </div>
          </div>
          <p className="mb-2 font-[family-name:var(--font-jetbrains)] text-xs text-[var(--text-primary)]">
            <span className="text-[var(--text-muted)]">Present </span>
            {asBool(arc.present) ? "yes" : "no"}
          </p>
          <button
            type="button"
            onClick={() => setOpenArc((o) => !o)}
            className="mb-2 text-xs text-[var(--accent-primary)] hover:underline"
          >
            {openArc ? "Hide details" : "Details"}
          </button>
          {openArc && (
            <div className="mb-2 rounded-lg border border-[var(--border)] bg-[var(--bg-tertiary)] p-2">
              <DetailRow k="present" v={String(asBool(arc.present))} />
              <DetailRow k="chain_valid" v={String(asBool(arc.chain_valid))} />
              <DetailRow k="instance_count" v={String(asNum(arc.instance_count))} />
            </div>
          )}
          <p className="text-sm italic leading-relaxed text-[var(--text-muted)]">{asString(arc.explanation)}</p>
        </div>
      </div>
    </section>
  );
}
