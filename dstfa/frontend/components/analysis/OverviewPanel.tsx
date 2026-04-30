"use client";

import type { AnalysisResult } from "@/lib/types";

type Props = {
  result: AnalysisResult;
};

function readAuth(obj: unknown, key: string): { result?: string } {
  if (!obj || typeof obj !== "object") return {};
  const a = (obj as Record<string, unknown>)[key];
  if (!a || typeof a !== "object") return {};
  const r = (a as Record<string, unknown>).result;
  return { result: typeof r === "string" ? r : undefined };
}

function readSig(obj: unknown, key: "pgp" | "smime"): { present?: boolean; valid?: boolean } {
  if (!obj || typeof obj !== "object") return {};
  const s = (obj as Record<string, unknown>)[key];
  if (!s || typeof s !== "object") return {};
  const o = s as Record<string, unknown>;
  return {
    present: o.present === true,
    valid: o.valid === true,
  };
}

function readHashFlags(hashes: AnalysisResult["hashes"]): { md5?: boolean } {
  if (!hashes || typeof hashes !== "object") return {};
  const vf = (hashes as Record<string, unknown>).vulnerability_flags;
  if (!vf || typeof vf !== "object") return {};
  return { md5: (vf as Record<string, unknown>).md5_detected === true };
}

function threatLevel(result: AnalysisResult): "low" | "medium" | "high" | "critical" {
  const li = result.llm_insights;
  if (li && typeof li === "object") {
    const raw = (li as Record<string, unknown>).threat_level;
    if (typeof raw === "string") {
      const t = raw.toLowerCase();
      if (t === "critical" || t === "high" || t === "medium" || t === "low") return t;
    }
  }
  const auth = result.authentication;
  const spf = readAuth(auth, "spf").result;
  const dkim = readAuth(auth, "dkim").result;
  const dmarc = readAuth(auth, "dmarc").result;
  const fails = [spf, dkim, dmarc].filter((x) => x === "fail").length;
  const md5 = readHashFlags(result.hashes).md5;
  if (md5 && fails >= 2) return "critical";
  if (md5 || fails >= 2) return "high";
  if (fails >= 1) return "medium";
  return "low";
}

function badgeClass(level: string): string {
  if (level === "critical") return "bg-[var(--danger)]/20 text-[var(--danger)] border-[var(--danger)]/40";
  if (level === "high") return "bg-[var(--danger)]/15 text-[var(--danger)] border-[var(--danger)]/30";
  if (level === "medium") return "bg-[var(--warning)]/15 text-[var(--warning)] border-[var(--warning)]/35";
  return "bg-[var(--success)]/15 text-[var(--success)] border-[var(--success)]/30";
}

export function OverviewPanel({ result }: Props) {
  const tl = threatLevel(result);
  const spf = readAuth(result.authentication, "spf").result ?? "—";
  const dkim = readAuth(result.authentication, "dkim").result ?? "—";
  const dmarc = readAuth(result.authentication, "dmarc").result ?? "—";
  const pgp = readSig(result.digital_signatures, "pgp");
  const smime = readSig(result.digital_signatures, "smime");
  const md5weak = readHashFlags(result.hashes).md5;
  const sha256 = (() => {
    const h = result.hashes;
    if (!h || typeof h !== "object") return "";
    const b = (h as Record<string, unknown>).body;
    if (!b || typeof b !== "object") return "";
    const v = (b as Record<string, unknown>).sha256;
    return typeof v === "string" ? v : "";
  })();

  const sigLine =
    pgp.valid || smime.valid
      ? `${pgp.valid ? "PGP ✓" : "PGP —"} · ${smime.valid ? "S/MIME ✓" : "S/MIME —"}`
      : pgp.present || smime.present
        ? "Present / not verified"
        : "Neither";

  const cards = [
    {
      title: "Threat level",
      body: (
        <span className={`inline-block rounded-md border px-2 py-1 text-xs font-semibold uppercase ${badgeClass(tl)}`}>
          {tl}
        </span>
      ),
    },
    {
      title: "Authentication",
      body: (
        <p className="font-[family-name:var(--font-jetbrains)] text-xs leading-relaxed text-[var(--text-primary)]">
          SPF <span className="text-[var(--accent-primary)]">{spf}</span>
          {" · "}
          DKIM <span className="text-[var(--accent-primary)]">{dkim}</span>
          {" · "}
          DMARC <span className="text-[var(--accent-primary)]">{dmarc}</span>
        </p>
      ),
    },
    {
      title: "Signatures",
      body: <p className="text-sm text-[var(--text-primary)]">{sigLine}</p>,
    },
    {
      title: "Hash status",
      body: (
        <div className="space-y-1">
          <p className="font-[family-name:var(--font-jetbrains)] text-xs text-[var(--success)]">
            SHA-256 {sha256 ? "✓" : "—"}
          </p>
          {md5weak ? (
            <p className="text-xs text-[var(--danger)]">MD5 ⚠ weak — collision demos available</p>
          ) : (
            <p className="text-xs text-[var(--text-muted)]">MD5 (empty body)</p>
          )}
        </div>
      ),
    },
  ];

  return (
    <section className="mb-8 space-y-4">
      <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-4">
        {cards.map((c) => (
          <div
            key={c.title}
            className="rounded-xl border border-[var(--border)] bg-[var(--bg-secondary)] p-4 shadow-[0_0_20px_rgba(0,212,255,0.05)]"
          >
            <p className="mb-2 text-xs uppercase tracking-wide text-[var(--text-muted)]">{c.title}</p>
            {c.body}
          </div>
        ))}
      </div>
      <div className="rounded-xl border border-[var(--border)] bg-[var(--bg-tertiary)]/60 p-4">
        <p className="mb-2 text-xs uppercase tracking-wide text-[var(--text-muted)]">Message</p>
        <p className="text-sm text-[var(--text-primary)]">
          <span className="text-[var(--text-muted)]">Subject:</span> {result.input_summary.subject || "—"}
        </p>
        <p className="mt-1 text-sm text-[var(--text-primary)]">
          <span className="text-[var(--text-muted)]">From:</span> {result.input_summary.from || "—"}
        </p>
      </div>
    </section>
  );
}
