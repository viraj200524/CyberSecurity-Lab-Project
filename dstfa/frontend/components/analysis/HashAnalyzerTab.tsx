"use client";

import { useCallback, useState } from "react";
import { Copy } from "lucide-react";

import { MerkleDamgardViz, type MerkleDamgardSteps } from "@/components/visualizers/MerkleDamgardViz";

type HashBody = {
  sha256?: string;
  md5?: string;
  sha1?: string;
};

type HashAttachment = {
  filename?: string;
  sha256?: string;
  md5?: string;
  size_bytes?: number;
};

type VulnerabilityFlags = {
  md5_detected?: boolean;
  sha1_detected?: boolean;
  length_extension_risk?: boolean;
  weak_hash_explanation?: string;
};

type HashesPayload = {
  body?: HashBody;
  attachments?: HashAttachment[];
  merkle_damgard_steps?: MerkleDamgardSteps | null;
  vulnerability_flags?: VulnerabilityFlags;
};

type Props = {
  hashes: Record<string, unknown> | HashesPayload;
};

function asString(v: unknown): string {
  return typeof v === "string" ? v : "";
}

async function copyText(value: string) {
  if (!value) return;
  try {
    await navigator.clipboard.writeText(value);
  } catch {
    /* ignore */
  }
}

function HashCard({
  title,
  value,
  variant,
}: {
  title: string;
  value: string;
  variant: "sha256" | "md5" | "sha1";
}) {
  const [copied, setCopied] = useState(false);
  const border =
    variant === "sha256"
      ? "border-[var(--success)] shadow-[0_0_16px_rgba(0,255,136,0.06)]"
      : variant === "md5"
        ? "border-[var(--danger)] shadow-[0_0_16px_rgba(255,56,96,0.08)]"
        : "border-[var(--warning)] shadow-[0_0_12px_rgba(255,184,0,0.08)]";
  const titleColor =
    variant === "sha256"
      ? "text-[var(--success)]"
      : variant === "md5"
        ? "text-[var(--danger)]"
        : "text-[var(--warning)]";

  const onCopy = useCallback(() => {
    void copyText(value).then(() => {
      setCopied(true);
      window.setTimeout(() => setCopied(false), 1500);
    });
  }, [value]);

  return (
    <div className={`rounded-lg border-2 ${border} bg-[var(--bg-tertiary)] p-3`}>
      <div className="mb-2 flex items-center justify-between gap-2">
        <div className="flex items-center gap-2">
          <span className={`text-xs font-semibold uppercase tracking-wide ${titleColor}`}>{title}</span>
          {variant === "md5" && (
            <span className="rounded px-1.5 py-0.5 text-[10px] font-bold uppercase text-[var(--danger)] ring-1 ring-[var(--danger)]">
              ⚠ WEAK
            </span>
          )}
        </div>
        <button
          type="button"
          onClick={onCopy}
          disabled={!value}
          aria-label={`Copy ${title}`}
          className="inline-flex items-center gap-1 rounded-md border border-[var(--border)] px-2 py-1 text-xs text-[var(--text-muted)] hover:border-[var(--accent-primary)] hover:text-[var(--accent-primary)] disabled:opacity-40"
        >
          <Copy className="size-3.5 shrink-0" aria-hidden />
          {copied ? "Copied" : "Copy"}
        </button>
      </div>
      <p className="break-all font-[family-name:var(--font-jetbrains)] text-xs text-[var(--text-primary)]">
        {value || "—"}
      </p>
    </div>
  );
}

export function HashAnalyzerTab({ hashes }: Props) {
  const h = hashes as HashesPayload;
  const body = h.body ?? {};
  const flags = h.vulnerability_flags ?? {};
  const attachments = Array.isArray(h.attachments) ? h.attachments : [];
  const steps = h.merkle_damgard_steps as MerkleDamgardSteps | null | undefined;

  const md5Banner = Boolean(flags.md5_detected);

  return (
    <section className="space-y-6">
      {md5Banner && (
        <div
          className="rounded-xl border-2 border-[var(--danger)]/70 bg-[var(--bg-secondary)] p-4"
          style={{ boxShadow: "0 0 20px rgba(255, 56, 96, 0.12)" }}
          role="alert"
        >
          <h3 className="mb-1 text-sm font-semibold text-[var(--danger)]">MD5 / legacy digest on message body</h3>
          <p className="text-sm leading-relaxed text-[var(--text-muted)]">
            {flags.weak_hash_explanation ||
              "MD5 is cryptographically broken for collision resistance; SHA-1 is deprecated. Do not rely on either for integrity in new systems."}
          </p>
          {flags.length_extension_risk && (
            <p className="mt-2 text-xs text-[var(--warning)]">
              Length-extension class risks apply to naive Merkle–Damgård MACs built from MD5 or SHA-1 (use HMAC or a
              modern primitive).
            </p>
          )}
          <p className="mt-3 text-xs text-[var(--text-muted)]">
            Interactive collision / length-extension lab (Vulnerability tab) ships in Phase 6.
          </p>
        </div>
      )}

      <div>
        <h3 className="mb-3 font-[family-name:var(--font-space)] text-sm text-[var(--text-muted)]">Message body</h3>
        <div className="grid gap-3 md:grid-cols-3">
          <HashCard title="SHA-256" value={asString(body.sha256)} variant="sha256" />
          <HashCard title="MD5" value={asString(body.md5)} variant="md5" />
          <HashCard title="SHA-1" value={asString(body.sha1)} variant="sha1" />
        </div>
      </div>

      <div>
        <h3 className="mb-3 font-[family-name:var(--font-space)] text-sm text-[var(--text-muted)]">Attachments</h3>
        {attachments.length === 0 ? (
          <p className="text-sm text-[var(--text-muted)]">No attachments in this message.</p>
        ) : (
          <details className="group rounded-xl border border-[var(--border)] bg-[var(--bg-secondary)]">
            <summary className="cursor-pointer list-none px-4 py-3 font-[family-name:var(--font-space)] text-sm text-[var(--accent-primary)]">
              {attachments.length} attachment{attachments.length === 1 ? "" : "s"}
              <span className="ml-2 text-[var(--text-muted)]">▸</span>
            </summary>
            <div className="overflow-x-auto border-t border-[var(--border)]">
              <table className="min-w-full border-collapse text-left text-sm">
                <thead className="bg-[var(--bg-tertiary)] font-[family-name:var(--font-jetbrains)] text-xs uppercase text-[var(--text-muted)]">
                  <tr>
                    <th className="px-3 py-2">File</th>
                    <th className="px-3 py-2">Size</th>
                    <th className="px-3 py-2">SHA-256</th>
                    <th className="px-3 py-2">MD5</th>
                  </tr>
                </thead>
                <tbody>
                  {attachments.map((row, i) => (
                    <tr key={`${row.filename ?? "f"}-${i}`} className="border-t border-[var(--border)] bg-[var(--bg-secondary)]">
                      <td className="px-3 py-2 text-[var(--text-primary)]">{row.filename || "—"}</td>
                      <td className="px-3 py-2 font-[family-name:var(--font-jetbrains)] text-xs text-[var(--text-muted)]">
                        {row.size_bytes ?? "—"}
                      </td>
                      <td className="max-w-[220px] px-3 py-2">
                        <code className="break-all font-[family-name:var(--font-jetbrains)] text-[11px] text-[var(--terminal-text)]">
                          {asString(row.sha256)}
                        </code>
                      </td>
                      <td className="max-w-[220px] px-3 py-2">
                        <code className="break-all font-[family-name:var(--font-jetbrains)] text-[11px] text-[var(--text-muted)]">
                          {asString(row.md5)}
                        </code>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </details>
        )}
      </div>

      <div>
        <h3 className="mb-3 font-[family-name:var(--font-space)] text-sm text-[var(--text-muted)]">
          SHA-256 Merkle–Damgård (body)
        </h3>
        <MerkleDamgardViz steps={steps} />
      </div>
    </section>
  );
}
