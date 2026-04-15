"use client";

import { ChevronDown, KeyRound, ShieldCheck, ShieldOff } from "lucide-react";
import { useMemo } from "react";

type PGPShape = {
  present: boolean;
  valid: boolean;
  key_id: string;
  fingerprint: string;
  algorithm: string;
  key_size: number;
  signer_uid: string;
  signature_date: string;
  trust_level: string;
  explanation: string;
};

type ChainLink = {
  level?: number;
  type?: string;
  subject?: string;
  issuer?: string;
  valid?: boolean;
};

type SMIMEShape = {
  present: boolean;
  valid: boolean;
  subject_cn: string;
  issuer_cn: string;
  valid_from: string;
  valid_to: string;
  serial_number: string;
  algorithm: string;
  chain: ChainLink[];
  explanation: string;
};

function asRecord(v: unknown): Record<string, unknown> {
  return v && typeof v === "object" ? (v as Record<string, unknown>) : {};
}

function readPGP(raw: unknown): PGPShape {
  const o = asRecord(raw);
  return {
    present: o.present === true,
    valid: o.valid === true,
    key_id: typeof o.key_id === "string" ? o.key_id : "",
    fingerprint: typeof o.fingerprint === "string" ? o.fingerprint : "",
    algorithm: typeof o.algorithm === "string" ? o.algorithm : "",
    key_size: typeof o.key_size === "number" ? o.key_size : 0,
    signer_uid: typeof o.signer_uid === "string" ? o.signer_uid : "",
    signature_date: typeof o.signature_date === "string" ? o.signature_date : "",
    trust_level: typeof o.trust_level === "string" ? o.trust_level : "none",
    explanation: typeof o.explanation === "string" ? o.explanation : "",
  };
}

function readSMIME(raw: unknown): SMIMEShape {
  const o = asRecord(raw);
  const chainRaw = o.chain;
  const chain: ChainLink[] = Array.isArray(chainRaw)
    ? chainRaw.map((row) => {
        const r = asRecord(row);
        return {
          level: typeof r.level === "number" ? r.level : undefined,
          type: typeof r.type === "string" ? r.type : undefined,
          subject: typeof r.subject === "string" ? r.subject : undefined,
          issuer: typeof r.issuer === "string" ? r.issuer : undefined,
          valid: r.valid === true,
        };
      })
    : [];
  return {
    present: o.present === true,
    valid: o.valid === true,
    subject_cn: typeof o.subject_cn === "string" ? o.subject_cn : "",
    issuer_cn: typeof o.issuer_cn === "string" ? o.issuer_cn : "",
    valid_from: typeof o.valid_from === "string" ? o.valid_from : "",
    valid_to: typeof o.valid_to === "string" ? o.valid_to : "",
    serial_number: typeof o.serial_number === "string" ? o.serial_number : "",
    algorithm: typeof o.algorithm === "string" ? o.algorithm : "",
    chain,
    explanation: typeof o.explanation === "string" ? o.explanation : "",
  };
}

function splitExplanation(explanation: string): { body: string; dsa: { r: string; s: string } | null } {
  const m = explanation.match(
    /__DSA_HEX__\s*\nr=([0-9a-fA-F]*)\s*\ns=([0-9a-fA-F]*)\s*\n__END_DSA__/m,
  );
  if (!m) return { body: explanation.trim(), dsa: null };
  const body = explanation.replace(/__DSA_HEX__[\s\S]*__END_DSA__/m, "").trim();
  return { body, dsa: { r: m[1] || "", s: m[2] || "" } };
}

function daysRemaining(iso: string): number | null {
  const t = Date.parse(iso);
  if (Number.isNaN(t)) return null;
  return Math.ceil((t - Date.now()) / 86400000);
}

function MetaTable({ rows }: { rows: { k: string; v: string }[] }) {
  return (
    <table className="w-full border-collapse text-left text-xs">
      <tbody>
        {rows.map(({ k, v }) => (
          <tr key={k} className="border-b border-[var(--border)] last:border-0">
            <th className="w-[38%] py-1.5 pr-2 align-top font-medium text-[var(--text-muted)]">{k}</th>
            <td className="py-1.5 font-[family-name:var(--font-jetbrains)] text-[var(--text-primary)] break-all">{v || "—"}</td>
          </tr>
        ))}
      </tbody>
    </table>
  );
}

function ValidityBadge({ valid, present, label }: { valid: boolean; present: boolean; label: string }) {
  if (!present) {
    return (
      <span className="inline-flex items-center gap-1 rounded-full bg-[var(--text-muted)]/25 px-2 py-0.5 text-xs text-[var(--text-muted)]">
        <ShieldOff className="h-3.5 w-3.5" aria-hidden />
        Absent
      </span>
    );
  }
  if (valid) {
    return (
      <span className="inline-flex items-center gap-1 rounded-full bg-[var(--success)]/15 px-2 py-0.5 text-xs text-[var(--success)]">
        <ShieldCheck className="h-3.5 w-3.5" aria-hidden />
        {label} valid
      </span>
    );
  }
  return (
    <span className="inline-flex items-center gap-1 rounded-full bg-[var(--danger)]/15 px-2 py-0.5 text-xs text-[var(--danger)]">
      <ShieldOff className="h-3.5 w-3.5" aria-hidden />
      Not verified
    </span>
  );
}

function AlgoBadge({ algorithm }: { algorithm: string }) {
  if (!algorithm) return null;
  return (
    <span className="rounded border border-[var(--accent-primary)]/40 bg-[var(--accent-primary)]/10 px-2 py-0.5 font-[family-name:var(--font-jetbrains)] text-[10px] uppercase tracking-wide text-[var(--accent-primary)]">
      {algorithm}
    </span>
  );
}

export type SignatureTabProps = {
  digitalSignatures?: Record<string, unknown> | null;
};

export function SignatureTab({ digitalSignatures }: SignatureTabProps) {
  const pgp = useMemo(() => readPGP(digitalSignatures?.pgp), [digitalSignatures]);
  const smime = useMemo(() => readSMIME(digitalSignatures?.smime), [digitalSignatures]);
  const pgpText = useMemo(() => splitExplanation(pgp.explanation), [pgp.explanation]);
  const smDays = daysRemaining(smime.valid_to);

  const pgpRows = [
    { k: "Key ID", v: pgp.key_id },
    { k: "Fingerprint", v: pgp.fingerprint },
    { k: "Key size", v: pgp.key_size ? String(pgp.key_size) : "" },
    { k: "Signer UID", v: pgp.signer_uid },
    { k: "Signature date", v: pgp.signature_date },
    { k: "Trust (WoT)", v: pgp.trust_level },
  ];

  const smRows = [
    { k: "Subject CN", v: smime.subject_cn },
    { k: "Issuer CN", v: smime.issuer_cn },
    { k: "Serial", v: smime.serial_number },
    { k: "Public-key algorithm", v: smime.algorithm },
    { k: "Valid from", v: smime.valid_from },
    { k: "Valid to", v: smime.valid_to },
  ];

  const sortedChain = useMemo(() => {
    return [...smime.chain].sort((a, b) => (a.level ?? 0) - (b.level ?? 0));
  }, [smime.chain]);

  return (
    <section className="mt-8 rounded-xl border border-[var(--border)] bg-[var(--bg-secondary)] p-4">
      <div className="mb-4 flex items-center gap-2 border-b border-[var(--border)] pb-3">
        <KeyRound className="h-5 w-5 text-[var(--accent-primary)]" aria-hidden />
        <h2 className="font-[family-name:var(--font-space)] text-lg font-semibold text-[var(--text-primary)]">
          Digital signatures
        </h2>
      </div>

      <div className="grid gap-4 md:grid-cols-2">
        {/* PGP */}
        <div className="flex min-h-[280px] flex-col rounded-lg border border-[var(--border)] bg-[var(--bg-tertiary)] p-4">
          <div className="mb-3 flex flex-wrap items-center justify-between gap-2">
            <h3 className="text-sm font-semibold text-[var(--text-primary)]">OpenPGP</h3>
            <div className="flex flex-wrap items-center gap-2">
              <ValidityBadge valid={pgp.valid} present={pgp.present} label="PGP" />
              <AlgoBadge algorithm={pgp.algorithm} />
            </div>
          </div>

          {!pgp.present ? (
            <p className="text-sm text-[var(--text-muted)]">
              No PGP clearsigned block or PGP/MIME detached signature detected in this message.
            </p>
          ) : (
            <>
              <MetaTable rows={pgpRows} />
              <div className="mt-3 space-y-1 font-[family-name:var(--font-jetbrains)] text-[11px] leading-relaxed text-[var(--text-muted)]">
                <p className="text-[10px] uppercase tracking-wide text-[var(--accent-primary)]">Key ID & fingerprint</p>
                <p className="break-all text-[var(--text-primary)]">{pgp.key_id || "—"}</p>
                <p className="break-all text-[var(--text-primary)]">{pgp.fingerprint || "—"}</p>
              </div>
              {pgpText.dsa && (pgpText.dsa.r || pgpText.dsa.s) && (
                <details className="group mt-3 rounded-lg border border-[var(--border)] bg-[var(--bg-secondary)] px-3 py-2">
                  <summary className="cursor-pointer list-none text-xs font-medium text-[var(--warning)]">
                    <span className="inline-flex items-center gap-1">
                      <ChevronDown
                        className="h-3.5 w-3.5 shrink-0 transition-transform group-open:rotate-180"
                        aria-hidden
                      />
                      Unit 6 — DSA signature material (r, s)
                    </span>
                  </summary>
                  <p className="mt-2 text-[10px] uppercase tracking-wide text-[var(--text-muted)]">Syllabus</p>
                  <pre className="mt-1 max-h-40 overflow-auto rounded bg-[var(--terminal-bg)] p-2 text-[10px] text-[var(--terminal-text)]">
                    r = 0x{pgpText.dsa.r}
                    {"\n"}
                    s = 0x{pgpText.dsa.s}
                  </pre>
                </details>
              )}
              {pgpText.body && <p className="mt-3 text-xs italic text-[var(--text-muted)]">{pgpText.body}</p>}
            </>
          )}
        </div>

        {/* S/MIME */}
        <div className="flex min-h-[280px] flex-col rounded-lg border border-[var(--border)] bg-[var(--bg-tertiary)] p-4">
          <div className="mb-3 flex flex-wrap items-center justify-between gap-2">
            <h3 className="text-sm font-semibold text-[var(--text-primary)]">S/MIME (PKCS#7)</h3>
            <div className="flex flex-wrap items-center gap-2">
              <ValidityBadge valid={smime.valid} present={smime.present} label="S/MIME" />
              <AlgoBadge algorithm={smime.algorithm} />
            </div>
          </div>

          {!smime.present ? (
            <p className="text-sm text-[var(--text-muted)]">
              No S/MIME or PKCS#7 signed structure detected (no application/pkcs7-* or PKCS multipart/signed protocol).
            </p>
          ) : (
            <>
              <MetaTable rows={smRows} />
              {smDays !== null && smime.valid_to && (
                <div className="mt-2">
                  <span
                    className={[
                      "inline-block rounded-full px-2 py-0.5 text-xs font-medium",
                      smDays < 0
                        ? "bg-[var(--danger)]/20 text-[var(--danger)]"
                        : smDays < 30
                          ? "bg-[var(--warning)]/20 text-[var(--warning)]"
                          : "bg-[var(--success)]/15 text-[var(--success)]",
                    ].join(" ")}
                  >
                    {smDays < 0 ? `Expired ${Math.abs(smDays)}d ago` : `${smDays}d remaining`}
                  </span>
                </div>
              )}
              {sortedChain.length > 0 ? (
                <div className="mt-4">
                  <p className="mb-2 text-[10px] font-medium uppercase tracking-wide text-[var(--text-muted)]">
                    Issuer chain (end-entity → root)
                  </p>
                  <ol className="relative space-y-2 border-l border-[var(--border)] pl-4">
                    {sortedChain.map((c, idx) => (
                      <li key={`${c.level}-${idx}`} className="relative text-xs">
                        <span className="absolute -left-[21px] top-1.5 h-2 w-2 rounded-full bg-[var(--accent-primary)]" />
                        <span className="font-medium text-[var(--accent-primary)]">{c.type ?? "cert"}</span>
                        <p className="mt-0.5 break-all text-[var(--text-primary)]">{c.subject || "—"}</p>
                        <p className="text-[var(--text-muted)]">issuer: {c.issuer || "—"}</p>
                        <p className={c.valid ? "text-[var(--success)]" : "text-[var(--danger)]"}>
                          {c.valid ? "link OK" : "link / validity issue"}
                        </p>
                      </li>
                    ))}
                  </ol>
                </div>
              ) : (
                <p className="mt-3 text-xs text-[var(--text-muted)]">
                  No embedded certificate list was returned (common for synthetic lab PKCS#7 placeholders).
                </p>
              )}
              {smime.explanation && (
                <p className="mt-3 text-xs italic text-[var(--text-muted)]">{smime.explanation}</p>
              )}
            </>
          )}
        </div>
      </div>
    </section>
  );
}
