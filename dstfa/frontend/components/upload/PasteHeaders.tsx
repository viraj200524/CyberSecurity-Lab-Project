"use client";

import { useState } from "react";

const PLACEHOLDER = `Received: from mail.example.com (mail.example.com [192.0.2.1])
\tby mx.dstfa.local with ESMTPS id abc123
\tfor <you@lab.local>; Tue, 14 Apr 2026 12:00:00 +0000
From: "Trusted Bank" <alerts@bank.example>
To: you@lab.local
Subject: Action required on your account
Reply-To: support@not-the-bank.example
Date: Tue, 14 Apr 2026 12:00:00 +0000
Message-ID: <paste-demo@dstfa.local>
`;

type Props = {
  onUploaded: (uploadId: string) => void;
  disabled?: boolean;
};

export function PasteHeaders({ onUploaded, disabled }: Props) {
  const [text, setText] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const submit = async () => {
    setBusy(true);
    setError(null);
    try {
      const { uploadViaRawHeaders } = await import("@/lib/uploadApi");
      const res = await uploadViaRawHeaders(text || PLACEHOLDER);
      onUploaded(res.upload_id);
    } catch (e: unknown) {
      const msg = e instanceof Error ? e.message : "Upload failed";
      setError(msg);
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="flex flex-col gap-3">
      <textarea
        value={text}
        onChange={(e) => setText(e.target.value)}
        placeholder={PLACEHOLDER}
        rows={14}
        disabled={disabled || busy}
        className="w-full resize-y rounded-lg border border-[var(--border)] bg-[var(--terminal-bg)] p-3 font-[family-name:var(--font-jetbrains)] text-sm leading-relaxed text-[var(--terminal-text)] placeholder:text-[#0d3d24]"
        spellCheck={false}
      />
      {error && <p className="text-sm text-[var(--danger)]">{error}</p>}
      <button
        type="button"
        onClick={submit}
        disabled={busy || disabled}
        className="rounded-lg bg-[var(--accent-primary)] px-4 py-2.5 text-sm font-semibold text-[#041018] disabled:opacity-40"
      >
        {busy ? "Submitting…" : "Analyze pasted headers"}
      </button>
    </div>
  );
}
