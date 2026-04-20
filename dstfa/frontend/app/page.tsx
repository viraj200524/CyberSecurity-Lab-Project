"use client";

import { useEffect, useState } from "react";
import { useRouter } from "next/navigation";
import { motion } from "framer-motion";
import { toast } from "sonner";

import { PasteHeaders } from "@/components/upload/PasteHeaders";
import { UploadDropzone } from "@/components/upload/UploadDropzone";
import { listSamples, loadSample } from "@/lib/uploadApi";
import type { SampleItem } from "@/lib/types";

export default function Home() {
  const router = useRouter();
  const [mode, setMode] = useState<"file" | "paste">("file");
  const [samples, setSamples] = useState<SampleItem[]>([]);

  useEffect(() => {
    listSamples()
      .then(setSamples)
      .catch(() => toast.error("Could not load sample list from API."));
  }, []);

  const go = (uploadId: string, sampleId?: string) => {
    const q = sampleId ? `?sample=${encodeURIComponent(sampleId)}` : "";
    router.push(`/analysis/${uploadId}${q}`);
  };

  return (
    <div className="dstfa-hex-bg relative min-h-screen overflow-hidden bg-[var(--bg-primary)] text-[var(--text-primary)]">
      <div className="relative z-10 mx-auto flex max-w-6xl flex-col gap-10 px-6 py-12 lg:flex-row lg:items-start lg:justify-between">
        <motion.div
          initial={{ opacity: 0, y: 12 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.45 }}
          className="max-w-xl flex-1 space-y-6"
        >
          <p className="font-[family-name:var(--font-space)] text-xs uppercase tracking-[0.2em] text-[var(--accent-primary)]">
            Digital Signature & Trust Forensic Agent
          </p>
          <h1 className="font-[family-name:var(--font-space)] text-3xl font-bold leading-tight md:text-4xl">
            Trace authenticity, headers, and trust — before you trust the message.
          </h1>
          <p className="text-base leading-relaxed text-[var(--text-muted)]">
            Upload a raw <code className="text-[var(--accent-primary)]">.eml</code> or Outlook{" "}
            <code className="text-[var(--accent-primary)]">.msg</code>, or paste headers. Phase 1
            surfaces parsed headers, Received chain, and spoofing hints for quick triage.
          </p>
          <ul className="space-y-2 text-sm text-[var(--text-muted)]">
            <li className="flex gap-2">
              <span className="text-[var(--success)]">●</span> Duplicate-safe header capture + Received hop ordering
            </li>
            <li className="flex gap-2">
              <span className="text-[var(--success)]">●</span> Reply-To / Date heuristics with inline explanations
            </li>
            <li className="flex gap-2">
              <span className="text-[var(--success)]">●</span> One-click samples wired to the same upload pipeline
            </li>
          </ul>
        </motion.div>

        <motion.div
          initial={{ opacity: 0, y: 16 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.5, delay: 0.08 }}
          className="w-full max-w-md flex-1 rounded-2xl border border-[var(--border)] bg-[var(--bg-secondary)] p-6 shadow-[0_0_20px_rgba(0,212,255,0.05)]"
        >
          <div className="mb-4 flex gap-2">
            <button
              type="button"
              onClick={() => setMode("file")}
              className={[
                "flex-1 rounded-lg px-3 py-2 text-sm font-medium",
                mode === "file" ? "bg-[var(--bg-tertiary)] text-[var(--accent-primary)]" : "text-[var(--text-muted)]",
              ].join(" ")}
            >
              File upload
            </button>
            <button
              type="button"
              onClick={() => setMode("paste")}
              className={[
                "flex-1 rounded-lg px-3 py-2 text-sm font-medium",
                mode === "paste" ? "bg-[var(--bg-tertiary)] text-[var(--accent-primary)]" : "text-[var(--text-muted)]",
              ].join(" ")}
            >
              Paste headers
            </button>
          </div>
          {mode === "file" ? <UploadDropzone onUploaded={go} /> : <PasteHeaders onUploaded={go} />}
        </motion.div>
      </div>

      <section className="relative z-10 mx-auto max-w-6xl px-6 pb-16">
        <h2 className="mb-4 font-[family-name:var(--font-space)] text-lg text-[var(--text-muted)]">Sample gallery</h2>
        <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-4">
          {samples.map((s) => (
            <button
              key={s.id}
              type="button"
              onClick={async () => {
                try {
                  const res = await loadSample(s.id);
                  go(res.upload_id, s.id);
                } catch {
                  toast.error("Failed to load sample.");
                }
              }}
              className="rounded-xl border border-[var(--border)] bg-[var(--bg-secondary)] p-4 text-left transition hover:border-[var(--accent-primary)] hover:shadow-[0_0_20px_rgba(0,212,255,0.08)]"
            >
              <p className="font-[family-name:var(--font-space)] text-sm text-[var(--accent-primary)]">{s.label}</p>
              <p className="mt-1 text-xs text-[var(--text-muted)]">{s.description}</p>
              {s.highlights.length > 0 && (
                <p className="mt-2 text-[10px] uppercase tracking-wide text-[var(--text-muted)]">
                  {s.highlights.join(" · ")}
                </p>
              )}
            </button>
          ))}
        </div>
      </section>
    </div>
  );
}
