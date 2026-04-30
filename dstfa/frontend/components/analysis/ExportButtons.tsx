"use client";

import { useCallback, useEffect, useRef, useState } from "react";
import { ChevronDown, FileJson, FileText, Loader2 } from "lucide-react";
import { toast } from "sonner";
import axios from "axios";

import { downloadAnalysisJson, downloadAnalysisPdf } from "@/lib/exportApi";

type Props = {
  analysisId: string;
};

export function ExportButtons({ analysisId }: Props) {
  const [open, setOpen] = useState(false);
  const [busy, setBusy] = useState<"pdf" | "json" | null>(null);
  const wrapRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    if (!open) return;
    const onDoc = (e: MouseEvent) => {
      if (wrapRef.current && !wrapRef.current.contains(e.target as Node)) setOpen(false);
    };
    document.addEventListener("mousedown", onDoc);
    return () => document.removeEventListener("mousedown", onDoc);
  }, [open]);

  const run = useCallback(
    async (kind: "pdf" | "json") => {
      setBusy(kind);
      try {
        if (kind === "pdf") await downloadAnalysisPdf(analysisId);
        else await downloadAnalysisJson(analysisId);
        toast.success(kind === "pdf" ? "PDF report downloaded." : "JSON export downloaded.");
        setOpen(false);
      } catch (e) {
        if (axios.isAxiosError(e)) {
          const st = e.response?.status;
          if (st === 404) toast.warning("Analysis expired or not found. Re-run analysis.");
          else if (!e.response) toast.error("Network error — could not reach export API.");
          else toast.error("Export failed. See backend logs.");
        } else {
          toast.error("Export failed.");
        }
      } finally {
        setBusy(null);
      }
    },
    [analysisId],
  );

  return (
    <div className="relative" ref={wrapRef}>
      <button
        type="button"
        className="inline-flex items-center gap-1.5 rounded-lg border border-[var(--border)] bg-[var(--bg-tertiary)] px-3 py-2 text-sm font-medium text-[var(--text-primary)] transition hover:border-[var(--accent-primary)] focus:outline-none focus-visible:ring-2 focus-visible:ring-[var(--accent-primary)] focus-visible:ring-offset-2 focus-visible:ring-offset-[var(--bg-secondary)]"
        aria-expanded={open}
        aria-haspopup="menu"
        onClick={() => setOpen((o) => !o)}
      >
        Export
        <ChevronDown className={`h-4 w-4 transition ${open ? "rotate-180" : ""}`} aria-hidden />
      </button>
      {open && (
        <ul
          className="absolute right-0 z-20 mt-1 min-w-[11rem] rounded-lg border border-[var(--border)] bg-[var(--bg-secondary)] py-1 shadow-lg"
          role="menu"
        >
          <li role="none">
            <button
              type="button"
              role="menuitem"
              disabled={busy !== null}
              className="flex w-full items-center gap-2 px-3 py-2 text-left text-sm hover:bg-[var(--bg-tertiary)] focus:bg-[var(--bg-tertiary)] focus:outline-none focus-visible:ring-2 focus-visible:ring-inset focus-visible:ring-[var(--accent-primary)] disabled:opacity-50"
              onClick={() => run("pdf")}
            >
              {busy === "pdf" ? <Loader2 className="h-4 w-4 animate-spin" aria-hidden /> : <FileText className="h-4 w-4" aria-hidden />}
              Download PDF
            </button>
          </li>
          <li role="none">
            <button
              type="button"
              role="menuitem"
              disabled={busy !== null}
              className="flex w-full items-center gap-2 px-3 py-2 text-left text-sm hover:bg-[var(--bg-tertiary)] focus:bg-[var(--bg-tertiary)] focus:outline-none focus-visible:ring-2 focus-visible:ring-inset focus-visible:ring-[var(--accent-primary)] disabled:opacity-50"
              onClick={() => run("json")}
            >
              {busy === "json" ? <Loader2 className="h-4 w-4 animate-spin" aria-hidden /> : <FileJson className="h-4 w-4" aria-hidden />}
              Download JSON
            </button>
          </li>
        </ul>
      )}
    </div>
  );
}
