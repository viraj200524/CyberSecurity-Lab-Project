"use client";

import { useEffect, useState } from "react";
import { useParams } from "next/navigation";
import { toast } from "sonner";

import { HeadersTab } from "@/components/analysis/HeadersTab";
import { OverviewPanel } from "@/components/analysis/OverviewPanel";
import { analyzeUpload } from "@/lib/analyzeApi";
import type { AnalysisResult } from "@/lib/types";
import { useDSTFAStore } from "@/lib/store";

export default function AnalysisPage() {
  const params = useParams<{ id: string }>();
  const id = params?.id;
  const setAnalysisResult = useDSTFAStore((s) => s.setAnalysisResult);
  const [result, setResult] = useState<AnalysisResult | null>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    if (!id) return;
    let cancelled = false;
    (async () => {
      setLoading(true);
      try {
        const data = await analyzeUpload(id, { run_llm: false, run_vulnerability_check: false });
        if (!cancelled) {
          setResult(data);
          setAnalysisResult(data);
        }
      } catch {
        if (!cancelled) toast.error("Analysis failed. Check API and upload id.");
      } finally {
        if (!cancelled) setLoading(false);
      }
    })();
    return () => {
      cancelled = true;
    };
  }, [id, setAnalysisResult]);

  if (!id) return null;

  return (
    <div className="min-h-screen bg-[var(--bg-primary)] px-6 py-10 text-[var(--text-primary)]">
      <div className="mx-auto max-w-5xl">
        <h1 className="mb-2 font-[family-name:var(--font-space)] text-2xl font-bold">Analysis</h1>
        <p className="mb-8 font-[family-name:var(--font-jetbrains)] text-sm text-[var(--text-muted)]">
          upload_id: {id}
        </p>

        {loading && (
          <div className="grid gap-4 sm:grid-cols-2">
            {[1, 2, 3, 4].map((k) => (
              <div
                key={k}
                className="h-24 animate-pulse rounded-xl bg-[var(--bg-secondary)]"
              />
            ))}
          </div>
        )}

        {!loading && result && (
          <>
            <OverviewPanel result={result} />
            <HeadersTab headers={result.headers} />
          </>
        )}
      </div>
    </div>
  );
}
