"use client";

import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { useParams } from "next/navigation";
import { toast } from "sonner";

import { AuthTab } from "@/components/analysis/AuthTab";
import { HashAnalyzerTab } from "@/components/analysis/HashAnalyzerTab";
import { HeadersTab } from "@/components/analysis/HeadersTab";
import { LLMInsightsTab } from "@/components/analysis/LLMInsightsTab";
import { OverviewPanel } from "@/components/analysis/OverviewPanel";
import { SignatureTab } from "@/components/analysis/SignatureTab";
import { TrustChainTab } from "@/components/analysis/TrustChainTab";
import { VulnerabilityTab } from "@/components/analysis/VulnerabilityTab";
import { analyzeUpload } from "@/lib/analyzeApi";
import type { AnalysisResult, VulnerabilityResult } from "@/lib/types";
import { runVulnerabilityDemo } from "@/lib/vulnerabilityApi";
import { useDSTFAStore } from "@/lib/store";

type TabId = "overview" | "headers" | "hashes" | "auth" | "signatures" | "trust" | "ai" | "vuln";

export default function AnalysisPage() {
  const params = useParams<{ id: string }>();
  const id = params?.id;
  const setAnalysisResult = useDSTFAStore((s) => s.setAnalysisResult);
  const isSyllabusMode = useDSTFAStore((s) => s.isSyllabusMode);
  const toggleSyllabusMode = useDSTFAStore((s) => s.toggleSyllabusMode);
  const [result, setResult] = useState<AnalysisResult | null>(null);
  const [loading, setLoading] = useState(true);
  const [tab, setTab] = useState<TabId>("overview");
  const [runLlm, setRunLlm] = useState(true);
  const [retryToken, setRetryToken] = useState(0);
  const [sampleHint, setSampleHint] = useState<string | null>(null);
  const [prefetchedVuln, setPrefetchedVuln] = useState<VulnerabilityResult | null>(null);
  const autoVulnRef = useRef(false);

  const bumpRetry = useCallback(() => setRetryToken((n) => n + 1), []);

  const visibleTabs = useMemo(() => {
    const base: { id: TabId; label: string }[] = [
      { id: "overview", label: "Overview" },
      { id: "headers", label: "Headers" },
      { id: "hashes", label: "Hash analysis" },
      { id: "auth", label: "Auth" },
      { id: "signatures", label: "Signatures" },
      { id: "trust", label: "Trust chain" },
      { id: "ai", label: "AI insights" },
    ];
    if (result?.vulnerability_available) {
      base.push({ id: "vuln", label: "⚠️ Vulnerability" });
    }
    return base;
  }, [result?.vulnerability_available]);

  useEffect(() => {
    if (typeof window === "undefined") return;
    setSampleHint(new URLSearchParams(window.location.search).get("sample"));
  }, [id]);

  useEffect(() => {
    autoVulnRef.current = false;
    setPrefetchedVuln(null);
  }, [id]);

  useEffect(() => {
    if (tab === "vuln" && !result?.vulnerability_available) setTab("overview");
  }, [tab, result?.vulnerability_available]);

  useEffect(() => {
    if (!id) return;
    let cancelled = false;
    (async () => {
      setLoading(true);
      try {
        const data = await analyzeUpload(id, {
          run_llm: runLlm,
          syllabus_mode: isSyllabusMode,
          run_vulnerability_check: false,
        });
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
  }, [id, runLlm, isSyllabusMode, retryToken, setAnalysisResult]);

  useEffect(() => {
    if (!result?.analysis_id || !result.vulnerability_available) return;
    if (sampleHint !== "md5_phishing") return;
    if (autoVulnRef.current) return;
    autoVulnRef.current = true;
    runVulnerabilityDemo(result.analysis_id, "collision")
      .then((r) => {
        setPrefetchedVuln(r);
        setTab("vuln");
      })
      .catch(() => {
        autoVulnRef.current = false;
        toast.error("Auto collision demo failed (check API key and backend logs).");
      });
  }, [result, sampleHint]);

  if (!id) return null;

  return (
    <div className="min-h-screen bg-[var(--bg-primary)] px-6 py-10 text-[var(--text-primary)]">
      <div className="mx-auto max-w-5xl">
        <h1 className="mb-2 font-[family-name:var(--font-space)] text-2xl font-bold">Analysis</h1>
        <p className="mb-4 font-[family-name:var(--font-jetbrains)] text-sm text-[var(--text-muted)]">
          upload_id: {id}
        </p>

        <div className="mb-6 flex flex-wrap items-center gap-6 rounded-xl border border-[var(--border)] bg-[var(--bg-secondary)] px-4 py-3">
          <label className="flex cursor-pointer items-center gap-2 text-sm">
            <input
              type="checkbox"
              className="h-4 w-4 rounded border-[var(--border)] accent-[var(--accent-primary)]"
              checked={runLlm}
              onChange={(e) => setRunLlm(e.target.checked)}
            />
            <span>
              AI insights <span className="text-[var(--text-muted)]">(Gemini 2.0 Flash)</span>
            </span>
          </label>
          <label className="flex cursor-pointer items-center gap-2 text-sm">
            <input
              type="checkbox"
              className="h-4 w-4 rounded border-[var(--border)] accent-[var(--accent-secondary)]"
              checked={isSyllabusMode}
              onChange={() => toggleSyllabusMode()}
            />
            <span>
              Syllabus mode <span className="text-[var(--text-muted)]">([Unit 4] / [Unit 6] tags)</span>
            </span>
          </label>
        </div>

        {loading && !result && (
          <div className="space-y-4">
            {runLlm && (
              <p className="text-center text-sm text-[var(--accent-primary)]">
                Running full pipeline + Gemini — this can take 10–20 seconds…
              </p>
            )}
            <div className="grid gap-4 sm:grid-cols-2">
              {[1, 2, 3, 4].map((k) => (
                <div key={k} className="h-24 animate-pulse rounded-xl bg-[var(--bg-secondary)]" />
              ))}
            </div>
          </div>
        )}

        {result && (
          <>
            {loading && (
              <p className="mb-4 text-center text-sm text-[var(--accent-primary)]">Refreshing analysis…</p>
            )}
            <OverviewPanel result={result} />

            <div
              className="mb-4 flex flex-wrap gap-2 border-b border-[var(--border)] pb-3"
              role="tablist"
              aria-label="Analysis sections"
            >
              {visibleTabs.map((t) => (
                <button
                  key={t.id}
                  type="button"
                  role="tab"
                  aria-selected={tab === t.id}
                  onClick={() => setTab(t.id)}
                  className={[
                    "rounded-lg px-3 py-2 text-sm font-medium transition",
                    tab === t.id
                      ? "border-l-2 border-[var(--accent-primary)] bg-[var(--bg-tertiary)] text-[var(--accent-primary)]"
                      : "text-[var(--text-muted)] hover:text-[var(--text-primary)]",
                    t.id === "vuln" ? "relative after:absolute after:right-1 after:top-1 after:h-1.5 after:w-1.5 after:animate-pulse after:rounded-full after:bg-[var(--danger)]" : "",
                  ].join(" ")}
                >
                  {t.label}
                </button>
              ))}
            </div>

            <div role="tabpanel">
              {tab === "overview" && (
                <p className="text-sm text-[var(--text-muted)]">
                  Use the tabs for raw headers, Merkle–Damgård stepping, authentication, signatures, trust chain, Gemini
                  insights, and (when MD5 is present) the live vulnerability lab.
                </p>
              )}
              {tab === "headers" && <HeadersTab headers={result.headers} />}
              {tab === "hashes" && (
                <HashAnalyzerTab hashes={(result.hashes ?? {}) as Record<string, unknown>} syllabusMode={isSyllabusMode} />
              )}
              {tab === "auth" && (
                <AuthTab authentication={(result.authentication ?? {}) as Record<string, unknown>} />
              )}
              {tab === "signatures" && (
                <SignatureTab digitalSignatures={(result.digital_signatures ?? {}) as Record<string, unknown>} />
              )}
              {tab === "trust" && <TrustChainTab trustChain={result.trust_chain ?? null} />}
              {tab === "ai" && (
                <LLMInsightsTab
                  llmInsights={result.llm_insights as Record<string, unknown> | null | undefined}
                  llmError={result.llm_error ?? null}
                  loading={loading}
                  runLlmRequested={runLlm}
                  onRetry={bumpRetry}
                />
              )}
              {tab === "vuln" && result.vulnerability_available && result.analysis_id && (
                <VulnerabilityTab analysisId={result.analysis_id} prefetched={prefetchedVuln} />
              )}
            </div>
          </>
        )}
      </div>
    </div>
  );
}
