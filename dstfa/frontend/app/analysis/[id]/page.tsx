"use client";

import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { useParams } from "next/navigation";
import { AnimatePresence, motion } from "framer-motion";
import axios from "axios";
import { toast } from "sonner";

import { AnalysisProgressSteps } from "@/components/analysis/AnalysisProgressSteps";
import { AuthTab } from "@/components/analysis/AuthTab";
import { ExportButtons } from "@/components/analysis/ExportButtons";
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
  const [result, setResult] = useState<AnalysisResult | null>(null);
  const [loading, setLoading] = useState(true);
  const [progStep, setProgStep] = useState(0);
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
    if (!loading) return;
    setProgStep(1);
    const ids = [
      window.setTimeout(() => setProgStep(2), 500),
      window.setTimeout(() => setProgStep(3), 1000),
    ];
    if (runLlm) ids.push(window.setTimeout(() => setProgStep(4), 1500));
    return () => ids.forEach((t) => window.clearTimeout(t));
  }, [loading, id, runLlm, retryToken]);

  useEffect(() => {
    if (!id) return;
    let cancelled = false;
    (async () => {
      setLoading(true);
      let ok = false;
      try {
        const data = await analyzeUpload(id, {
          run_llm: runLlm,
          run_vulnerability_check: false,
        });
        if (!cancelled) {
          ok = true;
          setResult(data);
          setAnalysisResult(data);
          if (runLlm && data.llm_error) {
            toast.info("AI insights unavailable — showing raw forensic data.", {
              description: data.llm_error.slice(0, 140) + (data.llm_error.length > 140 ? "…" : ""),
            });
          }
        }
      } catch (e) {
        if (!cancelled) {
          if (axios.isAxiosError(e)) {
            const st = e.response?.status;
            if (st === 404) toast.warning("Unknown upload id — upload the email again.");
            else if (!e.response) toast.error("Network error — cannot reach the analysis API.");
            else toast.error("Analysis failed. Check API logs and try again.");
          } else {
            toast.error("Analysis failed. Check API and upload id.");
          }
        }
      } finally {
        if (!cancelled) {
          setLoading(false);
          if (ok) {
            setProgStep(5);
            window.setTimeout(() => setProgStep(0), 650);
          } else {
            setProgStep(0);
          }
        }
      }
    })();
    return () => {
      cancelled = true;
    };
  }, [id, runLlm, retryToken, setAnalysisResult]);

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
    <div className="min-h-screen bg-[var(--bg-primary)] px-4 py-8 text-[var(--text-primary)] sm:px-6 sm:py-10">
      <a
        href="#analysis-main"
        className="sr-only rounded bg-[var(--accent-primary)] px-3 py-2 font-medium text-[#041018]"
      >
        Skip to analysis
      </a>
      <div className="mx-auto max-w-5xl" id="analysis-main">
        <div className="mb-4 flex flex-col gap-3 sm:flex-row sm:flex-wrap sm:items-start sm:justify-between">
          <div>
            <h1 className="mb-1 font-[family-name:var(--font-space)] text-2xl font-bold">Analysis</h1>
            <p className="font-[family-name:var(--font-jetbrains)] text-sm text-[var(--text-muted)]">upload_id: {id}</p>
          </div>
          {result?.analysis_id ? (
            <div className="flex shrink-0 items-center gap-2">
              <ExportButtons analysisId={result.analysis_id} />
            </div>
          ) : null}
        </div>

        <div className="mb-6 flex flex-wrap items-center gap-6 rounded-xl border border-[var(--border)] bg-[var(--bg-secondary)] px-4 py-3">
          <label className="flex cursor-pointer items-center gap-2 text-sm">
            <input
              type="checkbox"
              className="h-4 w-4 rounded border-[var(--border)] accent-[var(--accent-primary)] focus:outline-none focus-visible:ring-2 focus-visible:ring-[var(--accent-primary)]"
              checked={runLlm}
              onChange={(e) => setRunLlm(e.target.checked)}
            />
            <span>
              AI insights <span className="text-[var(--text-muted)]">(Groq)</span>
            </span>
          </label>
        </div>

        <AnalysisProgressSteps step={progStep} runLlm={runLlm} />

        {loading && !result && (
          <div className="grid gap-4 sm:grid-cols-2">
            {[1, 2, 3, 4].map((k) => (
              <div key={k} className="h-24 animate-pulse rounded-xl bg-[var(--bg-secondary)]" />
            ))}
          </div>
        )}

        {result && (
          <>
            {loading && (
              <p className="mb-4 text-center text-sm text-[var(--accent-primary)]">Refreshing analysis…</p>
            )}
            <OverviewPanel result={result} />

            <div
              className="mb-4 flex max-w-full flex-wrap gap-2 overflow-x-auto border-b border-[var(--border)] pb-3 [-ms-overflow-style:none] [scrollbar-width:none] [&::-webkit-scrollbar]:hidden"
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
                    "rounded-lg px-3 py-2 text-sm font-medium transition focus:outline-none focus-visible:ring-2 focus-visible:ring-[var(--accent-primary)] focus-visible:ring-offset-2 focus-visible:ring-offset-[var(--bg-primary)]",
                    tab === t.id
                      ? "border-l-2 border-[var(--accent-primary)] bg-[var(--bg-tertiary)] text-[var(--accent-primary)]"
                      : "text-[var(--text-muted)] hover:text-[var(--text-primary)]",
                    t.id === "vuln"
                      ? "relative after:absolute after:right-1 after:top-1 after:h-1.5 after:w-1.5 after:animate-pulse after:rounded-full after:bg-[var(--danger)]"
                      : "",
                  ].join(" ")}
                >
                  {t.label}
                </button>
              ))}
            </div>

            <div role="tabpanel">
              <AnimatePresence mode="wait">
                <motion.div
                  key={tab}
                  initial={{ opacity: 0, y: 6 }}
                  animate={{ opacity: 1, y: 0 }}
                  exit={{ opacity: 0, y: -4 }}
                  transition={{ duration: 0.22 }}
                >
                  {tab === "overview" && (
                    <p className="text-sm text-[var(--text-muted)]">
                      Use the tabs for raw headers, Merkle–Damgård stepping, authentication, signatures, trust chain,
                      Groq-powered AI insights, and (when MD5 is present) the live vulnerability lab.
                    </p>
                  )}
                  {tab === "headers" && <HeadersTab headers={result.headers} />}
                  {tab === "hashes" && (
                    <HashAnalyzerTab hashes={(result.hashes ?? {}) as Record<string, unknown>} />
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
                </motion.div>
              </AnimatePresence>
            </div>
          </>
        )}
      </div>
    </div>
  );
}
