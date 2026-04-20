"use client";

import { motion } from "framer-motion";

const STEPS = [
  "Parsing email structure…",
  "Running cryptographic verification…",
  "Checking authentication protocols…",
  "Querying Groq LLM…",
  "Building forensic report…",
] as const;

function pickLabel(displayStep: number, runLlm: boolean): string {
  if (displayStep < 1) return STEPS[0];
  if (displayStep === 1) return STEPS[0];
  if (displayStep === 2) return STEPS[1];
  if (displayStep === 3) return STEPS[2];
  if (runLlm && displayStep === 4) return STEPS[3];
  return STEPS[4];
}

type Props = {
  /** 1–5 while analysis is in flight; 0 hides the panel. */
  step: number;
  runLlm: boolean;
};

export function AnalysisProgressSteps({ step, runLlm }: Props) {
  if (step < 1) return null;

  const maxStep = runLlm ? 5 : 4;
  const displayStep = Math.min(Math.max(step, 1), maxStep);
  const label = pickLabel(displayStep, runLlm);

  const segments = runLlm ? [1, 2, 3, 4, 5] : [1, 2, 3, 5];

  return (
    <div className="mb-6 rounded-xl border border-[var(--border)] bg-[var(--bg-secondary)] p-4">
      <p className="mb-3 text-center text-sm text-[var(--accent-primary)]">{label}</p>
      <div className="flex gap-1" aria-hidden>
        {segments.map((s) => {
          const done = displayStep >= s;
          return (
            <div key={s} className="h-1.5 flex-1 overflow-hidden rounded-full bg-[var(--bg-tertiary)]">
              <motion.div
                className="h-full rounded-full bg-[var(--accent-primary)]"
                initial={false}
                animate={{ width: done ? "100%" : "0%" }}
                transition={{ duration: 0.35, ease: "easeOut" }}
              />
            </div>
          );
        })}
      </div>
      <p className="mt-2 text-center text-xs text-[var(--text-muted)]">
        Step {Math.min(displayStep, maxStep)} of {maxStep}
      </p>
    </div>
  );
}
