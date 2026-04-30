"use client";

import { motion } from "framer-motion";

type Props = {
  steps: string[];
  title?: string;
};

export function AttackTimeline({ steps, title }: Props) {
  if (!steps || steps.length === 0) return null;

  return (
    <div className="mt-2 space-y-1">
      {title && (
        <p className="mb-3 font-[family-name:var(--font-space)] text-sm font-semibold text-[var(--text-primary)]">
          {title}
        </p>
      )}
      <ol className="relative border-l border-[var(--border)] pl-5">
        {steps.map((step, i) => (
          <motion.li
            key={i}
            initial={{ opacity: 0, x: -8 }}
            animate={{ opacity: 1, x: 0 }}
            transition={{ delay: i * 0.07, duration: 0.25 }}
            className="mb-4 last:mb-0"
          >
            <span className="absolute -left-[9px] flex h-[18px] w-[18px] items-center justify-center rounded-full border border-[var(--border)] bg-[var(--bg-tertiary)] text-[10px] font-bold text-[var(--accent-primary)]">
              {i + 1}
            </span>
            <p className="text-sm leading-relaxed text-[var(--text-primary)]">
              {/* Strip leading "Step N:" prefix if model included it */}
              {step.replace(/^step\s*\d+[.:]\s*/i, "")}
            </p>
          </motion.li>
        ))}
      </ol>
    </div>
  );
}
