import { create } from "zustand";

import type { AnalysisResult, VulnerabilityResult } from "./types";

export type { VulnerabilityResult } from "./types";

interface DSFTAStore {
  uploadId: string | null;
  analysisResult: AnalysisResult | null;
  vulnerabilityResult: VulnerabilityResult | null;
  isAnalyzing: boolean;
  activeTab: string;
  setUploadId: (id: string) => void;
  setAnalysisResult: (result: AnalysisResult) => void;
  setVulnerabilityResult: (result: VulnerabilityResult) => void;
  setAnalyzing: (v: boolean) => void;
  setActiveTab: (tab: string) => void;
}

export const useDSTFAStore = create<DSFTAStore>((set) => ({
  uploadId: null,
  analysisResult: null,
  vulnerabilityResult: null,
  isAnalyzing: false,
  activeTab: "overview",
  setUploadId: (id) => set({ uploadId: id }),
  setAnalysisResult: (result) => set({ analysisResult: result }),
  setVulnerabilityResult: (result) => set({ vulnerabilityResult: result }),
  setAnalyzing: (v) => set({ isAnalyzing: v }),
  setActiveTab: (tab) => set({ activeTab: tab }),
}));
