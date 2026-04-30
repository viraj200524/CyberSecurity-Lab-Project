import { api } from "./api";
import type { AnalysisResult } from "./types";

export async function analyzeUpload(
  uploadId: string,
  options: { run_llm?: boolean; run_vulnerability_check?: boolean } = {},
): Promise<AnalysisResult> {
  const { data } = await api.post<AnalysisResult>("/analyze", {
    upload_id: uploadId,
    options: {
      run_llm: options.run_llm ?? false,
      run_vulnerability_check: options.run_vulnerability_check ?? false,
    },
  });
  return data;
}
