import { api } from "./api";

function triggerDownload(blob: Blob, fallbackName: string) {
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = fallbackName;
  a.rel = "noopener";
  document.body.appendChild(a);
  a.click();
  a.remove();
  URL.revokeObjectURL(url);
}

export async function downloadAnalysisPdf(analysisId: string): Promise<void> {
  const { data, headers } = await api.post<Blob>(
    "/export/pdf",
    { analysis_id: analysisId },
    { responseType: "blob", timeout: 120000 },
  );
  const cd = headers["content-disposition"] as string | undefined;
  const m = cd?.match(/filename="?([^";]+)"?/i);
  const name = m?.[1] ?? `dstfa_report_${analysisId.slice(0, 8)}.pdf`;
  triggerDownload(data, name);
}

export async function downloadAnalysisJson(analysisId: string): Promise<void> {
  const { data, headers } = await api.post<Blob>(
    "/export/json",
    { analysis_id: analysisId },
    { responseType: "blob", timeout: 60000 },
  );
  const cd = headers["content-disposition"] as string | undefined;
  const m = cd?.match(/filename="?([^";]+)"?/i);
  const name = m?.[1] ?? `dstfa_report_${analysisId.slice(0, 8)}.json`;
  triggerDownload(data, name);
}
