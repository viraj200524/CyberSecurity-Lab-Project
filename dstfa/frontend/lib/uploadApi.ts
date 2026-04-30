import { api } from "./api";
import type { SampleItem, SamplesListResponse, UploadResponse } from "./types";

export async function uploadViaFile(file: File): Promise<UploadResponse> {
  const fd = new FormData();
  fd.append("file", file);
  const { data } = await api.post<UploadResponse>("/upload", fd);
  return data;
}

export async function uploadViaRawHeaders(raw_headers: string): Promise<UploadResponse> {
  const { data } = await api.post<UploadResponse>("/upload", { raw_headers });
  return data;
}

export async function listSamples(): Promise<SampleItem[]> {
  const { data } = await api.get<SamplesListResponse>("/samples");
  return data.samples;
}

export async function loadSample(sampleId: string): Promise<UploadResponse> {
  const { data } = await api.get<UploadResponse>(`/samples/${encodeURIComponent(sampleId)}`);
  return data;
}
