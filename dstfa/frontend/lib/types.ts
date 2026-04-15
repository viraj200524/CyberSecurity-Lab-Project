/** Mirrors backend `AnalysisResult` / nested models (Phase 1 subset used in UI). */

export interface ParsedHeader {
  name: string;
  value: string;
  suspicious: boolean;
  explanation: string;
}

export interface ReceivedHop {
  from: string;
  by: string;
  timestamp: string;
  delay_seconds: number;
}

export interface HeadersResult {
  raw: string;
  parsed: ParsedHeader[];
  received_chain: ReceivedHop[];
}

export interface InputSummary {
  subject: string;
  from: string;
  to: string[];
  date: string;
  message_id: string;
  mime_parts: number;
}

export interface AnalysisResult {
  analysis_id: string;
  timestamp: string;
  input_summary: InputSummary;
  headers: HeadersResult;
  authentication?: Record<string, unknown>;
  hashes?: Record<string, unknown>;
  digital_signatures?: Record<string, unknown>;
  trust_chain?: Record<string, unknown>;
  llm_insights?: Record<string, unknown> | null;
  llm_error?: string | null;
  vulnerability_available: boolean;
}

export interface UploadResponse {
  upload_id: string;
  filename: string;
  size_bytes: number;
  detected_type: string;
  preview: {
    subject?: string;
    from?: string;
    to?: string[];
    date?: string;
  };
}

/** `GET /api/samples` item (PRD §8.1). */
export interface SampleItem {
  id: string;
  label: string;
  description: string;
  highlights: string[];
}

export interface SamplesListResponse {
  samples: SampleItem[];
}

export interface VulnerabilityResult {
  demo_type: "collision" | "length_extension";
  generated_script: string;
  execution_output: string;
  execution_success: boolean;
  execution_time_ms: number;
  collision_pair: {
    message_1_hex: string;
    message_2_hex: string;
    shared_md5: string;
  };
  llm_explanation: {
    why_md5_fails: string;
    merkle_damgard_failure_point: string;
    step_by_step: string[];
    why_sha256_resists: string;
    syllabus_note: string;
  };
}
