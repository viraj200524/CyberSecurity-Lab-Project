"use client";

import { useCallback, useState } from "react";
import { useDropzone } from "react-dropzone";
import axios from "axios";
import { Upload } from "lucide-react";
import { toast } from "sonner";

type Props = {
  onUploaded: (uploadId: string) => void;
  disabled?: boolean;
};

export function UploadDropzone({ onUploaded, disabled }: Props) {
  const [file, setFile] = useState<File | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const onDrop = useCallback((accepted: File[]) => {
    setError(null);
    if (accepted[0]) setFile(accepted[0]);
  }, []);

  const { getRootProps, getInputProps, isDragActive } = useDropzone({
    onDrop,
    accept: {
      "message/rfc822": [".eml"],
      "application/octet-stream": [".eml", ".msg"],
      "application/vnd.ms-outlook": [".msg"],
    },
    maxFiles: 1,
    disabled: disabled || busy,
  });

  const submit = async () => {
    if (!file) return;
    setBusy(true);
    setError(null);
    try {
      const { uploadViaFile } = await import("@/lib/uploadApi");
      const res = await uploadViaFile(file);
      onUploaded(res.upload_id);
    } catch (e: unknown) {
      if (axios.isAxiosError(e)) {
        const st = e.response?.status;
        const detail = (e.response?.data as { detail?: string } | undefined)?.detail;
        if (st === 400 || st === 413) {
          toast.warning(detail || (st === 413 ? "File too large." : "Upload rejected."));
        } else if (!e.response) {
          toast.error("Network error during upload.");
        } else {
          toast.error(detail || "Upload failed.");
        }
        setError(detail || "Upload failed");
      } else {
        const msg = e instanceof Error ? e.message : "Upload failed";
        setError(msg);
      }
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="flex flex-col gap-4">
      <div
        {...getRootProps()}
        className={[
          "cursor-pointer rounded-xl border-2 border-dashed p-10 text-center transition-[transform,colors,box-shadow] duration-200 ease-out",
          isDragActive ? "scale-[1.01] border-[var(--accent-primary)] shadow-[0_0_24px_rgba(0,212,255,0.25)]" : "scale-100 border-[var(--border)]",
          disabled || busy ? "opacity-50 pointer-events-none" : "",
        ].join(" ")}
      >
        <input {...getInputProps()} />
        <Upload className="mx-auto mb-3 h-10 w-10 text-[var(--accent-primary)]" aria-hidden />
        <p className="font-[family-name:var(--font-space)] text-sm text-[var(--text-muted)]">
          Drop <span className="text-[var(--accent-primary)]">.eml</span> or{" "}
          <span className="text-[var(--accent-primary)]">.msg</span> here, or click to browse
        </p>
      </div>
      {file && (
        <div className="rounded-lg border border-[var(--border)] bg-[var(--bg-secondary)] px-4 py-3 text-sm text-[var(--text-primary)]">
          <span className="font-[family-name:var(--font-jetbrains)]">{file.name}</span>
          <span className="ml-2 text-[var(--text-muted)]">({(file.size / 1024).toFixed(1)} KB)</span>
        </div>
      )}
      {error && <p className="text-sm text-[var(--danger)]">{error}</p>}
      <button
        type="button"
        onClick={submit}
        disabled={!file || busy || disabled}
        className="rounded-lg bg-[var(--accent-primary)] px-4 py-2.5 text-sm font-semibold text-[#041018] disabled:opacity-40"
      >
        {busy ? "Uploading…" : "Analyze"}
      </button>
    </div>
  );
}
