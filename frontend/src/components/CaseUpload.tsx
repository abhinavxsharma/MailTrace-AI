import React, { useState, useRef } from "react";
import { uploadCase, UploadCaseResponse } from "../api/client";
import { UploadCloud, FileText, CheckCircle2, AlertTriangle, Loader2 } from "lucide-react";

interface CaseUploadProps {
  onUploadSuccess: (res: UploadCaseResponse) => void;
  disabled?: boolean;
  activeCaseId?: string | null;
}

export const CaseUpload: React.FC<CaseUploadProps> = ({
  onUploadSuccess,
  disabled,
  activeCaseId,
}) => {
  const [dragActive, setDragActive] = useState(false);
  const [uploading, setUploading] = useState(false);
  const [errorMessage, setErrorMessage] = useState<string | null>(null);
  const [successMessage, setSuccessMessage] = useState<string | null>(null);
  const fileInputRef = useRef<HTMLInputElement>(null);

  const handleFile = async (file: File) => {
    setErrorMessage(null);
    setSuccessMessage(null);

    if (!file.name.toLowerCase().endsWith(".eml")) {
      setErrorMessage("Unsupported file format. Please upload an RFC 822 email file (.eml only).");
      return;
    }

    if (file.size === 0) {
      setErrorMessage("Selected file is empty (0 bytes).");
      return;
    }

    if (file.size > 25 * 1024 * 1024) {
      setErrorMessage("File exceeds 25 MB size limit.");
      return;
    }

    setUploading(true);

    try {
      const res = await uploadCase(file);
      setSuccessMessage(`Preserved as ${res.case_id}`);
      onUploadSuccess(res);
    } catch (err: unknown) {
      const msg = err && typeof err === "object" && "response" in err
        ? (err as { response?: { data?: { detail?: string } } }).response?.data?.detail
        : "Failed to upload and ingest email. Ensure backend is running.";
      setErrorMessage(String(msg || "Upload failed."));
    } finally {
      setUploading(false);
    }
  };

  const handleDrop = (e: React.DragEvent) => {
    e.preventDefault();
    e.stopPropagation();
    setDragActive(false);
    if (disabled || uploading) return;

    if (e.dataTransfer.files && e.dataTransfer.files[0]) {
      handleFile(e.dataTransfer.files[0]);
    }
  };

  const handleDrag = (e: React.DragEvent) => {
    e.preventDefault();
    e.stopPropagation();
    if (e.type === "dragenter" || e.type === "dragover") {
      setDragActive(true);
    } else if (e.type === "dragleave") {
      setDragActive(false);
    }
  };

  const handleChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    if (e.target.files && e.target.files[0]) {
      handleFile(e.target.files[0]);
    }
  };

  return (
    <div className="card p-3 bg-white border border-slate-200 rounded-lg">
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2">
        <div className="flex items-center gap-2">
          <span className="text-[11px] font-bold uppercase tracking-wider text-slate-500 flex items-center gap-1.5">
            <UploadCloud className="w-3.5 h-3.5 text-blue-600" />
            <span>Evidence Ingestion</span>
          </span>
          <span className="text-[10px] text-slate-400 font-mono bg-slate-50 px-1.5 py-0.2 rounded border border-slate-200">
            RFC 822 / .eml
          </span>
        </div>

        {activeCaseId && (
          <div className="text-[11px] text-slate-500">
            Current Case: <span className="font-mono font-bold text-slate-800">{activeCaseId}</span>
          </div>
        )}
      </div>

      <div
        onDragEnter={handleDrag}
        onDragLeave={handleDrag}
        onDragOver={handleDrag}
        onDrop={handleDrop}
        onClick={() => !uploading && !disabled && fileInputRef.current?.click()}
        className={`mt-2.5 border border-dashed rounded-md p-3 text-center cursor-pointer transition-all ${
          dragActive
            ? "border-blue-500 bg-blue-50/40"
            : disabled
            ? "border-slate-200 bg-slate-50 cursor-not-allowed opacity-60"
            : "border-slate-300 hover:border-blue-500 bg-slate-50/50 hover:bg-slate-50"
        }`}
      >
        <input
          ref={fileInputRef}
          type="file"
          accept=".eml"
          onChange={handleChange}
          disabled={disabled || uploading}
          className="hidden"
        />

        <div className="flex items-center justify-center gap-2 text-xs">
          {uploading ? (
            <>
              <Loader2 className="w-4 h-4 text-blue-600 animate-spin" />
              <span className="font-medium text-slate-700">Preserving evidence & calculating SHA-256...</span>
            </>
          ) : (
            <>
              <FileText className="w-4 h-4 text-slate-400 shrink-0" />
              <span className="text-slate-700 font-medium">
                Drop raw <strong className="text-slate-900 font-semibold">.eml</strong> email file here, or{" "}
                <span className="text-blue-600 hover:underline">browse</span>
              </span>
              <span className="text-[10px] text-slate-400 font-mono hidden md:inline">• max 25 MB</span>
            </>
          )}
        </div>
      </div>

      {successMessage && (
        <div className="mt-2 flex items-center gap-1.5 text-[11px] text-emerald-700 bg-emerald-50 px-2.5 py-1 rounded border border-emerald-200">
          <CheckCircle2 className="w-3.5 h-3.5 shrink-0 text-emerald-600" />
          <span>{successMessage}</span>
        </div>
      )}

      {errorMessage && (
        <div className="mt-2 flex items-center gap-1.5 text-[11px] text-red-700 bg-red-50 px-2.5 py-1 rounded border border-red-200">
          <AlertTriangle className="w-3.5 h-3.5 shrink-0 text-red-600" />
          <span>{errorMessage}</span>
        </div>
      )}
    </div>
  );
};
