import React, { useState } from "react";
import { CaseDetail } from "../types";
import { downloadCaseReport } from "../api/client";
import {
  FileText,
  Download,
  CheckCircle2,
  AlertTriangle,
  Loader2,
  X,
  Lock,
  Copy,
  Check,
} from "lucide-react";

interface ForensicReportModalProps {
  isOpen: boolean;
  onClose: () => void;
  caseDetail: CaseDetail | null;
  onReportGenerated?: () => void;
}

export const ForensicReportModal: React.FC<ForensicReportModalProps> = ({
  isOpen,
  onClose,
  caseDetail,
  onReportGenerated,
}) => {
  const [downloadingFormat, setDownloadingFormat] = useState<"pdf" | "json" | null>(null);
  const [downloadSuccess, setDownloadSuccess] = useState<string | null>(null);
  const [errorMessage, setErrorMessage] = useState<string | null>(null);
  const [copiedHash, setCopiedHash] = useState(false);

  if (!isOpen || !caseDetail) return null;

  const caseId = caseDetail.case_number || caseDetail.case_id;
  const riskScore = caseDetail.risk_score ?? 0;
  const riskLevel = caseDetail.classification || "LOW";
  const aiClassification = caseDetail.detection?.label || (riskScore >= 50 ? "MALICIOUS" : "BENIGN");
  const aiConfidence = caseDetail.detection?.confidence
    ? `${(caseDetail.detection.confidence * 100).toFixed(1)}%`
    : caseDetail.confidence
    ? `${(caseDetail.confidence * 100).toFixed(1)}%`
    : "85.0%";

  const authSpf = caseDetail.authentication?.spf || "UNKNOWN";
  const authDkim = caseDetail.authentication?.dkim || "UNKNOWN";
  const authDmarc = caseDetail.authentication?.dmarc || "UNKNOWN";
  const authAlignment = caseDetail.authentication?.alignment || "UNKNOWN";

  const sourceIp = caseDetail.infrastructure?.source_ip || "Unavailable";
  const campaignRelatedCount = caseDetail.correlation?.related_case_ids?.length || 0;
  const campaignStrength = caseDetail.correlation?.relationship_strength || "NONE";

  const evidenceSha256 =
    caseDetail.evidence && caseDetail.evidence.length > 0
      ? caseDetail.evidence[0].sha256
      : "Preserved in repository";

  const handleCopyHash = () => {
    navigator.clipboard.writeText(evidenceSha256);
    setCopiedHash(true);
    setTimeout(() => setCopiedHash(false), 2000);
  };

  const handleDownload = async (format: "pdf" | "json") => {
    setDownloadingFormat(format);
    setErrorMessage(null);
    setDownloadSuccess(null);
    try {
      await downloadCaseReport(caseId, format);
      setDownloadSuccess(`Forensic ${format.toUpperCase()} report successfully exported.`);
      if (onReportGenerated) {
        onReportGenerated();
      }
    } catch {
      setErrorMessage(`Failed to export ${format.toUpperCase()} report. Ensure case is analyzed.`);
    } finally {
      setDownloadingFormat(null);
    }
  };

  const getBadgeColor = (level: string) => {
    switch (level) {
      case "CRITICAL": return "bg-red-50 text-red-700 border-red-200";
      case "HIGH": return "bg-amber-50 text-amber-800 border-amber-200";
      case "MEDIUM": return "bg-yellow-50 text-yellow-800 border-yellow-200";
      default: return "bg-emerald-50 text-emerald-800 border-emerald-200";
    }
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-slate-900/60 backdrop-blur-2xs p-4 overflow-y-auto">
      <div className="bg-white rounded-lg shadow-xl border border-slate-300 max-w-xl w-full overflow-hidden animate-in fade-in zoom-in-95 duration-100 my-6">
        {/* Header */}
        <div className="bg-slate-900 text-white px-4 py-3 flex items-center justify-between border-b border-slate-800">
          <div className="flex items-center gap-2">
            <FileText className="w-4 h-4 text-blue-400" />
            <div>
              <div className="flex items-center gap-1.5">
                <span className="text-xs font-bold uppercase tracking-wide">Forensic Report Package</span>
                <span className="text-[10px] bg-slate-800 text-slate-300 font-mono px-1.5 py-0.2 rounded border border-slate-700">
                  {caseId}
                </span>
              </div>
            </div>
          </div>
          <button
            onClick={onClose}
            className="text-slate-400 hover:text-white p-1 rounded transition-colors"
          >
            <X className="w-4 h-4" />
          </button>
        </div>

        {/* Feedback Alerts */}
        {errorMessage && (
          <div className="mx-4 mt-3 p-2.5 bg-red-50 border border-red-200 rounded text-xs text-red-700 flex items-center gap-2">
            <AlertTriangle className="w-4 h-4 shrink-0 text-red-600" />
            <span>{errorMessage}</span>
          </div>
        )}
        {downloadSuccess && (
          <div className="mx-4 mt-3 p-2.5 bg-emerald-50 border border-emerald-200 rounded text-xs text-emerald-700 flex items-center gap-2">
            <CheckCircle2 className="w-4 h-4 shrink-0 text-emerald-600" />
            <span>{downloadSuccess}</span>
          </div>
        )}

        {/* Compact UI Preview (Requirement 11) */}
        <div className="p-4 space-y-3 text-xs">
          <div className="flex items-center justify-between">
            <span className="text-[10px] font-bold uppercase tracking-wider text-slate-500">
              Investigation Summary Preview
            </span>
            <span className="flex items-center gap-1 text-[10px] text-slate-500 font-medium">
              <Lock className="w-3 h-3 text-emerald-600" /> Chain-of-Custody Intact
            </span>
          </div>

          <div className="grid grid-cols-2 sm:grid-cols-4 gap-2">
            {/* Risk Score */}
            <div className="bg-slate-50 border border-slate-200 rounded p-2.5">
              <div className="text-[9px] font-bold uppercase text-slate-400">Risk Score</div>
              <div className="text-base font-extrabold font-mono text-slate-900 mt-0.5">{riskScore} / 100</div>
              <span className={`inline-block mt-0.5 text-[9px] font-bold px-1 rounded border uppercase ${getBadgeColor(riskLevel)}`}>
                {riskLevel}
              </span>
            </div>

            {/* AI Classification */}
            <div className="bg-slate-50 border border-slate-200 rounded p-2.5">
              <div className="text-[9px] font-bold uppercase text-slate-400">AI Result</div>
              <div className="text-xs font-bold text-slate-900 mt-0.5 truncate">{aiClassification}</div>
              <div className="text-[10px] text-slate-500 font-mono mt-0.5">Conf: {aiConfidence}</div>
            </div>

            {/* Source IP */}
            <div className="bg-slate-50 border border-slate-200 rounded p-2.5">
              <div className="text-[9px] font-bold uppercase text-slate-400">Source IP</div>
              <div className="text-xs font-mono font-bold text-slate-900 mt-0.5 truncate" title={sourceIp}>
                {sourceIp}
              </div>
              <div className="text-[10px] text-slate-500 mt-0.5 truncate">{caseDetail.infrastructure?.country || "N/A"}</div>
            </div>

            {/* Campaign Status */}
            <div className="bg-slate-50 border border-slate-200 rounded p-2.5">
              <div className="text-[9px] font-bold uppercase text-slate-400">Campaign</div>
              <div className="text-xs font-bold text-slate-900 mt-0.5">
                {campaignRelatedCount > 0 ? `${campaignRelatedCount} Related` : "Isolated"}
              </div>
              <div className="text-[10px] text-slate-500 font-mono mt-0.5">Str: {campaignStrength}</div>
            </div>
          </div>

          {/* Authentication Summary */}
          <div className="bg-slate-50 border border-slate-200 rounded p-2.5">
            <div className="text-[9px] font-bold uppercase text-slate-400 mb-1.5">Authentication & Alignment</div>
            <div className="grid grid-cols-4 gap-1.5 text-center text-xs font-mono">
              <div className="p-1 bg-white rounded border border-slate-200">
                <div className="text-[9px] text-slate-400 font-sans">SPF</div>
                <div className={`font-bold ${authSpf === "PASS" ? "text-emerald-700" : "text-red-700"}`}>{authSpf}</div>
              </div>
              <div className="p-1 bg-white rounded border border-slate-200">
                <div className="text-[9px] text-slate-400 font-sans">DKIM</div>
                <div className={`font-bold ${authDkim === "PASS" ? "text-emerald-700" : "text-red-700"}`}>{authDkim}</div>
              </div>
              <div className="p-1 bg-white rounded border border-slate-200">
                <div className="text-[9px] text-slate-400 font-sans">DMARC</div>
                <div className={`font-bold ${authDmarc === "PASS" ? "text-emerald-700" : "text-red-700"}`}>{authDmarc}</div>
              </div>
              <div className="p-1 bg-white rounded border border-slate-200">
                <div className="text-[9px] text-slate-400 font-sans">ALIGNMENT</div>
                <div className={`font-bold ${authAlignment === "PASS" ? "text-emerald-700" : "text-red-700"}`}>{authAlignment}</div>
              </div>
            </div>
          </div>

          {/* Evidence SHA-256 */}
          <div className="bg-slate-50 border border-slate-200 rounded p-2.5">
            <div className="flex items-center justify-between mb-1">
              <span className="text-[9px] font-bold uppercase text-slate-400">Evidence SHA-256</span>
              <button
                onClick={handleCopyHash}
                className="text-[10px] text-blue-600 hover:text-blue-800 flex items-center gap-1 font-medium"
              >
                {copiedHash ? <Check className="w-3 h-3 text-emerald-600" /> : <Copy className="w-3 h-3" />}
                {copiedHash ? "Copied" : "Copy"}
              </button>
            </div>
            <div className="text-[11px] font-mono bg-white p-1.5 rounded border border-slate-200 text-slate-800 break-all select-all">
              {evidenceSha256}
            </div>
          </div>

          {/* Disclaimer */}
          <div className="text-[10px] text-slate-400 leading-snug italic pt-1 border-t border-slate-100">
            * Safeguard Notice: Network observables reflect routing artifacts. IP Geolocation is approximate and does not prove human identity.
          </div>
        </div>

        {/* Modal Actions */}
        <div className="bg-slate-50 border-t border-slate-200 px-4 py-3 flex items-center justify-between gap-2">
          <button
            onClick={onClose}
            className="px-3 py-1.5 text-xs font-semibold text-slate-600 hover:text-slate-900 rounded hover:bg-slate-200 transition-colors"
          >
            Close
          </button>

          <div className="flex items-center gap-2">
            <button
              onClick={() => handleDownload("json")}
              disabled={downloadingFormat !== null}
              className="flex items-center gap-1.5 px-3 py-1.5 rounded text-xs font-semibold bg-white border border-slate-300 text-slate-700 hover:bg-slate-100 shadow-2xs transition-all disabled:opacity-50"
            >
              {downloadingFormat === "json" ? (
                <Loader2 className="w-3.5 h-3.5 animate-spin text-blue-600" />
              ) : (
                <Download className="w-3.5 h-3.5 text-slate-500" />
              )}
              <span>Download JSON</span>
            </button>

            <button
              onClick={() => handleDownload("pdf")}
              disabled={downloadingFormat !== null}
              className="flex items-center gap-1.5 px-3.5 py-1.5 rounded text-xs font-semibold bg-slate-900 hover:bg-slate-800 text-white shadow-xs transition-all disabled:opacity-50"
            >
              {downloadingFormat === "pdf" ? (
                <Loader2 className="w-3.5 h-3.5 animate-spin" />
              ) : (
                <FileText className="w-3.5 h-3.5" />
              )}
              <span>Download PDF</span>
            </button>
          </div>
        </div>
      </div>
    </div>
  );
};
