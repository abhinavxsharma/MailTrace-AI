import React, { useState } from "react";
import { RiskLevel, RiskContributions, RiskReason, AIResult, ForensicFeatures } from "../types";
import { downloadCaseReport } from "../api/client";
import {
  AlertTriangle,
  Bot,
  FileText,
  Download,
  Loader2,
  CheckCircle2,
} from "lucide-react";

interface RiskCardProps {
  caseId?: string | null;
  riskScore: number;
  riskLevel: RiskLevel;
  contributions: RiskContributions;
  reasons: RiskReason[];
  aiPrediction?: AIResult;
  confidence?: number;
  features?: ForensicFeatures;
  authSummary?: string;
  sourceIp?: string;
  sha256?: string;
}

export const RiskCard: React.FC<RiskCardProps> = ({
  caseId,
  riskScore,
  riskLevel,
  contributions,
  reasons,
  aiPrediction,
  confidence,
  features,
  authSummary,
  sourceIp,
  sha256,
}) => {
  const [downloadingFormat, setDownloadingFormat] = useState<"pdf" | "json" | null>(null);
  const [reportSuccess, setReportSuccess] = useState<string | null>(null);
  const [reportError, setReportError] = useState<string | null>(null);

  const getRiskBadge = (level: RiskLevel) => {
    switch (level) {
      case "CRITICAL":
        return "bg-red-50 text-red-700 border-red-200";
      case "HIGH":
        return "bg-amber-50 text-amber-800 border-amber-200";
      case "MEDIUM":
        return "bg-yellow-50 text-yellow-800 border-yellow-200";
      default:
        return "bg-emerald-50 text-emerald-800 border-emerald-200";
    }
  };

  const getScoreColor = (score: number) => {
    if (score >= 80) return "text-red-600";
    if (score >= 60) return "text-amber-600";
    if (score >= 40) return "text-yellow-600";
    return "text-emerald-600";
  };

  // Six contribution dimensions (Requirement 3)
  const contributionItems = [
    { label: "AI Threat", value: contributions?.ai_threat ?? 0, max: 25, color: "bg-purple-600" },
    { label: "Identity", value: contributions?.identity ?? 0, max: 20, color: "bg-blue-600" },
    { label: "Authentication", value: contributions?.authentication ?? 0, max: 15, color: "bg-amber-600" },
    { label: "URL / Domain", value: contributions?.url_domain ?? 0, max: 15, color: "bg-orange-600" },
    { label: "Infrastructure", value: contributions?.infrastructure ?? 0, max: 15, color: "bg-indigo-600" },
    { label: "Campaign", value: contributions?.campaign ?? 0, max: 10, color: "bg-rose-600" },
  ];

  // AI model prediction data (Requirement 6)
  const aiLabel = aiPrediction?.label || (riskScore >= 50 ? "MALICIOUS" : "BENIGN");
  const aiConfVal = (confidence || aiPrediction?.confidence || 0.85);
  const aiConfFormatted = `${(aiConfVal * 100).toFixed(1)}%`;
  const aiModelName = aiPrediction?.model || "dataset3_v1.0.0";

  // Forensic language signals (Requirement 6)
  const signals = [
    { label: "Urgency", active: !!features?.urgency_detected },
    { label: "Financial", active: !!features?.financial_detected },
    { label: "Credential", active: !!features?.credentials_detected },
    { label: "Authority", active: !!features?.authority_detected },
    { label: "Secrecy", active: !!features?.secrecy_detected },
    { label: "Action Request", active: !!(features?.urgency_detected || features?.financial_detected) },
    { label: "Suspicious Link", active: !!features?.suspicious_links_detected },
  ];

  const handleQuickDownload = async (format: "pdf" | "json") => {
    if (!caseId) return;
    setDownloadingFormat(format);
    setReportError(null);
    setReportSuccess(null);
    try {
      await downloadCaseReport(caseId, format);
      setReportSuccess(`${format.toUpperCase()} report exported.`);
      setTimeout(() => setReportSuccess(null), 4000);
    } catch {
      setReportError(`Failed to download ${format.toUpperCase()}.`);
      setTimeout(() => setReportError(null), 4000);
    } finally {
      setDownloadingFormat(null);
    }
  };

  return (
    <div className="space-y-3">
      {/* 1. Risk Summary Panel (Requirement 3) */}
      <div className="card bg-white border border-slate-200 rounded-lg p-3.5 shadow-xs text-xs">
        <div className="flex items-center justify-between pb-2 border-b border-slate-100">
          <span className="text-[10px] font-bold uppercase tracking-wider text-slate-500">
            Composite Forensic Risk Score
          </span>
          <span className={`text-[10px] font-bold px-2 py-0.5 rounded border uppercase tracking-wide ${getRiskBadge(riskLevel)}`}>
            {riskLevel} RISK
          </span>
        </div>

        {/* Big Score Display */}
        <div className="my-3 flex items-baseline justify-between">
          <div>
            <div className="text-[10px] uppercase font-bold text-slate-400 tracking-wider">Assessed Threat Score</div>
            <div className="text-[11px] text-slate-500 mt-0.5">Calibrated 0–100 evidence fusion</div>
          </div>
          <div className="flex items-baseline gap-1 font-mono">
            <span className={`text-4xl font-extrabold tracking-tight ${getScoreColor(riskScore)}`}>
              {riskScore}
            </span>
            <span className="text-slate-400 text-sm font-medium">/ 100</span>
          </div>
        </div>

        {/* Six Thin Horizontal Contribution Bars (Requirement 3) */}
        <div className="space-y-2 pt-2 border-t border-slate-100">
          <div className="text-[10px] font-bold uppercase tracking-wider text-slate-400 flex items-center justify-between">
            <span>Evidence Dimensions</span>
            <span className="font-mono">Contribution Points</span>
          </div>

          <div className="space-y-2">
            {contributionItems.map((item) => {
              const pct = Math.round((item.value / item.max) * 100);
              return (
                <div key={item.label} className="text-xs">
                  <div className="flex items-center justify-between text-[11px] mb-1">
                    <span className="text-slate-700 font-medium">{item.label}</span>
                    <span className="font-mono font-semibold text-slate-900">
                      {item.value} <span className="text-slate-400 text-[10px] font-normal">/ {item.max}</span>
                    </span>
                  </div>
                  <div className="contrib-bar">
                    <div
                      className={`contrib-fill ${item.color}`}
                      style={{ width: `${pct}%` }}
                    />
                  </div>
                </div>
              );
            })}
          </div>
        </div>
      </div>

      {/* 2. AI Threat Detection Panel (Requirement 6) */}
      <div className="card bg-white border border-slate-200 rounded-lg p-3.5 shadow-xs text-xs">
        <div className="flex items-center justify-between pb-2 mb-2.5 border-b border-slate-100">
          <span className="text-[10px] font-bold uppercase tracking-wider text-slate-500 flex items-center gap-1.5">
            <Bot className="w-3.5 h-3.5 text-purple-600" />
            <span>AI Threat Detection</span>
          </span>
          <span className="text-[10px] font-mono text-slate-500 bg-slate-100 px-1.5 py-0.2 rounded border border-slate-200">
            {aiModelName}
          </span>
        </div>

        {/* Model Classification & Confidence */}
        <div className="flex items-center justify-between p-2.5 bg-slate-50 rounded border border-slate-200 mb-2.5">
          <div>
            <div className="text-[9px] uppercase font-bold text-slate-400">Classification</div>
            <div className={`text-sm font-bold mt-0.5 ${aiLabel === "MALICIOUS" ? "text-red-700 font-mono" : "text-emerald-700 font-mono"}`}>
              {aiLabel}
            </div>
          </div>
          <div className="text-right">
            <div className="text-[9px] uppercase font-bold text-slate-400">Confidence</div>
            <div className="text-sm font-mono font-bold text-slate-900 mt-0.5">
              {aiConfFormatted}
            </div>
          </div>
        </div>

        {/* Detected Forensic Language Signals (Requirement 6) */}
        <div>
          <div className="text-[10px] font-bold uppercase tracking-wider text-slate-400 mb-1.5">
            Detected Forensic Signals
          </div>
          <div className="flex flex-wrap gap-1.5">
            {signals.map((sig) => (
              <span
                key={sig.label}
                className={`text-[10px] px-2 py-0.5 rounded font-medium border transition-colors ${
                  sig.active
                    ? "bg-red-50 text-red-800 border-red-200 font-semibold"
                    : "bg-slate-50 text-slate-400 border-slate-200/80"
                }`}
              >
                {sig.label}
              </span>
            ))}
          </div>
        </div>
      </div>

      {/* 3. Risk Explanation: WHY THIS SCORE? (Requirement 7) */}
      <div className="card bg-white border border-slate-200 rounded-lg p-3.5 shadow-xs text-xs">
        <div className="flex items-center justify-between pb-2 mb-2 border-b border-slate-100">
          <span className="text-[10px] font-bold uppercase tracking-wider text-slate-500">
            Why This Score?
          </span>
          <span className="text-[10px] font-mono text-slate-400">
            {reasons.length} Triggered Rules
          </span>
        </div>

        {reasons.length === 0 ? (
          <div className="p-3 bg-slate-50 rounded border border-slate-200 text-[11px] text-slate-400 text-center">
            No elevated risk rules triggered.
          </div>
        ) : (
          <div className="space-y-1.5 max-h-52 overflow-y-auto pr-1">
            {reasons.map((r, idx) => (
              <div
                key={idx}
                className="p-2 rounded border border-slate-200 bg-slate-50/60 hover:bg-slate-50 transition-colors flex items-start gap-2"
              >
                <span className="font-mono text-[10px] font-bold text-red-700 bg-red-50 border border-red-200 px-1.5 py-0.2 rounded shrink-0">
                  {r.points}
                </span>
                <div className="text-[11px] leading-tight">
                  <div className="font-semibold text-slate-800">{r.rule}</div>
                  <div className="text-slate-500 text-[10px] mt-0.5 leading-snug">{r.description}</div>
                </div>
              </div>
            ))}
          </div>
        )}
      </div>

      {/* 4. Forensic Report Actions Area (Requirement 13) */}
      <div className="card bg-white border border-slate-200 rounded-lg p-3.5 shadow-xs text-xs">
        <div className="flex items-center justify-between pb-2 mb-2 border-b border-slate-100">
          <span className="text-[10px] font-bold uppercase tracking-wider text-slate-500 flex items-center gap-1.5">
            <FileText className="w-3.5 h-3.5 text-blue-600" />
            <span>Forensic Report</span>
          </span>
          <span className="text-[10px] text-slate-400 font-mono">EXPORT</span>
        </div>

        {/* Compact Summary Preview (Requirement 13) */}
        <div className="bg-slate-50 rounded border border-slate-200 p-2.5 text-[11px] font-mono space-y-1 mb-2.5">
          <div className="flex justify-between">
            <span className="text-slate-400 font-sans">Case ID:</span>
            <span className="font-bold text-slate-800">{caseId || "N/A"}</span>
          </div>
          <div className="flex justify-between">
            <span className="text-slate-400 font-sans">Risk Score:</span>
            <span className="font-bold text-slate-800">{riskScore}/100 ({riskLevel})</span>
          </div>
          <div className="flex justify-between">
            <span className="text-slate-400 font-sans">AI Result:</span>
            <span className="font-bold text-slate-800">{aiLabel} ({aiConfFormatted})</span>
          </div>
          <div className="flex justify-between">
            <span className="text-slate-400 font-sans">Authentication:</span>
            <span className="font-bold text-slate-800">{authSummary || "DMARC FAIL"}</span>
          </div>
          <div className="flex justify-between">
            <span className="text-slate-400 font-sans">Source IP:</span>
            <span className="font-bold text-slate-800 truncate max-w-[140px]" title={sourceIp || "Unavailable"}>
              {sourceIp || "Unavailable"}
            </span>
          </div>
          {sha256 && (
            <div className="flex justify-between truncate">
              <span className="text-slate-400 font-sans shrink-0 mr-1">SHA-256:</span>
              <span className="text-slate-600 truncate text-[10px]" title={sha256}>
                {sha256.substring(0, 10)}...{sha256.substring(sha256.length - 6)}
              </span>
            </div>
          )}
        </div>

        {/* Feedback alerts */}
        {reportSuccess && (
          <div className="mb-2 p-1.5 rounded bg-emerald-50 border border-emerald-200 text-emerald-800 text-[11px] flex items-center gap-1.5">
            <CheckCircle2 className="w-3.5 h-3.5 text-emerald-600 shrink-0" />
            <span>{reportSuccess}</span>
          </div>
        )}
        {reportError && (
          <div className="mb-2 p-1.5 rounded bg-red-50 border border-red-200 text-red-800 text-[11px] flex items-center gap-1.5">
            <AlertTriangle className="w-3.5 h-3.5 text-red-600 shrink-0" />
            <span>{reportError}</span>
          </div>
        )}

        {/* Download Buttons */}
        <div className="grid grid-cols-2 gap-2">
          <button
            onClick={() => handleQuickDownload("pdf")}
            disabled={!caseId || downloadingFormat !== null}
            className="flex items-center justify-center gap-1.5 px-3 py-2 rounded bg-slate-900 hover:bg-slate-800 text-white font-semibold text-xs shadow-xs transition-colors disabled:opacity-50"
          >
            {downloadingFormat === "pdf" ? (
              <Loader2 className="w-3.5 h-3.5 animate-spin" />
            ) : (
              <FileText className="w-3.5 h-3.5" />
            )}
            <span>Generate PDF</span>
          </button>

          <button
            onClick={() => handleQuickDownload("json")}
            disabled={!caseId || downloadingFormat !== null}
            className="flex items-center justify-center gap-1.5 px-3 py-2 rounded bg-slate-100 hover:bg-slate-200 text-slate-800 border border-slate-300 font-semibold text-xs shadow-xs transition-colors disabled:opacity-50"
          >
            {downloadingFormat === "json" ? (
              <Loader2 className="w-3.5 h-3.5 animate-spin text-slate-600" />
            ) : (
              <Download className="w-3.5 h-3.5 text-slate-600" />
            )}
            <span>Download JSON</span>
          </button>
        </div>
      </div>
    </div>
  );
};
