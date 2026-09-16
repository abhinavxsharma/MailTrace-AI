import React from "react";
import { CaseStatus } from "../types";
import { Check, Cpu, ArrowRight, Loader2, FileText } from "lucide-react";

interface CaseWorkflowBarProps {
  currentStatus: CaseStatus | "INIT";
  caseId?: string | null;
  onVerify: () => void;
  onAnalyze: () => void;
  onOpenReport?: () => void;
  isVerifying: boolean;
  isAnalyzing: boolean;
}

const STAGES = [
  { id: "UPLOAD", label: "UPLOAD" },
  { id: "PARSED", label: "PARSED" },
  { id: "VERIFY", label: "VERIFY" },
  { id: "ANALYZE", label: "ANALYZE" },
  { id: "INVESTIGATE", label: "INVESTIGATE" },
];

export const CaseWorkflowBar: React.FC<CaseWorkflowBarProps> = ({
  currentStatus,
  caseId,
  onVerify,
  onAnalyze,
  onOpenReport,
  isVerifying,
  isAnalyzing,
}) => {
  const getStageIndex = (status: string) => {
    switch (status) {
      case "INIT": return 0;
      case "UPLOADED": return 1;
      case "PARSED": return 1;
      case "VERIFIED": return 2;
      case "ANALYZED":
      case "REPORTED":
      case "CORRELATED":
        return 4;
      default: return 1;
    }
  };

  const currentIndex = getStageIndex(currentStatus);
  const canVerify = !!caseId && (currentStatus === "PARSED" || currentStatus === "VERIFIED");
  const canAnalyze = !!caseId && (currentStatus === "PARSED" || currentStatus === "VERIFIED" || currentStatus === "ANALYZED" || currentStatus === "REPORTED");
  const canReport = !!caseId && (currentStatus === "ANALYZED" || currentStatus === "REPORTED" || currentStatus === "CORRELATED");

  return (
    <div className="card p-2.5 bg-white border border-slate-200 rounded-lg flex flex-col md:flex-row items-center justify-between gap-3 shadow-xs">
      {/* Subtle Step Progression */}
      <div className="flex items-center gap-2 overflow-x-auto w-full md:w-auto py-0.5">
        {STAGES.map((s, idx) => {
          const isCompleted = idx < currentIndex;
          const isCurrent = idx === currentIndex;
          const isPending = idx > currentIndex;

          return (
            <React.Fragment key={s.id}>
              <div className="flex items-center gap-1.5 shrink-0">
                <div
                  className={`w-5 h-5 rounded flex items-center justify-center text-[10px] font-bold font-mono transition-all ${
                    isCompleted
                      ? "bg-emerald-600 text-white"
                      : isCurrent
                      ? "bg-slate-900 text-white ring-2 ring-slate-200"
                      : "bg-slate-100 text-slate-400 border border-slate-200"
                  }`}
                >
                  {isCompleted ? <Check className="w-3 h-3 stroke-[3]" /> : idx + 1}
                </div>
                <span
                  className={`text-[11px] font-semibold tracking-wider font-mono ${
                    isCurrent
                      ? "text-slate-900 font-bold"
                      : isCompleted
                      ? "text-slate-700"
                      : "text-slate-400 font-normal"
                  }`}
                >
                  {s.label}
                </span>
              </div>
              {idx < STAGES.length - 1 && (
                <ArrowRight className="w-3 h-3 text-slate-300 shrink-0" />
              )}
            </React.Fragment>
          );
        })}
      </div>

      {/* Primary Actions */}
      <div className="flex items-center gap-2 shrink-0 w-full md:w-auto justify-end">
        {/* Verify Email */}
        <button
          onClick={onVerify}
          disabled={!canVerify || isVerifying || isAnalyzing}
          className={`flex items-center gap-1.5 px-3 py-1.5 rounded text-xs font-semibold transition-all ${
            canVerify && !isVerifying
              ? "bg-slate-900 hover:bg-slate-800 text-white shadow-xs"
              : "bg-slate-100 text-slate-400 cursor-not-allowed border border-slate-200"
          }`}
        >
          {isVerifying ? (
            <>
              <Loader2 className="w-3 h-3 animate-spin" />
              <span>Verifying...</span>
            </>
          ) : (
            <>
              <Check className="w-3.5 h-3.5 text-slate-300" />
              <span>Verify Email</span>
            </>
          )}
        </button>

        {/* Analyze Email */}
        <button
          onClick={onAnalyze}
          disabled={!canAnalyze || isAnalyzing || isVerifying}
          className={`flex items-center gap-1.5 px-3 py-1.5 rounded text-xs font-semibold transition-all ${
            canAnalyze && !isAnalyzing
              ? "bg-blue-600 hover:bg-blue-700 text-white shadow-xs"
              : "bg-slate-100 text-slate-400 cursor-not-allowed border border-slate-200"
          }`}
        >
          {isAnalyzing ? (
            <>
              <Loader2 className="w-3 h-3 animate-spin" />
              <span>Analyzing Threat...</span>
            </>
          ) : (
            <>
              <Cpu className="w-3.5 h-3.5 text-blue-200" />
              <span>Analyze Email</span>
            </>
          )}
        </button>

        {/* Generate Report */}
        {canReport && (
          <button
            onClick={onOpenReport}
            className="flex items-center gap-1.5 px-3 py-1.5 rounded text-xs font-semibold bg-slate-50 hover:bg-slate-100 text-slate-800 border border-slate-300 shadow-xs transition-all"
          >
            <FileText className="w-3.5 h-3.5 text-slate-600" />
            <span>Forensic Report</span>
          </button>
        )}
      </div>
    </div>
  );
};
