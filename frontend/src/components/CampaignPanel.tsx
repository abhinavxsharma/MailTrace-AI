import React from "react";
import { CorrelationData } from "../types";
import { Share2, Link2, FileText, AlertCircle } from "lucide-react";

interface CampaignPanelProps {
  correlation?: CorrelationData | null;
  isLoading?: boolean;
}

export const CampaignPanel: React.FC<CampaignPanelProps> = ({ correlation, isLoading }) => {
  const getStrengthBadge = (strength?: string) => {
    switch (strength) {
      case "HIGH":
        return "bg-red-50 text-red-700 border-red-200";
      case "MEDIUM":
        return "bg-amber-50 text-amber-700 border-amber-200";
      case "LOW":
        return "bg-blue-50 text-blue-700 border-blue-200";
      case "NONE":
      default:
        return "bg-slate-100 text-slate-500 border-slate-200";
    }
  };

  const strengthClass = getStrengthBadge(correlation?.relationship_strength);
  const relatedCases = correlation?.related_case_ids || [];
  const sharedIndicators = correlation?.shared_indicators || [];
  const reasons = correlation?.correlation_reasons || [];
  const campaignScore = correlation?.campaign_score || 0;

  return (
    <div className="card bg-white border border-slate-200 rounded-lg p-4 shadow-xs text-xs">
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 pb-3 mb-3 border-b border-slate-100">
        <div>
          <div className="flex items-center gap-2">
            <h2 className="text-sm font-bold text-slate-900 tracking-tight">Potential Campaign Relationship</h2>
            <span className={`text-[10px] font-bold px-2 py-0.5 rounded border uppercase font-mono ${strengthClass}`}>
              {correlation?.relationship_strength || "NONE"} STRENGTH
            </span>
          </div>
          <p className="text-[11px] text-slate-500 mt-0.5">
            Cross-case correlation identifying shared threat infrastructure across active investigations
          </p>
        </div>

        <div className="flex items-center gap-1.5 self-end sm:self-auto font-mono">
          <span className="text-[11px] text-slate-400 font-sans">Campaign Score:</span>
          <span className="text-xs font-bold text-slate-900 bg-slate-50 px-2 py-0.5 rounded border border-slate-200">
            +{campaignScore} <span className="text-slate-400 font-normal">/ 10</span>
          </span>
        </div>
      </div>

      {isLoading ? (
        <div className="p-8 text-center text-xs text-slate-400 font-mono animate-pulse">
          Correlating observables with recorded cases...
        </div>
      ) : relatedCases.length === 0 ? (
        <div className="p-6 bg-slate-50 rounded-lg border border-slate-200 text-center text-xs text-slate-500">
          <Share2 className="w-6 h-6 text-slate-300 mx-auto mb-1.5 stroke-[1.5]" />
          <div className="font-semibold text-slate-700">No campaign relationship detected.</div>
          <p className="text-slate-400 text-[11px] mt-0.5">
            This case does not share suspicious observables with any other recorded investigation.
          </p>
        </div>
      ) : (
        <div className="space-y-3">
          {/* Related Cases */}
          <div>
            <div className="text-[10px] font-bold uppercase tracking-wider text-slate-400 mb-1.5 flex items-center gap-1.5">
              <FileText className="w-3.5 h-3.5 text-blue-600" />
              <span>Related Cases ({relatedCases.length})</span>
            </div>
            <div className="flex flex-wrap gap-1.5">
              {relatedCases.map((caseId) => (
                <span
                  key={caseId}
                  className="px-2 py-0.5 rounded bg-blue-50 border border-blue-200 text-blue-800 text-[11px] font-mono font-bold"
                >
                  {caseId}
                </span>
              ))}
            </div>
          </div>

          {/* Shared Indicators */}
          {sharedIndicators.length > 0 && (
            <div>
              <div className="text-[10px] font-bold uppercase tracking-wider text-slate-400 mb-1.5 flex items-center gap-1.5">
                <Link2 className="w-3.5 h-3.5 text-indigo-600" />
                <span>Shared Infrastructure Indicators ({sharedIndicators.length})</span>
              </div>
              <div className="grid sm:grid-cols-2 gap-2">
                {sharedIndicators.map((si, idx) => (
                  <div
                    key={idx}
                    className="p-2 bg-slate-50 rounded border border-slate-200 text-xs font-mono flex items-center justify-between gap-2"
                  >
                    <div className="truncate">
                      <span className="text-[9px] uppercase text-slate-400 font-sans block">{si.type}</span>
                      <span className="font-semibold text-slate-800 truncate block">{si.value}</span>
                    </div>
                    {si.related_case && (
                      <span className="text-[9px] text-slate-500 bg-white border border-slate-200 px-1.5 py-0.2 rounded shrink-0">
                        {si.related_case}
                      </span>
                    )}
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* Correlation Reasons */}
          {reasons.length > 0 && (
            <div>
              <div className="text-[10px] font-bold uppercase tracking-wider text-slate-400 mb-1.5 flex items-center gap-1.5">
                <AlertCircle className="w-3.5 h-3.5 text-amber-600" />
                <span>Correlation Findings</span>
              </div>
              <div className="space-y-1 text-xs">
                {reasons.map((r, idx) => (
                  <div
                    key={idx}
                    className="p-2 rounded border border-amber-200/80 bg-amber-50/50 text-amber-900 leading-snug text-[11px]"
                  >
                    {r}
                  </div>
                ))}
              </div>
            </div>
          )}
        </div>
      )}

      {/* Forensic Safety Notice */}
      <div className="mt-3 p-2 rounded bg-slate-50 border border-slate-200 text-[10px] text-slate-500 leading-relaxed italic">
        * Campaign correlation establishes potential campaign relationships based on observed technical indicators. It does not prove identical human actors.
      </div>
    </div>
  );
};
