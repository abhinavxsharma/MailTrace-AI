import React from "react";
import { AuthenticationData, IdentityData, AuthStatus } from "../types";
import { AlertCircle } from "lucide-react";

interface AuthenticationPanelProps {
  auth?: AuthenticationData | null;
  identity?: IdentityData | null;
}

export const AuthenticationPanel: React.FC<AuthenticationPanelProps> = ({ auth, identity }) => {
  const getStatusStyle = (status?: AuthStatus) => {
    switch (status) {
      case "PASS":
        return "bg-emerald-50 text-emerald-800 border-emerald-200 font-bold";
      case "FAIL":
        return "bg-red-50 text-red-800 border-red-200 font-bold";
      case "UNAVAILABLE":
        return "bg-slate-100 text-slate-600 border-slate-200 font-medium";
      case "UNKNOWN":
      case "NONE":
      default:
        return "bg-amber-50 text-amber-800 border-amber-200 font-medium";
    }
  };

  const spfStatus = auth?.spf || "UNKNOWN";
  const dkimStatus = auth?.dkim || "UNKNOWN";
  const dmarcStatus = auth?.dmarc || "UNKNOWN";
  const alignmentStatus = auth?.alignment || "UNKNOWN";

  return (
    <div className="card bg-white border border-slate-200 rounded-lg p-3.5 shadow-xs text-xs">
      {/* Header */}
      <div className="flex items-center justify-between pb-2 mb-2.5 border-b border-slate-100">
        <span className="text-[10px] font-bold uppercase tracking-wider text-slate-500">
          Cryptographic Authentication & Policy Alignment
        </span>
        <div className="flex items-center gap-1.5">
          <span className="text-[10px] text-slate-400 font-mono">DMARC ALIGNMENT:</span>
          <span
            className={`text-[10px] font-mono px-2 py-0.5 rounded border ${
              alignmentStatus === "PASS"
                ? "bg-emerald-50 text-emerald-800 border-emerald-200 font-bold"
                : "bg-red-50 text-red-800 border-red-200 font-bold"
            }`}
          >
            {alignmentStatus}
          </span>
        </div>
      </div>

      {/* Professional Row: SPF | DKIM | DMARC (Requirement 5) */}
      <div className="grid grid-cols-3 gap-2 mb-3">
        {/* SPF */}
        <div className="p-2 bg-slate-50 rounded border border-slate-200 text-center">
          <div className="text-[10px] font-bold text-slate-500 font-mono">SPF</div>
          <div className={`mt-1 text-xs py-0.5 px-2 rounded border font-mono ${getStatusStyle(spfStatus)}`}>
            {spfStatus}
          </div>
          <div className="text-[9px] text-slate-400 mt-1 truncate">
            {spfStatus === "PASS" ? "Sender IP authorized" : spfStatus === "FAIL" ? "IP unauthorized" : "No SPF record"}
          </div>
        </div>

        {/* DKIM */}
        <div className="p-2 bg-slate-50 rounded border border-slate-200 text-center">
          <div className="text-[10px] font-bold text-slate-500 font-mono">DKIM</div>
          <div className={`mt-1 text-xs py-0.5 px-2 rounded border font-mono ${getStatusStyle(dkimStatus)}`}>
            {dkimStatus}
          </div>
          <div className="text-[9px] text-slate-400 mt-1 truncate">
            {dkimStatus === "PASS" ? "Signature verified" : dkimStatus === "FAIL" ? "Signature invalid" : "No signature"}
          </div>
        </div>

        {/* DMARC */}
        <div className="p-2 bg-slate-50 rounded border border-slate-200 text-center">
          <div className="text-[10px] font-bold text-slate-500 font-mono">DMARC</div>
          <div className={`mt-1 text-xs py-0.5 px-2 rounded border font-mono ${getStatusStyle(dmarcStatus)}`}>
            {dmarcStatus}
          </div>
          <div className="text-[9px] text-slate-400 mt-1 truncate">
            {dmarcStatus === "PASS" ? "Policy aligned" : dmarcStatus === "FAIL" ? "Policy failed" : "No policy published"}
          </div>
        </div>
      </div>

      {/* Identity Consistency Section (Requirement 5) */}
      {identity && (
        <div className="pt-2 border-t border-slate-100">
          <div className="flex items-center justify-between mb-1.5">
            <span className="text-[10px] font-bold uppercase tracking-wider text-slate-500">
              Identity Consistency
            </span>
            {(identity.reply_to_mismatch || identity.return_path_mismatch) && (
              <span className="text-[10px] font-semibold text-red-700 bg-red-50 border border-red-200 px-1.5 py-0.2 rounded flex items-center gap-1">
                <AlertCircle className="w-3 h-3 text-red-600" />
                <span>Inconsistency Flagged</span>
              </span>
            )}
          </div>

          <div className="grid grid-cols-1 sm:grid-cols-3 gap-2 font-mono text-xs">
            {/* From Domain */}
            <div className="p-2 rounded border border-slate-200 bg-slate-50">
              <span className="text-[9px] uppercase font-sans text-slate-400 block">From Domain</span>
              <span className="font-bold text-slate-800 truncate block mt-0.5" title={identity.from_domain || "None"}>
                {identity.from_domain || "None"}
              </span>
            </div>

            {/* Reply-To Domain */}
            <div
              className={`p-2 rounded border transition-all ${
                identity.reply_to_mismatch
                  ? "border-red-300 bg-red-50/70"
                  : "border-slate-200 bg-slate-50"
              }`}
            >
              <div className="flex items-center justify-between">
                <span className="text-[9px] uppercase font-sans text-slate-400 block">Reply-To Domain</span>
                {identity.reply_to_mismatch && (
                  <span className="text-[8px] font-bold text-red-700 bg-red-100 px-1 rounded uppercase">Mismatch</span>
                )}
              </div>
              <span
                className={`font-bold truncate block mt-0.5 ${
                  identity.reply_to_mismatch ? "text-red-800" : "text-slate-800"
                }`}
                title={identity.reply_to_domain || "Same as From"}
              >
                {identity.reply_to_domain || "Same as From"}
              </span>
            </div>

            {/* Return-Path Domain */}
            <div
              className={`p-2 rounded border transition-all ${
                identity.return_path_mismatch
                  ? "border-amber-300 bg-amber-50/70"
                  : "border-slate-200 bg-slate-50"
              }`}
            >
              <div className="flex items-center justify-between">
                <span className="text-[9px] uppercase font-sans text-slate-400 block">Return-Path Domain</span>
                {identity.return_path_mismatch && (
                  <span className="text-[8px] font-bold text-amber-700 bg-amber-100 px-1 rounded uppercase">Envelope Mismatch</span>
                )}
              </div>
              <span
                className={`font-bold truncate block mt-0.5 ${
                  identity.return_path_mismatch ? "text-amber-800" : "text-slate-800"
                }`}
                title={identity.return_path_domain || "Same as From"}
              >
                {identity.return_path_domain || "Same as From"}
              </span>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
