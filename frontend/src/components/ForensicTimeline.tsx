import React from "react";
import { TimelineEvent } from "../types";
import { Clock, Check, Mail, Database, Bot, Share2, FileCheck } from "lucide-react";

interface ForensicTimelineProps {
  timeline?: TimelineEvent[];
  isLoading?: boolean;
}

export const ForensicTimeline: React.FC<ForensicTimelineProps> = ({ timeline, isLoading }) => {
  const getEventIcon = (event: string) => {
    switch (event) {
      case "EMAIL_RECEIVED":
        return <Mail className="w-3 h-3 text-blue-600" />;
      case "EVIDENCE_PRESERVED":
        return <FileCheck className="w-3 h-3 text-emerald-600" />;
      case "AUTHENTICATION_VERIFIED":
        return <Check className="w-3 h-3 text-amber-600" />;
      case "AI_THREAT_ANALYZED":
        return <Bot className="w-3 h-3 text-purple-600" />;
      case "INFRASTRUCTURE_ENRICHED":
        return <Database className="w-3 h-3 text-indigo-600" />;
      case "CAMPAIGN_CORRELATED":
        return <Share2 className="w-3 h-3 text-rose-600" />;
      default:
        return <Clock className="w-3 h-3 text-slate-500" />;
    }
  };

  const formatTimestamp = (ts: string) => {
    try {
      const dt = new Date(ts);
      if (isNaN(dt.getTime())) return ts;
      return dt.toLocaleString(undefined, {
        month: "short",
        day: "numeric",
        year: "numeric",
        hour: "2-digit",
        minute: "2-digit",
        second: "2-digit",
        hour12: false,
      });
    } catch {
      return ts;
    }
  };

  return (
    <div className="card bg-white border border-slate-200 rounded-lg p-4 shadow-xs text-xs">
      <div className="flex items-center justify-between pb-3 mb-3 border-b border-slate-100">
        <div>
          <h2 className="text-sm font-bold text-slate-900 tracking-tight">Forensic Timeline</h2>
          <p className="text-[11px] text-slate-500 mt-0.5">Chronological audit trail of investigation milestones</p>
        </div>
        <span className="text-[10px] text-slate-500 font-mono bg-slate-50 px-2 py-0.5 rounded border border-slate-200">
          {timeline ? `${timeline.length} Milestones` : "0 Milestones"}
        </span>
      </div>

      {isLoading ? (
        <div className="p-8 text-center text-xs text-slate-400 font-mono animate-pulse">
          Loading chronological audit events...
        </div>
      ) : !timeline || timeline.length === 0 ? (
        <div className="p-6 text-center text-xs text-slate-400">
          No chronological timeline events recorded yet.
        </div>
      ) : (
        <div className="relative pl-5 space-y-3.5 before:absolute before:left-2 before:top-2 before:bottom-2 before:w-px before:bg-slate-200">
          {timeline.map((item, idx) => (
            <div key={idx} className="relative group">
              {/* Dot Icon */}
              <div className="absolute -left-5 top-1 w-4 h-4 rounded-full bg-white border border-slate-300 group-hover:border-blue-500 flex items-center justify-center transition-colors shadow-2xs">
                {getEventIcon(item.event)}
              </div>

              {/* Event Box */}
              <div className="p-2.5 rounded border border-slate-200 bg-slate-50/50 hover:bg-slate-50 transition-colors">
                <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-1">
                  <div className="flex items-center gap-1.5">
                    <span className="text-[11px] font-bold text-slate-900">
                      {item.event.replace(/_/g, " ")}
                    </span>
                    <span className="text-[9px] font-mono text-slate-500 bg-slate-200/80 px-1 py-0.2 rounded">
                      {item.source}
                    </span>
                  </div>
                  <span className="text-[10px] font-mono text-slate-500">
                    {formatTimestamp(item.timestamp)}
                  </span>
                </div>
                {item.details && (
                  <p className="text-[11px] text-slate-600 mt-1 leading-normal font-sans">
                    {item.details}
                  </p>
                )}
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  );
};
