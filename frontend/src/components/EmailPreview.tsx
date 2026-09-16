import React, { useState } from "react";
import { EmailData, EvidenceItem } from "../types";
import { Mail, Copy, Check, FileCode, Lock, X } from "lucide-react";

interface EmailPreviewProps {
  email?: EmailData | null;
  evidence?: EvidenceItem[];
  rawHeaders?: Record<string, string | string[]>;
}

export const EmailPreview: React.FC<EmailPreviewProps> = ({ email, evidence, rawHeaders }) => {
  const [showRawHeaders, setShowRawHeaders] = useState(false);
  const [copiedHash, setCopiedHash] = useState(false);

  const primaryEvidence = evidence && evidence.length > 0 ? evidence[0] : null;
  const sha256 = primaryEvidence?.sha256 || "UNKNOWN";
  const filename = primaryEvidence?.filename || "raw.eml";

  const handleCopyHash = () => {
    if (!sha256 || sha256 === "UNKNOWN") return;
    navigator.clipboard.writeText(sha256);
    setCopiedHash(true);
    setTimeout(() => setCopiedHash(false), 2000);
  };

  if (!email) {
    return (
      <div className="card p-6 text-center text-slate-400 text-xs">
        <Mail className="w-8 h-8 text-slate-300 mx-auto mb-2 stroke-[1.5]" />
        <div>No email evidence ingested yet. Upload an RFC 822 .eml file to inspect.</div>
      </div>
    );
  }

  return (
    <div className="card bg-white border border-slate-200 rounded-lg overflow-hidden shadow-xs">
      {/* Evidence Fingerprint Strip (Requirement 14) */}
      <div className="bg-slate-50 border-b border-slate-200 px-3.5 py-2 flex flex-wrap items-center justify-between gap-2 text-xs">
        <div className="flex items-center gap-2">
          <span className="flex items-center gap-1 text-[11px] font-bold text-slate-700 uppercase tracking-wider">
            <Lock className="w-3 h-3 text-emerald-600" />
            <span>Evidence Preserved</span>
          </span>
          <span className="text-[11px] text-slate-400">•</span>
          <span className="text-[11px] font-mono text-slate-600 truncate max-w-[180px] sm:max-w-xs" title={filename}>
            {filename}
          </span>
        </div>

        <div className="flex items-center gap-2">
          <span className="text-[10px] font-bold uppercase tracking-wider text-slate-400 font-mono">SHA-256</span>
          <span
            className="font-mono text-[11px] text-slate-800 font-medium bg-white px-1.5 py-0.5 rounded border border-slate-200 truncate max-w-[140px] sm:max-w-[200px]"
            title={sha256}
          >
            {sha256.length > 20 ? `${sha256.substring(0, 8)}...${sha256.substring(sha256.length - 8)}` : sha256}
          </span>
          <button
            onClick={handleCopyHash}
            className="text-[10px] font-medium text-slate-600 hover:text-slate-900 px-1.5 py-0.5 rounded hover:bg-slate-200/70 transition-colors flex items-center gap-1 border border-slate-200 bg-white"
            title="Copy SHA-256 fingerprint"
          >
            {copiedHash ? (
              <>
                <Check className="w-3 h-3 text-emerald-600" />
                <span className="text-emerald-700 font-bold">Copied</span>
              </>
            ) : (
              <>
                <Copy className="w-3 h-3 text-slate-500" />
                <span>Copy</span>
              </>
            )}
          </button>
        </div>
      </div>

      {/* Structured Email Envelope Details (Requirement 4) */}
      <div className="p-3.5 border-b border-slate-100 text-xs">
        <div className="grid grid-cols-1 sm:grid-cols-2 gap-x-4 gap-y-2">
          {/* Subject */}
          <div className="sm:col-span-2">
            <span className="text-[10px] font-bold uppercase tracking-wider text-slate-400 block">Subject</span>
            <div className="font-semibold text-slate-900 text-sm mt-0.5 leading-snug">
              {email.subject || "(No Subject)"}
            </div>
          </div>

          {/* From */}
          <div>
            <span className="text-[10px] font-bold uppercase tracking-wider text-slate-400 block">From</span>
            <div className="font-mono text-slate-800 truncate mt-0.5" title={email.from_address || "None"}>
              {email.from_address || "None"}
            </div>
          </div>

          {/* To */}
          <div>
            <span className="text-[10px] font-bold uppercase tracking-wider text-slate-400 block">To</span>
            <div className="font-mono text-slate-800 truncate mt-0.5" title={email.to_address || "None"}>
              {email.to_address || "None"}
            </div>
          </div>

          {/* Reply-To */}
          <div>
            <span className="text-[10px] font-bold uppercase tracking-wider text-slate-400 block">Reply-To</span>
            <div
              className={`font-mono truncate mt-0.5 ${
                email.reply_to && email.from_address && !email.from_address.includes(email.reply_to)
                  ? "text-red-700 font-semibold"
                  : "text-slate-800"
              }`}
              title={email.reply_to || "Same as From"}
            >
              {email.reply_to || "Same as From"}
            </div>
          </div>

          {/* Return-Path */}
          <div>
            <span className="text-[10px] font-bold uppercase tracking-wider text-slate-400 block">Return-Path</span>
            <div className="font-mono text-slate-800 truncate mt-0.5" title={email.return_path || "None"}>
              {email.return_path || "None"}
            </div>
          </div>

          {/* Date */}
          <div>
            <span className="text-[10px] font-bold uppercase tracking-wider text-slate-400 block">Date</span>
            <div className="font-mono text-slate-700 truncate mt-0.5">{email.date || "None"}</div>
          </div>

          {/* Message-ID */}
          <div>
            <span className="text-[10px] font-bold uppercase tracking-wider text-slate-400 block">Message-ID</span>
            <div className="font-mono text-slate-600 text-[11px] truncate mt-0.5" title={email.message_id || "None"}>
              {email.message_id || "None"}
            </div>
          </div>
        </div>
      </div>

      {/* Decoded Email Body Header & Action */}
      <div className="px-3.5 pt-3 pb-1.5 flex items-center justify-between">
        <span className="text-[10px] font-bold uppercase tracking-wider text-slate-500">
          Decoded Email Body
        </span>
        {rawHeaders && (
          <button
            onClick={() => setShowRawHeaders(true)}
            className="text-[11px] text-blue-600 hover:text-blue-800 font-semibold flex items-center gap-1 hover:underline"
          >
            <FileCode className="w-3.5 h-3.5" />
            <span>View Raw Headers</span>
          </button>
        )}
      </div>

      {/* Scrollable Forensic Email Body Viewer */}
      <div className="p-3.5 pt-0">
        <div className="rounded border border-slate-200 bg-slate-50/60 max-h-56 overflow-y-auto p-3 text-xs leading-relaxed text-slate-800 select-text">
          {email.body_html ? (
            <div
              className="prose prose-xs max-w-none text-slate-800 font-sans"
              dangerouslySetInnerHTML={{ __html: email.body_html }}
            />
          ) : (
            <pre className="font-mono text-[11px] whitespace-pre-wrap text-slate-800 font-medium">
              {email.body_text || "(Empty body content)"}
            </pre>
          )}
        </div>
      </div>

      {/* Raw Headers Modal/Drawer (Requirement 4) */}
      {showRawHeaders && rawHeaders && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-slate-900/60 backdrop-blur-2xs p-4">
          <div className="bg-white rounded-lg shadow-xl border border-slate-300 max-w-3xl w-full overflow-hidden animate-in fade-in zoom-in-95 duration-100 max-h-[85vh] flex flex-col">
            <div className="bg-slate-900 text-white px-4 py-3 flex items-center justify-between">
              <div className="flex items-center gap-2">
                <FileCode className="w-4 h-4 text-sky-400" />
                <h3 className="text-xs font-bold tracking-wide uppercase font-mono">RFC 5322 Raw Message Headers</h3>
              </div>
              <button
                onClick={() => setShowRawHeaders(false)}
                className="text-slate-400 hover:text-white p-1 rounded"
              >
                <X className="w-4 h-4" />
              </button>
            </div>

            <div className="p-4 overflow-y-auto flex-1 bg-slate-950 text-slate-200 font-mono text-[11px] leading-5">
              {Object.entries(rawHeaders).map(([hdr, val]) => (
                <div key={hdr} className="py-0.5 border-b border-slate-900/60 hover:bg-slate-900/40">
                  <span className="text-sky-300 font-bold">{hdr}:</span>{" "}
                  <span className="text-slate-300 select-all">
                    {Array.isArray(val) ? val.join(" | ") : String(val)}
                  </span>
                </div>
              ))}
            </div>

            <div className="bg-slate-100 border-t border-slate-200 px-4 py-2 flex items-center justify-between text-xs">
              <span className="text-slate-500 font-mono text-[11px]">
                {Object.keys(rawHeaders).length} Headers Extracted
              </span>
              <button
                onClick={() => setShowRawHeaders(false)}
                className="px-3 py-1 bg-slate-800 hover:bg-slate-900 text-white text-xs font-semibold rounded"
              >
                Close
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
