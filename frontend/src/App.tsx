import React, { useState, useEffect } from "react";
import { BackendHealth } from "./components/BackendHealth";
import { CaseUpload } from "./components/CaseUpload";
import { CaseWorkflowBar } from "./components/CaseWorkflowBar";
import { RiskCard } from "./components/RiskCard";
import { AuthenticationPanel } from "./components/AuthenticationPanel";
import { InfrastructurePanel } from "./components/InfrastructurePanel";
import { CaseGraph } from "./components/CaseGraph";
import { ForensicTimeline } from "./components/ForensicTimeline";
import { CampaignPanel } from "./components/CampaignPanel";
import { EmailPreview } from "./components/EmailPreview";
import { ForensicReportModal } from "./components/ForensicReportModal";
import {
  getCase,
  verifyCase,
  analyzeCase,
  getCaseGraph,
  getCaseTimeline,
  getCaseCorrelation,
  UploadCaseResponse,
} from "./api/client";
import {
  CaseDetail,
  GraphData,
  TimelineEvent,
  CorrelationData,
  CaseStatus,
} from "./types";
import {
  LayoutDashboard,
  Network,
  Clock,
  Share2,
  FileCheck,
  AlertTriangle,
  RefreshCw,
  FileText,
  UploadCloud,
} from "lucide-react";

export default function App() {
  const [activeTab, setActiveTab] = useState<"overview" | "graph" | "timeline" | "campaign">("overview");
  const [currentCaseId, setCurrentCaseId] = useState<string | null>(null);
  const [caseDetail, setCaseDetail] = useState<CaseDetail | null>(null);
  const [graphData, setGraphData] = useState<GraphData | null>(null);
  const [timeline, setTimeline] = useState<TimelineEvent[]>([]);
  const [correlation, setCorrelation] = useState<CorrelationData | null>(null);

  // Loading & View states
  const [isVerifying, setIsVerifying] = useState(false);
  const [isAnalyzing, setIsAnalyzing] = useState(false);
  const [isLoadingDetails, setIsLoadingDetails] = useState(false);
  const [errorBanner, setErrorBanner] = useState<string | null>(null);
  const [isReportModalOpen, setIsReportModalOpen] = useState(false);
  const [showUploadDrawer, setShowUploadDrawer] = useState(false);

  // Fetch full case details and sub-resources
  const refreshCase = async (caseId: string) => {
    setIsLoadingDetails(true);
    setErrorBanner(null);
    try {
      const detail = await getCase(caseId);
      setCaseDetail(detail);

      // Fetch graph, timeline, and correlation concurrently
      const [gRes, tRes, cRes] = await Promise.allSettled([
        getCaseGraph(caseId),
        getCaseTimeline(caseId),
        getCaseCorrelation(caseId),
      ]);

      if (gRes.status === "fulfilled") setGraphData(gRes.value);
      if (tRes.status === "fulfilled") setTimeline(tRes.value);
      if (cRes.status === "fulfilled") setCorrelation(cRes.value);
    } catch (err: unknown) {
      console.error("Failed to load case detail:", err);
      setErrorBanner("Failed to retrieve forensic case records from the backend.");
    } finally {
      setIsLoadingDetails(false);
    }
  };

  const handleUploadSuccess = async (res: UploadCaseResponse) => {
    setCurrentCaseId(res.case_id);
    setShowUploadDrawer(false);
    await refreshCase(res.case_id);
  };

  const handleVerify = async () => {
    if (!currentCaseId) return;
    setIsVerifying(true);
    setErrorBanner(null);
    try {
      await verifyCase(currentCaseId);
      await refreshCase(currentCaseId);
    } catch (err: unknown) {
      console.error("Verification error:", err);
      setErrorBanner("Authentication verification failed. Please check backend logs.");
    } finally {
      setIsVerifying(false);
    }
  };

  const handleAnalyze = async () => {
    if (!currentCaseId) return;
    setIsAnalyzing(true);
    setErrorBanner(null);
    try {
      await analyzeCase(currentCaseId);
      await refreshCase(currentCaseId);
    } catch (err: unknown) {
      console.error("Analyze error:", err);
      setErrorBanner("Threat analysis failed. Ensure the ML DistilBERT engine is responsive.");
    } finally {
      setIsAnalyzing(false);
    }
  };

  const status: CaseStatus | "INIT" = caseDetail?.status || "INIT";
  const canReport = status === "ANALYZED" || status === "REPORTED" || status === "CORRELATED";

  const primaryEvidence = caseDetail?.evidence && caseDetail.evidence.length > 0 ? caseDetail.evidence[0] : null;
  const authSummaryStr = caseDetail?.authentication
    ? `SPF: ${caseDetail.authentication.spf} | DKIM: ${caseDetail.authentication.dkim} | DMARC: ${caseDetail.authentication.dmarc}`
    : "Unverified";

  return (
    <div className="min-h-screen bg-[#f8fafc] text-slate-900 flex flex-col font-sans text-xs">
      {/* 1. APPLICATION SHELL: Clean Fixed Top Header (Requirement 1) */}
      <header className="h-14 bg-white border-b border-slate-200 sticky top-0 z-40 px-4 lg:px-6 flex items-center justify-between shadow-2xs">
        {/* Left: Project Title & Subtitle (No Project Icon) */}
        <div>
          <div className="flex items-center gap-1 leading-none">
            <span className="font-extrabold tracking-tight text-slate-900 text-base">MAILTRACE</span>
            <span className="font-extrabold text-blue-600 text-base">AI</span>
          </div>
          <div className="text-[9px] uppercase font-bold tracking-wider text-slate-500 mt-1">
            FORENSIC EMAIL THREAT PLATFORM
          </div>
        </div>

        {/* Center: Case ID & Status Badge (Requirement 1) */}
        {currentCaseId ? (
          <div className="flex items-center gap-2 px-3 py-1 bg-slate-50 rounded border border-slate-200 font-mono text-xs">
            <FileCheck className="w-3.5 h-3.5 text-blue-600" />
            <span className="font-bold text-slate-800">{currentCaseId}</span>
            <span className="text-slate-300">•</span>
            <span className="font-bold text-[10px] text-emerald-800 bg-emerald-50 px-1.5 py-0.2 rounded border border-emerald-200">
              {caseDetail?.status || "PARSED"}
            </span>
          </div>
        ) : (
          <div className="hidden sm:flex items-center gap-1.5 text-xs text-slate-400">
            <span>No case active • Ingest an .eml sample to begin</span>
          </div>
        )}

        {/* Right: Actions & Backend Health (Requirement 1) */}
        <div className="flex items-center gap-2">
          {currentCaseId && (
            <button
              onClick={() => setShowUploadDrawer(!showUploadDrawer)}
              className="flex items-center gap-1.5 px-2.5 py-1 text-slate-700 bg-slate-50 hover:bg-slate-100 border border-slate-200 rounded font-semibold text-xs transition-colors"
              title="Ingest another .eml file"
            >
              <UploadCloud className="w-3.5 h-3.5 text-blue-600" />
              <span className="hidden sm:inline">Ingest EML</span>
            </button>
          )}

          {canReport && (
            <button
              onClick={() => setIsReportModalOpen(true)}
              className="flex items-center gap-1.5 px-2.5 py-1 bg-blue-50 hover:bg-blue-100 text-blue-700 border border-blue-200 rounded font-semibold text-xs transition-colors"
            >
              <FileText className="w-3.5 h-3.5 text-blue-600" />
              <span className="hidden sm:inline">Report</span>
            </button>
          )}

          <BackendHealth />
        </div>
      </header>

      {/* Main Investigation Container */}
      <main className="flex-1 max-w-7xl w-full mx-auto p-3 lg:p-4 space-y-3">
        {/* Error Notification Banner (Requirement 21) */}
        {errorBanner && (
          <div className="p-2.5 bg-red-50 border border-red-200 rounded text-xs text-red-700 flex items-center justify-between shadow-2xs">
            <div className="flex items-center gap-2">
              <AlertTriangle className="w-4 h-4 text-red-600 shrink-0" />
              <span className="font-medium">{errorBanner}</span>
            </div>
            <button
              onClick={() => setErrorBanner(null)}
              className="text-red-500 hover:text-red-800 font-bold px-1"
            >
              ×
            </button>
          </div>
        )}

        {/* 2. MAIN INVESTIGATION WORKFLOW: Compact Step Bar (Requirement 2) */}
        <CaseWorkflowBar
          currentStatus={status}
          caseId={currentCaseId}
          onVerify={handleVerify}
          onAnalyze={handleAnalyze}
          onOpenReport={() => setIsReportModalOpen(true)}
          isVerifying={isVerifying}
          isAnalyzing={isAnalyzing}
        />

        {/* Ingestion Box (Always shown if no case loaded, or toggleable if case is loaded) */}
        {(!currentCaseId || showUploadDrawer) && (
          <div className="animate-in fade-in duration-100">
            <CaseUpload
              onUploadSuccess={handleUploadSuccess}
              activeCaseId={currentCaseId}
            />
          </div>
        )}

        {/* 9. INVESTIGATION TABS: Compact Tab Navigation (Requirement 9) */}
        {currentCaseId && (
          <div className="flex items-center gap-1 border-b border-slate-200 pb-1 overflow-x-auto">
            <button
              onClick={() => setActiveTab("overview")}
              className={`flex items-center gap-1.5 px-3 py-1.5 rounded font-semibold text-xs transition-all ${
                activeTab === "overview"
                  ? "bg-slate-900 text-white shadow-xs"
                  : "text-slate-600 hover:bg-slate-100"
              }`}
            >
              <LayoutDashboard className="w-3.5 h-3.5" />
              <span>Overview</span>
            </button>

            <button
              onClick={() => setActiveTab("graph")}
              className={`flex items-center gap-1.5 px-3 py-1.5 rounded font-semibold text-xs transition-all ${
                activeTab === "graph"
                  ? "bg-slate-900 text-white shadow-xs"
                  : "text-slate-600 hover:bg-slate-100"
              }`}
            >
              <Network className="w-3.5 h-3.5" />
              <span>Relationship Graph</span>
              {graphData && (
                <span className="text-[10px] bg-slate-200 text-slate-800 px-1 rounded font-mono">
                  {graphData.node_count}
                </span>
              )}
            </button>

            <button
              onClick={() => setActiveTab("timeline")}
              className={`flex items-center gap-1.5 px-3 py-1.5 rounded font-semibold text-xs transition-all ${
                activeTab === "timeline"
                  ? "bg-slate-900 text-white shadow-xs"
                  : "text-slate-600 hover:bg-slate-100"
              }`}
            >
              <Clock className="w-3.5 h-3.5" />
              <span>Forensic Timeline</span>
              {timeline.length > 0 && (
                <span className="text-[10px] bg-slate-200 text-slate-800 px-1 rounded font-mono">
                  {timeline.length}
                </span>
              )}
            </button>

            <button
              onClick={() => setActiveTab("campaign")}
              className={`flex items-center gap-1.5 px-3 py-1.5 rounded font-semibold text-xs transition-all ${
                activeTab === "campaign"
                  ? "bg-slate-900 text-white shadow-xs"
                  : "text-slate-600 hover:bg-slate-100"
              }`}
            >
              <Share2 className="w-3.5 h-3.5" />
              <span>Campaign Correlation</span>
              {correlation && correlation.related_case_ids.length > 0 && (
                <span className="text-[10px] bg-red-100 text-red-800 font-bold px-1 rounded font-mono">
                  {correlation.related_case_ids.length}
                </span>
              )}
            </button>

            <button
              onClick={() => currentCaseId && refreshCase(currentCaseId)}
              disabled={isLoadingDetails}
              title="Refresh Case"
              className="ml-auto p-1.5 text-slate-500 hover:text-slate-900 rounded hover:bg-slate-100 transition-colors"
            >
              <RefreshCw className={`w-3.5 h-3.5 ${isLoadingDetails ? "animate-spin" : ""}`} />
            </button>
          </div>
        )}

        {/* TAB 1: MAIN INVESTIGATION OVERVIEW (COMPACT TWO-COLUMN LAYOUT) */}
        {activeTab === "overview" && caseDetail && (
          <div className="grid grid-cols-1 lg:grid-cols-12 gap-3.5 items-start">
            {/* LEFT COLUMN: Email Information, Authentication, Infrastructure (Requirement 3, 4, 5, 8, 14) */}
            <div className="lg:col-span-7 space-y-3.5">
              {/* Email Evidence Panel with decoded body and SHA-256 fingerprint */}
              <EmailPreview
                email={caseDetail.email}
                evidence={caseDetail.evidence}
                rawHeaders={caseDetail.raw_headers}
              />

              {/* Cryptographic Authentication & Policy Alignment Panel */}
              <AuthenticationPanel
                auth={caseDetail.authentication}
                identity={caseDetail.identity}
              />

              {/* Observed Source Infrastructure Panel */}
              <InfrastructurePanel
                infrastructure={caseDetail.infrastructure}
                dns={caseDetail.dns}
                rdap={caseDetail.rdap}
                geoip={caseDetail.geoip}
              />
            </div>

            {/* RIGHT COLUMN: Risk Summary, AI Threat Detection, Why This Score, Report (Requirement 3, 6, 7, 13) */}
            <div className="lg:col-span-5 space-y-3.5">
              {caseDetail.risk_score !== undefined && caseDetail.risk_score !== null ? (
                <RiskCard
                  caseId={currentCaseId}
                  riskScore={caseDetail.risk_score}
                  riskLevel={caseDetail.classification || "LOW"}
                  contributions={
                    caseDetail.risk_contributions || {
                      ai_threat: 0,
                      identity: 0,
                      authentication: 0,
                      url_domain: 0,
                      infrastructure: 0,
                      campaign: 0,
                    }
                  }
                  reasons={caseDetail.reasons || []}
                  aiPrediction={caseDetail.detection}
                  confidence={caseDetail.confidence || undefined}
                  features={caseDetail.features}
                  authSummary={authSummaryStr}
                  sourceIp={caseDetail.infrastructure?.source_ip || undefined}
                  sha256={primaryEvidence?.sha256}
                />
              ) : (
                <div className="card p-5 bg-white border border-slate-200 rounded-lg text-center text-slate-500 text-xs">
                  <div className="font-semibold text-slate-700">No analysis available yet.</div>
                  <p className="text-slate-400 text-[11px] mt-1">
                    Verify the email before continuing.
                  </p>
                </div>
              )}
            </div>
          </div>
        )}

        {/* Empty State when no case uploaded (Requirement 22) */}
        {!currentCaseId && (
          <div className="card p-12 bg-white border border-slate-200 rounded-lg text-center text-slate-500">
            <h3 className="text-sm font-bold text-slate-800">No Forensic Case Ingested</h3>
            <p className="text-xs text-slate-400 max-w-md mx-auto mt-1 leading-relaxed">
              Upload an RFC 822 email file (.eml) above to generate cryptographic evidence preservation, evaluate authentication alignment, execute sequence AI threat detection, and assemble forensic intelligence.
            </p>
          </div>
        )}

        {/* TAB 2: RELATIONSHIP GRAPH (Requirement 10) */}
        {activeTab === "graph" && (
          <CaseGraph graphData={graphData} isLoading={isLoadingDetails} />
        )}

        {/* TAB 3: FORENSIC TIMELINE (Requirement 11) */}
        {activeTab === "timeline" && (
          <ForensicTimeline timeline={timeline} isLoading={isLoadingDetails} />
        )}

        {/* TAB 4: CAMPAIGN CORRELATION (Requirement 12) */}
        {activeTab === "campaign" && (
          <CampaignPanel correlation={correlation} isLoading={isLoadingDetails} />
        )}
      </main>

      {/* Footer */}
      <footer className="mt-auto border-t border-slate-200 bg-white py-2.5 px-4 text-center text-[11px] text-slate-400">
        MAILTRACE AI — SIH Prototype • DistilBERT Threat Sequence Detection • NetworkX/Cytoscape Knowledge Graph • 100% Explainable Evidence Fusion
      </footer>

      {/* Forensic Report Modal */}
      <ForensicReportModal
        isOpen={isReportModalOpen}
        onClose={() => setIsReportModalOpen(false)}
        caseDetail={caseDetail}
        onReportGenerated={() => currentCaseId && refreshCase(currentCaseId)}
      />
    </div>
  );
}
