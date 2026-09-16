/**
 * MAILTRACE AI - Typed Axios API Client.
 * Communicates with the FastAPI backend at http://127.0.0.1:8000.
 */

import axios from "axios";
import {
  AuthenticationData,
  CaseAnalysisResponse,
  CaseDetail,
  CorrelationData,
  EvidenceItem,
  GraphData,
  HealthResponse,
  IdentityData,
  TimelineEvent,
  CaseStatus,
} from "../types";

export const API_BASE_URL = "http://127.0.0.1:8000";

const api = axios.create({
  baseURL: API_BASE_URL,
  timeout: 45000,
  headers: {
    "Accept": "application/json",
  },
});

export interface UploadCaseResponse {
  case_id: string;
  status: CaseStatus;
  message: string;
  evidence?: EvidenceItem;
}

export interface VerifyCaseResponse {
  case_id: string;
  status: CaseStatus;
  authentication: AuthenticationData;
  identity: IdentityData;
}

/** Check backend health status */
export async function getHealth(): Promise<HealthResponse> {
  const res = await api.get<HealthResponse>("/api/health");
  return res.data;
}

/** Upload raw .eml file and secure evidence */
export async function uploadCase(file: File): Promise<UploadCaseResponse> {
  const formData = new FormData();
  formData.append("file", file);
  const res = await api.post<UploadCaseResponse>("/api/cases/upload", formData, {
    headers: {
      "Content-Type": "multipart/form-data",
    },
  });
  return res.data;
}

/** Run SPF, DKIM, and DMARC verification */
export async function verifyCase(caseId: string): Promise<VerifyCaseResponse> {
  const res = await api.post<VerifyCaseResponse>(`/api/cases/${caseId}/verify`);
  return res.data;
}

/** Execute AI threat classification, feature extraction, and risk fusion */
export async function analyzeCase(caseId: string): Promise<CaseAnalysisResponse> {
  const res = await api.post<CaseAnalysisResponse>(`/api/cases/${caseId}/analyze`);
  return res.data;
}

/** Retrieve full case detail with analysis json and evidences */
export async function getCase(caseId: string): Promise<CaseDetail> {
  const res = await api.get<CaseDetail>(`/api/cases/${caseId}`);
  return res.data;
}

/** Retrieve authentication schema for a case */
export async function getCaseAuthentication(caseId: string): Promise<AuthenticationData> {
  const res = await api.get<AuthenticationData>(`/api/cases/${caseId}/authentication`);
  return res.data;
}

/** Retrieve Cytoscape.js relationship graph */
export async function getCaseGraph(caseId: string): Promise<GraphData> {
  const res = await api.get<GraphData>(`/api/cases/${caseId}/graph`);
  return res.data;
}

/** Retrieve chronological forensic timeline */
export async function getCaseTimeline(caseId: string): Promise<TimelineEvent[]> {
  const res = await api.get<TimelineEvent[]>(`/api/cases/${caseId}/timeline`);
  return res.data;
}

/** Retrieve cross-case campaign correlation */
export async function getCaseCorrelation(caseId: string): Promise<CorrelationData> {
  const res = await api.get<CorrelationData>(`/api/cases/${caseId}/correlation`);
  return res.data;
}

/** Retrieve structured forensic report data object */
export async function getCaseReport(caseId: string): Promise<Record<string, unknown>> {
  const res = await api.get<Record<string, unknown>>(`/api/cases/${caseId}/report`);
  return res.data;
}

/** Download forensic report in PDF or JSON format via Blob */
export async function downloadCaseReport(caseId: string, format: "pdf" | "json"): Promise<void> {
  const response = await api.get(`/api/cases/${caseId}/report/${format}`, {
    responseType: "blob",
  });

  const mimeType = format === "pdf" ? "application/pdf" : "application/json";
  const blob = new Blob([response.data], { type: mimeType });
  const downloadUrl = window.URL.createObjectURL(blob);
  const link = document.createElement("a");
  link.href = downloadUrl;
  link.setAttribute("download", `forensic_report_${caseId}.${format}`);
  document.body.appendChild(link);
  link.click();
  link.remove();
  window.URL.revokeObjectURL(downloadUrl);
}

export default api;
