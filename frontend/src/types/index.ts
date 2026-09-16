/**
 * MAILTRACE AI - Shared Frontend TypeScript Data Contracts.
 * Matches FastAPI Pydantic schemas accurately without using `any`.
 */

export type CaseStatus = "UPLOADED" | "PARSED" | "VERIFIED" | "ANALYZED" | "CORRELATED" | "REPORTED" | "CLOSED";

export type RiskLevel = "LOW" | "MEDIUM" | "HIGH" | "CRITICAL";

export type AuthStatus = "PASS" | "FAIL" | "NONE" | "NEUTRAL" | "SOFTFAIL" | "PERMERROR" | "TEMPERROR" | "UNKNOWN" | "UNAVAILABLE";

export type AlignmentStatus = "PASS" | "FAIL" | "NONE" | "UNKNOWN";

export interface EmailData {
  from_address?: string | null;
  to_address?: string | null;
  subject?: string | null;
  date?: string | null;
  reply_to?: string | null;
  return_path?: string | null;
  body_text?: string | null;
  body_html?: string | null;
  message_id?: string | null;
}

export interface AuthDetails {
  status: AuthStatus;
  domain?: string | null;
  selector?: string | null;
  details?: string | null;
  reason?: string | null;
}

export interface AuthenticationData {
  spf: AuthStatus;
  dkim: AuthStatus;
  dmarc: AuthStatus;
  alignment: AlignmentStatus;
  spf_details?: AuthDetails | null;
  dkim_details?: AuthDetails | null;
  dmarc_details?: AuthDetails | null;
  declared?: {
    spf?: string | null;
    dkim?: string | null;
    dmarc?: string | null;
  };
  verified?: {
    spf?: string | null;
    dkim?: string | null;
    dmarc?: string | null;
  };
}

export interface IdentityData {
  from_domain?: string | null;
  reply_to_domain?: string | null;
  return_path_domain?: string | null;
  reply_to_mismatch: boolean;
  return_path_mismatch: boolean;
}

export interface AIResult {
  label: "BENIGN" | "MALICIOUS";
  confidence: number;
  threat_score?: number | null;
  model: string;
  version?: string;
  status?: string;
}

export interface ForensicFeatures {
  urgency_detected: boolean;
  financial_detected: boolean;
  authority_detected: boolean;
  secrecy_detected: boolean;
  reply_to_mismatch: boolean;
  return_path_mismatch: boolean;
  suspicious_links_detected: boolean;
  credentials_detected: boolean;
  url_count: number;
  domain_count: number;
  ip_count: number;
}

export interface GeoIPRecord {
  country?: string | null;
  region?: string | null;
  city?: string | null;
  latitude?: number | null;
  longitude?: number | null;
  status: "AVAILABLE" | "UNAVAILABLE" | "NOT_FOUND";
}

export interface RDAPRecord {
  organization?: string | null;
  network_name?: string | null;
  country?: string | null;
  status: "AVAILABLE" | "UNAVAILABLE" | "NOT_FOUND";
}

export interface DNSRecord {
  records: Record<string, string[]>;
  status: "AVAILABLE" | "UNAVAILABLE" | "NOT_FOUND";
}

export interface InfrastructureData {
  source_ip?: string | null;
  reverse_dns?: string | null;
  asn?: string | null;
  organization?: string | null;
  country?: string | null;
  dns_status: "available" | "unavailable" | "not_found";
  rdap_status: "available" | "unavailable" | "not_found";
  geoip_status: "available" | "unavailable" | "not_found";
}

export interface RiskContributions {
  ai_threat: number;        // 0-25
  identity: number;         // 0-20
  authentication: number;   // 0-15
  url_domain: number;       // 0-15
  infrastructure: number;   // 0-15
  campaign: number;         // 0-10
}

export interface RiskReason {
  rule: string;
  points: string;
  description: string;
}

export interface GraphNodeData {
  id: string;
  type: string;
  label: string;
  value?: string | null;
  metadata?: Record<string, unknown>;
}

export interface GraphNode {
  data: GraphNodeData;
}

export interface GraphEdgeData {
  id: string;
  source: string;
  target: string;
  relationship?: string | null;
  evidence?: string | null;
}

export interface GraphEdge {
  data: GraphEdgeData;
}

export interface GraphData {
  nodes: GraphNode[];
  edges: GraphEdge[];
  node_count: number;
  edge_count: number;
}

export interface SharedIndicator {
  type: string;
  value: string;
  related_case?: string;
}

export interface CorrelationData {
  related_case_ids: string[];
  shared_indicators: SharedIndicator[];
  relationship_strength: "NONE" | "LOW" | "MEDIUM" | "HIGH";
  correlation_reasons: string[];
  campaign_score: number;
}

export interface TimelineEvent {
  timestamp: string;
  event: string;
  source: string;
  details?: string | null;
}

export interface EvidenceItem {
  id: number;
  evidence_type: string;
  filename: string;
  path: string;
  sha256: string;
  size_bytes?: number;
  created_at?: string;
}

export interface IndicatorItem {
  type: string;
  value: string;
  source?: string;
  risk?: string | null;
}

export interface CaseSummary {
  case_id: string;
  filename: string;
  status: CaseStatus;
  created_at?: string;
}

export interface CaseAnalysisResponse {
  case_id: string;
  status: CaseStatus;
  ai_prediction: AIResult;
  ai_confidence: number;
  extracted_features: ForensicFeatures;
  risk_score: number;
  risk_level: RiskLevel;
  risk_contributions: RiskContributions;
  infrastructure: InfrastructureData;
  dns: Record<string, DNSRecord>;
  rdap: Record<string, RDAPRecord>;
  geoip: Record<string, GeoIPRecord>;
  infrastructure_score: number;
  graph: GraphData;
  correlation: CorrelationData;
  timeline: TimelineEvent[];
  campaign_score: number;
  explanations: string[];
}

export interface CaseDetail {
  case_id: string;
  case_number: string;
  filename: string;
  status: CaseStatus;
  risk_score?: number | null;
  classification?: RiskLevel | null;
  confidence?: number | null;
  created_at: string;
  updated_at: string;
  email?: EmailData;
  authentication?: AuthenticationData;
  identity?: IdentityData;
  detection?: AIResult;
  features?: ForensicFeatures;
  infrastructure?: InfrastructureData;
  dns?: Record<string, DNSRecord>;
  rdap?: Record<string, RDAPRecord>;
  geoip?: Record<string, GeoIPRecord>;
  infrastructure_score?: number;
  campaign_score?: number;
  graph?: GraphData;
  correlation?: CorrelationData;
  timeline?: TimelineEvent[];
  risk_contributions?: RiskContributions;
  reasons?: RiskReason[];
  explanations?: string[];
  evidence?: EvidenceItem[];
  indicators?: IndicatorItem[];
  raw_headers?: Record<string, string | string[]>;
}

export interface HealthResponse {
  status: string;
  project: string;
  version: string;
}
