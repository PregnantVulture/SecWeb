// Shared types used across the scanner, API routes, and UI

export interface CvssVector {
  attackVector: 'N' | 'A' | 'L' | 'P';          // Network/Adjacent/Local/Physical
  attackComplexity: 'L' | 'H';
  privilegesRequired: 'N' | 'L' | 'H';
  userInteraction: 'N' | 'R';
  scope: 'U' | 'C';
  confidentiality: 'N' | 'L' | 'H';
  integrity: 'N' | 'L' | 'H';
  availability: 'N' | 'L' | 'H';
  baseScore: number;
  vectorString: string;
}

export interface PocEvidence {
  payload: string;         // The actual exploit string / HTTP snippet
  requestSummary?: string; // e.g. "POST /api/login HTTP/1.1 ..."
  responseSummary?: string;
  validated: boolean;      // Did the AI confirm this worked?
}

export interface Finding {
  id: string;
  alertId: string;
  name: string;
  risk: 'Critical' | 'High' | 'Medium' | 'Low' | 'Informational';
  confidence: 'High' | 'Medium' | 'Low';
  url: string;
  param?: string;
  cweId?: string;
  owasp?: string;          // e.g. "A03:2021 – Injection"
  description?: string;
  poc?: PocEvidence;       // Proof-of-concept evidence (new — from Strix approach)
  evidence?: string;       // Legacy plain-text evidence
  solution?: string;
  remediationLink?: {
    title: string;
    url: string;
  };
  cvss?: CvssVector;       // Full CVSS v3 scoring (new — from Strix approach)
  tool: 'SecWeb AI Engine';
  fingerprint: string;
}

export interface AttackSurfaceEntry {
  type: 'endpoint' | 'parameter' | 'auth-surface' | 'data-asset' | 'trust-boundary';
  label: string;
  url?: string;
  description: string;
  riskNote?: string;
}

export interface ThreatModel {
  entryPoints: AttackSurfaceEntry[];
  highValueAssets: AttackSurfaceEntry[];
  trustBoundaries: AttackSurfaceEntry[];
  summary: string;
}

export interface DiscoveredPage {
  url: string;
  title: string;
  description: string;
  language: string;
  latencyMs: number;
  format: string;
  pageType: 'Public Page' | 'Login / Auth' | 'Admin Portal' | 'API Endpoint' | 'Static Asset';
  observedFacts: string[];
  inferredClassifications: string[];
}

export interface RemediationRecommendation {
  id: string;
  findingId: string;
  findingName: string;
  issueSummary: string;
  beginnerExplanation: string;
  practicalNextSteps: string[];
  remediationLink?: {
    title: string;
    url: string;
  };
  isTargetSpecific: boolean;
  priority: 'Critical' | 'High' | 'Medium' | 'Low' | 'Informational';
}

export interface ScanRecord {
  id: string;
  clientId: string;
  targetUrl: string;
  normalizedHost: string;
  startTime: string;
  endTime?: string;
  status: 'running' | 'completed' | 'partial' | 'failed' | 'timed_out';
  scanType: 'live-ai-scan' | 'demo-illustrative-scan';
  isIllustrativeDemo: boolean;
  totalFindings: number;
  severityCounts: {
    Critical: number;
    High: number;
    Medium: number;
    Low: number;
    Informational: number;
  };
  findings: Finding[];
  threatModel?: ThreatModel;           // Attack surface map (new)
  tinyfishIntelligence: {
    discoveredPages: DiscoveredPage[];
    summary: string;
  };
  remediationRecommendations: RemediationRecommendation[];
  coverageAndStatus: {
    toolAttribution: string[];
    latencyMs: number;
    completionStatus: string;
  };
  error?: string;
}

export interface ComparisonResult {
  olderScanId: string;
  newerScanId: string;
  targetHost: string;
  summary: {
    newCount: number;
    persistentCount: number;
    resolvedCount: number;
  };
  newFindings: Finding[];
  persistentFindings: { older: Finding; newer: Finding; severityChanged: boolean }[];
  resolvedFindings: Finding[];
}

// Stream event types (SSE)
export type ScanStreamEvent =
  | { type: 'status'; message: string }
  | { type: 'page_discovered'; page: DiscoveredPage }
  | { type: 'attack_surface'; threatModel: ThreatModel }
  | { type: 'finding'; finding: Finding }
  | { type: 'complete'; scan: ScanRecord }
  | { type: 'error'; message: string };
