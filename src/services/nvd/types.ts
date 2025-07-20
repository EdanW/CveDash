// NVD API Response Types
export interface NvdCveResponse {
  resultsPerPage: number;
  startIndex: number;
  totalResults: number;
  format: string;
  version: string;
  timestamp: string;
  vulnerabilities: NvdVulnerability[];
}

export interface NvdVulnerability {
  cve: NvdCve;
}

export interface NvdCve {
  id: string;
  sourceIdentifier?: string;
  published: string;
  lastModified: string;
  vulnStatus: string;
  descriptions: NvdDescription[];
  metrics?: NvdMetrics;
  weaknesses?: NvdWeakness[];
  configurations?: NvdConfiguration[];
  references?: NvdReference[];
  evaluatorComment?: string;
  evaluatorSolution?: string;
  evaluatorImpact?: string;
  cisaExploitAdd?: string;
  cisaActionDue?: string;
  cisaRequiredAction?: string;
  cisaVulnerabilityName?: string;
}

export interface NvdDescription {
  lang: string;
  value: string;
}

export interface NvdMetrics {
  cvssMetricV31?: NvdCvssMetric[];
  cvssMetricV30?: NvdCvssMetric[];
  cvssMetricV2?: NvdCvssMetric[];
}

export interface NvdCvssMetric {
  source: string;
  type: string;
  cvssData: NvdCvssData;
  exploitabilityScore?: number;
  impactScore?: number;
  acInsufInfo?: boolean;
  obtainAllPrivilege?: boolean;
  obtainUserPrivilege?: boolean;
  obtainOtherPrivilege?: boolean;
  userInteractionRequired?: boolean;
}

export interface NvdCvssData {
  version: string;
  vectorString: string;
  // CVSS v2 fields
  accessVector?: string;
  accessComplexity?: string;
  authentication?: string;
  // CVSS v3/v4 fields
  attackVector?: string;
  attackComplexity?: string;
  privilegesRequired?: string;
  userInteraction?: string;
  scope?: string;
  // Common fields
  confidentialityImpact?: string;
  integrityImpact?: string;
  availabilityImpact?: string;
  baseScore?: number;
  baseSeverity?: string;
  environmentalScore?: number;
  environmentalSeverity?: string;
  temporalScore?: number;
  temporalSeverity?: string;
}

export interface NvdWeakness {
  source: string;
  type: string;
  description: NvdDescription[];
}

export interface NvdConfiguration {
  nodes: NvdNode[];
}

export interface NvdNode {
  operator: string;
  negate?: boolean;
  cpeMatch?: NvdCpeMatch[];
}

export interface NvdCpeMatch {
  vulnerable: boolean;
  criteria: string;
  versionStartIncluding?: string;
  versionStartExcluding?: string;
  versionEndIncluding?: string;
  versionEndExcluding?: string;
  matchCriteriaId: string;
}

export interface NvdReference {
  url: string;
  source?: string;
  tags?: string[];
}

// NVD API Parameters
export interface NvdCveParams {
  cveId?: string;
  cpeName?: string;
  cvssV2Metrics?: string;
  cvssV2Severity?: 'LOW' | 'MEDIUM' | 'HIGH';
  cvssV3Metrics?: string;
  cvssV3Severity?: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
  cvssV4Metrics?: string;
  cvssV4Severity?: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
  cweId?: string;
  hasCertAlerts?: boolean;
  hasCertNotes?: boolean;
  hasKev?: boolean;
  hasOval?: boolean;
  isVulnerable?: boolean;
  keywordExactMatch?: boolean;
  keywordSearch?: string;
  lastModStartDate?: string;
  lastModEndDate?: string;
  pubStartDate?: string;
  pubEndDate?: string;
  resultsPerPage?: number;
  startIndex?: number;
  sourceIdentifier?: string;
  versionEnd?: string;
  versionEndType?: 'including' | 'excluding';
  versionStart?: string;
  versionStartType?: 'including' | 'excluding';
  virtualMatchString?: string;
} 