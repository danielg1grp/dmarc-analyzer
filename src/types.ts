// DMARC Report XML structure (as parsed from xml2js)
export interface DmarcReportXml {
  feedback: {
    version?: string[];
    report_metadata: [{
      org_name: string[];
      email: string[];
      report_id: string[];
      date_range: [{
        begin: string[];
        end: string[];
      }];
    }];
    policy_published: [{
      domain: string[];
      adkim: string[];
      aspf: string[];
      p: string[];
      sp: string[];
      pct: string[];
      fo?: string[];
    }];
    record: DmarcRecordXml[];
  };
}

export interface DmarcRecordXml {
  row: [{
    source_ip: string[];
    count: string[];
    policy_evaluated: [{
      disposition: string[];
      dkim: string[];
      spf: string[];
    }];
  }];
  identifiers: [{
    envelope_to?: string[];
    envelope_from?: string[];
    header_from: string[];
  }];
  auth_results: [{
    dkim?: DkimResultXml[];
    spf: SpfResultXml[];
  }];
}

export interface DkimResultXml {
  domain: string[];
  selector?: string[];
  result: string[];
}

export interface SpfResultXml {
  domain: string[];
  scope?: string[];
  result: string[];
}

// Normalized/processed data structures
export interface PolicyPublished {
  domain: string;
  adkim: string;  // r = relaxed, s = strict
  aspf: string;   // r = relaxed, s = strict
  p: string;      // none, quarantine, reject
  sp: string;     // subdomain policy
  pct: number;    // percentage
}

export interface DkimResult {
  domain: string;
  selector?: string;
  result: string;  // pass, fail, none, etc.
}

export interface SpfResult {
  domain: string;
  scope?: string;
  result: string;  // pass, fail, softfail, neutral, none, temperror, permerror
}

export interface PolicyEvaluated {
  disposition: string;  // none, quarantine, reject
  dkim: string;         // pass, fail
  spf: string;          // pass, fail
}

export interface Identifiers {
  headerFrom: string;
  envelopeFrom?: string;
  envelopeTo?: string;
}

export interface ProcessedRecord {
  reportId: string;
  dateRange: {
    begin: number;
    end: number;
  };
  sourceIp: string;
  count: number;
  policyEvaluated: PolicyEvaluated;
  identifiers: Identifiers;
  authResults: {
    dkim: DkimResult[];
    spf: SpfResult;
  };
}

export interface ReportMetadata {
  orgName: string;
  email: string;
  reportId: string;
  dateRange: {
    begin: number;
    end: number;
  };
}

export interface ParsedReport {
  filename: string;
  metadata: ReportMetadata;
  policy: PolicyPublished;
  records: ProcessedRecord[];
}

export interface ReportSummary {
  reportId: string;
  filename: string;
  reporter: string;
  dateRange: {
    begin: number;
    end: number;
  };
  totalMessages: number;
  passCount: number;
  failCount: number;
  issues: string[];
}

export interface DomainData {
  policy: PolicyPublished;
  records: ProcessedRecord[];
  reports: ReportSummary[];
}

export interface StoredData {
  processedFiles: string[];
  lastUpdated: string;
  domains: {
    [domain: string]: DomainData;
  };
}

// Issue types
export type IssueCode =
  | 'DKIM_ALIGNMENT_FAIL'
  | 'SPF_SOFTFAIL'
  | 'SPF_FAIL'
  | 'SPF_PERMERROR'
  | 'SPF_TEMPERROR'
  | 'DKIM_FAIL'
  | 'POLICY_NONE'
  | 'THIRD_PARTY_SENDER';

export interface Issue {
  code: IssueCode;
  title: string;
  explanation: string;
  remediation: string;
  affectedRecords: number;
  sampleSourceIps: string[];
}

export interface DomainAnalysis {
  domain: string;
  policy: PolicyPublished;
  totalMessages: number;
  passCount: number;
  failCount: number;
  passRate: number;
  issues: Issue[];
  trends: TrendPoint[];
  records: ProcessedRecord[];
}

export interface TrendPoint {
  dateRange: {
    begin: number;
    end: number;
  };
  totalMessages: number;
  passCount: number;
  failCount: number;
  passRate: number;
}

// API response types
export interface ApiResponse<T> {
  success: boolean;
  data?: T;
  error?: string;
}

export interface RefreshResult {
  newFilesProcessed: string[];
  skippedFiles: string[];
  totalDomains: number;
  domains: string[];
}

// DNS data structures for storage
export interface StoredSpfRecord {
  raw: string;
  version: string;
  mechanisms: string[];
  includes: string[];
  ipv4: string[];
  ipv6: string[];
  all: string;
  lookupCount: number;
  hasError: boolean;
  errorMessage?: string;
}

export interface StoredDmarcRecord {
  raw: string;
  version: string;
  policy: string;
  subdomainPolicy?: string;
  percentage?: number;
  rua?: string[];
  ruf?: string[];
  adkim?: string;
  aspf?: string;
  fo?: string;
}

export interface StoredDkimRecord {
  selector: string;
  raw: string;
  version?: string;
  keyType?: string;
  publicKey?: string;
  flags?: string;
  found: boolean;
  error?: string;
}

export interface StoredDnsData {
  spf: StoredSpfRecord | null;
  dmarc: StoredDmarcRecord | null;
  dkim: StoredDkimRecord[];
  fetchedAt: string;
  errors: string[];
}

// Service identification from IP analysis
export interface IdentifiedServiceInfo {
  name: string;
  spfInclude: string;
  confidence: 'high' | 'medium' | 'low';
  sourceIps: string[];
  messageCount: number;
}

// Analysis of source IPs for a domain
export interface SourceIpAnalysis {
  analyzedAt: string;
  identifiedServices: IdentifiedServiceInfo[];
  unidentifiedIps: Array<{
    ip: string;
    messageCount: number;
  }>;
}

// Enriched issue with DNS context
export interface RelevantDnsRecord {
  type: 'SPF' | 'DMARC' | 'DKIM';
  raw: string;
  explanation: string;
}

export interface ProposedChange {
  type: 'SPF' | 'DMARC' | 'DKIM';
  recordName: string;  // e.g., "@" for SPF, "_dmarc" for DMARC
  current: string | null;
  proposed: string;
  explanation: string;
  priority: 'high' | 'medium' | 'low';
}

export interface EnrichedIssue extends Issue {
  relevantDns: RelevantDnsRecord[];
  proposedChanges: ProposedChange[];
  context: string;  // Issue-specific contextual explanation based on actual DNS state
}

// Extended domain data with DNS
export interface DomainDataWithDns extends DomainData {
  dns?: StoredDnsData;
  sourceIpAnalysis?: SourceIpAnalysis;
}

// Extended stored data
export interface StoredDataWithDns {
  processedFiles: string[];
  lastUpdated: string;
  domains: {
    [domain: string]: DomainDataWithDns;
  };
}

// Record-centric analysis (grouped by SPF/DKIM/DMARC)
export interface IssueReference {
  code: IssueCode;
  title: string;
  explanation: string;
  affectedRecords: number;
  sampleSourceIps: string[];
  // Whether current DNS appears to resolve this issue
  resolvedByDns: boolean;
  // Explanation of why it appears resolved or still present
  resolutionStatus: string;
}

export interface SpfAnalysis {
  current: StoredSpfRecord | null;
  issues: IssueReference[];
  identifiedSenders: Array<{
    name: string;
    spfInclude: string;
    messageCount: number;
    inCurrentSpf: boolean;
  }>;
  unidentifiedIps: Array<{
    ip: string;
    messageCount: number;
  }>;
  proposed: {
    record: string;
    changes: string[];  // List of what's being added/changed
    priority: 'high' | 'medium' | 'low';
  } | null;
}

export interface DkimAnalysis {
  current: StoredDkimRecord[];
  issues: IssueReference[];
  proposed: Array<{
    selector: string;
    recordName: string;
    record: string;
    explanation: string;
    priority: 'high' | 'medium' | 'low';
  }>;
}

export interface DmarcAnalysis {
  current: StoredDmarcRecord | null;
  issues: IssueReference[];
  proposed: {
    record: string;
    changes: string[];
    priority: 'high' | 'medium' | 'low';
  } | null;
}

export interface RecordAnalysis {
  spf: SpfAnalysis;
  dkim: DkimAnalysis;
  dmarc: DmarcAnalysis;
}

// Extended domain analysis with enriched issues and DNS
export interface DomainAnalysisWithDns extends Omit<DomainAnalysis, 'issues'> {
  issues: EnrichedIssue[];
  dns?: StoredDnsData;
  recordAnalysis: RecordAnalysis;
}
