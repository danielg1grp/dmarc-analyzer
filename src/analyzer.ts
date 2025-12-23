import {
  ProcessedRecord,
  PolicyPublished,
  Issue,
  IssueCode,
  DomainAnalysis,
  TrendPoint,
  ReportSummary,
  ParsedReport
} from './types';

// Issue definitions with explanations and remediation steps
const ISSUE_DEFINITIONS: Record<IssueCode, { title: string; explanation: string; remediation: string }> = {
  DKIM_ALIGNMENT_FAIL: {
    title: 'DKIM Alignment Failure',
    explanation: 'DKIM signature verification passed, but the signing domain does not align with the From header domain. This commonly happens with Google Workspace when using the default DKIM signing (gappssmtp.com) instead of your own domain.',
    remediation: `To fix DKIM alignment:
1. For Google Workspace:
   - Go to Admin Console > Apps > Google Workspace > Gmail > Authenticate email
   - Generate a DKIM key for your domain
   - Add the provided TXT record to your DNS
   - Start authentication in the Admin Console
2. For other providers:
   - Configure DKIM signing to use your actual domain
   - Ensure the d= value in DKIM signatures matches your From domain
3. Verify with: dig TXT selector._domainkey.yourdomain.com`
  },
  SPF_SOFTFAIL: {
    title: 'SPF Soft Fail',
    explanation: 'The sending IP address is not explicitly authorized in your SPF record (~all). While not a hard failure, this indicates the IP should probably be added to your SPF record if it\'s a legitimate sender.',
    remediation: `To fix SPF soft fails:
1. Identify the legitimate sending IPs from the source_ip field
2. Add them to your SPF record:
   - For Google: include:_spf.google.com
   - For Microsoft 365: include:spf.protection.outlook.com
   - For specific IPs: ip4:x.x.x.x or ip6:xxxx:xxxx::
3. Example SPF record:
   v=spf1 include:_spf.google.com include:other.service.com ~all
4. Consider changing ~all to -all after confirming all senders`
  },
  SPF_FAIL: {
    title: 'SPF Hard Fail',
    explanation: 'The sending IP address is explicitly NOT authorized by your SPF record. This could indicate spoofing attempts or a misconfigured legitimate sender.',
    remediation: `To address SPF failures:
1. Check if the source IP is a legitimate sender
2. If legitimate, add to SPF record (see SPF_SOFTFAIL remediation)
3. If not legitimate, this may be a spoofing attempt - your SPF is working correctly
4. Consider implementing DMARC policy of quarantine or reject to block these`
  },
  SPF_PERMERROR: {
    title: 'SPF Permanent Error',
    explanation: 'Your SPF record has a syntax error or exceeds the DNS lookup limit (max 10 lookups). This prevents SPF from being evaluated properly.',
    remediation: `To fix SPF permanent errors:
1. Check your SPF record syntax with an online validator
2. Count your DNS lookups (each include/a/mx/redirect counts):
   - Maximum allowed: 10 DNS lookups
   - Use ip4/ip6 instead of include where possible
3. Consider SPF flattening services to reduce lookups
4. Common syntax issues:
   - Missing "v=spf1" prefix
   - Multiple SPF records (only one allowed)
   - Invalid mechanisms`
  },
  SPF_TEMPERROR: {
    title: 'SPF Temporary Error',
    explanation: 'A temporary DNS lookup failure occurred when checking SPF. This is usually transient and resolves on its own.',
    remediation: `SPF temporary errors are usually transient:
1. Monitor for persistence - occasional temperrors are normal
2. If persistent, check:
   - DNS server health
   - SPF record accessibility
   - TTL settings on DNS records
3. Ensure your DNS provider is reliable`
  },
  DKIM_FAIL: {
    title: 'DKIM Verification Failed',
    explanation: 'The DKIM signature on the email failed verification. This could mean the email was modified in transit, the DKIM key is missing/incorrect in DNS, or the signature is invalid.',
    remediation: `To fix DKIM failures:
1. Verify DKIM key is published in DNS:
   dig TXT selector._domainkey.yourdomain.com
2. Check for key rotation issues - ensure the selector in use matches DNS
3. If using a third-party sender, ensure they have correct DKIM configuration
4. Check if email is being modified in transit (mailing lists, forwarding)
5. Regenerate and republish DKIM key if corrupted`
  },
  POLICY_NONE: {
    title: 'DMARC Policy: None (Monitor Only)',
    explanation: 'Your DMARC policy is set to "none", which means failing emails are still delivered. This is appropriate for initial monitoring but provides no protection against spoofing.',
    remediation: `To strengthen your DMARC policy:
1. First, ensure SPF and DKIM are properly configured
2. Monitor reports to identify legitimate senders
3. Gradually increase policy:
   - p=none (current) - monitoring only
   - p=quarantine - failing emails go to spam
   - p=reject - failing emails are blocked
4. Consider: p=quarantine; pct=10 to start with 10%
5. Update DNS TXT record for _dmarc.yourdomain.com`
  },
  THIRD_PARTY_SENDER: {
    title: 'Third-Party Sender Detected',
    explanation: 'Emails are being sent from a different domain (envelope-from) than the visible From address. This is common for email services, marketing platforms, or forwarding, but requires proper authentication setup.',
    remediation: `To properly authenticate third-party senders:
1. Identify the third-party service from envelope_from
2. Configure the third-party to:
   - Sign with DKIM using your domain (preferred)
   - Or include their servers in your SPF record
3. For Google Workspace aliases (g1grp.com):
   - Ensure alias domain has matching DKIM/SPF
   - Or configure as a proper sending domain
4. Consider ARC (Authenticated Received Chain) for forwarding`
  }
};

/**
 * Detect issues in a set of records for a domain
 */
export function detectIssues(records: ProcessedRecord[], policy: PolicyPublished): Issue[] {
  const issues: Issue[] = [];
  const issueRecordCounts: Map<IssueCode, { count: number; ips: Set<string> }> = new Map();

  // Initialize counters
  const issueCodes: IssueCode[] = [
    'DKIM_ALIGNMENT_FAIL', 'SPF_SOFTFAIL', 'SPF_FAIL', 'SPF_PERMERROR',
    'SPF_TEMPERROR', 'DKIM_FAIL', 'POLICY_NONE', 'THIRD_PARTY_SENDER'
  ];
  issueCodes.forEach(code => issueRecordCounts.set(code, { count: 0, ips: new Set() }));

  // Check policy level issues
  if (policy.p === 'none') {
    const data = issueRecordCounts.get('POLICY_NONE')!;
    data.count = records.reduce((sum, r) => sum + r.count, 0);
  }

  // Analyze each record
  for (const record of records) {
    const messageCount = record.count;

    // Check for DKIM alignment failure (DKIM passes auth but fails alignment)
    const dkimAuthPassed = record.authResults.dkim.some(d => d.result === 'pass');
    const dkimAlignmentFailed = record.policyEvaluated.dkim === 'fail';
    if (dkimAuthPassed && dkimAlignmentFailed) {
      const data = issueRecordCounts.get('DKIM_ALIGNMENT_FAIL')!;
      data.count += messageCount;
      data.ips.add(record.sourceIp);
    }

    // Check for DKIM verification failure
    const dkimAuthFailed = record.authResults.dkim.some(d => d.result === 'fail');
    if (dkimAuthFailed) {
      const data = issueRecordCounts.get('DKIM_FAIL')!;
      data.count += messageCount;
      data.ips.add(record.sourceIp);
    }

    // Check SPF result issues
    const spfResult = record.authResults.spf.result.toLowerCase();
    if (spfResult === 'softfail') {
      const data = issueRecordCounts.get('SPF_SOFTFAIL')!;
      data.count += messageCount;
      data.ips.add(record.sourceIp);
    } else if (spfResult === 'fail') {
      const data = issueRecordCounts.get('SPF_FAIL')!;
      data.count += messageCount;
      data.ips.add(record.sourceIp);
    } else if (spfResult === 'permerror') {
      const data = issueRecordCounts.get('SPF_PERMERROR')!;
      data.count += messageCount;
      data.ips.add(record.sourceIp);
    } else if (spfResult === 'temperror') {
      const data = issueRecordCounts.get('SPF_TEMPERROR')!;
      data.count += messageCount;
      data.ips.add(record.sourceIp);
    }

    // Check for third-party sender
    if (record.identifiers.envelopeFrom && record.identifiers.headerFrom) {
      const envelopeDomain = extractDomain(record.identifiers.envelopeFrom);
      const headerDomain = extractDomain(record.identifiers.headerFrom);
      if (envelopeDomain && headerDomain && envelopeDomain !== headerDomain) {
        const data = issueRecordCounts.get('THIRD_PARTY_SENDER')!;
        data.count += messageCount;
        data.ips.add(record.sourceIp);
      }
    }
  }

  // Build issue objects for detected issues
  for (const [code, data] of issueRecordCounts.entries()) {
    if (data.count > 0 || (code === 'POLICY_NONE' && policy.p === 'none')) {
      const def = ISSUE_DEFINITIONS[code];
      issues.push({
        code,
        title: def.title,
        explanation: def.explanation,
        remediation: def.remediation,
        affectedRecords: data.count,
        sampleSourceIps: Array.from(data.ips).slice(0, 5)
      });
    }
  }

  // Sort by affected records count (most impactful first)
  issues.sort((a, b) => b.affectedRecords - a.affectedRecords);

  return issues;
}

/**
 * Extract domain from email address or domain string
 */
function extractDomain(value: string): string | null {
  if (!value) return null;
  if (value.includes('@')) {
    return value.split('@')[1]?.toLowerCase() || null;
  }
  return value.toLowerCase();
}

/**
 * Calculate pass/fail statistics for records
 */
export function calculateStats(records: ProcessedRecord[]): { total: number; pass: number; fail: number } {
  let total = 0;
  let pass = 0;
  let fail = 0;

  for (const record of records) {
    total += record.count;
    // DMARC passes if either DKIM or SPF passes AND aligns
    const dmarcPass = record.policyEvaluated.dkim === 'pass' || record.policyEvaluated.spf === 'pass';
    if (dmarcPass) {
      pass += record.count;
    } else {
      fail += record.count;
    }
  }

  return { total, pass, fail };
}

/**
 * Generate a report summary from a parsed report
 */
export function generateReportSummary(report: ParsedReport): ReportSummary {
  const stats = calculateStats(report.records);
  const issues = detectIssues(report.records, report.policy);

  return {
    reportId: report.metadata.reportId,
    filename: report.filename,
    reporter: report.metadata.orgName,
    dateRange: report.metadata.dateRange,
    totalMessages: stats.total,
    passCount: stats.pass,
    failCount: stats.fail,
    issues: issues.map(i => i.code)
  };
}

/**
 * Calculate trend data points from report summaries
 */
export function calculateTrends(summaries: ReportSummary[]): TrendPoint[] {
  // Sort by date
  const sorted = [...summaries].sort((a, b) => a.dateRange.begin - b.dateRange.begin);

  return sorted.map(summary => ({
    dateRange: summary.dateRange,
    totalMessages: summary.totalMessages,
    passCount: summary.passCount,
    failCount: summary.failCount,
    passRate: summary.totalMessages > 0
      ? Math.round((summary.passCount / summary.totalMessages) * 100)
      : 0
  }));
}

/**
 * Generate complete domain analysis
 */
export function analyzeDomain(
  domain: string,
  policy: PolicyPublished,
  records: ProcessedRecord[],
  summaries: ReportSummary[]
): DomainAnalysis {
  const stats = calculateStats(records);
  const issues = detectIssues(records, policy);
  const trends = calculateTrends(summaries);

  return {
    domain,
    policy,
    totalMessages: stats.total,
    passCount: stats.pass,
    failCount: stats.fail,
    passRate: stats.total > 0 ? Math.round((stats.pass / stats.total) * 100) : 0,
    issues,
    trends,
    records
  };
}
