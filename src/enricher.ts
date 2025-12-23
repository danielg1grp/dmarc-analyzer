import {
  Issue,
  IssueCode,
  EnrichedIssue,
  RelevantDnsRecord,
  ProposedChange,
  StoredDnsData,
  ProcessedRecord,
  PolicyPublished,
  SourceIpAnalysis,
  IdentifiedServiceInfo,
  RecordAnalysis,
  IssueReference,
  SpfAnalysis,
  DkimAnalysis,
  DmarcAnalysis
} from './types';

/**
 * Enrich issues with DNS context and proposed changes
 */
export function enrichIssues(
  issues: Issue[],
  dns: StoredDnsData | undefined,
  records: ProcessedRecord[],
  policy: PolicyPublished,
  domain: string,
  sourceIpAnalysis?: SourceIpAnalysis
): EnrichedIssue[] {
  return issues.map(issue => enrichIssue(issue, dns, records, policy, domain, sourceIpAnalysis));
}

/**
 * Enrich a single issue with DNS context
 */
function enrichIssue(
  issue: Issue,
  dns: StoredDnsData | undefined,
  records: ProcessedRecord[],
  policy: PolicyPublished,
  domain: string,
  sourceIpAnalysis?: SourceIpAnalysis
): EnrichedIssue {
  const relevantDns: RelevantDnsRecord[] = [];
  const proposedChanges: ProposedChange[] = [];
  let context = '';

  if (!dns) {
    return {
      ...issue,
      relevantDns: [],
      proposedChanges: [],
      context: 'DNS records have not been fetched yet. Click "Refresh Reports" to fetch current records.'
    };
  }

  switch (issue.code) {
    case 'DKIM_ALIGNMENT_FAIL':
      enrichDkimAlignmentFail(issue, dns, records, policy, domain, relevantDns, proposedChanges);
      context = generateDkimAlignmentContext(dns, records, domain);
      break;

    case 'SPF_SOFTFAIL':
    case 'SPF_FAIL':
      enrichSpfFail(issue, dns, records, domain, relevantDns, proposedChanges, sourceIpAnalysis);
      context = generateSpfFailContext(issue.code, dns, sourceIpAnalysis);
      break;

    case 'SPF_PERMERROR':
      enrichSpfPermerror(issue, dns, domain, relevantDns, proposedChanges, sourceIpAnalysis);
      context = generateSpfPermerrorContext(dns);
      break;

    case 'SPF_TEMPERROR':
      enrichSpfTemperror(dns, relevantDns);
      context = 'Temporary DNS lookup failures are usually transient. If persistent, check your DNS provider health.';
      break;

    case 'DKIM_FAIL':
      enrichDkimFail(issue, dns, records, domain, relevantDns, proposedChanges);
      context = generateDkimFailContext(dns, records);
      break;

    case 'POLICY_NONE':
      enrichPolicyNone(dns, domain, relevantDns, proposedChanges);
      context = generatePolicyNoneContext(dns, issue.affectedRecords);
      break;

    case 'THIRD_PARTY_SENDER':
      enrichThirdPartySender(issue, dns, records, domain, relevantDns, proposedChanges, sourceIpAnalysis);
      context = generateThirdPartySenderContext(records, sourceIpAnalysis);
      break;
  }

  return {
    ...issue,
    relevantDns,
    proposedChanges,
    context
  };
}

/**
 * Build a complete SPF record from scratch with identified services
 */
function buildCompleteSpfRecord(
  currentSpf: { includes: string[]; ipv4: string[]; ipv6: string[]; mechanisms: string[]; all: string } | null,
  identifiedServices: IdentifiedServiceInfo[],
  additionalIncludes: string[] = [],
  additionalIps: string[] = []
): string {
  const parts = ['v=spf1'];
  const addedIncludes = new Set<string>();

  // Add includes from identified services (if not already present)
  for (const svc of identifiedServices) {
    const include = svc.spfInclude;
    const alreadyHas = currentSpf?.includes.some(i =>
      i.toLowerCase().includes(include.toLowerCase()) ||
      include.toLowerCase().includes(i.toLowerCase())
    );
    if (!alreadyHas && !addedIncludes.has(include)) {
      parts.push(`include:${include}`);
      addedIncludes.add(include);
    }
  }

  // Keep existing includes that are still valid
  if (currentSpf) {
    for (const inc of currentSpf.includes) {
      if (!addedIncludes.has(inc)) {
        parts.push(`include:${inc}`);
        addedIncludes.add(inc);
      }
    }
  }

  // Add additional includes
  for (const inc of additionalIncludes) {
    if (!addedIncludes.has(inc)) {
      parts.push(`include:${inc}`);
      addedIncludes.add(inc);
    }
  }

  // Keep existing IPs
  if (currentSpf) {
    for (const ip of currentSpf.ipv4) {
      parts.push(`ip4:${ip}`);
    }
    for (const ip of currentSpf.ipv6) {
      parts.push(`ip6:${ip}`);
    }
  }

  // Add additional IPs
  for (const ip of additionalIps) {
    if (ip.includes(':')) {
      parts.push(`ip6:${ip}`);
    } else {
      parts.push(`ip4:${ip}`);
    }
  }

  // Use existing 'all' mechanism or default to ~all
  parts.push(currentSpf?.all || '~all');

  return parts.join(' ');
}

/**
 * Enrich DKIM alignment failure issue
 */
function enrichDkimAlignmentFail(
  issue: Issue,
  dns: StoredDnsData,
  records: ProcessedRecord[],
  policy: PolicyPublished,
  domain: string,
  relevantDns: RelevantDnsRecord[],
  proposedChanges: ProposedChange[]
): void {
  // Find signing domains and selectors from records
  const signingInfo = new Map<string, { domain: string; selector?: string; count: number }>();
  for (const record of records) {
    for (const dkim of record.authResults.dkim) {
      if (dkim.result === 'pass' && dkim.domain) {
        const key = `${dkim.domain}:${dkim.selector || 'unknown'}`;
        const existing = signingInfo.get(key) || { domain: dkim.domain, selector: dkim.selector, count: 0 };
        existing.count += record.count;
        signingInfo.set(key, existing);
      }
    }
  }

  // Add current DMARC record
  if (dns.dmarc) {
    relevantDns.push({
      type: 'DMARC',
      raw: dns.dmarc.raw,
      explanation: `Current DMARC alignment mode: adkim=${dns.dmarc.adkim || 'r'} (${dns.dmarc.adkim === 's' ? 'strict' : 'relaxed'}). Emails are signed by a different domain than "${domain}".`
    });
  }

  // Check if using gappssmtp (Google Workspace default)
  const gappssmtpEntry = Array.from(signingInfo.values()).find(s => s.domain.includes('gappssmtp.com'));
  const usesGoogleWorkspace = !!gappssmtpEntry;

  if (usesGoogleWorkspace) {
    // Check if Google DKIM is already configured
    const hasGoogleDkim = dns.dkim.some(d => d.selector === 'google' && d.found);

    if (hasGoogleDkim) {
      relevantDns.push({
        type: 'DKIM',
        raw: dns.dkim.find(d => d.selector === 'google')?.raw || '',
        explanation: `Google DKIM key exists but may not be active in Google Admin Console. Emails are still being signed with gappssmtp.com.`
      });

      proposedChanges.push({
        type: 'DKIM',
        recordName: `google._domainkey.${domain}`,
        current: dns.dkim.find(d => d.selector === 'google')?.raw || null,
        proposed: '(Enable in Google Admin Console)',
        explanation: `DKIM key exists in DNS but Google Workspace is not using it. Go to Google Admin Console > Apps > Google Workspace > Gmail > Authenticate email > Click "Start authentication" for ${domain}`,
        priority: 'high'
      });
    } else {
      // Need to generate and publish Google DKIM
      proposedChanges.push({
        type: 'DKIM',
        recordName: `google._domainkey.${domain}`,
        current: null,
        proposed: 'v=DKIM1; k=rsa; p=MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA... (generate in Google Admin)',
        explanation: `Generate DKIM key in Google Admin Console > Apps > Google Workspace > Gmail > Authenticate email > Click "Generate new record" for ${domain}. Then add the TXT record shown and click "Start authentication".`,
        priority: 'high'
      });
    }
  } else {
    // Other signing domains
    const signers = Array.from(signingInfo.values()).slice(0, 3);
    for (const signer of signers) {
      relevantDns.push({
        type: 'DKIM',
        raw: `Signing domain: ${signer.domain}, selector: ${signer.selector || 'unknown'}`,
        explanation: `${signer.count} messages signed by ${signer.domain} (not aligned with ${domain})`
      });
    }

    proposedChanges.push({
      type: 'DKIM',
      recordName: `(provider-specific)._domainkey.${domain}`,
      current: null,
      proposed: 'v=DKIM1; k=rsa; p=<your-public-key>',
      explanation: `Configure your email provider to sign emails with d=${domain} instead of ${signers[0]?.domain || 'their default domain'}. Check your provider's documentation for DKIM setup.`,
      priority: 'high'
    });
  }
}

/**
 * Generate context for DKIM alignment failure
 */
function generateDkimAlignmentContext(
  dns: StoredDnsData,
  records: ProcessedRecord[],
  domain: string
): string {
  const signingDomains = new Map<string, number>();
  for (const record of records) {
    for (const dkim of record.authResults.dkim) {
      if (dkim.result === 'pass' && dkim.domain) {
        signingDomains.set(dkim.domain.toLowerCase(),
          (signingDomains.get(dkim.domain.toLowerCase()) || 0) + record.count);
      }
    }
  }

  const sortedSigners = Array.from(signingDomains.entries())
    .sort((a, b) => b[1] - a[1])
    .slice(0, 3);

  const usesGappssmtp = sortedSigners.some(([d]) => d.includes('gappssmtp.com'));

  if (usesGappssmtp) {
    const gappsCount = signingDomains.get(sortedSigners.find(([d]) => d.includes('gappssmtp.com'))?.[0] || '') || 0;
    return `${gappsCount} emails are being signed by Google's default DKIM domain (gappssmtp.com) instead of ${domain}. This is the default Google Workspace behavior. You need to enable custom DKIM in Google Admin Console to fix this.`;
  }

  const signerList = sortedSigners.map(([d, c]) => `${d} (${c} msgs)`).join(', ');
  return `Emails are being DKIM-signed by: ${signerList}. These signatures are valid but don't match your From domain (${domain}), causing DMARC alignment to fail.`;
}

/**
 * Enrich SPF failure issues with identified services
 */
function enrichSpfFail(
  issue: Issue,
  dns: StoredDnsData,
  records: ProcessedRecord[],
  domain: string,
  relevantDns: RelevantDnsRecord[],
  proposedChanges: ProposedChange[],
  sourceIpAnalysis?: SourceIpAnalysis
): void {
  // Show current SPF record
  if (dns.spf) {
    relevantDns.push({
      type: 'SPF',
      raw: dns.spf.raw,
      explanation: `Current SPF: ${dns.spf.includes.length} includes (${dns.spf.includes.join(', ') || 'none'}), ${dns.spf.ipv4.length + dns.spf.ipv6.length} IPs, all=${dns.spf.all}`
    });
  }

  // Use identified services to build specific recommendations
  if (sourceIpAnalysis && sourceIpAnalysis.identifiedServices.length > 0) {
    // Find services that are NOT already in SPF
    const missingServices = sourceIpAnalysis.identifiedServices.filter(svc => {
      if (!dns.spf) return true;
      return !dns.spf.includes.some(inc =>
        inc.toLowerCase().includes(svc.spfInclude.toLowerCase()) ||
        svc.spfInclude.toLowerCase().includes(inc.toLowerCase())
      );
    });

    if (missingServices.length > 0) {
      // Add each missing service as relevant DNS
      for (const svc of missingServices) {
        relevantDns.push({
          type: 'SPF',
          raw: `Missing: include:${svc.spfInclude}`,
          explanation: `${svc.name} sent ${svc.messageCount} messages from ${svc.sourceIps.length} IP(s). Not in current SPF record.`
        });
      }

      // Build complete proposed SPF record with all missing services
      const completeSpf = buildCompleteSpfRecord(
        dns.spf,
        missingServices,
        [],
        []
      );

      const serviceNames = missingServices.map(s => s.name).join(', ');
      proposedChanges.push({
        type: 'SPF',
        recordName: `${domain}`,
        current: dns.spf?.raw || null,
        proposed: completeSpf,
        explanation: `Add ${missingServices.length} missing service(s): ${serviceNames}. This complete SPF record includes all identified senders.`,
        priority: 'high'
      });
    }

    // Handle unidentified IPs
    if (sourceIpAnalysis.unidentifiedIps.length > 0) {
      const topUnidentified = sourceIpAnalysis.unidentifiedIps.slice(0, 5);
      const totalUnidentifiedMessages = sourceIpAnalysis.unidentifiedIps.reduce((sum, ip) => sum + ip.messageCount, 0);

      relevantDns.push({
        type: 'SPF',
        raw: `Unidentified IPs: ${topUnidentified.map(u => u.ip).join(', ')}`,
        explanation: `${totalUnidentifiedMessages} messages from ${sourceIpAnalysis.unidentifiedIps.length} unidentified IP(s). Investigate if these are legitimate senders.`
      });

      // If no services found but there are IPs, suggest adding them directly
      if (missingServices.length === 0 && topUnidentified.length > 0) {
        const ipv4s = topUnidentified.filter(u => !u.ip.includes(':')).map(u => u.ip);
        const ipv6s = topUnidentified.filter(u => u.ip.includes(':')).map(u => u.ip);

        if (ipv4s.length > 0 || ipv6s.length > 0) {
          const newSpf = buildCompleteSpfRecord(dns.spf, [], [], [...ipv4s, ...ipv6s]);
          proposedChanges.push({
            type: 'SPF',
            recordName: `${domain}`,
            current: dns.spf?.raw || null,
            proposed: newSpf,
            explanation: `Add unidentified IPs if they are legitimate senders: ${topUnidentified.map(u => `${u.ip} (${u.messageCount} msgs)`).join(', ')}`,
            priority: 'medium'
          });
        }
      }
    }
  } else if (!dns.spf) {
    // No SPF record and no IP analysis - suggest creating one
    proposedChanges.push({
      type: 'SPF',
      recordName: `${domain}`,
      current: null,
      proposed: 'v=spf1 include:_spf.google.com ~all',
      explanation: 'No SPF record found. Create one starting with your primary email provider.',
      priority: 'high'
    });
  } else {
    // Have SPF but no IP analysis - generic suggestion
    const failingIps = issue.sampleSourceIps.slice(0, 3);
    if (failingIps.length > 0) {
      relevantDns.push({
        type: 'SPF',
        raw: `Failing IPs: ${failingIps.join(', ')}`,
        explanation: `These IPs are sending mail but not authorized by SPF. Run "Refresh Reports" to identify the services.`
      });
    }
  }
}

/**
 * Generate context for SPF failures
 */
function generateSpfFailContext(
  issueCode: IssueCode,
  dns: StoredDnsData,
  sourceIpAnalysis?: SourceIpAnalysis
): string {
  const failType = issueCode === 'SPF_FAIL' ? 'hard fail (-all)' : 'soft fail (~all)';

  if (!dns.spf) {
    return `No SPF record exists for this domain. All SPF checks result in ${failType}. Create an SPF record to authorize your legitimate senders.`;
  }

  if (sourceIpAnalysis && sourceIpAnalysis.identifiedServices.length > 0) {
    const missingServices = sourceIpAnalysis.identifiedServices.filter(svc => {
      return !dns.spf!.includes.some(inc =>
        inc.toLowerCase().includes(svc.spfInclude.toLowerCase()) ||
        svc.spfInclude.toLowerCase().includes(inc.toLowerCase())
      );
    });

    if (missingServices.length > 0) {
      const svcList = missingServices.map(s => `${s.name} (${s.messageCount} msgs)`).join(', ');
      return `Your SPF record is missing these identified services: ${svcList}. Add their SPF includes to authorize them.`;
    }
  }

  return `Your SPF record ends with "${dns.spf.all}" causing ${failType} for unauthorized IPs. Check the proposed changes for specific fixes.`;
}

/**
 * Enrich SPF permanent error
 */
function enrichSpfPermerror(
  issue: Issue,
  dns: StoredDnsData,
  domain: string,
  relevantDns: RelevantDnsRecord[],
  proposedChanges: ProposedChange[],
  sourceIpAnalysis?: SourceIpAnalysis
): void {
  if (dns.spf) {
    relevantDns.push({
      type: 'SPF',
      raw: dns.spf.raw,
      explanation: `SPF has ${dns.spf.lookupCount} DNS lookups. Maximum allowed is 10. Each "include:" counts as 1+ lookups.`
    });

    if (dns.spf.lookupCount > 10) {
      // Need to flatten or reduce includes
      // Keep only the most important includes based on identified services
      if (sourceIpAnalysis && sourceIpAnalysis.identifiedServices.length > 0) {
        const essentialIncludes = sourceIpAnalysis.identifiedServices
          .slice(0, 5) // Keep top 5 by message count
          .map(s => s.spfInclude);

        const flattenedSpf = `v=spf1 ${essentialIncludes.map(i => `include:${i}`).join(' ')} ~all`;

        proposedChanges.push({
          type: 'SPF',
          recordName: `${domain}`,
          current: dns.spf.raw,
          proposed: flattenedSpf,
          explanation: `Reduce to ${essentialIncludes.length} essential includes (top services by message count). Consider using an SPF flattening service for more includes.`,
          priority: 'high'
        });
      } else {
        // Generic flatten suggestion
        proposedChanges.push({
          type: 'SPF',
          recordName: `${domain}`,
          current: dns.spf.raw,
          proposed: `v=spf1 ip4:<resolved-ips> ~all`,
          explanation: `Your SPF has ${dns.spf.lookupCount} lookups (max 10). Use an SPF flattening service like dmarcian, EasyDMARC, or AutoSPF to resolve includes to IP addresses.`,
          priority: 'high'
        });
      }
    }
  }
}

/**
 * Generate context for SPF permanent errors
 */
function generateSpfPermerrorContext(dns: StoredDnsData): string {
  if (!dns.spf) {
    return 'SPF record could not be parsed or is missing.';
  }

  if (dns.spf.lookupCount > 10) {
    return `Your SPF record requires ${dns.spf.lookupCount} DNS lookups but the RFC limit is 10. When exceeded, SPF returns "permerror" and fails completely. You have ${dns.spf.includes.length} include statements. Consider SPF flattening or removing unused includes.`;
  }

  if (dns.spf.hasError) {
    return `SPF error: ${dns.spf.errorMessage}`;
  }

  return 'SPF record has a syntax error or configuration issue preventing evaluation.';
}

/**
 * Enrich SPF temporary error
 */
function enrichSpfTemperror(
  dns: StoredDnsData,
  relevantDns: RelevantDnsRecord[]
): void {
  if (dns.spf) {
    relevantDns.push({
      type: 'SPF',
      raw: dns.spf.raw,
      explanation: 'SPF record exists. Temporary errors are typically caused by DNS timeout issues, not configuration problems.'
    });
  }
}

/**
 * Enrich DKIM failure
 */
function enrichDkimFail(
  issue: Issue,
  dns: StoredDnsData,
  records: ProcessedRecord[],
  domain: string,
  relevantDns: RelevantDnsRecord[],
  proposedChanges: ProposedChange[]
): void {
  // Find selectors and domains used in failing records
  const failingSelectors = new Map<string, { selector: string; domain: string; count: number }>();
  for (const record of records) {
    for (const dkim of record.authResults.dkim) {
      if (dkim.result === 'fail' && dkim.selector) {
        const key = `${dkim.selector}:${dkim.domain}`;
        const existing = failingSelectors.get(key) || { selector: dkim.selector, domain: dkim.domain || domain, count: 0 };
        existing.count += record.count;
        failingSelectors.set(key, existing);
      }
    }
  }

  // Add existing DKIM records
  if (dns.dkim.length > 0) {
    for (const dkim of dns.dkim) {
      relevantDns.push({
        type: 'DKIM',
        raw: dkim.raw || `Selector: ${dkim.selector}`,
        explanation: `DKIM key for selector "${dkim.selector}" ${dkim.found ? 'found in DNS' : 'NOT found in DNS'}`
      });
    }
  }

  // Check for selectors that don't have DNS records
  for (const [key, info] of failingSelectors) {
    const existsInDns = dns.dkim.some(d => d.selector === info.selector && d.found);

    if (!existsInDns) {
      proposedChanges.push({
        type: 'DKIM',
        recordName: `${info.selector}._domainkey.${info.domain}`,
        current: null,
        proposed: 'v=DKIM1; k=rsa; p=<public-key-from-your-email-provider>',
        explanation: `Selector "${info.selector}" signed ${info.count} messages but no DNS record exists. Get the public key from your email provider and publish it.`,
        priority: 'high'
      });
    } else {
      // Key exists but still failing - might be key mismatch
      proposedChanges.push({
        type: 'DKIM',
        recordName: `${info.selector}._domainkey.${info.domain}`,
        current: dns.dkim.find(d => d.selector === info.selector)?.raw || null,
        proposed: '(Verify key matches email provider)',
        explanation: `Selector "${info.selector}" has a DNS record but signatures are failing. The key may have been rotated - verify with your email provider that the DNS record matches their current signing key.`,
        priority: 'high'
      });
    }
  }
}

/**
 * Generate context for DKIM failures
 */
function generateDkimFailContext(dns: StoredDnsData, records: ProcessedRecord[]): string {
  const failingSelectors = new Set<string>();

  for (const record of records) {
    for (const dkim of record.authResults.dkim) {
      if (dkim.result === 'fail' && dkim.selector) {
        failingSelectors.add(dkim.selector);
      }
    }
  }

  const selList = Array.from(failingSelectors).slice(0, 3);
  const foundSelectors = dns.dkim.filter(d => d.found).map(d => d.selector);
  const missingInDns = selList.filter(s => !foundSelectors.includes(s));

  if (missingInDns.length > 0) {
    return `DKIM signatures using selector(s) "${missingInDns.join(', ')}" are failing because no DNS record exists. Publish the DKIM public key from your email provider.`;
  }

  return `DKIM verification is failing for selector(s) "${selList.join(', ')}". The DNS records exist but don't match the signing key. This usually means the key was rotated - update DNS with the current public key from your email provider.`;
}

/**
 * Enrich policy:none issue
 */
function enrichPolicyNone(
  dns: StoredDnsData,
  domain: string,
  relevantDns: RelevantDnsRecord[],
  proposedChanges: ProposedChange[]
): void {
  if (dns.dmarc) {
    relevantDns.push({
      type: 'DMARC',
      raw: dns.dmarc.raw,
      explanation: `Current policy: p=${dns.dmarc.policy}, sp=${dns.dmarc.subdomainPolicy || 'none'}, pct=${dns.dmarc.percentage || 100}%`
    });

    // Get current rua or suggest one
    const currentRua = dns.dmarc.rua?.join(', ') || `mailto:dmarc@${domain}`;

    // Propose single progressive change
    proposedChanges.push({
      type: 'DMARC',
      recordName: `_dmarc.${domain}`,
      current: dns.dmarc.raw,
      proposed: `v=DMARC1; p=quarantine; pct=25; rua=${currentRua}; adkim=r; aspf=r`,
      explanation: 'Recommended next step: Move to p=quarantine at 25%. This will quarantine (spam folder) 25% of failing emails while you monitor the impact. Increase pct gradually (25→50→100) then move to p=reject.',
      priority: 'medium'
    });
  } else {
    proposedChanges.push({
      type: 'DMARC',
      recordName: `_dmarc.${domain}`,
      current: null,
      proposed: `v=DMARC1; p=none; rua=mailto:dmarc@${domain}; adkim=r; aspf=r`,
      explanation: 'No DMARC record found. Start with p=none to collect reports without affecting mail delivery.',
      priority: 'high'
    });
  }
}

/**
 * Generate context for policy:none
 */
function generatePolicyNoneContext(dns: StoredDnsData, affectedMessages: number): string {
  if (!dns.dmarc) {
    return 'No DMARC record exists. Without DMARC, receivers cannot verify your email authentication policy and spoofed emails will be delivered.';
  }

  return `Your DMARC policy is "none", meaning all ${affectedMessages.toLocaleString()} messages are delivered regardless of SPF/DKIM results. Spoofed emails claiming to be from your domain will reach recipients. Once you confirm SPF and DKIM are correctly configured for all legitimate senders, increase to p=quarantine then p=reject.`;
}

/**
 * Enrich third-party sender issue
 */
function enrichThirdPartySender(
  issue: Issue,
  dns: StoredDnsData,
  records: ProcessedRecord[],
  domain: string,
  relevantDns: RelevantDnsRecord[],
  proposedChanges: ProposedChange[],
  sourceIpAnalysis?: SourceIpAnalysis
): void {
  // Show current SPF record
  if (dns.spf) {
    relevantDns.push({
      type: 'SPF',
      raw: dns.spf.raw,
      explanation: 'Current SPF record - third-party services need to be included here'
    });
  }

  // Find third-party domains from records
  const thirdParties = new Map<string, { envDomain: string; count: number }>();
  for (const record of records) {
    if (record.identifiers.envelopeFrom) {
      const envDomain = extractDomain(record.identifiers.envelopeFrom);
      const headerDomain = extractDomain(record.identifiers.headerFrom);
      if (envDomain && headerDomain && envDomain !== headerDomain) {
        const existing = thirdParties.get(envDomain) || { envDomain, count: 0 };
        existing.count += record.count;
        thirdParties.set(envDomain, existing);
      }
    }
  }

  // Use identified services if available
  if (sourceIpAnalysis && sourceIpAnalysis.identifiedServices.length > 0) {
    const missingServices = sourceIpAnalysis.identifiedServices.filter(svc => {
      if (!dns.spf) return true;
      return !dns.spf.includes.some(inc =>
        inc.toLowerCase().includes(svc.spfInclude.toLowerCase()) ||
        svc.spfInclude.toLowerCase().includes(inc.toLowerCase())
      );
    });

    if (missingServices.length > 0) {
      for (const svc of missingServices) {
        relevantDns.push({
          type: 'SPF',
          raw: `Third-party: ${svc.name}`,
          explanation: `${svc.name} sent ${svc.messageCount} messages. Needs include:${svc.spfInclude} in SPF.`
        });
      }

      // Build complete SPF with missing services
      const completeSpf = buildCompleteSpfRecord(dns.spf, missingServices, [], []);
      const svcNames = missingServices.map(s => s.name).join(', ');

      proposedChanges.push({
        type: 'SPF',
        recordName: `${domain}`,
        current: dns.spf?.raw || null,
        proposed: completeSpf,
        explanation: `Add ${missingServices.length} third-party service(s) to SPF: ${svcNames}`,
        priority: 'high'
      });
    }
  } else {
    // Fall back to envelope domain matching
    const sortedThirdParties = Array.from(thirdParties.values())
      .sort((a, b) => b.count - a.count)
      .slice(0, 5);

    for (const tp of sortedThirdParties) {
      relevantDns.push({
        type: 'SPF',
        raw: `Envelope-from: ${tp.envDomain}`,
        explanation: `${tp.count} messages sent with envelope-from @${tp.envDomain} (header-from is @${domain})`
      });
    }
  }
}

/**
 * Generate context for third-party senders
 */
function generateThirdPartySenderContext(
  records: ProcessedRecord[],
  sourceIpAnalysis?: SourceIpAnalysis
): string {
  if (sourceIpAnalysis && sourceIpAnalysis.identifiedServices.length > 0) {
    const svcList = sourceIpAnalysis.identifiedServices
      .map(s => `${s.name} (${s.messageCount} msgs)`)
      .join(', ');
    return `Third-party services detected: ${svcList}. These services send email on your behalf and need SPF authorization and/or DKIM signing to pass DMARC.`;
  }

  const thirdParties = new Set<string>();
  for (const record of records) {
    if (record.identifiers.envelopeFrom) {
      const envDomain = extractDomain(record.identifiers.envelopeFrom);
      const headerDomain = extractDomain(record.identifiers.headerFrom);
      if (envDomain && headerDomain && envDomain !== headerDomain) {
        thirdParties.add(envDomain);
      }
    }
  }

  const list = Array.from(thirdParties).slice(0, 3).join(', ');
  return `Third-party services (${list || 'various'}) are sending email on your behalf. Run "Refresh Reports" to identify specific services and get SPF recommendations.`;
}

// Helper function

function extractDomain(value: string): string | null {
  if (!value) return null;
  if (value.includes('@')) {
    return value.split('@')[1]?.toLowerCase() || null;
  }
  return value.toLowerCase();
}

/**
 * Build record-centric analysis with unified proposals per record type
 */
export function buildRecordAnalysis(
  issues: Issue[],
  dns: StoredDnsData | undefined,
  records: ProcessedRecord[],
  policy: PolicyPublished,
  domain: string,
  sourceIpAnalysis?: SourceIpAnalysis
): RecordAnalysis {
  return {
    spf: buildSpfAnalysis(issues, dns, records, domain, sourceIpAnalysis),
    dkim: buildDkimAnalysis(issues, dns, records, domain, sourceIpAnalysis),
    dmarc: buildDmarcAnalysis(issues, dns, domain)
  };
}

/**
 * Issue codes that relate to SPF
 */
const SPF_ISSUE_CODES: IssueCode[] = ['SPF_SOFTFAIL', 'SPF_FAIL', 'SPF_PERMERROR', 'SPF_TEMPERROR', 'THIRD_PARTY_SENDER'];

/**
 * Issue codes that relate to DKIM
 */
const DKIM_ISSUE_CODES: IssueCode[] = ['DKIM_ALIGNMENT_FAIL', 'DKIM_FAIL'];

/**
 * Issue codes that relate to DMARC
 */
const DMARC_ISSUE_CODES: IssueCode[] = ['POLICY_NONE'];

/**
 * Check if an SPF-related issue appears resolved based on current DNS
 */
function checkSpfIssueResolution(
  issue: Issue,
  dns: StoredDnsData | undefined,
  sourceIpAnalysis?: SourceIpAnalysis
): { resolved: boolean; status: string } {
  if (!dns?.spf) {
    return { resolved: false, status: 'No SPF record found in DNS' };
  }

  switch (issue.code) {
    case 'SPF_SOFTFAIL':
    case 'SPF_FAIL': {
      // Check if all identified services are now in SPF
      if (sourceIpAnalysis && sourceIpAnalysis.identifiedServices.length > 0) {
        const missingServices = sourceIpAnalysis.identifiedServices.filter(svc => {
          return !dns.spf!.includes.some(inc =>
            inc.toLowerCase().includes(svc.spfInclude.toLowerCase()) ||
            svc.spfInclude.toLowerCase().includes(inc.toLowerCase())
          );
        });

        if (missingServices.length === 0) {
          return {
            resolved: true,
            status: 'All identified services are now in SPF record'
          };
        } else {
          const names = missingServices.map(s => s.name).join(', ');
          return {
            resolved: false,
            status: `Still missing: ${names}`
          };
        }
      }
      return { resolved: false, status: 'Unable to verify - no service identification data' };
    }

    case 'SPF_PERMERROR': {
      if (dns.spf.lookupCount <= 10 && !dns.spf.hasError) {
        return {
          resolved: true,
          status: `SPF now has ${dns.spf.lookupCount} lookups (≤10 limit)`
        };
      }
      if (dns.spf.lookupCount > 10) {
        return {
          resolved: false,
          status: `SPF still has ${dns.spf.lookupCount} lookups (exceeds 10 limit)`
        };
      }
      if (dns.spf.hasError) {
        return {
          resolved: false,
          status: `SPF still has error: ${dns.spf.errorMessage || 'syntax issue'}`
        };
      }
      return { resolved: false, status: 'SPF configuration issue persists' };
    }

    case 'SPF_TEMPERROR': {
      // Temperrors are transient - if we can read SPF now, it's likely resolved
      return {
        resolved: true,
        status: 'SPF record is now accessible (temperrors are transient)'
      };
    }

    case 'THIRD_PARTY_SENDER': {
      // Same check as SPF_SOFTFAIL - are the third-party services in SPF?
      if (sourceIpAnalysis && sourceIpAnalysis.identifiedServices.length > 0) {
        const allInSpf = sourceIpAnalysis.identifiedServices.every(svc =>
          dns.spf!.includes.some(inc =>
            inc.toLowerCase().includes(svc.spfInclude.toLowerCase()) ||
            svc.spfInclude.toLowerCase().includes(inc.toLowerCase())
          )
        );

        if (allInSpf) {
          return {
            resolved: true,
            status: 'All identified third-party senders are in SPF'
          };
        }
      }
      return { resolved: false, status: 'Third-party senders may still need SPF authorization' };
    }

    default:
      return { resolved: false, status: 'Unable to determine resolution status' };
  }
}

/**
 * Check if a DKIM-related issue appears resolved based on current DNS
 */
function checkDkimIssueResolution(
  issue: Issue,
  dns: StoredDnsData | undefined,
  records: ProcessedRecord[]
): { resolved: boolean; status: string } {
  if (!dns) {
    return { resolved: false, status: 'No DNS data available' };
  }

  switch (issue.code) {
    case 'DKIM_ALIGNMENT_FAIL': {
      // Check if there's now a DKIM record for the domain (not gappssmtp)
      // Look for 'google' selector which indicates custom DKIM is set up
      const hasGoogleDkim = dns.dkim.some(d => d.selector === 'google' && d.found);

      // Check if emails are still using gappssmtp
      const gappssmtpUsed = records.some(r =>
        r.authResults.dkim.some(d => d.domain.includes('gappssmtp.com'))
      );

      if (hasGoogleDkim) {
        return {
          resolved: true,
          status: 'Google DKIM key found in DNS - enable in Admin Console to complete'
        };
      }

      // Check for any custom DKIM selector
      const hasCustomDkim = dns.dkim.some(d => d.found && !d.selector.includes('default'));
      if (hasCustomDkim) {
        return {
          resolved: true,
          status: 'Custom DKIM selector found in DNS'
        };
      }

      return {
        resolved: false,
        status: 'No custom DKIM key found - emails still signing with provider default'
      };
    }

    case 'DKIM_FAIL': {
      // Check if the failing selectors now have DNS records
      const failingSelectors = new Set<string>();
      for (const record of records) {
        for (const dkim of record.authResults.dkim) {
          if (dkim.result === 'fail' && dkim.selector) {
            failingSelectors.add(dkim.selector);
          }
        }
      }

      const nowFound = Array.from(failingSelectors).filter(sel =>
        dns.dkim.some(d => d.selector === sel && d.found)
      );

      if (nowFound.length === failingSelectors.size && failingSelectors.size > 0) {
        return {
          resolved: true,
          status: `DKIM key(s) now in DNS: ${nowFound.join(', ')}`
        };
      }

      const stillMissing = Array.from(failingSelectors).filter(sel =>
        !dns.dkim.some(d => d.selector === sel && d.found)
      );

      if (stillMissing.length > 0) {
        return {
          resolved: false,
          status: `DKIM key(s) still missing: ${stillMissing.join(', ')}`
        };
      }

      return { resolved: false, status: 'DKIM verification issues persist' };
    }

    default:
      return { resolved: false, status: 'Unable to determine resolution status' };
  }
}

/**
 * Check if a DMARC-related issue appears resolved based on current DNS
 */
function checkDmarcIssueResolution(
  issue: Issue,
  dns: StoredDnsData | undefined
): { resolved: boolean; status: string } {
  if (!dns?.dmarc) {
    return { resolved: false, status: 'No DMARC record found in DNS' };
  }

  switch (issue.code) {
    case 'POLICY_NONE': {
      if (dns.dmarc.policy === 'quarantine') {
        const pct = dns.dmarc.percentage ?? 100;
        return {
          resolved: true,
          status: `Policy upgraded to quarantine (${pct}% enforcement)`
        };
      }
      if (dns.dmarc.policy === 'reject') {
        return {
          resolved: true,
          status: 'Policy upgraded to reject (full protection)'
        };
      }
      return {
        resolved: false,
        status: 'Policy still set to "none" (monitoring only)'
      };
    }

    default:
      return { resolved: false, status: 'Unable to determine resolution status' };
  }
}

/**
 * Convert Issue to IssueReference with resolution status
 */
function toIssueReferenceWithResolution(
  issue: Issue,
  dns: StoredDnsData | undefined,
  records: ProcessedRecord[],
  sourceIpAnalysis?: SourceIpAnalysis
): IssueReference {
  let resolution: { resolved: boolean; status: string };

  // Determine resolution based on issue type
  if (['SPF_SOFTFAIL', 'SPF_FAIL', 'SPF_PERMERROR', 'SPF_TEMPERROR', 'THIRD_PARTY_SENDER'].includes(issue.code)) {
    resolution = checkSpfIssueResolution(issue, dns, sourceIpAnalysis);
  } else if (['DKIM_ALIGNMENT_FAIL', 'DKIM_FAIL'].includes(issue.code)) {
    resolution = checkDkimIssueResolution(issue, dns, records);
  } else if (['POLICY_NONE'].includes(issue.code)) {
    resolution = checkDmarcIssueResolution(issue, dns);
  } else {
    resolution = { resolved: false, status: 'Unknown issue type' };
  }

  return {
    code: issue.code,
    title: issue.title,
    explanation: issue.explanation,
    affectedRecords: issue.affectedRecords,
    sampleSourceIps: issue.sampleSourceIps,
    resolvedByDns: resolution.resolved,
    resolutionStatus: resolution.status
  };
}

/**
 * Build unified SPF analysis
 */
function buildSpfAnalysis(
  issues: Issue[],
  dns: StoredDnsData | undefined,
  records: ProcessedRecord[],
  domain: string,
  sourceIpAnalysis?: SourceIpAnalysis
): SpfAnalysis {
  const spfIssues = issues.filter(i => SPF_ISSUE_CODES.includes(i.code));

  // Build identified senders list
  const identifiedSenders: SpfAnalysis['identifiedSenders'] = [];
  if (sourceIpAnalysis) {
    for (const svc of sourceIpAnalysis.identifiedServices) {
      const inCurrentSpf = dns?.spf?.includes.some(inc =>
        inc.toLowerCase().includes(svc.spfInclude.toLowerCase()) ||
        svc.spfInclude.toLowerCase().includes(inc.toLowerCase())
      ) ?? false;

      identifiedSenders.push({
        name: svc.name,
        spfInclude: svc.spfInclude,
        messageCount: svc.messageCount,
        inCurrentSpf
      });
    }
  }

  // Get unidentified IPs
  const unidentifiedIps = sourceIpAnalysis?.unidentifiedIps.slice(0, 10) || [];

  // Build ONE unified proposed SPF record
  let proposed: SpfAnalysis['proposed'] = null;

  if (spfIssues.length > 0 || identifiedSenders.some(s => !s.inCurrentSpf)) {
    const changes: string[] = [];

    // Find services missing from SPF
    const missingServices = identifiedSenders.filter(s => !s.inCurrentSpf);

    if (missingServices.length > 0) {
      for (const svc of missingServices) {
        changes.push(`Add include:${svc.spfInclude} (${svc.name})`);
      }
    }

    // Check for lookup limit issue
    const hasLookupIssue = spfIssues.some(i => i.code === 'SPF_PERMERROR') &&
      dns?.spf && dns.spf.lookupCount > 10;

    if (hasLookupIssue) {
      changes.push(`Reduce DNS lookups (currently ${dns!.spf!.lookupCount}, max 10)`);
    }

    // Build the complete proposed record
    if (dns?.spf || missingServices.length > 0) {
      const servicesToAdd = sourceIpAnalysis?.identifiedServices.filter(svc =>
        !dns?.spf?.includes.some(inc =>
          inc.toLowerCase().includes(svc.spfInclude.toLowerCase()) ||
          svc.spfInclude.toLowerCase().includes(inc.toLowerCase())
        )
      ) || [];

      const completeSpf = buildCompleteSpfRecord(
        dns?.spf || null,
        servicesToAdd,
        [],
        []
      );

      // Only propose if there are actual changes
      if (completeSpf !== dns?.spf?.raw) {
        proposed = {
          record: completeSpf,
          changes,
          priority: missingServices.length > 0 ? 'high' : 'medium'
        };
      }
    } else if (!dns?.spf) {
      // No SPF record exists - create a basic one
      const includes = identifiedSenders.map(s => `include:${s.spfInclude}`).join(' ');
      proposed = {
        record: `v=spf1 ${includes || 'include:_spf.google.com'} ~all`,
        changes: ['Create SPF record'],
        priority: 'high'
      };
    }
  }

  return {
    current: dns?.spf || null,
    issues: spfIssues.map(issue => toIssueReferenceWithResolution(issue, dns, records, sourceIpAnalysis)),
    identifiedSenders,
    unidentifiedIps,
    proposed
  };
}

/**
 * Build unified DKIM analysis
 */
function buildDkimAnalysis(
  issues: Issue[],
  dns: StoredDnsData | undefined,
  records: ProcessedRecord[],
  domain: string,
  sourceIpAnalysis?: SourceIpAnalysis
): DkimAnalysis {
  const dkimIssues = issues.filter(i => DKIM_ISSUE_CODES.includes(i.code));
  const proposed: DkimAnalysis['proposed'] = [];

  // Find signing domains and selectors from records
  const signingInfo = new Map<string, { domain: string; selector: string; count: number; result: string }>();
  for (const record of records) {
    for (const dkim of record.authResults.dkim) {
      if (dkim.selector) {
        const key = `${dkim.domain}:${dkim.selector}`;
        const existing = signingInfo.get(key) || {
          domain: dkim.domain,
          selector: dkim.selector,
          count: 0,
          result: dkim.result
        };
        existing.count += record.count;
        // Keep track of failures
        if (dkim.result === 'fail') {
          existing.result = 'fail';
        }
        signingInfo.set(key, existing);
      }
    }
  }

  // Check for DKIM alignment issues (using gappssmtp.com)
  const gappssmtpSigners = Array.from(signingInfo.values()).filter(s =>
    s.domain.includes('gappssmtp.com') && s.result === 'pass'
  );

  if (gappssmtpSigners.length > 0) {
    const hasGoogleDkim = dns?.dkim.some(d => d.selector === 'google' && d.found);

    if (!hasGoogleDkim) {
      proposed.push({
        selector: 'google',
        recordName: `google._domainkey.${domain}`,
        record: 'v=DKIM1; k=rsa; p=<generate-in-google-admin>',
        explanation: `Generate DKIM key in Google Admin Console > Apps > Google Workspace > Gmail > Authenticate email. ${gappssmtpSigners.reduce((sum, s) => sum + s.count, 0)} messages are using default gappssmtp.com signing.`,
        priority: 'high'
      });
    } else {
      proposed.push({
        selector: 'google',
        recordName: `google._domainkey.${domain}`,
        record: '(Enable in Google Admin Console)',
        explanation: 'DKIM key exists in DNS but Google Workspace is not using it. Go to Google Admin > Gmail > Authenticate email and click "Start authentication".',
        priority: 'high'
      });
    }
  }

  // Check for failing selectors that need DNS records
  const failingSelectors = Array.from(signingInfo.values()).filter(s => s.result === 'fail');
  for (const failing of failingSelectors) {
    // Skip if already addressed by Google DKIM above
    if (failing.domain.includes('gappssmtp.com')) continue;

    const existsInDns = dns?.dkim.some(d => d.selector === failing.selector && d.found);

    if (!existsInDns) {
      proposed.push({
        selector: failing.selector,
        recordName: `${failing.selector}._domainkey.${failing.domain}`,
        record: 'v=DKIM1; k=rsa; p=<public-key-from-provider>',
        explanation: `Selector "${failing.selector}" signed ${failing.count} messages but no DNS record exists.`,
        priority: 'high'
      });
    }
  }

  return {
    current: dns?.dkim || [],
    issues: dkimIssues.map(issue => toIssueReferenceWithResolution(issue, dns, records, sourceIpAnalysis)),
    proposed
  };
}

/**
 * Build unified DMARC analysis
 */
function buildDmarcAnalysis(
  issues: Issue[],
  dns: StoredDnsData | undefined,
  domain: string
): DmarcAnalysis {
  const dmarcIssues = issues.filter(i => DMARC_ISSUE_CODES.includes(i.code));
  let proposed: DmarcAnalysis['proposed'] = null;

  if (!dns?.dmarc) {
    // No DMARC record - suggest creating one
    proposed = {
      record: `v=DMARC1; p=none; rua=mailto:dmarc@${domain}; adkim=r; aspf=r`,
      changes: ['Create DMARC record with p=none to start monitoring'],
      priority: 'high'
    };
  } else if (dns.dmarc.policy === 'none') {
    // Policy is none - suggest progression
    const currentRua = dns.dmarc.rua?.join(';') || `mailto:dmarc@${domain}`;

    proposed = {
      record: `v=DMARC1; p=quarantine; pct=25; rua=${currentRua}; adkim=r; aspf=r`,
      changes: [
        'Change policy from p=none to p=quarantine',
        'Set pct=25 to start with 25% enforcement',
        'Gradually increase: pct=50 → pct=100 → p=reject'
      ],
      priority: 'medium'
    };
  } else if (dns.dmarc.policy === 'quarantine' && (dns.dmarc.percentage || 100) < 100) {
    // Quarantine but not at 100%
    const currentRua = dns.dmarc.rua?.join(';') || `mailto:dmarc@${domain}`;
    const currentPct = dns.dmarc.percentage || 100;
    const nextPct = currentPct < 50 ? 50 : 100;

    proposed = {
      record: `v=DMARC1; p=quarantine; pct=${nextPct}; rua=${currentRua}; adkim=r; aspf=r`,
      changes: [`Increase pct from ${currentPct}% to ${nextPct}%`],
      priority: 'low'
    };
  } else if (dns.dmarc.policy === 'quarantine') {
    // Full quarantine - suggest reject
    const currentRua = dns.dmarc.rua?.join(';') || `mailto:dmarc@${domain}`;

    proposed = {
      record: `v=DMARC1; p=reject; rua=${currentRua}; adkim=r; aspf=r`,
      changes: ['Upgrade from p=quarantine to p=reject for full protection'],
      priority: 'low'
    };
  }
  // If already at p=reject, no changes needed

  return {
    current: dns?.dmarc || null,
    issues: dmarcIssues.map(issue => toIssueReferenceWithResolution(issue, dns, [], undefined)),
    proposed
  };
}
