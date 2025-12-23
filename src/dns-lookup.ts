import * as dns from 'dns';
import { promisify } from 'util';

const resolveTxt = promisify(dns.resolveTxt);
const reversePromise = promisify(dns.reverse);

export interface DnsRecords {
  domain: string;
  spf: SpfRecord | null;
  dmarc: DmarcRecord | null;
  dkim: DkimRecord[];
  fetchedAt: string;
  errors: string[];
}

export interface SpfRecord {
  raw: string;
  version: string;
  mechanisms: string[];
  includes: string[];
  ipv4: string[];
  ipv6: string[];
  all: string;  // +all, -all, ~all, ?all
  lookupCount: number;
  hasError: boolean;
  errorMessage?: string;
}

export interface DmarcRecord {
  raw: string;
  version: string;
  policy: string;           // p= (none, quarantine, reject)
  subdomainPolicy?: string; // sp=
  percentage?: number;      // pct=
  rua?: string[];          // aggregate report URIs
  ruf?: string[];          // forensic report URIs
  adkim?: string;          // DKIM alignment (r=relaxed, s=strict)
  aspf?: string;           // SPF alignment
  fo?: string;             // failure reporting options
}

export interface DkimRecord {
  selector: string;
  raw: string;
  version?: string;
  keyType?: string;    // k=
  publicKey?: string;  // p= (truncated for display)
  flags?: string;      // t=
  found: boolean;
  error?: string;
}

// Common DKIM selectors to check
const COMMON_SELECTORS = [
  'default',
  'google',
  'selector1',  // Microsoft
  'selector2',  // Microsoft
  's1',
  's2',
  'k1',
  'mail',
  'dkim',
  '20230601',   // Google Workspace date-based
  '20220101',
  '20210101',
];

/**
 * Fetch all DNS records for a domain
 */
export async function fetchDnsRecords(domain: string, additionalSelectors: string[] = []): Promise<DnsRecords> {
  const errors: string[] = [];
  const selectors = [...new Set([...COMMON_SELECTORS, ...additionalSelectors])];

  // Fetch all records in parallel
  const [spf, dmarc, dkimResults] = await Promise.all([
    fetchSpfRecord(domain).catch(err => {
      errors.push(`SPF: ${err.message}`);
      return null;
    }),
    fetchDmarcRecord(domain).catch(err => {
      errors.push(`DMARC: ${err.message}`);
      return null;
    }),
    Promise.all(selectors.map(sel => fetchDkimRecord(domain, sel)))
  ]);

  // Filter to only found DKIM records
  const dkim = dkimResults.filter(d => d.found);

  return {
    domain,
    spf,
    dmarc,
    dkim,
    fetchedAt: new Date().toISOString(),
    errors
  };
}

/**
 * Fetch and parse SPF record
 */
async function fetchSpfRecord(domain: string): Promise<SpfRecord | null> {
  try {
    const records = await withTimeout(resolveTxt(domain), 5000, [] as string[][]);
    const spfRecords = records
      .map(r => r.join(''))
      .filter(r => r.toLowerCase().startsWith('v=spf1'));

    if (spfRecords.length === 0) {
      return null;
    }

    if (spfRecords.length > 1) {
      return {
        raw: spfRecords[0],
        version: 'spf1',
        mechanisms: [],
        includes: [],
        ipv4: [],
        ipv6: [],
        all: 'unknown',
        lookupCount: 0,
        hasError: true,
        errorMessage: 'Multiple SPF records found - this causes SPF to fail'
      };
    }

    const raw = spfRecords[0];
    return parseSpfRecord(raw);
  } catch (err: any) {
    if (err.code === 'ENODATA' || err.code === 'ENOTFOUND') {
      return null;
    }
    throw err;
  }
}

/**
 * Parse SPF record into structured data
 */
function parseSpfRecord(raw: string): SpfRecord {
  const parts = raw.split(/\s+/);
  const includes: string[] = [];
  const ipv4: string[] = [];
  const ipv6: string[] = [];
  const mechanisms: string[] = [];
  let all = 'unknown';
  let lookupCount = 0;

  for (const part of parts) {
    // Remove SPF qualifier prefix (+, -, ~, ?) if present
    const cleanPart = part.replace(/^[+\-~?]/, '');
    const lower = cleanPart.toLowerCase();

    if (lower.startsWith('include:')) {
      includes.push(cleanPart.substring(8));
      lookupCount++;
    } else if (lower.startsWith('ip4:')) {
      ipv4.push(cleanPart.substring(4));
    } else if (lower.startsWith('ip6:')) {
      ipv6.push(cleanPart.substring(4));
    } else if (lower.startsWith('a:') || lower === 'a') {
      mechanisms.push(cleanPart);
      lookupCount++;
    } else if (lower.startsWith('mx:') || lower === 'mx') {
      mechanisms.push(cleanPart);
      lookupCount++;
    } else if (lower.startsWith('ptr:') || lower === 'ptr') {
      mechanisms.push(part);
      lookupCount++;
    } else if (lower.startsWith('exists:')) {
      mechanisms.push(part);
      lookupCount++;
    } else if (lower.startsWith('redirect=')) {
      mechanisms.push(part);
      lookupCount++;
    } else if (lower.endsWith('all')) {
      all = part;
    }
  }

  return {
    raw,
    version: 'spf1',
    mechanisms,
    includes,
    ipv4,
    ipv6,
    all,
    lookupCount,
    hasError: lookupCount > 10,
    errorMessage: lookupCount > 10 ? `Too many DNS lookups (${lookupCount}/10 max)` : undefined
  };
}

/**
 * Fetch and parse DMARC record
 */
async function fetchDmarcRecord(domain: string): Promise<DmarcRecord | null> {
  try {
    const records = await withTimeout(resolveTxt(`_dmarc.${domain}`), 5000, [] as string[][]);
    const dmarcRecords = records
      .map(r => r.join(''))
      .filter(r => r.toLowerCase().startsWith('v=dmarc1'));

    if (dmarcRecords.length === 0) {
      return null;
    }

    const raw = dmarcRecords[0];
    return parseDmarcRecord(raw);
  } catch (err: any) {
    if (err.code === 'ENODATA' || err.code === 'ENOTFOUND') {
      return null;
    }
    throw err;
  }
}

/**
 * Parse DMARC record into structured data
 */
function parseDmarcRecord(raw: string): DmarcRecord {
  const record: DmarcRecord = {
    raw,
    version: 'DMARC1',
    policy: 'none'
  };

  const parts = raw.split(/;\s*/);

  for (const part of parts) {
    const [key, ...valueParts] = part.split('=');
    const value = valueParts.join('=');

    switch (key.toLowerCase().trim()) {
      case 'p':
        record.policy = value.toLowerCase();
        break;
      case 'sp':
        record.subdomainPolicy = value.toLowerCase();
        break;
      case 'pct':
        record.percentage = parseInt(value, 10);
        break;
      case 'rua':
        record.rua = value.split(',').map(v => v.trim());
        break;
      case 'ruf':
        record.ruf = value.split(',').map(v => v.trim());
        break;
      case 'adkim':
        record.adkim = value.toLowerCase();
        break;
      case 'aspf':
        record.aspf = value.toLowerCase();
        break;
      case 'fo':
        record.fo = value;
        break;
    }
  }

  return record;
}

/**
 * Fetch DKIM record for a specific selector
 */
async function fetchDkimRecord(domain: string, selector: string): Promise<DkimRecord> {
  const dkimDomain = `${selector}._domainkey.${domain}`;

  try {
    const records = await withTimeout(resolveTxt(dkimDomain), 3000, [] as string[][]);
    const raw = records.map(r => r.join('')).join('');

    if (!raw) {
      return { selector, raw: '', found: false };
    }

    return parseDkimRecord(selector, raw);
  } catch (err: any) {
    if (err.code === 'ENODATA' || err.code === 'ENOTFOUND') {
      return { selector, raw: '', found: false };
    }
    return {
      selector,
      raw: '',
      found: false,
      error: err.message
    };
  }
}

/**
 * Parse DKIM record into structured data
 */
function parseDkimRecord(selector: string, raw: string): DkimRecord {
  const record: DkimRecord = {
    selector,
    raw,
    found: true
  };

  const parts = raw.split(/;\s*/);

  for (const part of parts) {
    const [key, ...valueParts] = part.split('=');
    const value = valueParts.join('=');

    switch (key.toLowerCase().trim()) {
      case 'v':
        record.version = value;
        break;
      case 'k':
        record.keyType = value;
        break;
      case 'p':
        // Truncate public key for display
        record.publicKey = value.length > 50 ? value.substring(0, 50) + '...' : value;
        break;
      case 't':
        record.flags = value;
        break;
    }
  }

  return record;
}

/**
 * Extract DKIM selectors from DMARC report records
 */
export function extractSelectorsFromRecords(records: Array<{ authResults: { dkim: Array<{ selector?: string }> } }>): string[] {
  const selectors = new Set<string>();

  for (const record of records) {
    for (const dkim of record.authResults.dkim) {
      if (dkim.selector) {
        selectors.add(dkim.selector);
      }
    }
  }

  return Array.from(selectors);
}

/**
 * Known email service identification
 */
export interface IdentifiedService {
  name: string;
  spfInclude: string;
  confidence: 'high' | 'medium' | 'low';
  matchedOn: string;
}

// Known service patterns for reverse DNS and IP identification
const KNOWN_SERVICES: Array<{
  name: string;
  spfInclude: string;
  reverseDnsPatterns: RegExp[];
  ipPrefixes?: string[];
}> = [
  {
    name: 'Google Workspace / Gmail',
    spfInclude: '_spf.google.com',
    reverseDnsPatterns: [/\.google\.com$/i, /\.googlemail\.com$/i, /\.gappssmtp\.com$/i, /mail-\w+\.google\.com$/i],
    ipPrefixes: ['209.85.', '74.125.', '172.217.', '142.250.', '2607:f8b0:']
  },
  {
    name: 'Microsoft 365 / Outlook',
    spfInclude: 'spf.protection.outlook.com',
    reverseDnsPatterns: [/\.outlook\.com$/i, /\.microsoft\.com$/i, /\.protection\.outlook\.com$/i, /mail-\w+\.microsoft\.com$/i],
    ipPrefixes: ['40.92.', '40.93.', '40.94.', '40.95.', '52.96.', '52.97.', '104.47.']
  },
  {
    name: 'Amazon SES',
    spfInclude: 'amazonses.com',
    reverseDnsPatterns: [/\.amazonses\.com$/i, /\.amazon\.com$/i, /\.aws\.com$/i],
    ipPrefixes: ['54.240.', '199.255.192.', '199.127.232.']
  },
  {
    name: 'SendGrid',
    spfInclude: 'sendgrid.net',
    reverseDnsPatterns: [/\.sendgrid\.net$/i, /\.sendgrid\.com$/i],
    ipPrefixes: ['167.89.', '198.21.', '50.31.']
  },
  {
    name: 'Mailchimp',
    spfInclude: 'servers.mcsv.net',
    reverseDnsPatterns: [/\.mcsv\.net$/i, /\.mailchimp\.com$/i, /\.mandrillapp\.com$/i],
    ipPrefixes: ['205.201.128.', '198.2.128.']
  },
  {
    name: 'Mailgun',
    spfInclude: 'mailgun.org',
    reverseDnsPatterns: [/\.mailgun\.org$/i, /\.mailgun\.com$/i],
    ipPrefixes: ['198.61.254.', '50.56.21.']
  },
  {
    name: 'Zendesk',
    spfInclude: 'mail.zendesk.com',
    reverseDnsPatterns: [/\.zendesk\.com$/i],
  },
  {
    name: 'HubSpot',
    spfInclude: 'spf.hubspot.com',
    reverseDnsPatterns: [/\.hubspot\.com$/i, /\.hubspotemail\.net$/i],
  },
  {
    name: 'Salesforce',
    spfInclude: '_spf.salesforce.com',
    reverseDnsPatterns: [/\.salesforce\.com$/i, /\.exacttarget\.com$/i],
  },
  {
    name: 'Freshdesk',
    spfInclude: 'email.freshdesk.com',
    reverseDnsPatterns: [/\.freshdesk\.com$/i, /\.freshworks\.com$/i],
  },
  {
    name: 'Postmark',
    spfInclude: 'spf.mtasv.net',
    reverseDnsPatterns: [/\.mtasv\.net$/i, /\.postmarkapp\.com$/i],
  },
  {
    name: 'SparkPost',
    spfInclude: 'sparkpostmail.com',
    reverseDnsPatterns: [/\.sparkpostmail\.com$/i, /\.sparkpost\.com$/i],
  },
  {
    name: 'Constant Contact',
    spfInclude: 'spf.constantcontact.com',
    reverseDnsPatterns: [/\.constantcontact\.com$/i, /\.ccsend\.com$/i],
  },
  {
    name: 'GoDaddy',
    spfInclude: 'secureserver.net',
    reverseDnsPatterns: [/\.secureserver\.net$/i, /\.godaddy\.com$/i],
  },
  {
    name: 'Zoho',
    spfInclude: 'zoho.com',
    reverseDnsPatterns: [/\.zoho\.com$/i, /\.zohomail\.com$/i],
  }
];

/**
 * Create a promise that rejects after a timeout
 */
function withTimeout<T>(promise: Promise<T>, ms: number, fallback: T): Promise<T> {
  return Promise.race([
    promise,
    new Promise<T>((resolve) => setTimeout(() => resolve(fallback), ms))
  ]);
}

/**
 * Perform reverse DNS lookup on an IP address with timeout
 */
export async function reverseDnsLookup(ip: string): Promise<string[]> {
  try {
    const hostnames = await withTimeout(reversePromise(ip), 2000, []);
    return hostnames;
  } catch (err: any) {
    // Common for IPs to not have reverse DNS
    return [];
  }
}

/**
 * Identify email service from IP address using reverse DNS and known patterns
 */
export async function identifyServiceFromIp(ip: string): Promise<IdentifiedService | null> {
  // First check IP prefix patterns (faster, no DNS lookup needed)
  for (const service of KNOWN_SERVICES) {
    if (service.ipPrefixes) {
      for (const prefix of service.ipPrefixes) {
        if (ip.startsWith(prefix)) {
          return {
            name: service.name,
            spfInclude: service.spfInclude,
            confidence: 'high',
            matchedOn: `IP prefix ${prefix}`
          };
        }
      }
    }
  }

  // Try reverse DNS lookup
  const hostnames = await reverseDnsLookup(ip);

  for (const hostname of hostnames) {
    for (const service of KNOWN_SERVICES) {
      for (const pattern of service.reverseDnsPatterns) {
        if (pattern.test(hostname)) {
          return {
            name: service.name,
            spfInclude: service.spfInclude,
            confidence: 'high',
            matchedOn: `Reverse DNS: ${hostname}`
          };
        }
      }
    }
  }

  return null;
}

/**
 * Identify services from multiple IPs (batch operation)
 */
export async function identifyServicesFromIps(ips: string[]): Promise<Map<string, IdentifiedService>> {
  const results = new Map<string, IdentifiedService>();
  const uniqueIps = [...new Set(ips)];

  // Process in parallel with a limit
  const batchSize = 10;
  for (let i = 0; i < uniqueIps.length; i += batchSize) {
    const batch = uniqueIps.slice(i, i + batchSize);
    const promises = batch.map(async (ip) => {
      const service = await identifyServiceFromIp(ip);
      if (service) {
        results.set(ip, service);
      }
    });
    await Promise.all(promises);
  }

  return results;
}

/**
 * Get aggregated service recommendations from identified IPs
 */
export function aggregateServiceRecommendations(
  ipServiceMap: Map<string, IdentifiedService>
): Array<{ service: IdentifiedService; ips: string[]; count: number }> {
  const serviceGroups = new Map<string, { service: IdentifiedService; ips: string[] }>();

  for (const [ip, service] of ipServiceMap) {
    const key = service.spfInclude;
    if (!serviceGroups.has(key)) {
      serviceGroups.set(key, { service, ips: [] });
    }
    serviceGroups.get(key)!.ips.push(ip);
  }

  return Array.from(serviceGroups.values())
    .map(g => ({ ...g, count: g.ips.length }))
    .sort((a, b) => b.count - a.count);
}
