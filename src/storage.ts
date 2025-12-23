import * as fs from 'fs';
import * as path from 'path';
import {
  StoredData,
  DomainData,
  ParsedReport,
  RefreshResult,
  StoredDataWithDns,
  DomainDataWithDns,
  StoredDnsData,
  SourceIpAnalysis,
  IdentifiedServiceInfo,
  ProcessedRecord
} from './types';
import { parseReports } from './parser';
import { generateReportSummary } from './analyzer';
import { fetchDnsRecords, extractSelectorsFromRecords, identifyServicesFromIps, IdentifiedService } from './dns-lookup';

// DNS cache TTL in milliseconds (1 hour)
const DNS_CACHE_TTL = 60 * 60 * 1000;

const DATA_FILE = 'dmarc-data.json';

/**
 * Get the path to the data file
 */
export function getDataFilePath(baseDir: string): string {
  return path.join(baseDir, DATA_FILE);
}

/**
 * Load stored data from JSON file
 */
export function loadData(baseDir: string): StoredDataWithDns {
  const filePath = getDataFilePath(baseDir);

  if (!fs.existsSync(filePath)) {
    return createEmptyData();
  }

  try {
    const content = fs.readFileSync(filePath, 'utf-8');
    return JSON.parse(content) as StoredDataWithDns;
  } catch (error) {
    console.error('Error loading data file:', error);
    return createEmptyData();
  }
}

/**
 * Save data to JSON file
 */
export function saveData(baseDir: string, data: StoredDataWithDns): void {
  const filePath = getDataFilePath(baseDir);
  data.lastUpdated = new Date().toISOString();
  fs.writeFileSync(filePath, JSON.stringify(data, null, 2), 'utf-8');
}

/**
 * Create empty data structure
 */
function createEmptyData(): StoredDataWithDns {
  return {
    processedFiles: [],
    lastUpdated: new Date().toISOString(),
    domains: {}
  };
}

/**
 * Merge new parsed reports into existing stored data
 */
export function mergeReports(existingData: StoredDataWithDns, newReports: ParsedReport[]): StoredDataWithDns {
  const data = { ...existingData };

  for (const report of newReports) {
    const domain = report.policy.domain;

    // Initialize domain if needed
    if (!data.domains[domain]) {
      data.domains[domain] = {
        policy: report.policy,
        records: [],
        reports: []
      };
    }

    const domainData = data.domains[domain];

    // Update policy (use latest)
    domainData.policy = report.policy;

    // Add records
    domainData.records.push(...report.records);

    // Add report summary
    const summary = generateReportSummary(report);
    domainData.reports.push(summary);

    // Track processed file
    if (!data.processedFiles.includes(report.filename)) {
      data.processedFiles.push(report.filename);
    }
  }

  return data;
}

/**
 * Check if DNS data needs refresh (expired TTL or missing)
 */
function isDnsStale(dns: StoredDnsData | undefined): boolean {
  if (!dns) return true;

  const fetchedAt = new Date(dns.fetchedAt).getTime();
  const now = Date.now();

  return (now - fetchedAt) > DNS_CACHE_TTL;
}

/**
 * Fetch DNS records for a domain and convert to storage format
 */
async function fetchDnsForDomain(domain: string, records: Array<{ authResults: { dkim: Array<{ selector?: string }> } }>): Promise<StoredDnsData> {
  const additionalSelectors = extractSelectorsFromRecords(records);
  const dnsRecords = await fetchDnsRecords(domain, additionalSelectors);

  return {
    spf: dnsRecords.spf,
    dmarc: dnsRecords.dmarc,
    dkim: dnsRecords.dkim,
    fetchedAt: dnsRecords.fetchedAt,
    errors: dnsRecords.errors
  };
}

/**
 * Analyze source IPs from records to identify email services
 */
async function analyzeSourceIps(records: ProcessedRecord[]): Promise<SourceIpAnalysis> {
  // Aggregate IPs with their message counts
  const ipCounts = new Map<string, number>();
  for (const record of records) {
    const current = ipCounts.get(record.sourceIp) || 0;
    ipCounts.set(record.sourceIp, current + record.count);
  }

  // Get all unique IPs
  const allIps = Array.from(ipCounts.keys());

  // Identify services for each IP
  const ipServiceMap = await identifyServicesFromIps(allIps);

  // Group by service
  const serviceGroups = new Map<string, { service: IdentifiedService; ips: string[]; messageCount: number }>();
  const unidentifiedIps: Array<{ ip: string; messageCount: number }> = [];

  for (const [ip, count] of ipCounts) {
    const service = ipServiceMap.get(ip);
    if (service) {
      const key = service.spfInclude;
      if (!serviceGroups.has(key)) {
        serviceGroups.set(key, { service, ips: [], messageCount: 0 });
      }
      const group = serviceGroups.get(key)!;
      group.ips.push(ip);
      group.messageCount += count;
    } else {
      unidentifiedIps.push({ ip, messageCount: count });
    }
  }

  // Convert to array and sort by message count
  const identifiedServices: IdentifiedServiceInfo[] = Array.from(serviceGroups.values())
    .map(g => ({
      name: g.service.name,
      spfInclude: g.service.spfInclude,
      confidence: g.service.confidence,
      sourceIps: g.ips,
      messageCount: g.messageCount
    }))
    .sort((a, b) => b.messageCount - a.messageCount);

  // Sort unidentified IPs by message count
  unidentifiedIps.sort((a, b) => b.messageCount - a.messageCount);

  return {
    analyzedAt: new Date().toISOString(),
    identifiedServices,
    unidentifiedIps: unidentifiedIps.slice(0, 20) // Keep top 20 unidentified
  };
}

/**
 * Process new report files and update storage
 */
export async function refreshData(
  baseDir: string,
  reportsDir: string
): Promise<RefreshResult> {
  // Load existing data
  const existingData = loadData(baseDir);

  // Parse new reports
  const { parsed, skipped, newFiles } = await parseReports(reportsDir, existingData.processedFiles);

  // Merge new data
  const updatedData = mergeReports(existingData, parsed);

  // Fetch DNS and analyze source IPs for each domain
  const domains = Object.keys(updatedData.domains);
  console.log(`Processing ${domains.length} domain(s)...`);

  for (const domain of domains) {
    const domainData = updatedData.domains[domain];

    // Fetch DNS if stale or missing
    if (isDnsStale(domainData.dns)) {
      console.log(`Fetching DNS for ${domain}...`);
      try {
        domainData.dns = await fetchDnsForDomain(domain, domainData.records);
        console.log(`  DNS fetched: SPF=${domainData.dns.spf ? 'found' : 'missing'}, DMARC=${domainData.dns.dmarc ? 'found' : 'missing'}, DKIM=${domainData.dns.dkim.length} selectors`);
      } catch (error) {
        console.error(`  Error fetching DNS for ${domain}:`, error);
        domainData.dns = {
          spf: null,
          dmarc: null,
          dkim: [],
          fetchedAt: new Date().toISOString(),
          errors: [`Failed to fetch DNS: ${error}`]
        };
      }
    } else {
      console.log(`DNS for ${domain} is fresh (cached)`);
    }

    // Analyze source IPs if not done or if we have new records
    const needsIpAnalysis = !domainData.sourceIpAnalysis ||
      (newFiles.length > 0 && parsed.some(r => r.policy.domain === domain));

    if (needsIpAnalysis) {
      console.log(`Analyzing source IPs for ${domain}...`);
      try {
        domainData.sourceIpAnalysis = await analyzeSourceIps(domainData.records);
        const serviceCount = domainData.sourceIpAnalysis.identifiedServices.length;
        const unidentifiedCount = domainData.sourceIpAnalysis.unidentifiedIps.length;
        console.log(`  Identified ${serviceCount} service(s), ${unidentifiedCount} unidentified IP(s)`);

        // Log identified services
        for (const svc of domainData.sourceIpAnalysis.identifiedServices) {
          console.log(`    - ${svc.name}: ${svc.messageCount} messages from ${svc.sourceIps.length} IP(s)`);
        }
      } catch (error) {
        console.error(`  Error analyzing IPs for ${domain}:`, error);
      }
    }
  }

  // Save updated data
  saveData(baseDir, updatedData);

  return {
    newFilesProcessed: newFiles,
    skippedFiles: skipped,
    totalDomains: Object.keys(updatedData.domains).length,
    domains: Object.keys(updatedData.domains)
  };
}

/**
 * Force refresh DNS for a specific domain
 */
export async function refreshDnsForDomain(baseDir: string, domain: string): Promise<StoredDnsData | null> {
  const data = loadData(baseDir);
  const domainData = data.domains[domain];

  if (!domainData) {
    return null;
  }

  try {
    domainData.dns = await fetchDnsForDomain(domain, domainData.records);
    saveData(baseDir, data);
    return domainData.dns;
  } catch (error) {
    console.error(`Error refreshing DNS for ${domain}:`, error);
    return null;
  }
}

/**
 * Get data for a specific domain
 */
export function getDomainData(baseDir: string, domain: string): DomainDataWithDns | null {
  const data = loadData(baseDir);
  return data.domains[domain] || null;
}

/**
 * Get all stored data
 */
export function getAllData(baseDir: string): StoredDataWithDns {
  return loadData(baseDir);
}

/**
 * Clear all stored data (for testing/reset)
 */
export function clearData(baseDir: string): void {
  const filePath = getDataFilePath(baseDir);
  if (fs.existsSync(filePath)) {
    fs.unlinkSync(filePath);
  }
}
