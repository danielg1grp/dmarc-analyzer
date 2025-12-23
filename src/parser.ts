import * as fs from 'fs';
import * as path from 'path';
import { parseStringPromise } from 'xml2js';
import {
  DmarcReportXml,
  DmarcRecordXml,
  ParsedReport,
  ProcessedRecord,
  PolicyPublished,
  DkimResult,
  SpfResult,
  ReportMetadata
} from './types';

/**
 * Parse a single DMARC XML file and return normalized data
 */
export async function parseReport(filePath: string): Promise<ParsedReport> {
  const xmlContent = fs.readFileSync(filePath, 'utf-8');
  const parsed = await parseStringPromise(xmlContent) as DmarcReportXml;

  const feedback = parsed.feedback;
  const reportMeta = feedback.report_metadata[0];
  const policyPub = feedback.policy_published[0];

  const metadata: ReportMetadata = {
    orgName: reportMeta.org_name[0],
    email: reportMeta.email[0],
    reportId: reportMeta.report_id[0],
    dateRange: {
      begin: parseInt(reportMeta.date_range[0].begin[0], 10),
      end: parseInt(reportMeta.date_range[0].end[0], 10)
    }
  };

  const policy: PolicyPublished = {
    domain: policyPub.domain[0],
    adkim: policyPub.adkim[0],
    aspf: policyPub.aspf[0],
    p: policyPub.p[0],
    sp: policyPub.sp[0],
    pct: parseInt(policyPub.pct[0], 10)
  };

  const records = (feedback.record || []).map(rec => parseRecord(rec, metadata));

  return {
    filename: path.basename(filePath),
    metadata,
    policy,
    records
  };
}

/**
 * Parse a single record from the DMARC report
 */
function parseRecord(record: DmarcRecordXml, metadata: ReportMetadata): ProcessedRecord {
  const row = record.row[0];
  const identifiers = record.identifiers[0];
  const authResults = record.auth_results[0];

  // Parse DKIM results (can be multiple)
  const dkimResults: DkimResult[] = (authResults.dkim || []).map(dkim => ({
    domain: dkim.domain[0],
    selector: dkim.selector?.[0],
    result: dkim.result[0]
  }));

  // Parse SPF result
  const spfData = authResults.spf[0];
  const spfResult: SpfResult = {
    domain: spfData.domain[0],
    scope: spfData.scope?.[0],
    result: spfData.result[0]
  };

  return {
    reportId: metadata.reportId,
    dateRange: metadata.dateRange,
    sourceIp: row.source_ip[0],
    count: parseInt(row.count[0], 10),
    policyEvaluated: {
      disposition: row.policy_evaluated[0].disposition[0],
      dkim: row.policy_evaluated[0].dkim[0],
      spf: row.policy_evaluated[0].spf[0]
    },
    identifiers: {
      headerFrom: identifiers.header_from[0],
      envelopeFrom: identifiers.envelope_from?.[0],
      envelopeTo: identifiers.envelope_to?.[0]
    },
    authResults: {
      dkim: dkimResults,
      spf: spfResult
    }
  };
}

/**
 * Get all XML files from the reports directory
 */
export function getReportFiles(reportsDir: string): string[] {
  if (!fs.existsSync(reportsDir)) {
    return [];
  }

  return fs.readdirSync(reportsDir)
    .filter(file => file.endsWith('.xml'))
    .map(file => path.join(reportsDir, file));
}

/**
 * Parse multiple report files, optionally skipping already processed ones
 */
export async function parseReports(
  reportsDir: string,
  processedFiles: string[] = []
): Promise<{ parsed: ParsedReport[]; skipped: string[]; newFiles: string[] }> {
  const allFiles = getReportFiles(reportsDir);
  const processedSet = new Set(processedFiles);

  const skipped: string[] = [];
  const newFiles: string[] = [];
  const parsed: ParsedReport[] = [];

  for (const filePath of allFiles) {
    const filename = path.basename(filePath);

    if (processedSet.has(filename)) {
      skipped.push(filename);
      continue;
    }

    try {
      const report = await parseReport(filePath);
      parsed.push(report);
      newFiles.push(filename);
    } catch (error) {
      console.error(`Error parsing ${filename}:`, error);
    }
  }

  return { parsed, skipped, newFiles };
}
