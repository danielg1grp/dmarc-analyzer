import express, { Request, Response } from 'express';
import * as path from 'path';
import { getAllData, refreshData, getDomainData, refreshDnsForDomain } from './storage';
import { analyzeDomain, detectIssues, calculateStats, calculateTrends } from './analyzer';
import { ApiResponse, DomainAnalysis, RefreshResult, DomainAnalysisWithDns, StoredDnsData } from './types';
import { fetchDnsRecords, extractSelectorsFromRecords, DnsRecords } from './dns-lookup';
import { enrichIssues, buildRecordAnalysis } from './enricher';

const app = express();
const PORT = 8080;

// Resolve paths
const BASE_DIR = path.resolve(__dirname, '..');
const REPORTS_DIR = path.join(BASE_DIR, 'dmarc-reports');
const PUBLIC_DIR = path.join(BASE_DIR, 'public');

// Middleware
app.use(express.json());
app.use(express.static(PUBLIC_DIR));

/**
 * GET /api/data
 * Returns all processed DMARC data with analysis and enriched issues
 */
app.get('/api/data', (req: Request, res: Response) => {
  try {
    const storedData = getAllData(BASE_DIR);

    // Build analysis for each domain with enriched issues
    const analyses: DomainAnalysisWithDns[] = [];
    for (const [domain, domainData] of Object.entries(storedData.domains)) {
      // Get base analysis
      const stats = calculateStats(domainData.records);
      const baseIssues = detectIssues(domainData.records, domainData.policy);
      const trends = calculateTrends(domainData.reports);

      // Enrich issues with DNS context and service analysis
      const enrichedIssues = enrichIssues(
        baseIssues,
        domainData.dns,
        domainData.records,
        domainData.policy,
        domain,
        domainData.sourceIpAnalysis
      );

      // Build record-centric analysis with unified proposals
      const recordAnalysis = buildRecordAnalysis(
        baseIssues,
        domainData.dns,
        domainData.records,
        domainData.policy,
        domain,
        domainData.sourceIpAnalysis
      );

      const analysis: DomainAnalysisWithDns = {
        domain,
        policy: domainData.policy,
        totalMessages: stats.total,
        passCount: stats.pass,
        failCount: stats.fail,
        passRate: stats.total > 0 ? Math.round((stats.pass / stats.total) * 100) : 0,
        issues: enrichedIssues,
        trends,
        records: domainData.records,
        dns: domainData.dns,
        recordAnalysis
      };

      analyses.push(analysis);
    }

    const response: ApiResponse<{
      lastUpdated: string;
      processedFiles: string[];
      domains: DomainAnalysisWithDns[];
    }> = {
      success: true,
      data: {
        lastUpdated: storedData.lastUpdated,
        processedFiles: storedData.processedFiles,
        domains: analyses
      }
    };

    res.json(response);
  } catch (error) {
    console.error('Error getting data:', error);
    res.status(500).json({
      success: false,
      error: 'Failed to retrieve data'
    } as ApiResponse<never>);
  }
});

/**
 * POST /api/refresh
 * Process new report files and return results
 */
app.post('/api/refresh', async (req: Request, res: Response) => {
  try {
    const result = await refreshData(BASE_DIR, REPORTS_DIR);

    const response: ApiResponse<RefreshResult> = {
      success: true,
      data: result
    };

    res.json(response);
  } catch (error) {
    console.error('Error refreshing data:', error);
    res.status(500).json({
      success: false,
      error: 'Failed to refresh data'
    } as ApiResponse<never>);
  }
});

/**
 * GET /api/domain/:domain
 * Get analysis for a specific domain with enriched issues
 */
app.get('/api/domain/:domain', (req: Request, res: Response) => {
  try {
    const { domain } = req.params;
    const domainData = getDomainData(BASE_DIR, domain);

    if (!domainData) {
      res.status(404).json({
        success: false,
        error: `Domain not found: ${domain}`
      } as ApiResponse<never>);
      return;
    }

    // Get base analysis
    const stats = calculateStats(domainData.records);
    const baseIssues = detectIssues(domainData.records, domainData.policy);
    const trends = calculateTrends(domainData.reports);

    // Enrich issues with DNS context and service analysis
    const enrichedIssues = enrichIssues(
      baseIssues,
      domainData.dns,
      domainData.records,
      domainData.policy,
      domain,
      domainData.sourceIpAnalysis
    );

    // Build record-centric analysis with unified proposals
    const recordAnalysis = buildRecordAnalysis(
      baseIssues,
      domainData.dns,
      domainData.records,
      domainData.policy,
      domain,
      domainData.sourceIpAnalysis
    );

    const analysis: DomainAnalysisWithDns = {
      domain,
      policy: domainData.policy,
      totalMessages: stats.total,
      passCount: stats.pass,
      failCount: stats.fail,
      passRate: stats.total > 0 ? Math.round((stats.pass / stats.total) * 100) : 0,
      issues: enrichedIssues,
      trends,
      records: domainData.records,
      dns: domainData.dns,
      recordAnalysis
    };

    const response: ApiResponse<DomainAnalysisWithDns> = {
      success: true,
      data: analysis
    };

    res.json(response);
  } catch (error) {
    console.error('Error getting domain data:', error);
    res.status(500).json({
      success: false,
      error: 'Failed to retrieve domain data'
    } as ApiResponse<never>);
  }
});

/**
 * GET /api/dns/:domain
 * Get DNS records for a domain (from cache or force refresh)
 * Query param: ?refresh=true to force refresh
 */
app.get('/api/dns/:domain', async (req: Request, res: Response) => {
  try {
    const { domain } = req.params;
    const forceRefresh = req.query.refresh === 'true';

    const domainData = getDomainData(BASE_DIR, domain);

    // If domain exists and we have cached DNS and not forcing refresh, return cached
    if (domainData?.dns && !forceRefresh) {
      const response: ApiResponse<StoredDnsData> = {
        success: true,
        data: domainData.dns
      };
      res.json(response);
      return;
    }

    // Otherwise fetch fresh DNS
    if (domainData) {
      // Use refreshDnsForDomain to fetch and store
      const freshDns = await refreshDnsForDomain(BASE_DIR, domain);
      if (freshDns) {
        const response: ApiResponse<StoredDnsData> = {
          success: true,
          data: freshDns
        };
        res.json(response);
        return;
      }
    }

    // Domain not in storage, just fetch DNS without storing
    const additionalSelectors = domainData
      ? extractSelectorsFromRecords(domainData.records)
      : [];
    const dnsRecords = await fetchDnsRecords(domain, additionalSelectors);

    const response: ApiResponse<DnsRecords> = {
      success: true,
      data: dnsRecords
    };

    res.json(response);
  } catch (error) {
    console.error('Error fetching DNS records:', error);
    res.status(500).json({
      success: false,
      error: 'Failed to fetch DNS records'
    } as ApiResponse<never>);
  }
});

/**
 * POST /api/dns/:domain/refresh
 * Force refresh DNS records for a domain
 */
app.post('/api/dns/:domain/refresh', async (req: Request, res: Response) => {
  try {
    const { domain } = req.params;

    const freshDns = await refreshDnsForDomain(BASE_DIR, domain);

    if (!freshDns) {
      res.status(404).json({
        success: false,
        error: `Domain not found: ${domain}`
      } as ApiResponse<never>);
      return;
    }

    const response: ApiResponse<StoredDnsData> = {
      success: true,
      data: freshDns
    };

    res.json(response);
  } catch (error) {
    console.error('Error refreshing DNS records:', error);
    res.status(500).json({
      success: false,
      error: 'Failed to refresh DNS records'
    } as ApiResponse<never>);
  }
});

/**
 * Serve the main page for any other route
 */
app.get('*', (req: Request, res: Response) => {
  res.sendFile(path.join(PUBLIC_DIR, 'index.html'));
});

// Start server
app.listen(PORT, () => {
  console.log(`DMARC Analyzer running at http://localhost:${PORT}`);
  console.log(`Reports directory: ${REPORTS_DIR}`);
  console.log(`Data file: ${path.join(BASE_DIR, 'dmarc-data.json')}`);
});
