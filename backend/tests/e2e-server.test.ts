import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import http from 'http';
import { bootstrap } from '../src/index';
import { ingestQueue } from '../src/ingest/ingest-queue';
import { pdfReportGenerator, csvReportGenerator } from '../src/reports/pdf-generator';
import { db } from '../src/db/database';
import { udpIngestServer } from '../src/ingest/udp-ingest';
import { probeScheduler } from '../src/prober/probe-scheduler';

describe('The Watch Full System End-to-End Test', () => {
  let server: http.Server;

  beforeAll(async () => {
    process.env.NODE_ENV = 'test';
    server = await bootstrap(4005, 9885);

    // Process a guaranteed test incident
    await ingestQueue.processItem({
      systemId: 'NOUN-HRMS',
      method: 'POST',
      path: '/api/v1/payroll/export',
      statusCode: 500,
      latencyMs: 140,
      clientIp: '194.26.29.112',
      payloadSnippet: `dept_id=1' UNION SELECT staff_id, full_name, bvn, salary FROM staff_payroll --`,
      userAgent: 'sqlmap/1.7.2#stable',
    });
  });

  afterAll(async () => {
    probeScheduler.stop();
    udpIngestServer.stop();
    await new Promise<void>((resolve) => {
      server.close(() => resolve());
    });
  });

  it('should generate executive PDF forensic audit report with valid binary structure', async () => {
    const pdfBuffer = await pdfReportGenerator.generatePdf({ systemId: 'NOUN-HRMS' });
    expect(pdfBuffer).toBeDefined();
    expect(pdfBuffer.length).toBeGreaterThan(1000);
    // PDF Magic Header %PDF-
    expect(pdfBuffer.toString('utf-8', 0, 5)).toBe('%PDF-');
  });

  it('should generate CSV forensic audit report with correct columns and WAT timestamps', async () => {
    const csv = await csvReportGenerator.generateCsv('NOUN-HRMS');
    expect(csv).toContain('IncidentID,SystemID,TimestampWAT,Severity,ThreatClassification');
    expect(csv).toContain('NOUN-HRMS');
  });

  it('should calculate platform health overview correctly', async () => {
    const overview = await db.getSystemHealthOverview('NOUN-HRMS');
    expect(overview.healthScore).toBeGreaterThanOrEqual(0);
    expect(overview.healthScore).toBeLessThanOrEqual(100);
    expect(overview.threatLevel).toBeDefined();
    expect(overview.timestampWat).toContain('WAT');
    expect(overview.activeTenantsCount).toBeGreaterThan(0);
  });

  it('should accept and process non-blocking telemetry', async () => {
    await ingestQueue.processItem({
      systemId: 'NOUN-HRMS',
      method: 'GET',
      path: '/api/v1/payroll/status',
      statusCode: 200,
      latencyMs: 18.2,
      clientIp: '197.210.64.12',
      userAgent: 'Mozilla/5.0 SentinelAgent/1.0',
    });

    const logs = await db.getTelemetryLogs('NOUN-HRMS', 5);
    expect(logs.length).toBeGreaterThan(0);
    expect(logs[0].system_id).toBe('NOUN-HRMS');
  });
});
