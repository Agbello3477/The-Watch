import { describe, it, expect, beforeEach } from 'vitest';
import { db } from '../src/db/database';
import { IngestQueue } from '../src/ingest/ingest-queue';

describe('Non-Blocking Telemetry Ingest Pipeline', () => {
  let ingestQueue: IngestQueue;

  beforeEach(async () => {
    await db.initialize();
    ingestQueue = new IngestQueue();
  });

  it('should asynchronously process and record telemetry logs', async () => {
    await ingestQueue.processItem({
      systemId: 'NOUN-HRMS',
      method: 'GET',
      path: '/api/v1/staff/profile',
      statusCode: 200,
      latencyMs: 14.5,
      clientIp: '197.210.64.12',
      userAgent: 'Mozilla/5.0 NOUN-Client/2.0',
    });

    const logs = await db.getTelemetryLogs('NOUN-HRMS', 5);
    expect(logs.length).toBeGreaterThan(0);
    const lastLog = logs[0];
    expect(lastLog.path).toBe('/api/v1/staff/profile');
    expect(lastLog.status_code).toBe(200);
    expect(lastLog.system_id).toBe('NOUN-HRMS');
  });

  it('should trigger threat detection on malicious telemetry ingest', async () => {
    await ingestQueue.processItem({
      systemId: 'NOUN-HRMS',
      method: 'POST',
      path: '/api/v1/auth/login',
      statusCode: 400,
      latencyMs: 22,
      clientIp: '194.26.29.112',
      payloadSnippet: `' OR '1'='1' --`,
    });

    const incidents = await db.getIncidents({ systemId: 'NOUN-HRMS', severity: 'CRITICAL' });
    expect(incidents.length).toBeGreaterThan(0);
    const sqliInc = incidents.find((i) => i.offending_ip === '194.26.29.112');
    expect(sqliInc).toBeDefined();
    expect(sqliInc?.threat_classification).toContain('SQLi');
  });
});
