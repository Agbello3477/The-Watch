import { describe, it, expect, beforeEach } from 'vitest';
import { HeartbeatEngine } from '../src/prober/heartbeat-engine';
import { SyntheticProbe, db } from '../src/db/database';

describe('Synthetic Endpoint Probe Engine', () => {
  let heartbeat: HeartbeatEngine;

  beforeEach(async () => {
    await db.initialize();
    heartbeat = new HeartbeatEngine();
  });

  it('should detect a healthy simulated mock probe', async () => {
    const probe: SyntheticProbe = {
      id: 'test-probe-1',
      system_id: 'NOUN-HRMS',
      name: 'HRMS Test Health',
      target_url: 'http://localhost:4000/api/mock/noun/health',
      method: 'GET',
      expected_status: 200,
      interval_seconds: 30,
      is_enabled: true,
      last_status: 'PENDING',
      last_ttfb_ms: 0,
      last_dns_ms: 0,
      last_tcp_ms: 0,
      uptime_percent: 100,
    };

    const result = await heartbeat.executeProbe(probe);

    expect(result.status).toBe('HEALTHY');
    expect(result.statusCode).toBe(200);
    expect(result.isSuccess).toBe(true);
    expect(result.ttfbMs).toBeGreaterThan(0);
    expect(result.sslValid).toBe(true);
  });

  it('should detect probe failure and record an incident when target is down', async () => {
    const failingProbe: SyntheticProbe = {
      id: 'test-failing-probe',
      system_id: 'NOUN-HRMS',
      name: 'Unreachable Gateway',
      target_url: 'http://127.0.0.1:59999/unreachable/route', // offline port
      method: 'GET',
      expected_status: 200,
      interval_seconds: 30,
      is_enabled: true,
      last_status: 'PENDING',
      last_ttfb_ms: 0,
      last_dns_ms: 0,
      last_tcp_ms: 0,
      uptime_percent: 100,
    };

    const result = await heartbeat.executeProbe(failingProbe);

    expect(result.status).toBe('DOWN');
    expect(result.isSuccess).toBe(false);
    expect(result.errorMessage).toBeDefined();

    // Verify incident was saved in database
    const incidents = await db.getIncidents({ systemId: 'NOUN-HRMS' });
    const probeIncident = incidents.find((i) => i.target_endpoint.includes('59999'));

    expect(probeIncident).toBeDefined();
    expect(probeIncident?.severity).toBe('HIGH');
    expect(probeIncident?.created_at_wat).toContain('WAT');
  });
});
