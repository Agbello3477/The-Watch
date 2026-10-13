import { Router, Request, Response } from 'express';
import { REGISTERED_TENANTS } from '../config/index.js';
import { db } from '../db/database.js';

export const tenantsRouter = Router();

/**
 * GET /api/v1/tenants
 * Returns all registered tenants with their API keys and connection status
 * (for the Super Admin integration panel — shows what key to put in HRMS)
 */
tenantsRouter.get('/', async (_req: Request, res: Response) => {
  const tenants = Object.values(REGISTERED_TENANTS).map((t) => ({
    systemId: t.systemId,
    name: t.name,
    description: t.description,
    primaryContact: t.primaryContact,
    enabled: t.enabled,
    apiKey: t.apiKey,         // the X-Telemetry-Key value HRMS must send
    apiSecret: t.apiSecret,   // optional HMAC signing secret
  }));
  res.json({ tenants });
});

/**
 * GET /api/v1/tenants/:systemId/connection-status
 * Returns whether The Watch has received any telemetry from this system recently
 */
tenantsRouter.get('/:systemId/connection-status', async (req: Request, res: Response) => {
  const { systemId } = req.params;
  const logs = await db.getRecentTelemetryLogs(systemId, 5);
  const lastSeen = logs.length > 0 ? logs[0].created_at : null;
  const isConnected = logs.length > 0;

  // Calculate minutes since last ping
  let minutesSinceLastPing: number | null = null;
  if (lastSeen) {
    minutesSinceLastPing = Math.floor((Date.now() - new Date(lastSeen).getTime()) / 60000);
  }

  res.json({
    systemId,
    isConnected,
    lastSeen,
    minutesSinceLastPing,
    recentRequestCount: logs.length,
    status: isConnected
      ? minutesSinceLastPing !== null && minutesSinceLastPing < 2 ? 'LIVE' : 'STALE'
      : 'DISCONNECTED',
    message: isConnected
      ? `Receiving telemetry from ${systemId}. Last ping ${minutesSinceLastPing}m ago.`
      : `No telemetry received from ${systemId}. Install the Sentinel Agent in your HRMS.`,
  });
});

/**
 * GET /api/v1/tenants/:systemId/sdk-config
 * Returns the exact configuration snippet the HRMS developer needs to paste
 */
tenantsRouter.get('/:systemId/sdk-config', (req: Request, res: Response) => {
  const { systemId } = req.params;
  const tenant = REGISTERED_TENANTS[systemId];

  if (!tenant) {
    res.status(404).json({ error: 'SYSTEM_NOT_REGISTERED', message: `System '${systemId}' is not registered in The Watch.` });
    return;
  }

  const watchUrl = process.env.THE_WATCH_PUBLIC_URL || `http://localhost:${process.env.PORT || 4000}`;

  res.json({
    systemId,
    name: tenant.name,
    ingestUrl: `${watchUrl}/api/v1/telemetry/ingest`,
    xTelemetryKey: tenant.apiKey,
    xTelemetrySecret: tenant.apiSecret,
    instructions: [
      '1. Install the sentinel-agent middleware in your HRMS Express app (or download from /api/v1/tenants/sentinel-agent.ts)',
      `2. Set environment variable: THE_WATCH_URL=${watchUrl}`,
      `3. Set environment variable: THE_WATCH_API_KEY=${tenant.apiKey}`,
      '4. Import and mount: app.use(sentinelAgent)',
      '5. Verify connection at: ' + watchUrl + `/api/v1/tenants/${systemId}/connection-status`,
    ],
    envSnippet: `THE_WATCH_URL=${watchUrl}\nTHE_WATCH_API_KEY=${tenant.apiKey}\nTHE_WATCH_SYSTEM_ID=${systemId}`,
    curlTest: `curl -X POST ${watchUrl}/api/v1/telemetry/ingest \\\n  -H "Content-Type: application/json" \\\n  -H "X-Telemetry-Key: ${tenant.apiKey}" \\\n  -d '{"method":"GET","path":"/api/health","statusCode":200,"latencyMs":42,"clientIp":"127.0.0.1"}'`,
  });
});
