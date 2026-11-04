import { Router, Response } from 'express';
import { authenticateTenant, AuthenticatedTenantRequest } from '../middleware/tenant-auth';
import { ingestQueue, TelemetryPayload } from './ingest-queue';
import { socEngine } from '../soc/soc-engine';

export const httpIngestRouter = Router();

/**
 * Non-blocking HTTP Telemetry Ingest Gateway
 * Monitored systems ship logs asynchronously without blocking primary transactions
 * and receive the live permanent SOC IP blocklist to enforce on NOUN-HRMS
 */
httpIngestRouter.post('/ingest', authenticateTenant, (req: AuthenticatedTenantRequest, res: Response) => {
  const tenant = req.tenant!;
  const body = req.body;

  let items: TelemetryPayload[] = [];

  if (Array.isArray(body)) {
    items = body.map((b) => ({
      ...b,
      systemId: tenant.systemId,
      clientIp: b.clientIp || req.ip || '127.0.0.1',
    }));
  } else if (typeof body === 'object' && body !== null) {
    items = [
      {
        ...body,
        systemId: tenant.systemId,
        clientIp: body.clientIp || req.ip || '127.0.0.1',
      },
    ];
  } else {
    res.status(400).json({ error: 'INVALID_PAYLOAD', message: 'Expected JSON telemetry object or array.' });
    return;
  }

  // Non-blocking asynchronous enqueuing
  ingestQueue.enqueue(items);

  const activeBlockedIps = socEngine.getActiveBlockedIps();
  const quarantinedClients = items
    .map((i) => i.clientIp)
    .filter((ip) => socEngine.isIpBlocked(ip));

  // Return immediate 202 Accepted (<5ms) along with active blocked IPs for NOUN-HRMS enforcement
  res.status(202).json({
    status: 'ACCEPTED',
    systemId: tenant.systemId,
    receivedCount: items.length,
    activeBlockedIps,
    quarantinedClients,
    unlockPolicy: 'SUPER_ADMIN_ONLY',
    queuedAt: new Date().toISOString(),
  });
});
