import { Router, Response } from 'express';
import { authenticateTenant, AuthenticatedTenantRequest } from '../middleware/tenant-auth';
import { ingestQueue, TelemetryPayload } from './ingest-queue';

export const httpIngestRouter = Router();

/**
 * Non-blocking HTTP Telemetry Ingest Gateway
 * Monitored systems ship logs asynchronously without blocking primary transactions
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

  // Return immediate 202 Accepted (<5ms)
  res.status(202).json({
    status: 'ACCEPTED',
    systemId: tenant.systemId,
    receivedCount: items.length,
    queuedAt: new Date().toISOString(),
  });
});
