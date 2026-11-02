import { Router, Request, Response } from 'express';
import { db, getWATFormattedDate } from '../db/database.js';
import { heuristicEngine } from '../threat/heuristic-engine.js';
import { socEngine } from '../soc/soc-engine.js';

export const trafficRouter = Router();

function classifyPacket(log: any, index: number, total: number) {
  let parsedMeta: any = {};
  if (log.headers_json) {
    try {
      parsedMeta = typeof log.headers_json === 'string' ? JSON.parse(log.headers_json) : log.headers_json;
    } catch {}
  }

  const statusCode = Number(log.status_code || 200);
  const payloadStr = String(log.payload_snippet || '');
  const pathStr = String(log.path || '/');
  const clientIp = String(log.client_ip || '127.0.0.1');

  let verdict: 'ALLOWED_HEALTHY' | 'UNSUCCESSFUL' | 'MALICIOUS_BLOCKED' = parsedMeta.verdict;
  let threatClassification: string | undefined = parsedMeta.threatClassification;

  if (!verdict) {
    const isBlockedPayload =
      payloadStr.includes('BLOCKED_BY_SOC_FIREWALL') ||
      payloadStr.includes('MALICIOUS_SIGNATURE') ||
      socEngine.isIpBlocked(clientIp);

    const match = heuristicEngine.evaluate({
      method: log.method || 'GET',
      path: pathStr,
      payload: payloadStr,
      userAgent: log.user_agent,
      clientIp,
    });

    if (isBlockedPayload || match.detected) {
      verdict = 'MALICIOUS_BLOCKED';
      threatClassification = match.detected ? match.threatClassification : 'Quarantined / Blocked by SOC Firewall';
    } else if (statusCode >= 400) {
      verdict = 'UNSUCCESSFUL';
    } else {
      verdict = 'ALLOWED_HEALTHY';
    }
  }

  // Deterministic ephemeral port from log ID so each packet row has a stable TCP port
  let hash = 0;
  const idStr = String(log.id || index);
  for (let i = 0; i < idStr.length; i++) {
    hash = (hash * 31 + idStr.charCodeAt(i)) & 0xffff;
  }
  const sourcePort = parsedMeta.sourcePort || 49152 + (hash % 16000);
  const systemId = log.system_id || 'NOUN-HRMS';
  const destIp = parsedMeta.destIp || (systemId === 'THE-WATCH-SOC' ? '10.20.0.10 (THE-WATCH-SOC)' : '10.20.1.55 (NOUN-HRMS)');
  const destPort = parsedMeta.destPort || 443;
  const protocol = parsedMeta.protocol || (pathStr.includes('/stream') ? 'SSE/HTTP2' : 'HTTPS/TLSv1.3');
  const direction =
    parsedMeta.direction ||
    (verdict === 'MALICIOUS_BLOCKED'
      ? 'INBOUND_REQ'
      : statusCode >= 400
      ? 'OUTBOUND_RES'
      : 'INBOUND_AND_OUTBOUND');
  const lengthBytes =
    parsedMeta.lengthBytes ||
    460 + payloadStr.length + pathStr.length * 4 + (statusCode < 400 ? (hash % 1800) + 320 : 180);

  let watTimestamp = '';
  try {
    watTimestamp = log.created_at ? getWATFormattedDate(new Date(log.created_at)) : getWATFormattedDate();
  } catch {
    watTimestamp = getWATFormattedDate();
  }

  return {
    ...log,
    packetNumber: total - index,
    verdict,
    threatClassification,
    direction,
    protocol,
    sourceIp: clientIp,
    sourcePort,
    destIp,
    destPort,
    lengthBytes,
    watTimestamp,
  };
}

// GET /api/v1/traffic/live?systemId=ALL&limit=150
trafficRouter.get('/live', async (req: Request, res: Response) => {
  const systemId = (req.query.systemId as string) || 'ALL';
  const limit = Math.min(parseInt(req.query.limit as string) || 150, 500);
  const rawLogs = await db.getRecentTelemetryLogs(systemId, limit);
  const logs = rawLogs.map((l, idx) => classifyPacket(l, idx, rawLogs.length));
  res.json({ logs, systemId, fetchedAt: new Date().toISOString() });
});

// GET /api/v1/traffic/stats?systemId=ALL
trafficRouter.get('/stats', async (req: Request, res: Response) => {
  const systemId = (req.query.systemId as string) || 'ALL';
  const rawLogs = await db.getRecentTelemetryLogs(systemId, 500);
  const logs = rawLogs.map((l, idx) => classifyPacket(l, idx, rawLogs.length));

  const total = logs.length;
  const healthyGreenCount = logs.filter((l) => l.verdict === 'ALLOWED_HEALTHY').length;
  const unsuccessfulAmberCount = logs.filter((l) => l.verdict === 'UNSUCCESSFUL').length;
  const maliciousRedCount = logs.filter((l) => l.verdict === 'MALICIOUS_BLOCKED').length;

  const errors = unsuccessfulAmberCount + maliciousRedCount;
  const ok = healthyGreenCount;
  const avgLatency =
    total > 0 ? Math.round(logs.reduce((s: number, l: any) => s + (l.latency_ms || 0), 0) / total) : 0;
  const slowRequests = logs.filter((l: any) => (l.latency_ms || 0) > 500).length;

  const endpointMap: Record<string, number> = {};
  logs.forEach((l: any) => {
    const key = `[${l.system_id}] ${l.method} ${l.path}`;
    endpointMap[key] = (endpointMap[key] || 0) + 1;
  });
  const topEndpoints = Object.entries(endpointMap)
    .sort((a, b) => b[1] - a[1])
    .slice(0, 10)
    .map(([endpoint, count]) => ({ endpoint, count }));

  const ipMap: Record<string, number> = {};
  logs.forEach((l: any) => {
    ipMap[l.client_ip] = (ipMap[l.client_ip] || 0) + 1;
  });
  const topIps = Object.entries(ipMap)
    .sort((a, b) => b[1] - a[1])
    .slice(0, 6)
    .map(([ip, count]) => ({ ip, count }));

  const methodMap: Record<string, number> = {};
  logs.forEach((l: any) => {
    methodMap[l.method] = (methodMap[l.method] || 0) + 1;
  });

  res.json({
    total,
    ok,
    errors,
    healthyGreenCount,
    unsuccessfulAmberCount,
    maliciousRedCount,
    avgLatency,
    slowRequests,
    topEndpoints,
    topIps,
    methodBreakdown: methodMap,
    systemId,
  });
});
