import { Router, Request, Response } from 'express';
import { db } from '../db/database.js';

export const trafficRouter = Router();

// GET /api/v1/traffic/live?systemId=NOUN-HRMS&limit=100
// Returns recent telemetry logs for traffic analysis
trafficRouter.get('/live', async (req: Request, res: Response) => {
  const systemId = (req.query.systemId as string) || 'NOUN-HRMS';
  const limit = Math.min(parseInt(req.query.limit as string) || 100, 500);
  const logs = await db.getRecentTelemetryLogs(systemId, limit);
  res.json({ logs, systemId, fetchedAt: new Date().toISOString() });
});

// GET /api/v1/traffic/stats?systemId=NOUN-HRMS
// Returns aggregate traffic statistics
trafficRouter.get('/stats', async (req: Request, res: Response) => {
  const systemId = (req.query.systemId as string) || 'NOUN-HRMS';
  const logs = await db.getRecentTelemetryLogs(systemId, 500);
  
  const total = logs.length;
  const errors = logs.filter((l: any) => l.status_code >= 400).length;
  const ok = logs.filter((l: any) => l.status_code >= 200 && l.status_code < 400).length;
  const avgLatency = total > 0 ? Math.round(logs.reduce((s: number, l: any) => s + (l.latency_ms || 0), 0) / total) : 0;
  const slowRequests = logs.filter((l: any) => (l.latency_ms || 0) > 500).length;
  
  // Top endpoints by frequency
  const endpointMap: Record<string, number> = {};
  logs.forEach((l: any) => {
    const key = `${l.method} ${l.path}`;
    endpointMap[key] = (endpointMap[key] || 0) + 1;
  });
  const topEndpoints = Object.entries(endpointMap)
    .sort((a, b) => b[1] - a[1])
    .slice(0, 10)
    .map(([endpoint, count]) => ({ endpoint, count }));
  
  // Top IPs
  const ipMap: Record<string, number> = {};
  logs.forEach((l: any) => { ipMap[l.client_ip] = (ipMap[l.client_ip] || 0) + 1; });
  const topIps = Object.entries(ipMap).sort((a, b) => b[1] - a[1]).slice(0, 5).map(([ip, count]) => ({ ip, count }));
  
  // Method breakdown
  const methodMap: Record<string, number> = {};
  logs.forEach((l: any) => { methodMap[l.method] = (methodMap[l.method] || 0) + 1; });
  
  res.json({ total, errors, ok, avgLatency, slowRequests, topEndpoints, topIps, methodBreakdown: methodMap, systemId });
});
