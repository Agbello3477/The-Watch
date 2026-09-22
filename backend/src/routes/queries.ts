import { Router, Request, Response } from 'express';
import { db } from '../db/database';

export const queriesRouter = Router();

/**
 * Returns database query metrics and slow query analysis (>200ms)
 */
queriesRouter.get('/', async (req: Request, res: Response) => {
  const systemId = req.query.systemId as string;
  const slowOnly = req.query.slowOnly === 'true';
  const limit = req.query.limit ? parseInt(String(req.query.limit), 10) : 50;

  const metrics = await db.getQueryMetrics(systemId, slowOnly, limit);

  // Compute summary stats
  const total = metrics.length;
  const slowCount = metrics.filter((m) => m.exceeded_threshold || m.duration_ms > 200).length;
  const avgDuration = total > 0 ? metrics.reduce((a, b) => a + b.duration_ms, 0) / total : 0;
  const maxDuration = total > 0 ? Math.max(...metrics.map((m) => m.duration_ms)) : 0;

  res.json({
    summary: {
      totalLogged: total,
      slowQueriesCount: slowCount,
      avgDurationMs: Math.round(avgDuration * 10) / 10,
      maxDurationMs: Math.round(maxDuration * 10) / 10,
      poolActiveConnections: metrics[0]?.pool_active_connections || 4,
      poolIdleConnections: metrics[0]?.pool_idle_connections || 16,
    },
    metrics,
  });
});
