import { Router, Request, Response } from 'express';
import { db } from '../db/database';
import { heartbeatEngine } from '../prober/heartbeat-engine';

export const probesRouter = Router();

/**
 * List all synthetic probes with uptime and latency metrics
 */
probesRouter.get('/', async (req: Request, res: Response) => {
  const systemId = req.query.systemId as string;
  const probes = await db.getProbes(systemId);

  // Attach recent history for each probe
  const enrichedProbes = await Promise.all(
    probes.map(async (p) => {
      const history = await db.getProbeHistory(p.id, 15);
      return {
        ...p,
        history,
      };
    })
  );

  res.json(enrichedProbes);
});

/**
 * Trigger immediate on-demand probe check
 */
probesRouter.post('/:id/run', async (req: Request, res: Response) => {
  const { id } = req.params;
  const probes = await db.getProbes();
  const probe = probes.find((p) => p.id === id);

  if (!probe) {
    res.status(404).json({ error: 'Probe not found' });
    return;
  }

  const result = await heartbeatEngine.executeProbe(probe);
  res.json(result);
});
