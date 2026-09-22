import { Router, Request, Response } from 'express';
import { db } from '../db/database';

export const incidentsRouter = Router();

/**
 * List historical threat incidents & failures
 */
incidentsRouter.get('/', async (req: Request, res: Response) => {
  const { systemId, severity, status, limit } = req.query;

  const incidents = await db.getIncidents({
    systemId: systemId ? String(systemId) : undefined,
    severity: severity ? String(severity) : undefined,
    status: status ? String(status) : undefined,
    limit: limit ? parseInt(String(limit), 10) : 50,
  });

  res.json(incidents);
});

/**
 * Update incident status (Acknowledge or Resolve)
 */
incidentsRouter.patch('/:id/status', async (req: Request, res: Response) => {
  const { id } = req.params;
  const { status, adminUser } = req.body;

  if (status !== 'ACKNOWLEDGED' && status !== 'RESOLVED') {
    res.status(400).json({ error: 'Invalid status. Must be ACKNOWLEDGED or RESOLVED.' });
    return;
  }

  const updated = await db.updateIncidentStatus(id, status, adminUser || 'Security-Admin');
  if (!updated) {
    res.status(404).json({ error: 'Incident not found' });
    return;
  }

  res.json(updated);
});
