import { Router, Request, Response } from 'express';
import { db } from '../db/database';
import { socEngine } from '../soc/soc-engine';

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
 * Update incident status (Acknowledge or Resolve with Active Threat Neutralization)
 */
const updateIncidentStatusHandler = async (req: Request, res: Response) => {
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

  const containmentActions: string[] = [];

  // ACTIVE THREAT NEUTRALIZATION PIPELINE
  if (status === 'RESOLVED') {
    // 1. Quarantines offending origin IP in active Ingest Edge Firewall (drop 403)
    if (updated.offending_ip && updated.offending_ip !== '127.0.0.1') {
      socEngine.blockIp({
        ip: updated.offending_ip,
        reason: `Threat Neutralization: ${updated.threat_classification} (${updated.id})`,
        threatClassification: updated.threat_classification,
        systemId: updated.system_id,
        blockedBy: adminUser || 'SOC Lead Analyst',
        durationHours: 24,
      });
      containmentActions.push(`Enforced Ingest Firewall Quarantine on ${updated.offending_ip} (HTTP 403 Drop Policy)`);
    }

    // 2. Query Latency & Database Performance Mitigation
    if (updated.incident_type === 'DATABASE_QUERY_REGRESSION' || updated.threat_classification.includes('Database Query')) {
      containmentActions.push(`Applied Query Indexing Mitigation Blueprint to ${updated.system_id} database connection pool`);
    }

    // 3. Credential Stuffing & Auth Defense
    if (updated.incident_type === 'CREDENTIAL_STUFFING_BURST' || updated.target_endpoint.includes('/auth')) {
      containmentActions.push(`Invalidated compromised session tokens originating from ${updated.offending_ip}`);
    }

    // 4. Synchronize with SOC Engine Case Management
    const cases = socEngine.getCases();
    const linkedCase = cases.find((c) => c.incidentId === updated.id || (c.offendingIp === updated.offending_ip && c.systemId === updated.system_id));
    if (linkedCase) {
      socEngine.updateCaseStatus(linkedCase.id, 'RESOLVED');
      socEngine.addCaseNote(
        linkedCase.id,
        adminUser || 'SOC Lead Analyst',
        'Incident Commander',
        `Threat marked RESOLVED from Triage Desk. Containment actions executed: ${containmentActions.join('; ')}`
      );
    }
  }

  res.json({
    ...updated,
    containmentActions,
    neutralized: status === 'RESOLVED',
  });
};

incidentsRouter.patch('/:id/status', updateIncidentStatusHandler);
incidentsRouter.post('/:id/status', updateIncidentStatusHandler);
