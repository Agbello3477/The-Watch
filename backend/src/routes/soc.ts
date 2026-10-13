import { Router, Request, Response } from 'express';
import { socEngine } from '../soc/soc-engine';

export const socRouter = Router();

// ─── 1. SOC Operational Metrics & KPIs ─────────────────────────
socRouter.get('/metrics', (_req: Request, res: Response) => {
  const metrics = socEngine.getSocMetrics();
  res.json(metrics);
});

// ─── 2. Tiered Case Management ────────────────────────────────
socRouter.get('/cases', (req: Request, res: Response) => {
  const { severity, tier, status, systemId } = req.query;
  const cases = socEngine.getCases({
    severity: severity ? String(severity) : undefined,
    tier: tier ? String(tier) : undefined,
    status: status ? String(status) : undefined,
    systemId: systemId ? String(systemId) : undefined,
  });
  res.json({ cases, total: cases.length });
});

socRouter.get('/cases/:id', (req: Request, res: Response) => {
  const socCase = socEngine.getCaseById(req.params.id);
  if (!socCase) {
    res.status(404).json({ error: 'Case not found' });
    return;
  }
  res.json(socCase);
});

socRouter.post('/cases/:id/notes', (req: Request, res: Response) => {
  const { author, authorRole, text } = req.body;
  if (!text) {
    res.status(400).json({ error: 'Note text is required' });
    return;
  }
  const note = socEngine.addCaseNote(
    req.params.id,
    author || 'SOC Analyst',
    authorRole || 'Tier 2 Responder',
    text
  );
  if (!note) {
    res.status(404).json({ error: 'Case not found' });
    return;
  }
  res.status(201).json(note);
});

socRouter.patch('/cases/:id/status', (req: Request, res: Response) => {
  const { status, resolvedAtWat } = req.body;
  const updated = socEngine.updateCaseStatus(req.params.id, status, resolvedAtWat);
  if (!updated) {
    res.status(404).json({ error: 'Case not found' });
    return;
  }
  res.json(updated);
});

socRouter.patch('/cases/:id/assign', (req: Request, res: Response) => {
  const { analyst, tier } = req.body;
  if (!analyst) {
    res.status(400).json({ error: 'Analyst name is required' });
    return;
  }
  const updated = socEngine.assignCase(req.params.id, analyst, tier);
  if (!updated) {
    res.status(404).json({ error: 'Case not found' });
    return;
  }
  res.json(updated);
});

// ─── 3. Dynamic IP Blocklist & Ingest Firewall ─────────────────
socRouter.get('/blocklist', (_req: Request, res: Response) => {
  const blocklist = socEngine.getBlocklist();
  res.json({ blocklist, total: blocklist.length });
});

socRouter.post('/blocklist', (req: Request, res: Response) => {
  const { ip, reason, threatClassification, systemId, blockedBy, durationHours } = req.body;
  if (!ip || !reason) {
    res.status(400).json({ error: 'IP and reason are required' });
    return;
  }
  const entry = socEngine.blockIp({
    ip,
    reason,
    threatClassification,
    systemId,
    blockedBy,
    durationHours: durationHours ? parseInt(durationHours, 10) : 24,
  });
  res.status(201).json(entry);
});

socRouter.delete('/blocklist/:ip', (req: Request, res: Response) => {
  const success = socEngine.unblockIp(req.params.ip);
  if (!success) {
    res.status(404).json({ error: 'IP not found in blocklist' });
    return;
  }
  res.json({ status: 'UNBLOCKED', ip: req.params.ip });
});

// ─── 4. Threat Intelligence (IOCs) ────────────────────────────
socRouter.get('/iocs', (_req: Request, res: Response) => {
  const iocs = socEngine.getIocs();
  res.json({ iocs, total: iocs.length });
});

socRouter.post('/iocs', (req: Request, res: Response) => {
  const { type, value, threatActor, severity, confidence, mitreTactic, mitreTechnique, tags, addedBy } = req.body;
  if (!type || !value) {
    res.status(400).json({ error: 'Type and value are required' });
    return;
  }
  const ioc = socEngine.addIoc({
    type,
    value,
    threatActor: threatActor || 'Unknown Adversary',
    severity: severity || 'HIGH',
    confidence: confidence || 85,
    mitreTactic: mitreTactic || 'Initial Access',
    mitreTechnique: mitreTechnique || 'T1190',
    tags: Array.isArray(tags) ? tags : [tags || 'SOC-Manual'],
    addedBy: addedBy || 'SOC Analyst',
    status: 'ACTIVE',
  });
  res.status(201).json(ioc);
});

// ─── 5. SOAR Playbooks ─────────────────────────────────────────
socRouter.get('/playbooks', (_req: Request, res: Response) => {
  const playbooks = socEngine.getPlaybooks();
  res.json({ playbooks });
});

socRouter.post('/playbooks/:id/execute', (req: Request, res: Response) => {
  const { targetCaseId } = req.body;
  try {
    const result = socEngine.executePlaybook(req.params.id, targetCaseId);
    res.json(result);
  } catch (err: any) {
    res.status(404).json({ error: err.message });
  }
});

// ─── 6. Detection Engineering Rules ───────────────────────────
socRouter.get('/rules', (_req: Request, res: Response) => {
  const rules = socEngine.getDetectionRules();
  res.json({ rules });
});

socRouter.patch('/rules/:id/toggle', (req: Request, res: Response) => {
  const { enabled } = req.body;
  const updated = socEngine.toggleRule(req.params.id, Boolean(enabled));
  if (!updated) {
    res.status(404).json({ error: 'Rule not found' });
    return;
  }
  res.json(updated);
});

// ─── 7. Shift Handovers ────────────────────────────────────────
socRouter.get('/shifts', (_req: Request, res: Response) => {
  const handovers = socEngine.getShiftHandovers();
  res.json({ handovers });
});

socRouter.post('/shifts', (req: Request, res: Response) => {
  const { shiftName, leadAnalyst, analystsOnDuty, handoffNotes, actionItems } = req.body;
  if (!shiftName || !leadAnalyst) {
    res.status(400).json({ error: 'shiftName and leadAnalyst are required' });
    return;
  }
  const shift = socEngine.createShiftHandover({
    shiftName,
    leadAnalyst,
    analystsOnDuty: Array.isArray(analystsOnDuty) ? analystsOnDuty : [leadAnalyst],
    handoffNotes: handoffNotes || 'Shift handover completed with no major unresolved escalations.',
    actionItems: Array.isArray(actionItems) ? actionItems : [],
  });
  res.status(201).json(shift);
});
