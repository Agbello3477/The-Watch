import { Router, Request, Response } from 'express';
import { socEngine } from '../soc/soc-engine';
import { authenticateUser, requireSuperAdmin, AuthenticatedUserRequest } from '../middleware/user-auth';
import { db, getWATFormattedDate } from '../db/database';
import { authService } from '../auth/auth-service';

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

// ─── 3. Dynamic IP Blocklist & Permanent Cross-System Firewall ─
socRouter.get('/blocklist', (_req: Request, res: Response) => {
  const blocklist = socEngine.getBlocklist();
  res.json({
    blocklist,
    activeIps: socEngine.getActiveBlockedIps(),
    total: blocklist.length,
    enforcedSystems: ['THE-WATCH-SOC', 'NOUN-HRMS'],
    unlockPolicy: 'SUPER_ADMIN_ONLY',
  });
});

/**
 * Fast real-time blocklist sync endpoint for NOUN-HRMS Sentinel Agent & connected systems
 */
socRouter.get('/blocklist/active-ips', (_req: Request, res: Response) => {
  const activeIps = socEngine.getActiveBlockedIps();
  res.json({
    activeIps,
    count: activeIps.length,
    enforcedSystems: ['THE-WATCH-SOC', 'NOUN-HRMS'],
    unlockPolicy: 'SUPER_ADMIN_ONLY',
    timestampWat: getWATFormattedDate(),
  });
});

/**
 * Fast real-time IP check endpoint for NOUN-HRMS Sentinel Agent & edge gateways
 */
socRouter.get('/blocklist/check/:ip', (req: Request, res: Response) => {
  const ip = decodeURIComponent(req.params.ip || '').trim();
  const blocked = socEngine.isIpBlocked(ip);
  const entry = socEngine.getBlockEntry(ip);
  res.json({
    ip,
    blocked,
    enforcedSystems: ['THE-WATCH-SOC', 'NOUN-HRMS'],
    unlockPolicy: 'SUPER_ADMIN_ONLY',
    reason: blocked ? entry?.reason : undefined,
    threatClassification: blocked ? entry?.threatClassification : undefined,
    blockedAtWat: blocked ? entry?.blockedAtWat : undefined,
    expiresAtWat: blocked ? entry?.expiresAtWat : undefined,
  });
});

socRouter.post('/blocklist', (req: Request, res: Response) => {
  const { ip, reason, threatClassification, systemId, blockedBy } = req.body;
  if (!ip || !reason) {
    res.status(400).json({ error: 'IP and reason are required' });
    return;
  }

  let actorName = blockedBy || 'SOC Firewall Operator';
  const authHeader = req.headers.authorization;
  if (authHeader && authHeader.startsWith('Bearer ')) {
    const decoded = authService.verifyToken(authHeader.slice(7).trim());
    if (decoded?.email) {
      actorName = `${decoded.name || decoded.email} (${decoded.role})`;
    }
  }

  const entry = socEngine.blockIp({
    ip,
    reason,
    threatClassification,
    systemId: systemId || 'NOUN-HRMS & THE-WATCH-SOC',
    blockedBy: actorName,
  });
  res.status(201).json(entry);
});

const handleSuperAdminUnlock = async (req: AuthenticatedUserRequest, res: Response) => {
  const operatorIp = ((req.headers['x-forwarded-for'] as string) || req.socket.remoteAddress || '127.0.0.1')
    .split(',')[0]
    .trim();
  const targetIp = decodeURIComponent(req.params.ip === 'SELF' ? operatorIp : req.params.ip).trim();
  const superAdminLabel = `${req.user?.fullName || req.user?.email} (SUPER_ADMIN)`;

  const success = socEngine.unblockIp(targetIp, superAdminLabel);
  if (!success) {
    res.status(404).json({ error: 'IP not found in blocklist' });
    return;
  }

  await db.saveUserAuditLog({
    id: `ual-unblock-${Date.now()}-${Math.random().toString(36).substr(2, 4)}`,
    system_id: 'THE-WATCH-SOC',
    user_id: req.user?.id,
    email: req.user?.email || 'abdulgaffarbello3477@gmail.com',
    full_name: req.user?.fullName || 'Super Admin',
    role: 'SUPER_ADMIN',
    action: 'CLICK',
    ip_address: operatorIp,
    user_agent: req.headers['user-agent'],
    status: 'SUCCESS',
    details: `Super Admin unlocked quarantined IP ${targetIp} across The Watch and NOUN-HRMS`,
    created_at_wat: getWATFormattedDate(),
  });

  res.json({
    status: 'UNBLOCKED',
    ip: targetIp,
    unlockedBy: superAdminLabel,
    unlockedAtWat: getWATFormattedDate(),
    enforcedSystems: ['THE-WATCH-SOC', 'NOUN-HRMS'],
  });
};

socRouter.delete('/blocklist/:ip', authenticateUser, requireSuperAdmin, handleSuperAdminUnlock);
socRouter.post('/blocklist/:ip/unlock', authenticateUser, requireSuperAdmin, handleSuperAdminUnlock);

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
