import { Router, Request, Response } from 'express';
import { authService } from '../auth/auth-service';
import { db, UserAuditLog, getWATFormattedDate } from '../db/database';
import { geoIPService } from '../threat/geoip-service';
import { realtimeAlertHub } from '../alerts/realtime-alert-hub';
import { heuristicEngine } from '../threat/heuristic-engine';
import { socEngine } from '../soc/soc-engine';

export const auditRouter = Router();

/**
 * Record a real-time user activity event (CLICK, DOWNLOAD, ACTION)
 * Automatically captures: Client IP, GeoIP location, Full Name, Role, WAT Timestamp, Target & Details
 */
auditRouter.post('/track', async (req: Request, res: Response) => {
  try {
    const { 
      action, 
      details, 
      target, 
      systemId, 
      email: bodyEmail, 
      fullName: bodyFullName, 
      role: bodyRole, 
      clientIp: bodyClientIp,
      status: bodyStatus
    } = req.body;

    if (!action) {
      res.status(400).json({ error: 'MISSING_ACTION', message: 'Action type is required.' });
      return;
    }

    // 1. Resolve User Identity (from body payload or Bearer token)
    let email = bodyEmail || 'visitor@noun-hrms.gov.ng';
    let fullName = bodyFullName || 'NOUN HRMS Operator';
    let role = bodyRole || 'STAFF';
    let userId: string | undefined = undefined;

    const authHeader = req.headers.authorization;
    const token = authHeader?.startsWith('Bearer ') ? authHeader.slice(7) : (req.query.token as string);

    if (token) {
      const decoded = authService.verifyToken(token);
      if (decoded) {
        userId = decoded.sub;
        if (!bodyEmail) email = decoded.email;
        if (!bodyFullName) fullName = decoded.name || decoded.email;
        if (!bodyRole) role = decoded.role || 'SOC_ANALYST';
      }
    }

    // 2. Resolve Client IP Address
    const rawIp = bodyClientIp || (req.headers['x-forwarded-for'] as string || req.socket.remoteAddress || '127.0.0.1');
    const ipAddress = String(rawIp).split(',')[0].trim();

    // 3. Resolve GeoIP Location
    const geo = await geoIPService.resolve(ipAddress);
    const location = `${geo.city}, ${geo.country}${geo.asn ? ` (${geo.asn})` : ''}`;

    // 4. Construct Audit Log
    const auditLog: UserAuditLog = {
      id: `ual-${(action || 'act').toLowerCase()}-${Date.now()}-${Math.random().toString(36).substr(2, 4)}`,
      system_id: systemId || 'NOUN-HRMS',
      user_id: userId,
      email,
      full_name: fullName,
      role,
      action: action as any,
      ip_address: ipAddress,
      location,
      geo_city: geo.city,
      geo_country: geo.country,
      user_agent: req.headers['user-agent'] || 'NOUN-HRMS Client',
      status: (bodyStatus as any) || 'SUCCESS',
      details: details || (target ? `Interacted with: ${target}` : `${action} on ${systemId || 'NOUN-HRMS'}`),
      created_at_wat: getWATFormattedDate(),
      created_at: new Date().toISOString(),
    };

    // 5. Persist to DB and broadcast via SSE in real time
    await db.saveUserAuditLog(auditLog);
    realtimeAlertHub.broadcastAuditLog(auditLog);

    // 6. If this event is an intrusion attempt (LOGIN_FAILED, BLOCKED, or malicious payload) on NOUN-HRMS or monitored system, trigger loud real-time threat alert!
    const heuristicCheck = heuristicEngine.evaluate({
      method: 'POST',
      path: target || '/auth/login',
      payload: `${details || ''} ${target || ''} ${email || ''}`,
      userAgent: req.headers['user-agent'],
      clientIp: ipAddress,
    });

    if (action === 'LOGIN_FAILED' || bodyStatus === 'FAILED' || bodyStatus === 'BLOCKED' || heuristicCheck.detected) {
      const incident = {
        id: `inc-hrms-${Date.now()}-${Math.random().toString(36).substr(2, 4)}`,
        system_id: systemId || 'NOUN-HRMS',
        incident_type: heuristicCheck.detected ? heuristicCheck.incidentType : 'INTRUSION_ATTEMPT',
        threat_classification: heuristicCheck.detected
          ? heuristicCheck.threatClassification
          : `Unauthorized Intrusion / Failed Login Attempt on ${systemId || 'NOUN-HRMS'}`,
        severity: (heuristicCheck.detected ? heuristicCheck.severity : 'CRITICAL') as 'CRITICAL' | 'HIGH',
        offending_ip: ipAddress,
        geo_country: geo.country,
        geo_region: geo.region,
        geo_city: geo.city,
        geo_lat: geo.latitude,
        geo_lng: geo.longitude,
        asn: geo.asn,
        isp: geo.isp,
        is_proxy_or_vpn: geo.isProxyOrVpn,
        target_endpoint: target || '/api/auth/login',
        http_method: 'POST',
        captured_payload: details || `Unauthorized access attempt by "${email}" (${fullName}) from ${location}`,
        status: 'UNRESOLVED' as const,
        mitigation_blueprint: heuristicEngine.generateWafMitigation(ipAddress, target || '/api/auth/login', 'Intrusion'),
        remediation_summary: `Active intrusion attempt detected on ${systemId || 'NOUN-HRMS'} from ${ipAddress} (${location}).`,
        created_at_wat: getWATFormattedDate(),
      };

      await db.saveIncident(incident);
      realtimeAlertHub.broadcastThreat(incident);
      socEngine.createCaseFromIncident({
        id: incident.id,
        systemId: incident.system_id,
        threatClassification: incident.threat_classification,
        severity: incident.severity,
        offendingIp: ipAddress,
        targetEndpoint: incident.target_endpoint,
        capturedPayload: incident.captured_payload,
      });
    }

    res.json({
      success: true,
      log: auditLog,
    });
  } catch (err: any) {
    console.error('[AuditTrack] Error tracking event:', err);
    res.status(500).json({ error: 'FAILED_TO_TRACK_EVENT', message: err.message });
  }
});

/**
 * Fetch real-time audit logs
 */
auditRouter.get('/recent', async (req: Request, res: Response) => {
  const limit = req.query.limit ? parseInt(String(req.query.limit), 10) : 100;
  const systemId = req.query.systemId as string;
  const logs = await db.getUserAuditLogs(limit, systemId);
  res.json({
    totalLogs: logs.length,
    logs,
  });
});
