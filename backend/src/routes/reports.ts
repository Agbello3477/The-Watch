import { Router, Request, Response } from 'express';
import { pdfReportGenerator, csvReportGenerator } from '../reports/pdf-generator';
import { authService } from '../auth/auth-service';
import { db, UserAuditLog, getWATFormattedDate } from '../db/database';
import { geoIPService } from '../threat/geoip-service';
import { realtimeAlertHub } from '../alerts/realtime-alert-hub';

export const reportsRouter = Router();

async function logDownloadEvent(req: Request, fileType: 'PDF' | 'CSV', scope: string) {
  try {
    const authHeader = req.headers.authorization;
    const token = authHeader?.startsWith('Bearer ') ? authHeader.slice(7) : (req.query.token as string);
    let user = { id: undefined as string | undefined, email: 'analyst@soc.gov.ng', fullName: 'SOC Analyst', role: 'SOC_ANALYST' };

    if (token) {
      const decoded = authService.verifyToken(token);
      if (decoded) {
        user = {
          id: decoded.sub,
          email: decoded.email,
          fullName: decoded.name || decoded.email,
          role: decoded.role || 'SOC_ANALYST',
        };
      }
    }

    const ipAddress = (req.headers['x-forwarded-for'] as string || req.socket.remoteAddress || '127.0.0.1').split(',')[0].trim();
    const geo = await geoIPService.resolve(ipAddress);
    const location = `${geo.city}, ${geo.country}${geo.asn ? ` (${geo.asn})` : ''}`;

    const auditLog: UserAuditLog = {
      id: `ual-dl-${Date.now()}-${Math.random().toString(36).substr(2, 4)}`,
      user_id: user.id,
      email: user.email,
      full_name: user.fullName,
      role: user.role,
      action: 'DOWNLOAD',
      ip_address: ipAddress,
      location,
      geo_city: geo.city,
      geo_country: geo.country,
      user_agent: req.headers['user-agent'],
      status: 'SUCCESS',
      details: `Downloaded ${fileType} forensic report for system: ${scope}`,
      created_at_wat: getWATFormattedDate(),
      created_at: new Date().toISOString(),
    };

    await db.saveUserAuditLog(auditLog);
    realtimeAlertHub.broadcastAuditLog(auditLog);
  } catch (err) {
    console.warn('[Reports] Failed to log download audit event:', err);
  }
}

/**
 * Downloads Executive Forensic Security Audit PDF Report
 */
reportsRouter.get('/pdf', async (req: Request, res: Response) => {
  try {
    const systemId = req.query.systemId as string;
    const incidentId = req.query.incidentId as string;
    const pdfBuffer = await pdfReportGenerator.generatePdf({
      systemId,
      incidentId,
      reportTitle: incidentId
        ? `INTRUSION FORENSIC DOSSIER: ${incidentId.toUpperCase()}`
        : systemId
        ? `FORENSIC SECURITY AUDIT: ${systemId.toUpperCase()}`
        : 'THE WATCH // INSTITUTIONAL SECURITY & OBSERVABILITY AUDIT',
    });

    const filename = incidentId
      ? `TheWatch_Intrusion_Dossier_${incidentId}_${Date.now()}.pdf`
      : `TheWatch_Forensic_Audit_${systemId || 'AllSystems'}_${Date.now()}.pdf`;

    // Asynchronously record download audit log
    logDownloadEvent(req, 'PDF', incidentId || systemId || 'All Systems');

    res.setHeader('Content-Type', 'application/pdf');
    res.setHeader('Content-Disposition', `attachment; filename="${filename}"`);
    res.setHeader('Content-Length', pdfBuffer.length);
    res.end(pdfBuffer);
  } catch (err: any) {
    console.error('[Reports] PDF generation error:', err);
    res.status(500).json({ error: 'FAILED_TO_GENERATE_PDF', message: err.message });
  }
});

/**
 * Downloads Raw CSV Forensic Log
 */
reportsRouter.get('/csv', async (req: Request, res: Response) => {
  try {
    const systemId = req.query.systemId as string;
    const csvContent = await csvReportGenerator.generateCsv(systemId);
    const filename = `TheWatch_Threat_Incidents_${systemId || 'AllSystems'}_${Date.now()}.csv`;

    // Asynchronously record download audit log
    logDownloadEvent(req, 'CSV', systemId || 'All Systems');

    res.setHeader('Content-Type', 'text/csv');
    res.setHeader('Content-Disposition', `attachment; filename="${filename}"`);
    res.send(csvContent);
  } catch (err: any) {
    console.error('[Reports] CSV generation error:', err);
    res.status(500).json({ error: 'FAILED_TO_GENERATE_CSV', message: err.message });
  }
});

/**
 * Downloads User Activity & Access Security Audit Trail CSV
 */
reportsRouter.get('/audit-csv', async (req: Request, res: Response) => {
  try {
    const systemId = req.query.systemId as string;
    const csvContent = await csvReportGenerator.generateAuditCsv(systemId);
    const filename = `TheWatch_User_Audit_Trail_${systemId || 'AllSystems'}_${Date.now()}.csv`;

    logDownloadEvent(req, 'CSV', `User Audit Trail (${systemId || 'All Systems'})`);

    res.setHeader('Content-Type', 'text/csv');
    res.setHeader('Content-Disposition', `attachment; filename="${filename}"`);
    res.send(csvContent);
  } catch (err: any) {
    console.error('[Reports] Audit CSV generation error:', err);
    res.status(500).json({ error: 'FAILED_TO_GENERATE_AUDIT_CSV', message: err.message });
  }
});
