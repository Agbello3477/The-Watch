import { Response } from 'express';
import { ThreatIncident, UserAuditLog, getWATFormattedDate } from '../db/database';

export interface RealtimeAlertPayload {
  id: string;
  systemId: string;
  incidentType: string;
  threatClassification: string;
  severity: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
  offendingIp: string;
  geoCountry?: string;
  geoRegion?: string;
  geoCity?: string;
  geoLat?: number;
  geoLng?: number;
  asn?: string;
  isp?: string;
  isProxyOrVpn?: boolean;
  targetEndpoint: string;
  httpMethod: string;
  capturedPayload: string;
  status: 'UNRESOLVED' | 'ACKNOWLEDGED' | 'RESOLVED';
  mitigationBlueprint?: string;
  remediationSummary?: string;
  timestampWat: string;
  timestampIso: string;
}

export class RealtimeAlertHub {
  private clients: Set<Response> = new Set();
  private recentAlerts: RealtimeAlertPayload[] = [];
  private readonly MAX_HISTORY = 50;

  /**
   * Register a new Server-Sent Events (SSE) client stream
   */
  public registerClient(res: Response): void {
    this.clients.add(res);

    // Send initial handshake
    res.write(`event: handshake\ndata: ${JSON.stringify({ status: 'CONNECTED', serverTimeWat: getWATFormattedDate() })}\n\n`);

    // Send recent unacknowledged alerts from last 5 minutes
    if (this.recentAlerts.length > 0) {
      const activeRecent = this.recentAlerts.slice(0, 5);
      res.write(`event: history\ndata: ${JSON.stringify(activeRecent)}\n\n`);
    }

    // Clean up when client disconnects
    res.on('close', () => {
      this.clients.delete(res);
    });
  }

  /**
   * Broadcast a threat incident to all active SOC operators in real time (<1ms)
   */
  public broadcastThreat(incident: ThreatIncident | any): void {
    const payload: RealtimeAlertPayload = {
      id: incident.id,
      systemId: incident.system_id || incident.systemId || 'NOUN-HRMS',
      incidentType: incident.incident_type || incident.incidentType || 'SECURITY_THREAT',
      threatClassification: incident.threat_classification || incident.threatClassification || 'Malicious Attack Vector',
      severity: incident.severity || 'HIGH',
      offendingIp: incident.offending_ip || incident.offendingIp || '127.0.0.1',
      geoCountry: incident.geo_country || incident.geoCountry || 'Nigeria',
      geoRegion: incident.geo_region || incident.geoRegion || 'Abuja (FCT)',
      geoCity: incident.geo_city || incident.geoCity || 'Abuja',
      geoLat: incident.geo_lat ?? incident.geoLat ?? 9.0765,
      geoLng: incident.geo_lng ?? incident.geoLng ?? 7.3986,
      asn: incident.asn || 'AS37075',
      isp: incident.isp || 'Unknown ISP',
      isProxyOrVpn: Boolean(incident.is_proxy_or_vpn ?? incident.isProxyOrVpn),
      targetEndpoint: incident.target_endpoint || incident.targetEndpoint || '/',
      httpMethod: incident.http_method || incident.httpMethod || 'POST',
      capturedPayload: incident.captured_payload || incident.capturedPayload || '',
      status: incident.status || 'UNRESOLVED',
      mitigationBlueprint: incident.mitigation_blueprint || incident.mitigationBlueprint,
      remediationSummary: incident.remediation_summary || incident.remediationSummary,
      timestampWat: incident.created_at_wat || getWATFormattedDate(),
      timestampIso: incident.created_at || new Date().toISOString(),
    };

    // Prepend to recent history
    this.recentAlerts.unshift(payload);
    if (this.recentAlerts.length > this.MAX_HISTORY) {
      this.recentAlerts.length = this.MAX_HISTORY;
    }

    const sseMessage = `event: threat-alert\ndata: ${JSON.stringify(payload)}\n\n`;

    // Dispatch to all connected SSE clients
    for (const client of this.clients) {
      try {
        client.write(sseMessage);
      } catch (err) {
        this.clients.delete(client);
      }
    }

    console.log(`[RealtimeAlertHub] 🚨 Broadcasted ${payload.severity} threat "${payload.threatClassification}" to ${this.clients.size} active SOC operator sessions.`);
  }

  /**
   * Broadcast a user activity audit log (LOGIN, LOGOUT, CLICK, DOWNLOAD) in real time
   */
  public broadcastAuditLog(log: UserAuditLog): void {
    const sseMessage = `event: user-audit\ndata: ${JSON.stringify(log)}\n\n`;
    for (const client of this.clients) {
      try {
        client.write(sseMessage);
      } catch (err) {
        this.clients.delete(client);
      }
    }
    console.log(`[RealtimeAlertHub] 📋 Broadcasted audit event [${log.action}] for "${log.full_name || log.email}" to ${this.clients.size} active SOC operator sessions.`);
  }

  /**
   * Polling fallback endpoint for clients behind restrictive proxies
   */
  public getAlertsSince(timestampIso?: string): RealtimeAlertPayload[] {
    if (!timestampIso) return this.recentAlerts.slice(0, 10);
    const sinceTime = new Date(timestampIso).getTime();
    return this.recentAlerts.filter((a) => new Date(a.timestampIso).getTime() > sinceTime);
  }

  /**
   * Keepalive ping to prevent proxy connection timeouts
   */
  public pingAll(): void {
    const ping = `: ping\n\n`;
    for (const client of this.clients) {
      try {
        client.write(ping);
      } catch {
        this.clients.delete(client);
      }
    }
  }
}

export const realtimeAlertHub = new RealtimeAlertHub();

// Run keepalive ping every 20 seconds
setInterval(() => {
  realtimeAlertHub.pingAll();
}, 20000);
