import { db, getWATFormattedDate } from '../db/database';
import { heuristicEngine } from '../threat/heuristic-engine';
import { ddosDetector } from '../threat/ddos-detector';
import { geoIPService } from '../threat/geoip-service';
import { advisorService } from '../advisor/advisor-service';
import { notificationDispatcher } from '../alerts/notification-dispatcher';

export interface TelemetryPayload {
  systemId: string;
  method: string;
  path: string;
  statusCode: number;
  latencyMs: number;
  clientIp: string;
  payloadSnippet?: string;
  userAgent?: string;
  queryLatencyMs?: number;
  queryText?: string;
  errorMessage?: string;
  timestamp?: string;
}

export class IngestQueue {
  private queue: TelemetryPayload[] = [];
  private isProcessing = false;

  /**
   * Pushes telemetry item to queue with zero delay
   */
  public enqueue(item: TelemetryPayload | TelemetryPayload[]): void {
    if (Array.isArray(item)) {
      this.queue.push(...item);
    } else {
      this.queue.push(item);
    }

    // Trigger non-blocking worker tick
    setImmediate(() => {
      this.processQueue();
    });
  }

  private async processQueue(): Promise<void> {
    if (this.isProcessing || this.queue.length === 0) return;
    this.isProcessing = true;

    while (this.queue.length > 0) {
      const item = this.queue.shift();
      if (!item) continue;

      try {
        await this.processItem(item);
      } catch (err: any) {
        console.error('[IngestQueue] Failed to process telemetry item:', err.message);
      }
    }

    this.isProcessing = false;
  }

  public async processItem(item: TelemetryPayload): Promise<void> {
    const {
      systemId,
      method,
      path,
      statusCode,
      latencyMs,
      clientIp,
      payloadSnippet,
      userAgent,
      queryLatencyMs,
      queryText,
      errorMessage,
    } = item;

    // 1. Save standard telemetry log
    await db.saveTelemetryLog({
      id: `tel-${Date.now()}-${Math.random().toString(36).substr(2, 6)}`,
      system_id: systemId,
      method: method || 'GET',
      path: path || '/',
      status_code: statusCode || 200,
      latency_ms: latencyMs || 10,
      client_ip: clientIp || '127.0.0.1',
      payload_snippet: payloadSnippet,
      user_agent: userAgent,
    });

    // 2. Track DB query metrics if reported
    if (queryLatencyMs !== undefined || queryText) {
      const isSlow = (queryLatencyMs || 0) > 200;
      await db.saveQueryMetric({
        id: `qm-${Date.now()}-${Math.random().toString(36).substr(2, 6)}`,
        system_id: systemId,
        query_text: queryText || 'SELECT * FROM records WHERE tenant_id = $1',
        duration_ms: queryLatencyMs || 50,
        pool_active_connections: isSlow ? 18 : 3,
        pool_idle_connections: isSlow ? 1 : 12,
        pool_waiting_queries: isSlow ? 8 : 0,
        exceeded_threshold: isSlow,
        created_at: new Date().toISOString(),
      });

      if (isSlow) {
        const diagnosis = advisorService.diagnose({
          queryDurationMs: queryLatencyMs,
          systemId,
        });

        if (diagnosis) {
          const incident = {
            id: `inc-query-${Date.now()}-${Math.random().toString(36).substr(2, 4)}`,
            system_id: systemId,
            incident_type: 'DATABASE_QUERY_REGRESSION',
            threat_classification: diagnosis.patternName,
            severity: diagnosis.severity,
            offending_ip: clientIp || '127.0.0.1',
            geo_country: 'Nigeria',
            geo_region: 'Abuja (FCT)',
            geo_city: 'Jabi - NOUN HQ',
            geo_lat: 9.0765,
            geo_lng: 7.3986,
            asn: 'AS37075',
            isp: 'Internal Campus Infrastructure',
            is_proxy_or_vpn: false,
            target_endpoint: path,
            http_method: method,
            captured_payload: queryText || `Query latency ${queryLatencyMs}ms`,
            status: 'UNRESOLVED' as const,
            mitigation_blueprint: diagnosis.codePatch,
            remediation_summary: diagnosis.incidentSummary,
            created_at_wat: getWATFormattedDate(),
          };

          await db.saveIncident(incident);
          await notificationDispatcher.dispatchIncidentAlert(incident);
        }
      }
    }

    // 3. Inspect for Threat Signatures (SQLi, XSS, Path Traversal)
    const threatMatch = heuristicEngine.evaluate({
      method,
      path,
      payload: payloadSnippet,
      userAgent,
      clientIp,
    });

    if (threatMatch.detected) {
      const geoProfile = await geoIPService.resolve(clientIp);

      const incident = {
        id: `inc-threat-${Date.now()}-${Math.random().toString(36).substr(2, 5)}`,
        system_id: systemId,
        incident_type: threatMatch.incidentType,
        threat_classification: threatMatch.threatClassification,
        severity: threatMatch.severity,
        offending_ip: clientIp,
        geo_country: geoProfile.country,
        geo_region: geoProfile.region,
        geo_city: geoProfile.city,
        geo_lat: geoProfile.latitude,
        geo_lng: geoProfile.longitude,
        asn: geoProfile.asn,
        isp: geoProfile.isp,
        is_proxy_or_vpn: geoProfile.isProxyOrVpn,
        target_endpoint: path,
        http_method: method,
        captured_payload: payloadSnippet || path,
        status: 'UNRESOLVED' as const,
        mitigation_blueprint: threatMatch.mitigationBlueprint,
        remediation_summary: threatMatch.remediationSummary,
        created_at_wat: getWATFormattedDate(),
      };

      await db.saveIncident(incident);
      await notificationDispatcher.dispatchIncidentAlert(incident);
      return;
    }

    // 4. Inspect for DDoS & Credential Stuffing Anomaly
    const anomaly = await ddosDetector.trackAndInspect({
      clientIp,
      path,
      statusCode,
    });

    if (anomaly.isAnomaly) {
      const geoProfile = await geoIPService.resolve(clientIp);

      const incident = {
        id: `inc-anomaly-${Date.now()}-${Math.random().toString(36).substr(2, 5)}`,
        system_id: systemId,
        incident_type: anomaly.anomalyType,
        threat_classification: anomaly.anomalyType === 'DDOS_RATE_SPIKE' ? 'DDoS Volumetric Traffic Spike' : 'Credential Stuffing Brute Force',
        severity: anomaly.severity,
        offending_ip: clientIp,
        geo_country: geoProfile.country,
        geo_region: geoProfile.region,
        geo_city: geoProfile.city,
        geo_lat: geoProfile.latitude,
        geo_lng: geoProfile.longitude,
        asn: geoProfile.asn,
        isp: geoProfile.isp,
        is_proxy_or_vpn: geoProfile.isProxyOrVpn,
        target_endpoint: path,
        http_method: method,
        captured_payload: `Anomaly: ${anomaly.description}`,
        status: 'UNRESOLVED' as const,
        mitigation_blueprint: anomaly.mitigationBlueprint,
        remediation_summary: anomaly.description,
        created_at_wat: getWATFormattedDate(),
      };

      await db.saveIncident(incident);
      await notificationDispatcher.dispatchIncidentAlert(incident);
      return;
    }

    // 5. Inspect 5xx server errors for Self-Healing Advisor
    if (statusCode >= 500 || errorMessage) {
      const diagnosis = advisorService.diagnose({
        errorMessage: errorMessage || `HTTP ${statusCode} internal error on ${path}`,
        targetPath: path,
        systemId,
      });

      if (diagnosis) {
        const geoProfile = await geoIPService.resolve(clientIp);

        const incident = {
          id: `inc-err-${Date.now()}-${Math.random().toString(36).substr(2, 5)}`,
          system_id: systemId,
          incident_type: 'INFRASTRUCTURE_REGRESSION',
          threat_classification: diagnosis.patternName,
          severity: diagnosis.severity,
          offending_ip: clientIp,
          geo_country: geoProfile.country,
          geo_region: geoProfile.region,
          geo_city: geoProfile.city,
          geo_lat: geoProfile.latitude,
          geo_lng: geoProfile.longitude,
          asn: geoProfile.asn,
          isp: geoProfile.isp,
          is_proxy_or_vpn: false,
          target_endpoint: path,
          http_method: method,
          captured_payload: errorMessage || `5xx Server Error Trace on ${path}`,
          status: 'UNRESOLVED' as const,
          mitigation_blueprint: diagnosis.codePatch,
          remediation_summary: diagnosis.incidentSummary,
          created_at_wat: getWATFormattedDate(),
        };

        await db.saveIncident(incident);
        await notificationDispatcher.dispatchIncidentAlert(incident);
      }
    }
  }
}

export const ingestQueue = new IngestQueue();
