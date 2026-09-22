import { Pool, QueryResult } from 'pg';
import { CONFIG, REGISTERED_TENANTS, DEFAULT_PROBES } from '../config';
import fs from 'fs';
import path from 'path';

export interface TelemetryLog {
  id: string;
  system_id: string;
  method: string;
  path: string;
  status_code: number;
  latency_ms: number;
  client_ip: string;
  payload_snippet?: string;
  user_agent?: string;
  headers_json?: string;
  created_at?: string;
}

export interface ThreatIncident {
  id: string;
  system_id: string;
  incident_type: string;
  threat_classification: string;
  severity: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
  offending_ip: string;
  geo_country: string;
  geo_region: string;
  geo_city: string;
  geo_lat: number;
  geo_lng: number;
  asn: string;
  isp: string;
  is_proxy_or_vpn: boolean;
  target_endpoint: string;
  http_method: string;
  captured_payload: string;
  status: 'UNRESOLVED' | 'ACKNOWLEDGED' | 'RESOLVED';
  mitigation_blueprint: string;
  remediation_summary?: string;
  created_at_wat: string;
  created_at?: string;
  acknowledged_by?: string;
  resolved_at?: string;
}

export interface SyntheticProbe {
  id: string;
  system_id: string;
  name: string;
  target_url: string;
  method: string;
  expected_status: number;
  interval_seconds: number;
  is_enabled: boolean;
  last_run_at?: string;
  last_status: 'HEALTHY' | 'DEGRADED' | 'DOWN' | 'PENDING';
  last_ttfb_ms: number;
  last_dns_ms: number;
  last_tcp_ms: number;
  ssl_expiry_days?: number;
  uptime_percent: number;
  created_at?: string;
}

export interface ProbeHistoryRecord {
  id: string;
  probe_id: string;
  system_id: string;
  status_code?: number;
  ttfb_ms: number;
  dns_ms: number;
  tcp_ms: number;
  ssl_valid: boolean;
  ssl_days_remaining?: number;
  is_success: boolean;
  error_message?: string;
  checked_at: string;
}

export interface DatabaseQueryMetric {
  id: string;
  system_id: string;
  query_text: string;
  duration_ms: number;
  pool_active_connections: number;
  pool_idle_connections: number;
  pool_waiting_queries: number;
  exceeded_threshold: boolean; // >200ms
  created_at: string;
}

export interface AuditReportRecord {
  id: string;
  report_title: string;
  system_id: string;
  format: 'PDF' | 'CSV';
  period_start?: string;
  period_end?: string;
  health_score: number;
  total_incidents: number;
  file_path: string;
  generated_at_wat: string;
  created_at?: string;
}

/**
 * Format current date in West Africa Time (WAT / UTC+1)
 */
export function getWATFormattedDate(d: Date = new Date()): string {
  const options: Intl.DateTimeFormatOptions = {
    timeZone: CONFIG.TIMEZONE,
    year: 'numeric',
    month: 'short',
    day: '2-digit',
    hour: '2-digit',
    minute: '2-digit',
    second: '2-digit',
    hour12: false,
  };
  return new Intl.DateTimeFormat('en-GB', options).format(d) + ' WAT';
}

class DatabaseManager {
  private pgPool: Pool | null = null;
  private isPostgresConnected = false;

  // Embedded store for local dev & zero-config operation
  private memoryStore = {
    tenants: new Map<string, any>(),
    telemetryLogs: [] as TelemetryLog[],
    threatIncidents: [] as ThreatIncident[],
    syntheticProbes: new Map<string, SyntheticProbe>(),
    probeHistory: [] as ProbeHistoryRecord[],
    queryMetrics: [] as DatabaseQueryMetric[],
    auditReports: [] as AuditReportRecord[],
  };

  constructor() {
    if (CONFIG.DATABASE_URL) {
      try {
        this.pgPool = new Pool({
          connectionString: CONFIG.DATABASE_URL,
          max: 20,
          idleTimeoutMillis: 30000,
          connectionTimeoutMillis: 5000,
        });
      } catch (err) {
        console.warn('[DB] PostgreSQL init skipped, utilizing embedded memory store.');
      }
    }
  }

  public async initialize(): Promise<void> {
    if (this.pgPool) {
      try {
        const client = await this.pgPool.connect();
        const schemaPath = path.join(__dirname, 'schema.sql');
        if (fs.existsSync(schemaPath)) {
          const sql = fs.readFileSync(schemaPath, 'utf-8');
          await client.query(sql);
        }
        client.release();
        this.isPostgresConnected = true;
        console.log('[DB] Connected to PostgreSQL successfully.');
      } catch (err) {
        console.warn('[DB] Could not connect to PostgreSQL. Falling back to embedded in-memory repository.', (err as Error).message);
        this.isPostgresConnected = false;
      }
    }

    // Seed default tenants and probes
    await this.seedDefaults();
  }

  private async seedDefaults(): Promise<void> {
    // Seed Tenants
    for (const [key, tenant] of Object.entries(REGISTERED_TENANTS)) {
      this.memoryStore.tenants.set(tenant.systemId, {
        id: `tenant-${tenant.systemId.toLowerCase()}`,
        system_id: tenant.systemId,
        name: tenant.name,
        api_key: tenant.apiKey,
        api_secret: tenant.apiSecret,
        primary_contact: tenant.primaryContact,
        enabled: tenant.enabled,
        created_at: new Date().toISOString(),
      });
    }

    // Seed Default Probes
    for (const probe of DEFAULT_PROBES) {
      this.memoryStore.syntheticProbes.set(probe.id, {
        id: probe.id,
        system_id: probe.systemId,
        name: probe.name,
        target_url: probe.targetUrl,
        method: probe.method,
        expected_status: probe.expectedStatus,
        interval_seconds: probe.intervalSeconds,
        is_enabled: probe.enabled,
        last_run_at: new Date().toISOString(),
        last_status: 'HEALTHY',
        last_ttfb_ms: 45.2,
        last_dns_ms: 12.1,
        last_tcp_ms: 18.4,
        ssl_expiry_days: 84,
        uptime_percent: 99.98,
        created_at: new Date().toISOString(),
      });
    }
  }

  // ===================== TENANTS =====================
  public async getTenantByApiKey(apiKey: string): Promise<any | null> {
    if (this.isPostgresConnected && this.pgPool) {
      try {
        const res = await this.pgPool.query('SELECT * FROM tenants WHERE api_key = $1 AND enabled = true', [apiKey]);
        return res.rows[0] || null;
      } catch (e) {
        // fallback
      }
    }
    for (const tenant of this.memoryStore.tenants.values()) {
      if (tenant.api_key === apiKey && tenant.enabled) {
        return tenant;
      }
    }
    return null;
  }

  public async getTenantBySystemId(systemId: string): Promise<any | null> {
    if (this.isPostgresConnected && this.pgPool) {
      try {
        const res = await this.pgPool.query('SELECT * FROM tenants WHERE system_id = $1', [systemId]);
        return res.rows[0] || null;
      } catch (e) {
        // fallback
      }
    }
    return this.memoryStore.tenants.get(systemId) || null;
  }

  public async getAllTenants(): Promise<any[]> {
    if (this.isPostgresConnected && this.pgPool) {
      try {
        const res = await this.pgPool.query('SELECT * FROM tenants ORDER BY system_id ASC');
        return res.rows;
      } catch (e) {}
    }
    return Array.from(this.memoryStore.tenants.values());
  }

  // ===================== TELEMETRY LOGS =====================
  public async saveTelemetryLog(log: TelemetryLog): Promise<void> {
    if (!log.id) log.id = `tel-${Date.now()}-${Math.random().toString(36).substr(2, 6)}`;
    if (!log.created_at) log.created_at = new Date().toISOString();

    if (this.isPostgresConnected && this.pgPool) {
      try {
        await this.pgPool.query(
          `INSERT INTO telemetry_logs (id, system_id, method, path, status_code, latency_ms, client_ip, payload_snippet, user_agent, headers_json, created_at)
           VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)`,
          [
            log.id,
            log.system_id,
            log.method,
            log.path,
            log.status_code,
            log.latency_ms,
            log.client_ip,
            log.payload_snippet || null,
            log.user_agent || null,
            log.headers_json || null,
            log.created_at,
          ]
        );
      } catch (e) {}
    }

    this.memoryStore.telemetryLogs.unshift(log);
    // Keep max 2000 in memory for high efficiency
    if (this.memoryStore.telemetryLogs.length > 2000) {
      this.memoryStore.telemetryLogs.length = 2000;
    }
  }

  public async getTelemetryLogs(systemId?: string, limit: number = 50): Promise<TelemetryLog[]> {
    if (this.isPostgresConnected && this.pgPool) {
      try {
        const query = systemId
          ? 'SELECT * FROM telemetry_logs WHERE system_id = $1 ORDER BY created_at DESC LIMIT $2'
          : 'SELECT * FROM telemetry_logs ORDER BY created_at DESC LIMIT $1';
        const params = systemId ? [systemId, limit] : [limit];
        const res = await this.pgPool.query(query, params);
        return res.rows;
      } catch (e) {}
    }

    let logs = this.memoryStore.telemetryLogs;
    if (systemId) {
      logs = logs.filter((l) => l.system_id === systemId);
    }
    return logs.slice(0, limit);
  }

  // ===================== THREAT INCIDENTS =====================
  public async saveIncident(incident: ThreatIncident): Promise<void> {
    if (!incident.id) incident.id = `inc-${Date.now()}-${Math.random().toString(36).substr(2, 6)}`;
    if (!incident.created_at) incident.created_at = new Date().toISOString();
    if (!incident.created_at_wat) incident.created_at_wat = getWATFormattedDate();
    if (!incident.status) incident.status = 'UNRESOLVED';

    if (this.isPostgresConnected && this.pgPool) {
      try {
        await this.pgPool.query(
          `INSERT INTO threat_incidents 
           (id, system_id, incident_type, threat_classification, severity, offending_ip, geo_country, geo_region, geo_city, geo_lat, geo_lng, asn, isp, is_proxy_or_vpn, target_endpoint, http_method, captured_payload, status, mitigation_blueprint, remediation_summary, created_at_wat, created_at)
           VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, $19, $20, $21, $22)`,
          [
            incident.id,
            incident.system_id,
            incident.incident_type,
            incident.threat_classification,
            incident.severity,
            incident.offending_ip,
            incident.geo_country,
            incident.geo_region,
            incident.geo_city,
            incident.geo_lat,
            incident.geo_lng,
            incident.asn,
            incident.isp,
            incident.is_proxy_or_vpn,
            incident.target_endpoint,
            incident.http_method,
            incident.captured_payload,
            incident.status,
            incident.mitigation_blueprint,
            incident.remediation_summary || null,
            incident.created_at_wat,
            incident.created_at,
          ]
        );
      } catch (e) {}
    }

    this.memoryStore.threatIncidents.unshift(incident);
    if (this.memoryStore.threatIncidents.length > 1000) {
      this.memoryStore.threatIncidents.length = 1000;
    }
  }

  public async getIncidents(options: {
    systemId?: string;
    severity?: string;
    status?: string;
    limit?: number;
  } = {}): Promise<ThreatIncident[]> {
    const { systemId, severity, status, limit = 50 } = options;

    if (this.isPostgresConnected && this.pgPool) {
      try {
        const conditions: string[] = [];
        const params: any[] = [];
        let pIdx = 1;

        if (systemId) {
          conditions.push(`system_id = $${pIdx++}`);
          params.push(systemId);
        }
        if (severity) {
          conditions.push(`severity = $${pIdx++}`);
          params.push(severity);
        }
        if (status) {
          conditions.push(`status = $${pIdx++}`);
          params.push(status);
        }

        const whereClause = conditions.length > 0 ? `WHERE ${conditions.join(' AND ')}` : '';
        params.push(limit);
        const query = `SELECT * FROM threat_incidents ${whereClause} ORDER BY created_at DESC LIMIT $${pIdx}`;
        const res = await this.pgPool.query(query, params);
        return res.rows;
      } catch (e) {}
    }

    let items = this.memoryStore.threatIncidents;
    if (systemId) items = items.filter((i) => i.system_id === systemId);
    if (severity) items = items.filter((i) => i.severity === severity);
    if (status) items = items.filter((i) => i.status === status);

    return items.slice(0, limit);
  }

  public async updateIncidentStatus(
    id: string,
    status: 'ACKNOWLEDGED' | 'RESOLVED',
    adminUser: string = 'Security-Admin'
  ): Promise<ThreatIncident | null> {
    const resolvedAt = status === 'RESOLVED' ? new Date().toISOString() : undefined;

    if (this.isPostgresConnected && this.pgPool) {
      try {
        const res = await this.pgPool.query(
          `UPDATE threat_incidents 
           SET status = $1, acknowledged_by = $2, resolved_at = $3 
           WHERE id = $4 RETURNING *`,
          [status, adminUser, resolvedAt || null, id]
        );
        if (res.rows.length > 0) return res.rows[0];
      } catch (e) {}
    }

    const inc = this.memoryStore.threatIncidents.find((i) => i.id === id);
    if (inc) {
      inc.status = status;
      inc.acknowledged_by = adminUser;
      if (resolvedAt) inc.resolved_at = resolvedAt;
      return inc;
    }
    return null;
  }

  // ===================== SYNTHETIC PROBES =====================
  public async getProbes(systemId?: string): Promise<SyntheticProbe[]> {
    if (this.isPostgresConnected && this.pgPool) {
      try {
        const query = systemId
          ? 'SELECT * FROM synthetic_probes WHERE system_id = $1 ORDER BY id ASC'
          : 'SELECT * FROM synthetic_probes ORDER BY id ASC';
        const params = systemId ? [systemId] : [];
        const res = await this.pgPool.query(query, params);
        return res.rows;
      } catch (e) {}
    }

    let probes = Array.from(this.memoryStore.syntheticProbes.values());
    if (systemId) {
      probes = probes.filter((p) => p.system_id === systemId);
    }
    return probes;
  }

  public async updateProbeMetrics(
    probeId: string,
    data: {
      status: 'HEALTHY' | 'DEGRADED' | 'DOWN';
      ttfbMs: number;
      dnsMs: number;
      tcpMs: number;
      sslExpiryDays?: number;
      isSuccess: boolean;
      errorMessage?: string;
    }
  ): Promise<void> {
    const now = new Date().toISOString();

    if (this.isPostgresConnected && this.pgPool) {
      try {
        await this.pgPool.query(
          `UPDATE synthetic_probes 
           SET last_status = $1, last_ttfb_ms = $2, last_dns_ms = $3, last_tcp_ms = $4,
               ssl_expiry_days = $5, last_run_at = $6
           WHERE id = $7`,
          [data.status, data.ttfbMs, data.dnsMs, data.tcpMs, data.sslExpiryDays || null, now, probeId]
        );
      } catch (e) {}
    }

    const probe = this.memoryStore.syntheticProbes.get(probeId);
    if (probe) {
      probe.last_status = data.status;
      probe.last_ttfb_ms = data.ttfbMs;
      probe.last_dns_ms = data.dnsMs;
      probe.last_tcp_ms = data.tcpMs;
      if (data.sslExpiryDays !== undefined) probe.ssl_expiry_days = data.sslExpiryDays;
      probe.last_run_at = now;

      // recalculate running uptime
      const history = this.memoryStore.probeHistory.filter((h) => h.probe_id === probeId);
      if (history.length > 0) {
        const successCount = history.filter((h) => h.is_success).length;
        probe.uptime_percent = Math.round((successCount / history.length) * 10000) / 100;
      }
    }

    // Save history record
    const historyRecord: ProbeHistoryRecord = {
      id: `ph-${Date.now()}-${Math.random().toString(36).substr(2, 6)}`,
      probe_id: probeId,
      system_id: probe ? probe.system_id : 'UNKNOWN',
      ttfb_ms: data.ttfbMs,
      dns_ms: data.dnsMs,
      tcp_ms: data.tcpMs,
      ssl_valid: (data.sslExpiryDays || 0) > 0,
      ssl_days_remaining: data.sslExpiryDays,
      is_success: data.isSuccess,
      error_message: data.errorMessage,
      checked_at: now,
    };

    this.memoryStore.probeHistory.unshift(historyRecord);
    if (this.memoryStore.probeHistory.length > 1000) {
      this.memoryStore.probeHistory.length = 1000;
    }
  }

  public async getProbeHistory(probeId: string, limit: number = 30): Promise<ProbeHistoryRecord[]> {
    let items = this.memoryStore.probeHistory.filter((h) => h.probe_id === probeId);
    return items.slice(0, limit);
  }

  // ===================== DATABASE QUERY METRICS =====================
  public async saveQueryMetric(metric: DatabaseQueryMetric): Promise<void> {
    if (!metric.id) metric.id = `qm-${Date.now()}-${Math.random().toString(36).substr(2, 6)}`;
    if (!metric.created_at) metric.created_at = new Date().toISOString();

    this.memoryStore.queryMetrics.unshift(metric);
    if (this.memoryStore.queryMetrics.length > 500) {
      this.memoryStore.queryMetrics.length = 500;
    }
  }

  public async getQueryMetrics(systemId?: string, slowOnly: boolean = false, limit: number = 50): Promise<DatabaseQueryMetric[]> {
    let list = this.memoryStore.queryMetrics;
    if (systemId) list = list.filter((q) => q.system_id === systemId);
    if (slowOnly) list = list.filter((q) => q.exceeded_threshold || q.duration_ms > 200);
    return list.slice(0, limit);
  }

  // ===================== AUDIT REPORTS =====================
  public async saveAuditReport(report: AuditReportRecord): Promise<void> {
    this.memoryStore.auditReports.unshift(report);
  }

  public async getAuditReports(systemId?: string): Promise<AuditReportRecord[]> {
    let reports = this.memoryStore.auditReports;
    if (systemId) reports = reports.filter((r) => r.system_id === systemId);
    return reports;
  }

  // ===================== OVERVIEW COMPUTATION =====================
  public async getSystemHealthOverview(systemId?: string) {
    const probes = await this.getProbes(systemId);
    const incidents = await this.getIncidents({ systemId, limit: 100 });
    const queryMetrics = await this.getQueryMetrics(systemId, false, 100);

    const unresolvedIncidents = incidents.filter((i) => i.status === 'UNRESOLVED');
    const criticalIncidents = unresolvedIncidents.filter((i) => i.severity === 'CRITICAL').length;
    const highIncidents = unresolvedIncidents.filter((i) => i.severity === 'HIGH').length;
    const medIncidents = unresolvedIncidents.filter((i) => i.severity === 'MEDIUM').length;

    // Calculate Platform Health Score (0-100%)
    let healthScore = 100;
    // Down probes deduct 25 points each
    const downProbes = probes.filter((p) => p.last_status === 'DOWN').length;
    const degradedProbes = probes.filter((p) => p.last_status === 'DEGRADED').length;
    healthScore -= downProbes * 25;
    healthScore -= degradedProbes * 10;
    // Critical incidents deduct 15 points each
    healthScore -= criticalIncidents * 15;
    healthScore -= highIncidents * 5;
    healthScore -= medIncidents * 2;
    // Slow queries deduct score
    const slowQueries = queryMetrics.filter((q) => q.duration_ms > 200).length;
    if (slowQueries > 5) healthScore -= 5;
    if (healthScore < 0) healthScore = 0;

    // Average TTFB
    const avgTtfb = probes.length > 0
      ? probes.reduce((acc, p) => acc + (p.last_ttfb_ms || 0), 0) / probes.length
      : 0;

    // Threat level calculation
    let threatLevel: 'NORMAL' | 'ELEVATED' | 'SEVERE' | 'CRITICAL' = 'NORMAL';
    if (criticalIncidents > 0 || unresolvedIncidents.length > 10) {
      threatLevel = 'CRITICAL';
    } else if (highIncidents > 0 || unresolvedIncidents.length > 5) {
      threatLevel = 'SEVERE';
    } else if (unresolvedIncidents.length > 0) {
      threatLevel = 'ELEVATED';
    }

    return {
      systemId: systemId || 'ALL_SYSTEMS',
      healthScore: Math.round(healthScore),
      threatLevel,
      probesCount: probes.length,
      probesHealthy: probes.filter((p) => p.last_status === 'HEALTHY').length,
      probesDegraded: degradedProbes,
      probesDown: downProbes,
      avgTtfbMs: Math.round(avgTtfb * 10) / 10,
      totalIncidents: incidents.length,
      unresolvedIncidents: unresolvedIncidents.length,
      criticalIncidents,
      highIncidents,
      slowQueriesCount: slowQueries,
      activeTenantsCount: (await this.getAllTenants()).length,
      timestampWat: getWATFormattedDate(),
    };
  }
}

export const db = new DatabaseManager();
