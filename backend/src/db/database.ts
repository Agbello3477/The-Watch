import { Pool } from 'pg';
import { CONFIG, REGISTERED_TENANTS, DEFAULT_PROBES } from '../config';
import crypto from 'crypto';
import fs from 'fs';
import path from 'path';

export interface User {
  id: string;
  email: string;
  password_hash: string;
  salt: string;
  full_name: string;
  role: 'SUPER_ADMIN' | 'SOC_ANALYST' | 'SECURITY_OPERATOR' | 'AUDITOR';
  status: 'ACTIVE' | 'SUSPENDED';
  allowed_systems: string; // 'ALL' or comma-separated systemIds
  failed_login_attempts: number;
  locked_until?: string | null;
  last_login_at?: string | null;
  last_login_ip?: string | null;
  created_by?: string;
  created_at?: string;
}

export interface UserAuditLog {
  id: string;
  user_id?: string;
  email: string;
  action: 'LOGIN_SUCCESS' | 'LOGIN_FAILED' | 'ACCOUNT_CREATED' | 'ACCOUNT_SUSPENDED' | 'ACCOUNT_ACTIVATED' | 'ACCOUNT_DELETED';
  ip_address: string;
  user_agent?: string;
  status: 'SUCCESS' | 'FAILED' | 'BLOCKED';
  details?: string;
  created_at_wat: string;
  created_at?: string;
}

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

/**
 * Helper to hash password using PBKDF2 with unique cryptographic salt
 */
export function hashPassword(password: string, salt?: string): { hash: string; salt: string } {
  const generatedSalt = salt || crypto.randomBytes(16).toString('hex');
  const hash = crypto.pbkdf2Sync(password, generatedSalt, 100000, 64, 'sha512').toString('hex');
  return { hash, salt: generatedSalt };
}

class DatabaseManager {
  private pgPool: Pool | null = null;
  private isPostgresConnected = false;

  // Embedded store for local dev & zero-config operation
  private memoryStore = {
    users: new Map<string, User>(),
    userAuditLogs: [] as UserAuditLog[],
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

    // Seed default users, tenants, and probes
    await this.seedDefaults();
  }

  private async seedDefaults(): Promise<void> {
    // 1. Seed Default Super Admin
    const superAdminEmail = 'abdulgaffarbello3477@gmail.com';
    const { hash, salt } = hashPassword('Agbello@3477');

    const superAdminUser: User = {
      id: 'usr-superadmin-001',
      email: superAdminEmail,
      password_hash: hash,
      salt,
      full_name: 'Abdulgaffar Bello (Super Admin)',
      role: 'SUPER_ADMIN',
      status: 'ACTIVE',
      allowed_systems: 'ALL',
      failed_login_attempts: 0,
      locked_until: null,
      created_by: 'SYSTEM_BOOTSTRAP',
      created_at: new Date().toISOString(),
    };

    if (this.isPostgresConnected && this.pgPool) {
      try {
        await this.pgPool.query(
          `INSERT INTO users (id, email, password_hash, salt, full_name, role, status, allowed_systems, failed_login_attempts, created_by, created_at)
           VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
           ON CONFLICT (email) DO NOTHING`,
          [
            superAdminUser.id,
            superAdminUser.email,
            superAdminUser.password_hash,
            superAdminUser.salt,
            superAdminUser.full_name,
            superAdminUser.role,
            superAdminUser.status,
            superAdminUser.allowed_systems,
            0,
            superAdminUser.created_by,
            superAdminUser.created_at,
          ]
        );
      } catch (e) {}
    }

    this.memoryStore.users.set(superAdminEmail, superAdminUser);

    // 2. Seed Default Institutional Operators
    const analystEmail = 'analyst.soc@noun.edu.ng';
    const { hash: aHash, salt: aSalt } = hashPassword('Analyst@2026');
    this.memoryStore.users.set(analystEmail, {
      id: 'usr-analyst-002',
      email: analystEmail,
      password_hash: aHash,
      salt: aSalt,
      full_name: 'Ibrahim Danjuma (Lead Analyst)',
      role: 'SOC_ANALYST',
      status: 'ACTIVE',
      allowed_systems: 'NOUN-HRMS,Clinic-EHR',
      failed_login_attempts: 0,
      locked_until: null,
      created_by: superAdminEmail,
      created_at: new Date(Date.now() - 86400000).toISOString(),
    });

    // 3. Seed Tenants
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

    // 4. Seed Default Probes
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

    // 5. Seed initial audit log
    this.saveUserAuditLog({
      id: 'ual-init-001',
      user_id: superAdminUser.id,
      email: superAdminEmail,
      action: 'ACCOUNT_CREATED',
      ip_address: '102.89.23.45',
      user_agent: 'The Watch Bootstrap Agent v2.4',
      status: 'SUCCESS',
      details: 'Super Admin master account initialized with cryptographic PBKDF2 hash',
      created_at_wat: getWATFormattedDate(),
      created_at: new Date().toISOString(),
    });
  }

  // ===================== USER MANAGEMENT =====================
  public async getUserByEmail(email: string): Promise<User | null> {
    const cleanEmail = email.toLowerCase().trim();

    if (this.isPostgresConnected && this.pgPool) {
      try {
        const res = await this.pgPool.query('SELECT * FROM users WHERE LOWER(email) = $1', [cleanEmail]);
        return res.rows[0] || null;
      } catch (e) {}
    }

    for (const user of this.memoryStore.users.values()) {
      if (user.email.toLowerCase() === cleanEmail) {
        return user;
      }
    }
    return null;
  }

  public async getUserById(id: string): Promise<User | null> {
    if (this.isPostgresConnected && this.pgPool) {
      try {
        const res = await this.pgPool.query('SELECT * FROM users WHERE id = $1', [id]);
        return res.rows[0] || null;
      } catch (e) {}
    }

    for (const user of this.memoryStore.users.values()) {
      if (user.id === id) {
        return user;
      }
    }
    return null;
  }

  public async getAllUsers(): Promise<Omit<User, 'password_hash' | 'salt'>[]> {
    if (this.isPostgresConnected && this.pgPool) {
      try {
        const res = await this.pgPool.query(
          'SELECT id, email, full_name, role, status, allowed_systems, failed_login_attempts, locked_until, last_login_at, last_login_ip, created_by, created_at FROM users ORDER BY created_at DESC'
        );
        return res.rows;
      } catch (e) {}
    }

    return Array.from(this.memoryStore.users.values()).map((u) => {
      const { password_hash, salt, ...safeUser } = u;
      return safeUser;
    });
  }

  public async saveUser(user: User): Promise<void> {
    if (!user.id) user.id = `usr-${Date.now()}-${Math.random().toString(36).substr(2, 6)}`;
    if (!user.created_at) user.created_at = new Date().toISOString();
    user.email = user.email.toLowerCase().trim();

    if (this.isPostgresConnected && this.pgPool) {
      try {
        await this.pgPool.query(
          `INSERT INTO users (id, email, password_hash, salt, full_name, role, status, allowed_systems, failed_login_attempts, created_by, created_at)
           VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)`,
          [
            user.id,
            user.email,
            user.password_hash,
            user.salt,
            user.full_name,
            user.role,
            user.status,
            user.allowed_systems || 'ALL',
            user.failed_login_attempts || 0,
            user.created_by || 'SUPER_ADMIN',
            user.created_at,
          ]
        );
      } catch (e) {}
    }

    this.memoryStore.users.set(user.email, user);
  }

  public async updateUserStatus(id: string, status: 'ACTIVE' | 'SUSPENDED'): Promise<User | null> {
    if (this.isPostgresConnected && this.pgPool) {
      try {
        const res = await this.pgPool.query('UPDATE users SET status = $1 WHERE id = $2 RETURNING *', [status, id]);
        if (res.rows.length > 0) return res.rows[0];
      } catch (e) {}
    }

    for (const user of this.memoryStore.users.values()) {
      if (user.id === id) {
        user.status = status;
        return user;
      }
    }
    return null;
  }

  public async updateUserLoginMetrics(id: string, ip: string): Promise<void> {
    const now = new Date().toISOString();

    if (this.isPostgresConnected && this.pgPool) {
      try {
        await this.pgPool.query(
          'UPDATE users SET last_login_at = $1, last_login_ip = $2, failed_login_attempts = 0, locked_until = NULL WHERE id = $3',
          [now, ip, id]
        );
      } catch (e) {}
    }

    for (const user of this.memoryStore.users.values()) {
      if (user.id === id) {
        user.last_login_at = now;
        user.last_login_ip = ip;
        user.failed_login_attempts = 0;
        user.locked_until = null;
        break;
      }
    }
  }

  public async incrementFailedLoginAttempts(email: string, lockUntil?: string): Promise<void> {
    const cleanEmail = email.toLowerCase().trim();

    if (this.isPostgresConnected && this.pgPool) {
      try {
        await this.pgPool.query(
          'UPDATE users SET failed_login_attempts = failed_login_attempts + 1, locked_until = COALESCE($1, locked_until) WHERE LOWER(email) = $2',
          [lockUntil || null, cleanEmail]
        );
      } catch (e) {}
    }

    const user = this.memoryStore.users.get(cleanEmail);
    if (user) {
      user.failed_login_attempts = (user.failed_login_attempts || 0) + 1;
      if (lockUntil) user.locked_until = lockUntil;
    }
  }

  public async deleteUser(id: string): Promise<boolean> {
    if (this.isPostgresConnected && this.pgPool) {
      try {
        const res = await this.pgPool.query('DELETE FROM users WHERE id = $1', [id]);
        return (res.rowCount || 0) > 0;
      } catch (e) {}
    }

    for (const [key, user] of this.memoryStore.users.entries()) {
      if (user.id === id) {
        this.memoryStore.users.delete(key);
        return true;
      }
    }
    return false;
  }

  // ===================== USER AUDIT LOGS =====================
  public async saveUserAuditLog(log: UserAuditLog): Promise<void> {
    if (!log.id) log.id = `ual-${Date.now()}-${Math.random().toString(36).substr(2, 6)}`;
    if (!log.created_at) log.created_at = new Date().toISOString();
    if (!log.created_at_wat) log.created_at_wat = getWATFormattedDate();

    if (this.isPostgresConnected && this.pgPool) {
      try {
        await this.pgPool.query(
          `INSERT INTO user_audit_logs (id, user_id, email, action, ip_address, user_agent, status, details, created_at_wat, created_at)
           VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)`,
          [
            log.id,
            log.user_id || null,
            log.email,
            log.action,
            log.ip_address,
            log.user_agent || null,
            log.status,
            log.details || null,
            log.created_at_wat,
            log.created_at,
          ]
        );
      } catch (e) {}
    }

    this.memoryStore.userAuditLogs.unshift(log);
    if (this.memoryStore.userAuditLogs.length > 2000) {
      this.memoryStore.userAuditLogs.length = 2000;
    }
  }

  public async getUserAuditLogs(limit: number = 100): Promise<UserAuditLog[]> {
    if (this.isPostgresConnected && this.pgPool) {
      try {
        const res = await this.pgPool.query('SELECT * FROM user_audit_logs ORDER BY created_at DESC LIMIT $1', [limit]);
        return res.rows;
      } catch (e) {}
    }

    return this.memoryStore.userAuditLogs.slice(0, limit);
  }

  // ===================== TENANTS =====================
  public async getTenantByApiKey(apiKey: string): Promise<any | null> {
    if (this.isPostgresConnected && this.pgPool) {
      try {
        const res = await this.pgPool.query('SELECT * FROM tenants WHERE api_key = $1 AND enabled = true', [apiKey]);
        return res.rows[0] || null;
      } catch (e) {}
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
      } catch (e) {}
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

      const history = this.memoryStore.probeHistory.filter((h) => h.probe_id === probeId);
      if (history.length > 0) {
        const successCount = history.filter((h) => h.is_success).length;
        probe.uptime_percent = Math.round((successCount / history.length) * 10000) / 100;
      }
    }

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

    let healthScore = 100;
    const downProbes = probes.filter((p) => p.last_status === 'DOWN').length;
    const degradedProbes = probes.filter((p) => p.last_status === 'DEGRADED').length;
    healthScore -= downProbes * 25;
    healthScore -= degradedProbes * 10;
    healthScore -= criticalIncidents * 15;
    healthScore -= highIncidents * 5;
    healthScore -= medIncidents * 2;
    const slowQueries = queryMetrics.filter((q) => q.duration_ms > 200).length;
    if (slowQueries > 5) healthScore -= 5;
    if (healthScore < 0) healthScore = 0;

    const avgTtfb = probes.length > 0
      ? probes.reduce((acc, p) => acc + (p.last_ttfb_ms || 0), 0) / probes.length
      : 0;

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
