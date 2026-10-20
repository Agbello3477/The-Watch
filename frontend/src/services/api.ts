import {
  SystemOverview,
  ThreatIncident,
  SyntheticProbe,
  ThreatMapNode,
  QueryMetricsResponse,
  AdvisorResponse,
  User,
  AuthSessionUser,
  LoginResponse,
  UserAuditLog,
  UsersListResponse,
  UserAuditLogsResponse,
  SocMetrics,
  SocCase,
  IpBlocklistEntry,
  IocEntry,
  SocPlaybook,
  DetectionRule,
  ShiftHandover,
} from '../types/dashboard';
import { buildClientSidePdfBinary, triggerBrowserBlobDownload } from '../utils/pdfExporter';

const rawApiUrl = (import.meta as any).env?.VITE_API_URL || '';
const API_BASE = rawApiUrl ? `${rawApiUrl.replace(/\/$/, '')}/api/v1` : '/api/v1';

export const authStorage = {
  getToken(): string | null {
    return localStorage.getItem('the_watch_token');
  },
  setToken(token: string) {
    localStorage.setItem('the_watch_token', token);
  },
  removeToken() {
    localStorage.removeItem('the_watch_token');
  },
  getUser(): AuthSessionUser | null {
    const data = localStorage.getItem('the_watch_user');
    if (!data) return null;
    try {
      return JSON.parse(data);
    } catch {
      return null;
    }
  },
  setUser(user: AuthSessionUser) {
    localStorage.setItem('the_watch_user', JSON.stringify(user));
  },
  removeUser() {
    localStorage.removeItem('the_watch_user');
  },
  clear() {
    this.removeToken();
    this.removeUser();
  },
};

function getAuthHeaders(): HeadersInit {
  const token = authStorage.getToken();
  const headers: Record<string, string> = {
    'Content-Type': 'application/json',
  };
  if (token) {
    headers['Authorization'] = `Bearer ${token}`;
  }
  return headers;
}

export const api = {
  // ================= AUTHENTICATION =================
  async login(credentials: { email: string; password: string }): Promise<LoginResponse> {
    const res = await fetch(`${API_BASE}/auth/login`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(credentials),
    });
    const data = await res.json();
    if (res.ok && data.success && data.token && data.user) {
      authStorage.setToken(data.token);
      authStorage.setUser(data.user);
    }
    return data;
  },

  async getMe(): Promise<{ user?: AuthSessionUser; sessionValid: boolean }> {
    try {
      const res = await fetch(`${API_BASE}/auth/me`, {
        headers: getAuthHeaders(),
      });
      if (!res.ok) {
        authStorage.clear();
        return { sessionValid: false };
      }
      return await res.json();
    } catch {
      return { sessionValid: false };
    }
  },

  async logout(): Promise<void> {
    try {
      await fetch(`${API_BASE}/auth/logout`, {
        method: 'POST',
        headers: getAuthHeaders(),
      });
    } finally {
      authStorage.clear();
    }
  },

  // ================= SUPER ADMIN USER MANAGEMENT =================
  async getUsers(): Promise<UsersListResponse> {
    const res = await fetch(`${API_BASE}/users`, {
      headers: getAuthHeaders(),
    });
    return res.json();
  },

  async createUser(userData: {
    email: string;
    fullName: string;
    password: string;
    role: 'SUPER_ADMIN' | 'SOC_ANALYST' | 'SECURITY_OPERATOR' | 'AUDITOR';
    allowedSystems?: string;
  }): Promise<{ success: boolean; user?: User; message?: string; error?: string }> {
    const res = await fetch(`${API_BASE}/users`, {
      method: 'POST',
      headers: getAuthHeaders(),
      body: JSON.stringify(userData),
    });
    return res.json();
  },

  async updateUserStatus(id: string, status: 'ACTIVE' | 'SUSPENDED'): Promise<{ success: boolean; user?: User; message?: string }> {
    const res = await fetch(`${API_BASE}/users/${id}/status`, {
      method: 'PATCH',
      headers: getAuthHeaders(),
      body: JSON.stringify({ status }),
    });
    return res.json();
  },

  async deleteUser(id: string): Promise<{ success: boolean; message?: string }> {
    const res = await fetch(`${API_BASE}/users/${id}`, {
      method: 'DELETE',
      headers: getAuthHeaders(),
    });
    return res.json();
  },

  async getUserAuditLogs(limit: number = 100, systemId?: string): Promise<UserAuditLogsResponse> {
    const params = new URLSearchParams({ limit: String(limit) });
    if (systemId && systemId !== 'ALL') params.append('systemId', systemId);
    const res = await fetch(`${API_BASE}/users/audit?${params.toString()}`, {
      headers: getAuthHeaders(),
    });
    return res.json();
  },

  async trackUserAction(data: {
    action: 'CLICK' | 'DOWNLOAD' | 'LOGIN_SUCCESS' | 'LOGIN_FAILED' | 'LOGOUT';
    systemId?: string;
    email?: string;
    fullName?: string;
    role?: string;
    details?: string;
    target?: string;
    clientIp?: string;
  }): Promise<void> {
    try {
      await fetch(`${API_BASE}/audit/track`, {
        method: 'POST',
        headers: getAuthHeaders(),
        body: JSON.stringify(data),
      });
    } catch {
      // Non-blocking telemetry
    }
  },

  // ================= SOC PLATFORM OPERATIONS =================
  async getOverview(systemId?: string): Promise<SystemOverview> {
    const query = systemId ? `?systemId=${encodeURIComponent(systemId)}` : '';
    const res = await fetch(`${API_BASE}/overview${query}`, {
      headers: getAuthHeaders(),
    });
    return res.json();
  },

  async getIncidents(options: {
    systemId?: string;
    severity?: string;
    status?: string;
    limit?: number;
  } = {}): Promise<ThreatIncident[]> {
    const params = new URLSearchParams();
    if (options.systemId) params.append('systemId', options.systemId);
    if (options.severity && options.severity !== 'ALL') params.append('severity', options.severity);
    if (options.status && options.status !== 'ALL') params.append('status', options.status);
    if (options.limit) params.append('limit', String(options.limit));

    const res = await fetch(`${API_BASE}/incidents?${params.toString()}`, {
      headers: getAuthHeaders(),
    });
    return res.json();
  },

  async updateIncidentStatus(id: string, status: 'ACKNOWLEDGED' | 'RESOLVED'): Promise<ThreatIncident> {
    const user = authStorage.getUser();
    const adminUser = user ? `${user.fullName} (${user.role})` : 'Lead-SOC-Analyst';
    try {
      const res = await fetch(`${API_BASE}/incidents/${id}/status`, {
        method: 'PATCH',
        headers: getAuthHeaders(),
        body: JSON.stringify({ status, adminUser }),
      });
      if (res.ok) {
        return await res.json();
      }
    } catch (e) {
      console.warn('[API] PATCH /incidents/:id/status failed, attempting POST fallback:', e);
    }

    const postRes = await fetch(`${API_BASE}/incidents/${id}/status`, {
      method: 'POST',
      headers: getAuthHeaders(),
      body: JSON.stringify({ status, adminUser }),
    });
    return await postRes.json();
  },

  async getProbes(systemId?: string): Promise<SyntheticProbe[]> {
    const query = systemId ? `?systemId=${encodeURIComponent(systemId)}` : '';
    const res = await fetch(`${API_BASE}/probes${query}`, {
      headers: getAuthHeaders(),
    });
    return res.json();
  },

  async runProbe(id: string): Promise<any> {
    const res = await fetch(`${API_BASE}/probes/${id}/run`, {
      method: 'POST',
      headers: getAuthHeaders(),
    });
    return res.json();
  },

  async getThreatMap(systemId?: string): Promise<{ totalNodes: number; nodes: ThreatMapNode[] }> {
    const query = systemId ? `?systemId=${encodeURIComponent(systemId)}` : '';
    const res = await fetch(`${API_BASE}/threats/map${query}`, {
      headers: getAuthHeaders(),
    });
    return res.json();
  },

  async getIpIntelligence(ip: string): Promise<any> {
    const res = await fetch(`${API_BASE}/threats/intelligence/${encodeURIComponent(ip)}`, {
      headers: getAuthHeaders(),
    });
    return res.json();
  },

  async traceIp(ip: string): Promise<any> {
    const res = await fetch(`${API_BASE}/threats/trace/${encodeURIComponent(ip)}`, {
      headers: getAuthHeaders(),
    });
    return res.json();
  },

  async getQueryMetrics(systemId?: string, slowOnly: boolean = false): Promise<QueryMetricsResponse> {
    const params = new URLSearchParams();
    if (systemId) params.append('systemId', systemId);
    if (slowOnly) params.append('slowOnly', 'true');
    const res = await fetch(`${API_BASE}/queries?${params.toString()}`, {
      headers: getAuthHeaders(),
    });
    return res.json();
  },

  async getAdvisorRecommendations(systemId?: string): Promise<AdvisorResponse> {
    const query = systemId ? `?systemId=${encodeURIComponent(systemId)}` : '';
    const res = await fetch(`${API_BASE}/advisor/recommendations${query}`, {
      headers: getAuthHeaders(),
    });
    return res.json();
  },

  async triggerSimulation(scenario: string, systemId: string = 'NOUN-HRMS'): Promise<any> {
    const res = await fetch(`${API_BASE}/simulation/attack`, {
      method: 'POST',
      headers: getAuthHeaders(),
      body: JSON.stringify({ scenario, systemId }),
    });
    return res.json();
  },

  getPdfReportUrl(systemId?: string, incidentId?: string): string {
    const token = authStorage.getToken();
    const params = new URLSearchParams();
    if (systemId) params.append('systemId', systemId);
    if (incidentId) params.append('incidentId', incidentId);
    if (token) params.append('token', token);
    const qs = params.toString();
    return `${API_BASE}/reports/pdf${qs ? `?${qs}` : ''}`;
  },

  getCsvReportUrl(systemId?: string): string {
    const token = authStorage.getToken();
    const params = new URLSearchParams();
    if (systemId) params.append('systemId', systemId);
    if (token) params.append('token', token);
    const qs = params.toString();
    return `${API_BASE}/reports/csv${qs ? `?${qs}` : ''}`;
  },

  getAuditCsvReportUrl(systemId?: string): string {
    const token = authStorage.getToken();
    const params = new URLSearchParams();
    if (systemId && systemId !== 'ALL') params.append('systemId', systemId);
    if (token) params.append('token', token);
    const qs = params.toString();
    return `${API_BASE}/reports/audit-csv${qs ? `?${qs}` : ''}`;
  },

  /**
   * Guaranteed PDF Forensic & Audit Report Downloader
   * Fetches binary PDF from backend via Blob download (never blocked by popup blockers),
   * and falls back to client-side PDF 1.4 binary synthesis if backend is offline or sleeping.
   */
  async downloadPdfReport(options: {
    systemId?: string;
    incidentId?: string;
    incidentData?: any;
  } = {}): Promise<void> {
    const { systemId, incidentId, incidentData } = options;
    const filename = incidentId
      ? `TheWatch_Intrusion_Dossier_${incidentId}_${Date.now()}.pdf`
      : `TheWatch_Forensic_Audit_${systemId || 'AllSystems'}_${Date.now()}.pdf`;

    try {
      const url = this.getPdfReportUrl(
        systemId && systemId !== 'ALL' ? systemId : undefined,
        incidentId && !incidentId.startsWith('inc-wakeup-test-') ? incidentId : undefined
      );
      const res = await fetch(url, { headers: getAuthHeaders() });
      const contentType = res.headers.get('content-type') || '';

      if (res.ok && contentType.includes('application/pdf')) {
        const arrayBuffer = await res.arrayBuffer();
        if (arrayBuffer.byteLength > 100) {
          const blob = new Blob([arrayBuffer], { type: 'application/pdf' });
          triggerBrowserBlobDownload(blob, filename);
          return;
        }
      }
    } catch (err) {
      console.warn('[PDFDownload] Server PDF endpoint unreachable, using client-side PDF 1.4 generator:', err);
    }

    // Fallback: Gather available incidents and audit logs and build a valid binary PDF 1.4 directly in browser
    let incidents: any[] = [];
    let auditLogs: any[] = [];
    try {
      const [incRes, audRes] = await Promise.allSettled([
        this.getIncidents({ systemId: systemId !== 'ALL' ? systemId : undefined, limit: 25 }),
        this.getUserAuditLogs(25, systemId),
      ]);
      if (incRes.status === 'fulfilled' && Array.isArray(incRes.value)) incidents = incRes.value;
      if (audRes.status === 'fulfilled' && audRes.value?.logs) auditLogs = audRes.value.logs;
    } catch {}

    const pdfBytes = buildClientSidePdfBinary({
      systemId: systemId || 'NOUN-HRMS & THE WATCH SOC',
      incident: incidentData,
      incidents,
      auditLogs,
    });
    const blob = new Blob([pdfBytes as unknown as BlobPart], { type: 'application/pdf' });
    triggerBrowserBlobDownload(blob, filename);
  },

  /**
   * Guaranteed CSV Threat Report Downloader
   */
  async downloadCsvReport(systemId?: string): Promise<void> {
    const filename = `TheWatch_Threat_Incidents_${systemId || 'AllSystems'}_${Date.now()}.csv`;
    try {
      const url = this.getCsvReportUrl(systemId && systemId !== 'ALL' ? systemId : undefined);
      const res = await fetch(url, { headers: getAuthHeaders() });
      if (res.ok) {
        const text = await res.text();
        if (text && text.length > 10) {
          const blob = new Blob([text], { type: 'text/csv;charset=utf-8;' });
          triggerBrowserBlobDownload(blob, filename);
          return;
        }
      }
    } catch {}

    // Fallback CSV build
    let incidents: any[] = [];
    try {
      incidents = await this.getIncidents({ systemId: systemId !== 'ALL' ? systemId : undefined, limit: 200 });
    } catch {}
    const headers = ['IncidentID,SystemID,TimestampWAT,Severity,ThreatClassification,Status,OffendingIP,Country,City,ASN,HTTPMethod,TargetEndpoint,CapturedPayload'];
    const rows = (incidents || []).map((i: any) =>
      [i.id, i.system_id, i.created_at_wat, i.severity, i.threat_classification, i.status, i.offending_ip, i.geo_country, i.geo_city, i.asn, i.http_method, i.target_endpoint, i.captured_payload]
        .map((v) => `"${String(v || '').replace(/"/g, '""')}"`)
        .join(',')
    );
    const blob = new Blob([[...headers, ...rows].join('\n')], { type: 'text/csv;charset=utf-8;' });
    triggerBrowserBlobDownload(blob, filename);
  },

  /**
   * Guaranteed User Activity Audit Trail CSV Downloader
   */
  async downloadAuditCsvReport(systemId?: string): Promise<void> {
    const filename = `TheWatch_User_Audit_Trail_${systemId || 'AllSystems'}_${Date.now()}.csv`;
    try {
      const url = this.getAuditCsvReportUrl(systemId && systemId !== 'ALL' ? systemId : undefined);
      const res = await fetch(url, { headers: getAuthHeaders() });
      if (res.ok) {
        const text = await res.text();
        if (text && text.length > 10) {
          const blob = new Blob([text], { type: 'text/csv;charset=utf-8;' });
          triggerBrowserBlobDownload(blob, filename);
          return;
        }
      }
    } catch {}

    let logs: any[] = [];
    try {
      const res = await this.getUserAuditLogs(200, systemId);
      logs = res.logs || [];
    } catch {}
    const headers = ['AuditID,SystemID,TimestampWAT,Action,Status,FullName,Email,SystemRole,ClientIP,Location,Details'];
    const rows = logs.map((l: any) =>
      [l.id, l.system_id || 'NOUN-HRMS', l.created_at_wat, l.action, l.status, l.full_name || l.email, l.email, l.role, l.ip_address, l.location, l.details]
        .map((v) => `"${String(v || '').replace(/"/g, '""')}"`)
        .join(',')
    );
    const blob = new Blob([[...headers, ...rows].join('\n')], { type: 'text/csv;charset=utf-8;' });
    triggerBrowserBlobDownload(blob, filename);
  },

  /**
   * Reroutes intrusion / failover alerts to +2347063054357 & abdulgaffarbello3477@gmail.com
   */
  async rerouteAlertToMobileAndEmail(payload: {
    reason: 'SYSTEM_SLEEP_MODE' | 'SYSTEM_SHUTDOWN' | 'OPERATOR_UNREACHABLE' | 'MANUAL_MOBILE_REROUTE' | 'ONLINE_ACTIVE';
    systemId?: string;
    incident?: any;
    customMessage?: string;
  }): Promise<any> {
    try {
      const res = await fetch(`${API_BASE}/threats/reroute-alert`, {
        method: 'POST',
        headers: getAuthHeaders(),
        body: JSON.stringify(payload),
        keepalive: true,
      });
      return await res.json();
    } catch (err) {
      return {
        success: true,
        phone: '+2347063054357',
        email: 'abdulgaffarbello3477@gmail.com',
        fallback: true,
      };
    }
  },

  // ─── STANDARD SOC OPERATIONS APIS ─────────────────────────
  async getSocMetrics(): Promise<SocMetrics> {
    const res = await fetch(`${API_BASE}/soc/metrics`, {
      headers: getAuthHeaders(),
    });
    return res.json();
  },

  async getSocCases(filters?: { severity?: string; tier?: string; status?: string; systemId?: string }): Promise<{ cases: SocCase[]; total: number }> {
    const params = new URLSearchParams();
    if (filters?.severity) params.append('severity', filters.severity);
    if (filters?.tier) params.append('tier', filters.tier);
    if (filters?.status) params.append('status', filters.status);
    if (filters?.systemId) params.append('systemId', filters.systemId);
    const res = await fetch(`${API_BASE}/soc/cases?${params.toString()}`, {
      headers: getAuthHeaders(),
    });
    return res.json();
  },

  async addSocCaseNote(id: string, text: string, author?: string, authorRole?: string): Promise<any> {
    const res = await fetch(`${API_BASE}/soc/cases/${encodeURIComponent(id)}/notes`, {
      method: 'POST',
      headers: getAuthHeaders(),
      body: JSON.stringify({ text, author, authorRole }),
    });
    return res.json();
  },

  async updateSocCaseStatus(id: string, status: string): Promise<SocCase> {
    const res = await fetch(`${API_BASE}/soc/cases/${encodeURIComponent(id)}/status`, {
      method: 'PATCH',
      headers: getAuthHeaders(),
      body: JSON.stringify({ status }),
    });
    return res.json();
  },

  async assignSocCase(id: string, analyst: string, tier?: string): Promise<SocCase> {
    const res = await fetch(`${API_BASE}/soc/cases/${encodeURIComponent(id)}/assign`, {
      method: 'PATCH',
      headers: getAuthHeaders(),
      body: JSON.stringify({ analyst, tier }),
    });
    return res.json();
  },

  async getSocBlocklist(): Promise<{ blocklist: IpBlocklistEntry[]; total: number }> {
    const res = await fetch(`${API_BASE}/soc/blocklist`, {
      headers: getAuthHeaders(),
    });
    return res.json();
  },

  async blockIp(data: { ip: string; reason: string; threatClassification?: string; systemId?: string; durationHours?: number }): Promise<IpBlocklistEntry> {
    const res = await fetch(`${API_BASE}/soc/blocklist`, {
      method: 'POST',
      headers: getAuthHeaders(),
      body: JSON.stringify(data),
    });
    return res.json();
  },

  async unblockIp(ip: string): Promise<any> {
    const res = await fetch(`${API_BASE}/soc/blocklist/${encodeURIComponent(ip)}`, {
      method: 'DELETE',
      headers: getAuthHeaders(),
    });
    return res.json();
  },

  async getSocIocs(): Promise<{ iocs: IocEntry[]; total: number }> {
    const res = await fetch(`${API_BASE}/soc/iocs`, {
      headers: getAuthHeaders(),
    });
    return res.json();
  },

  async addSocIoc(data: Partial<IocEntry>): Promise<IocEntry> {
    const res = await fetch(`${API_BASE}/soc/iocs`, {
      method: 'POST',
      headers: getAuthHeaders(),
      body: JSON.stringify(data),
    });
    return res.json();
  },

  async getSocPlaybooks(): Promise<{ playbooks: SocPlaybook[] }> {
    const res = await fetch(`${API_BASE}/soc/playbooks`, {
      headers: getAuthHeaders(),
    });
    return res.json();
  },

  async executeSocPlaybook(id: string, targetCaseId?: string): Promise<{ success: boolean; playbook: SocPlaybook; actionsTaken: string[] }> {
    const res = await fetch(`${API_BASE}/soc/playbooks/${encodeURIComponent(id)}/execute`, {
      method: 'POST',
      headers: getAuthHeaders(),
      body: JSON.stringify({ targetCaseId }),
    });
    return res.json();
  },

  async getSocRules(): Promise<{ rules: DetectionRule[] }> {
    const res = await fetch(`${API_BASE}/soc/rules`, {
      headers: getAuthHeaders(),
    });
    return res.json();
  },

  async toggleSocRule(id: string, enabled: boolean): Promise<DetectionRule> {
    const res = await fetch(`${API_BASE}/soc/rules/${encodeURIComponent(id)}/toggle`, {
      method: 'PATCH',
      headers: getAuthHeaders(),
      body: JSON.stringify({ enabled }),
    });
    return res.json();
  },

  async getSocShifts(): Promise<{ handovers: ShiftHandover[] }> {
    const res = await fetch(`${API_BASE}/soc/shifts`, {
      headers: getAuthHeaders(),
    });
    return res.json();
  },

  async createSocShift(data: { shiftName: string; leadAnalyst: string; analystsOnDuty?: string[]; handoffNotes: string; actionItems?: string[] }): Promise<ShiftHandover> {
    const res = await fetch(`${API_BASE}/soc/shifts`, {
      method: 'POST',
      headers: getAuthHeaders(),
      body: JSON.stringify(data),
    });
    return res.json();
  },
};
