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
} from '../types/dashboard';

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

  async getUserAuditLogs(limit: number = 100): Promise<UserAuditLogsResponse> {
    const res = await fetch(`${API_BASE}/users/audit?limit=${limit}`, {
      headers: getAuthHeaders(),
    });
    return res.json();
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
    const res = await fetch(`${API_BASE}/incidents/${id}/status`, {
      method: 'PATCH',
      headers: getAuthHeaders(),
      body: JSON.stringify({ status, adminUser }),
    });
    return res.json();
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

  getPdfReportUrl(systemId?: string): string {
    const token = authStorage.getToken();
    const params = new URLSearchParams();
    if (systemId) params.append('systemId', systemId);
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
};
