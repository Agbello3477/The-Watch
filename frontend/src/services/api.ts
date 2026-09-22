import {
  SystemOverview,
  ThreatIncident,
  SyntheticProbe,
  ThreatMapNode,
  QueryMetricsResponse,
  AdvisorResponse,
} from '../types/dashboard';

const rawApiUrl = import.meta.env.VITE_API_URL || '';
const API_BASE = rawApiUrl ? `${rawApiUrl.replace(/\/$/, '')}/api/v1` : '/api/v1';

export const api = {
  async getOverview(systemId?: string): Promise<SystemOverview> {
    const query = systemId ? `?systemId=${encodeURIComponent(systemId)}` : '';
    const res = await fetch(`${API_BASE}/overview${query}`);
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

    const res = await fetch(`${API_BASE}/incidents?${params.toString()}`);
    return res.json();
  },

  async updateIncidentStatus(id: string, status: 'ACKNOWLEDGED' | 'RESOLVED'): Promise<ThreatIncident> {
    const res = await fetch(`${API_BASE}/incidents/${id}/status`, {
      method: 'PATCH',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ status, adminUser: 'Lead-SOC-Analyst' }),
    });
    return res.json();
  },

  async getProbes(systemId?: string): Promise<SyntheticProbe[]> {
    const query = systemId ? `?systemId=${encodeURIComponent(systemId)}` : '';
    const res = await fetch(`${API_BASE}/probes${query}`);
    return res.json();
  },

  async runProbe(id: string): Promise<any> {
    const res = await fetch(`${API_BASE}/probes/${id}/run`, { method: 'POST' });
    return res.json();
  },

  async getThreatMap(systemId?: string): Promise<{ totalNodes: number; nodes: ThreatMapNode[] }> {
    const query = systemId ? `?systemId=${encodeURIComponent(systemId)}` : '';
    const res = await fetch(`${API_BASE}/threats/map${query}`);
    return res.json();
  },

  async getIpIntelligence(ip: string): Promise<any> {
    const res = await fetch(`${API_BASE}/threats/intelligence/${encodeURIComponent(ip)}`);
    return res.json();
  },

  async getQueryMetrics(systemId?: string, slowOnly: boolean = false): Promise<QueryMetricsResponse> {
    const params = new URLSearchParams();
    if (systemId) params.append('systemId', systemId);
    if (slowOnly) params.append('slowOnly', 'true');
    const res = await fetch(`${API_BASE}/queries?${params.toString()}`);
    return res.json();
  },

  async getAdvisorRecommendations(systemId?: string): Promise<AdvisorResponse> {
    const query = systemId ? `?systemId=${encodeURIComponent(systemId)}` : '';
    const res = await fetch(`${API_BASE}/advisor/recommendations${query}`);
    return res.json();
  },

  async triggerSimulation(scenario: string, systemId: string = 'NOUN-HRMS'): Promise<any> {
    const res = await fetch(`${API_BASE}/simulation/attack`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ scenario, systemId }),
    });
    return res.json();
  },

  getPdfReportUrl(systemId?: string): string {
    return `${API_BASE}/reports/pdf${systemId ? `?systemId=${encodeURIComponent(systemId)}` : ''}`;
  },

  getCsvReportUrl(systemId?: string): string {
    return `${API_BASE}/reports/csv${systemId ? `?systemId=${encodeURIComponent(systemId)}` : ''}`;
  },
};
