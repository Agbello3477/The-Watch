export interface SystemOverview {
  systemId: string;
  healthScore: number;
  threatLevel: 'NORMAL' | 'ELEVATED' | 'SEVERE' | 'CRITICAL';
  probesCount: number;
  probesHealthy: number;
  probesDegraded: number;
  probesDown: number;
  avgTtfbMs: number;
  totalIncidents: number;
  unresolvedIncidents: number;
  criticalIncidents: number;
  highIncidents: number;
  slowQueriesCount: number;
  activeTenantsCount: number;
  timestampWat: string;
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
  last_status: 'HEALTHY' | 'DEGRADED' | 'DOWN' | 'PENDING';
  last_ttfb_ms: number;
  last_dns_ms: number;
  last_tcp_ms: number;
  ssl_expiry_days?: number;
  uptime_percent: number;
  last_run_at?: string;
  history?: Array<{
    id: string;
    ttfb_ms: number;
    dns_ms: number;
    tcp_ms: number;
    is_success: boolean;
    checked_at: string;
  }>;
}

export interface ThreatMapNode {
  id: string;
  systemId: string;
  threatClassification: string;
  severity: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
  offendingIp: string;
  country: string;
  region: string;
  city: string;
  latitude: number;
  longitude: number;
  asn: string;
  isp: string;
  isProxyOrVpn: boolean;
  targetEndpoint: string;
  httpMethod: string;
  status: string;
  timestampWat: string;
}

export interface QueryMetric {
  id: string;
  system_id: string;
  query_text: string;
  duration_ms: number;
  pool_active_connections: number;
  pool_idle_connections: number;
  pool_waiting_queries: number;
  exceeded_threshold: boolean;
  created_at: string;
}

export interface QueryMetricsResponse {
  summary: {
    totalLogged: number;
    slowQueriesCount: number;
    avgDurationMs: number;
    maxDurationMs: number;
    poolActiveConnections: number;
    poolIdleConnections: number;
  };
  metrics: QueryMetric[];
}

export interface RemediationRecommendation {
  incidentId: string;
  systemId: string;
  threatClassification: string;
  severity: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
  targetEndpoint: string;
  createdAtWat: string;
  diagnosis: {
    id: string;
    patternName: string;
    incidentSummary: string;
    suspectedRootCause: string;
    severity: string;
    mitigationBlueprint: string;
    codePatch: string;
    infrastructureFix: string;
    recommendedAction: string;
  };
}

export interface AdvisorResponse {
  activeDiagnosesCount: number;
  activeDiagnoses: RemediationRecommendation[];
  allCatalogRules: any[];
}
