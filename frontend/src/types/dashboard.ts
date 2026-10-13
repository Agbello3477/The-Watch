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

export interface User {
  id: string;
  email: string;
  full_name: string;
  role: 'SUPER_ADMIN' | 'SOC_ANALYST' | 'SECURITY_OPERATOR' | 'AUDITOR';
  status: 'ACTIVE' | 'SUSPENDED';
  allowed_systems: string;
  failed_login_attempts?: number;
  locked_until?: string | null;
  last_login_at?: string | null;
  last_login_ip?: string | null;
  created_by?: string;
  created_at?: string;
}

export interface AuthSessionUser {
  id: string;
  email: string;
  fullName: string;
  role: 'SUPER_ADMIN' | 'SOC_ANALYST' | 'SECURITY_OPERATOR' | 'AUDITOR';
  status: 'ACTIVE' | 'SUSPENDED';
  allowedSystems: string;
  lastLoginAt?: string;
  lastLoginIp?: string;
}

export interface LoginResponse {
  success: boolean;
  token?: string;
  user?: AuthSessionUser;
  error?: string;
  code?: 'INVALID_CREDENTIALS' | 'ACCOUNT_LOCKED' | 'ACCOUNT_SUSPENDED' | 'RATE_LIMITED';
  lockedUntil?: string;
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

export interface UsersListResponse {
  totalUsers: number;
  users: User[];
}

export interface UserAuditLogsResponse {
  totalLogs: number;
  logs: UserAuditLog[];
}

// ===================== SOC STANDARD OPERATIONS TYPES =====================
export interface SocMetrics {
  mttdSec: number;
  mttrMin: number;
  slaCompliancePercent: number;
  openCasesCount: number;
  p1CriticalCasesCount: number;
  p2HighCasesCount: number;
  activeBlocksCount: number;
  activeIocsCount: number;
  activePlaybooksCount: number;
  activeRulesCount: number;
  mitreDistribution: Record<string, number>;
  timestampWat: string;
}

export interface SocCaseNote {
  id: string;
  author: string;
  authorRole: string;
  text: string;
  createdAtWat: string;
}

export interface SocCase {
  id: string;
  incidentId?: string;
  title: string;
  systemId: string;
  severity: 'P1' | 'P2' | 'P3' | 'P4';
  tier: 'TIER_1' | 'TIER_2' | 'TIER_3';
  assignedAnalyst: string;
  status: 'TRIAGE' | 'INVESTIGATING' | 'CONTAINED' | 'RESOLVED' | 'CLOSED';
  slaDeadlineWat: string;
  isSlaBreached: boolean;
  mitreTactic: string;
  mitreTechnique: string;
  offendingIp: string;
  targetEndpoint: string;
  capturedPayload: string;
  containmentStatus: 'UNCONTAINED' | 'IP_BLOCKED' | 'HOST_ISOLATED' | 'SESSIONS_REVOKED';
  notes: SocCaseNote[];
  containmentActions: string[];
  createdAtWat: string;
  resolvedAtWat?: string;
  timeToDetectSec: number;
  timeToResolveMin?: number;
}

export interface IpBlocklistEntry {
  id: string;
  ip: string;
  reason: string;
  threatClassification: string;
  systemId: string;
  blockedBy: string;
  blockedAtWat: string;
  expiresAtWat: string;
  status: 'ACTIVE' | 'REVOKED';
  requestCountBlocked: number;
}

export interface IocEntry {
  id: string;
  type: 'IP' | 'DOMAIN' | 'HASH_SHA256' | 'REGEX_SIGNATURE' | 'USER_AGENT';
  value: string;
  threatActor?: string;
  severity: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
  confidence: number;
  mitreTactic: string;
  mitreTechnique: string;
  tags: string[];
  addedBy: string;
  firstSeenWat: string;
  lastSeenWat: string;
  status: 'ACTIVE' | 'WHITELISTED';
}

export interface PlaybookStep {
  id: string;
  order: number;
  title: string;
  description: string;
  actionType: 'BLOCK_IP' | 'REVOKE_SESSIONS' | 'NOTIFY_LEAD' | 'GENERATE_REPORT' | 'ISOLATE_HOST';
  automated: boolean;
  status: 'PENDING' | 'RUNNING' | 'COMPLETED' | 'SKIPPED';
  executedAtWat?: string;
}

export interface SocPlaybook {
  id: string;
  name: string;
  description: string;
  triggerEvent: string;
  mitreTactic: string;
  mitreTechnique: string;
  steps: PlaybookStep[];
  executionCount: number;
  lastRunWat?: string;
}

export interface DetectionRule {
  id: string;
  name: string;
  category: 'INJECTION' | 'CREDENTIAL_ACCESS' | 'DENIAL_OF_SERVICE' | 'EXFILTRATION' | 'ANOMALY';
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';
  mitreTactic: string;
  mitreTechnique: string;
  queryPattern: string;
  enabled: boolean;
  triggerCount: number;
  lastTriggeredWat?: string;
  description: string;
}

export interface ShiftHandover {
  id: string;
  shiftName: string;
  leadAnalyst: string;
  analystsOnDuty: string[];
  unresolvedP1P2Count: number;
  activeContainmentsCount: number;
  handoffNotes: string;
  actionItems: string[];
  handoverTimestampWat: string;
  status: 'ACTIVE' | 'ARCHIVED';
}


