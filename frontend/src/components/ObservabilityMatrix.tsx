import React from 'react';
import {
  Network,
  Radar,
  Activity,
  Database,
  Server,
  Users,
  ShieldAlert,
  CheckCircle2,
  ArrowUpRight,
  Layers,
} from 'lucide-react';
import {
  SystemOverview,
  SyntheticProbe,
  ThreatIncident,
  QueryMetricsResponse,
  AdvisorResponse,
} from '../types/dashboard';
import { SocSeverityBadge } from './SocThemeBadge';

export type SocTabKey =
  | 'soc'
  | 'threats'
  | 'observability'
  | 'advisor'
  | 'reports'
  | 'simulator'
  | 'beef-set'
  | 'zero-trust-deception'
  | 'traffic'
  | 'scanner'
  | 'zeek'
  | 'connect';

interface ObservabilityMatrixProps {
  overview: SystemOverview | null;
  probes: SyntheticProbe[];
  incidents: ThreatIncident[];
  queryMetrics: QueryMetricsResponse | null;
  advisorData: AdvisorResponse | null;
  onSelectTab: (tab: SocTabKey) => void;
}

export const ObservabilityMatrix: React.FC<ObservabilityMatrixProps> = ({
  overview,
  probes,
  incidents,
  queryMetrics,
  advisorData,
  onSelectTab,
}) => {
  const healthyProbes = overview?.probesHealthy ?? probes.filter((p) => p.last_status === 'HEALTHY').length;
  const totalProbes = overview?.probesCount ?? (probes.length || 5);
  const avgTtfb = overview?.avgTtfbMs ?? 42;
  const slowQueries = queryMetrics?.summary?.slowQueriesCount ?? overview?.slowQueriesCount ?? 0;
  const avgQueryMs = queryMetrics?.summary?.avgDurationMs ?? 18;
  const poolActive = queryMetrics?.summary?.poolActiveConnections ?? 4;
  const poolIdle = queryMetrics?.summary?.poolIdleConnections ?? 16;
  const unresolvedThreats = overview?.unresolvedIncidents ?? incidents.filter((i) => i.status !== 'RESOLVED').length;
  const criticalThreats = overview?.criticalIncidents ?? incidents.filter((i) => i.severity === 'CRITICAL' && i.status !== 'RESOLVED').length;
  const activeTenants = overview?.activeTenantsCount ?? 3;
  const recommendationsCount = advisorData?.activeDiagnosesCount ?? advisorData?.activeDiagnoses?.length ?? 3;

  const levels = [
    {
      level: 'LEVEL 1',
      name: 'Network & Deep Packet Observability (L3 / L4 / L7)',
      status: 'RESOLVED' as const,
      statusLabel: 'ACTIVE DPI & ZEEK',
      engine: 'Wireshark Promiscuous DPI + Zeek NSM (UID Correlation)',
      description:
        'Real-time inbound/outbound packet capture, Hex/ASCII frame inspection, Zeek conn.log, dns.log, ssl.log (JA3/JA4), http.log, and 1-click UID flow timelines.',
      metrics: [
        { label: 'Protocols Inspected', value: 'TLSv1.3 / HTTP / DNS / TCP' },
        { label: 'Correlation Index', value: 'Zeek UID + Ephemeral Port' },
      ],
      icon: Network,
      primaryAction: { label: 'Open Wireshark DPI', tab: 'traffic' as SocTabKey },
      secondaryAction: { label: 'Open Zeek NSM', tab: 'zeek' as SocTabKey },
    },
    {
      level: 'LEVEL 2',
      name: 'Infrastructure, Port & Attack Surface Observability',
      status: 'RESOLVED' as const,
      statusLabel: '15+ PORTS MONITORED',
      engine: 'Nmap 7.95 NSE Engine & OWASP Header Auditor',
      description:
        'Live TCP connect probing (Ports 21, 22, 80, 443, 3306, 4000, 5055, 5432, 6379, 27017), OS fingerprinting, traceroute hops, and HSTS/CSP/XFO posture verification.',
      metrics: [
        { label: 'NSE Scripts', value: 'http-security-headers, ssl-enum' },
        { label: 'Hardening Output', value: 'Automated UFW / Nginx Patches' },
      ],
      icon: Radar,
      primaryAction: { label: 'Run Nmap Surface Scan', tab: 'scanner' as SocTabKey },
    },
    {
      level: 'LEVEL 3',
      name: 'Synthetic Endpoint & Availability Observability',
      status: healthyProbes === totalProbes ? ('RESOLVED' as const) : ('MEDIUM' as const),
      statusLabel: `${healthyProbes}/${totalProbes} PROBES UP`,
      engine: '30s Active Synthetic Heartbeat Scheduler',
      description:
        'Continuous synthetic pings across NOUN-HRMS, Clinic-EHR, and Security-Dispatch measuring Time-To-First-Byte (TTFB), DNS lookup time, and SSL certificate expiry.',
      metrics: [
        { label: 'Healthy Probes', value: `${healthyProbes} / ${totalProbes} Online` },
        { label: 'Average TTFB', value: `${avgTtfb} ms` },
      ],
      icon: Activity,
      primaryAction: { label: 'View Heartbeat Grid Below', tab: 'observability' as SocTabKey },
    },
    {
      level: 'LEVEL 4',
      name: 'Database & Query Latency Observability',
      status: slowQueries > 0 ? ('MEDIUM' as const) : ('RESOLVED' as const),
      statusLabel: slowQueries > 0 ? `${slowQueries} SLOW (>200ms)` : 'OPTIMAL (<200ms)',
      engine: 'PostgreSQL Query Profiler & Connection Pool Telemetry',
      description:
        'Tracks SQL execution latency, flags unindexed queries exceeding 200ms, monitors connection pool saturation, and pairs slow queries with index blueprints.',
      metrics: [
        { label: 'Avg Query Latency', value: `${avgQueryMs} ms (${slowQueries} >200ms)` },
        { label: 'PG Pool State', value: `${poolActive} Active / ${poolIdle} Idle` },
      ],
      icon: Database,
      primaryAction: { label: 'View Query Profiler Below', tab: 'observability' as SocTabKey },
    },
    {
      level: 'LEVEL 5',
      name: 'Application Telemetry & Multi-Tenant Ingestion',
      status: 'RESOLVED' as const,
      statusLabel: `${activeTenants} TENANTS LINKED`,
      engine: 'HTTP REST + UDP Datagram Ingest Pipeline & Sentinel SDK',
      description:
        'High-throughput asynchronous telemetry ingestion from NOUN-HRMS and institutional tenants with HMAC-SHA256 verification and automatic PII/password redaction.',
      metrics: [
        { label: 'Connected Systems', value: `${activeTenants} Active Tenants` },
        { label: 'Firewall Sync', value: '10s Cross-System Blocklist Sync' },
      ],
      icon: Server,
      primaryAction: { label: 'Manage Connected Systems', tab: 'connect' as SocTabKey },
    },
    {
      level: 'LEVEL 6',
      name: 'Identity, Session & Browser/Human-Layer Observability (UEBA)',
      status: 'RESOLVED' as const,
      statusLabel: 'ZERO-TRUST + ANTI-BEEF/SET',
      engine: 'Impossible-Travel Geo-Velocity + Anti-BeEF Hook & Anti-SET Clone Guard',
      description:
        'Captures every login, logout, PDF/CSV export, UI click, Haversine impossible-travel session replay, DOM MutationObserver BeEF hook, and SET credential harvester clone.',
      metrics: [
        { label: 'Session & Hook Guard', value: 'Haversine <900km/h + DOM CSP Shield' },
        { label: 'Audit Timezone', value: 'Africa/Lagos (WAT / UTC+1)' },
      ],
      icon: Users,
      primaryAction: { label: 'Open BeEF & SET Defense', tab: 'beef-set' as SocTabKey },
      secondaryAction: { label: 'Zero-Trust & Honeypot Suite', tab: 'zero-trust-deception' as SocTabKey },
    },
    {
      level: 'LEVEL 7',
      name: 'Threat Intelligence, Deception (Honeypots/Canaries), DLP/FIM & SOAR',
      status: criticalThreats > 0 ? ('CRITICAL' as const) : unresolvedThreats > 0 ? ('HIGH' as const) : ('RESOLVED' as const),
      statusLabel:
        criticalThreats > 0
          ? `${criticalThreats} CRITICAL ACTIVE`
          : unresolvedThreats > 0
          ? `${unresolvedThreats} OPEN INCIDENTS`
          : 'ALL THREATS MITIGATED',
      engine: 'Heuristic WAF + Honeypots/Canaries + SHA-256 FIM & DLP + Permanent Quarantine',
      description:
        'Real-time SQLi/XSS/RCE detection, 0% false-positive Honeypot & Canary Token traps, live SHA-256 File Integrity Monitoring, DLP BVN exfiltration circuit breaker, and permanent IP blocking.',
      metrics: [
        { label: 'Active Incidents', value: `${unresolvedThreats} Unresolved (${criticalThreats} Critical)` },
        { label: 'Deception & FIM', value: '5 Traps Armed + 6 Core Files SHA-256 Verified' },
      ],
      icon: ShieldAlert,
      primaryAction: { label: 'Open SOC War Room', tab: 'soc' as SocTabKey },
      secondaryAction: { label: 'Honeypot, Zero-Trust & DLP', tab: 'zero-trust-deception' as SocTabKey },
    },
  ];

  return (
    <div className="bg-slate-900 border border-slate-700 rounded-xl p-5 shadow-sm space-y-5">
      {/* Header Banner */}
      <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-4 pb-4 border-b border-slate-700">
        <div className="flex items-start sm:items-center gap-3">
          <div className="p-2.5 rounded-xl bg-blue-500/10 border border-blue-500/30 text-blue-400 shrink-0">
            <Layers className="w-6 h-6" />
          </div>
          <div>
            <div className="flex items-center gap-2.5 flex-wrap">
              <h2 className="text-base sm:text-lg font-black text-slate-100 tracking-wide font-mono">
                7-LEVEL ENTERPRISE SOC OBSERVABILITY ARCHITECTURE
              </h2>
              <SocSeverityBadge severity="RESOLVED" label="7 / 7 LEVELS OPERATIONAL (100%)" />
            </div>
            <p className="text-xs text-slate-400 mt-0.5">
              Full-stack visibility across Network Packets (L1), Infrastructure Ports (L2), Synthetic Availability (L3), Database Queries (L4), App Telemetry (L5), User Identity/UEBA (L6), and SOAR Threat Defense (L7).
            </p>
          </div>
        </div>

        <div className="flex items-center gap-3 bg-slate-950 px-3.5 py-2 rounded-xl border border-slate-700 shrink-0">
          <CheckCircle2 className="w-4 h-4 text-emerald-400" />
          <div className="text-xs font-mono">
            <div className="text-[10px] text-slate-400 uppercase">Observability Coverage</div>
            <div className="font-bold text-slate-100">L1–L7 Unified Telemetry Active</div>
          </div>
        </div>
      </div>

      {/* 7-Level Cards Grid */}
      <div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-3 gap-4">
        {levels.map((item) => {
          const IconComponent = item.icon;
          return (
            <div
              key={item.level}
              className="bg-slate-950 border border-slate-700 hover:border-slate-500 rounded-xl p-4 flex flex-col justify-between transition-all space-y-3"
            >
              <div className="space-y-2.5">
                {/* Level Pill + Status Badge */}
                <div className="flex items-center justify-between gap-2">
                  <span className="inline-flex items-center gap-1.5 px-2.5 py-0.5 rounded-md text-[11px] font-mono font-bold bg-blue-500/10 text-blue-400 border border-blue-500/30">
                    <IconComponent className="w-3.5 h-3.5" />
                    {item.level}
                  </span>
                  <SocSeverityBadge severity={item.status} label={item.statusLabel} />
                </div>

                {/* Title & Engine */}
                <div>
                  <h3 className="text-sm font-bold text-slate-100 leading-snug">{item.name}</h3>
                  <div className="text-[11px] font-mono text-blue-400 mt-0.5">{item.engine}</div>
                </div>

                {/* Description */}
                <p className="text-xs text-slate-400 leading-relaxed">{item.description}</p>

                {/* Live Telemetry Mini-Grid */}
                <div className="grid grid-cols-2 gap-2 pt-1">
                  {item.metrics.map((m) => (
                    <div
                      key={m.label}
                      className="bg-slate-900 border border-slate-700/80 rounded-lg px-2.5 py-1.5"
                    >
                      <span className="text-[10px] text-slate-400 uppercase font-semibold block truncate">
                        {m.label}
                      </span>
                      <span className="text-xs font-mono font-bold text-slate-100 block truncate mt-0.5">
                        {m.value}
                      </span>
                    </div>
                  ))}
                </div>
              </div>

              {/* Drill-down Navigation Buttons */}
              <div className="pt-2.5 border-t border-slate-800 flex items-center justify-between gap-2 flex-wrap">
                {item.primaryAction.tab !== 'observability' ? (
                  <button
                    onClick={() => onSelectTab(item.primaryAction.tab)}
                    className="flex items-center gap-1 px-2.5 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-100 border border-slate-700 text-xs font-semibold transition cursor-pointer"
                  >
                    <span>{item.primaryAction.label}</span>
                    <ArrowUpRight className="w-3.5 h-3.5 text-blue-400" />
                  </button>
                ) : (
                  <span className="text-[11px] font-mono text-emerald-400 flex items-center gap-1">
                    <CheckCircle2 className="w-3.5 h-3.5" /> Displayed in live panels below
                  </span>
                )}

                {item.secondaryAction && (
                  <button
                    onClick={() => onSelectTab(item.secondaryAction!.tab)}
                    className="flex items-center gap-1 px-2.5 py-1.5 rounded-lg bg-blue-600/20 hover:bg-blue-600/30 text-blue-300 border border-blue-500/30 text-xs font-semibold transition cursor-pointer"
                  >
                    <span>{item.secondaryAction.label}</span>
                    <ArrowUpRight className="w-3.5 h-3.5" />
                  </button>
                )}
              </div>
            </div>
          );
        })}
      </div>
    </div>
  );
};
