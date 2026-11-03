import React from 'react';
import { ShieldCheck, AlertTriangle, Zap, Server, Database } from 'lucide-react';
import { SystemOverview } from '../types/dashboard';
import { SocSeverityBadge } from './SocThemeBadge';

interface HealthGaugeCardProps {
  overview: SystemOverview | null;
}

export const HealthGaugeCard: React.FC<HealthGaugeCardProps> = ({ overview }) => {
  const healthScore = overview ? overview.healthScore : 100;

  const getScoreRingStroke = (score: number) => {
    if (score >= 90) return '#10B981'; // Resolved / Normal Emerald Green
    if (score >= 70) return '#EAB308'; // Medium / P3 Warning Yellow
    return '#EF4444'; // Critical / P1 Vivid Red
  };

  const radius = 38;
  const circumference = 2 * Math.PI * radius;
  const strokeDashoffset = circumference - (healthScore / 100) * circumference;

  return (
    <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
      
      {/* 1. Health Score Circular Gauge */}
      <div className="bg-slate-900 border border-slate-700 rounded-xl p-5 shadow-sm flex items-center justify-between">
        <div>
          <span className="text-xs uppercase tracking-wider font-semibold text-slate-400">Platform Health Score</span>
          <div className="mt-1 flex items-baseline gap-2">
            <span className="text-3xl font-black text-slate-100">{healthScore}%</span>
            <SocSeverityBadge
              severity={healthScore >= 90 ? 'RESOLVED' : healthScore >= 70 ? 'MEDIUM' : 'CRITICAL'}
              label={healthScore >= 90 ? 'OPTIMAL' : healthScore >= 70 ? 'DEGRADED' : 'CRITICAL'}
            />
          </div>
          <p className="text-[11px] text-slate-500 mt-1">
            Calculated across probe TTFB, error spikes & SQLi heuristics
          </p>
        </div>

        <div className="relative w-24 h-24 flex items-center justify-center shrink-0">
          <svg className="w-24 h-24 transform -rotate-90">
            <circle
              cx="48"
              cy="48"
              r={radius}
              className="text-slate-700/40"
              strokeWidth="7"
              stroke="currentColor"
              fill="transparent"
            />
            <circle
              cx="48"
              cy="48"
              r={radius}
              stroke={getScoreRingStroke(healthScore)}
              strokeWidth="7"
              strokeDasharray={circumference}
              strokeDashoffset={strokeDashoffset}
              strokeLinecap="round"
              fill="transparent"
              className="transition-all duration-1000 ease-out"
            />
          </svg>
          <div className="absolute inset-0 flex flex-col items-center justify-center">
            <ShieldCheck className={`w-6 h-6 ${healthScore >= 90 ? 'text-emerald-400' : 'text-yellow-400'}`} />
          </div>
        </div>
      </div>

      {/* 2. Synthetic Heartbeat & Average TTFB */}
      <div className="bg-slate-900 border border-slate-700 rounded-xl p-5 shadow-sm flex flex-col justify-between">
        <div className="flex items-center justify-between">
          <span className="text-xs uppercase tracking-wider font-semibold text-slate-400">Synthetic Endpoint Probes</span>
          <div className="w-8 h-8 rounded-lg bg-blue-500/10 border border-blue-500/30 flex items-center justify-center">
            <Server className="w-4 h-4 text-blue-400" />
          </div>
        </div>

        <div className="mt-3 flex items-baseline gap-2">
          <span className="text-2xl font-black text-slate-100">
            {overview?.probesHealthy ?? 0}/{overview?.probesCount ?? 0}
          </span>
          <SocSeverityBadge severity="RESOLVED" label="UP & RUNNING" />
        </div>

        <div className="mt-2 pt-2 border-t border-slate-700 flex items-center justify-between text-xs text-slate-400">
          <span className="flex items-center gap-1">
            <Zap className="w-3.5 h-3.5 text-yellow-400" /> Avg TTFB:
          </span>
          <span className="font-mono font-bold text-slate-200">{overview?.avgTtfbMs ?? 0} ms</span>
        </div>
      </div>

      {/* 3. Threat Incidents Triage Counter */}
      <div className="bg-slate-900 border border-slate-700 rounded-xl p-5 shadow-sm flex flex-col justify-between">
        <div className="flex items-center justify-between">
          <span className="text-xs uppercase tracking-wider font-semibold text-slate-400">Unresolved Threats</span>
          <div className="w-8 h-8 rounded-lg bg-red-500/10 border border-red-500/30 flex items-center justify-center">
            <AlertTriangle className="w-4 h-4 text-red-400" />
          </div>
        </div>

        <div className="mt-3 flex items-baseline gap-2">
          <span className="text-2xl font-black text-slate-100">
            {overview?.unresolvedIncidents ?? 0}
          </span>
          <span className="text-xs font-semibold text-slate-400">Active Incidents</span>
        </div>

        <div className="mt-2 pt-2 border-t border-slate-700 flex items-center gap-2 text-xs">
          <SocSeverityBadge severity="CRITICAL" label={`${overview?.criticalIncidents ?? 0} Critical`} />
          <SocSeverityBadge severity="HIGH" label={`${overview?.highIncidents ?? 0} High`} />
        </div>
      </div>

      {/* 4. Query Observability & DB Saturation */}
      <div className="bg-slate-900 border border-slate-700 rounded-xl p-5 shadow-sm flex flex-col justify-between">
        <div className="flex items-center justify-between">
          <span className="text-xs uppercase tracking-wider font-semibold text-slate-400">Query Observability</span>
          <div className="w-8 h-8 rounded-lg bg-blue-500/10 border border-blue-500/30 flex items-center justify-center">
            <Database className="w-4 h-4 text-blue-400" />
          </div>
        </div>

        <div className="mt-3 flex items-baseline gap-2">
          <span className={`text-2xl font-black ${(overview?.slowQueriesCount || 0) > 0 ? 'text-yellow-400' : 'text-slate-100'}`}>
            {overview?.slowQueriesCount ?? 0}
          </span>
          <span className="text-xs font-semibold text-slate-400">Slow Queries (&gt;200ms)</span>
        </div>

        <div className="mt-2 pt-2 border-t border-slate-700 flex items-center justify-between text-xs text-slate-400">
          <span>Active Monitored Systems:</span>
          <span className="font-bold text-blue-400">{overview?.activeTenantsCount ?? 3} Tenants</span>
        </div>
      </div>

    </div>
  );
};
