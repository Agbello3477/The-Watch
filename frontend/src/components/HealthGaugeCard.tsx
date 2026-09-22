import React from 'react';
import { ShieldCheck, AlertTriangle, Zap, Server, Database, Globe } from 'lucide-react';
import { SystemOverview } from '../types/dashboard';

interface HealthGaugeCardProps {
  overview: SystemOverview | null;
}

export const HealthGaugeCard: React.FC<HealthGaugeCardProps> = ({ overview }) => {
  const healthScore = overview ? overview.healthScore : 100;
  
  const getScoreColor = (score: number) => {
    if (score >= 90) return 'text-emerald-400 border-emerald-500/30 bg-emerald-500/10';
    if (score >= 70) return 'text-yellow-400 border-yellow-500/30 bg-yellow-500/10';
    return 'text-red-400 border-red-500/30 bg-red-500/10';
  };

  const getScoreRingStroke = (score: number) => {
    if (score >= 90) return '#10b981'; // emerald-500
    if (score >= 70) return '#eab308'; // yellow-500
    return '#ef4444'; // red-500
  };

  const radius = 38;
  const circumference = 2 * Math.PI * radius;
  const strokeDashoffset = circumference - (healthScore / 100) * circumference;

  return (
    <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
      
      {/* 1. Health Score Circular Gauge */}
      <div className="bg-slate-900/80 border border-slate-800 rounded-xl p-5 shadow-sm flex items-center justify-between">
        <div>
          <span className="text-xs uppercase tracking-wider font-semibold text-slate-400">Platform Health Score</span>
          <div className="mt-1 flex items-baseline gap-2">
            <span className="text-3xl font-black text-white">{healthScore}%</span>
            <span className="text-xs font-semibold text-slate-400">
              {healthScore >= 90 ? 'OPTIMAL' : healthScore >= 70 ? 'DEGRADED' : 'CRITICAL'}
            </span>
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
              className="text-slate-800"
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
      <div className="bg-slate-900/80 border border-slate-800 rounded-xl p-5 shadow-sm flex flex-col justify-between">
        <div className="flex items-center justify-between">
          <span className="text-xs uppercase tracking-wider font-semibold text-slate-400">Synthetic Endpoint Probes</span>
          <div className="w-8 h-8 rounded-lg bg-cyan-500/10 border border-cyan-500/30 flex items-center justify-center">
            <Server className="w-4 h-4 text-cyan-400" />
          </div>
        </div>

        <div className="mt-3 flex items-baseline gap-2">
          <span className="text-2xl font-black text-white">
            {overview?.probesHealthy ?? 0}/{overview?.probesCount ?? 0}
          </span>
          <span className="text-xs font-semibold text-emerald-400">UP & RUNNING</span>
        </div>

        <div className="mt-2 pt-2 border-t border-slate-800 flex items-center justify-between text-xs text-slate-400">
          <span className="flex items-center gap-1">
            <Zap className="w-3.5 h-3.5 text-yellow-400" /> Avg TTFB:
          </span>
          <span className="font-mono font-bold text-slate-200">{overview?.avgTtfbMs ?? 0} ms</span>
        </div>
      </div>

      {/* 3. Threat Incidents Triage Counter */}
      <div className="bg-slate-900/80 border border-slate-800 rounded-xl p-5 shadow-sm flex flex-col justify-between">
        <div className="flex items-center justify-between">
          <span className="text-xs uppercase tracking-wider font-semibold text-slate-400">Unresolved Threats</span>
          <div className="w-8 h-8 rounded-lg bg-red-500/10 border border-red-500/30 flex items-center justify-center">
            <AlertTriangle className="w-4 h-4 text-red-400" />
          </div>
        </div>

        <div className="mt-3 flex items-baseline gap-2">
          <span className="text-2xl font-black text-white">
            {overview?.unresolvedIncidents ?? 0}
          </span>
          <span className="text-xs font-semibold text-slate-400">Active Incidents</span>
        </div>

        <div className="mt-2 pt-2 border-t border-slate-800 flex items-center gap-2 text-xs">
          <span className="bg-red-500/20 text-red-400 border border-red-500/30 px-2 py-0.5 rounded text-[11px] font-bold">
            {overview?.criticalIncidents ?? 0} Critical
          </span>
          <span className="bg-orange-500/20 text-orange-400 border border-orange-500/30 px-2 py-0.5 rounded text-[11px] font-bold">
            {overview?.highIncidents ?? 0} High
          </span>
        </div>
      </div>

      {/* 4. Query Observability & DB Saturation */}
      <div className="bg-slate-900/80 border border-slate-800 rounded-xl p-5 shadow-sm flex flex-col justify-between">
        <div className="flex items-center justify-between">
          <span className="text-xs uppercase tracking-wider font-semibold text-slate-400">Query Observability</span>
          <div className="w-8 h-8 rounded-lg bg-indigo-500/10 border border-indigo-500/30 flex items-center justify-center">
            <Database className="w-4 h-4 text-indigo-400" />
          </div>
        </div>

        <div className="mt-3 flex items-baseline gap-2">
          <span className={`text-2xl font-black ${(overview?.slowQueriesCount || 0) > 0 ? 'text-amber-400' : 'text-white'}`}>
            {overview?.slowQueriesCount ?? 0}
          </span>
          <span className="text-xs font-semibold text-slate-400">Slow Queries (&gt;200ms)</span>
        </div>

        <div className="mt-2 pt-2 border-t border-slate-800 flex items-center justify-between text-xs text-slate-400">
          <span>Active Monitored Systems:</span>
          <span className="font-bold text-cyan-400">{overview?.activeTenantsCount ?? 3} Tenants</span>
        </div>
      </div>

    </div>
  );
};
