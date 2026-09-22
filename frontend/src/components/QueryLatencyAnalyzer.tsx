import React from 'react';
import { Database, AlertTriangle, Cpu, TrendingUp, Zap } from 'lucide-react';
import { QueryMetricsResponse } from '../types/dashboard';

interface QueryLatencyAnalyzerProps {
  data: QueryMetricsResponse | null;
}

export const QueryLatencyAnalyzer: React.FC<QueryLatencyAnalyzerProps> = ({ data }) => {
  const summary = data?.summary || {
    totalLogged: 0,
    slowQueriesCount: 0,
    avgDurationMs: 0,
    maxDurationMs: 0,
    poolActiveConnections: 4,
    poolIdleConnections: 16,
  };

  const metrics = data?.metrics || [];

  return (
    <div className="bg-slate-900/80 border border-slate-800 rounded-xl p-5 shadow-sm">
      
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 mb-4">
        <div>
          <div className="flex items-center gap-2">
            <Database className="w-5 h-5 text-indigo-400" />
            <h2 className="text-base font-bold text-white tracking-wide">DATABASE QUERY OBSERVABILITY & LATENCY PROFILER</h2>
          </div>
          <p className="text-xs text-slate-400 mt-0.5">
            Real-time tracking of database query latency, pool saturation events, and queries exceeding 200ms threshold
          </p>
        </div>

        {/* Pool Saturation Indicator */}
        <div className="flex items-center gap-3 bg-slate-950 px-3 py-1.5 rounded-lg border border-slate-800 text-xs">
          <span className="flex items-center gap-1 text-slate-400">
            <Cpu className="w-3.5 h-3.5 text-cyan-400" /> Pool:
          </span>
          <span className="font-mono font-bold text-slate-200">
            {summary.poolActiveConnections} Active / {summary.poolIdleConnections} Idle
          </span>
        </div>
      </div>

      {/* Query Metrics Summary Stats */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-3 mb-4">
        <div className="bg-slate-950 p-3 rounded-lg border border-slate-800">
          <span className="text-[10px] uppercase font-bold text-slate-400 block">Total Queries Tracked</span>
          <span className="text-lg font-black text-white font-mono mt-0.5 block">{summary.totalLogged}</span>
        </div>

        <div className="bg-slate-950 p-3 rounded-lg border border-slate-800">
          <span className="text-[10px] uppercase font-bold text-slate-400 block">Queries &gt; 200ms</span>
          <span className={`text-lg font-black font-mono mt-0.5 block ${summary.slowQueriesCount > 0 ? 'text-amber-400' : 'text-emerald-400'}`}>
            {summary.slowQueriesCount} Flagged
          </span>
        </div>

        <div className="bg-slate-950 p-3 rounded-lg border border-slate-800">
          <span className="text-[10px] uppercase font-bold text-slate-400 block">Average Latency</span>
          <span className="text-lg font-black text-slate-200 font-mono mt-0.5 block">{summary.avgDurationMs} ms</span>
        </div>

        <div className="bg-slate-950 p-3 rounded-lg border border-slate-800">
          <span className="text-[10px] uppercase font-bold text-slate-400 block">Max Peak Latency</span>
          <span className="text-lg font-black text-red-400 font-mono mt-0.5 block">{summary.maxDurationMs} ms</span>
        </div>
      </div>

      {/* Queries List */}
      <div className="overflow-x-auto">
        <table className="w-full text-left border-collapse text-xs">
          <thead>
            <tr className="border-b border-slate-800 text-slate-400 font-semibold uppercase tracking-wider bg-slate-950/60">
              <th className="py-2.5 px-3">Status</th>
              <th className="py-2.5 px-3">System</th>
              <th className="py-2.5 px-3">SQL Query Text</th>
              <th className="py-2.5 px-3">Duration (ms)</th>
              <th className="py-2.5 px-3">Pool State</th>
              <th className="py-2.5 px-3">Timestamp</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-slate-800/60 font-mono">
            {metrics.length === 0 ? (
              <tr>
                <td colSpan={6} className="py-6 text-center text-slate-500 font-sans font-semibold">
                  ✓ No queries captured yet.
                </td>
              </tr>
            ) : (
              metrics.slice(0, 8).map((m) => {
                const isSlow = m.exceeded_threshold || m.duration_ms > 200;
                return (
                  <tr key={m.id} className="hover:bg-slate-800/30 transition">
                    <td className="py-2.5 px-3">
                      {isSlow ? (
                        <span className="bg-amber-500/20 text-amber-400 border border-amber-500/30 px-2 py-0.5 rounded text-[10px] font-bold">
                          SLOW &gt;200ms
                        </span>
                      ) : (
                        <span className="bg-emerald-500/20 text-emerald-400 border border-emerald-500/30 px-2 py-0.5 rounded text-[10px] font-bold">
                          FAST
                        </span>
                      )}
                    </td>

                    <td className="py-2.5 px-3 text-cyan-400 font-bold">{m.system_id}</td>

                    <td className="py-2.5 px-3 max-w-md truncate text-slate-300">
                      {m.query_text}
                    </td>

                    <td className={`py-2.5 px-3 font-bold ${isSlow ? 'text-amber-400' : 'text-slate-200'}`}>
                      {m.duration_ms} ms
                    </td>

                    <td className="py-2.5 px-3 text-slate-400 text-[11px]">
                      {m.pool_active_connections} act / {m.pool_idle_connections} idle
                    </td>

                    <td className="py-2.5 px-3 text-slate-500 text-[11px] whitespace-nowrap">
                      {new Date(m.created_at).toLocaleTimeString()}
                    </td>
                  </tr>
                );
              })
            )}
          </tbody>
        </table>
      </div>

    </div>
  );
};
