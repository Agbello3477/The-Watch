import React, { useState, useEffect } from 'react';

const API = (import.meta as any).env?.VITE_API_URL || 'http://localhost:4000';

interface TelemetryLog {
  id: string;
  system_id: string;
  method: string;
  path: string;
  status_code: number;
  latency_ms: number;
  client_ip: string;
  payload_snippet?: string;
  user_agent?: string;
  created_at: string;
}

interface TrafficStats {
  total: number;
  errors: number;
  ok: number;
  avgLatency: number;
  slowRequests: number;
  topEndpoints: { endpoint: string; count: number }[];
  topIps: { ip: string; count: number }[];
  methodBreakdown: Record<string, number>;
  systemId: string;
}

export const TrafficMonitor: React.FC<{ selectedSystem: string }> = ({ selectedSystem }) => {
  const [logs, setLogs] = useState<TelemetryLog[]>([]);
  const [stats, setStats] = useState<TrafficStats | null>(null);
  const [expandedLogId, setExpandedLogId] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    let intervalId: any;

    const fetchData = async () => {
      try {
        const [liveRes, statsRes] = await Promise.all([
          fetch(`${API}/api/v1/traffic/live?systemId=${selectedSystem}&limit=100`),
          fetch(`${API}/api/v1/traffic/stats?systemId=${selectedSystem}`)
        ]);

        if (!liveRes.ok || !statsRes.ok) {
          throw new Error('Failed to fetch traffic data');
        }

        const liveData = await liveRes.json();
        const statsData = await statsRes.json();

        setLogs(liveData.logs);
        setStats(statsData);
        setError(null);
      } catch (err: any) {
        setError(err.message);
      } finally {
        setLoading(false);
      }
    };

    fetchData();
    intervalId = setInterval(fetchData, 5000);

    return () => clearInterval(intervalId);
  }, [selectedSystem]);

  const getMethodColor = (method: string) => {
    switch (method.toUpperCase()) {
      case 'GET': return 'bg-blue-500/20 text-blue-400 border-blue-500/30';
      case 'POST': return 'bg-green-500/20 text-green-400 border-green-500/30';
      case 'PUT': return 'bg-yellow-500/20 text-yellow-400 border-yellow-500/30';
      case 'DELETE': return 'bg-red-500/20 text-red-400 border-red-500/30';
      case 'PATCH': return 'bg-orange-500/20 text-orange-400 border-orange-500/30';
      default: return 'bg-slate-500/20 text-slate-400 border-slate-500/30';
    }
  };

  const getStatusColor = (status: number) => {
    if (status >= 200 && status < 300) return 'text-emerald-400';
    if (status >= 300 && status < 400) return 'text-blue-400';
    if (status >= 400 && status < 500) return 'text-orange-400';
    if (status >= 500) return 'text-red-400';
    return 'text-slate-400';
  };

  const getLatencyColor = (latency: number) => {
    if (latency < 100) return 'text-emerald-400';
    if (latency < 500) return 'text-yellow-400';
    return 'text-red-400';
  };

  const formatTime = (ts: string) => {
    try {
      return new Date(ts).toLocaleString('en-GB', { timeZone: 'Africa/Lagos', hour12: false });
    } catch {
      return ts;
    }
  };

  if (loading && logs.length === 0) {
    return (
      <div className="flex flex-col items-center justify-center py-20 text-slate-400">
        <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-cyan-400 mb-4"></div>
        Waiting for HRMS traffic...
      </div>
    );
  }

  return (
    <div className="flex flex-col gap-6 w-full text-sm">
      <div className="flex items-center justify-between">
        <h2 className="text-xl font-bold text-slate-100 flex items-center gap-3">
          <span className="relative flex h-3 w-3">
            <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-emerald-400 opacity-75"></span>
            <span className="relative inline-flex rounded-full h-3 w-3 bg-emerald-500"></span>
          </span>
          Live Traffic Monitor
          <span className="text-xs font-mono bg-slate-800 text-cyan-400 px-2 py-0.5 rounded-full border border-cyan-500/30">
            {selectedSystem}
          </span>
        </h2>
      </div>

      {error && (
        <div className="bg-red-500/10 border border-red-500/50 text-red-400 p-4 rounded-lg">
          Error: {error}
        </div>
      )}

      {/* Stats Cards */}
      <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
        <div className="bg-slate-900 border border-slate-800 rounded-lg p-4">
          <div className="text-slate-400 text-xs uppercase tracking-wider mb-1">Total Requests</div>
          <div className="text-2xl font-bold text-slate-100">{stats?.total || 0}</div>
        </div>
        <div className="bg-slate-900 border border-slate-800 rounded-lg p-4">
          <div className="text-slate-400 text-xs uppercase tracking-wider mb-1">Error Rate</div>
          <div className={`text-2xl font-bold ${(stats?.errors || 0) > 0 ? 'text-red-400' : 'text-emerald-400'}`}>
            {stats?.total ? ((stats.errors / stats.total) * 100).toFixed(1) : '0.0'}%
          </div>
        </div>
        <div className="bg-slate-900 border border-slate-800 rounded-lg p-4">
          <div className="text-slate-400 text-xs uppercase tracking-wider mb-1">Avg Latency</div>
          <div className={`text-2xl font-bold ${getLatencyColor(stats?.avgLatency || 0)}`}>
            {stats?.avgLatency || 0}ms
          </div>
        </div>
        <div className="bg-slate-900 border border-slate-800 rounded-lg p-4">
          <div className="text-slate-400 text-xs uppercase tracking-wider mb-1">Slow Requests (&gt;500ms)</div>
          <div className={`text-2xl font-bold ${(stats?.slowRequests || 0) > 0 ? 'text-yellow-400' : 'text-emerald-400'}`}>
            {stats?.slowRequests || 0}
          </div>
        </div>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Top Endpoints */}
        <div className="bg-slate-900 border border-slate-800 rounded-lg p-4 lg:col-span-2">
          <h3 className="text-slate-300 font-semibold mb-4">Top Endpoints</h3>
          <div className="space-y-3">
            {stats?.topEndpoints.map((ep, i) => {
              const maxCount = stats.topEndpoints[0]?.count || 1;
              const width = Math.max(5, (ep.count / maxCount) * 100);
              return (
                <div key={i} className="flex items-center gap-3">
                  <div className="w-24 text-right text-xs text-slate-400 truncate" title={ep.endpoint}>
                    {ep.endpoint}
                  </div>
                  <div className="flex-1 bg-slate-800 h-4 rounded-full overflow-hidden">
                    <div 
                      className="bg-cyan-500 h-full rounded-full" 
                      style={{ width: `${width}%` }}
                    />
                  </div>
                  <div className="w-10 text-xs text-slate-400 font-mono">
                    {ep.count}
                  </div>
                </div>
              );
            })}
            {(!stats?.topEndpoints || stats.topEndpoints.length === 0) && (
              <div className="text-slate-500 text-sm italic">No data</div>
            )}
          </div>
        </div>

        {/* Method Breakdown */}
        <div className="bg-slate-900 border border-slate-800 rounded-lg p-4">
          <h3 className="text-slate-300 font-semibold mb-4">Methods</h3>
          <div className="flex flex-wrap gap-2">
            {stats?.methodBreakdown && Object.entries(stats.methodBreakdown).map(([method, count]) => (
              <div key={method} className={`px-3 py-1.5 rounded border text-xs font-mono flex items-center gap-2 ${getMethodColor(method)}`}>
                <span>{method}</span>
                <span className="bg-black/20 px-1.5 py-0.5 rounded text-[10px]">{count}</span>
              </div>
            ))}
            {(!stats?.methodBreakdown || Object.keys(stats.methodBreakdown).length === 0) && (
              <div className="text-slate-500 text-sm italic">No data</div>
            )}
          </div>
        </div>
      </div>

      {/* Live Feed Table */}
      <div className="bg-slate-900 border border-slate-800 rounded-lg overflow-hidden flex flex-col">
        <div className="p-4 border-b border-slate-800 flex justify-between items-center bg-slate-800/50">
          <h3 className="text-slate-300 font-semibold">Live Traffic Feed (Last {logs.length})</h3>
        </div>
        <div className="overflow-x-auto">
          <table className="w-full text-left border-collapse">
            <thead>
              <tr className="bg-slate-900/50 text-slate-400 text-xs uppercase tracking-wider">
                <th className="p-3 font-medium">Time (WAT)</th>
                <th className="p-3 font-medium">Method</th>
                <th className="p-3 font-medium">Path</th>
                <th className="p-3 font-medium">Status</th>
                <th className="p-3 font-medium">Latency</th>
                <th className="p-3 font-medium">Client IP</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/50">
              {logs.length === 0 ? (
                <tr>
                  <td colSpan={6} className="p-6 text-center text-slate-500 italic">
                    No recent traffic recorded.
                  </td>
                </tr>
              ) : (
                logs.map((log) => (
                  <React.Fragment key={log.id}>
                    <tr 
                      className={`hover:bg-slate-800/50 transition cursor-pointer ${expandedLogId === log.id ? 'bg-slate-800/30' : ''}`}
                      onClick={() => setExpandedLogId(expandedLogId === log.id ? null : log.id)}
                    >
                      <td className="p-3 text-xs text-slate-400 whitespace-nowrap">{formatTime(log.created_at)}</td>
                      <td className="p-3">
                        <span className={`px-2 py-0.5 rounded border text-[10px] font-mono ${getMethodColor(log.method)}`}>
                          {log.method}
                        </span>
                      </td>
                      <td className="p-3 text-slate-300 font-mono text-xs truncate max-w-[200px]" title={log.path}>
                        {log.path}
                      </td>
                      <td className={`p-3 font-mono text-xs font-bold ${getStatusColor(log.status_code)}`}>
                        {log.status_code}
                      </td>
                      <td className={`p-3 font-mono text-xs ${getLatencyColor(log.latency_ms)}`}>
                        {log.latency_ms}ms
                      </td>
                      <td className="p-3 text-slate-400 font-mono text-xs">
                        {log.client_ip}
                      </td>
                    </tr>
                    {expandedLogId === log.id && (
                      <tr className="bg-slate-950/50">
                        <td colSpan={6} className="p-4 border-b border-slate-800/50">
                          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                            <div>
                              <h4 className="text-xs text-slate-500 uppercase tracking-wider mb-2">Request Details</h4>
                              <pre className="text-[10px] bg-slate-900 p-3 rounded border border-slate-800 text-slate-300 overflow-x-auto font-mono">
{`ID: ${log.id}
System ID: ${log.system_id}
User Agent: ${log.user_agent || 'N/A'}`}
                              </pre>
                            </div>
                            {log.payload_snippet && (
                              <div>
                                <h4 className="text-xs text-slate-500 uppercase tracking-wider mb-2">Payload Snippet</h4>
                                <pre className="text-[10px] bg-slate-900 p-3 rounded border border-slate-800 text-slate-300 overflow-x-auto font-mono">
                                  {log.payload_snippet}
                                </pre>
                              </div>
                            )}
                          </div>
                        </td>
                      </tr>
                    )}
                  </React.Fragment>
                ))
              )}
            </tbody>
          </table>
        </div>
      </div>
      
      <div className="text-center text-xs text-slate-500 mt-4 mb-8">
        Powered by: MaSha Tech Innovations
      </div>
    </div>
  );
};
