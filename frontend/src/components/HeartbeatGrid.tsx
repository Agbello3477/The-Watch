import React, { useState } from 'react';
import { Activity, Play, Lock, Clock } from 'lucide-react';
import { SyntheticProbe } from '../types/dashboard';
import { SocSeverityBadge } from './SocThemeBadge';

interface HeartbeatGridProps {
  probes: SyntheticProbe[];
  onRunProbe: (id: string) => Promise<void>;
}

export const HeartbeatGrid: React.FC<HeartbeatGridProps> = ({ probes, onRunProbe }) => {
  const [runningId, setRunningId] = useState<string | null>(null);

  const handleRun = async (id: string) => {
    setRunningId(id);
    try {
      await onRunProbe(id);
    } finally {
      setRunningId(null);
    }
  };

  const getStatusBadge = (status: string) => {
    switch (status) {
      case 'HEALTHY':
        return <SocSeverityBadge severity="RESOLVED" label="HEALTHY" />;
      case 'DEGRADED':
        return <SocSeverityBadge severity="MEDIUM" label="DEGRADED" />;
      case 'DOWN':
        return <SocSeverityBadge severity="CRITICAL" label="DOWN" pulse />;
      default:
        return <SocSeverityBadge severity="LOW" label="PENDING" />;
    }
  };

  return (
    <div className="bg-slate-900 border border-slate-700 rounded-xl p-5 shadow-sm">
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 mb-4">
        <div>
          <div className="flex items-center gap-2">
            <Activity className="w-5 h-5 text-blue-400" />
            <h2 className="text-base font-bold text-slate-100 tracking-wide">SYNTHETIC ENDPOINT HEARTBEAT PROBES</h2>
          </div>
          <p className="text-xs text-slate-400 mt-0.5">
            Periodic 30–60s active synthetic pings measuring TTFB, DNS resolution, TCP handshakes, and SSL expiration
          </p>
        </div>
      </div>

      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-4">
        {probes.map((probe) => {
          const isRunning = runningId === probe.id;
          const isTtfbHigh = probe.last_ttfb_ms > 400;

          return (
            <div
              key={probe.id}
              className="bg-slate-950 border border-slate-700 hover:border-slate-600 rounded-xl p-4 transition-all flex flex-col justify-between"
            >
              <div>
                {/* Header */}
                <div className="flex items-start justify-between gap-2">
                  <div>
                    <span className="text-[10px] font-bold font-mono tracking-wider text-blue-400 uppercase">
                      {probe.system_id}
                    </span>
                    <h3 className="text-sm font-bold text-slate-100">{probe.name}</h3>
                  </div>
                  {getStatusBadge(probe.last_status)}
                </div>

                {/* Target URL */}
                <div className="mt-2 text-[11px] font-mono text-slate-400 truncate bg-slate-900 px-2 py-1 rounded border border-slate-700">
                  {probe.method} {probe.target_url}
                </div>

                {/* Metrics Grid */}
                <div className="mt-3 grid grid-cols-3 gap-2 text-center">
                  <div className="bg-slate-900 p-2 rounded border border-slate-700">
                    <span className="text-[10px] text-slate-400 uppercase font-semibold block">TTFB</span>
                    <span className={`text-xs font-mono font-bold ${isTtfbHigh ? 'text-yellow-400' : 'text-slate-100'}`}>
                      {probe.last_ttfb_ms || 0} ms
                    </span>
                  </div>

                  <div className="bg-slate-900 p-2 rounded border border-slate-700">
                    <span className="text-[10px] text-slate-400 uppercase font-semibold block">DNS</span>
                    <span className="text-xs font-mono font-bold text-slate-100">
                      {probe.last_dns_ms || 0} ms
                    </span>
                  </div>

                  <div className="bg-slate-900 p-2 rounded border border-slate-700">
                    <span className="text-[10px] text-slate-400 uppercase font-semibold block">Uptime</span>
                    <span className="text-xs font-mono font-bold text-emerald-400">
                      {probe.uptime_percent || 100}%
                    </span>
                  </div>
                </div>

                {/* SSL Expiration Badge */}
                <div className="mt-3 flex items-center justify-between text-xs text-slate-400">
                  <span className="flex items-center gap-1 text-[11px]">
                    <Lock className="w-3.5 h-3.5 text-blue-400" /> SSL Cert:
                  </span>
                  <span className={`font-mono text-[11px] font-semibold ${(probe.ssl_expiry_days || 80) <= 7 ? 'text-red-400' : 'text-slate-300'}`}>
                    {probe.ssl_expiry_days ? `${probe.ssl_expiry_days} days left` : 'Valid SSL'}
                  </span>
                </div>
              </div>

              {/* Action Button */}
              <div className="mt-4 pt-3 border-t border-slate-700 flex items-center justify-between">
                <span className="text-[10px] text-slate-500 flex items-center gap-1">
                  <Clock className="w-3 h-3" /> Every {probe.interval_seconds}s
                </span>

                <button
                  onClick={() => handleRun(probe.id)}
                  disabled={isRunning}
                  className="flex items-center gap-1 text-xs font-semibold text-slate-100 bg-slate-800 hover:bg-slate-700 border border-slate-700 px-2.5 py-1 rounded-lg transition"
                >
                  <Play className={`w-3 h-3 text-blue-400 ${isRunning ? 'animate-spin' : ''}`} />
                  {isRunning ? 'Probing...' : 'Ping Now'}
                </button>
              </div>

            </div>
          );
        })}
      </div>
    </div>
  );
};
