import React, { useEffect, useState } from 'react';
import { Clock, Layers, RefreshCw } from 'lucide-react';
import { SystemOverview } from '../types/dashboard';

interface HeaderProps {
  overview: SystemOverview | null;
  selectedSystem: string;
  onSelectSystem: (sys: string) => void;
  onRefresh: () => void;
  isRefreshing: boolean;
  autoRefreshInterval: number;
  setAutoRefreshInterval: (interval: number) => void;
}

export const Header: React.FC<HeaderProps> = ({
  overview,
  selectedSystem,
  onSelectSystem,
  onRefresh,
  isRefreshing,
  autoRefreshInterval,
  setAutoRefreshInterval,
}) => {
  const [watTime, setWatTime] = useState<string>('');

  useEffect(() => {
    const updateTime = () => {
      const now = new Date();
      const options: Intl.DateTimeFormatOptions = {
        timeZone: 'Africa/Lagos',
        hour: '2-digit',
        minute: '2-digit',
        second: '2-digit',
        hour12: false,
      };
      setWatTime(new Intl.DateTimeFormat('en-GB', options).format(now) + ' WAT');
    };

    updateTime();
    const timer = setInterval(updateTime, 1000);
    return () => clearInterval(timer);
  }, []);

  const getThreatBadge = () => {
    const level = overview?.threatLevel || 'NORMAL';
    switch (level) {
      case 'CRITICAL':
        return <span className="bg-red-500/20 text-red-400 border border-red-500/40 px-3 py-1 rounded-full text-xs font-bold tracking-wide flex items-center gap-1.5 animate-pulse"><span className="w-2 h-2 rounded-full bg-red-500"></span>THREAT LEVEL: CRITICAL</span>;
      case 'SEVERE':
        return <span className="bg-orange-500/20 text-orange-400 border border-orange-500/40 px-3 py-1 rounded-full text-xs font-bold tracking-wide flex items-center gap-1.5"><span className="w-2 h-2 rounded-full bg-orange-500"></span>THREAT LEVEL: SEVERE</span>;
      case 'ELEVATED':
        return <span className="bg-yellow-500/20 text-yellow-400 border border-yellow-500/40 px-3 py-1 rounded-full text-xs font-bold tracking-wide flex items-center gap-1.5"><span className="w-2 h-2 rounded-full bg-yellow-400"></span>THREAT LEVEL: ELEVATED</span>;
      default:
        return <span className="bg-emerald-500/20 text-emerald-400 border border-emerald-500/40 px-3 py-1 rounded-full text-xs font-bold tracking-wide flex items-center gap-1.5"><span className="w-2 h-2 rounded-full bg-emerald-400 animate-ping-slow"></span>THREAT LEVEL: NORMAL</span>;
    }
  };

  return (
    <header className="bg-slate-900/90 backdrop-blur border-b border-slate-800 sticky top-0 z-40 px-6 py-3 transition-all">
      <div className="max-w-7xl mx-auto flex flex-col md:flex-row items-center justify-between gap-4">
        
        {/* Brand & Logo with MaSha Tech Innovations */}
        <div className="flex items-center gap-3.5">
          <div className="relative flex items-center justify-center w-12 h-12 rounded-xl bg-slate-950/80 p-1 shadow-lg shadow-cyan-500/10 border border-slate-700/80 overflow-hidden shrink-0">
            <img
              src="/logo.jpg"
              alt="The Watch Logo"
              className="w-full h-full object-contain rounded-lg"
            />
            <span className="absolute -top-1 -right-1 flex h-2.5 w-2.5">
              <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-cyan-400 opacity-75"></span>
              <span className="relative inline-flex rounded-full h-2.5 w-2.5 bg-cyan-500"></span>
            </span>
          </div>
          <div>
            <div className="flex items-center gap-2">
              <h1 className="text-xl font-black tracking-wider text-white">THE WATCH</h1>
              <span className="text-[10px] uppercase font-bold tracking-widest bg-cyan-950 text-cyan-400 border border-cyan-800 px-2 py-0.5 rounded">
                ENTERPRISE SOC v2.4
              </span>
            </div>
            <p className="text-[11px] text-slate-400 flex items-center gap-1.5 mt-0.5">
              <span>External Observability & Threat Gateway</span>
              <span className="text-slate-600">•</span>
              <span className="text-cyan-400/90 font-mono text-[11px]">Zero-Overhead Watchdog</span>
            </p>
          </div>
        </div>

        {/* Center: System Selector & Threat Status */}
        <div className="flex flex-wrap items-center gap-3">
          <div className="flex items-center bg-slate-950 border border-slate-800 rounded-lg p-1">
            <Layers className="w-4 h-4 text-slate-400 ml-2 mr-1.5" />
            <select
              value={selectedSystem}
              onChange={(e) => onSelectSystem(e.target.value)}
              className="bg-transparent text-sm font-semibold text-slate-200 focus:outline-none pr-3 cursor-pointer py-1"
            >
              <option value="" className="bg-slate-900 text-slate-100">All Institutional Systems</option>
              <option value="NOUN-HRMS" className="bg-slate-900 text-slate-100">NOUN-HRMS (Flagship)</option>
              <option value="Clinic-EHR" className="bg-slate-900 text-slate-100">Clinic-EHR (Medical)</option>
              <option value="Security-Dispatch" className="bg-slate-900 text-slate-100">Security-Dispatch (Campus)</option>
            </select>
          </div>

          {getThreatBadge()}
        </div>

        {/* Right Controls: WAT Clock & Auto Refresh */}
        <div className="flex items-center gap-3.5">
          <div className="hidden lg:flex items-center gap-1.5 bg-slate-950/80 border border-slate-800/80 px-3 py-1.5 rounded-lg text-xs font-mono text-slate-300">
            <Clock className="w-3.5 h-3.5 text-cyan-400" />
            <span>{watTime || 'Loading WAT...'}</span>
          </div>

          <div className="flex items-center gap-2">
            <select
              value={autoRefreshInterval}
              onChange={(e) => setAutoRefreshInterval(Number(e.target.value))}
              className="bg-slate-950 border border-slate-800 text-xs text-slate-400 rounded-lg px-2.5 py-1.5 focus:outline-none cursor-pointer"
            >
              <option value={5000}>Auto 5s</option>
              <option value={10000}>Auto 10s</option>
              <option value={30000}>Auto 30s</option>
              <option value={0}>Manual</option>
            </select>

            <button
              onClick={onRefresh}
              disabled={isRefreshing}
              title="Refresh telemetry"
              className="flex items-center justify-center w-9 h-9 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-300 hover:text-white border border-slate-700 transition cursor-pointer"
            >
              <RefreshCw className={`w-4 h-4 ${isRefreshing ? 'animate-spin text-cyan-400' : ''}`} />
            </button>
          </div>
        </div>

      </div>
    </header>
  );
};
