import React, { useEffect, useState } from 'react';
import { Clock, Layers, RefreshCw, User, LogOut, KeyRound, Home, Users, ShieldCheck } from 'lucide-react';
import { SystemOverview, AuthSessionUser } from '../types/dashboard';

interface HeaderProps {
  overview: SystemOverview | null;
  selectedSystem: string;
  onSelectSystem: (sys: string) => void;
  onRefresh: () => void;
  isRefreshing: boolean;
  autoRefreshInterval: number;
  setAutoRefreshInterval: (interval: number) => void;
  currentUser: AuthSessionUser | null;
  activeTab: string;
  onTabChange: (tab: string) => void;
  onOpenLogin: () => void;
  onLogout: () => void;
  onGoHome: () => void;
}

export const Header: React.FC<HeaderProps> = ({
  overview,
  selectedSystem,
  onSelectSystem,
  onRefresh,
  isRefreshing,
  autoRefreshInterval,
  setAutoRefreshInterval,
  currentUser,
  activeTab,
  onTabChange,
  onOpenLogin,
  onLogout,
  onGoHome,
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
        
        {/* Brand & Logo */}
        <div className="flex items-center gap-3.5">
          <div 
            onClick={onGoHome}
            className="relative flex items-center justify-center w-11 h-11 rounded-xl bg-slate-950/80 p-1 shadow-lg shadow-cyan-500/10 border border-slate-700/80 overflow-hidden shrink-0 cursor-pointer hover:border-cyan-500 transition"
          >
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
              <h1 
                onClick={onGoHome}
                className="text-lg font-black tracking-wider text-white cursor-pointer hover:text-cyan-400 transition"
              >
                THE WATCH
              </h1>
              <span className="text-[9px] uppercase font-mono font-bold tracking-widest bg-cyan-950 text-cyan-400 border border-cyan-800 px-1.5 py-0.5 rounded">
                v2.4 SOC
              </span>
            </div>
            <p className="text-[11px] text-slate-400 flex items-center gap-1.5 mt-0.5">
              <span>Observability & Threat Gateway</span>
              <span className="text-slate-600">•</span>
              <span className="text-cyan-400/90 font-mono text-[10px]">Zero Host Overhead</span>
            </p>
          </div>
        </div>

        {/* Center Navigation & System Selector */}
        <div className="flex flex-wrap items-center gap-2.5">
          <div className="flex items-center bg-slate-950/80 border border-slate-800 rounded-xl p-1">
            <button
              onClick={onGoHome}
              className={`px-3 py-1.5 rounded-lg text-xs font-semibold flex items-center space-x-1.5 transition ${
                activeTab === 'home' ? 'bg-slate-800 text-cyan-400 font-bold' : 'text-slate-400 hover:text-slate-200'
              }`}
            >
              <Home className="w-3.5 h-3.5" />
              <span>Home</span>
            </button>

            <button
              onClick={() => onTabChange('overview')}
              className={`px-3 py-1.5 rounded-lg text-xs font-semibold flex items-center space-x-1.5 transition ${
                activeTab !== 'home' && activeTab !== 'users' ? 'bg-slate-800 text-cyan-400 font-bold' : 'text-slate-400 hover:text-slate-200'
              }`}
            >
              <ShieldCheck className="w-3.5 h-3.5" />
              <span>SOC Command</span>
            </button>

            {currentUser?.role === 'SUPER_ADMIN' && (
              <button
                onClick={() => onTabChange('users')}
                className={`px-3 py-1.5 rounded-lg text-xs font-semibold flex items-center space-x-1.5 transition ${
                  activeTab === 'users' ? 'bg-indigo-950 text-indigo-300 font-bold border border-indigo-700/60' : 'text-slate-400 hover:text-slate-200'
                }`}
              >
                <Users className="w-3.5 h-3.5" />
                <span>Users & Audit</span>
              </button>
            )}
          </div>

          <div className="flex items-center bg-slate-950 border border-slate-800 rounded-xl p-1">
            <Layers className="w-4 h-4 text-slate-400 ml-2 mr-1.5" />
            <select
              value={selectedSystem}
              onChange={(e) => onSelectSystem(e.target.value)}
              className="bg-transparent text-xs font-semibold text-slate-200 focus:outline-none pr-3 cursor-pointer py-1"
            >
              <option value="" className="bg-slate-900 text-slate-100">All Systems (Universal)</option>
              <option value="NOUN-HRMS" className="bg-slate-900 text-slate-100">NOUN-HRMS (Flagship)</option>
              <option value="Clinic-EHR" className="bg-slate-900 text-slate-100">Clinic-EHR (Medical)</option>
              <option value="Security-Dispatch" className="bg-slate-900 text-slate-100">Security-Dispatch (Campus)</option>
            </select>
          </div>

          {getThreatBadge()}
        </div>

        {/* Right Controls: WAT Clock & User Profile / Login */}
        <div className="flex items-center gap-3">
          <div className="hidden xl:flex items-center gap-1.5 bg-slate-950/80 border border-slate-800/80 px-2.5 py-1.5 rounded-xl text-[11px] font-mono text-slate-300">
            <Clock className="w-3.5 h-3.5 text-cyan-400" />
            <span>{watTime || 'WAT (UTC+1)'}</span>
          </div>

          <div className="flex items-center gap-1.5">
            <select
              value={autoRefreshInterval}
              onChange={(e) => setAutoRefreshInterval(Number(e.target.value))}
              className="bg-slate-950 border border-slate-800 text-[11px] text-slate-400 rounded-lg px-2 py-1.5 focus:outline-none cursor-pointer"
            >
              <option value={5000}>5s</option>
              <option value={10000}>10s</option>
              <option value={30000}>30s</option>
              <option value={0}>Manual</option>
            </select>

            <button
              onClick={onRefresh}
              disabled={isRefreshing}
              title="Refresh telemetry"
              className="flex items-center justify-center w-8 h-8 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-300 hover:text-white border border-slate-700 transition cursor-pointer"
            >
              <RefreshCw className={`w-3.5 h-3.5 ${isRefreshing ? 'animate-spin text-cyan-400' : ''}`} />
            </button>
          </div>

          {/* User Profile or Sign In Button */}
          {currentUser ? (
            <div className="flex items-center space-x-2 pl-1 border-l border-slate-800">
              <div className="hidden sm:block text-right">
                <div className="text-xs font-semibold text-slate-200">{currentUser.fullName}</div>
                <div className="text-[10px] text-indigo-400 font-mono font-bold">
                  {currentUser.role}
                </div>
              </div>

              <button
                onClick={onLogout}
                title="Sign Out"
                className="p-2 rounded-lg bg-slate-800/80 hover:bg-rose-950/60 text-slate-400 hover:text-rose-300 border border-slate-700 hover:border-rose-900/50 transition cursor-pointer"
              >
                <LogOut className="w-3.5 h-3.5" />
              </button>
            </div>
          ) : (
            <button
              onClick={onOpenLogin}
              className="px-3 py-1.5 rounded-lg bg-gradient-to-r from-cyan-500 to-blue-600 hover:from-cyan-400 hover:to-blue-500 text-slate-950 font-bold text-xs flex items-center space-x-1.5 shadow-md shadow-cyan-500/20 transition cursor-pointer"
            >
              <KeyRound className="w-3.5 h-3.5" />
              <span>Sign In</span>
            </button>
          )}
        </div>

      </div>
    </header>
  );
};
