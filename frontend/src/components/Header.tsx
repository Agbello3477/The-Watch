import React, { useEffect, useState } from 'react';
import { 
  Clock, 
  Layers, 
  RefreshCw, 
  LogOut, 
  KeyRound, 
  Home, 
  Users, 
  ShieldCheck, 
  Menu, 
  X as XIcon,
  Timer
} from 'lucide-react';
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
  sessionTimeRemaining?: number | null; // Seconds remaining in active session
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
  sessionTimeRemaining,
}) => {
  const [watTime, setWatTime] = useState<string>('');
  const [isMobileMenuOpen, setIsMobileMenuOpen] = useState(false);

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
        return (
          <span className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-lg text-xs font-bold tracking-wide font-mono bg-rose-500/15 text-rose-400 border border-rose-500/30 shrink-0">
            <span className="w-2 h-2 rounded-full bg-rose-500 animate-pulse" />
            <span>THREAT: CRITICAL</span>
          </span>
        );
      case 'SEVERE':
        return (
          <span className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-lg text-xs font-bold tracking-wide font-mono bg-orange-500/15 text-orange-400 border border-orange-500/30 shrink-0">
            <span className="w-2 h-2 rounded-full bg-orange-500" />
            <span>THREAT: SEVERE</span>
          </span>
        );
      case 'ELEVATED':
        return (
          <span className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-lg text-xs font-bold tracking-wide font-mono bg-amber-500/15 text-amber-300 border border-amber-500/30 shrink-0">
            <span className="w-2 h-2 rounded-full bg-amber-400 animate-ping-slow" />
            <span>THREAT: ELEVATED</span>
          </span>
        );
      default:
        return (
          <span className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-lg text-xs font-bold tracking-wide font-mono bg-emerald-500/15 text-emerald-400 border border-emerald-500/30 shrink-0">
            <span className="w-2 h-2 rounded-full bg-emerald-400" />
            <span>THREAT: NORMAL</span>
          </span>
        );
    }
  };

  const formatSessionTime = (seconds: number) => {
    const mins = Math.floor(seconds / 60);
    const secs = seconds % 60;
    return `${mins}:${secs < 10 ? '0' : ''}${secs}`;
  };

  return (
    <header className="bg-slate-900/95 backdrop-blur-md border-b border-slate-800 sticky top-0 z-40 px-4 sm:px-6 py-2.5 transition-all">
      <div className="max-w-7xl mx-auto flex items-center justify-between gap-3">
        
        {/* ─── LEFT: Logo & Platform Identity ─── */}
        <div className="flex items-center gap-3 shrink-0">
          <div 
            onClick={onGoHome}
            className="relative flex items-center justify-center w-10 h-10 rounded-xl bg-slate-950 p-1 shadow-md shadow-cyan-500/10 border border-slate-700/80 overflow-hidden cursor-pointer hover:border-cyan-500 transition"
          >
            <img
              src="/logo.jpg"
              alt="The Watch Logo"
              className="w-full h-full object-contain rounded-lg"
            />
            <span className="absolute -top-1 -right-1 flex h-2 w-2">
              <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-cyan-400 opacity-75" />
              <span className="relative inline-flex rounded-full h-2 w-2 bg-cyan-500" />
            </span>
          </div>

          <div>
            <div className="flex items-center gap-2">
              <h1 
                onClick={onGoHome}
                className="text-base font-black tracking-wider text-white cursor-pointer hover:text-cyan-400 transition"
              >
                THE WATCH
              </h1>
              <span className="text-[9px] uppercase font-mono font-bold tracking-wider bg-cyan-950/80 text-cyan-400 border border-cyan-800/80 px-1.5 py-0.5 rounded">
                v2.4 SOC
              </span>
            </div>
            <p className="text-[10.5px] text-slate-400 flex items-center gap-1.5 font-mono">
              <span className="truncate max-w-[150px] sm:max-w-none">Observability & Threat Gateway</span>
              <span className="text-slate-600 hidden sm:inline">•</span>
              <span className="text-cyan-400/90 hidden sm:inline text-[9.5px]">Zero Host Overhead</span>
            </p>
          </div>
        </div>

        {/* ─── CENTER: Clean Nav Tabs, Target Selector, Threat Badge (Desktop) ─── */}
        <div className="hidden lg:flex items-center gap-2.5">
          {/* View Segmented Tabs */}
          <div className="flex items-center bg-slate-950 border border-slate-800 rounded-xl p-0.5">
            <button
              onClick={onGoHome}
              className={`px-3 py-1.5 rounded-lg text-xs font-semibold flex items-center gap-1.5 transition ${
                activeTab === 'home' 
                  ? 'bg-slate-800 text-cyan-400 font-bold shadow-sm' 
                  : 'text-slate-400 hover:text-slate-200'
              }`}
            >
              <Home className="w-3.5 h-3.5" />
              <span>Home</span>
            </button>

            <button
              onClick={() => onTabChange('overview')}
              className={`px-3 py-1.5 rounded-lg text-xs font-semibold flex items-center gap-1.5 transition ${
                activeTab !== 'home' && activeTab !== 'users' 
                  ? 'bg-slate-800 text-cyan-400 font-bold shadow-sm' 
                  : 'text-slate-400 hover:text-slate-200'
              }`}
            >
              <ShieldCheck className="w-3.5 h-3.5" />
              <span>SOC Command</span>
            </button>

            {currentUser?.role === 'SUPER_ADMIN' && (
              <button
                onClick={() => onTabChange('users')}
                className={`px-3 py-1.5 rounded-lg text-xs font-semibold flex items-center gap-1.5 transition ${
                  activeTab === 'users' 
                    ? 'bg-indigo-950 text-indigo-300 font-bold border border-indigo-700/60 shadow-sm' 
                    : 'text-slate-400 hover:text-slate-200'
                }`}
              >
                <Users className="w-3.5 h-3.5" />
                <span>Users & Audit</span>
              </button>
            )}
          </div>

          {/* System Dropdown Selector */}
          <div className="flex items-center bg-slate-950 border border-slate-800 rounded-xl px-2.5 py-1">
            <Layers className="w-3.5 h-3.5 text-slate-400 mr-2 shrink-0" />
            <select
              value={selectedSystem}
              onChange={(e) => onSelectSystem(e.target.value)}
              className="bg-transparent text-xs font-medium text-slate-200 focus:outline-none cursor-pointer pr-1"
            >
              <option value="" className="bg-slate-900 text-slate-100">All Systems (Universal)</option>
              <option value="NOUN-HRMS" className="bg-slate-900 text-slate-100">NOUN-HRMS (Flagship)</option>
              <option value="Clinic-EHR" className="bg-slate-900 text-slate-100">Clinic-EHR (Medical)</option>
              <option value="Security-Dispatch" className="bg-slate-900 text-slate-100">Security-Dispatch (Campus)</option>
            </select>
          </div>

          {/* Threat Badge */}
          {getThreatBadge()}
        </div>

        {/* ─── RIGHT: WAT Clock, Session Inactivity Counter, Auto-Refresh & User Profile ─── */}
        <div className="flex items-center gap-2 sm:gap-2.5">
          
          {/* WAT Master Clock */}
          <div className="hidden md:flex items-center gap-1.5 bg-slate-950 border border-slate-800/80 px-2.5 py-1 rounded-xl text-[11px] font-mono text-slate-300 shrink-0">
            <Clock className="w-3.5 h-3.5 text-cyan-400" />
            <span>{watTime || 'WAT (UTC+1)'}</span>
          </div>

          {/* Active Session Inactivity Countdown (Visible when logged in) */}
          {currentUser && typeof sessionTimeRemaining === 'number' && (
            <div 
              title="Session inactivity timeout (3 mins). Any mouse movement or keystroke resets timer."
              className={`hidden sm:flex items-center gap-1.5 px-2.5 py-1 rounded-xl text-[11px] font-mono border transition ${
                sessionTimeRemaining <= 30
                  ? 'bg-rose-950/70 text-rose-300 border-rose-700/80 animate-pulse font-bold'
                  : 'bg-slate-950 text-slate-400 border-slate-800'
              }`}
            >
              <Timer className={`w-3.5 h-3.5 ${sessionTimeRemaining <= 30 ? 'text-rose-400' : 'text-slate-500'}`} />
              <span className="hidden xl:inline text-[10px] uppercase text-slate-500">Timeout:</span>
              <span className="font-semibold">{formatSessionTime(sessionTimeRemaining)}</span>
            </div>
          )}

          {/* Telemetry Refresh Controls */}
          <div className="flex items-center gap-1 bg-slate-950 border border-slate-800 rounded-xl p-0.5">
            <select
              value={autoRefreshInterval}
              onChange={(e) => setAutoRefreshInterval(Number(e.target.value))}
              className="bg-transparent text-[11px] font-mono text-slate-400 px-2 py-1 focus:outline-none cursor-pointer"
            >
              <option value={5000} className="bg-slate-900">5s</option>
              <option value={10000} className="bg-slate-900">10s</option>
              <option value={30000} className="bg-slate-900">30s</option>
              <option value={0} className="bg-slate-900">Off</option>
            </select>

            <button
              onClick={onRefresh}
              disabled={isRefreshing}
              title="Refresh telemetry"
              className="p-1 rounded-lg hover:bg-slate-800 text-slate-400 hover:text-white transition cursor-pointer"
            >
              <RefreshCw className={`w-3.5 h-3.5 ${isRefreshing ? 'animate-spin text-cyan-400' : ''}`} />
            </button>
          </div>

          {/* User Profile or Sign In */}
          {currentUser ? (
            <div className="flex items-center gap-2 pl-1 border-l border-slate-800">
              <div className="hidden sm:block text-right">
                <div className="text-xs font-semibold text-slate-200 truncate max-w-[140px]">
                  {currentUser.fullName}
                </div>
                <div className="text-[10px] text-cyan-400 font-mono font-bold">
                  {currentUser.role}
                </div>
              </div>

              <button
                onClick={onLogout}
                title="Sign Out"
                className="p-1.5 rounded-lg bg-slate-950 hover:bg-rose-950/60 text-slate-400 hover:text-rose-300 border border-slate-800 hover:border-rose-900/50 transition cursor-pointer"
              >
                <LogOut className="w-3.5 h-3.5" />
              </button>
            </div>
          ) : (
            <button
              onClick={onOpenLogin}
              className="px-3 py-1.5 rounded-lg bg-gradient-to-r from-cyan-500 to-blue-600 hover:from-cyan-400 hover:to-blue-500 text-slate-950 font-bold text-xs flex items-center gap-1.5 shadow-md shadow-cyan-500/20 transition cursor-pointer shrink-0"
            >
              <KeyRound className="w-3.5 h-3.5" />
              <span>Sign In</span>
            </button>
          )}

          {/* Mobile Menu Toggle Button */}
          <div className="flex lg:hidden">
            <button 
              onClick={() => setIsMobileMenuOpen(!isMobileMenuOpen)} 
              className="p-1.5 rounded-lg bg-slate-950 text-slate-400 hover:text-white border border-slate-800"
            >
              {isMobileMenuOpen ? <XIcon className="w-4 h-4" /> : <Menu className="w-4 h-4" />}
            </button>
          </div>

        </div>

      </div>

      {/* ─── MOBILE ACCORDION MENU ─── */}
      {isMobileMenuOpen && (
        <div className="lg:hidden mt-3 pt-3 border-t border-slate-800 space-y-3">
          <div className="flex items-center justify-between">
            {getThreatBadge()}
            <div className="text-xs font-mono text-cyan-400 flex items-center gap-1">
              <Clock className="w-3 h-3" />
              <span>{watTime}</span>
            </div>
          </div>

          <div className="grid grid-cols-2 gap-2">
            <button
              onClick={() => {
                onGoHome();
                setIsMobileMenuOpen(false);
              }}
              className={`p-2 rounded-lg text-xs font-semibold flex items-center justify-center gap-1.5 border ${
                activeTab === 'home' 
                  ? 'bg-slate-800 border-cyan-500 text-cyan-300' 
                  : 'bg-slate-950 border-slate-800 text-slate-300'
              }`}
            >
              <Home className="w-3.5 h-3.5" />
              <span>Home</span>
            </button>

            <button
              onClick={() => {
                onTabChange('overview');
                setIsMobileMenuOpen(false);
              }}
              className={`p-2 rounded-lg text-xs font-semibold flex items-center justify-center gap-1.5 border ${
                activeTab !== 'home' && activeTab !== 'users' 
                  ? 'bg-slate-800 border-cyan-500 text-cyan-300' 
                  : 'bg-slate-950 border-slate-800 text-slate-300'
              }`}
            >
              <ShieldCheck className="w-3.5 h-3.5" />
              <span>SOC War Room</span>
            </button>
          </div>

          {currentUser?.role === 'SUPER_ADMIN' && (
            <button
              onClick={() => {
                onTabChange('users');
                setIsMobileMenuOpen(false);
              }}
              className="w-full p-2 rounded-lg text-xs font-semibold flex items-center justify-center gap-1.5 bg-indigo-950/60 border border-indigo-700/60 text-indigo-300"
            >
              <Users className="w-3.5 h-3.5" />
              <span>User Management Console</span>
            </button>
          )}

          <div className="bg-slate-950 border border-slate-800 rounded-xl p-2 flex items-center">
            <Layers className="w-3.5 h-3.5 text-slate-400 mr-2 shrink-0" />
            <select
              value={selectedSystem}
              onChange={(e) => onSelectSystem(e.target.value)}
              className="bg-transparent text-xs text-slate-200 focus:outline-none w-full"
            >
              <option value="" className="bg-slate-900">All Systems (Universal)</option>
              <option value="NOUN-HRMS" className="bg-slate-900">NOUN-HRMS (Flagship)</option>
              <option value="Clinic-EHR" className="bg-slate-900">Clinic-EHR (Medical)</option>
              <option value="Security-Dispatch" className="bg-slate-900">Security-Dispatch (Campus)</option>
            </select>
          </div>
        </div>
      )}

    </header>
  );
};
