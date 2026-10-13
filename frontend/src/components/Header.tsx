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
  sessionTimeRemaining?: number | null;
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

  const getThreatDot = () => {
    const level = overview?.threatLevel || 'NORMAL';
    switch (level) {
      case 'CRITICAL':
        return {
          label: 'CRITICAL',
          badgeClass: 'bg-rose-500/15 text-rose-400 border-rose-500/40',
          dotClass: 'bg-rose-500 animate-pulse',
        };
      case 'SEVERE':
        return {
          label: 'SEVERE',
          badgeClass: 'bg-orange-500/15 text-orange-400 border-orange-500/40',
          dotClass: 'bg-orange-500',
        };
      case 'ELEVATED':
        return {
          label: 'ELEVATED',
          badgeClass: 'bg-amber-500/15 text-amber-300 border-amber-500/40',
          dotClass: 'bg-amber-400 animate-ping-slow',
        };
      default:
        return {
          label: 'NORMAL',
          badgeClass: 'bg-emerald-500/15 text-emerald-400 border-emerald-500/40',
          dotClass: 'bg-emerald-400',
        };
    }
  };

  const threat = getThreatDot();

  const formatSessionTime = (seconds: number) => {
    const mins = Math.floor(seconds / 60);
    const secs = seconds % 60;
    return `${mins}:${secs < 10 ? '0' : ''}${secs}`;
  };

  // Strip "(Super Admin)" if accidentally embedded in fullName
  const cleanDisplayName = currentUser?.fullName?.replace(/\s*\(Super Admin\)/i, '').trim() || 'Abdulgaffar Bello';
  const roleDisplay = currentUser?.role === 'SUPER_ADMIN' ? 'SUPER_ADMIN' : currentUser?.role || 'OPERATOR';

  return (
    <header className="bg-slate-900/95 backdrop-blur-md border-b border-slate-800 sticky top-0 z-40 px-3 sm:px-6 py-2 transition-all w-full">
      <div className="w-full flex items-center justify-between gap-2 sm:gap-3">
        
        {/* ─── LEFT: Logo, Title & Tagline ─── */}
        <div className="flex items-center gap-2.5 sm:gap-3 shrink-0">
          <div 
            onClick={onGoHome}
            className="relative flex items-center justify-center w-9 h-9 sm:w-10 sm:h-10 rounded-xl bg-slate-950 p-1 shadow-md shadow-cyan-500/10 border border-slate-700/80 overflow-hidden cursor-pointer hover:border-cyan-500 transition shrink-0"
          >
            <img
              src="/logo.jpg"
              alt="The Watch Logo"
              className="w-full h-full object-contain rounded-lg"
            />
            <span className="absolute -top-0.5 -right-0.5 flex h-2 w-2">
              <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-cyan-400 opacity-75" />
              <span className="relative inline-flex rounded-full h-2 w-2 bg-cyan-500" />
            </span>
          </div>

          <div className="shrink-0">
            <div className="flex items-center gap-1.5 sm:gap-2">
              <h1 
                onClick={onGoHome}
                className="text-sm sm:text-base font-black tracking-wider text-white cursor-pointer hover:text-cyan-400 transition"
              >
                THE WATCH
              </h1>
              <span className="text-[9px] uppercase font-mono font-bold tracking-wider bg-cyan-950/90 text-cyan-400 border border-cyan-800/80 px-1.5 py-0.2 rounded">
                v2.4 SOC
              </span>
            </div>
            <p className="text-[10px] text-slate-400 flex items-center gap-1.5 font-mono">
              <span className="hidden sm:inline">Observability & Threat Gateway</span>
              <span className="text-slate-600 hidden sm:inline">•</span>
              <span className="text-cyan-400/90 text-[9.5px]">Zero Host Overhead</span>
            </p>
          </div>
        </div>

        {/* ─── CENTER: High-Resolution Operations Bar ─── */}
        <div className="hidden 2xl:flex items-center gap-2 shrink-0">
          {/* Segmented View Switcher */}
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

          {/* System Dropdown */}
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

          {/* Threat Pill */}
          <div className={`flex items-center gap-1.5 px-2.5 py-1 rounded-xl text-xs font-mono font-bold border shrink-0 ${threat.badgeClass}`}>
            <span className={`w-2 h-2 rounded-full ${threat.dotClass}`} />
            <span>THREAT: {threat.label}</span>
          </div>
        </div>

        {/* ─── RIGHT: WAT Clock, Session Inactivity, Auto-Refresh & PROMINENT LOGOUT ─── */}
        <div className="flex items-center gap-2 sm:gap-3 shrink-0">
          
          {/* WAT Clock */}
          <div className="hidden xl:flex items-center gap-1.5 bg-slate-950 border border-slate-800/80 px-2.5 py-1 rounded-xl text-[11px] font-mono text-slate-300 shrink-0">
            <Clock className="w-3.5 h-3.5 text-cyan-400" />
            <span>{watTime || 'WAT (UTC+1)'}</span>
          </div>

          {/* Session Inactivity Timeout Countdown */}
          {currentUser && typeof sessionTimeRemaining === 'number' && (
            <div 
              title="Session inactivity timeout (3 mins). Any action resets timer."
              className={`hidden sm:flex items-center gap-1.5 px-2.5 py-1 rounded-xl text-[11px] font-mono border transition shrink-0 ${
                sessionTimeRemaining <= 30
                  ? 'bg-rose-950/80 text-rose-300 border-rose-700/80 animate-pulse font-bold'
                  : 'bg-slate-950 text-slate-400 border-slate-800'
              }`}
            >
              <Timer className={`w-3.5 h-3.5 ${sessionTimeRemaining <= 30 ? 'text-rose-400' : 'text-slate-500'}`} />
              <span className="hidden md:inline text-[10px] uppercase text-slate-500">Timeout:</span>
              <span className="font-semibold">{formatSessionTime(sessionTimeRemaining)}</span>
            </div>
          )}

          {/* Telemetry Refresh Controls */}
          <div className="flex items-center gap-0.5 bg-slate-950 border border-slate-800 rounded-xl p-0.5 shrink-0">
            <select
              value={autoRefreshInterval}
              onChange={(e) => setAutoRefreshInterval(Number(e.target.value))}
              className="bg-transparent text-[11px] font-mono text-slate-400 px-1.5 py-1 focus:outline-none cursor-pointer"
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

          {/* ─── USER PROFILE & PROMINENT LOGOUT BUTTON ─── */}
          {currentUser ? (
            <div className="flex items-center gap-2 pl-2 border-l border-slate-800 shrink-0">
              {/* Stacked Name on Top & Role Below */}
              <div className="text-right flex flex-col justify-center leading-tight">
                <span className="text-xs font-bold text-white tracking-wide">
                  {cleanDisplayName}
                </span>
                <span className="text-[10px] text-cyan-400 font-mono font-bold tracking-wider uppercase mt-0.5">
                  {roleDisplay}
                </span>
              </div>

              {/* High-visibility Logout button with icon and label */}
              <button
                onClick={onLogout}
                title="Sign Out of SOC Session"
                className="flex items-center gap-1.5 px-2.5 py-1.5 rounded-lg bg-rose-950/60 hover:bg-rose-900/80 text-rose-300 hover:text-white border border-rose-800/80 hover:border-rose-600 transition shadow-sm cursor-pointer shrink-0"
              >
                <LogOut className="w-3.5 h-3.5 text-rose-400" />
                <span className="text-xs font-bold font-mono">Logout</span>
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

          {/* Mobile / Tablet Accordion Menu Toggle */}
          <div className="flex 2xl:hidden shrink-0">
            <button 
              onClick={() => setIsMobileMenuOpen(!isMobileMenuOpen)} 
              className="p-1.5 rounded-lg bg-slate-950 text-slate-400 hover:text-white border border-slate-800"
            >
              {isMobileMenuOpen ? <XIcon className="w-4 h-4" /> : <Menu className="w-4 h-4" />}
            </button>
          </div>

        </div>

      </div>

      {/* ─── RESPONSIVE ACCORDION MENU (For widths < 1536px) ─── */}
      {isMobileMenuOpen && (
        <div className="2xl:hidden mt-2.5 pt-2.5 border-t border-slate-800 space-y-2.5 animate-fadeIn">
          <div className="flex items-center justify-between">
            <div className={`flex items-center gap-1.5 px-2.5 py-1 rounded-xl text-xs font-mono font-bold border ${threat.badgeClass}`}>
              <span className={`w-2 h-2 rounded-full ${threat.dotClass}`} />
              <span>THREAT: {threat.label}</span>
            </div>

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
              <span>SOC Command</span>
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

          {/* Explicit mobile Logout button */}
          {currentUser && (
            <div className="pt-1 border-t border-slate-800/80">
              <button
                onClick={() => {
                  setIsMobileMenuOpen(false);
                  onLogout();
                }}
                className="w-full py-2 rounded-xl bg-rose-950/80 hover:bg-rose-900 text-rose-300 border border-rose-800 text-xs font-bold flex items-center justify-center gap-2 transition"
              >
                <LogOut className="w-4 h-4" />
                <span>Sign Out ({cleanDisplayName})</span>
              </button>
            </div>
          )}
        </div>
      )}

    </header>
  );
};
