import React, { useState, useEffect, useCallback } from 'react';
import { Header } from './components/Header';
import { HealthGaugeCard } from './components/HealthGaugeCard';
import { ThreatMap } from './components/ThreatMap';
import { HeartbeatGrid } from './components/HeartbeatGrid';
import { IncidentFeed } from './components/IncidentFeed';
import { QueryLatencyAnalyzer } from './components/QueryLatencyAnalyzer';
import { RemediationAdvisor } from './components/RemediationAdvisor';
import { ReportExporter } from './components/ReportExporter';
import { AttackSimulator } from './components/AttackSimulator';
import { TrafficMonitor } from './components/TrafficMonitor';
import { LandingHome } from './components/LandingHome';
import { LoginModal } from './components/LoginModal';
import { UserManagement } from './components/UserManagement';
import { ConnectionPanel } from './components/ConnectionPanel';
import { SocCommandCenter } from './components/SocCommandCenter';
import { RealtimeThreatAlertPrompt, LiveThreatAlert } from './components/RealtimeThreatAlertPrompt';
import { api, authStorage } from './services/api';
import {
  SystemOverview,
  ThreatIncident,
  SyntheticProbe,
  ThreatMapNode,
  QueryMetricsResponse,
  AdvisorResponse,
  AuthSessionUser,
} from './types/dashboard';
import { Globe, Activity, Sparkles, FileText, Flame, Users, ShieldCheck, ShieldAlert } from 'lucide-react';

export const App: React.FC = () => {
  const [selectedSystem, setSelectedSystem] = useState<string>('');
  const [currentView, setCurrentView] = useState<'home' | 'dashboard' | 'users'>('home');
  const [activeSocTab, setActiveSocTab] = useState<'soc' | 'threats' | 'observability' | 'advisor' | 'reports' | 'simulator' | 'traffic' | 'connect'>('soc');
  
  // Auth state
  const [currentUser, setCurrentUser] = useState<AuthSessionUser | null>(authStorage.getUser());
  const [isLoginModalOpen, setIsLoginModalOpen] = useState<boolean>(false);

  // Telemetry data states
  const [overview, setOverview] = useState<SystemOverview | null>(null);
  const [threatNodes, setThreatNodes] = useState<ThreatMapNode[]>([]);
  const [probes, setProbes] = useState<SyntheticProbe[]>([]);
  const [incidents, setIncidents] = useState<ThreatIncident[]>([]);
  const [queryMetrics, setQueryMetrics] = useState<QueryMetricsResponse | null>(null);
  const [advisorData, setAdvisorData] = useState<AdvisorResponse | null>(null);
  
  // UI states
  const [isRefreshing, setIsRefreshing] = useState<boolean>(false);
  const [autoRefreshInterval, setAutoRefreshInterval] = useState<number>(5000);

  // 3-Minute Session Inactivity Timeout (180 seconds)
  const INACTIVITY_TIMEOUT_SECONDS = 180;
  const [sessionTimeRemaining, setSessionTimeRemaining] = useState<number>(INACTIVITY_TIMEOUT_SECONDS);
  const [sessionTimeoutNotice, setSessionTimeoutNotice] = useState<boolean>(false);

  // Validate active auth session on mount
  useEffect(() => {
    const verifySession = async () => {
      if (authStorage.getToken()) {
        const res = await api.getMe();
        if (res.sessionValid && res.user) {
          const cleanUser = {
            ...res.user,
            fullName: res.user.fullName?.replace(/\s*\(Super Admin\)/i, '').trim() || 'Abdulgaffar Bello',
          };
          setCurrentUser(cleanUser);
          authStorage.setUser(cleanUser);
        } else {
          setCurrentUser(null);
        }
      }
    };
    verifySession();
  }, []);

  // Inactivity tracking: resets on any user interaction (mousemove, keydown, click, scroll, touchstart)
  useEffect(() => {
    if (!currentUser) {
      setSessionTimeRemaining(INACTIVITY_TIMEOUT_SECONDS);
      return;
    }

    let lastActivityTime = Date.now();

    const handleUserActivity = () => {
      lastActivityTime = Date.now();
      setSessionTimeRemaining(INACTIVITY_TIMEOUT_SECONDS);
    };

    const activityEvents = ['mousemove', 'keydown', 'mousedown', 'touchstart', 'scroll'];
    activityEvents.forEach((ev) => window.addEventListener(ev, handleUserActivity, { passive: true }));

    // Tick every 1 second
    const interval = setInterval(() => {
      const elapsedSeconds = Math.floor((Date.now() - lastActivityTime) / 1000);
      const remaining = Math.max(0, INACTIVITY_TIMEOUT_SECONDS - elapsedSeconds);
      setSessionTimeRemaining(remaining);

      if (remaining === 0) {
        // Automatically terminate session due to 3-minute inactivity
        clearInterval(interval);
        api.logout().catch(() => {});
        setCurrentUser(null);
        setCurrentView('home');
        setSessionTimeoutNotice(true);
      }
    }, 1000);

    return () => {
      activityEvents.forEach((ev) => window.removeEventListener(ev, handleUserActivity));
      clearInterval(interval);
    };
  }, [currentUser]);

  // Real-time Click Monitoring & Recording for every interactive action across all users
  useEffect(() => {
    let lastTracked = 0;
    let lastTargetText = '';

    const handleGlobalClick = (event: MouseEvent) => {
      const target = event.target as HTMLElement | null;
      if (!target) return;

      // Identify interactive elements (buttons, links, menu items, tabs, inputs)
      const interactiveEl = target.closest('button, a, [role="button"], input[type="submit"], select, [data-track]');
      if (!interactiveEl) return;

      const rawText = (
        interactiveEl.getAttribute('data-track') ||
        interactiveEl.getAttribute('aria-label') ||
        interactiveEl.getAttribute('title') ||
        interactiveEl.textContent?.trim().slice(0, 80) ||
        interactiveEl.tagName.toLowerCase()
      ).replace(/\s+/g, ' ');

      const now = Date.now();
      // Throttle identical rapid clicks within 800ms
      if (now - lastTracked < 800 && lastTargetText === rawText) {
        return;
      }

      lastTracked = now;
      lastTargetText = rawText;

      const tagName = interactiveEl.tagName.toLowerCase();
      const details = `Clicked <${tagName}> "${rawText}"`;

      api.trackUserAction({
        action: 'CLICK',
        details,
        target: rawText,
      });
    };

    window.addEventListener('click', handleGlobalClick, { capture: true, passive: true });
    return () => {
      window.removeEventListener('click', handleGlobalClick, { capture: true });
    };
  }, [currentUser]);

  const fetchData = useCallback(async () => {
    if (currentView === 'home') return; // Don't aggressively poll when on home view
    setIsRefreshing(true);
    try {
      const [
        overviewRes,
        threatMapRes,
        probesRes,
        incidentsRes,
        queriesRes,
        advisorRes,
      ] = await Promise.all([
        api.getOverview(selectedSystem || undefined),
        api.getThreatMap(selectedSystem || undefined),
        api.getProbes(selectedSystem || undefined),
        api.getIncidents({ systemId: selectedSystem || undefined, limit: 50 }),
        api.getQueryMetrics(selectedSystem || undefined, false),
        api.getAdvisorRecommendations(selectedSystem || undefined),
      ]);

      setOverview(overviewRes);
      setThreatNodes(threatMapRes.nodes || []);
      setProbes(probesRes || []);
      setIncidents(incidentsRes || []);
      setQueryMetrics(queriesRes);
      setAdvisorData(advisorRes);
    } catch (err) {
      console.error('[Dashboard] Error fetching telemetry data:', err);
    } finally {
      setIsRefreshing(false);
    }
  }, [selectedSystem, currentView]);

  useEffect(() => {
    if (currentView !== 'home') {
      fetchData();
    }

    if (autoRefreshInterval > 0 && currentView !== 'home') {
      const timer = setInterval(fetchData, autoRefreshInterval);
      return () => clearInterval(timer);
    }
  }, [fetchData, autoRefreshInterval, currentView]);

  const handleUpdateIncidentStatus = async (id: string, status: 'ACKNOWLEDGED' | 'RESOLVED') => {
    // 1. Immediate optimistic UI update
    setIncidents((prev) =>
      prev.map((inc) => (inc.id === id ? { ...inc, status } : inc))
    );
    setOverview((prev) => {
      if (!prev) return prev;
      return {
        ...prev,
        unresolvedIncidents: Math.max(0, prev.unresolvedIncidents - (status === 'RESOLVED' ? 1 : 0)),
      };
    });

    try {
      await api.updateIncidentStatus(id, status);
    } catch (err) {
      console.error('[Incident] Failed to update status on server:', err);
    }

    await fetchData();
  };

  const handleRunProbe = async (id: string) => {
    await api.runProbe(id);
    await fetchData();
  };

  const handleLoginSuccess = (user: AuthSessionUser) => {
    const cleanUser = {
      ...user,
      fullName: user.fullName?.replace(/\s*\(Super Admin\)/i, '').trim() || 'Abdulgaffar Bello',
    };
    setCurrentUser(cleanUser);
    authStorage.setUser(cleanUser);
    // If super admin, stay ready or navigate to SOC
    if (currentView === 'home') {
      setCurrentView('dashboard');
    }
  };

  const handleLogout = async () => {
    await api.logout();
    setCurrentUser(null);
    setCurrentView('home');
  };

  const handleTabChangeFromHeader = (tab: string) => {
    if (tab === 'home') {
      setCurrentView('home');
    } else if (tab === 'users') {
      setCurrentView('users');
    } else {
      setCurrentView('dashboard');
    }
  };

  const handleViewThreatInWarRoom = (alert: LiveThreatAlert) => {
    setCurrentView('dashboard');
    setActiveSocTab('soc');
    fetchData();
  };

  // If on landing home page:
  if (currentView === 'home') {
    return (
      <>
        {/* Real-time Threat Alert Floating HUD Prompt */}
        <RealtimeThreatAlertPrompt
          onViewWarRoom={handleViewThreatInWarRoom}
          onAlertNeutralized={() => fetchData()}
        />

        <LandingHome
          currentUser={currentUser}
          onOpenLogin={() => setIsLoginModalOpen(true)}
          onEnterDashboard={() => setCurrentView('dashboard')}
          onOpenUserManagement={() => setCurrentView('users')}
        />
        <LoginModal
          isOpen={isLoginModalOpen}
          onClose={() => setIsLoginModalOpen(false)}
          onLoginSuccess={handleLoginSuccess}
        />

        {/* 3-Minute Session Inactivity Timeout Notification Modal */}
        {sessionTimeoutNotice && (
          <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-slate-950/85 backdrop-blur-md animate-fadeIn">
            <div className="relative w-full max-w-sm bg-slate-900 border border-amber-500/50 rounded-2xl p-6 shadow-2xl shadow-amber-950/60 text-center space-y-4">
              <div className="w-12 h-12 rounded-2xl bg-amber-500/10 border border-amber-500/30 flex items-center justify-center mx-auto text-amber-400">
                <ShieldAlert className="w-6 h-6 animate-pulse" />
              </div>

              <div>
                <h3 className="text-base font-bold text-white">Session Timed Out</h3>
                <p className="text-xs text-slate-300 mt-1 font-mono">
                  For security compliance, your active session was terminated following 3 minutes of inactivity.
                </p>
              </div>

              <button
                onClick={() => {
                  setSessionTimeoutNotice(false);
                  setIsLoginModalOpen(true);
                }}
                className="w-full py-2.5 rounded-xl bg-gradient-to-r from-cyan-500 to-blue-600 hover:from-cyan-400 hover:to-blue-500 text-slate-950 font-bold text-xs transition shadow-lg shadow-cyan-500/25 cursor-pointer"
              >
                Sign In Again
              </button>
            </div>
          </div>
        )}
      </>
    );
  }

  return (
    <div className="min-h-screen bg-slate-950 text-slate-100 flex flex-col font-sans selection:bg-cyan-500 selection:text-black">
      
      {/* 1. Header Bar with Auth, Navigation & WAT Clock */}
      <Header
        overview={overview}
        selectedSystem={selectedSystem}
        onSelectSystem={setSelectedSystem}
        onRefresh={fetchData}
        isRefreshing={isRefreshing}
        autoRefreshInterval={autoRefreshInterval}
        setAutoRefreshInterval={setAutoRefreshInterval}
        currentUser={currentUser}
        activeTab={currentView === 'users' ? 'users' : 'overview'}
        onTabChange={handleTabChangeFromHeader}
        onOpenLogin={() => setIsLoginModalOpen(true)}
        onLogout={handleLogout}
        onGoHome={() => setCurrentView('home')}
        sessionTimeRemaining={sessionTimeRemaining}
      />

      {/* Main Content Area */}
      <main className="flex-1 max-w-7xl w-full mx-auto px-4 sm:px-6 py-6 space-y-6">
        
        {/* VIEW 1: SUPER ADMIN USER MANAGEMENT CONSOLE */}
        {currentView === 'users' && currentUser?.role === 'SUPER_ADMIN' && (
          <UserManagement currentUser={currentUser} />
        )}

        {/* VIEW 2: SOC TELEMETRY & COMMAND CENTER */}
        {currentView === 'dashboard' && (
          <>
            {/* Platform Reliability Gauges */}
            <HealthGaugeCard overview={overview} />

            {/* Sub-Navigation Tabs */}
            <div className="flex overflow-x-auto whitespace-nowrap scrollbar-hide items-center justify-between gap-3 border-b border-slate-800 pb-3" style={{ scrollbarWidth: 'none', msOverflowStyle: 'none' }}>
              <div className="flex items-center gap-1 bg-slate-900 p-1 rounded-xl border border-slate-800 shrink-0">
                
                <button
                  onClick={() => setActiveSocTab('soc')}
                  className={`flex items-center gap-2 px-3.5 py-1.5 rounded-lg text-xs font-bold transition ${
                    activeSocTab === 'soc'
                      ? 'bg-gradient-to-r from-red-600 to-amber-600 text-white shadow-lg shadow-red-600/30'
                      : 'text-red-400 hover:text-red-300 hover:bg-slate-800/60'
                  }`}
                >
                  <ShieldAlert className="w-3.5 h-3.5 animate-pulse" />
                  <span>SOC War Room & Ops</span>
                  <span className="bg-red-950 text-red-300 border border-red-800 text-[10px] font-mono px-1.5 py-0.2 rounded-full">
                    LIVE
                  </span>
                </button>

                <button
                  onClick={() => setActiveSocTab('threats')}
                  className={`flex items-center gap-2 px-3.5 py-1.5 rounded-lg text-xs font-bold transition ${
                    activeSocTab === 'threats'
                      ? 'bg-cyan-500 text-slate-950 shadow-lg shadow-cyan-500/20'
                      : 'text-slate-400 hover:text-slate-200'
                  }`}
                >
                  <Globe className="w-3.5 h-3.5" />
                  <span>Threat Radar & Incidents</span>
                  {(overview?.unresolvedIncidents || 0) > 0 && (
                    <span className="bg-red-500 text-white text-[10px] font-mono px-1.5 py-0.2 rounded-full">
                      {overview?.unresolvedIncidents}
                    </span>
                  )}
                </button>

                <button
                  onClick={() => setActiveSocTab('observability')}
                  className={`flex items-center gap-2 px-3.5 py-1.5 rounded-lg text-xs font-bold transition ${
                    activeSocTab === 'observability'
                      ? 'bg-cyan-500 text-slate-950 shadow-lg shadow-cyan-500/20'
                      : 'text-slate-400 hover:text-slate-200'
                  }`}
                >
                  <Activity className="w-3.5 h-3.5" />
                  <span>Probes & Query Latency</span>
                </button>

                <button
                  onClick={() => setActiveSocTab('advisor')}
                  className={`flex items-center gap-2 px-3.5 py-1.5 rounded-lg text-xs font-bold transition ${
                    activeSocTab === 'advisor'
                      ? 'bg-cyan-500 text-slate-950 shadow-lg shadow-cyan-500/20'
                      : 'text-slate-400 hover:text-slate-200'
                  }`}
                >
                  <Sparkles className="w-3.5 h-3.5" />
                  <span>Self-Healing Advisor</span>
                </button>

                <button
                  onClick={() => setActiveSocTab('reports')}
                  className={`flex items-center gap-2 px-3.5 py-1.5 rounded-lg text-xs font-bold transition ${
                    activeSocTab === 'reports'
                      ? 'bg-cyan-500 text-slate-950 shadow-lg shadow-cyan-500/20'
                      : 'text-slate-400 hover:text-slate-200'
                  }`}
                >
                  <FileText className="w-3.5 h-3.5" />
                  <span>Forensic Reports (PDF/CSV)</span>
                </button>

                <button
                  onClick={() => setActiveSocTab('simulator')}
                  className={`flex items-center gap-2 px-3.5 py-1.5 rounded-lg text-xs font-bold transition ${
                    activeSocTab === 'simulator'
                      ? 'bg-orange-500 text-slate-950 shadow-lg shadow-orange-500/20'
                      : 'text-orange-400 hover:text-orange-300'
                  }`}
                >
                  <Flame className="w-3.5 h-3.5" />
                  <span>Attack Simulator</span>
                </button>

                <button
                  onClick={() => setActiveSocTab('traffic')}
                  className={`flex items-center gap-2 px-3.5 py-1.5 rounded-lg text-xs font-bold transition ${
                    activeSocTab === 'traffic'
                      ? 'bg-emerald-500 text-slate-950 shadow-lg shadow-emerald-500/20'
                      : 'text-emerald-400 hover:text-emerald-300'
                  }`}
                >
                  <Activity className="w-3.5 h-3.5" />
                  <span>HRMS Traffic</span>
                </button>

                <button
                  onClick={() => setActiveSocTab('connect')}
                  className={`flex items-center gap-2 px-3.5 py-1.5 rounded-lg text-xs font-bold transition ${
                    activeSocTab === 'connect'
                      ? 'bg-cyan-500 text-slate-950 shadow-lg shadow-cyan-500/20'
                      : 'text-cyan-400 hover:text-cyan-300'
                  }`}
                >
                  <Globe className="w-3.5 h-3.5" />
                  <span>Connect Systems</span>
                </button>

              </div>

              <span className="text-xs text-slate-500 font-mono hidden md:inline">
                Timezone: West Africa Time (WAT / UTC+1)
              </span>
            </div>

            {/* Tab Content Panes */}
            {activeSocTab === 'soc' && (
              <div className="space-y-6">
                <SocCommandCenter
                  currentUser={currentUser}
                  selectedSystem={selectedSystem}
                />
              </div>
            )}

            {activeSocTab === 'threats' && (
              <div className="space-y-6">
                <ThreatMap nodes={threatNodes} />
                <IncidentFeed
                  incidents={incidents}
                  onUpdateStatus={handleUpdateIncidentStatus}
                />
              </div>
            )}

            {activeSocTab === 'observability' && (
              <div className="space-y-6">
                <HeartbeatGrid probes={probes} onRunProbe={handleRunProbe} />
                <QueryLatencyAnalyzer data={queryMetrics} />
              </div>
            )}

            {activeSocTab === 'advisor' && (
              <div className="space-y-6">
                <RemediationAdvisor advisorData={advisorData} />
              </div>
            )}

            {activeSocTab === 'reports' && (
              <div className="space-y-6">
                <ReportExporter selectedSystem={selectedSystem} />
              </div>
            )}

            {activeSocTab === 'simulator' && (
              <div className="space-y-6">
                <AttackSimulator
                  selectedSystem={selectedSystem}
                  onSimulationTriggered={fetchData}
                />
              </div>
            )}

            {activeSocTab === 'traffic' && (
              <div className="space-y-6">
                <TrafficMonitor selectedSystem={selectedSystem || 'NOUN-HRMS'} />
              </div>
            )}

            {activeSocTab === 'connect' && (
              <div className="space-y-6">
                <ConnectionPanel />
              </div>
            )}
          </>
        )}

      </main>

      {/* Footer with MaSha Tech Innovations Branding */}
      <footer className="bg-slate-900/80 border-t border-slate-800 py-4 px-6 text-xs text-slate-400">
        <div className="max-w-7xl mx-auto flex flex-col sm:flex-row items-center justify-between gap-3">
          <div className="flex items-center gap-2.5">
            <img src="/logo.jpg" alt="Logo" className="w-6 h-6 object-contain rounded" />
            <span className="font-bold text-slate-200 tracking-wider">THE WATCH</span>
            <span className="text-slate-600">•</span>
            <span className="text-cyan-400 font-semibold tracking-wide">
              Powered by: MaSha Tech Innovations
            </span>
          </div>
          <div className="text-slate-500 font-mono text-[11px] flex items-center gap-2">
            <span>West Africa Time (WAT / UTC+1)</span>
            <span>•</span>
            <span>National Open University SOC</span>
          </div>
        </div>
      </footer>

      {/* Real-time Threat Alert Floating HUD Prompt */}
      <RealtimeThreatAlertPrompt
        onViewWarRoom={handleViewThreatInWarRoom}
        onAlertNeutralized={() => fetchData()}
      />

      {/* Global Login Modal */}
      <LoginModal
        isOpen={isLoginModalOpen}
        onClose={() => setIsLoginModalOpen(false)}
        onLoginSuccess={handleLoginSuccess}
      />

      {/* 3-Minute Session Inactivity Timeout Notification Modal */}
      {sessionTimeoutNotice && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-slate-950/85 backdrop-blur-md animate-fadeIn">
          <div className="relative w-full max-w-sm bg-slate-900 border border-amber-500/50 rounded-2xl p-6 shadow-2xl shadow-amber-950/60 text-center space-y-4">
            <div className="w-12 h-12 rounded-2xl bg-amber-500/10 border border-amber-500/30 flex items-center justify-center mx-auto text-amber-400">
              <ShieldAlert className="w-6 h-6 animate-pulse" />
            </div>

            <div>
              <h3 className="text-base font-bold text-white">Session Timed Out</h3>
              <p className="text-xs text-slate-300 mt-1 font-mono">
                For security compliance, your active session was terminated following 3 minutes of inactivity.
              </p>
            </div>

            <button
              onClick={() => {
                setSessionTimeoutNotice(false);
                setIsLoginModalOpen(true);
              }}
              className="w-full py-2.5 rounded-xl bg-gradient-to-r from-cyan-500 to-blue-600 hover:from-cyan-400 hover:to-blue-500 text-slate-950 font-bold text-xs transition shadow-lg shadow-cyan-500/25 cursor-pointer"
            >
              Sign In Again
            </button>
          </div>
        </div>
      )}

    </div>
  );
};

export default App;
