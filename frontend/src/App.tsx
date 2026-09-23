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
import { LandingHome } from './components/LandingHome';
import { LoginModal } from './components/LoginModal';
import { UserManagement } from './components/UserManagement';
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
import { Globe, Activity, Sparkles, FileText, Flame, Users, ShieldCheck } from 'lucide-react';

export const App: React.FC = () => {
  const [selectedSystem, setSelectedSystem] = useState<string>('');
  const [currentView, setCurrentView] = useState<'home' | 'dashboard' | 'users'>('home');
  const [activeSocTab, setActiveSocTab] = useState<'threats' | 'observability' | 'advisor' | 'reports' | 'simulator'>('threats');
  
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

  // Validate active auth session on mount
  useEffect(() => {
    const verifySession = async () => {
      if (authStorage.getToken()) {
        const res = await api.getMe();
        if (res.sessionValid && res.user) {
          setCurrentUser(res.user);
          authStorage.setUser(res.user);
        } else {
          setCurrentUser(null);
        }
      }
    };
    verifySession();
  }, []);

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
    await api.updateIncidentStatus(id, status);
    await fetchData();
  };

  const handleRunProbe = async (id: string) => {
    await api.runProbe(id);
    await fetchData();
  };

  const handleLoginSuccess = (user: AuthSessionUser) => {
    setCurrentUser(user);
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

  // If on landing home page:
  if (currentView === 'home') {
    return (
      <>
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
            <div className="flex flex-wrap items-center justify-between gap-3 border-b border-slate-800 pb-3">
              <div className="flex items-center gap-1 bg-slate-900 p-1 rounded-xl border border-slate-800">
                
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

              </div>

              <span className="text-xs text-slate-500 font-mono hidden md:inline">
                Timezone: West Africa Time (WAT / UTC+1)
              </span>
            </div>

            {/* Tab Content Panes */}
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

      {/* Global Login Modal */}
      <LoginModal
        isOpen={isLoginModalOpen}
        onClose={() => setIsLoginModalOpen(false)}
        onLoginSuccess={handleLoginSuccess}
      />

    </div>
  );
};

export default App;
