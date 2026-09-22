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
import { api } from './services/api';
import {
  SystemOverview,
  ThreatIncident,
  SyntheticProbe,
  ThreatMapNode,
  QueryMetricsResponse,
  AdvisorResponse,
} from './types/dashboard';
import { Globe, Activity, Sparkles, FileText, Flame, ShieldAlert } from 'lucide-react';

export const App: React.FC = () => {
  const [selectedSystem, setSelectedSystem] = useState<string>('');
  const [activeTab, setActiveTab] = useState<'threats' | 'observability' | 'advisor' | 'reports' | 'simulator'>('threats');
  
  // Data states
  const [overview, setOverview] = useState<SystemOverview | null>(null);
  const [threatNodes, setThreatNodes] = useState<ThreatMapNode[]>([]);
  const [probes, setProbes] = useState<SyntheticProbe[]>([]);
  const [incidents, setIncidents] = useState<ThreatIncident[]>([]);
  const [queryMetrics, setQueryMetrics] = useState<QueryMetricsResponse | null>(null);
  const [advisorData, setAdvisorData] = useState<AdvisorResponse | null>(null);
  
  // UI states
  const [isRefreshing, setIsRefreshing] = useState<boolean>(false);
  const [autoRefreshInterval, setAutoRefreshInterval] = useState<number>(5000);

  const fetchData = useCallback(async () => {
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
  }, [selectedSystem]);

  useEffect(() => {
    fetchData();

    if (autoRefreshInterval > 0) {
      const timer = setInterval(fetchData, autoRefreshInterval);
      return () => clearInterval(timer);
    }
  }, [fetchData, autoRefreshInterval]);

  const handleUpdateIncidentStatus = async (id: string, status: 'ACKNOWLEDGED' | 'RESOLVED') => {
    await api.updateIncidentStatus(id, status);
    await fetchData();
  };

  const handleRunProbe = async (id: string) => {
    await api.runProbe(id);
    await fetchData();
  };

  return (
    <div className="min-h-screen bg-slate-950 text-slate-100 flex flex-col font-sans">
      
      {/* 1. Header Bar */}
      <Header
        overview={overview}
        selectedSystem={selectedSystem}
        onSelectSystem={setSelectedSystem}
        onRefresh={fetchData}
        isRefreshing={isRefreshing}
        autoRefreshInterval={autoRefreshInterval}
        setAutoRefreshInterval={setAutoRefreshInterval}
      />

      {/* Main Content Area */}
      <main className="flex-1 max-w-7xl w-full mx-auto px-4 sm:px-6 py-6 space-y-6">
        
        {/* 2. Platform Reliability Gauges */}
        <HealthGaugeCard overview={overview} />

        {/* 3. Navigation Tabs */}
        <div className="flex flex-wrap items-center justify-between gap-3 border-b border-slate-800 pb-3">
          <div className="flex items-center gap-1 bg-slate-900 p-1 rounded-xl border border-slate-800">
            
            <button
              onClick={() => setActiveTab('threats')}
              className={`flex items-center gap-2 px-3.5 py-1.5 rounded-lg text-xs font-bold transition ${
                activeTab === 'threats'
                  ? 'bg-cyan-500 text-white shadow-lg shadow-cyan-500/20'
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
              onClick={() => setActiveTab('observability')}
              className={`flex items-center gap-2 px-3.5 py-1.5 rounded-lg text-xs font-bold transition ${
                activeTab === 'observability'
                  ? 'bg-cyan-500 text-white shadow-lg shadow-cyan-500/20'
                  : 'text-slate-400 hover:text-slate-200'
              }`}
            >
              <Activity className="w-3.5 h-3.5" />
              <span>Probes & Query Latency</span>
            </button>

            <button
              onClick={() => setActiveTab('advisor')}
              className={`flex items-center gap-2 px-3.5 py-1.5 rounded-lg text-xs font-bold transition ${
                activeTab === 'advisor'
                  ? 'bg-cyan-500 text-white shadow-lg shadow-cyan-500/20'
                  : 'text-slate-400 hover:text-slate-200'
              }`}
            >
              <Sparkles className="w-3.5 h-3.5" />
              <span>Self-Healing Advisor</span>
            </button>

            <button
              onClick={() => setActiveTab('reports')}
              className={`flex items-center gap-2 px-3.5 py-1.5 rounded-lg text-xs font-bold transition ${
                activeTab === 'reports'
                  ? 'bg-cyan-500 text-white shadow-lg shadow-cyan-500/20'
                  : 'text-slate-400 hover:text-slate-200'
              }`}
            >
              <FileText className="w-3.5 h-3.5" />
              <span>Forensic Reports (PDF/CSV)</span>
            </button>

            <button
              onClick={() => setActiveTab('simulator')}
              className={`flex items-center gap-2 px-3.5 py-1.5 rounded-lg text-xs font-bold transition ${
                activeTab === 'simulator'
                  ? 'bg-orange-500 text-white shadow-lg shadow-orange-500/20'
                  : 'text-orange-400 hover:text-orange-300'
              }`}
            >
              <Flame className="w-3.5 h-3.5" />
              <span>Attack Simulator</span>
            </button>

          </div>

          <span className="text-xs text-slate-500 font-mono hidden md:inline">
            Status: Synchronized (WAT)
          </span>
        </div>

        {/* 4. Tab Content Panes */}
        {activeTab === 'threats' && (
          <div className="space-y-6">
            <ThreatMap nodes={threatNodes} />
            <IncidentFeed
              incidents={incidents}
              onUpdateStatus={handleUpdateIncidentStatus}
            />
          </div>
        )}

        {activeTab === 'observability' && (
          <div className="space-y-6">
            <HeartbeatGrid probes={probes} onRunProbe={handleRunProbe} />
            <QueryLatencyAnalyzer data={queryMetrics} />
          </div>
        )}

        {activeTab === 'advisor' && (
          <div className="space-y-6">
            <RemediationAdvisor advisorData={advisorData} />
          </div>
        )}

        {activeTab === 'reports' && (
          <div className="space-y-6">
            <ReportExporter selectedSystem={selectedSystem} />
          </div>
        )}

        {activeTab === 'simulator' && (
          <div className="space-y-6">
            <AttackSimulator
              selectedSystem={selectedSystem}
              onSimulationTriggered={fetchData}
            />
          </div>
        )}

      </main>

      {/* Footer with MaSha Tech Innovations Branding */}
      <footer className="bg-slate-900/80 border-t border-slate-800 py-4 px-6 text-xs text-slate-400">
        <div className="max-w-7xl mx-auto flex flex-col sm:flex-row items-center justify-between gap-3">
          <div className="flex items-center gap-2.5">
            <img src="/logo.jpg" alt="Logo" className="w-6 h-6 object-contain rounded" />
            <span className="font-bold text-slate-200 tracking-wider">THE WATCH</span>
            <span className="text-slate-600">•</span>
            <span className="text-amber-400 font-semibold tracking-wide">
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

    </div>
  );
};

export default App;
