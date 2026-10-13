import React, { useState, useEffect, useCallback } from 'react';
import {
  Wifi, WifiOff, Copy, CheckCheck, Terminal, Key, AlertTriangle,
  RefreshCw, ExternalLink, ShieldCheck, Clock
} from 'lucide-react';

const API = (import.meta as any).env?.VITE_API_URL || 'http://localhost:4000';

interface Tenant {
  systemId: string;
  name: string;
  description: string;
  primaryContact: string;
  enabled: boolean;
  apiKey: string;
  apiSecret: string;
}

interface ConnectionStatus {
  systemId: string;
  isConnected: boolean;
  lastSeen: string | null;
  minutesSinceLastPing: number | null;
  recentRequestCount: number;
  status: 'LIVE' | 'STALE' | 'DISCONNECTED';
  message: string;
}

interface SdkConfig {
  systemId: string;
  name: string;
  ingestUrl: string;
  xTelemetryKey: string;
  xTelemetrySecret: string;
  envSnippet: string;
  curlTest: string;
  instructions: string[];
}

function CopyButton({ text, label }: { text: string; label?: string }) {
  const [copied, setCopied] = useState(false);
  const copy = () => {
    navigator.clipboard.writeText(text).then(() => {
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    });
  };
  return (
    <button
      onClick={copy}
      className="flex items-center gap-1 px-2 py-1 rounded text-[10px] font-mono bg-slate-800 hover:bg-slate-700 text-slate-400 hover:text-cyan-400 border border-slate-700 transition"
    >
      {copied ? <CheckCheck className="w-3 h-3 text-emerald-400" /> : <Copy className="w-3 h-3" />}
      {copied ? 'Copied!' : (label || 'Copy')}
    </button>
  );
}

function StatusBadge({ status }: { status: ConnectionStatus['status'] }) {
  if (status === 'LIVE') return (
    <span className="flex items-center gap-1.5 px-2.5 py-1 rounded-full text-[11px] font-bold bg-emerald-500/15 text-emerald-400 border border-emerald-500/30">
      <span className="relative flex h-2 w-2">
        <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-emerald-400 opacity-75" />
        <span className="relative inline-flex rounded-full h-2 w-2 bg-emerald-500" />
      </span>
      LIVE
    </span>
  );
  if (status === 'STALE') return (
    <span className="flex items-center gap-1.5 px-2.5 py-1 rounded-full text-[11px] font-bold bg-yellow-500/15 text-yellow-400 border border-yellow-500/30">
      <Clock className="w-3 h-3" />
      STALE
    </span>
  );
  return (
    <span className="flex items-center gap-1.5 px-2.5 py-1 rounded-full text-[11px] font-bold bg-red-500/15 text-red-400 border border-red-500/30">
      <WifiOff className="w-3 h-3" />
      DISCONNECTED
    </span>
  );
}

export const ConnectionPanel: React.FC = () => {
  const [tenants, setTenants] = useState<Tenant[]>([]);
  const [statuses, setStatuses] = useState<Record<string, ConnectionStatus>>({});
  const [selectedTenant, setSelectedTenant] = useState<string>('NOUN-HRMS');
  const [sdkConfig, setSdkConfig] = useState<SdkConfig | null>(null);
  const [loading, setLoading] = useState(true);
  const [refreshing, setRefreshing] = useState(false);
  const [activeTab, setActiveTab] = useState<'status' | 'setup' | 'test'>('status');

  const fetchAll = useCallback(async () => {
    try {
      const res = await fetch(`${API}/api/v1/tenants`);
      const data = await res.json();
      const tenantList: Tenant[] = data.tenants || [];
      setTenants(tenantList);

      // Fetch connection status for each tenant in parallel
      const statusResults = await Promise.all(
        tenantList.map((t) =>
          fetch(`${API}/api/v1/tenants/${t.systemId}/connection-status`)
            .then((r) => r.json())
            .catch(() => ({ systemId: t.systemId, status: 'DISCONNECTED', isConnected: false, message: 'Unable to check status', lastSeen: null, minutesSinceLastPing: null, recentRequestCount: 0 }))
        )
      );

      const statusMap: Record<string, ConnectionStatus> = {};
      statusResults.forEach((s) => { statusMap[s.systemId] = s; });
      setStatuses(statusMap);
    } catch (e) {
      // silently fail
    } finally {
      setLoading(false);
      setRefreshing(false);
    }
  }, []);

  const fetchSdkConfig = useCallback(async (systemId: string) => {
    try {
      const res = await fetch(`${API}/api/v1/tenants/${systemId}/sdk-config`);
      const data = await res.json();
      setSdkConfig(data);
    } catch {
      setSdkConfig(null);
    }
  }, []);

  useEffect(() => {
    fetchAll();
    const interval = setInterval(fetchAll, 15000); // refresh status every 15s
    return () => clearInterval(interval);
  }, [fetchAll]);

  useEffect(() => {
    if (selectedTenant) fetchSdkConfig(selectedTenant);
  }, [selectedTenant, fetchSdkConfig]);

  const handleRefresh = () => {
    setRefreshing(true);
    fetchAll();
  };

  const sentinelAgentCode = `// ─── sentinel-agent.ts ───────────────────────────────────────
// Drop-in middleware. Mount BEFORE all your routes.
//
// Your HRMS .env:
//   THE_WATCH_URL=${sdkConfig?.ingestUrl?.replace('/api/v1/telemetry/ingest', '') || API}
//   THE_WATCH_API_KEY=${sdkConfig?.xTelemetryKey || 'tel_sec_noun_hrms_98234'}
//   THE_WATCH_SYSTEM_ID=${selectedTenant}

import type { Request, Response, NextFunction } from 'express';

const INGEST = \`\${process.env.THE_WATCH_URL}/api/v1/telemetry/ingest\`;
const KEY    = process.env.THE_WATCH_API_KEY || '';
const SYSTEM = process.env.THE_WATCH_SYSTEM_ID || '${selectedTenant}';

export function sentinelAgent(req: Request, res: Response, next: NextFunction) {
  const t0 = Date.now();
  res.on('finish', () => {
    const body = { ...req.body };
    ['password','token','secret','bvn','pin'].forEach(k => { if (body[k]) body[k] = '[REDACTED]'; });
    fetch(INGEST, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'X-Telemetry-Key': KEY },
      body: JSON.stringify({
        systemId: SYSTEM, method: req.method, path: req.originalUrl,
        statusCode: res.statusCode, latencyMs: Date.now() - t0,
        clientIp: req.headers['x-forwarded-for']?.toString().split(',')[0] || req.ip,
        userAgent: req.headers['user-agent'],
        payloadSnippet: JSON.stringify(body).slice(0, 300),
        errorMessage: res.statusCode >= 500 ? \`HTTP \${res.statusCode}\` : undefined,
      }),
    }).catch(() => {}); // fire-and-forget — never blocks HRMS
  });
  next();
}

// In your app.ts — mount FIRST:
// import { sentinelAgent } from './middleware/sentinel-agent';
// app.use(sentinelAgent);
`;

  if (loading) return (
    <div className="flex items-center justify-center py-20 text-slate-400">
      <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-cyan-400 mr-3" />
      Loading connection status...
    </div>
  );

  const selected = statuses[selectedTenant];

  return (
    <div className="flex flex-col gap-6">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
        <div>
          <h2 className="text-xl font-bold text-slate-100 flex items-center gap-2">
            <Wifi className="w-5 h-5 text-cyan-400" />
            System Connection Manager
          </h2>
          <p className="text-sm text-slate-400 mt-1">
            Register and monitor live connections between The Watch and your institutional systems.
          </p>
        </div>
        <button
          onClick={handleRefresh}
          disabled={refreshing}
          className="flex items-center gap-2 px-3 py-2 rounded-lg bg-slate-800 border border-slate-700 text-slate-300 hover:text-white text-sm transition"
        >
          <RefreshCw className={`w-4 h-4 ${refreshing ? 'animate-spin text-cyan-400' : ''}`} />
          Refresh
        </button>
      </div>

      {/* Connection Status Cards */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-4">
        {tenants.map((t) => {
          const s = statuses[t.systemId];
          return (
            <button
              key={t.systemId}
              onClick={() => setSelectedTenant(t.systemId)}
              className={`text-left p-4 rounded-xl border transition ${
                selectedTenant === t.systemId
                  ? 'bg-slate-800 border-cyan-500/50 shadow-lg shadow-cyan-500/10'
                  : 'bg-slate-900 border-slate-800 hover:border-slate-700'
              }`}
            >
              <div className="flex items-start justify-between gap-2 mb-2">
                <div className="font-bold text-slate-200 text-sm">{t.systemId}</div>
                {s && <StatusBadge status={s.status} />}
              </div>
              <div className="text-xs text-slate-400 mb-3 leading-relaxed">{t.name}</div>
              {s?.isConnected ? (
                <div className="text-[11px] text-emerald-400 font-mono">
                  {s.recentRequestCount} recent requests · last {s.minutesSinceLastPing ?? '?'}m ago
                </div>
              ) : (
                <div className="text-[11px] text-red-400 font-mono flex items-center gap-1">
                  <AlertTriangle className="w-3 h-3" /> Not sending telemetry
                </div>
              )}
            </button>
          );
        })}
      </div>

      {/* Detail Panel for Selected Tenant */}
      {selected && sdkConfig && (
        <div className="bg-slate-900 border border-slate-800 rounded-2xl overflow-hidden">
          {/* Detail Header */}
          <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 p-5 border-b border-slate-800 bg-slate-950/50">
            <div className="flex items-center gap-3">
              <div className={`p-2 rounded-lg ${selected.isConnected ? 'bg-emerald-500/10' : 'bg-red-500/10'}`}>
                {selected.isConnected
                  ? <ShieldCheck className="w-5 h-5 text-emerald-400" />
                  : <WifiOff className="w-5 h-5 text-red-400" />
                }
              </div>
              <div>
                <div className="font-bold text-slate-100">{selectedTenant}</div>
                <div className="text-xs text-slate-400">{selected.message}</div>
              </div>
            </div>
            <StatusBadge status={selected.status} />
          </div>

          {/* Sub-tabs */}
          <div className="flex border-b border-slate-800 overflow-x-auto">
            {(['status', 'setup', 'test'] as const).map((tab) => (
              <button
                key={tab}
                onClick={() => setActiveTab(tab)}
                className={`px-5 py-3 text-xs font-bold uppercase tracking-wider whitespace-nowrap transition ${
                  activeTab === tab
                    ? 'text-cyan-400 border-b-2 border-cyan-500 bg-slate-800/50'
                    : 'text-slate-500 hover:text-slate-300'
                }`}
              >
                {tab === 'status' ? '📊 Connection Status' : tab === 'setup' ? '⚙️ Integration Setup' : '🧪 Test Connection'}
              </button>
            ))}
          </div>

          <div className="p-5">
            {/* STATUS TAB */}
            {activeTab === 'status' && (
              <div className="space-y-4">
                <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
                  <div className="bg-slate-950 border border-slate-800 rounded-lg p-4">
                    <div className="text-slate-400 text-xs uppercase tracking-wider mb-1">Status</div>
                    <div className={`text-lg font-bold ${selected.isConnected ? 'text-emerald-400' : 'text-red-400'}`}>
                      {selected.status}
                    </div>
                  </div>
                  <div className="bg-slate-950 border border-slate-800 rounded-lg p-4">
                    <div className="text-slate-400 text-xs uppercase tracking-wider mb-1">Last Seen</div>
                    <div className="text-sm font-mono text-slate-200">
                      {selected.lastSeen
                        ? new Date(selected.lastSeen).toLocaleString('en-GB', { timeZone: 'Africa/Lagos', hour12: false })
                        : 'Never'}
                    </div>
                  </div>
                  <div className="bg-slate-950 border border-slate-800 rounded-lg p-4">
                    <div className="text-slate-400 text-xs uppercase tracking-wider mb-1">Recent Requests</div>
                    <div className="text-lg font-bold text-slate-200">{selected.recentRequestCount}</div>
                  </div>
                  <div className="bg-slate-950 border border-slate-800 rounded-lg p-4">
                    <div className="text-slate-400 text-xs uppercase tracking-wider mb-1">Ingest URL</div>
                    <div className="text-[10px] font-mono text-cyan-400 truncate">{sdkConfig.ingestUrl}</div>
                  </div>
                </div>

                {!selected.isConnected && (
                  <div className="bg-amber-500/10 border border-amber-500/30 rounded-xl p-4 flex gap-3">
                    <AlertTriangle className="w-5 h-5 text-amber-400 shrink-0 mt-0.5" />
                    <div>
                      <div className="font-bold text-amber-300 text-sm mb-1">HRMS not sending telemetry</div>
                      <div className="text-xs text-amber-200/80">
                        The Sentinel Agent is not installed or not running in <strong>{selectedTenant}</strong>.
                        Go to the <strong>Integration Setup</strong> tab to get your API key and installation code.
                      </div>
                      <button
                        onClick={() => setActiveTab('setup')}
                        className="mt-3 px-3 py-1.5 rounded-lg bg-amber-500 text-slate-950 text-xs font-bold hover:bg-amber-400 transition"
                      >
                        View Setup Instructions →
                      </button>
                    </div>
                  </div>
                )}
              </div>
            )}

            {/* SETUP TAB */}
            {activeTab === 'setup' && (
              <div className="space-y-5">
                {/* Step indicators */}
                <div className="flex flex-col sm:flex-row gap-3">
                  {['1. Add env vars', '2. Install middleware', '3. Deploy & verify'].map((step, i) => (
                    <div key={i} className="flex items-center gap-2 bg-slate-950 border border-slate-800 rounded-lg px-4 py-2.5 flex-1">
                      <div className="w-5 h-5 rounded-full bg-cyan-500/20 border border-cyan-500/50 text-cyan-400 text-[10px] font-bold flex items-center justify-center shrink-0">
                        {i + 1}
                      </div>
                      <span className="text-xs text-slate-300 font-medium">{step.slice(3)}</span>
                    </div>
                  ))}
                </div>

                {/* API Key */}
                <div>
                  <div className="flex items-center gap-2 mb-2">
                    <Key className="w-4 h-4 text-yellow-400" />
                    <span className="text-sm font-semibold text-slate-200">Step 1 — Add to your HRMS <code className="text-cyan-400">.env</code> file</span>
                    <CopyButton text={sdkConfig.envSnippet} label="Copy .env" />
                  </div>
                  <pre className="bg-slate-950 border border-slate-800 rounded-lg p-4 text-xs font-mono text-emerald-300 overflow-x-auto">
{sdkConfig.envSnippet}
                  </pre>
                </div>

                {/* Middleware code */}
                <div>
                  <div className="flex items-center gap-2 mb-2">
                    <Terminal className="w-4 h-4 text-cyan-400" />
                    <span className="text-sm font-semibold text-slate-200">Step 2 — Install the Sentinel Agent middleware</span>
                    <CopyButton text={sentinelAgentCode} label="Copy code" />
                  </div>
                  <pre className="bg-slate-950 border border-slate-800 rounded-lg p-4 text-[11px] font-mono text-slate-300 overflow-x-auto max-h-72 overflow-y-auto">
{sentinelAgentCode}
                  </pre>
                </div>

                <div className="bg-slate-950/80 border border-slate-800 rounded-lg p-4 text-xs text-slate-400 leading-relaxed">
                  <strong className="text-slate-200">⚡ Zero performance impact guarantee:</strong> The sentinel agent hooks into Node.js's
                  <code className="text-cyan-400 mx-1">res.on('finish')</code> event — it ships telemetry <em>after</em> the response has
                  already been sent to the user. Your HRMS never waits for The Watch.
                </div>
              </div>
            )}

            {/* TEST TAB */}
            {activeTab === 'test' && (
              <div className="space-y-5">
                <div>
                  <div className="flex items-center gap-2 mb-2">
                    <Terminal className="w-4 h-4 text-emerald-400" />
                    <span className="text-sm font-semibold text-slate-200">Test with cURL (run this in your terminal)</span>
                    <CopyButton text={sdkConfig.curlTest} label="Copy cURL" />
                  </div>
                  <pre className="bg-slate-950 border border-slate-800 rounded-lg p-4 text-xs font-mono text-emerald-300 overflow-x-auto whitespace-pre-wrap">
{sdkConfig.curlTest}
                  </pre>
                </div>

                <div>
                  <div className="flex items-center gap-2 mb-2">
                    <ExternalLink className="w-4 h-4 text-blue-400" />
                    <span className="text-sm font-semibold text-slate-200">Check connection status endpoint directly</span>
                    <CopyButton text={`${API}/api/v1/tenants/${selectedTenant}/connection-status`} label="Copy URL" />
                  </div>
                  <div className="bg-slate-950 border border-slate-800 rounded-lg p-4 font-mono text-xs text-blue-400 break-all">
                    GET {API}/api/v1/tenants/{selectedTenant}/connection-status
                  </div>
                </div>

                <div className="bg-emerald-500/5 border border-emerald-500/20 rounded-lg p-4 text-xs text-slate-300 leading-relaxed">
                  <strong className="text-emerald-400">After running the cURL command:</strong>
                  <ul className="mt-2 space-y-1.5 list-disc list-inside text-slate-400">
                    <li>Come back to the <strong>Connection Status</strong> tab and click <strong>Refresh</strong></li>
                    <li>The status badge should change from <span className="text-red-400">DISCONNECTED</span> to <span className="text-emerald-400">LIVE</span></li>
                    <li>Switch to the <strong>HRMS Traffic</strong> tab to see the request appear in the live feed</li>
                  </ul>
                </div>
              </div>
            )}
          </div>
        </div>
      )}

      <div className="text-center text-xs text-slate-500 py-2">
        Powered by: MaSha Tech Innovations
      </div>
    </div>
  );
};
