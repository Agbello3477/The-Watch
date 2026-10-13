import React, { useState, useEffect } from 'react';
import { 
  ShieldAlert, 
  ShieldCheck,
  Activity, 
  Cpu, 
  Lock, 
  Terminal, 
  Zap, 
  CheckCircle2, 
  ArrowRight, 
  Layers,
  Users,
  Eye,
  Crosshair,
  KeyRound,
  Radio,
  Clock,
  Ban,
  Target,
  Sparkles,
  Server,
  AlertTriangle,
  Play
} from 'lucide-react';
import { AuthSessionUser } from '../types/dashboard';

interface LandingHomeProps {
  currentUser: AuthSessionUser | null;
  onOpenLogin: () => void;
  onEnterDashboard: () => void;
  onOpenUserManagement?: () => void;
}

export const LandingHome: React.FC<LandingHomeProps> = ({
  currentUser,
  onOpenLogin,
  onEnterDashboard,
  onOpenUserManagement,
}) => {
  const [watTime, setWatTime] = useState<string>('');
  const [activeTabPreview, setActiveTabPreview] = useState<'stream' | 'mitre' | 'playbooks'>('stream');

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

  return (
    <div className="min-h-screen bg-slate-950 text-slate-100 flex flex-col font-sans selection:bg-cyan-500 selection:text-black">
      {/* Top Ambient Cyber Grid & Glow */}
      <div className="absolute inset-0 bg-[linear-gradient(to_right,#081726_1px,transparent_1px),linear-gradient(to_bottom,#081726_1px,transparent_1px)] bg-[size:3.5rem_3.5rem] [mask-image:radial-gradient(ellipse_70%_50%_at_50%_0%,#000_80%,transparent_100%)] pointer-events-none" />

      {/* ─── 1. MISSION-CRITICAL OPERATIONAL TOPBAR ─────────────────────── */}
      <div className="relative z-20 bg-slate-950/95 border-b border-slate-800 text-[11px] font-mono py-1.5 px-4 sm:px-8 flex flex-wrap items-center justify-between gap-3 text-slate-400">
        <div className="flex items-center gap-4">
          <div className="flex items-center gap-1.5">
            <span className="relative flex h-2 w-2">
              <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-emerald-400 opacity-75"></span>
              <span className="relative inline-flex rounded-full h-2 w-2 bg-emerald-500"></span>
            </span>
            <span className="text-slate-300 font-bold">THREATCON 3 (ELEVATED)</span>
          </div>
          <span className="text-slate-600 hidden sm:inline">•</span>
          <div className="hidden sm:flex items-center gap-1 text-slate-300">
            <span>DEFENSE CLUSTER:</span>
            <span className="text-cyan-400">NATIONAL OPEN UNIVERSITY SOC</span>
          </div>
        </div>

        <div className="flex items-center gap-4">
          <div className="flex items-center gap-1.5 text-cyan-400">
            <Clock className="w-3.5 h-3.5" />
            <span>{watTime || 'WAT (UTC+1)'}</span>
          </div>
          <span className="text-slate-600 hidden md:inline">•</span>
          <div className="hidden md:flex items-center gap-1 text-emerald-400">
            <span>INGESTION STATUS:</span>
            <span>ACTIVE (0.00% OVERHEAD)</span>
          </div>
        </div>
      </div>

      {/* ─── 2. MAIN NAVIGATION HEADER ──────────────────────────────────── */}
      <header className="relative z-10 border-b border-slate-800/80 bg-slate-900/60 backdrop-blur-xl sticky top-0 px-4 sm:px-8 py-3.5">
        <div className="max-w-7xl mx-auto flex items-center justify-between gap-4">
          
          {/* Logo & Platform Designation */}
          <div className="flex items-center space-x-3.5 cursor-pointer" onClick={onEnterDashboard}>
            <div className="relative flex items-center justify-center w-11 h-11 rounded-xl bg-slate-950/90 p-1 shadow-lg shadow-cyan-500/10 border border-slate-700/80 overflow-hidden shrink-0">
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
              <div className="flex items-center space-x-2">
                <span className="font-black tracking-widest text-lg text-white font-mono">
                  THE WATCH
                </span>
                <span className="text-[9px] uppercase font-mono font-bold px-1.5 py-0.5 rounded bg-cyan-950 text-cyan-400 border border-cyan-800/80">
                  ENTERPRISE SOC v2.4
                </span>
              </div>
              <p className="text-[11px] text-slate-400 font-mono flex items-center gap-1.5">
                <span>Autonomous Observability & Threat Intelligence System</span>
              </p>
            </div>
          </div>

          {/* User Controls & Quick Access */}
          <div className="flex items-center space-x-3">
            {currentUser ? (
              <div className="flex items-center space-x-3">
                <div className="text-right hidden sm:block">
                  <div className="text-xs font-semibold text-slate-200">{currentUser.fullName}</div>
                  <div className="text-[10px] text-cyan-400 font-mono flex items-center justify-end space-x-1">
                    <span className="w-1.5 h-1.5 rounded-full bg-emerald-400 inline-block" />
                    <span>{currentUser.role}</span>
                  </div>
                </div>

                {currentUser.role === 'SUPER_ADMIN' && onOpenUserManagement && (
                  <button
                    onClick={onOpenUserManagement}
                    className="px-3 py-2 rounded-xl bg-slate-800 hover:bg-slate-700 text-slate-200 border border-slate-700 text-xs font-medium flex items-center space-x-1.5 transition"
                  >
                    <Users className="w-3.5 h-3.5 text-cyan-400" />
                    <span className="hidden md:inline">User Directory</span>
                  </button>
                )}

                <button
                  onClick={onEnterDashboard}
                  className="px-4 py-2 rounded-xl bg-gradient-to-r from-red-600 via-amber-600 to-cyan-500 hover:from-red-500 hover:to-cyan-400 text-white font-bold text-xs flex items-center space-x-2 shadow-lg shadow-cyan-500/20 transition transform active:scale-95"
                >
                  <ShieldAlert className="w-3.5 h-3.5 animate-pulse" />
                  <span>Launch SOC War Room</span>
                  <ArrowRight className="w-3.5 h-3.5" />
                </button>
              </div>
            ) : (
              <button
                onClick={onOpenLogin}
                className="px-4 py-2 rounded-xl bg-gradient-to-r from-cyan-500 to-blue-600 hover:from-cyan-400 hover:to-blue-500 text-slate-950 font-bold text-xs flex items-center space-x-2 shadow-lg shadow-cyan-500/25 transition transform active:scale-95"
              >
                <KeyRound className="w-3.5 h-3.5" />
                <span>Sign In to SOC Portal</span>
              </button>
            )}
          </div>
        </div>
      </header>

      {/* ─── 3. LIVE THREAT RADAR TICKER ────────────────────────────────── */}
      <div className="relative z-10 bg-slate-900/90 border-b border-slate-800/80 px-4 py-2 overflow-hidden">
        <div className="max-w-7xl mx-auto flex items-center gap-3 text-xs font-mono">
          <span className="px-2 py-0.5 rounded bg-red-950 text-red-400 border border-red-800 text-[10px] font-bold uppercase tracking-wider shrink-0 flex items-center gap-1">
            <Radio className="w-2.5 h-2.5 animate-ping" /> LIVE INTERCEPT FEED
          </span>
          <div className="text-slate-300 truncate">
            <span className="text-red-400 font-bold">[15:12 WAT] BLOCKED:</span> SQLi UNION exploit on <code className="text-cyan-300">NOUN-HRMS (/payroll/export)</code> from <code className="text-slate-200">194.26.29.112</code> · <span className="text-amber-400 font-bold">[15:10 WAT] QUARANTINED:</span> Tor Credential Stuffing on <code className="text-cyan-300">/auth/session</code> · <span className="text-emerald-400 font-bold">[15:08 WAT] RESOLVED:</span> Postgres query pool saturation mitigated
          </div>
        </div>
      </div>

      {/* ─── 4. HERO COMMAND CENTER ─────────────────────────────────────── */}
      <main className="relative z-10 flex-1 max-w-7xl mx-auto px-4 sm:px-8 py-10 md:py-16 space-y-16">
        
        <div className="grid grid-cols-1 lg:grid-cols-12 gap-8 lg:gap-12 items-center">
          
          {/* Left Column: Mission Briefing */}
          <div className="lg:col-span-7 space-y-6">
            <div className="inline-flex items-center space-x-2 px-3.5 py-1 rounded-full bg-cyan-950/80 border border-cyan-700/60 text-cyan-400 text-xs font-mono shadow-lg shadow-cyan-950/40">
              <span className="w-2 h-2 rounded-full bg-emerald-400 animate-ping" />
              <span>SOC SENTINEL ACTIVE • MULTI-TENANT INCIDENT DEFENSE</span>
            </div>

            <h1 className="text-3xl sm:text-5xl md:text-6xl font-black tracking-tight leading-[1.08] text-white">
              Institutional Cyber Observability.{' '}
              <span className="bg-gradient-to-r from-cyan-400 via-sky-300 to-indigo-400 bg-clip-text text-transparent">
                Real-Time SOC Threat Neutralization.
              </span>
            </h1>

            <p className="text-slate-300 text-sm sm:text-base md:text-lg leading-relaxed max-w-2xl font-light">
              An enterprise Security Operations Center (SOC) purpose-built for university platforms and critical infrastructure. Defends <strong className="text-white font-semibold">NOUN-HRMS</strong>, <strong className="text-white font-semibold">Clinic-EHR</strong>, and institutional services through non-blocking heuristic defense, SOAR playbooks, and active edge firewalling.
            </p>

            {/* Core SOC SLA Counters */}
            <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 pt-2">
              <div className="bg-slate-900/80 border border-slate-800 rounded-xl p-3">
                <div className="text-[10px] text-slate-400 font-mono uppercase">Mean Time to Detect</div>
                <div className="text-2xl font-black text-cyan-400 font-mono mt-0.5">14s MTTD</div>
                <div className="text-[10px] text-slate-500 font-mono">Automated Ingest</div>
              </div>

              <div className="bg-slate-900/80 border border-slate-800 rounded-xl p-3">
                <div className="text-[10px] text-slate-400 font-mono uppercase">Mean Time to Remediate</div>
                <div className="text-2xl font-black text-emerald-400 font-mono mt-0.5">18m MTTR</div>
                <div className="text-[10px] text-slate-500 font-mono">SOAR Playbooks</div>
              </div>

              <div className="bg-slate-900/80 border border-slate-800 rounded-xl p-3">
                <div className="text-[10px] text-slate-400 font-mono uppercase">Host App Overhead</div>
                <div className="text-2xl font-black text-indigo-400 font-mono mt-0.5">0.00%</div>
                <div className="text-[10px] text-slate-500 font-mono">Non-blocking</div>
              </div>

              <div className="bg-slate-900/80 border border-slate-800 rounded-xl p-3">
                <div className="text-[10px] text-slate-400 font-mono uppercase">SLA Adherence</div>
                <div className="text-2xl font-black text-amber-400 font-mono mt-0.5">98.4%</div>
                <div className="text-[10px] text-slate-500 font-mono">Strict P1/P2 Policy</div>
              </div>
            </div>

            {/* CTA Buttons */}
            <div className="pt-2 flex flex-wrap items-center gap-4">
              {currentUser ? (
                <button
                  onClick={onEnterDashboard}
                  className="px-6 py-3.5 rounded-xl bg-gradient-to-r from-red-600 via-amber-600 to-cyan-500 hover:from-red-500 hover:to-cyan-400 text-white font-extrabold text-sm flex items-center space-x-3 shadow-xl shadow-cyan-500/25 transition transform active:scale-95"
                >
                  <ShieldAlert className="w-4 h-4 animate-pulse" />
                  <span>Enter SOC War Room Console</span>
                  <ArrowRight className="w-4 h-4" />
                </button>
              ) : (
                <button
                  onClick={onOpenLogin}
                  className="px-6 py-3.5 rounded-xl bg-gradient-to-r from-cyan-500 via-blue-500 to-indigo-600 hover:from-cyan-400 hover:to-indigo-500 text-slate-950 font-extrabold text-sm flex items-center space-x-3 shadow-xl shadow-cyan-500/25 transition transform active:scale-95"
                >
                  <KeyRound className="w-4 h-4 text-slate-950" />
                  <span>Access Secure SOC Portal</span>
                  <ArrowRight className="w-4 h-4 text-slate-950" />
                </button>
              )}

              <button
                onClick={onEnterDashboard}
                className="px-5 py-3.5 rounded-xl bg-slate-900 hover:bg-slate-800 text-slate-200 border border-slate-700 text-sm font-semibold flex items-center space-x-2 transition"
              >
                <Terminal className="w-4 h-4 text-cyan-400" />
                <span>Connect Monitored Host</span>
              </button>
            </div>
          </div>

          {/* Right Column: Live Holographic SOC Operations Terminal HUD */}
          <div className="lg:col-span-5">
            <div className="relative rounded-2xl border border-cyan-800/60 bg-slate-900/90 p-5 shadow-2xl shadow-cyan-950/70 backdrop-blur-2xl space-y-4">
              
              {/* HUD Header */}
              <div className="flex items-center justify-between border-b border-slate-800 pb-3">
                <div className="flex items-center space-x-2">
                  <div className="w-2.5 h-2.5 rounded-full bg-emerald-400 animate-pulse" />
                  <span className="text-xs font-mono font-bold text-slate-200 uppercase tracking-wider">
                    SOC THREAT INTERCEPT TERMINAL
                  </span>
                </div>
                <div className="flex gap-1">
                  {(['stream', 'mitre', 'playbooks'] as const).map((sub) => (
                    <button
                      key={sub}
                      onClick={() => setActiveTabPreview(sub)}
                      className={`text-[10px] font-mono px-2 py-0.5 rounded transition ${
                        activeTabPreview === sub
                          ? 'bg-cyan-500 text-slate-950 font-bold'
                          : 'bg-slate-950 text-slate-400 hover:text-white'
                      }`}
                    >
                      {sub.toUpperCase()}
                    </button>
                  ))}
                </div>
              </div>

              {/* HUD Screen 1: Real-Time Stream */}
              {activeTabPreview === 'stream' && (
                <div className="space-y-3 font-mono text-xs">
                  <div className="grid grid-cols-2 gap-2 text-[11px]">
                    <div className="bg-slate-950 border border-slate-800 p-2.5 rounded-lg">
                      <span className="text-slate-500 block text-[10px]">INGESTION SINK</span>
                      <span className="text-cyan-400 font-bold">HTTP / UDP Port 9876</span>
                    </div>
                    <div className="bg-slate-950 border border-slate-800 p-2.5 rounded-lg">
                      <span className="text-slate-500 block text-[10px]">ACTIVE QUARANTINES</span>
                      <span className="text-red-400 font-bold">3 Offending IPs Banned</span>
                    </div>
                  </div>

                  {/* Packet Intercept Feed */}
                  <div className="bg-slate-950 rounded-xl p-3 border border-slate-800/90 space-y-2">
                    <div className="flex items-center justify-between text-[10px] text-slate-400">
                      <span>PACKET DISPATCH STREAM</span>
                      <span className="text-emerald-400 flex items-center gap-1">
                        <span className="w-1.5 h-1.5 rounded-full bg-emerald-400 animate-ping"></span>
                        SYNCHRONIZED
                      </span>
                    </div>

                    <div className="space-y-1.5 text-[11px]">
                      <div className="p-2 rounded bg-red-950/40 border border-red-900/50 text-red-300">
                        <div className="flex justify-between font-bold">
                          <span>[P1] SQLi UNION Attack</span>
                          <span className="text-red-400">403 DROPPED</span>
                        </div>
                        <div className="text-[10px] text-slate-400 truncate mt-0.5">
                          Src: 194.26.29.112 (AS37075) → /api/v1/payroll/export
                        </div>
                      </div>

                      <div className="p-2 rounded bg-amber-950/40 border border-amber-900/50 text-amber-300">
                        <div className="flex justify-between font-bold">
                          <span>[P2] Credential Stuffing</span>
                          <span className="text-amber-400">QUARANTINED</span>
                        </div>
                        <div className="text-[10px] text-slate-400 truncate mt-0.5">
                          Src: 185.220.101.5 (Tor Exit) → /api/v1/auth/session
                        </div>
                      </div>

                      <div className="p-2 rounded bg-emerald-950/30 border border-emerald-900/40 text-emerald-300">
                        <div className="flex justify-between font-bold">
                          <span>Normal Staff Telemetry</span>
                          <span className="text-emerald-400">200 ACCEPTED</span>
                        </div>
                        <div className="text-[10px] text-slate-400 truncate mt-0.5">
                          Src: 102.89.23.45 (Abuja) → /api/v1/dashboard/overview
                        </div>
                      </div>
                    </div>
                  </div>
                </div>
              )}

              {/* HUD Screen 2: MITRE Matrix */}
              {activeTabPreview === 'mitre' && (
                <div className="space-y-2 text-xs font-mono">
                  <div className="text-[11px] text-slate-400">Enterprise MITRE ATT&CK Matrix Alignment:</div>
                  <div className="grid grid-cols-2 gap-2 text-[10px]">
                    <div className="p-2 rounded bg-slate-950 border border-slate-800">
                      <div className="text-slate-500">INITIAL ACCESS</div>
                      <div className="font-bold text-red-400 mt-1">T1190 Exploit Public App</div>
                      <div className="text-slate-400 mt-0.5">38 SQLi / DDL Triggers</div>
                    </div>
                    <div className="p-2 rounded bg-slate-950 border border-slate-800">
                      <div className="text-slate-500">CREDENTIAL ACCESS</div>
                      <div className="font-bold text-amber-400 mt-1">T1110.004 Brute Force</div>
                      <div className="text-slate-400 mt-0.5">19 Auth Bursts Blocked</div>
                    </div>
                    <div className="p-2 rounded bg-slate-950 border border-slate-800">
                      <div className="text-slate-500">DEFENSE EVASION</div>
                      <div className="font-bold text-cyan-400 mt-1">T1083 Directory Discovery</div>
                      <div className="text-slate-400 mt-0.5">14 Path Traversal Probes</div>
                    </div>
                    <div className="p-2 rounded bg-slate-950 border border-slate-800">
                      <div className="text-slate-500">IMPACT / DDOS</div>
                      <div className="font-bold text-indigo-400 mt-1">T1499 Denial of Service</div>
                      <div className="text-slate-400 mt-0.5">7 Volumetric Floods</div>
                    </div>
                  </div>
                </div>
              )}

              {/* HUD Screen 3: SOAR Playbooks */}
              {activeTabPreview === 'playbooks' && (
                <div className="space-y-2 text-xs font-mono">
                  <div className="text-[11px] text-slate-400">Automated SOAR Incident Containments:</div>
                  <div className="space-y-1.5 text-[10px]">
                    <div className="p-2 rounded bg-slate-950 border border-slate-800 flex items-center justify-between">
                      <div>
                        <div className="font-bold text-amber-400">PB-SQLI-01</div>
                        <div className="text-slate-400">SQL Injection Containment</div>
                      </div>
                      <span className="text-emerald-400">✓ Auto-Quarantine</span>
                    </div>
                    <div className="p-2 rounded bg-slate-950 border border-slate-800 flex items-center justify-between">
                      <div>
                        <div className="font-bold text-amber-400">PB-BRUTE-02</div>
                        <div className="text-slate-400">Credential Stuffing Defense</div>
                      </div>
                      <span className="text-emerald-400">✓ Invalidate Sessions</span>
                    </div>
                    <div className="p-2 rounded bg-slate-950 border border-slate-800 flex items-center justify-between">
                      <div>
                        <div className="font-bold text-amber-400">PB-DDOS-03</div>
                        <div className="text-slate-400">Layer 7 Traffic Flood Guard</div>
                      </div>
                      <span className="text-emerald-400">✓ Edge Drop Active</span>
                    </div>
                  </div>
                </div>
              )}

              {/* Monitored Host Status */}
              <div className="bg-slate-950/80 border border-slate-800 rounded-xl p-3 flex items-center justify-between text-xs font-mono">
                <div>
                  <div className="text-[10px] text-slate-500">ACTIVE MONITORED TENANCY</div>
                  <div className="font-bold text-slate-200 mt-0.5">NOUN-HRMS (Flagship University)</div>
                </div>
                <button
                  onClick={onEnterDashboard}
                  className="px-3 py-1.5 rounded-lg bg-cyan-600 hover:bg-cyan-500 text-slate-950 font-bold text-[11px] transition"
                >
                  Inspect Host →
                </button>
              </div>

            </div>
          </div>

        </div>

        {/* ─── 5. CORE SOC OPERATIONAL CAPABILITIES MATRIX ─────────────── */}
        <div className="space-y-6 pt-8 border-t border-slate-800">
          <div>
            <div className="inline-flex items-center space-x-1.5 text-xs font-mono text-cyan-400 font-bold uppercase tracking-wider mb-1">
              <ShieldAlert className="w-4 h-4" />
              <span>Full-Spectrum Enterprise SOC Capabilities</span>
            </div>
            <h2 className="text-2xl sm:text-3xl font-black text-white">
              Six Specialized Security Modules Operating 24/7
            </h2>
            <p className="text-xs sm:text-sm text-slate-400 max-w-2xl mt-1">
              Engineered according to NIST SP 800-61 Rev. 2 computer security incident handling guidelines.
            </p>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
            
            {/* Capability 1 */}
            <div className="bg-slate-900/60 border border-slate-800 rounded-2xl p-6 space-y-3 hover:border-cyan-500/60 transition group">
              <div className="w-10 h-10 rounded-xl bg-red-950 text-red-400 flex items-center justify-center border border-red-800/60 group-hover:scale-105 transition">
                <ShieldAlert className="w-5 h-5" />
              </div>
              <h3 className="font-bold text-base text-slate-100 font-mono">Tiered Triage & Incident War Room</h3>
              <p className="text-xs text-slate-400 leading-relaxed">
                Prioritized queue management (P1 Critical to P4 Low), active SLA countdown clocks (15m P1 SLA), digital evidence lockers, and encrypted timeline notes for SOC analysts.
              </p>
            </div>

            {/* Capability 2 */}
            <div className="bg-slate-900/60 border border-slate-800 rounded-2xl p-6 space-y-3 hover:border-cyan-500/60 transition group">
              <div className="w-10 h-10 rounded-xl bg-cyan-950 text-cyan-400 flex items-center justify-center border border-cyan-800/60 group-hover:scale-105 transition">
                <Ban className="w-5 h-5" />
              </div>
              <h3 className="font-bold text-base text-slate-100 font-mono">Edge Ingest Firewall & IP Quarantine</h3>
              <p className="text-xs text-slate-400 leading-relaxed">
                Dynamic IP blocklist enforcement. Drops malicious traffic on ingress with immediate HTTP 403. Generates copy-paste Cloudflare WAF and Nginx upstream rule exports.
              </p>
            </div>

            {/* Capability 3 */}
            <div className="bg-slate-900/60 border border-slate-800 rounded-2xl p-6 space-y-3 hover:border-cyan-500/60 transition group">
              <div className="w-10 h-10 rounded-xl bg-indigo-950 text-indigo-400 flex items-center justify-center border border-indigo-800/60 group-hover:scale-105 transition">
                <Target className="w-5 h-5" />
              </div>
              <h3 className="font-bold text-base text-slate-100 font-mono">Enterprise MITRE ATT&CK Matrix</h3>
              <p className="text-xs text-slate-400 leading-relaxed">
                Full 11-tactic behavioral attack mapping (Initial Access, Credential Access, Defense Evasion, Exfiltration). Live heatmap telemetry displaying active threat concentrations.
              </p>
            </div>

            {/* Capability 4 */}
            <div className="bg-slate-900/60 border border-slate-800 rounded-2xl p-6 space-y-3 hover:border-cyan-500/60 transition group">
              <div className="w-10 h-10 rounded-xl bg-amber-950 text-amber-400 flex items-center justify-center border border-amber-800/60 group-hover:scale-105 transition">
                <Play className="w-5 h-5" />
              </div>
              <h3 className="font-bold text-base text-slate-100 font-mono">Automated SOAR Incident Playbooks</h3>
              <p className="text-xs text-slate-400 leading-relaxed">
                One-click containment workflows for SQL injection, credential stuffing, DDoS floods, and data exfiltration. Auto-terminates hanging queries and revokes compromised sessions.
              </p>
            </div>

            {/* Capability 5 */}
            <div className="bg-slate-900/60 border border-slate-800 rounded-2xl p-6 space-y-3 hover:border-cyan-500/60 transition group">
              <div className="w-10 h-10 rounded-xl bg-emerald-950 text-emerald-400 flex items-center justify-center border border-emerald-800/60 group-hover:scale-105 transition">
                <Radio className="w-5 h-5" />
              </div>
              <h3 className="font-bold text-base text-slate-100 font-mono">Threat Intelligence (CTI) & IOC Feed</h3>
              <p className="text-xs text-slate-400 leading-relaxed">
                Indicators of Compromise repository tracking bulletproof proxies, Tor exit nodes, C2 domains (<code className="text-emerald-400">c2-exfil.tor</code>), with confidence ratings and threat actor attribution.
              </p>
            </div>

            {/* Capability 6 */}
            <div className="bg-slate-900/60 border border-slate-800 rounded-2xl p-6 space-y-3 hover:border-cyan-500/60 transition group">
              <div className="w-10 h-10 rounded-xl bg-sky-950 text-sky-400 flex items-center justify-center border border-sky-800/60 group-hover:scale-105 transition">
                <Sparkles className="w-5 h-5" />
              </div>
              <h3 className="font-bold text-base text-slate-100 font-mono">Self-Healing Remediation Advisor</h3>
              <p className="text-xs text-slate-400 leading-relaxed">
                When database regressions, pool starvation, or 5xx crashes occur, the advisor generates step-by-step TypeScript patches and parameterized SQL rewrites in real time.
              </p>
            </div>

          </div>
        </div>

        {/* ─── 6. HOST ISOLATION ARCHITECTURE BLUEPRINT ──────────────────── */}
        <div className="bg-slate-900/40 border border-slate-800 rounded-2xl p-6 sm:p-8 space-y-6">
          <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
            <div>
              <div className="text-xs font-mono text-emerald-400 font-bold uppercase tracking-wider">
                ZERO HOST APPLICATION OVERHEAD
              </div>
              <h3 className="text-xl font-bold text-slate-100 mt-1">
                How The Watch Monitors NOUN-HRMS with Zero Latency Penalty
              </h3>
            </div>
            <span className="text-xs font-mono text-cyan-400 px-3 py-1 rounded-full bg-cyan-950 border border-cyan-800/70 self-start md:self-auto">
              Fire-and-Forget Asynchronous Pipeline
            </span>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-4 gap-4 text-xs font-mono">
            <div className="bg-slate-950 border border-slate-800 p-4 rounded-xl space-y-2">
              <div className="text-cyan-400 font-bold">1. Sentinel Middleware</div>
              <p className="text-slate-400 text-[11px] leading-relaxed">
                Imported once in HRMS <code className="text-slate-300">app.use(sentinelAgent)</code>. Redacts sensitive passwords/BVNs in memory.
              </p>
            </div>

            <div className="bg-slate-950 border border-slate-800 p-4 rounded-xl space-y-2">
              <div className="text-emerald-400 font-bold">2. Response Finish Hook</div>
              <p className="text-slate-400 text-[11px] leading-relaxed">
                Hooks into Node.js <code className="text-slate-300">res.on('finish')</code>. Dispatches telemetry only AFTER user receives response.
              </p>
            </div>

            <div className="bg-slate-950 border border-slate-800 p-4 rounded-xl space-y-2">
              <div className="text-indigo-400 font-bold">3. Ingest Gateway</div>
              <p className="text-slate-400 text-[11px] leading-relaxed">
                Receives micro-payloads, verifies <code className="text-slate-300">X-Telemetry-Key</code>, checks IP firewall, and acknowledges in &lt; 1ms.
              </p>
            </div>

            <div className="bg-slate-950 border border-slate-800 p-4 rounded-xl space-y-2">
              <div className="text-amber-400 font-bold">4. SOC Heuristic Engine</div>
              <p className="text-slate-400 text-[11px] leading-relaxed">
                Asynchronous worker evaluates SQLi, DDoS, and auth bursts. Auto-escalates critical attacks to SOC cases with SLA timers.
              </p>
            </div>
          </div>
        </div>

        {/* ─── 7. ENTERPRISE ACCESS CALLOUT ──────────────────────────────── */}
        <div className="bg-gradient-to-r from-slate-900 via-indigo-950/40 to-slate-900 border border-indigo-900/60 rounded-2xl p-6 sm:p-8 flex flex-col md:flex-row items-center justify-between gap-6 shadow-2xl">
          <div className="space-y-1.5 text-center md:text-left">
            <div className="text-xs font-mono uppercase text-indigo-400 font-bold tracking-wider">
              AUTHORIZATION & GOVERNANCE
            </div>
            <h3 className="text-xl font-bold text-white">
              Institutional Staff & SOC Operator Access
            </h3>
            <p className="text-xs text-slate-400 max-w-xl leading-relaxed">
              Protected by PBKDF2 cryptographic hashing (100,000 iterations), brute-force defense lockout (5 attempts / 15-minute freeze), and full WAT audit logging.
            </p>
          </div>

          <div className="flex items-center gap-3 shrink-0">
            {currentUser ? (
              <button
                onClick={onEnterDashboard}
                className="px-6 py-3 rounded-xl bg-gradient-to-r from-cyan-500 to-blue-600 hover:from-cyan-400 hover:to-blue-500 text-slate-950 font-bold text-xs shadow-lg shadow-cyan-500/25 transition"
              >
                Go to SOC Console
              </button>
            ) : (
              <button
                onClick={onOpenLogin}
                className="px-6 py-3 rounded-xl bg-gradient-to-r from-cyan-500 to-blue-600 hover:from-cyan-400 hover:to-blue-500 text-slate-950 font-bold text-xs shadow-lg shadow-cyan-500/25 transition"
              >
                Sign In to SOC Portal
              </button>
            )}
          </div>
        </div>

      </main>

      {/* ─── 8. FOOTER WITH MASHA TECH INNOVATIONS BRANDING ─────────────── */}
      <footer className="relative z-10 border-t border-slate-800/80 bg-slate-950/90 py-6 px-6 text-xs text-slate-400">
        <div className="max-w-7xl mx-auto flex flex-col sm:flex-row items-center justify-between gap-4">
          <div className="flex items-center gap-2.5">
            <img src="/logo.jpg" alt="Logo" className="w-6 h-6 object-contain rounded" />
            <span className="font-bold text-slate-200 tracking-wider font-mono">THE WATCH</span>
            <span className="text-slate-600">•</span>
            <span className="text-cyan-400 font-semibold tracking-wide">
              Powered by: MaSha Tech Innovations
            </span>
          </div>

          <div className="text-slate-500 font-mono text-[11px] flex flex-wrap items-center gap-2">
            <span>Timezone: West Africa Time (WAT / UTC+1)</span>
            <span>•</span>
            <span>National Open University Cyber Defense System</span>
          </div>
        </div>
      </footer>
    </div>
  );
};
