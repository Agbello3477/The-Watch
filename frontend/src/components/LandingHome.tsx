import React from 'react';
import { 
  ShieldAlert, 
  Activity, 
  Cpu, 
  Lock, 
  Terminal, 
  Zap, 
  FileText, 
  Server, 
  CheckCircle2, 
  ArrowRight, 
  Layers,
  Users,
  Eye,
  Crosshair,
  KeyRound
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
  return (
    <div className="min-h-screen bg-slate-950 text-slate-100 flex flex-col selection:bg-cyan-500 selection:text-black">
      {/* Top Ambient Cyber Grid & Glow */}
      <div className="absolute inset-0 bg-[linear-gradient(to_right,#081726_1px,transparent_1px),linear-gradient(to_bottom,#081726_1px,transparent_1px)] bg-[size:4rem_4rem] [mask-image:radial-gradient(ellipse_60%_50%_at_50%_0%,#000_70%,transparent_100%)] pointer-events-none" />

      {/* Navigation Bar */}
      <header className="relative z-10 border-b border-slate-800/80 bg-slate-950/70 backdrop-blur-md sticky top-0 px-6 py-4">
        <div className="max-w-7xl mx-auto flex items-center justify-between">
          <div className="flex items-center space-x-3">
            <div className="w-10 h-10 rounded-xl bg-gradient-to-tr from-cyan-600 via-blue-600 to-indigo-600 p-[1.5px] shadow-lg shadow-cyan-500/20">
              <div className="w-full h-full bg-slate-950 rounded-[10px] flex items-center justify-center">
                <ShieldAlert className="w-5 h-5 text-cyan-400 animate-pulse" />
              </div>
            </div>
            <div>
              <div className="flex items-center space-x-2">
                <span className="font-extrabold tracking-wider text-lg bg-gradient-to-r from-cyan-400 via-blue-300 to-indigo-200 bg-clip-text text-transparent">
                  THE WATCH
                </span>
                <span className="text-[10px] uppercase font-mono px-2 py-0.5 rounded bg-cyan-950 text-cyan-400 border border-cyan-800/50">
                  v2.4 SOC
                </span>
              </div>
              <p className="text-xs text-slate-400">Autonomous Observability & Threat Intelligence Platform</p>
            </div>
          </div>

          <div className="flex items-center space-x-4">
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
                    className="px-3 py-2 rounded-lg bg-indigo-950/60 hover:bg-indigo-900/80 text-indigo-300 border border-indigo-700/50 text-xs font-medium flex items-center space-x-1.5 transition shadow-sm"
                  >
                    <Users className="w-3.5 h-3.5" />
                    <span>User Directory</span>
                  </button>
                )}

                <button
                  onClick={onEnterDashboard}
                  className="px-4 py-2 rounded-lg bg-gradient-to-r from-cyan-500 to-blue-600 hover:from-cyan-400 hover:to-blue-500 text-slate-950 font-bold text-xs flex items-center space-x-2 shadow-lg shadow-cyan-500/25 transition"
                >
                  <span>Open SOC Center</span>
                  <ArrowRight className="w-4 h-4" />
                </button>
              </div>
            ) : (
              <button
                onClick={onOpenLogin}
                className="px-4 py-2 rounded-lg bg-gradient-to-r from-cyan-500 to-blue-600 hover:from-cyan-400 hover:to-blue-500 text-slate-950 font-bold text-xs flex items-center space-x-2 shadow-lg shadow-cyan-500/25 transition"
              >
                <KeyRound className="w-3.5 h-3.5" />
                <span>Sign In to Portal</span>
              </button>
            )}
          </div>
        </div>
      </header>

      {/* Hero Section */}
      <main className="relative z-10 flex-1 max-w-7xl mx-auto px-6 py-12 md:py-20 flex flex-col justify-center">
        <div className="grid grid-cols-1 lg:grid-cols-12 gap-12 items-center">
          
          {/* Left Column: Headline & Action */}
          <div className="lg:col-span-7 space-y-6">
            <div className="inline-flex items-center space-x-2 px-3 py-1 rounded-full bg-cyan-950/80 border border-cyan-700/50 text-cyan-400 text-xs font-mono">
              <span className="w-2 h-2 rounded-full bg-emerald-400 animate-ping" />
              <span>SOC Sentinel Core Active • 0.00% Host Application Overhead</span>
            </div>

            <h1 className="text-4xl sm:text-5xl md:text-6xl font-black tracking-tight leading-[1.1]">
              Zero-Impact Observability.{' '}
              <span className="bg-gradient-to-r from-cyan-400 via-sky-300 to-indigo-400 bg-clip-text text-transparent">
                Real-Time Heuristic Threat Defense.
              </span>
            </h1>

            <p className="text-slate-300 text-base sm:text-lg leading-relaxed max-w-2xl">
              An independent, multi-tenant monitoring and threat intelligence platform designed to protect flagship institutional platforms with zero performance degradation on monitored systems.
            </p>

            {/* Feature Checkpoints */}
            <div className="grid grid-cols-2 gap-3 pt-2 text-xs font-mono text-slate-300">
              <div className="flex items-center space-x-2">
                <CheckCircle2 className="w-4 h-4 text-cyan-400 shrink-0" />
                <span>Sub-millisecond UDP/HTTP Ingest</span>
              </div>
              <div className="flex items-center space-x-2">
                <CheckCircle2 className="w-4 h-4 text-cyan-400 shrink-0" />
                <span>SQLi, XSS, DDoS, LFI Heuristics</span>
              </div>
              <div className="flex items-center space-x-2">
                <CheckCircle2 className="w-4 h-4 text-cyan-400 shrink-0" />
                <span>PBKDF2 + JWT Enterprise Auth</span>
              </div>
              <div className="flex items-center space-x-2">
                <CheckCircle2 className="w-4 h-4 text-cyan-400 shrink-0" />
                <span>Automated Self-Healing Code Patches</span>
              </div>
            </div>

            {/* Action Buttons */}
            <div className="pt-4 flex flex-wrap items-center gap-4">
              {currentUser ? (
                <button
                  onClick={onEnterDashboard}
                  className="px-6 py-3.5 rounded-xl bg-gradient-to-r from-cyan-500 via-blue-500 to-indigo-600 hover:from-cyan-400 hover:to-indigo-500 text-slate-950 font-extrabold text-sm flex items-center space-x-3 shadow-xl shadow-cyan-500/25 hover:shadow-cyan-500/40 transition transform active:scale-95"
                >
                  <Eye className="w-4 h-4 text-slate-950" />
                  <span>Launch SOC Live Monitoring</span>
                  <ArrowRight className="w-4 h-4 text-slate-950" />
                </button>
              ) : (
                <button
                  onClick={onOpenLogin}
                  className="px-6 py-3.5 rounded-xl bg-gradient-to-r from-cyan-500 via-blue-500 to-indigo-600 hover:from-cyan-400 hover:to-indigo-500 text-slate-950 font-extrabold text-sm flex items-center space-x-3 shadow-xl shadow-cyan-500/25 hover:shadow-cyan-500/40 transition transform active:scale-95"
                >
                  <KeyRound className="w-4 h-4 text-slate-950" />
                  <span>Access Secure SOC Portal</span>
                  <ArrowRight className="w-4 h-4 text-slate-950" />
                </button>
              )}

              {currentUser?.role === 'SUPER_ADMIN' && onOpenUserManagement && (
                <button
                  onClick={onOpenUserManagement}
                  className="px-5 py-3.5 rounded-xl bg-slate-900/90 hover:bg-slate-800 text-slate-200 border border-slate-700 text-sm font-semibold flex items-center space-x-2 transition"
                >
                  <Users className="w-4 h-4 text-cyan-400" />
                  <span>Super Admin Management</span>
                </button>
              )}
            </div>
          </div>

          {/* Right Column: Live SOC Holographic Preview Card */}
          <div className="lg:col-span-5">
            <div className="relative rounded-2xl border border-cyan-800/50 bg-slate-900/80 p-6 shadow-2xl shadow-cyan-950/60 backdrop-blur-xl space-y-5">
              
              {/* Card Header */}
              <div className="flex items-center justify-between border-b border-slate-800 pb-4">
                <div className="flex items-center space-x-2.5">
                  <div className="w-3 h-3 rounded-full bg-emerald-400 animate-pulse" />
                  <span className="text-xs font-mono font-bold text-slate-200">ACTIVE TELEMETRY INGEST STREAM</span>
                </div>
                <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-emerald-950 text-emerald-400 border border-emerald-800/60">
                  WAT (UTC+1)
                </span>
              </div>

              {/* Status Counters */}
              <div className="grid grid-cols-2 gap-3">
                <div className="bg-slate-950/80 border border-slate-800 rounded-xl p-3">
                  <div className="text-[11px] text-slate-400 font-mono">Protected Tenants</div>
                  <div className="text-2xl font-black text-cyan-400 font-mono mt-0.5">3 Active</div>
                  <div className="text-[10px] text-slate-500 font-mono mt-1">NOUN-HRMS • Clinic-EHR</div>
                </div>

                <div className="bg-slate-950/80 border border-slate-800 rounded-xl p-3">
                  <div className="text-[11px] text-slate-400 font-mono">Heuristic Latency</div>
                  <div className="text-2xl font-black text-emerald-400 font-mono mt-0.5">&lt; 0.8ms</div>
                  <div className="text-[10px] text-slate-500 font-mono mt-1">Zero host degradation</div>
                </div>
              </div>

              {/* Live Threat Log Feed Simulation */}
              <div className="bg-slate-950 rounded-xl p-3.5 border border-slate-800/80 font-mono text-[11px] space-y-2">
                <div className="text-slate-400 flex items-center justify-between text-[10px]">
                  <span>RECENT FORENSIC EVENTS</span>
                  <span className="text-cyan-400">ENCRYPTED STREAM</span>
                </div>
                <div className="flex items-start space-x-2 text-rose-400 bg-rose-950/30 p-2 rounded border border-rose-900/40">
                  <ShieldAlert className="w-4 h-4 shrink-0 mt-0.5" />
                  <div>
                    <div className="font-bold">SQL Injection Blocked</div>
                    <div className="text-[10px] text-slate-400">NOUN-HRMS • /api/v1/payroll/export</div>
                  </div>
                </div>
                <div className="flex items-start space-x-2 text-amber-400 bg-amber-950/30 p-2 rounded border border-amber-900/40">
                  <Crosshair className="w-4 h-4 shrink-0 mt-0.5" />
                  <div>
                    <div className="font-bold">XSS Payload Intercepted</div>
                    <div className="text-[10px] text-slate-400">NOUN-HRMS • /api/v1/auth/session</div>
                  </div>
                </div>
              </div>

              {/* Super Admin Quick Link */}
              {!currentUser && (
                <div className="bg-indigo-950/40 border border-indigo-800/40 rounded-xl p-3 flex items-center justify-between text-xs">
                  <div className="space-y-0.5">
                    <div className="font-semibold text-indigo-200">Super Admin Access Available</div>
                    <div className="text-[10px] text-indigo-400">Audited via West Africa Time (WAT)</div>
                  </div>
                  <button
                    onClick={onOpenLogin}
                    className="px-3 py-1.5 rounded-lg bg-indigo-600 hover:bg-indigo-500 text-white font-bold text-xs transition shadow-md shadow-indigo-600/30"
                  >
                    Log In
                  </button>
                </div>
              )}
            </div>
          </div>
        </div>

        {/* Feature Grid */}
        <div className="mt-20 grid grid-cols-1 md:grid-cols-3 gap-6">
          <div className="rounded-2xl border border-slate-800 bg-slate-900/50 p-6 space-y-3 hover:border-cyan-700/60 transition">
            <div className="w-10 h-10 rounded-xl bg-cyan-950 text-cyan-400 flex items-center justify-center border border-cyan-800/50">
              <Zap className="w-5 h-5" />
            </div>
            <h3 className="font-bold text-base text-slate-100">Non-Blocking Telemetry Ingest</h3>
            <p className="text-xs text-slate-400 leading-relaxed">
              Monitored applications ship micro-logs over asynchronous HTTP or UDP fire-and-forget sockets. If The Watch experiences load spikes, client apps experience 0ms overhead.
            </p>
          </div>

          <div className="rounded-2xl border border-slate-800 bg-slate-900/50 p-6 space-y-3 hover:border-cyan-700/60 transition">
            <div className="w-10 h-10 rounded-xl bg-indigo-950 text-indigo-400 flex items-center justify-center border border-indigo-800/50">
              <Lock className="w-5 h-5" />
            </div>
            <h3 className="font-bold text-base text-slate-100">Super Admin & RBAC Security</h3>
            <p className="text-xs text-slate-400 leading-relaxed">
              Multi-tiered Role Based Access Control (Super Admin, SOC Analyst, Auditor) with PBKDF2 cryptography, brute-force defense (5-attempt 15-min lockout), and location audit logging.
            </p>
          </div>

          <div className="rounded-2xl border border-slate-800 bg-slate-900/50 p-6 space-y-3 hover:border-cyan-700/60 transition">
            <div className="w-10 h-10 rounded-xl bg-emerald-950 text-emerald-400 flex items-center justify-center border border-emerald-800/50">
              <Terminal className="w-5 h-5" />
            </div>
            <h3 className="font-bold text-base text-slate-100">Self-Healing Remediation Advisor</h3>
            <p className="text-xs text-slate-400 leading-relaxed">
              Synthesizes forensic intelligence into concrete, ready-to-deploy TypeScript code patches, parameterized SQL query rewrites, and Nginx/WAF rate-limiting blueprints.
            </p>
          </div>
        </div>
      </main>

      {/* Footer with Powered by: MaSha Tech Innovations */}
      <footer className="relative z-10 border-t border-slate-800/80 bg-slate-950/80 py-6 px-6 text-center text-xs text-slate-500">
        <div className="max-w-7xl mx-auto flex flex-col sm:flex-row items-center justify-between gap-3">
          <div className="flex items-center space-x-2">
            <ShieldAlert className="w-4 h-4 text-cyan-400" />
            <span className="font-semibold text-slate-400">The Watch SOC Platform</span>
            <span>•</span>
            <span>Timezone: West Africa Time (WAT / UTC+1)</span>
          </div>
          <div className="font-mono text-cyan-400 font-medium">
            Powered by: MaSha Tech Innovations
          </div>
        </div>
      </footer>
    </div>
  );
};
