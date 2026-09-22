import React, { useState } from 'react';
import { Flame, Play, AlertTriangle, ShieldCheck, Zap, Server, Database, Radio } from 'lucide-react';
import { api } from '../services/api';

interface AttackSimulatorProps {
  selectedSystem: string;
  onSimulationTriggered: () => void;
}

export const AttackSimulator: React.FC<AttackSimulatorProps> = ({ selectedSystem, onSimulationTriggered }) => {
  const [activeScenario, setActiveScenario] = useState<string | null>(null);
  const [successMessage, setSuccessMessage] = useState<string | null>(null);

  const targetSystem = selectedSystem || 'NOUN-HRMS';

  const scenarios = [
    {
      id: 'sqli',
      name: 'SQL Injection (SQLi)',
      category: 'THREAT',
      desc: "Simulate ' UNION SELECT attack payload targeting /api/v1/payroll/export from Russian Botnet IP",
      severity: 'CRITICAL',
    },
    {
      id: 'xss',
      name: 'Cross-Site Scripting (XSS)',
      category: 'THREAT',
      desc: 'Simulate <script> cookie exfiltration payload targeting /api/v1/auth/session from German Tor Exit Node',
      severity: 'HIGH',
    },
    {
      id: 'traversal',
      name: 'Directory Traversal (LFI)',
      category: 'THREAT',
      desc: 'Simulate ../../../etc/passwd probe targeting /api/v1/documents/download from Netherlands VPN IP',
      severity: 'HIGH',
    },
    {
      id: 'brute_force',
      name: 'Credential Stuffing Burst',
      category: 'THREAT',
      desc: 'Simulate 18 rapid 401 auth drops on /login from Chinese drone IP within 60 seconds',
      severity: 'HIGH',
    },
    {
      id: 'ddos',
      name: 'Layer 7 DDoS Flood',
      category: 'THREAT',
      desc: 'Simulate 60 rapid requests/sec triggering volumetric sliding-window rate limit threshold',
      severity: 'CRITICAL',
    },
    {
      id: 'neon_timeout',
      name: 'Neon Pooler Timeout',
      category: 'INFRASTRUCTURE',
      desc: 'Simulate PostgreSQL connection exhaustion (504 Gateway Timeout) triggering Neon pgBouncer rule',
      severity: 'CRITICAL',
    },
    {
      id: 'render_oom',
      name: 'Render Memory OOM',
      category: 'INFRASTRUCTURE',
      desc: 'Simulate JavaScript heap out of memory container crash triggering Stream Pipeline advisor patch',
      severity: 'HIGH',
    },
    {
      id: 'coturn_stall',
      name: 'Coturn UDP Relay Stall',
      category: 'INFRASTRUCTURE',
      desc: 'Simulate UDP port 3478 unreachable failure triggering UFW firewall port-opening blueprint',
      severity: 'HIGH',
    },
    {
      id: 'slow_query',
      name: 'Slow Database Query (>200ms)',
      category: 'QUERY',
      desc: 'Simulate 912ms unindexed payroll query triggering CREATE INDEX CONCURRENTLY optimization',
      severity: 'MEDIUM',
    },
    {
      id: 'probe_failure',
      name: 'Synthetic Probe Outage',
      category: 'PROBE',
      desc: 'Simulate synthetic heartbeat drop and SSL expiring within 4 days on target endpoint',
      severity: 'HIGH',
    },
  ];

  const handleTrigger = async (scenarioId: string) => {
    setActiveScenario(scenarioId);
    setSuccessMessage(null);
    try {
      await api.triggerSimulation(scenarioId, targetSystem);
      setSuccessMessage(`Simulated scenario [${scenarioId}] triggered successfully against ${targetSystem}!`);
      onSimulationTriggered();
      setTimeout(() => setSuccessMessage(null), 4000);
    } catch (err: any) {
      alert(`Simulation failed: ${err.message}`);
    } finally {
      setActiveScenario(null);
    }
  };

  return (
    <div className="bg-slate-900/80 border border-slate-800 rounded-xl p-5 shadow-sm">
      
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 mb-4">
        <div>
          <div className="flex items-center gap-2">
            <Flame className="w-5 h-5 text-orange-400" />
            <h2 className="text-base font-bold text-white tracking-wide">INTERACTIVE SOC ATTACK & REGRESSION SIMULATOR</h2>
          </div>
          <p className="text-xs text-slate-400 mt-0.5">
            Fire realistic attack vectors, credential stuffing bursts, and infrastructure failure modes to verify real-time watchdog detection
          </p>
        </div>

        <span className="text-xs font-mono text-cyan-400 bg-slate-950 px-3 py-1 rounded-lg border border-slate-800 self-start sm:self-auto">
          Target: {targetSystem}
        </span>
      </div>

      {successMessage && (
        <div className="mb-4 bg-emerald-500/10 border border-emerald-500/30 text-emerald-400 text-xs px-4 py-2.5 rounded-lg flex items-center gap-2 animate-in fade-in">
          <ShieldCheck className="w-4 h-4" />
          <span>{successMessage}</span>
        </div>
      )}

      {/* Grid of Simulation Scenarios */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-3">
        {scenarios.map((sc) => {
          const isTriggering = activeScenario === sc.id;
          return (
            <div
              key={sc.id}
              className="bg-slate-950 border border-slate-800 hover:border-slate-700 rounded-xl p-3.5 flex flex-col justify-between transition"
            >
              <div>
                <div className="flex items-center justify-between gap-1 mb-1.5">
                  <span className="text-xs font-bold text-white">{sc.name}</span>
                  <span className={`text-[9px] font-bold px-1.5 py-0.5 rounded ${
                    sc.severity === 'CRITICAL' ? 'bg-red-500/20 text-red-400' : sc.severity === 'HIGH' ? 'bg-orange-500/20 text-orange-400' : 'bg-yellow-500/20 text-yellow-400'
                  }`}>
                    {sc.severity}
                  </span>
                </div>

                <p className="text-[11px] text-slate-400 leading-relaxed">
                  {sc.desc}
                </p>
              </div>

              <div className="mt-3 pt-2.5 border-t border-slate-800/80 flex items-center justify-between">
                <span className="text-[10px] font-mono text-slate-500 uppercase">{sc.category}</span>
                <button
                  onClick={() => handleTrigger(sc.id)}
                  disabled={isTriggering}
                  className="flex items-center gap-1.5 bg-orange-500/10 hover:bg-orange-500/20 text-orange-400 hover:text-orange-300 border border-orange-500/30 px-3 py-1 rounded-lg text-xs font-bold transition cursor-pointer"
                >
                  <Play className={`w-3 h-3 ${isTriggering ? 'animate-spin' : ''}`} />
                  {isTriggering ? 'Firing...' : 'Fire Vector'}
                </button>
              </div>
            </div>
          );
        })}
      </div>

    </div>
  );
};
