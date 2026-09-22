import React, { useState } from 'react';
import { Sparkles, Wrench, Copy, Check, Terminal, Layers, ArrowRight, ShieldCheck } from 'lucide-react';
import { AdvisorResponse } from '../types/dashboard';

interface RemediationAdvisorProps {
  advisorData: AdvisorResponse | null;
}

export const RemediationAdvisor: React.FC<RemediationAdvisorProps> = ({ advisorData }) => {
  const [copiedId, setCopiedId] = useState<string | null>(null);
  const [viewCatalog, setViewCatalog] = useState<boolean>(false);

  const activeDiagnoses = advisorData?.activeDiagnoses || [];
  const catalogRules = advisorData?.allCatalogRules || [];

  const handleCopy = (id: string, text: string) => {
    navigator.clipboard.writeText(text);
    setCopiedId(id);
    setTimeout(() => setCopiedId(null), 2000);
  };

  return (
    <div className="bg-slate-900/80 border border-slate-800 rounded-xl p-5 shadow-sm">
      
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 mb-4">
        <div>
          <div className="flex items-center gap-2">
            <Sparkles className="w-5 h-5 text-amber-400" />
            <h2 className="text-base font-bold text-white tracking-wide">SELF-HEALING & REMEDIATION ADVISOR</h2>
          </div>
          <p className="text-xs text-slate-400 mt-0.5">
            Automated root-cause diagnosis and instant mitigation code patches for database connection leaks, memory spikes, and infrastructure stalls
          </p>
        </div>

        <button
          onClick={() => setViewCatalog(!viewCatalog)}
          className="flex items-center gap-1.5 text-xs font-semibold text-slate-300 hover:text-white bg-slate-800 hover:bg-slate-700 px-3 py-1.5 rounded-lg border border-slate-700 transition self-start sm:self-auto"
        >
          <Layers className="w-3.5 h-3.5 text-cyan-400" />
          {viewCatalog ? 'Show Active Incident Diagnoses' : 'Browse All Rule Blueprints'}
        </button>
      </div>

      {/* Mode 1: Active Diagnoses */}
      {!viewCatalog ? (
        <div className="space-y-4">
          {activeDiagnoses.length === 0 ? (
            <div className="bg-slate-950 border border-slate-800/80 rounded-xl p-8 text-center">
              <ShieldCheck className="w-10 h-10 text-emerald-400 mx-auto mb-2" />
              <h3 className="text-sm font-bold text-slate-200">All Infrastructure Channels Healthy</h3>
              <p className="text-xs text-slate-400 mt-1 max-w-md mx-auto">
                No active connection timeouts, memory exhaustion, or probe regressions detected. Advisor is actively monitoring incoming telemetry streams.
              </p>
            </div>
          ) : (
            activeDiagnoses.map((rec) => {
              const diag = rec.diagnosis;
              return (
                <div
                  key={rec.incidentId}
                  className="bg-slate-950 border border-slate-800 rounded-xl p-5 transition hover:border-slate-700"
                >
                  {/* Top Bar */}
                  <div className="flex flex-wrap items-center justify-between gap-2 pb-3 border-b border-slate-800">
                    <div className="flex items-center gap-2">
                      <span className="bg-amber-500/20 text-amber-400 border border-amber-500/40 text-[10px] font-bold px-2 py-0.5 rounded">
                        {rec.severity} SEVERITY
                      </span>
                      <span className="font-mono text-cyan-400 text-xs font-semibold">{rec.systemId}</span>
                      <span className="text-slate-600">•</span>
                      <span className="text-sm font-bold text-white">{diag.patternName}</span>
                    </div>
                    <span className="text-[11px] font-mono text-slate-500">{rec.createdAtWat}</span>
                  </div>

                  {/* Diagnosis Grid */}
                  <div className="mt-4 grid grid-cols-1 md:grid-cols-2 gap-4 text-xs">
                    {/* Left: Summary & Root Cause */}
                    <div className="space-y-3">
                      <div>
                        <span className="text-slate-400 uppercase font-bold text-[10px] tracking-wider block">
                          1. Plain-Text Incident Summary:
                        </span>
                        <p className="text-slate-200 mt-1 leading-relaxed bg-slate-900/90 p-3 rounded-lg border border-slate-800">
                          {diag.incidentSummary}
                        </p>
                      </div>

                      <div>
                        <span className="text-amber-400 uppercase font-bold text-[10px] tracking-wider block">
                          2. Exact Suspected Root Cause:
                        </span>
                        <p className="text-slate-200 mt-1 leading-relaxed bg-amber-950/20 border border-amber-800/40 p-3 rounded-lg text-amber-200/90">
                          {diag.suspectedRootCause}
                        </p>
                      </div>
                    </div>

                    {/* Right: Code Patch & Infrastructure Fix */}
                    <div className="space-y-3">
                      <div className="flex items-center justify-between">
                        <span className="text-cyan-400 uppercase font-bold text-[10px] tracking-wider">
                          3. Mitigation Code Patch / Config Fix:
                        </span>
                        <button
                          onClick={() => handleCopy(rec.incidentId, diag.codePatch || diag.infrastructureFix)}
                          className="flex items-center gap-1 text-[11px] font-semibold text-slate-300 hover:text-white bg-slate-800 hover:bg-slate-700 px-2 py-0.5 rounded transition"
                        >
                          {copiedId === rec.incidentId ? (
                            <>
                              <Check className="w-3 h-3 text-emerald-400" /> Copied!
                            </>
                          ) : (
                            <>
                              <Copy className="w-3 h-3" /> Copy Patch
                            </>
                          )}
                        </button>
                      </div>

                      <pre className="bg-slate-900 border border-slate-800 p-3 rounded-lg font-mono text-[11px] text-slate-200 overflow-x-auto max-h-48">
                        {diag.codePatch || diag.infrastructureFix}
                      </pre>
                    </div>
                  </div>
                </div>
              );
            })
          )}
        </div>
      ) : (
        /* Mode 2: Catalog of Rules */
        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          {catalogRules.map((rule) => (
            <div key={rule.id} className="bg-slate-950 border border-slate-800 rounded-xl p-4 flex flex-col justify-between">
              <div>
                <div className="flex items-center justify-between pb-2 border-b border-slate-800">
                  <span className="text-xs font-bold text-white">{rule.patternName}</span>
                  <span className="text-[10px] font-mono text-cyan-400 bg-slate-900 px-2 py-0.5 rounded">
                    {rule.id}
                  </span>
                </div>

                <div className="mt-3 space-y-2 text-xs">
                  <div>
                    <span className="text-[10px] text-slate-400 uppercase font-semibold">Diagnosis:</span>
                    <p className="text-slate-300 text-[11px] mt-0.5">{rule.incidentSummary}</p>
                  </div>

                  <div>
                    <span className="text-[10px] text-amber-400 uppercase font-semibold">Suspected Cause:</span>
                    <p className="text-slate-300 text-[11px] mt-0.5">{rule.suspectedRootCause}</p>
                  </div>
                </div>
              </div>

              <div className="mt-4 pt-3 border-t border-slate-800/80 flex items-center justify-between">
                <span className="text-[10px] text-slate-500">{rule.recommendedAction}</span>
                <button
                  onClick={() => handleCopy(rule.id, rule.codePatch || rule.infrastructureFix)}
                  className="flex items-center gap-1 text-[11px] font-semibold text-cyan-400 hover:text-cyan-300 bg-cyan-950/40 px-2 py-1 rounded border border-cyan-800/60"
                >
                  {copiedId === rule.id ? 'Copied!' : 'Copy Blueprint'}
                </button>
              </div>
            </div>
          ))}
        </div>
      )}

    </div>
  );
};
