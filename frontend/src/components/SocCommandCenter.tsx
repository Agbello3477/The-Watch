import React, { useState, useEffect, useCallback } from 'react';
import {
  ShieldAlert, ShieldCheck, Flame, Clock, Radio, Users,
  Terminal, Search, Play, CheckCircle2,
  FileCode, Layers, ShieldX, KeyRound,
  FileSpreadsheet, Sparkles, Send, Ban,
  Lock, Target, Cpu, RefreshCw
} from 'lucide-react';
import { api } from '../services/api';
import {
  SocMetrics,
  SocCase,
  IpBlocklistEntry,
  IocEntry,
  SocPlaybook,
  DetectionRule,
  ShiftHandover,
  AuthSessionUser,
} from '../types/dashboard';

interface SocCommandCenterProps {
  currentUser: AuthSessionUser | null;
  selectedSystem: string;
}

export const SocCommandCenter: React.FC<SocCommandCenterProps> = ({ currentUser, selectedSystem }) => {
  const [activeSubTab, setActiveSubTab] = useState<'cases' | 'firewall' | 'mitre' | 'playbooks' | 'iocs' | 'rules' | 'shifts'>('cases');

  // SOC Data State
  const [metrics, setMetrics] = useState<SocMetrics | null>(null);
  const [cases, setCases] = useState<SocCase[]>([]);
  const [blocklist, setBlocklist] = useState<IpBlocklistEntry[]>([]);
  const [iocs, setIocs] = useState<IocEntry[]>([]);
  const [playbooks, setPlaybooks] = useState<SocPlaybook[]>([]);
  const [rules, setRules] = useState<DetectionRule[]>([]);
  const [shifts, setShifts] = useState<ShiftHandover[]>([]);

  // UI State
  const [loading, setLoading] = useState(true);
  const [refreshing, setRefreshing] = useState(false);
  const [selectedCase, setSelectedCase] = useState<SocCase | null>(null);
  const [caseFilterSeverity, setCaseFilterSeverity] = useState<string>('ALL');
  const [caseFilterStatus, setCaseFilterStatus] = useState<string>('ALL');

  // Modals & Action States
  const [isBanModalOpen, setIsBanModalOpen] = useState(false);
  const [banIpInput, setBanIpInput] = useState('');
  const [banReasonInput, setBanReasonInput] = useState('');
  const [newNoteText, setNewNoteText] = useState('');
  const [playbookRunMessage, setPlaybookRunMessage] = useState<string | null>(null);
  const [isShiftModalOpen, setIsShiftModalOpen] = useState(false);
  const [shiftNameInput, setShiftNameInput] = useState('BRAVO (Evening 16:00 - 00:00 WAT)');
  const [shiftNotesInput, setShiftNotesInput] = useState('');

  // Fetch all SOC telemetry
  const fetchSocData = useCallback(async () => {
    try {
      setRefreshing(true);
      const [
        metricsData,
        casesData,
        blocklistData,
        iocsData,
        playbooksData,
        rulesData,
        shiftsData,
      ] = await Promise.all([
        api.getSocMetrics(),
        api.getSocCases({ systemId: selectedSystem || undefined }),
        api.getSocBlocklist(),
        api.getSocIocs(),
        api.getSocPlaybooks(),
        api.getSocRules(),
        api.getSocShifts(),
      ]);

      setMetrics(metricsData);
      setCases(casesData.cases || []);
      setBlocklist(blocklistData.blocklist || []);
      setIocs(iocsData.iocs || []);
      setPlaybooks(playbooksData.playbooks || []);
      setRules(rulesData.rules || []);
      setShifts(shiftsData.handovers || []);

      // If active case is open, update its reference
      if (selectedCase) {
        const refreshedCase = casesData.cases?.find((c) => c.id === selectedCase.id);
        if (refreshedCase) setSelectedCase(refreshedCase);
      }
    } catch (err) {
      console.error('[SOC] Error fetching SOC operational data:', err);
    } finally {
      setLoading(false);
      setRefreshing(false);
    }
  }, [selectedSystem, selectedCase]);

  useEffect(() => {
    fetchSocData();
    const interval = setInterval(fetchSocData, 10000); // 10s SOC poll
    return () => clearInterval(interval);
  }, [fetchSocData]);

  // Handlers
  const handleAddCaseNote = async () => {
    if (!selectedCase || !newNoteText.trim()) return;
    try {
      await api.addSocCaseNote(
        selectedCase.id,
        newNoteText.trim(),
        currentUser?.fullName || 'SOC Operator',
        currentUser?.role || 'SOC_ANALYST'
      );
      setNewNoteText('');
      fetchSocData();
    } catch (e) {
      console.error(e);
    }
  };

  const handleUpdateCaseStatus = async (caseId: string, status: string) => {
    try {
      await api.updateSocCaseStatus(caseId, status);
      fetchSocData();
    } catch (e) {
      console.error(e);
    }
  };

  const handleExecutePlaybook = async (playbookId: string, targetCaseId?: string) => {
    try {
      const res = await api.executeSocPlaybook(playbookId, targetCaseId);
      setPlaybookRunMessage(`Executed "${res.playbook.name}". Actions: ${res.actionsTaken.join(', ')}`);
      setTimeout(() => setPlaybookRunMessage(null), 7000);
      fetchSocData();
    } catch (e: any) {
      alert(`Playbook execution failed: ${e.message}`);
    }
  };

  const handleBlockIp = async () => {
    if (!banIpInput.trim() || !banReasonInput.trim()) return;
    try {
      await api.blockIp({
        ip: banIpInput.trim(),
        reason: banReasonInput.trim(),
        systemId: selectedSystem || 'NOUN-HRMS',
        durationHours: 24,
      });
      setBanIpInput('');
      setBanReasonInput('');
      setIsBanModalOpen(false);
      fetchSocData();
    } catch (e: any) {
      alert(`Block failed: ${e.message}`);
    }
  };

  const handleUnblockIp = async (ip: string) => {
    if (!confirm(`Are you sure you want to unblock ${ip} from the SOC Ingest Firewall?`)) return;
    try {
      await api.unblockIp(ip);
      fetchSocData();
    } catch (e: any) {
      alert(`Unblock failed: ${e.message}`);
    }
  };

  const handleToggleRule = async (ruleId: string, currentEnabled: boolean) => {
    try {
      await api.toggleSocRule(ruleId, !currentEnabled);
      fetchSocData();
    } catch (e) {
      console.error(e);
    }
  };

  const handleCreateShift = async () => {
    if (!shiftNotesInput.trim()) return;
    try {
      await api.createSocShift({
        shiftName: shiftNameInput,
        leadAnalyst: currentUser?.fullName || 'Lead Analyst',
        analystsOnDuty: [currentUser?.fullName || 'Lead Analyst', 'Ibrahim Danjuma (Tier 2)'],
        handoffNotes: shiftNotesInput.trim(),
        actionItems: ['Review pending P1/P2 cases', 'Monitor NOUN-HRMS auth rates'],
      });
      setShiftNotesInput('');
      setIsShiftModalOpen(false);
      fetchSocData();
    } catch (e: any) {
      alert(`Shift creation failed: ${e.message}`);
    }
  };

  // Filter cases
  const filteredCases = cases.filter((c) => {
    if (caseFilterSeverity !== 'ALL' && c.severity !== caseFilterSeverity) return false;
    if (caseFilterStatus !== 'ALL' && c.status !== caseFilterStatus) return false;
    return true;
  });

  return (
    <div className="space-y-6">
      {/* ─── 1. TOP SOC OPERATIONAL KPI BAR ───────────────────────── */}
      <div className="bg-slate-900/90 border border-slate-800 rounded-2xl p-4 md:p-5 shadow-2xl backdrop-blur">
        <div className="flex flex-col lg:flex-row items-start lg:items-center justify-between gap-4 pb-4 border-b border-slate-800/80">
          <div className="flex items-center gap-3">
            <div className="p-2.5 rounded-xl bg-cyan-500/10 border border-cyan-500/30 text-cyan-400">
              <ShieldAlert className="w-6 h-6 animate-pulse" />
            </div>
            <div>
              <div className="flex items-center gap-2">
                <h2 className="text-lg md:text-xl font-black tracking-wide text-white font-mono">
                  ENTERPRISE SOC WAR ROOM
                </h2>
                <span className="px-2 py-0.5 rounded-full text-[10px] font-bold bg-emerald-500/20 text-emerald-400 border border-emerald-500/40 flex items-center gap-1">
                  <Radio className="w-2.5 h-2.5 animate-ping" /> LIVE OPERATIONS
                </span>
              </div>
              <p className="text-xs text-slate-400 mt-0.5">
                Multi-Tenant Sentinel Monitoring · National Open University SOC Command
              </p>
            </div>
          </div>

          <div className="flex items-center gap-2 self-stretch sm:self-auto justify-end">
            <button
              onClick={fetchSocData}
              disabled={refreshing}
              className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-xs font-semibold text-slate-200 border border-slate-700 transition"
            >
              <RefreshCw className={`w-3.5 h-3.5 ${refreshing ? 'animate-spin text-cyan-400' : ''}`} />
              <span>Refresh SOC</span>
            </button>

            <button
              onClick={() => setIsBanModalOpen(true)}
              className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-red-600 hover:bg-red-500 text-xs font-bold text-white shadow-lg shadow-red-600/20 transition"
            >
              <Ban className="w-3.5 h-3.5" />
              <span>Quarantine IP</span>
            </button>
          </div>
        </div>

        {/* Live Metrics Grid */}
        <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-6 gap-3 pt-4">
          <div className="bg-slate-950/70 border border-slate-800/80 rounded-xl p-3">
            <div className="text-[11px] text-slate-400 font-mono uppercase flex items-center gap-1">
              <Clock className="w-3 h-3 text-cyan-400" /> MTTD (Detect)
            </div>
            <div className="text-xl font-black text-cyan-400 font-mono mt-1">
              {metrics?.mttdSec || 14}s
            </div>
            <div className="text-[10px] text-slate-500 mt-0.5">Automated Ingest SLA</div>
          </div>

          <div className="bg-slate-950/70 border border-slate-800/80 rounded-xl p-3">
            <div className="text-[11px] text-slate-400 font-mono uppercase flex items-center gap-1">
              <CheckCircle2 className="w-3 h-3 text-emerald-400" /> MTTR (Resolve)
            </div>
            <div className="text-xl font-black text-emerald-400 font-mono mt-1">
              {metrics?.mttrMin || 18}m
            </div>
            <div className="text-[10px] text-slate-500 mt-0.5">Target: &lt; 30m (WAT)</div>
          </div>

          <div className="bg-slate-950/70 border border-slate-800/80 rounded-xl p-3">
            <div className="text-[11px] text-slate-400 font-mono uppercase flex items-center gap-1">
              <ShieldCheck className="w-3 h-3 text-indigo-400" /> SLA Adherence
            </div>
            <div className="text-xl font-black text-indigo-300 font-mono mt-1">
              {metrics?.slaCompliancePercent || 98}%
            </div>
            <div className="text-[10px] text-emerald-400 mt-0.5">Strict Enterprise SLA</div>
          </div>

          <div className="bg-slate-950/70 border border-slate-800/80 rounded-xl p-3">
            <div className="text-[11px] text-slate-400 font-mono uppercase flex items-center gap-1">
              <ShieldX className="w-3 h-3 text-red-400" /> Ingest Blocks
            </div>
            <div className="text-xl font-black text-red-400 font-mono mt-1">
              {metrics?.activeBlocksCount || blocklist.length}
            </div>
            <div className="text-[10px] text-slate-500 mt-0.5">Active IP Firewalls</div>
          </div>

          <div className="bg-slate-950/70 border border-slate-800/80 rounded-xl p-3">
            <div className="text-[11px] text-slate-400 font-mono uppercase flex items-center gap-1">
              <Flame className="w-3 h-3 text-orange-400" /> Triage Queue
            </div>
            <div className="text-xl font-black text-orange-400 font-mono mt-1">
              {metrics?.openCasesCount || cases.length}
            </div>
            <div className="text-[10px] text-red-400 mt-0.5">{metrics?.p1CriticalCasesCount || 1} P1 Critical</div>
          </div>

          <div className="bg-slate-950/70 border border-slate-800/80 rounded-xl p-3">
            <div className="text-[11px] text-slate-400 font-mono uppercase flex items-center gap-1">
              <Sparkles className="w-3 h-3 text-amber-400" /> SOAR Playbooks
            </div>
            <div className="text-xl font-black text-amber-300 font-mono mt-1">
              {playbooks.length}
            </div>
            <div className="text-[10px] text-slate-500 mt-0.5">Active Auto-Remediations</div>
          </div>
        </div>

        {playbookRunMessage && (
          <div className="mt-3 p-3 rounded-xl bg-cyan-950/80 border border-cyan-800 text-xs font-mono text-cyan-300 flex items-center gap-2 animate-pulse">
            <Terminal className="w-4 h-4 text-cyan-400" />
            <span>{playbookRunMessage}</span>
          </div>
        )}
      </div>

      {/* ─── 2. SOC SUB-NAVIGATION TABS ───────────────────────── */}
      <div className="flex border-b border-slate-800 overflow-x-auto gap-2 pb-1 scrollbar-none">
        {[
          { id: 'cases', label: 'Triage & War Room (Cases)', icon: ShieldAlert, badge: cases.filter((c) => c.status !== 'RESOLVED').length },
          { id: 'firewall', label: 'Ingest Firewall & IP Blocklist', icon: Ban, badge: blocklist.filter((b) => b.status === 'ACTIVE').length },
          { id: 'mitre', label: 'MITRE ATT&CK Matrix', icon: Target },
          { id: 'playbooks', label: 'SOAR Playbooks', icon: Play, badge: playbooks.length },
          { id: 'iocs', label: 'Threat Intel & IOCs', icon: Radio, badge: iocs.length },
          { id: 'rules', label: 'SIEM Detection Rules', icon: Cpu, badge: rules.filter((r) => r.enabled).length },
          { id: 'shifts', label: 'Shift Handover Logs', icon: Users, badge: shifts.length },
        ].map((tab) => {
          const Icon = tab.icon;
          const isActive = activeSubTab === tab.id;
          return (
            <button
              key={tab.id}
              onClick={() => setActiveSubTab(tab.id as any)}
              className={`flex items-center gap-2 px-4 py-2.5 rounded-xl text-xs font-bold transition whitespace-nowrap border ${
                isActive
                  ? 'bg-cyan-500 text-slate-950 border-cyan-400 shadow-lg shadow-cyan-500/20'
                  : 'bg-slate-900/60 text-slate-400 border-slate-800 hover:text-slate-200 hover:bg-slate-800/60'
              }`}
            >
              <Icon className="w-3.5 h-3.5" />
              <span>{tab.label}</span>
              {tab.badge !== undefined && (
                <span
                  className={`px-1.5 py-0.2 rounded-full text-[10px] font-mono ${
                    isActive ? 'bg-slate-950 text-cyan-400' : 'bg-slate-800 text-slate-300'
                  }`}
                >
                  {tab.badge}
                </span>
              )}
            </button>
          );
        })}
      </div>

      {/* ─── 3. TAB CONTENT PANES ───────────────────────── */}

      {/* ──── TAB 1: CASES & WAR ROOM ──── */}
      {activeSubTab === 'cases' && (
        <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
          {/* Left Column: Cases Queue */}
          <div className="lg:col-span-2 space-y-4">
            <div className="flex flex-wrap items-center justify-between gap-3 bg-slate-900 border border-slate-800 rounded-xl p-3">
              <div className="flex items-center gap-2 text-xs font-semibold text-slate-300">
                <span>Filter Severity:</span>
                {['ALL', 'P1', 'P2', 'P3'].map((sev) => (
                  <button
                    key={sev}
                    onClick={() => setCaseFilterSeverity(sev)}
                    className={`px-2.5 py-1 rounded-lg text-[11px] font-mono font-bold transition ${
                      caseFilterSeverity === sev
                        ? 'bg-cyan-500 text-slate-950'
                        : 'bg-slate-800 text-slate-400 hover:text-white'
                    }`}
                  >
                    {sev}
                  </button>
                ))}
              </div>

              <div className="flex items-center gap-2 text-xs font-semibold text-slate-300">
                <span>Status:</span>
                {['ALL', 'TRIAGE', 'INVESTIGATING', 'CONTAINED', 'RESOLVED'].map((st) => (
                  <button
                    key={st}
                    onClick={() => setCaseFilterStatus(st)}
                    className={`px-2 py-0.5 rounded-lg text-[10px] font-mono transition ${
                      caseFilterStatus === st
                        ? 'bg-slate-700 text-white font-bold'
                        : 'text-slate-400 hover:text-slate-200'
                    }`}
                  >
                    {st}
                  </button>
                ))}
              </div>
            </div>

            <div className="space-y-3">
              {filteredCases.map((socCase) => {
                const isSelected = selectedCase?.id === socCase.id;
                const isP1 = socCase.severity === 'P1';
                return (
                  <div
                    key={socCase.id}
                    onClick={() => setSelectedCase(socCase)}
                    className={`p-4 rounded-xl border transition cursor-pointer ${
                      isSelected
                        ? 'bg-slate-800/90 border-cyan-500 shadow-xl shadow-cyan-500/10 ring-1 ring-cyan-500'
                        : 'bg-slate-900 border-slate-800 hover:border-slate-700 hover:bg-slate-850'
                    }`}
                  >
                    <div className="flex items-start justify-between gap-2">
                      <div className="flex items-center gap-2">
                        <span
                          className={`px-2 py-0.5 rounded text-[10px] font-black font-mono tracking-wider ${
                            isP1
                              ? 'bg-red-500/20 text-red-400 border border-red-500/40 animate-pulse'
                              : 'bg-orange-500/20 text-orange-400 border border-orange-500/40'
                          }`}
                        >
                          {socCase.severity}
                        </span>
                        <span className="text-xs font-mono text-slate-400">{socCase.id}</span>
                        <span className="text-[10px] font-mono px-1.5 py-0.5 rounded bg-slate-800 text-cyan-400 border border-slate-700">
                          {socCase.tier}
                        </span>
                      </div>

                      <div className="flex items-center gap-2">
                        <span
                          className={`text-[10px] font-mono font-bold px-2 py-0.5 rounded-full ${
                            socCase.status === 'CONTAINED' || socCase.status === 'RESOLVED'
                              ? 'bg-emerald-500/20 text-emerald-400 border border-emerald-500/30'
                              : 'bg-amber-500/20 text-amber-300 border border-amber-500/30'
                          }`}
                        >
                          {socCase.status}
                        </span>
                      </div>
                    </div>

                    <h4 className="text-sm font-bold text-slate-100 mt-2 hover:text-cyan-400 transition">
                      {socCase.title}
                    </h4>

                    <div className="flex flex-wrap items-center gap-x-4 gap-y-1 text-xs text-slate-400 mt-2 font-mono">
                      <div>Target: <span className="text-slate-300">{socCase.targetEndpoint}</span></div>
                      <div>Origin: <span className="text-red-400">{socCase.offendingIp}</span></div>
                      <div>Analyst: <span className="text-indigo-400">{socCase.assignedAnalyst}</span></div>
                      <div className="text-[11px] text-cyan-400">SLA: {socCase.slaDeadlineWat}</div>
                    </div>

                    {socCase.containmentActions.length > 0 && (
                      <div className="flex flex-wrap gap-1.5 mt-2.5 pt-2.5 border-t border-slate-800/80">
                        {socCase.containmentActions.map((action, i) => (
                          <span key={i} className="text-[10px] bg-slate-950 text-emerald-400 border border-emerald-500/30 px-2 py-0.5 rounded font-mono">
                            ✓ {action}
                          </span>
                        ))}
                      </div>
                    )}
                  </div>
                );
              })}
            </div>
          </div>

          {/* Right Column: Case War Room Details */}
          <div className="bg-slate-900 border border-slate-800 rounded-2xl p-5 space-y-5">
            {selectedCase ? (
              <>
                <div className="flex items-start justify-between pb-3 border-b border-slate-800">
                  <div>
                    <div className="flex items-center gap-2">
                      <span className="text-xs font-mono text-cyan-400 font-bold">{selectedCase.id}</span>
                      <span className="text-[10px] font-mono bg-red-950 text-red-400 border border-red-800 px-2 py-0.5 rounded">
                        {selectedCase.severity}
                      </span>
                    </div>
                    <h3 className="text-base font-bold text-slate-100 mt-1">{selectedCase.title}</h3>
                  </div>
                </div>

                {/* MITRE ATT&CK Mapping */}
                <div className="bg-slate-950/80 border border-slate-800 rounded-xl p-3">
                  <div className="text-[11px] font-mono uppercase text-slate-400 mb-1 flex items-center gap-1.5">
                    <Target className="w-3.5 h-3.5 text-cyan-400" /> MITRE ATT&CK Alignment
                  </div>
                  <div className="text-xs font-bold text-slate-200">
                    Tactic: <span className="text-cyan-400">{selectedCase.mitreTactic}</span>
                  </div>
                  <div className="text-xs text-slate-400 font-mono mt-0.5">
                    Technique: <span className="text-emerald-400">{selectedCase.mitreTechnique}</span>
                  </div>
                </div>

                {/* Payload Sneak Peek */}
                <div>
                  <div className="text-[11px] font-mono uppercase text-slate-400 mb-1">Captured Payload Snippet</div>
                  <pre className="bg-slate-950 border border-slate-800 rounded-lg p-3 text-[11px] font-mono text-red-300 overflow-x-auto whitespace-pre-wrap">
                    {selectedCase.capturedPayload}
                  </pre>
                </div>

                {/* SOAR Playbook Execution Button */}
                <div className="bg-indigo-950/30 border border-indigo-900/50 rounded-xl p-3.5 space-y-2">
                  <div className="text-xs font-bold text-indigo-300 flex items-center gap-1.5">
                    <Play className="w-3.5 h-3.5 text-indigo-400" /> Automated SOAR Containment
                  </div>
                  <p className="text-[11px] text-slate-400 leading-relaxed">
                    Trigger the pre-configured response playbook to instantly quarantine IP {selectedCase.offendingIp} and terminate hanging sessions.
                  </p>
                  <button
                    onClick={() => handleExecutePlaybook('PB-SQLI-01', selectedCase.id)}
                    className="w-full py-2 rounded-lg bg-indigo-600 hover:bg-indigo-500 text-xs font-bold text-white shadow-lg shadow-indigo-600/30 transition flex items-center justify-center gap-1.5"
                  >
                    <Play className="w-3 h-3" />
                    <span>Run PB-SQLI-01 Containment Playbook</span>
                  </button>
                </div>

                {/* Case Status Control */}
                <div className="flex items-center gap-2 pt-2 border-t border-slate-800">
                  <span className="text-xs text-slate-400 font-medium">Status:</span>
                  {(['INVESTIGATING', 'CONTAINED', 'RESOLVED'] as const).map((st) => (
                    <button
                      key={st}
                      onClick={() => handleUpdateCaseStatus(selectedCase.id, st)}
                      className={`px-2.5 py-1 rounded text-[10px] font-bold font-mono transition ${
                        selectedCase.status === st
                          ? 'bg-cyan-500 text-slate-950'
                          : 'bg-slate-800 text-slate-300 hover:bg-slate-700'
                      }`}
                    >
                      {st}
                    </button>
                  ))}
                </div>

                {/* Investigation Timeline & Notes */}
                <div className="space-y-3 pt-2 border-t border-slate-800">
                  <div className="text-xs font-bold text-slate-300 flex items-center gap-1.5">
                    <Terminal className="w-3.5 h-3.5 text-cyan-400" /> Evidence Timeline & Analyst Notes ({selectedCase.notes.length})
                  </div>

                  <div className="space-y-2 max-h-52 overflow-y-auto pr-1">
                    {selectedCase.notes.map((note) => (
                      <div key={note.id} className="bg-slate-950 border border-slate-850 p-2.5 rounded-lg text-xs space-y-1">
                        <div className="flex items-center justify-between text-[10px] text-slate-400 font-mono">
                          <span className="font-bold text-cyan-400">{note.author} ({note.authorRole})</span>
                          <span>{note.createdAtWat}</span>
                        </div>
                        <p className="text-slate-300 leading-relaxed text-[11px]">{note.text}</p>
                      </div>
                    ))}
                  </div>

                  <div className="flex gap-2">
                    <input
                      type="text"
                      value={newNoteText}
                      onChange={(e) => setNewNoteText(e.target.value)}
                      placeholder="Add investigation evidence / action note..."
                      className="flex-1 bg-slate-950 border border-slate-800 rounded-lg px-3 py-1.5 text-xs text-slate-200 focus:outline-none focus:border-cyan-500"
                      onKeyDown={(e) => e.key === 'Enter' && handleAddCaseNote()}
                    />
                    <button
                      onClick={handleAddCaseNote}
                      className="p-2 rounded-lg bg-cyan-600 hover:bg-cyan-500 text-slate-950 transition"
                    >
                      <Send className="w-3.5 h-3.5" />
                    </button>
                  </div>
                </div>
              </>
            ) : (
              <div className="text-center py-20 text-slate-500 space-y-2">
                <ShieldAlert className="w-8 h-8 mx-auto text-slate-600" />
                <p className="text-xs">Select any case from the triage queue to open the incident war room.</p>
              </div>
            )}
          </div>
        </div>
      )}

      {/* ──── TAB 2: INGEST FIREWALL & IP BLOCKLIST ──── */}
      {activeSubTab === 'firewall' && (
        <div className="space-y-4">
          <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 bg-slate-900 border border-slate-800 rounded-xl p-4">
            <div>
              <h3 className="text-base font-bold text-slate-100 flex items-center gap-2">
                <Ban className="w-5 h-5 text-red-400" />
                Active Ingest Edge Firewall & Quarantined IPs
              </h3>
              <p className="text-xs text-slate-400 mt-0.5">
                Requests from these IP addresses are dropped immediately by The Watch Ingest Engine with HTTP 403 Forbidden.
              </p>
            </div>
            <button
              onClick={() => setIsBanModalOpen(true)}
              className="px-3.5 py-2 rounded-lg bg-red-600 hover:bg-red-500 text-xs font-bold text-white shadow-lg shadow-red-600/30 transition flex items-center gap-1.5 self-start sm:self-auto"
            >
              <Ban className="w-3.5 h-3.5" />
              <span>Quarantine Offending IP</span>
            </button>
          </div>

          <div className="bg-slate-900 border border-slate-800 rounded-2xl overflow-hidden shadow-xl">
            <div className="overflow-x-auto">
              <table className="w-full text-left text-xs text-slate-300 font-mono">
                <thead className="bg-slate-950/80 border-b border-slate-800 text-[11px] uppercase text-slate-400">
                  <tr>
                    <th className="px-5 py-3">Quarantined IP</th>
                    <th className="px-5 py-3">Trigger Reason / Classification</th>
                    <th className="px-5 py-3">Blocked By</th>
                    <th className="px-5 py-3">Blocked WAT</th>
                    <th className="px-5 py-3">Dropped Reqs</th>
                    <th className="px-5 py-3">Status</th>
                    <th className="px-5 py-3 text-right">Actions</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-800/60">
                  {blocklist.map((entry) => (
                    <tr key={entry.id} className="hover:bg-slate-800/40 transition">
                      <td className="px-5 py-3 font-bold text-red-400">{entry.ip}</td>
                      <td className="px-5 py-3 text-slate-200">
                        <div>{entry.threatClassification}</div>
                        <div className="text-[10px] text-slate-500">{entry.reason}</div>
                      </td>
                      <td className="px-5 py-3 text-slate-400">{entry.blockedBy}</td>
                      <td className="px-5 py-3 text-[11px] text-slate-400">{entry.blockedAtWat}</td>
                      <td className="px-5 py-3 font-bold text-cyan-400">{entry.requestCountBlocked} dropped</td>
                      <td className="px-5 py-3">
                        <span
                          className={`px-2 py-0.5 rounded text-[10px] font-bold ${
                            entry.status === 'ACTIVE'
                              ? 'bg-red-950 text-red-300 border border-red-800'
                              : 'bg-slate-800 text-slate-400'
                          }`}
                        >
                          {entry.status}
                        </span>
                      </td>
                      <td className="px-5 py-3 text-right">
                        {entry.status === 'ACTIVE' ? (
                          <button
                            onClick={() => handleUnblockIp(entry.ip)}
                            className="px-2.5 py-1 rounded bg-slate-800 hover:bg-emerald-950/60 text-slate-300 hover:text-emerald-400 border border-slate-700 transition"
                          >
                            Unblock
                          </button>
                        ) : (
                          <span className="text-[10px] text-slate-500">Revoked</span>
                        )}
                      </td>
                    </tr>
                  ))}
                  {blocklist.length === 0 && (
                    <tr>
                      <td colSpan={7} className="px-5 py-8 text-center text-slate-500 italic">
                        No active IP quarantines at this time.
                      </td>
                    </tr>
                  )}
                </tbody>
              </table>
            </div>
          </div>

          {/* Upstream Firewall Export Snippet */}
          <div className="bg-slate-900 border border-slate-800 rounded-xl p-4 space-y-2">
            <div className="text-xs font-bold text-slate-200 flex items-center gap-2">
              <FileCode className="w-4 h-4 text-cyan-400" />
              Upstream WAF / Cloudflare Firewall Rule Export
            </div>
            <p className="text-xs text-slate-400">
              Copy and paste this expression into your Cloudflare WAF or Nginx configuration to block these IPs before traffic touches your server:
            </p>
            <pre className="bg-slate-950 border border-slate-850 p-3 rounded-lg text-xs font-mono text-cyan-300 overflow-x-auto whitespace-pre-wrap">
{`# Cloudflare WAF Custom Rule (Expression):
(http.request.client_ip in {${blocklist.filter((b) => b.status === 'ACTIVE').map((b) => `"${b.ip}"`).join(' ')}})

# Nginx / Host Drop Directive:
${blocklist.filter((b) => b.status === 'ACTIVE').map((b) => `deny ${b.ip};`).join('\n')}`}
            </pre>
          </div>
        </div>
      )}

      {/* ──── TAB 3: MITRE ATT&CK MATRIX ──── */}
      {activeSubTab === 'mitre' && (
        <div className="space-y-4">
          <div className="bg-slate-900 border border-slate-800 rounded-xl p-4">
            <h3 className="text-base font-bold text-slate-100 flex items-center gap-2">
              <Target className="w-5 h-5 text-cyan-400" />
              Enterprise MITRE ATT&CK Framework Mapping
            </h3>
            <p className="text-xs text-slate-400 mt-1">
              Real-time adversary technique alignment across institutional telemetry. Heat numbers represent detected exploitation triggers.
            </p>
          </div>

          <div className="grid grid-cols-2 sm:grid-cols-3 md:grid-cols-4 lg:grid-cols-6 gap-3">
            {[
              { tactic: 'Initial Access', tech: 'T1190 Exploit Public-Facing App', desc: 'SQLi, RCE and web parameter tampering' },
              { tactic: 'Execution', tech: 'T1059 Command/Scripting Interpreter', desc: 'xp_cmdshell and shell command payloads' },
              { tactic: 'Persistence', tech: 'T1078 Valid Accounts', desc: 'Dormant staff account abuse & token retention' },
              { tactic: 'Privilege Escalation', tech: 'T1068 Exploitation for Privilege', desc: 'Role authorization bypass attempts' },
              { tactic: 'Defense Evasion', tech: 'T1083 File & Directory Discovery', desc: 'Path traversal (../) and null byte tricks' },
              { tactic: 'Credential Access', tech: 'T1110.004 Credential Stuffing', desc: 'High-frequency brute-force login loops' },
              { tactic: 'Discovery', tech: 'T1046 Network Service Scanning', desc: 'Automated vulnerability reconnaissance' },
              { tactic: 'Lateral Movement', tech: 'T1210 Remote Services Exploitation', desc: 'Pivoting from HRMS to internal Clinic EHR' },
              { tactic: 'Collection', tech: 'T1005 Data from Local System', desc: 'Payroll dump & employee BVN exfiltration' },
              { tactic: 'Exfiltration', tech: 'T1048 Exfiltration Over Protocol', desc: 'Out-of-band HTTP exfiltration to C2 domains' },
              { tactic: 'Impact', tech: 'T1499 Endpoint Denial of Service', desc: 'Layer 7 volumetric traffic & query saturation' },
            ].map((m) => {
              const heat = metrics?.mitreDistribution?.[m.tactic] || 0;
              const hasHeat = heat > 0;
              return (
                <div
                  key={m.tactic}
                  className={`p-3.5 rounded-xl border transition flex flex-col justify-between ${
                    hasHeat
                      ? 'bg-slate-900 border-cyan-500/50 shadow-lg shadow-cyan-500/10'
                      : 'bg-slate-950/50 border-slate-850 opacity-70'
                  }`}
                >
                  <div>
                    <div className="flex items-center justify-between">
                      <span className="text-[10px] font-bold uppercase tracking-wider text-slate-400 font-mono">
                        {m.tactic}
                      </span>
                      <span
                        className={`px-1.5 py-0.2 rounded-full text-[10px] font-mono font-bold ${
                          hasHeat ? 'bg-cyan-500 text-slate-950' : 'bg-slate-800 text-slate-500'
                        }`}
                      >
                        {heat}
                      </span>
                    </div>
                    <div className="text-xs font-bold text-slate-200 mt-2 font-mono">{m.tech}</div>
                    <p className="text-[11px] text-slate-400 mt-1 leading-snug">{m.desc}</p>
                  </div>
                  <div className="mt-3 pt-2 border-t border-slate-850 text-[10px] text-cyan-400/80 font-mono">
                    {hasHeat ? '● Active Detection' : '○ Guarded'}
                  </div>
                </div>
              );
            })}
          </div>
        </div>
      )}

      {/* ──── TAB 4: SOAR PLAYBOOKS ──── */}
      {activeSubTab === 'playbooks' && (
        <div className="space-y-4">
          <div className="bg-slate-900 border border-slate-800 rounded-xl p-4">
            <h3 className="text-base font-bold text-slate-100 flex items-center gap-2">
              <Play className="w-5 h-5 text-amber-400" />
              Automated & Interactive SOAR Playbooks
            </h3>
            <p className="text-xs text-slate-400 mt-1">
              Standardized incident response workflows executing automated containments, notifications, and containment patches.
            </p>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
            {playbooks.map((pb) => (
              <div key={pb.id} className="bg-slate-900 border border-slate-800 rounded-2xl p-5 flex flex-col justify-between space-y-4 shadow-xl">
                <div>
                  <div className="flex items-center justify-between">
                    <span className="text-xs font-mono font-bold text-amber-400 bg-amber-950/60 border border-amber-800/80 px-2 py-0.5 rounded">
                      {pb.id}
                    </span>
                    <span className="text-[11px] text-slate-400 font-mono">Runs: {pb.executionCount}</span>
                  </div>

                  <h4 className="text-base font-bold text-slate-100 mt-2">{pb.name}</h4>
                  <p className="text-xs text-slate-400 mt-1 leading-relaxed">{pb.description}</p>

                  <div className="space-y-2 mt-4 pt-3 border-t border-slate-800">
                    <div className="text-[11px] font-mono text-slate-400 uppercase tracking-wider">Playbook Action Steps:</div>
                    {pb.steps.map((step) => (
                      <div key={step.id} className="flex items-start gap-2 text-xs">
                        <span className="w-4 h-4 rounded-full bg-emerald-500/20 text-emerald-400 flex items-center justify-center shrink-0 text-[10px] font-bold mt-0.5">
                          ✓
                        </span>
                        <div>
                          <div className="font-semibold text-slate-200">{step.title}</div>
                          <div className="text-[11px] text-slate-500">{step.description}</div>
                        </div>
                      </div>
                    ))}
                  </div>
                </div>

                <div className="pt-3 border-t border-slate-800">
                  <button
                    onClick={() => handleExecutePlaybook(pb.id)}
                    className="w-full py-2.5 rounded-xl bg-amber-500 hover:bg-amber-400 text-slate-950 font-bold text-xs shadow-lg shadow-amber-500/20 transition flex items-center justify-center gap-2"
                  >
                    <Play className="w-3.5 h-3.5" />
                    <span>Execute Playbook Now</span>
                  </button>
                </div>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* ──── TAB 5: THREAT INTEL & IOCS ──── */}
      {activeSubTab === 'iocs' && (
        <div className="space-y-4">
          <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 bg-slate-900 border border-slate-800 rounded-xl p-4">
            <div>
              <h3 className="text-base font-bold text-slate-100 flex items-center gap-2">
                <Radio className="w-5 h-5 text-cyan-400" />
                Indicators of Compromise (IOC) Threat Intelligence Feed
              </h3>
              <p className="text-xs text-slate-400 mt-0.5">
                Targeted institutional indicators, known adversary C2 domains, and malicious hash feeds.
              </p>
            </div>
          </div>

          <div className="bg-slate-900 border border-slate-800 rounded-2xl overflow-hidden shadow-xl">
            <div className="overflow-x-auto">
              <table className="w-full text-left text-xs text-slate-300 font-mono">
                <thead className="bg-slate-950/80 border-b border-slate-800 text-[11px] uppercase text-slate-400">
                  <tr>
                    <th className="px-5 py-3">IOC Type</th>
                    <th className="px-5 py-3">Indicator Value</th>
                    <th className="px-5 py-3">Attributed Threat Actor</th>
                    <th className="px-5 py-3">Severity</th>
                    <th className="px-5 py-3">Confidence</th>
                    <th className="px-5 py-3">MITRE Technique</th>
                    <th className="px-5 py-3">Tags</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-800/60">
                  {iocs.map((ioc) => (
                    <tr key={ioc.id} className="hover:bg-slate-800/40 transition">
                      <td className="px-5 py-3">
                        <span className="px-2 py-0.5 rounded bg-slate-800 text-cyan-400 font-bold text-[10px]">
                          {ioc.type}
                        </span>
                      </td>
                      <td className="px-5 py-3 font-bold text-slate-100">{ioc.value}</td>
                      <td className="px-5 py-3 text-slate-400">{ioc.threatActor || 'Unknown'}</td>
                      <td className="px-5 py-3">
                        <span
                          className={`px-2 py-0.5 rounded text-[10px] font-bold ${
                            ioc.severity === 'CRITICAL' ? 'bg-red-950 text-red-400' : 'bg-orange-950 text-orange-400'
                          }`}
                        >
                          {ioc.severity}
                        </span>
                      </td>
                      <td className="px-5 py-3 text-emerald-400 font-bold">{ioc.confidence}%</td>
                      <td className="px-5 py-3 text-slate-300">{ioc.mitreTechnique}</td>
                      <td className="px-5 py-3">
                        <div className="flex flex-wrap gap-1">
                          {ioc.tags.map((tag, i) => (
                            <span key={i} className="text-[9px] bg-slate-950 text-slate-400 px-1.5 py-0.5 rounded">
                              #{tag}
                            </span>
                          ))}
                        </div>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        </div>
      )}

      {/* ──── TAB 6: SIEM DETECTION RULES ──── */}
      {activeSubTab === 'rules' && (
        <div className="space-y-4">
          <div className="bg-slate-900 border border-slate-800 rounded-xl p-4">
            <h3 className="text-base font-bold text-slate-100 flex items-center gap-2">
              <Cpu className="w-5 h-5 text-emerald-400" />
              SIEM & Detection Engineering Rules Catalog
            </h3>
            <p className="text-xs text-slate-400 mt-1">
              Active heuristic and threshold rules continuously inspecting incoming university HTTP/UDP telemetry.
            </p>
          </div>

          <div className="space-y-3">
            {rules.map((rule) => (
              <div
                key={rule.id}
                className="bg-slate-900 border border-slate-800 rounded-xl p-4 flex flex-col md:flex-row items-start md:items-center justify-between gap-4 transition hover:border-slate-700"
              >
                <div className="space-y-1">
                  <div className="flex items-center gap-2">
                    <span className="text-xs font-mono font-bold text-cyan-400">{rule.id}</span>
                    <span
                      className={`text-[10px] font-bold px-2 py-0.5 rounded font-mono ${
                        rule.severity === 'CRITICAL'
                          ? 'bg-red-950 text-red-400'
                          : rule.severity === 'HIGH'
                          ? 'bg-orange-950 text-orange-400'
                          : 'bg-amber-950 text-amber-300'
                      }`}
                    >
                      {rule.severity}
                    </span>
                    <span className="text-[10px] font-mono text-slate-400 bg-slate-950 px-2 py-0.5 rounded">
                      {rule.mitreTechnique}
                    </span>
                  </div>

                  <h4 className="text-sm font-bold text-slate-100">{rule.name}</h4>
                  <p className="text-xs text-slate-400">{rule.description}</p>
                  <div className="text-[11px] font-mono text-slate-500">
                    Signature: <span className="text-cyan-400/90">{rule.queryPattern}</span>
                  </div>
                </div>

                <div className="flex items-center gap-4 self-end md:self-auto shrink-0">
                  <div className="text-right font-mono">
                    <div className="text-xs font-bold text-slate-200">{rule.triggerCount} Triggers</div>
                    <div className="text-[10px] text-slate-500">Last: {rule.lastTriggeredWat || 'N/A'}</div>
                  </div>

                  <button
                    onClick={() => handleToggleRule(rule.id, rule.enabled)}
                    className={`px-3 py-1.5 rounded-lg text-xs font-bold transition font-mono ${
                      rule.enabled
                        ? 'bg-emerald-500/20 text-emerald-400 border border-emerald-500/40 hover:bg-emerald-500/30'
                        : 'bg-slate-800 text-slate-500 border border-slate-700 hover:text-slate-300'
                    }`}
                  >
                    {rule.enabled ? 'ENABLED' : 'DISABLED'}
                  </button>
                </div>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* ──── TAB 7: SHIFT HANDOVER LOGS ──── */}
      {activeSubTab === 'shifts' && (
        <div className="space-y-4">
          <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 bg-slate-900 border border-slate-800 rounded-xl p-4">
            <div>
              <h3 className="text-base font-bold text-slate-100 flex items-center gap-2">
                <Users className="w-5 h-5 text-indigo-400" />
                SOC Analyst Shift Handover & Operations Roster
              </h3>
              <p className="text-xs text-slate-400 mt-0.5">
                Official operational continuity records between outgoing and incoming SOC duty watches.
              </p>
            </div>
            <button
              onClick={() => setIsShiftModalOpen(true)}
              className="px-3.5 py-2 rounded-lg bg-indigo-600 hover:bg-indigo-500 text-xs font-bold text-white shadow-lg shadow-indigo-600/30 transition flex items-center gap-1.5 self-start sm:self-auto"
            >
              <Users className="w-3.5 h-3.5" />
              <span>Initiate Shift Handover</span>
            </button>
          </div>

          <div className="space-y-4">
            {shifts.map((shift) => (
              <div key={shift.id} className="bg-slate-900 border border-slate-800 rounded-2xl p-5 space-y-4 shadow-xl">
                <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 pb-3 border-b border-slate-800">
                  <div>
                    <span className="text-xs font-mono font-bold text-indigo-400">{shift.id}</span>
                    <h4 className="text-base font-bold text-slate-100 mt-0.5">{shift.shiftName}</h4>
                  </div>
                  <div className="text-xs text-slate-400 font-mono">
                    Handover WAT: <span className="text-slate-200">{shift.handoverTimestampWat}</span>
                  </div>
                </div>

                <div className="grid grid-cols-1 md:grid-cols-2 gap-4 text-xs">
                  <div>
                    <div className="text-[11px] font-mono uppercase text-slate-400 mb-1">Lead Analyst in Charge:</div>
                    <div className="font-bold text-slate-200">{shift.leadAnalyst}</div>
                    <div className="text-slate-400 mt-0.5">Duty Roster: {shift.analystsOnDuty.join(', ')}</div>
                  </div>

                  <div>
                    <div className="text-[11px] font-mono uppercase text-slate-400 mb-1">Shift Handover Summary:</div>
                    <p className="text-slate-300 leading-relaxed">{shift.handoffNotes}</p>
                  </div>
                </div>

                {shift.actionItems.length > 0 && (
                  <div className="pt-3 border-t border-slate-800 space-y-1.5">
                    <div className="text-[11px] font-mono uppercase text-cyan-400 font-bold">Priority Follow-Up Items:</div>
                    {shift.actionItems.map((item, idx) => (
                      <div key={idx} className="flex items-center gap-2 text-xs text-slate-300">
                        <span className="w-1.5 h-1.5 rounded-full bg-cyan-400" />
                        <span>{item}</span>
                      </div>
                    ))}
                  </div>
                )}
              </div>
            ))}
          </div>
        </div>
      )}

      {/* ─── MODAL: QUARANTINE IP ───────────────────────── */}
      {isBanModalOpen && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/80 backdrop-blur-sm">
          <div className="bg-slate-900 border border-slate-800 rounded-2xl max-w-md w-full p-6 space-y-4 shadow-2xl">
            <h3 className="text-lg font-bold text-slate-100 flex items-center gap-2">
              <Ban className="w-5 h-5 text-red-500" />
              Quarantine Offending IP
            </h3>
            <p className="text-xs text-slate-400">
              Immediately drop all incoming HTTP/UDP telemetry from this IP address across all registered systems.
            </p>

            <div className="space-y-3">
              <div>
                <label className="text-xs text-slate-300 font-medium">IP Address / Host</label>
                <input
                  type="text"
                  placeholder="e.g. 194.26.29.112"
                  value={banIpInput}
                  onChange={(e) => setBanIpInput(e.target.value)}
                  className="w-full mt-1 bg-slate-950 border border-slate-800 rounded-lg px-3 py-2 text-xs text-slate-200 font-mono focus:outline-none focus:border-red-500"
                />
              </div>

              <div>
                <label className="text-xs text-slate-300 font-medium">Quarantine Justification</label>
                <input
                  type="text"
                  placeholder="e.g. Manual ban due to suspicious SQL injection probe"
                  value={banReasonInput}
                  onChange={(e) => setBanReasonInput(e.target.value)}
                  className="w-full mt-1 bg-slate-950 border border-slate-800 rounded-lg px-3 py-2 text-xs text-slate-200 focus:outline-none focus:border-red-500"
                />
              </div>
            </div>

            <div className="flex justify-end gap-2 pt-2">
              <button
                onClick={() => setIsBanModalOpen(false)}
                className="px-4 py-2 rounded-lg bg-slate-800 text-xs font-semibold text-slate-300 hover:bg-slate-700"
              >
                Cancel
              </button>
              <button
                onClick={handleBlockIp}
                className="px-4 py-2 rounded-lg bg-red-600 hover:bg-red-500 text-xs font-bold text-white shadow-lg shadow-red-600/30"
              >
                Enforce Quarantine
              </button>
            </div>
          </div>
        </div>
      )}

      {/* ─── MODAL: SHIFT HANDOVER ───────────────────────── */}
      {isShiftModalOpen && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/80 backdrop-blur-sm">
          <div className="bg-slate-900 border border-slate-800 rounded-2xl max-w-md w-full p-6 space-y-4 shadow-2xl">
            <h3 className="text-lg font-bold text-slate-100 flex items-center gap-2">
              <Users className="w-5 h-5 text-indigo-400" />
              Document Duty Shift Handover
            </h3>

            <div className="space-y-3">
              <div>
                <label className="text-xs text-slate-300 font-medium">Shift Name</label>
                <select
                  value={shiftNameInput}
                  onChange={(e) => setShiftNameInput(e.target.value)}
                  className="w-full mt-1 bg-slate-950 border border-slate-800 rounded-lg px-3 py-2 text-xs text-slate-200"
                >
                  <option value="ALPHA (Morning 08:00 - 16:00 WAT)">ALPHA (Morning 08:00 - 16:00 WAT)</option>
                  <option value="BRAVO (Evening 16:00 - 00:00 WAT)">BRAVO (Evening 16:00 - 00:00 WAT)</option>
                  <option value="CHARLIE (Night 00:00 - 08:00 WAT)">CHARLIE (Night 00:00 - 08:00 WAT)</option>
                </select>
              </div>

              <div>
                <label className="text-xs text-slate-300 font-medium">Operational Handover Notes</label>
                <textarea
                  rows={4}
                  value={shiftNotesInput}
                  onChange={(e) => setShiftNotesInput(e.target.value)}
                  placeholder="Detail active containment status, ongoing investigations, and specific watch instructions for next watch..."
                  className="w-full mt-1 bg-slate-950 border border-slate-800 rounded-lg p-3 text-xs text-slate-200 focus:outline-none focus:border-indigo-500"
                />
              </div>
            </div>

            <div className="flex justify-end gap-2 pt-2">
              <button
                onClick={() => setIsShiftModalOpen(false)}
                className="px-4 py-2 rounded-lg bg-slate-800 text-xs font-semibold text-slate-300 hover:bg-slate-700"
              >
                Cancel
              </button>
              <button
                onClick={handleCreateShift}
                className="px-4 py-2 rounded-lg bg-indigo-600 hover:bg-indigo-500 text-xs font-bold text-white shadow-lg shadow-indigo-600/30"
              >
                Sign Off & Save Handover
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
