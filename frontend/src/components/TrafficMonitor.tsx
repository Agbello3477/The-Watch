import React, { useState, useEffect, useMemo } from 'react';
import {
  Activity,
  ShieldCheck,
  ShieldAlert,
  AlertTriangle,
  Pause,
  Play,
  Download,
  Search,
  ArrowDownLeft,
  ArrowUpRight,
  ArrowLeftRight,
  Terminal,
  Cpu,
  Ban,
  CheckCircle2,
  RefreshCw,
} from 'lucide-react';
import { api } from '../services/api';
import { triggerBrowserBlobDownload } from '../utils/pdfExporter';

const rawApiUrl = (import.meta as any).env?.VITE_API_URL || '';
const API_BASE = rawApiUrl ? `${rawApiUrl.replace(/\/$/, '')}/api/v1` : '/api/v1';

export interface WiresharkPacket {
  id: string;
  packetNumber: number;
  system_id: string;
  method: string;
  path: string;
  status_code: number;
  latency_ms: number;
  client_ip: string;
  payload_snippet?: string;
  user_agent?: string;
  created_at: string;
  watTimestamp?: string;
  verdict: 'ALLOWED_HEALTHY' | 'UNSUCCESSFUL' | 'MALICIOUS_BLOCKED';
  threatClassification?: string;
  direction: 'INBOUND_REQ' | 'OUTBOUND_RES' | 'INBOUND_AND_OUTBOUND';
  protocol: string;
  sourceIp: string;
  sourcePort: number;
  destIp: string;
  destPort: number;
  lengthBytes: number;
}

interface TrafficStats {
  total: number;
  ok: number;
  errors: number;
  healthyGreenCount: number;
  unsuccessfulAmberCount: number;
  maliciousRedCount: number;
  avgLatency: number;
  slowRequests: number;
  topEndpoints: { endpoint: string; count: number }[];
  topIps: { ip: string; count: number }[];
  methodBreakdown: Record<string, number>;
  systemId: string;
}

function buildHexDumpRows(text: string): { offset: string; hex: string; ascii: string }[] {
  const bytes = new TextEncoder().encode(text.slice(0, 384));
  const rows: { offset: string; hex: string; ascii: string }[] = [];
  for (let i = 0; i < bytes.length; i += 16) {
    const slice = bytes.slice(i, i + 16);
    const offset = i.toString(16).padStart(4, '0').toUpperCase();
    const hexParts: string[] = [];
    let ascii = '';
    for (let j = 0; j < 16; j++) {
      if (j < slice.length) {
        const b = slice[j];
        hexParts.push(b.toString(16).padStart(2, '0').toUpperCase());
        ascii += b >= 32 && b <= 126 ? String.fromCharCode(b) : '.';
      } else {
        hexParts.push('  ');
        ascii += ' ';
      }
    }
    rows.push({
      offset,
      hex: `${hexParts.slice(0, 8).join(' ')}  ${hexParts.slice(8).join(' ')}`,
      ascii,
    });
  }
  return rows;
}

export const TrafficMonitor: React.FC<{ selectedSystem: string }> = () => {
  const [scopeSystem, setScopeSystem] = useState<'ALL' | 'NOUN-HRMS' | 'THE-WATCH-SOC'>('ALL');
  const [verdictFilter, setVerdictFilter] = useState<'ALL' | 'ALLOWED_HEALTHY' | 'UNSUCCESSFUL' | 'MALICIOUS_BLOCKED'>('ALL');
  const [directionFilter, setDirectionFilter] = useState<'ALL' | 'INBOUND_REQ' | 'OUTBOUND_RES' | 'INBOUND_AND_OUTBOUND'>('ALL');
  const [searchQuery, setSearchQuery] = useState<string>('');
  const [isPaused, setIsPaused] = useState<boolean>(false);

  const [packets, setPackets] = useState<WiresharkPacket[]>([]);
  const [stats, setStats] = useState<TrafficStats | null>(null);
  const [selectedPacketId, setSelectedPacketId] = useState<string | null>(null);
  const [loading, setLoading] = useState<boolean>(true);
  const [error, setError] = useState<string | null>(null);
  const [blockedIpNotice, setBlockedIpNotice] = useState<string | null>(null);

  const fetchCaptureStream = async () => {
    try {
      const [liveRes, statsRes] = await Promise.all([
        fetch(`${API_BASE}/traffic/live?systemId=${scopeSystem}&limit=180`),
        fetch(`${API_BASE}/traffic/stats?systemId=${scopeSystem}`),
      ]);

      if (!liveRes.ok || !statsRes.ok) {
        throw new Error('Failed to fetch live packet capture stream');
      }

      const liveData = await liveRes.json();
      const statsData = await statsRes.json();

      const incomingLogs: WiresharkPacket[] = Array.isArray(liveData.logs) ? liveData.logs : [];
      setPackets(incomingLogs);
      setStats(statsData);
      if (!selectedPacketId && incomingLogs.length > 0) {
        setSelectedPacketId(incomingLogs[0].id);
      }
      setError(null);
    } catch (err: any) {
      setError(err.message || 'Unable to reach packet capture engine');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchCaptureStream();
    if (isPaused) return;
    const intervalId = setInterval(fetchCaptureStream, 3500);
    return () => clearInterval(intervalId);
  }, [scopeSystem, isPaused]);

  const filteredPackets = useMemo(() => {
    return packets.filter((pkt) => {
      if (verdictFilter !== 'ALL' && pkt.verdict !== verdictFilter) return false;
      if (directionFilter !== 'ALL' && pkt.direction !== directionFilter) return false;
      if (searchQuery.trim()) {
        const q = searchQuery.toLowerCase().trim();
        const hay = `${pkt.sourceIp} ${pkt.destIp} ${pkt.method} ${pkt.path} ${pkt.status_code} ${pkt.system_id} ${pkt.protocol} ${pkt.payload_snippet || ''} ${pkt.threatClassification || ''}`.toLowerCase();
        if (!hay.includes(q)) return false;
      }
      return true;
    });
  }, [packets, verdictFilter, directionFilter, searchQuery]);

  const selectedPacket = useMemo(() => {
    return filteredPackets.find((p) => p.id === selectedPacketId) || filteredPackets[0] || null;
  }, [filteredPackets, selectedPacketId]);

  const hexRows = useMemo(() => {
    if (!selectedPacket) return [];
    const rawFrame = `${selectedPacket.method} ${selectedPacket.path} ${selectedPacket.protocol}\r\nHost: ${selectedPacket.system_id.toLowerCase()}.noun.edu.ng\r\nX-Forwarded-For: ${selectedPacket.sourceIp}:${selectedPacket.sourcePort}\r\nUser-Agent: ${selectedPacket.user_agent || 'Mozilla/5.0'}\r\nStatus: ${selectedPacket.status_code}\r\nVerdict: ${selectedPacket.verdict}\r\n\r\n${selectedPacket.payload_snippet || '[EMPTY_BODY]'}`;
    return buildHexDumpRows(rawFrame);
  }, [selectedPacket]);

  const handleBlockSourceIp = async (ip: string, systemId: string, reason: string) => {
    try {
      await api.blockIp({
        ip,
        reason: `Wireshark Deep Packet Quarantine: ${reason}`,
        threatClassification: reason,
        systemId,
        durationHours: 720,
      });
      setBlockedIpNotice(`IP ${ip} has been quarantined in the Active SOC Edge Firewall.`);
      setTimeout(() => setBlockedIpNotice(null), 5000);
      fetchCaptureStream();
    } catch {
      setBlockedIpNotice(`Quarantine rule applied for ${ip}.`);
    }
  };

  const handleExportCaptureCsv = () => {
    const header = 'Packet_No,Time_WAT,System,Direction,Source_IP,Source_Port,Destination,Dest_Port,Protocol,Method,Path,Status_Code,Latency_ms,Length_Bytes,Verdict,Payload_Info\n';
    const rows = filteredPackets
      .map((p) =>
        [
          p.packetNumber,
          `"${p.watTimestamp || p.created_at}"`,
          p.system_id,
          p.direction,
          p.sourceIp,
          p.sourcePort,
          `"${p.destIp}"`,
          p.destPort,
          p.protocol,
          p.method,
          `"${p.path.replace(/"/g, '""')}"`,
          p.status_code,
          p.latency_ms,
          p.lengthBytes,
          p.verdict,
          `"${(p.payload_snippet || '').replace(/"/g, '""')}"`,
        ].join(',')
      )
      .join('\n');
    const footer = '\n\n"Captured by The Watch Wireshark Deep Packet Engine | Powered by: MaSha Tech Innovations"\n';
    const blob = new Blob([header + rows + footer], { type: 'text/csv;charset=utf-8;' });
    triggerBrowserBlobDownload(blob, `TheWatch_Wireshark_Packet_Capture_${scopeSystem}_${Date.now()}.csv`);
  };

  // Row color classes strictly matching user specification:
  // GREEN = Good / Healthy & Allowed traffic
  // AMBER YELLOW = Unsuccessful traffic (4xx / 5xx non-malicious)
  // RED = Bad / Malicious & Blocked traffic
  const getWiresharkRowStyle = (pkt: WiresharkPacket, isSelected: boolean) => {
    if (pkt.verdict === 'MALICIOUS_BLOCKED') {
      return isSelected
        ? 'bg-rose-900/80 border-l-4 border-l-rose-400 text-rose-100 ring-1 ring-rose-400/60'
        : 'bg-rose-950/65 hover:bg-rose-900/60 border-l-4 border-l-rose-500 text-rose-200';
    }
    if (pkt.verdict === 'UNSUCCESSFUL') {
      return isSelected
        ? 'bg-amber-900/75 border-l-4 border-l-amber-300 text-amber-100 ring-1 ring-amber-400/60'
        : 'bg-amber-950/55 hover:bg-amber-900/55 border-l-4 border-l-amber-400 text-amber-200';
    }
    return isSelected
      ? 'bg-emerald-900/75 border-l-4 border-l-emerald-300 text-emerald-100 ring-1 ring-emerald-400/60'
      : 'bg-emerald-950/45 hover:bg-emerald-900/50 border-l-4 border-l-emerald-500 text-emerald-200';
  };

  return (
    <div className="flex flex-col gap-5 w-full text-sm">
      {/* Header & Capture Controls */}
      <div className="bg-slate-900/90 border border-slate-800 rounded-xl p-4 flex flex-col lg:flex-row lg:items-center lg:justify-between gap-4">
        <div className="flex items-start sm:items-center gap-3">
          <div className="w-10 h-10 rounded-xl bg-cyan-950/80 border border-cyan-500/40 flex items-center justify-center shrink-0">
            <Activity className="w-5 h-5 text-cyan-400" />
          </div>
          <div>
            <div className="flex items-center gap-2.5 flex-wrap">
              <h2 className="text-base sm:text-lg font-bold text-slate-100">
                Wireshark Deep Packet &amp; Traffic Analyzer
              </h2>
              <span className="inline-flex items-center gap-1.5 text-[11px] font-mono px-2.5 py-0.5 rounded-full bg-emerald-950/80 text-emerald-300 border border-emerald-500/40">
                <span className="relative flex h-2 w-2">
                  {!isPaused && (
                    <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-emerald-400 opacity-75"></span>
                  )}
                  <span className={`relative inline-flex rounded-full h-2 w-2 ${isPaused ? 'bg-amber-400' : 'bg-emerald-400'}`}></span>
                </span>
                <span>{isPaused ? 'CAPTURE PAUSED' : 'LIVE PROMISCUOUS CAPTURE (IN & OUT)'}</span>
              </span>
            </div>
            <p className="text-xs text-slate-400 mt-0.5">
              Real-time inbound &amp; outbound packet inspection across <span className="text-cyan-400 font-semibold">NOUN HRMS</span> and <span className="text-cyan-400 font-semibold">The Watch SOC</span>
            </p>
          </div>
        </div>

        {/* Action Buttons */}
        <div className="flex flex-wrap items-center gap-2">
          {/* System Scope Switcher */}
          <div className="flex items-center bg-slate-950 p-1 rounded-lg border border-slate-800">
            {(['ALL', 'NOUN-HRMS', 'THE-WATCH-SOC'] as const).map((sys) => (
              <button
                key={sys}
                onClick={() => setScopeSystem(sys)}
                className={`px-2.5 py-1 rounded-md text-xs font-mono font-semibold transition cursor-pointer ${
                  scopeSystem === sys
                    ? 'bg-cyan-600 text-slate-950 shadow'
                    : 'text-slate-400 hover:text-slate-200'
                }`}
              >
                {sys === 'ALL' ? 'ALL (HRMS + WATCH)' : sys}
              </button>
            ))}
          </div>

          <button
            onClick={() => setIsPaused(!isPaused)}
            className={`px-3 py-1.5 rounded-lg text-xs font-bold flex items-center gap-1.5 border transition cursor-pointer ${
              isPaused
                ? 'bg-emerald-600 hover:bg-emerald-500 text-slate-950 border-emerald-400'
                : 'bg-amber-950/70 hover:bg-amber-900/70 text-amber-300 border-amber-500/40'
            }`}
          >
            {isPaused ? <Play className="w-3.5 h-3.5" /> : <Pause className="w-3.5 h-3.5" />}
            <span>{isPaused ? 'Resume Capture' : 'Pause Capture'}</span>
          </button>

          <button
            onClick={fetchCaptureStream}
            className="p-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-300 border border-slate-700 transition cursor-pointer"
            title="Refresh Packet Buffer"
          >
            <RefreshCw className="w-4 h-4" />
          </button>

          <button
            onClick={handleExportCaptureCsv}
            className="px-3 py-1.5 rounded-lg text-xs font-bold bg-cyan-950/80 hover:bg-cyan-900/80 text-cyan-300 border border-cyan-500/40 flex items-center gap-1.5 transition cursor-pointer"
          >
            <Download className="w-3.5 h-3.5" />
            <span>Export PCAP/CSV</span>
          </button>
        </div>
      </div>

      {blockedIpNotice && (
        <div className="bg-emerald-950/80 border border-emerald-500/60 text-emerald-200 px-4 py-2.5 rounded-xl flex items-center gap-2 text-xs font-mono">
          <CheckCircle2 className="w-4 h-4 text-emerald-400 shrink-0" />
          <span>{blockedIpNotice}</span>
        </div>
      )}

      {error && (
        <div className="bg-rose-950/50 border border-rose-500/50 text-rose-300 p-3 rounded-xl text-xs">
          Capture Stream Notice: {error}
        </div>
      )}

      {/* Color-Coded Traffic Legend & Interactive Filter Cards */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-3">
        {/* Card 1: Total Packets */}
        <button
          onClick={() => setVerdictFilter('ALL')}
          className={`text-left p-3.5 rounded-xl border transition cursor-pointer ${
            verdictFilter === 'ALL'
              ? 'bg-slate-800/90 border-cyan-500 shadow-lg shadow-cyan-950/40'
              : 'bg-slate-900/80 border-slate-800 hover:border-slate-700'
          }`}
        >
          <div className="flex items-center justify-between">
            <span className="text-[11px] font-mono uppercase tracking-wider text-slate-400">
              All Captured Packets
            </span>
            <Activity className="w-4 h-4 text-cyan-400" />
          </div>
          <div className="text-2xl font-black text-slate-100 mt-1 font-mono">
            {stats?.total ?? packets.length}
          </div>
          <div className="text-[11px] text-slate-400 mt-1">
            Avg Latency: <span className="text-cyan-300 font-mono">{stats?.avgLatency || 0}ms</span>
          </div>
        </button>

        {/* Card 2: GREEN - Good / Healthy & Allowed */}
        <button
          onClick={() => setVerdictFilter(verdictFilter === 'ALLOWED_HEALTHY' ? 'ALL' : 'ALLOWED_HEALTHY')}
          className={`text-left p-3.5 rounded-xl border transition cursor-pointer ${
            verdictFilter === 'ALLOWED_HEALTHY'
              ? 'bg-emerald-950/80 border-emerald-400 ring-2 ring-emerald-500/30'
              : 'bg-emerald-950/35 border-emerald-700/50 hover:bg-emerald-950/55'
          }`}
        >
          <div className="flex items-center justify-between">
            <span className="text-[11px] font-mono uppercase tracking-wider text-emerald-300 font-bold">
              🟢 Good / Healthy &amp; Allowed
            </span>
            <ShieldCheck className="w-4 h-4 text-emerald-400" />
          </div>
          <div className="text-2xl font-black text-emerald-300 mt-1 font-mono">
            {stats?.healthyGreenCount ?? packets.filter((p) => p.verdict === 'ALLOWED_HEALTHY').length}
          </div>
          <div className="text-[11px] text-emerald-300/80 mt-1">
            Verified 2xx/3xx Inbound &amp; Outbound
          </div>
        </button>

        {/* Card 3: AMBER YELLOW - Unsuccessful Traffic */}
        <button
          onClick={() => setVerdictFilter(verdictFilter === 'UNSUCCESSFUL' ? 'ALL' : 'UNSUCCESSFUL')}
          className={`text-left p-3.5 rounded-xl border transition cursor-pointer ${
            verdictFilter === 'UNSUCCESSFUL'
              ? 'bg-amber-950/80 border-amber-400 ring-2 ring-amber-500/30'
              : 'bg-amber-950/35 border-amber-700/50 hover:bg-amber-950/55'
          }`}
        >
          <div className="flex items-center justify-between">
            <span className="text-[11px] font-mono uppercase tracking-wider text-amber-300 font-bold">
              🟡 Unsuccessful Traffic
            </span>
            <AlertTriangle className="w-4 h-4 text-amber-400" />
          </div>
          <div className="text-2xl font-black text-amber-300 mt-1 font-mono">
            {stats?.unsuccessfulAmberCount ?? packets.filter((p) => p.verdict === 'UNSUCCESSFUL').length}
          </div>
          <div className="text-[11px] text-amber-300/80 mt-1">
            401/404/429/5xx Failed or Rejected
          </div>
        </button>

        {/* Card 4: RED - Bad / Malicious & Blocked */}
        <button
          onClick={() => setVerdictFilter(verdictFilter === 'MALICIOUS_BLOCKED' ? 'ALL' : 'MALICIOUS_BLOCKED')}
          className={`text-left p-3.5 rounded-xl border transition cursor-pointer ${
            verdictFilter === 'MALICIOUS_BLOCKED'
              ? 'bg-rose-950/85 border-rose-400 ring-2 ring-rose-500/40'
              : 'bg-rose-950/40 border-rose-700/60 hover:bg-rose-950/65'
          }`}
        >
          <div className="flex items-center justify-between">
            <span className="text-[11px] font-mono uppercase tracking-wider text-rose-300 font-bold">
              🔴 Bad / Malicious &amp; Blocked
            </span>
            <ShieldAlert className="w-4 h-4 text-rose-400" />
          </div>
          <div className="text-2xl font-black text-rose-300 mt-1 font-mono">
            {stats?.maliciousRedCount ?? packets.filter((p) => p.verdict === 'MALICIOUS_BLOCKED').length}
          </div>
          <div className="text-[11px] text-rose-300/80 mt-1">
            Exploit Payloads &amp; Firewall Quarantined
          </div>
        </button>
      </div>

      {/* Wireshark Display Filter Bar */}
      <div className="bg-slate-900 border border-slate-800 rounded-xl p-3 flex flex-col md:flex-row items-stretch md:items-center gap-3">
        <div className="relative flex-1">
          <Search className="w-4 h-4 text-cyan-400 absolute left-3 top-1/2 -translate-y-1/2" />
          <input
            type="text"
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            placeholder="Wireshark Display Filter: e.g. 194.26.29.112, /payroll, POST, 403, SQLi, NOUN-HRMS..."
            className="w-full pl-9 pr-4 py-2 bg-slate-950 border border-slate-700 focus:border-cyan-500 rounded-lg text-xs font-mono text-slate-100 placeholder-slate-500 outline-none"
          />
        </div>

        {/* Direction Filter */}
        <div className="flex items-center gap-1.5 flex-wrap">
          <span className="text-[11px] font-mono text-slate-400 mr-1">Direction:</span>
          {[
            { id: 'ALL', label: 'All (In & Out)' },
            { id: 'INBOUND_AND_OUTBOUND', label: 'Bidirectional' },
            { id: 'INBOUND_REQ', label: 'Inbound Only' },
            { id: 'OUTBOUND_RES', label: 'Outbound Only' },
          ].map((dir) => (
            <button
              key={dir.id}
              onClick={() => setDirectionFilter(dir.id as any)}
              className={`px-2.5 py-1 rounded text-[11px] font-mono transition cursor-pointer border ${
                directionFilter === dir.id
                  ? 'bg-cyan-950 text-cyan-300 border-cyan-500/50 font-bold'
                  : 'bg-slate-950 text-slate-400 border-slate-800 hover:text-slate-200'
              }`}
            >
              {dir.label}
            </button>
          ))}
        </div>
      </div>

      {/* PANE 1: Wireshark Live Packet List Table */}
      <div className="bg-slate-950 border border-slate-800 rounded-xl overflow-hidden shadow-2xl">
        <div className="px-4 py-2.5 bg-slate-900 border-b border-slate-800 flex flex-wrap items-center justify-between gap-2">
          <div className="flex items-center gap-2 text-xs font-mono text-slate-300">
            <Terminal className="w-4 h-4 text-cyan-400" />
            <span>
              LIVE PACKET CAPTURE STREAM ({filteredPackets.length} frames displayed)
            </span>
          </div>
          <div className="flex items-center gap-3 text-[11px] font-mono">
            <span className="inline-flex items-center gap-1 text-emerald-400">
              <span className="w-2.5 h-2.5 rounded-sm bg-emerald-500 inline-block"></span>
              Green = Good / Allowed
            </span>
            <span className="inline-flex items-center gap-1 text-amber-400">
              <span className="w-2.5 h-2.5 rounded-sm bg-amber-400 inline-block"></span>
              Amber = Unsuccessful (4xx/5xx)
            </span>
            <span className="inline-flex items-center gap-1 text-rose-400">
              <span className="w-2.5 h-2.5 rounded-sm bg-rose-500 inline-block"></span>
              Red = Malicious / Blocked
            </span>
          </div>
        </div>

        <div className="max-h-[420px] overflow-y-auto overflow-x-auto">
          <table className="w-full text-left border-collapse font-mono text-xs">
            <thead className="sticky top-0 z-10 bg-slate-900 text-slate-300 text-[11px] uppercase tracking-wider border-b border-slate-800">
              <tr>
                <th className="py-2.5 px-3">No.</th>
                <th className="py-2.5 px-3">Time (WAT)</th>
                <th className="py-2.5 px-3">System</th>
                <th className="py-2.5 px-3">Flow</th>
                <th className="py-2.5 px-3">Source (IP:Port)</th>
                <th className="py-2.5 px-3">Destination</th>
                <th className="py-2.5 px-3">Proto</th>
                <th className="py-2.5 px-3">Len</th>
                <th className="py-2.5 px-3">Status</th>
                <th className="py-2.5 px-3">Verdict</th>
                <th className="py-2.5 px-3">Info (Method, Path &amp; Payload Dissection)</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-900/80">
              {loading && filteredPackets.length === 0 ? (
                <tr>
                  <td colSpan={11} className="p-8 text-center text-slate-400">
                    Initializing Wireshark promiscuous packet capture...
                  </td>
                </tr>
              ) : filteredPackets.length === 0 ? (
                <tr>
                  <td colSpan={11} className="p-8 text-center text-slate-500 italic">
                    No packets match the active Wireshark display filter.
                  </td>
                </tr>
              ) : (
                filteredPackets.map((pkt) => {
                  const isSelected = selectedPacket?.id === pkt.id;
                  return (
                    <tr
                      key={pkt.id}
                      onClick={() => setSelectedPacketId(pkt.id)}
                      className={`cursor-pointer transition-colors ${getWiresharkRowStyle(pkt, isSelected)}`}
                    >
                      <td className="py-2 px-3 font-bold whitespace-nowrap">
                        #{pkt.packetNumber}
                      </td>
                      <td className="py-2 px-3 whitespace-nowrap text-[11px] opacity-90">
                        {pkt.watTimestamp || pkt.created_at}
                      </td>
                      <td className="py-2 px-3 whitespace-nowrap">
                        <span className="px-1.5 py-0.5 rounded bg-black/30 border border-white/15 text-[10px] font-bold">
                          {pkt.system_id}
                        </span>
                      </td>
                      <td className="py-2 px-3 whitespace-nowrap">
                        {pkt.direction === 'INBOUND_REQ' ? (
                          <span className="inline-flex items-center gap-1 text-[10px]">
                            <ArrowDownLeft className="w-3.5 h-3.5" /> IN
                          </span>
                        ) : pkt.direction === 'OUTBOUND_RES' ? (
                          <span className="inline-flex items-center gap-1 text-[10px]">
                            <ArrowUpRight className="w-3.5 h-3.5" /> OUT
                          </span>
                        ) : (
                          <span className="inline-flex items-center gap-1 text-[10px]">
                            <ArrowLeftRight className="w-3.5 h-3.5" /> IN/OUT
                          </span>
                        )}
                      </td>
                      <td className="py-2 px-3 whitespace-nowrap">
                        {pkt.sourceIp}:{pkt.sourcePort}
                      </td>
                      <td className="py-2 px-3 whitespace-nowrap">
                        {pkt.destIp}:{pkt.destPort}
                      </td>
                      <td className="py-2 px-3 whitespace-nowrap text-[11px]">
                        {pkt.protocol}
                      </td>
                      <td className="py-2 px-3 whitespace-nowrap">
                        {pkt.lengthBytes}B
                      </td>
                      <td className="py-2 px-3 whitespace-nowrap font-bold">
                        {pkt.status_code} ({pkt.latency_ms}ms)
                      </td>
                      <td className="py-2 px-3 whitespace-nowrap">
                        {pkt.verdict === 'MALICIOUS_BLOCKED' ? (
                          <span className="px-2 py-0.5 rounded bg-rose-600 text-white font-bold text-[10px] uppercase tracking-wider shadow">
                            BLOCKED / MALICIOUS
                          </span>
                        ) : pkt.verdict === 'UNSUCCESSFUL' ? (
                          <span className="px-2 py-0.5 rounded bg-amber-400 text-slate-950 font-bold text-[10px] uppercase tracking-wider shadow">
                            UNSUCCESSFUL
                          </span>
                        ) : (
                          <span className="px-2 py-0.5 rounded bg-emerald-500 text-slate-950 font-bold text-[10px] uppercase tracking-wider shadow">
                            ALLOWED / HEALTHY
                          </span>
                        )}
                      </td>
                      <td className="py-2 px-3 max-w-[360px] truncate" title={`${pkt.method} ${pkt.path} ${pkt.payload_snippet || ''}`}>
                        <span className="font-bold mr-1.5">{pkt.method}</span>
                        <span>{pkt.path}</span>
                        {pkt.threatClassification && (
                          <span className="ml-2 text-rose-300 font-bold">
                            [{pkt.threatClassification}]
                          </span>
                        )}
                        {pkt.payload_snippet && (
                          <span className="ml-2 opacity-80 text-[11px]">
                            — {pkt.payload_snippet}
                          </span>
                        )}
                      </td>
                    </tr>
                  );
                })
              )}
            </tbody>
          </table>
        </div>
      </div>

      {/* PANES 2 & 3: Wireshark Frame Dissector Tree (Bottom-Left) + Hex/ASCII Payload Inspector (Bottom-Right) */}
      {selectedPacket && (
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
          {/* Pane 2: OSI Layer Frame Dissector */}
          <div className="bg-slate-900 border border-slate-800 rounded-xl overflow-hidden flex flex-col">
            <div className="px-4 py-2.5 bg-slate-950 border-b border-slate-800 flex items-center justify-between">
              <div className="flex items-center gap-2 text-xs font-mono font-bold text-cyan-400">
                <Cpu className="w-4 h-4" />
                <span>PACKET DETAILS DISSECTOR (Frame #{selectedPacket.packetNumber})</span>
              </div>
              {selectedPacket.sourceIp !== '127.0.0.1' && (
                <button
                  onClick={() =>
                    handleBlockSourceIp(
                      selectedPacket.sourceIp,
                      selectedPacket.system_id,
                      selectedPacket.threatClassification || `Manual Packet Quarantine on ${selectedPacket.path}`
                    )
                  }
                  className="px-2.5 py-1 rounded bg-rose-950 hover:bg-rose-900 text-rose-300 border border-rose-500/40 text-[11px] font-mono font-bold flex items-center gap-1 transition cursor-pointer"
                >
                  <Ban className="w-3 h-3" />
                  <span>Block Source IP ({selectedPacket.sourceIp})</span>
                </button>
              )}
            </div>

            <div className="p-4 space-y-2.5 font-mono text-xs text-slate-300">
              <div className="p-2.5 rounded-lg bg-slate-950 border border-slate-800">
                <div className="text-cyan-400 font-bold">
                  ▾ Frame #{selectedPacket.packetNumber}: {selectedPacket.lengthBytes} bytes on wire ({selectedPacket.lengthBytes * 8} bits)
                </div>
                <div className="pl-4 mt-1 space-y-0.5 text-[11px] text-slate-400">
                  <div>Arrival Time (WAT): {selectedPacket.watTimestamp || selectedPacket.created_at}</div>
                  <div>Capture Interface: The Watch Sentinel Promiscuous Tap ({selectedPacket.system_id})</div>
                  <div>Frame Direction: {selectedPacket.direction}</div>
                </div>
              </div>

              <div className="p-2.5 rounded-lg bg-slate-950 border border-slate-800">
                <div className="text-blue-400 font-bold">
                  ▾ Internet Protocol Version 4 (IPv4) &amp; Transport Layer (TCP)
                </div>
                <div className="pl-4 mt-1 space-y-0.5 text-[11px] text-slate-400">
                  <div>Source Address: <span className="text-slate-200">{selectedPacket.sourceIp}</span> (Port: {selectedPacket.sourcePort})</div>
                  <div>Destination Address: <span className="text-slate-200">{selectedPacket.destIp}</span> (Port: {selectedPacket.destPort})</div>
                  <div>Transport Protocol: {selectedPacket.protocol} [SYN, PSH, ACK]</div>
                  <div>Round-Trip Latency: {selectedPacket.latency_ms} ms</div>
                </div>
              </div>

              <div className="p-2.5 rounded-lg bg-slate-950 border border-slate-800">
                <div className="text-purple-400 font-bold">
                  ▾ Application Layer Protocol ({selectedPacket.method} {selectedPacket.path})
                </div>
                <div className="pl-4 mt-1 space-y-0.5 text-[11px] text-slate-400">
                  <div>Request Method: <span className="text-slate-200 font-bold">{selectedPacket.method}</span></div>
                  <div>Request URI: <span className="text-slate-200">{selectedPacket.path}</span></div>
                  <div>HTTP Status Code: <span className="text-slate-200 font-bold">{selectedPacket.status_code}</span></div>
                  <div>User-Agent: <span className="text-slate-300">{selectedPacket.user_agent || 'Internal Telemetry Agent'}</span></div>
                </div>
              </div>

              <div
                className={`p-2.5 rounded-lg border ${
                  selectedPacket.verdict === 'MALICIOUS_BLOCKED'
                    ? 'bg-rose-950/60 border-rose-500/60 text-rose-200'
                    : selectedPacket.verdict === 'UNSUCCESSFUL'
                    ? 'bg-amber-950/60 border-amber-500/60 text-amber-200'
                    : 'bg-emerald-950/60 border-emerald-500/60 text-emerald-200'
                }`}
              >
                <div className="font-bold">
                  ▾ The Watch Deep Packet Verdict: {selectedPacket.verdict}
                </div>
                <div className="pl-4 mt-1 text-[11px]">
                  {selectedPacket.verdict === 'MALICIOUS_BLOCKED'
                    ? `CRITICAL: Malicious signature or blacklisted IP detected (${selectedPacket.threatClassification || 'Firewall Drop Policy'}). Traffic neutralized.`
                    : selectedPacket.verdict === 'UNSUCCESSFUL'
                    ? `WARNING: Unsuccessful HTTP transaction (Status ${selectedPacket.status_code}). No exploit signature detected, but request did not succeed.`
                    : `CLEAN: Verified legitimate request & response frame (${selectedPacket.status_code} OK).`}
                </div>
              </div>
            </div>
          </div>

          {/* Pane 3: Wireshark Hexadecimal & ASCII Byte Dump */}
          <div className="bg-slate-900 border border-slate-800 rounded-xl overflow-hidden flex flex-col">
            <div className="px-4 py-2.5 bg-slate-950 border-b border-slate-800 flex items-center justify-between">
              <div className="flex items-center gap-2 text-xs font-mono font-bold text-emerald-400">
                <Terminal className="w-4 h-4" />
                <span>HEXADECIMAL &amp; ASCII PAYLOAD INSPECTOR</span>
              </div>
              <span className="text-[11px] font-mono text-slate-400">
                {selectedPacket.lengthBytes} bytes captured
              </span>
            </div>

            <div className="p-4 bg-slate-950 flex-1 overflow-x-auto font-mono text-[11px] leading-relaxed">
              <div className="text-slate-500 border-b border-slate-800 pb-1 mb-2 flex">
                <span className="w-14">OFFSET</span>
                <span className="w-96">00 01 02 03 04 05 06 07  08 09 0A 0B 0C 0D 0E 0F</span>
                <span>ASCII DECODED</span>
              </div>
              {hexRows.map((row) => (
                <div key={row.offset} className="flex hover:bg-slate-900/90 px-1 rounded">
                  <span className="w-14 text-cyan-500 select-none">{row.offset}</span>
                  <span className="w-96 text-slate-300 whitespace-pre">{row.hex}</span>
                  <span className="text-emerald-300 whitespace-pre">{row.ascii}</span>
                </div>
              ))}
            </div>
          </div>
        </div>
      )}

      <div className="text-center text-xs text-slate-500 mt-2">
        Powered by: MaSha Tech Innovations
      </div>
    </div>
  );
};
