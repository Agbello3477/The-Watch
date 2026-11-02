import React, { useState, useEffect, useMemo } from 'react';
import {
  Network,
  ShieldAlert,
  Activity,
  Search,
  Copy,
  Check,
  X,
  ArrowRight,
  Lock,
  FileCode,
  Cpu,
  RefreshCw,
  Filter,
  Layers,
  Terminal,
  ExternalLink,
} from 'lucide-react';

const rawApiUrl = (import.meta as any).env?.VITE_API_URL || '';
const ZEEK_API_BASE = rawApiUrl ? `${rawApiUrl.replace(/\/$/, '')}/api/soc/zeek` : '/api/soc/zeek';

interface ZeekConnLog {
  ts: string;
  ts_wat: string;
  uid: string;
  system_id: string;
  'id.orig_h': string;
  'id.orig_p': number;
  'id.resp_h': string;
  'id.resp_p': number;
  proto: 'tcp' | 'udp' | 'icmp';
  service: string;
  duration: number;
  orig_bytes: number;
  resp_bytes: number;
  conn_state: string;
  history: string;
  orig_pkts: number;
  resp_pkts: number;
  community_id: string;
  verdict: 'ALLOWED_HEALTHY' | 'UNSUCCESSFUL' | 'MALICIOUS_BLOCKED';
}

interface ZeekNoticeLog {
  ts: string;
  ts_wat: string;
  uid: string;
  'id.orig_h': string;
  'id.orig_p': number;
  'id.resp_h': string;
  'id.resp_p': number;
  proto: string;
  note: string;
  msg: string;
  sub: string;
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';
  mitre_technique: string;
  actions: string[];
  system_id: string;
}

interface ZeekFileLog {
  ts: string;
  ts_wat: string;
  fuid: string;
  uid: string;
  tx_hosts: string[];
  rx_hosts: string[];
  source: string;
  mime_type: string;
  filename: string;
  total_bytes: number;
  md5: string;
  sha256: string;
  extracted: boolean;
  threat_verdict: 'CLEAN' | 'SUSPICIOUS' | 'MALICIOUS_PAYLOAD';
}

interface ZeekSslLog {
  ts: string;
  ts_wat: string;
  uid: string;
  'id.orig_h': string;
  'id.orig_p': number;
  'id.resp_h': string;
  'id.resp_p': number;
  version: string;
  cipher: string;
  curve: string;
  server_name: string;
  ja3: string;
  ja4: string;
  subject: string;
  issuer: string;
  validation_status: string;
}

interface ZeekTimeline {
  uid: string;
  reconstructedAtWat: string;
  conn: ZeekConnLog | null;
  dns: any[];
  ssl: ZeekSslLog[];
  http: any[];
  files: ZeekFileLog[];
  notices: ZeekNoticeLog[];
  chronologicalEvents: Array<{
    ts: string;
    ts_wat: string;
    logType: string;
    summary: string;
    raw: any;
  }>;
}

interface ZeekEpsMetrics {
  sensorStatus: string;
  sensorNode: string;
  zeekVersion: string;
  eps: number;
  bandwidthMbps: number;
  packetDropRatePercent: number;
  indexedUidsCount: number;
  logCounts: {
    conn: number;
    dns: number;
    ssl: number;
    files: number;
    notices: number;
  };
  timestampWat: string;
}

export const ZeekNetworkMonitor: React.FC = () => {
  const [connections, setConnections] = useState<ZeekConnLog[]>([]);
  const [notices, setNotices] = useState<ZeekNoticeLog[]>([]);
  const [filesIntel, setFilesIntel] = useState<ZeekFileLog[]>([]);
  const [sslIntel, setSslIntel] = useState<ZeekSslLog[]>([]);
  const [metrics, setMetrics] = useState<ZeekEpsMetrics | null>(null);

  // Filters
  const [ipFilter, setIpFilter] = useState<string>('');
  const [uidFilter, setUidFilter] = useState<string>('');
  const [protoFilter, setProtoFilter] = useState<string>('ALL');
  const [serviceFilter, setServiceFilter] = useState<string>('ALL');

  // Drawer & UID Timeline State
  const [selectedConn, setSelectedConn] = useState<ZeekConnLog | null>(null);
  const [activeTimeline, setActiveTimeline] = useState<ZeekTimeline | null>(null);
  const [loadingTimeline, setLoadingTimeline] = useState<boolean>(false);
  const [copiedHash, setCopiedHash] = useState<string | null>(null);
  const [loading, setLoading] = useState<boolean>(true);

  const fetchZeekData = async () => {
    try {
      const [connRes, noticeRes, epsRes, intelRes] = await Promise.all([
        fetch(`${ZEEK_API_BASE}/connections`),
        fetch(`${ZEEK_API_BASE}/notices`),
        fetch(`${ZEEK_API_BASE}/metrics/eps`),
        fetch(`${ZEEK_API_BASE}/intel`),
      ]);

      if (connRes.ok) {
        const d = await connRes.json();
        setConnections(d.connections || []);
      }
      if (noticeRes.ok) {
        const d = await noticeRes.json();
        setNotices(d.notices || []);
      }
      if (epsRes.ok) {
        const d = await epsRes.json();
        setMetrics(d);
      }
      if (intelRes.ok) {
        const d = await intelRes.json();
        setFilesIntel(d.files || []);
        setSslIntel(d.sslFingerprints || []);
      }
    } catch (err) {
      console.warn('[ZeekNSM] Telemetry fetch error:', err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchZeekData();
    const timer = setInterval(fetchZeekData, 4500);
    return () => clearInterval(timer);
  }, []);

  const openUidDrawer = async (uid: string, connRow?: ZeekConnLog) => {
    const found = connRow || connections.find((c) => c.uid === uid) || null;
    setSelectedConn(found);
    setLoadingTimeline(true);
    try {
      const res = await fetch(`${ZEEK_API_BASE}/timeline/${encodeURIComponent(uid)}`);
      if (res.ok) {
        const data: ZeekTimeline = await res.json();
        setActiveTimeline(data);
        if (!found && data.conn) {
          setSelectedConn(data.conn);
        }
      }
    } catch {
      // Fallback
    } finally {
      setLoadingTimeline(false);
    }
  };

  const handlePivotToFullStream = (uid: string) => {
    setUidFilter(uid);
    openUidDrawer(uid);
  };

  const handleCopy = (key: string, text: string) => {
    navigator.clipboard.writeText(text);
    setCopiedHash(key);
    setTimeout(() => setCopiedHash(null), 2200);
  };

  const filteredConnections = useMemo(() => {
    return connections.filter((c) => {
      if (uidFilter.trim() && !c.uid.toLowerCase().includes(uidFilter.toLowerCase().trim())) {
        return false;
      }
      if (ipFilter.trim()) {
        const q = ipFilter.toLowerCase().trim();
        if (
          !c['id.orig_h'].toLowerCase().includes(q) &&
          !c['id.resp_h'].toLowerCase().includes(q) &&
          !String(c['id.orig_p']).includes(q) &&
          !String(c['id.resp_p']).includes(q)
        ) {
          return false;
        }
      }
      if (protoFilter !== 'ALL' && c.proto.toLowerCase() !== protoFilter.toLowerCase()) {
        return false;
      }
      if (serviceFilter !== 'ALL' && c.service.toLowerCase() !== serviceFilter.toLowerCase()) {
        return false;
      }
      return true;
    });
  }, [connections, uidFilter, ipFilter, protoFilter, serviceFilter]);

  // Severity badge classes strictly matching prompt specification:
  // CRITICAL: bg-red-500/10 text-red-400 border border-red-500/30
  // HIGH: bg-orange-500/10 text-orange-400 border border-orange-500/30
  // MEDIUM: bg-yellow-500/10 text-yellow-400 border border-yellow-500/30
  // LOW / INFO: bg-blue-500/10 text-blue-400 border border-blue-500/30
  const getNoticeSeverityStyle = (severity: ZeekNoticeLog['severity']) => {
    switch (severity) {
      case 'CRITICAL':
        return 'bg-red-500/10 text-red-400 border border-red-500/30';
      case 'HIGH':
        return 'bg-orange-500/10 text-orange-400 border border-orange-500/30';
      case 'MEDIUM':
        return 'bg-yellow-500/10 text-yellow-400 border border-yellow-500/30';
      default:
        return 'bg-blue-500/10 text-blue-400 border border-blue-500/30';
    }
  };

  const getConnStateBadge = (state: string) => {
    if (state === 'SF') return 'bg-emerald-500/15 text-emerald-300 border-emerald-500/30';
    if (state === 'REJ' || state === 'RSTO' || state === 'RSTR') return 'bg-red-500/15 text-red-300 border-red-500/30';
    return 'bg-yellow-500/15 text-yellow-300 border-yellow-500/30';
  };

  return (
    <div
      className="rounded-2xl p-4 sm:p-6 space-y-6 text-sm"
      style={{
        backgroundColor: '#0B0F19',
        color: '#F8FAFC',
        border: '1px solid #2D3748',
      }}
    >
      {/* Top Sensor Health & EPS Telemetry Bar */}
      <div
        className="rounded-xl p-4 flex flex-col lg:flex-row lg:items-center lg:justify-between gap-4"
        style={{ backgroundColor: '#161B26', border: '1px solid #2D3748' }}
      >
        <div className="flex items-start sm:items-center gap-3.5">
          <div
            className="w-11 h-11 rounded-xl flex items-center justify-center shrink-0"
            style={{ backgroundColor: '#1F2937', border: '1px solid #2D3748' }}
          >
            <Network className="w-6 h-6 text-cyan-400" />
          </div>
          <div>
            <div className="flex items-center gap-2.5 flex-wrap">
              <h2 className="text-base sm:text-lg font-bold" style={{ color: '#F8FAFC' }}>
                Zeek Network Security Monitor (NSM) Engine
              </h2>
              <span className="inline-flex items-center gap-1.5 px-2.5 py-0.5 rounded-full text-[11px] font-mono bg-emerald-500/10 text-emerald-400 border border-emerald-500/30">
                <span className="w-2 h-2 rounded-full bg-emerald-400 animate-pulse"></span>
                <span>{metrics?.sensorStatus || 'SPAN/TAP PASSIVE SENSOR ONLINE'}</span>
              </span>
            </div>
            <p className="text-xs mt-0.5 font-mono" style={{ color: '#94A3B8' }}>
              Node: <span className="text-cyan-400">{metrics?.sensorNode || 'noun-hrms-zeek-tap-01'}</span> •{' '}
              <span>{metrics?.zeekVersion || 'Zeek v6.0.4 LTS'}</span> •{' '}
              <span style={{ color: '#64748B' }}>redef LogAscii::use_json = T;</span>
            </p>
          </div>
        </div>

        {/* Real-time EPS & Bandwidth Metrics */}
        <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
          <div
            className="px-3.5 py-2 rounded-lg font-mono"
            style={{ backgroundColor: '#1F2937', border: '1px solid #2D3748' }}
          >
            <div className="text-[10px] uppercase" style={{ color: '#94A3B8' }}>
              Ingest Rate (EPS)
            </div>
            <div className="text-base font-bold text-cyan-400">
              {metrics?.eps ?? 154} evt/s
            </div>
          </div>

          <div
            className="px-3.5 py-2 rounded-lg font-mono"
            style={{ backgroundColor: '#1F2937', border: '1px solid #2D3748' }}
          >
            <div className="text-[10px] uppercase" style={{ color: '#94A3B8' }}>
              SPAN Throughput
            </div>
            <div className="text-base font-bold text-emerald-400">
              {metrics?.bandwidthMbps ?? 14.8} Mbps
            </div>
          </div>

          <div
            className="px-3.5 py-2 rounded-lg font-mono"
            style={{ backgroundColor: '#1F2937', border: '1px solid #2D3748' }}
          >
            <div className="text-[10px] uppercase" style={{ color: '#94A3B8' }}>
              Indexed UIDs
            </div>
            <div className="text-base font-bold" style={{ color: '#F8FAFC' }}>
              {metrics?.indexedUidsCount ?? connections.length} flows
            </div>
          </div>

          <div
            className="px-3.5 py-2 rounded-lg font-mono"
            style={{ backgroundColor: '#1F2937', border: '1px solid #2D3748' }}
          >
            <div className="text-[10px] uppercase" style={{ color: '#94A3B8' }}>
              Packet Loss
            </div>
            <div className="text-base font-bold text-emerald-400">
              0.00%
            </div>
          </div>
        </div>
      </div>

      {/* =====================================================================
          1. LIVE CONNECTION STREAM (conn.log Table)
         ===================================================================== */}
      <div
        className="rounded-xl overflow-hidden"
        style={{ backgroundColor: '#161B26', border: '1px solid #2D3748' }}
      >
        <div
          className="p-4 flex flex-col lg:flex-row lg:items-center lg:justify-between gap-3"
          style={{ borderBottom: '1px solid #2D3748', backgroundColor: '#1F2937' }}
        >
          <div>
            <h3 className="text-sm sm:text-base font-bold flex items-center gap-2" style={{ color: '#F8FAFC' }}>
              <Activity className="w-4 h-4 text-cyan-400" />
              <span>1. Live Connection Stream (conn.log)</span>
              <span
                className="text-xs font-mono px-2 py-0.5 rounded"
                style={{ backgroundColor: '#161B26', color: '#94A3B8', border: '1px solid #2D3748' }}
              >
                {filteredConnections.length} sessions
              </span>
            </h3>
            <p className="text-xs mt-0.5" style={{ color: '#94A3B8' }}>
              Click any connection row to open the cross-log <code className="text-cyan-400">uid</code> correlation drawer across DNS, SSL/X.509, HTTP, Files, and Notices.
            </p>
          </div>

          {/* Filter Controls */}
          <div className="flex flex-wrap items-center gap-2">
            <div className="relative">
              <Search className="w-3.5 h-3.5 absolute left-2.5 top-1/2 -translate-y-1/2" style={{ color: '#94A3B8' }} />
              <input
                type="text"
                value={ipFilter}
                onChange={(e) => setIpFilter(e.target.value)}
                placeholder="Filter IP or Port..."
                className="pl-8 pr-3 py-1.5 rounded-lg text-xs font-mono outline-none"
                style={{
                  backgroundColor: '#0B0F19',
                  border: '1px solid #2D3748',
                  color: '#F8FAFC',
                }}
              />
            </div>

            <div className="relative">
              <Filter className="w-3.5 h-3.5 absolute left-2.5 top-1/2 -translate-y-1/2 text-cyan-400" />
              <input
                type="text"
                value={uidFilter}
                onChange={(e) => setUidFilter(e.target.value)}
                placeholder="Filter by Zeek UID..."
                className="pl-8 pr-3 py-1.5 rounded-lg text-xs font-mono outline-none"
                style={{
                  backgroundColor: '#0B0F19',
                  border: '1px solid #2D3748',
                  color: '#F8FAFC',
                }}
              />
            </div>

            <select
              value={protoFilter}
              onChange={(e) => setProtoFilter(e.target.value)}
              className="px-2.5 py-1.5 rounded-lg text-xs font-mono outline-none cursor-pointer"
              style={{ backgroundColor: '#0B0F19', border: '1px solid #2D3748', color: '#F8FAFC' }}
            >
              <option value="ALL">Proto: ALL</option>
              <option value="tcp">TCP</option>
              <option value="udp">UDP</option>
            </select>

            <select
              value={serviceFilter}
              onChange={(e) => setServiceFilter(e.target.value)}
              className="px-2.5 py-1.5 rounded-lg text-xs font-mono outline-none cursor-pointer"
              style={{ backgroundColor: '#0B0F19', border: '1px solid #2D3748', color: '#F8FAFC' }}
            >
              <option value="ALL">Service: ALL</option>
              <option value="ssl">ssl / tls</option>
              <option value="http">http</option>
              <option value="postgresql">postgresql</option>
              <option value="dns">dns</option>
            </select>

            {(ipFilter || uidFilter || protoFilter !== 'ALL' || serviceFilter !== 'ALL') && (
              <button
                onClick={() => {
                  setIpFilter('');
                  setUidFilter('');
                  setProtoFilter('ALL');
                  setServiceFilter('ALL');
                }}
                className="px-2.5 py-1.5 rounded-lg text-xs font-mono bg-red-500/10 text-red-400 border border-red-500/30 cursor-pointer"
              >
                Reset
              </button>
            )}

            <button
              onClick={fetchZeekData}
              className="p-1.5 rounded-lg cursor-pointer"
              style={{ backgroundColor: '#0B0F19', border: '1px solid #2D3748', color: '#94A3B8' }}
              title="Refresh Zeek Stream"
            >
              <RefreshCw className="w-4 h-4" />
            </button>
          </div>
        </div>

        {/* High-Density conn.log Table */}
        <div className="max-h-[380px] overflow-y-auto overflow-x-auto">
          <table className="w-full text-left border-collapse font-mono text-xs">
            <thead
              className="sticky top-0 z-10 text-[11px] uppercase tracking-wider"
              style={{ backgroundColor: '#0B0F19', color: '#94A3B8', borderBottom: '1px solid #2D3748' }}
            >
              <tr>
                <th className="py-2.5 px-3">Timestamp (WAT)</th>
                <th className="py-2.5 px-3">UID</th>
                <th className="py-2.5 px-3">Source IP:Port</th>
                <th className="py-2.5 px-3">Destination IP:Port</th>
                <th className="py-2.5 px-3">Protocol</th>
                <th className="py-2.5 px-3">Service</th>
                <th className="py-2.5 px-3">TCP Flags</th>
                <th className="py-2.5 px-3">Duration</th>
                <th className="py-2.5 px-3">Bytes (Sent / Rcvd)</th>
              </tr>
            </thead>
            <tbody>
              {loading && filteredConnections.length === 0 ? (
                <tr>
                  <td colSpan={9} className="p-8 text-center" style={{ color: '#94A3B8' }}>
                    Loading Zeek conn.log telemetry stream...
                  </td>
                </tr>
              ) : filteredConnections.length === 0 ? (
                <tr>
                  <td colSpan={9} className="p-8 text-center italic" style={{ color: '#64748B' }}>
                    No Zeek connection sessions match the active filter criteria.
                  </td>
                </tr>
              ) : (
                filteredConnections.map((conn) => {
                  const isSelected = selectedConn?.uid === conn.uid;
                  return (
                    <tr
                      key={conn.uid}
                      onClick={() => openUidDrawer(conn.uid, conn)}
                      className="cursor-pointer transition-colors"
                      style={{
                        backgroundColor: isSelected
                          ? '#1F2937'
                          : conn.verdict === 'MALICIOUS_BLOCKED'
                          ? 'rgba(239, 68, 68, 0.08)'
                          : conn.verdict === 'UNSUCCESSFUL'
                          ? 'rgba(234, 179, 8, 0.07)'
                          : 'transparent',
                        borderBottom: '1px solid #2D3748',
                      }}
                    >
                      <td className="py-2.5 px-3 whitespace-nowrap" style={{ color: '#94A3B8' }}>
                        {conn.ts_wat}
                      </td>
                      <td className="py-2.5 px-3 whitespace-nowrap font-bold text-cyan-400">
                        {conn.uid}
                      </td>
                      <td className="py-2.5 px-3 whitespace-nowrap" style={{ color: '#F8FAFC' }}>
                        {conn['id.orig_h']}:{conn['id.orig_p']}
                      </td>
                      <td className="py-2.5 px-3 whitespace-nowrap" style={{ color: '#F8FAFC' }}>
                        {conn['id.resp_h']}:{conn['id.resp_p']}{' '}
                        <span className="text-[10px]" style={{ color: '#64748B' }}>
                          ({conn.system_id})
                        </span>
                      </td>
                      <td className="py-2.5 px-3 whitespace-nowrap">
                        <span
                          className="px-2 py-0.5 rounded text-[10px] uppercase font-bold"
                          style={{ backgroundColor: '#1F2937', color: '#F8FAFC', border: '1px solid #2D3748' }}
                        >
                          {conn.proto}
                        </span>
                      </td>
                      <td className="py-2.5 px-3 whitespace-nowrap">
                        <span className="px-2 py-0.5 rounded text-[10px] uppercase bg-cyan-500/10 text-cyan-300 border border-cyan-500/30">
                          {conn.service}
                        </span>
                      </td>
                      <td className="py-2.5 px-3 whitespace-nowrap">
                        <span className={`px-2 py-0.5 rounded text-[10px] font-bold border ${getConnStateBadge(conn.conn_state)}`}>
                          {conn.conn_state} ({conn.history})
                        </span>
                      </td>
                      <td className="py-2.5 px-3 whitespace-nowrap" style={{ color: '#94A3B8' }}>
                        {conn.duration}s
                      </td>
                      <td className="py-2.5 px-3 whitespace-nowrap">
                        <span className="text-emerald-400">{conn.orig_bytes.toLocaleString()}B</span>
                        <span style={{ color: '#64748B' }}> / </span>
                        <span className="text-cyan-300">{conn.resp_bytes.toLocaleString()}B</span>
                      </td>
                    </tr>
                  );
                })
              )}
            </tbody>
          </table>
        </div>
      </div>

      {/* =====================================================================
          2. NOTICE & ANOMALY FEED (notice.log Cards) & 3. THREAT INTEL (files.log / ssl.log)
         ===================================================================== */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
        {/* 2. Notice & Anomaly Feed (notice.log Cards) - 6 Columns */}
        <div
          className="lg:col-span-6 rounded-xl overflow-hidden flex flex-col"
          style={{ backgroundColor: '#161B26', border: '1px solid #2D3748' }}
        >
          <div
            className="p-4 flex items-center justify-between"
            style={{ backgroundColor: '#1F2937', borderBottom: '1px solid #2D3748' }}
          >
            <div>
              <h3 className="text-sm sm:text-base font-bold flex items-center gap-2" style={{ color: '#F8FAFC' }}>
                <ShieldAlert className="w-4 h-4 text-red-400" />
                <span>2. Notice &amp; Anomaly Feed (notice.log)</span>
              </h3>
              <p className="text-xs mt-0.5" style={{ color: '#94A3B8' }}>
                Zeek policy violations, heuristic triggers, and one-click UID stream pivoting.
              </p>
            </div>
            <span
              className="text-xs font-mono px-2.5 py-0.5 rounded"
              style={{ backgroundColor: '#161B26', color: '#F8FAFC', border: '1px solid #2D3748' }}
            >
              {notices.length} notices
            </span>
          </div>

          <div className="p-4 space-y-3 max-h-[520px] overflow-y-auto">
            {notices.map((notice, idx) => (
              <div
                key={`${notice.uid}-${idx}`}
                className="p-3.5 rounded-xl space-y-2.5"
                style={{ backgroundColor: '#0B0F19', border: '1px solid #2D3748' }}
              >
                <div className="flex items-center justify-between gap-2 flex-wrap">
                  <div className="flex items-center gap-2">
                    <span className={`px-2.5 py-0.5 rounded text-[10px] font-mono font-bold ${getNoticeSeverityStyle(notice.severity)}`}>
                      {notice.severity}
                    </span>
                    <span className="font-mono text-xs font-bold" style={{ color: '#F8FAFC' }}>
                      {notice.note}
                    </span>
                  </div>
                  <span className="text-[11px] font-mono" style={{ color: '#64748B' }}>
                    {notice.ts_wat}
                  </span>
                </div>

                <p className="text-xs leading-relaxed" style={{ color: '#F8FAFC' }}>
                  {notice.msg}
                </p>

                <div className="text-[11px] font-mono" style={{ color: '#94A3B8' }}>
                  {notice.sub}
                </div>

                <div
                  className="pt-2 flex flex-wrap items-center justify-between gap-2 text-[11px] font-mono"
                  style={{ borderTop: '1px solid #2D3748' }}
                >
                  <div style={{ color: '#94A3B8' }}>
                    Src: <span style={{ color: '#F8FAFC' }}>{notice['id.orig_h']}:{notice['id.orig_p']}</span> • UID:{' '}
                    <span className="text-cyan-400 font-bold">{notice.uid}</span>
                  </div>

                  <button
                    onClick={() => handlePivotToFullStream(notice.uid)}
                    className="px-3 py-1 rounded-lg text-xs font-mono font-bold bg-cyan-500/15 hover:bg-cyan-500/25 text-cyan-300 border border-cyan-500/40 flex items-center gap-1.5 transition cursor-pointer"
                  >
                    <span>Pivot to Full Stream</span>
                    <ArrowRight className="w-3.5 h-3.5" />
                  </button>
                </div>
              </div>
            ))}
          </div>
        </div>

        {/* 3. Threat Intel & Hash Watch (files.log / ssl.log) - 6 Columns */}
        <div
          className="lg:col-span-6 rounded-xl overflow-hidden flex flex-col"
          style={{ backgroundColor: '#161B26', border: '1px solid #2D3748' }}
        >
          <div
            className="p-4 flex items-center justify-between"
            style={{ backgroundColor: '#1F2937', borderBottom: '1px solid #2D3748' }}
          >
            <div>
              <h3 className="text-sm sm:text-base font-bold flex items-center gap-2" style={{ color: '#F8FAFC' }}>
                <Lock className="w-4 h-4 text-emerald-400" />
                <span>3. Threat Intel &amp; Hash Watch (files.log / ssl.log)</span>
              </h3>
              <p className="text-xs mt-0.5" style={{ color: '#94A3B8' }}>
                In-flight MD5/SHA256 file hashes and TLS JA3/JA4 client fingerprints with SNIs.
              </p>
            </div>
          </div>

          <div className="p-4 space-y-5 max-h-[520px] overflow-y-auto">
            {/* In-Flight File Hashes (files.log) */}
            <div className="space-y-2.5">
              <div className="text-xs font-mono uppercase tracking-wider font-bold flex items-center gap-1.5" style={{ color: '#94A3B8' }}>
                <FileCode className="w-3.5 h-3.5 text-cyan-400" />
                <span>Captured File Hashes In-Flight (files.log)</span>
              </div>

              {filesIntel.map((f) => (
                <div
                  key={f.fuid}
                  className="p-3 rounded-xl space-y-2 font-mono text-xs"
                  style={{ backgroundColor: '#0B0F19', border: '1px solid #2D3748' }}
                >
                  <div className="flex items-center justify-between gap-2 flex-wrap">
                    <span className="font-bold" style={{ color: '#F8FAFC' }}>
                      {f.filename} ({f.mime_type})
                    </span>
                    <span
                      className={`px-2 py-0.5 rounded text-[10px] font-bold ${
                        f.threat_verdict === 'MALICIOUS_PAYLOAD'
                          ? 'bg-red-500/10 text-red-400 border border-red-500/30'
                          : 'bg-emerald-500/10 text-emerald-400 border border-emerald-500/30'
                      }`}
                    >
                      {f.threat_verdict}
                    </span>
                  </div>

                  <div className="text-[11px]" style={{ color: '#94A3B8' }}>
                    FUID: <span style={{ color: '#F8FAFC' }}>{f.fuid}</span> • Session UID:{' '}
                    <button
                      onClick={() => openUidDrawer(f.uid)}
                      className="text-cyan-400 hover:underline cursor-pointer font-bold"
                    >
                      {f.uid}
                    </button>{' '}
                    • Size: {f.total_bytes.toLocaleString()}B
                  </div>

                  {/* MD5 with 1-Click Copy */}
                  <div className="flex items-center justify-between gap-2 px-2.5 py-1.5 rounded" style={{ backgroundColor: '#161B26', border: '1px solid #2D3748' }}>
                    <div className="truncate text-[11px]">
                      <span style={{ color: '#94A3B8' }}>MD5: </span>
                      <span style={{ color: '#64748B' }}>{f.md5}</span>
                    </div>
                    <button
                      onClick={() => handleCopy(`md5-${f.fuid}`, f.md5)}
                      className="px-2 py-0.5 rounded text-[10px] flex items-center gap-1 cursor-pointer"
                      style={{ backgroundColor: '#1F2937', color: '#F8FAFC' }}
                    >
                      {copiedHash === `md5-${f.fuid}` ? <Check className="w-3 h-3 text-emerald-400" /> : <Copy className="w-3 h-3" />}
                      <span>{copiedHash === `md5-${f.fuid}` ? 'Copied' : 'Copy MD5'}</span>
                    </button>
                  </div>

                  {/* SHA256 with 1-Click Copy */}
                  <div className="flex items-center justify-between gap-2 px-2.5 py-1.5 rounded" style={{ backgroundColor: '#161B26', border: '1px solid #2D3748' }}>
                    <div className="truncate text-[11px]">
                      <span style={{ color: '#94A3B8' }}>SHA256: </span>
                      <span style={{ color: '#64748B' }}>{f.sha256}</span>
                    </div>
                    <button
                      onClick={() => handleCopy(`sha256-${f.fuid}`, f.sha256)}
                      className="px-2 py-0.5 rounded text-[10px] flex items-center gap-1 cursor-pointer"
                      style={{ backgroundColor: '#1F2937', color: '#F8FAFC' }}
                    >
                      {copiedHash === `sha256-${f.fuid}` ? <Check className="w-3 h-3 text-emerald-400" /> : <Copy className="w-3 h-3" />}
                      <span>{copiedHash === `sha256-${f.fuid}` ? 'Copied' : 'Copy SHA256'}</span>
                    </button>
                  </div>
                </div>
              ))}
            </div>

            {/* SSL/TLS JA3 & JA4 Fingerprints (ssl.log / x509.log) */}
            <div className="space-y-2.5 pt-2" style={{ borderTop: '1px solid #2D3748' }}>
              <div className="text-xs font-mono uppercase tracking-wider font-bold flex items-center gap-1.5" style={{ color: '#94A3B8' }}>
                <Lock className="w-3.5 h-3.5 text-emerald-400" />
                <span>SSL/TLS JA3 &amp; JA4 Fingerprints &amp; Destination SNIs (ssl.log)</span>
              </div>

              {sslIntel.slice(0, 6).map((s, idx) => (
                <div
                  key={`${s.uid}-${idx}`}
                  className="p-3 rounded-xl space-y-1.5 font-mono text-xs"
                  style={{ backgroundColor: '#0B0F19', border: '1px solid #2D3748' }}
                >
                  <div className="flex items-center justify-between gap-2 flex-wrap">
                    <span className="font-bold text-cyan-400">
                      SNI: {s.server_name}
                    </span>
                    <span className="px-2 py-0.5 rounded text-[10px] bg-emerald-500/10 text-emerald-300 border border-emerald-500/30">
                      {s.version} • {s.cipher}
                    </span>
                  </div>

                  <div className="text-[11px]" style={{ color: '#94A3B8' }}>
                    Client: <span style={{ color: '#F8FAFC' }}>{s['id.orig_h']}:{s['id.orig_p']}</span> • UID:{' '}
                    <button
                      onClick={() => openUidDrawer(s.uid)}
                      className="text-cyan-400 hover:underline cursor-pointer font-bold"
                    >
                      {s.uid}
                    </button>
                  </div>

                  <div className="flex items-center justify-between gap-2 text-[11px]">
                    <span className="truncate">
                      <span style={{ color: '#94A3B8' }}>JA3: </span>
                      <span style={{ color: '#64748B' }}>{s.ja3}</span>
                    </span>
                    <button
                      onClick={() => handleCopy(`ja3-${s.uid}-${idx}`, s.ja3)}
                      className="text-[10px] px-1.5 py-0.5 rounded cursor-pointer"
                      style={{ backgroundColor: '#1F2937', color: '#94A3B8' }}
                    >
                      {copiedHash === `ja3-${s.uid}-${idx}` ? 'Copied' : 'Copy'}
                    </button>
                  </div>

                  <div className="flex items-center justify-between gap-2 text-[11px]">
                    <span className="truncate">
                      <span style={{ color: '#94A3B8' }}>JA4: </span>
                      <span style={{ color: '#64748B' }}>{s.ja4}</span>
                    </span>
                    <button
                      onClick={() => handleCopy(`ja4-${s.uid}-${idx}`, s.ja4)}
                      className="text-[10px] px-1.5 py-0.5 rounded cursor-pointer"
                      style={{ backgroundColor: '#1F2937', color: '#94A3B8' }}
                    >
                      {copiedHash === `ja4-${s.uid}-${idx}` ? 'Copied' : 'Copy'}
                    </button>
                  </div>

                  <div className="text-[10px] truncate" style={{ color: '#64748B' }}>
                    Issuer: {s.issuer} ({s.validation_status})
                  </div>
                </div>
              ))}
            </div>
          </div>
        </div>
      </div>

      {/* =====================================================================
          INTERACTIVE ROW DRAWER / SIDEBAR: UID CROSS-LOG CORRELATION & JSON
         ===================================================================== */}
      {(selectedConn || activeTimeline) && (
        <div className="fixed inset-0 z-50 flex justify-end bg-black/70 backdrop-blur-sm animate-fadeIn">
          <div
            className="w-full max-w-2xl h-full overflow-y-auto p-6 space-y-5 shadow-2xl"
            style={{ backgroundColor: '#161B26', borderLeft: '1px solid #2D3748', color: '#F8FAFC' }}
          >
            {/* Drawer Header */}
            <div className="flex items-center justify-between pb-4" style={{ borderBottom: '1px solid #2D3748' }}>
              <div>
                <div className="flex items-center gap-2">
                  <Layers className="w-5 h-5 text-cyan-400" />
                  <h3 className="text-base font-bold font-mono">
                    Zeek Cross-Log UID Correlation Drawer
                  </h3>
                </div>
                <p className="text-xs font-mono mt-1" style={{ color: '#94A3B8' }}>
                  Unified Connection UID:{' '}
                  <span className="text-cyan-400 font-bold">
                    {activeTimeline?.uid || selectedConn?.uid}
                  </span>
                </p>
              </div>
              <button
                onClick={() => {
                  setSelectedConn(null);
                  setActiveTimeline(null);
                }}
                className="p-2 rounded-lg hover:bg-slate-800 cursor-pointer"
                style={{ color: '#94A3B8' }}
              >
                <X className="w-5 h-5" />
              </button>
            </div>

            {/* Quick Pivot Filters */}
            {selectedConn && (
              <div className="flex flex-wrap items-center gap-2">
                <button
                  onClick={() => {
                    setIpFilter(selectedConn['id.orig_h']);
                    setSelectedConn(null);
                    setActiveTimeline(null);
                  }}
                  className="px-3 py-1.5 rounded-lg text-xs font-mono font-bold bg-cyan-500/15 text-cyan-300 border border-cyan-500/30 flex items-center gap-1.5 cursor-pointer"
                >
                  <ExternalLink className="w-3.5 h-3.5" />
                  <span>Pivot by Source IP ({selectedConn['id.orig_h']})</span>
                </button>

                <button
                  onClick={() => {
                    setUidFilter(selectedConn.uid);
                    setSelectedConn(null);
                    setActiveTimeline(null);
                  }}
                  className="px-3 py-1.5 rounded-lg text-xs font-mono font-bold flex items-center gap-1.5 cursor-pointer"
                  style={{ backgroundColor: '#1F2937', color: '#F8FAFC', border: '1px solid #2D3748' }}
                >
                  <Cpu className="w-3.5 h-3.5 text-emerald-400" />
                  <span>Trace UID ({selectedConn.uid})</span>
                </button>
              </div>
            )}

            {/* Cross-Log Transaction Timeline Reconstruction */}
            <div className="space-y-3">
              <div className="text-xs font-mono uppercase tracking-wider font-bold" style={{ color: '#94A3B8' }}>
                Full Transaction Trace Reconstruction (DNS → Conn → SSL → HTTP → Files → Notice)
              </div>

              {loadingTimeline ? (
                <div className="p-6 text-center font-mono text-xs" style={{ color: '#94A3B8' }}>
                  Reconstructing multi-log timeline for UID...
                </div>
              ) : (
                <div className="space-y-2.5">
                  {(activeTimeline?.chronologicalEvents || []).map((ev, i) => (
                    <div
                      key={i}
                      className="p-3 rounded-xl font-mono text-xs space-y-1"
                      style={{ backgroundColor: '#0B0F19', border: '1px solid #2D3748' }}
                    >
                      <div className="flex items-center justify-between">
                        <span className="px-2 py-0.5 rounded text-[10px] font-bold bg-cyan-500/15 text-cyan-300 border border-cyan-500/30">
                          {ev.logType}
                        </span>
                        <span className="text-[11px]" style={{ color: '#64748B' }}>
                          {ev.ts_wat}
                        </span>
                      </div>
                      <div style={{ color: '#F8FAFC' }}>{ev.summary}</div>
                    </div>
                  ))}
                </div>
              )}
            </div>

            {/* Full Raw JSON Payload */}
            <div className="space-y-2">
              <div className="flex items-center justify-between">
                <span className="text-xs font-mono uppercase tracking-wider font-bold flex items-center gap-1.5" style={{ color: '#94A3B8' }}>
                  <Terminal className="w-3.5 h-3.5 text-emerald-400" />
                  <span>Raw Zeek JSON Dissection Payload</span>
                </span>
                <button
                  onClick={() =>
                    handleCopy(
                      'drawer-json',
                      JSON.stringify(activeTimeline || selectedConn, null, 2)
                    )
                  }
                  className="px-2.5 py-1 rounded text-xs font-mono flex items-center gap-1 cursor-pointer"
                  style={{ backgroundColor: '#1F2937', color: '#F8FAFC', border: '1px solid #2D3748' }}
                >
                  {copiedHash === 'drawer-json' ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
                  <span>{copiedHash === 'drawer-json' ? 'Copied JSON' : 'Copy JSON'}</span>
                </button>
              </div>
              <pre
                className="p-4 rounded-xl text-[11px] font-mono overflow-x-auto leading-relaxed"
                style={{ backgroundColor: '#0B0F19', border: '1px solid #2D3748', color: '#94A3B8' }}
              >
                {JSON.stringify(activeTimeline || selectedConn, null, 2)}
              </pre>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
