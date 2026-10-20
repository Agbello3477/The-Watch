import React, { useState } from 'react';
import {
  AlertOctagon,
  CheckCircle,
  Eye,
  ShieldAlert,
  Terminal,
  Filter,
  Check,
  Clock,
  MapPin,
  Flame,
  RefreshCw,
  ShieldCheck,
  Ban,
  CheckCircle2,
  X,
  Crosshair,
  Download,
  FileText,
} from 'lucide-react';
import { ThreatIncident } from '../types/dashboard';
import { api } from '../services/api';

interface IncidentFeedProps {
  incidents: ThreatIncident[];
  onUpdateStatus: (id: string, status: 'ACKNOWLEDGED' | 'RESOLVED') => Promise<void>;
}

export const IncidentFeed: React.FC<IncidentFeedProps> = ({ incidents, onUpdateStatus }) => {
  const [selectedIncident, setSelectedIncident] = useState<ThreatIncident | null>(null);
  const [severityFilter, setSeverityFilter] = useState<string>('ALL');
  const [statusFilter, setStatusFilter] = useState<string>('ALL');
  const [loadingActionId, setLoadingActionId] = useState<string | null>(null);
  const [traceData, setTraceData] = useState<any | null>(null);
  const [isTracingIp, setIsTracingIp] = useState<boolean>(false);
  const [neutralizedAlert, setNeutralizedAlert] = useState<{
    id: string;
    threatName: string;
    ip: string;
    actions: string[];
  } | null>(null);

  const handleTraceIp = async (inc: ThreatIncident) => {
    setSelectedIncident(inc);
    setIsTracingIp(true);
    setTraceData(null);
    try {
      const res = await api.traceIp(inc.offending_ip);
      setTraceData(res);
    } catch (err) {
      console.error('[IncidentFeed] Failed to trace IP:', err);
    } finally {
      setIsTracingIp(false);
    }
  };

  const handleBlockAndResolve = async (e: React.MouseEvent, inc: ThreatIncident) => {
    e.stopPropagation();
    setLoadingActionId(inc.id);
    try {
      await api.blockIp({
        ip: inc.offending_ip,
        reason: `SOC Firewall Block: ${inc.threat_classification} (${inc.target_endpoint})`,
        threatClassification: inc.threat_classification,
        systemId: inc.system_id,
        durationHours: 720,
      });
      await handleAction(e, inc.id, 'RESOLVED');
    } catch (err) {
      console.error('[IncidentFeed] Block IP error:', err);
    } finally {
      setLoadingActionId(null);
    }
  };

  const handleAction = async (e: React.MouseEvent, id: string, status: 'ACKNOWLEDGED' | 'RESOLVED') => {
    e.stopPropagation();
    setLoadingActionId(id);
    try {
      await onUpdateStatus(id, status);
      if (status === 'RESOLVED') {
        const inc = incidents.find((i) => i.id === id);
        const actionsList: string[] = [];
        if (inc?.offending_ip && inc.offending_ip !== '127.0.0.1') {
          actionsList.push(`Quarantined IP ${inc.offending_ip} in Ingest Edge Firewall (HTTP 403 Drop Policy)`);
        }
        if (inc?.threat_classification.includes('Database Query') || inc?.incident_type === 'DATABASE_QUERY_REGRESSION') {
          actionsList.push(`Applied Query Indexing Mitigation Blueprint to database pool`);
        }
        actionsList.push(`SLA Clock Stopped & Logged in West Africa Time (WAT)`);

        setNeutralizedAlert({
          id,
          threatName: inc?.threat_classification || 'Security Incident',
          ip: inc?.offending_ip || 'Origin IP',
          actions: actionsList,
        });

        setTimeout(() => setNeutralizedAlert(null), 9000);
      }
    } catch (err) {
      console.error('[IncidentFeed] Action failed:', err);
    } finally {
      setLoadingActionId(null);
    }
  };

  const filteredIncidents = incidents.filter((inc) => {
    if (severityFilter !== 'ALL' && inc.severity !== severityFilter) return false;
    if (statusFilter !== 'ALL' && inc.status !== statusFilter) return false;
    return true;
  });

  const getSeverityBadge = (severity: string) => {
    switch (severity) {
      case 'CRITICAL':
        return <span className="bg-red-500/20 text-red-400 border border-red-500/40 px-2 py-0.5 rounded text-[10px] font-bold">CRITICAL</span>;
      case 'HIGH':
        return <span className="bg-orange-500/20 text-orange-400 border border-orange-500/40 px-2 py-0.5 rounded text-[10px] font-bold">HIGH</span>;
      case 'MEDIUM':
        return <span className="bg-yellow-500/20 text-yellow-400 border border-yellow-500/40 px-2 py-0.5 rounded text-[10px] font-bold">MEDIUM</span>;
      default:
        return <span className="bg-emerald-500/20 text-emerald-400 border border-emerald-500/40 px-2 py-0.5 rounded text-[10px] font-bold">LOW</span>;
    }
  };

  const getStatusBadge = (status: string) => {
    switch (status) {
      case 'ACKNOWLEDGED':
        return <span className="text-yellow-400 bg-yellow-500/10 border border-yellow-500/30 px-2 py-0.5 rounded text-[10px] font-semibold">ACKNOWLEDGED</span>;
      case 'RESOLVED':
        return <span className="text-emerald-400 bg-emerald-500/10 border border-emerald-500/30 px-2 py-0.5 rounded text-[10px] font-semibold">RESOLVED</span>;
      default:
        return <span className="text-red-400 bg-red-500/10 border border-red-500/30 px-2 py-0.5 rounded text-[10px] font-semibold animate-pulse">UNRESOLVED</span>;
    }
  };

  return (
    <div className="bg-slate-900/80 border border-slate-800 rounded-xl p-5 shadow-sm">
      
      {/* Header & Filters */}
      <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-4 mb-4">
        <div>
          <div className="flex items-center gap-2">
            <ShieldAlert className="w-5 h-5 text-red-400" />
            <h2 className="text-base font-bold text-white tracking-wide">REAL-TIME THREAT & INCIDENT TRIAGE DESK</h2>
          </div>
          <p className="text-xs text-slate-400 mt-0.5">
            Prioritized security incidents, injection attempts, and proactive remediation logs
          </p>
        </div>

        {/* Filter Controls */}
        <div className="flex flex-wrap items-center gap-2">
          {/* Severity Filters */}
          <div className="flex items-center bg-slate-950 border border-slate-800 rounded-lg p-1 text-xs">
            {['ALL', 'CRITICAL', 'HIGH', 'MEDIUM'].map((sev) => (
              <button
                key={sev}
                onClick={() => setSeverityFilter(sev)}
                className={`px-2.5 py-1 rounded font-semibold transition ${
                  severityFilter === sev ? 'bg-slate-800 text-white shadow' : 'text-slate-400 hover:text-slate-200'
                }`}
              >
                {sev}
              </button>
            ))}
          </div>

          {/* Status Filters */}
          <div className="flex items-center bg-slate-950 border border-slate-800 rounded-lg p-1 text-xs">
            {['ALL', 'UNRESOLVED', 'RESOLVED'].map((st) => (
              <button
                key={st}
                onClick={() => setStatusFilter(st)}
                className={`px-2.5 py-1 rounded font-semibold transition ${
                  statusFilter === st ? 'bg-slate-800 text-white shadow' : 'text-slate-400 hover:text-slate-200'
                }`}
              >
                {st}
              </button>
            ))}
          </div>
        </div>
      </div>

      {/* Active Threat Neutralization Banner */}
      {neutralizedAlert && (
        <div className="mb-4 bg-emerald-950/80 border border-emerald-500/60 rounded-xl p-4 shadow-xl shadow-emerald-950/40 animate-in fade-in slide-in-from-top-2">
          <div className="flex items-start justify-between gap-3">
            <div className="flex items-start gap-3">
              <div className="p-2 rounded-lg bg-emerald-500/20 text-emerald-400 mt-0.5 shrink-0 border border-emerald-500/40">
                <ShieldCheck className="w-5 h-5 animate-pulse" />
              </div>
              <div>
                <div className="flex items-center gap-2">
                  <h4 className="text-sm font-bold text-emerald-300 font-mono tracking-wide">
                    THREAT NEUTRALIZED & CONTAINMENT ENFORCED
                  </h4>
                  <span className="text-[10px] font-mono bg-emerald-900/60 text-emerald-300 px-2 py-0.5 rounded border border-emerald-700">
                    SOC DEFENSE ACTIVE
                  </span>
                </div>
                <p className="text-xs text-slate-300 mt-1">
                  Incident <span className="font-mono text-cyan-400 font-bold">{neutralizedAlert.id}</span> ({neutralizedAlert.threatName}) has been completely neutralized.
                </p>
                <div className="mt-2.5 space-y-1 bg-slate-950/60 border border-emerald-900/60 p-2.5 rounded-lg">
                  {neutralizedAlert.actions.map((act, i) => (
                    <div key={i} className="text-xs font-mono text-emerald-300 flex items-center gap-1.5">
                      <CheckCircle2 className="w-3.5 h-3.5 text-emerald-400 shrink-0" />
                      <span>{act}</span>
                    </div>
                  ))}
                </div>
              </div>
            </div>
            <button
              onClick={() => setNeutralizedAlert(null)}
              className="text-slate-400 hover:text-white p-1 rounded-lg hover:bg-slate-800 transition"
            >
              <X className="w-4 h-4" />
            </button>
          </div>
        </div>
      )}

      {/* Incidents Table / List */}
      <div className="overflow-x-auto">
        <table className="w-full text-left border-collapse text-xs block md:table">
          <thead className="hidden md:table-header-group">
            <tr className="border-b border-slate-800 text-slate-400 font-semibold uppercase tracking-wider bg-slate-950/60">
              <th className="py-3 px-3">Severity & Threat</th>
              <th className="py-3 px-3">System</th>
              <th className="py-3 px-3">Target Vector</th>
              <th className="py-3 px-3">Origin Forensics (IP & ASN)</th>
              <th className="py-3 px-3">Time (WAT)</th>
              <th className="py-3 px-3">Status</th>
              <th className="py-3 px-3 text-right">Triage Actions</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-slate-800/60 block md:table-row-group">
            {filteredIncidents.length === 0 ? (
              <tr>
                <td colSpan={7} className="py-8 text-center text-slate-500 font-semibold">
                  ✓ No threat incidents matching active filters.
                </td>
              </tr>
            ) : (
              filteredIncidents.map((inc) => (
                <tr key={inc.id} className="hover:bg-slate-800/40 transition block md:table-row bg-slate-900/40 md:bg-transparent rounded-lg md:rounded-none mb-3 md:mb-0 p-3 md:p-0 border border-slate-800/60 md:border-none">
                  <td className="py-2 md:py-3 px-0 md:px-3 block md:table-cell">
                    <div className="flex items-center gap-2">
                      {getSeverityBadge(inc.severity)}
                      <span className="font-bold text-slate-200">{inc.threat_classification}</span>
                    </div>
                  </td>

                  <td className="py-2 md:py-3 px-0 md:px-3 block md:table-cell">
                    <span className="font-mono text-cyan-400 font-semibold">{inc.system_id}</span>
                  </td>

                  <td className="py-2 md:py-3 px-0 md:px-3 block md:table-cell">
                    <div className="font-mono text-slate-300 max-w-xs truncate">
                      <span className="text-amber-400 font-bold">{inc.http_method}</span> {inc.target_endpoint}
                    </div>
                  </td>

                  <td className="py-2 md:py-3 px-0 md:px-3 block md:table-cell">
                    <div className="text-slate-300 font-mono text-[11px]">
                      <span>{inc.offending_ip}</span>
                      <span className="text-slate-500 text-[10px] block">
                        {inc.geo_city}, {inc.geo_country} ({inc.asn})
                      </span>
                    </div>
                  </td>

                  <td className="py-2 md:py-3 px-0 md:px-3 text-slate-400 font-mono text-[11px] whitespace-nowrap block md:table-cell">
                    {inc.created_at_wat}
                  </td>

                  <td className="py-2 md:py-3 px-0 md:px-3 whitespace-nowrap block md:table-cell">
                    {getStatusBadge(inc.status)}
                  </td>

                  <td className="py-2 md:py-3 px-0 md:px-3 block md:table-cell text-left md:text-right whitespace-nowrap mt-2 md:mt-0 pt-3 md:pt-0 border-t border-slate-800 md:border-none">
                    <div className="flex items-center justify-start md:justify-end gap-1.5 flex-wrap">
                      <button
                        onClick={() => handleTraceIp(inc)}
                        title="Trace Attacker IP Origin & Multi-Hop Route"
                        className="px-2 py-1 rounded bg-cyan-500/20 hover:bg-cyan-500/30 text-cyan-300 border border-cyan-500/40 text-[10px] font-bold transition flex items-center gap-1 cursor-pointer"
                      >
                        <Crosshair className="w-3 h-3" />
                        <span>Trace IP</span>
                      </button>

                      <button
                        onClick={() =>
                          api.downloadPdfReport({
                            systemId: inc.system_id,
                            incidentId: inc.id,
                            incidentData: {
                              id: inc.id,
                              systemId: inc.system_id,
                              incidentType: inc.incident_type,
                              threatClassification: inc.threat_classification,
                              severity: inc.severity,
                              offendingIp: inc.offending_ip,
                              geoCity: inc.geo_city,
                              geoRegion: inc.geo_region,
                              geoCountry: inc.geo_country,
                              geoLat: inc.geo_lat,
                              geoLng: inc.geo_lng,
                              asn: inc.asn,
                              isp: inc.isp,
                              targetEndpoint: inc.target_endpoint,
                              httpMethod: inc.http_method,
                              capturedPayload: inc.captured_payload,
                              status: inc.status,
                              timestampWat: inc.created_at_wat,
                            },
                          })
                        }
                        title="Download Forensic Incident Report (PDF)"
                        className="p-1.5 rounded bg-indigo-500/20 hover:bg-indigo-500/30 text-indigo-300 border border-indigo-500/40 transition cursor-pointer"
                      >
                        <Download className="w-3.5 h-3.5" />
                      </button>

                      <button
                        onClick={() => {
                          setSelectedIncident(inc);
                          setTraceData(null);
                        }}
                        title="View Forensic Details & Mitigation Blueprint"
                        className="p-1.5 rounded bg-slate-800 hover:bg-slate-700 text-slate-300 hover:text-white transition cursor-pointer"
                      >
                        <Eye className="w-3.5 h-3.5" />
                      </button>

                      {inc.status === 'UNRESOLVED' && (
                        <button
                          onClick={(e) => handleAction(e, inc.id, 'ACKNOWLEDGED')}
                          disabled={loadingActionId === inc.id}
                          title="Acknowledge Incident"
                          className="px-2.5 py-1 rounded bg-yellow-500/20 hover:bg-yellow-500/30 text-yellow-400 border border-yellow-500/40 text-[10px] font-bold transition flex items-center gap-1 disabled:opacity-50 cursor-pointer"
                        >
                          {loadingActionId === inc.id ? (
                            <RefreshCw className="w-2.5 h-2.5 animate-spin" />
                          ) : null}
                          <span>Ack</span>
                        </button>
                      )}

                      {inc.status !== 'RESOLVED' ? (
                        <button
                          onClick={(e) => handleBlockAndResolve(e, inc)}
                          disabled={loadingActionId === inc.id}
                          title="Block Attacker IP & Resolve Incident"
                          className="px-2.5 py-1 rounded bg-rose-500/20 hover:bg-rose-500/30 text-rose-300 border border-rose-500/40 text-[10px] font-bold transition flex items-center gap-1 disabled:opacity-50 cursor-pointer"
                        >
                          {loadingActionId === inc.id ? (
                            <>
                              <RefreshCw className="w-2.5 h-2.5 animate-spin" />
                              <span>Blocking...</span>
                            </>
                          ) : (
                            <>
                              <Ban className="w-3 h-3" />
                              <span>Block IP & Resolve</span>
                            </>
                          )}
                        </button>
                      ) : (
                        <span className="px-2 py-0.5 rounded bg-emerald-950 text-emerald-400 border border-emerald-800 text-[10px] font-mono flex items-center gap-1">
                          <Check className="w-3 h-3 text-emerald-400" /> Blocked & Resolved
                        </span>
                      )}
                    </div>
                  </td>
                </tr>
              ))
            )}
          </tbody>
        </table>
      </div>

      {/* Forensics & Mitigation Details Modal */}
      {selectedIncident && (
        <div className="fixed inset-0 bg-black/70 backdrop-blur-sm z-50 flex items-center justify-center p-4">
          <div className="bg-slate-900 border border-slate-700 rounded-2xl max-w-2xl w-full max-h-[90vh] overflow-y-auto p-6 shadow-2xl animate-in fade-in zoom-in-95">
            
            <div className="flex items-start justify-between pb-4 border-b border-slate-800">
              <div>
                <div className="flex items-center gap-2">
                  {getSeverityBadge(selectedIncident.severity)}
                  <h3 className="text-base font-bold text-white">{selectedIncident.threat_classification}</h3>
                </div>
                <p className="text-xs text-slate-400 mt-1">
                  Incident ID: <span className="font-mono text-cyan-400">{selectedIncident.id}</span> | Time: {selectedIncident.created_at_wat}
                </p>
              </div>

              <button
                onClick={() => setSelectedIncident(null)}
                className="w-8 h-8 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-400 hover:text-white flex items-center justify-center"
              >
                ✕
              </button>
            </div>

            <div className="mt-4 space-y-4 text-xs">
              
              {/* Target & Origin Box */}
              <div className="grid grid-cols-2 gap-3 bg-slate-950 p-3 rounded-lg border border-slate-800">
                <div>
                  <span className="text-slate-400 block font-semibold">Target Vector:</span>
                  <span className="font-mono text-amber-400 mt-0.5 block">{selectedIncident.http_method} {selectedIncident.target_endpoint}</span>
                </div>
                <div>
                  <span className="text-slate-400 block font-semibold">Origin Forensics:</span>
                  <span className="font-mono text-slate-200 mt-0.5 block">
                    {selectedIncident.offending_ip} ({selectedIncident.geo_city}, {selectedIncident.geo_country})
                  </span>
                  <span className="text-cyan-400 text-[11px] block">{selectedIncident.asn} - {selectedIncident.isp}</span>
                </div>
              </div>

              {/* Captured Payload */}
              <div>
                <span className="text-slate-300 font-semibold block mb-1">Captured Malicious Payload / Error:</span>
                <div className="bg-slate-950 p-3 rounded-lg border border-slate-800 font-mono text-red-400 text-[11px] break-all">
                  {selectedIncident.captured_payload || 'N/A'}
                </div>
              </div>

              {/* Automated Mitigation Blueprint */}
              <div>
                <span className="text-cyan-400 font-semibold block mb-1">Automated Mitigation Blueprint (WAF & Firewall Rules):</span>
                <pre className="bg-slate-950 p-3 rounded-lg border border-cyan-900/60 font-mono text-slate-200 text-[11px] whitespace-pre-wrap overflow-x-auto">
                  {selectedIncident.mitigation_blueprint}
                </pre>
              </div>

              {/* Multi-Hop IP Trace Results */}
              {isTracingIp && (
                <div className="bg-slate-950 p-4 rounded-xl border border-cyan-800/60 text-cyan-300 font-mono text-xs flex items-center gap-2">
                  <RefreshCw className="w-4 h-4 animate-spin" />
                  <span>Tracing multi-hop network path and Whois registry for {selectedIncident.offending_ip}...</span>
                </div>
              )}

              {traceData && (
                <div className="bg-slate-950 p-4 rounded-xl border border-cyan-500/50 space-y-3 font-mono">
                  <div className="flex items-center justify-between border-b border-slate-800 pb-2">
                    <span className="text-cyan-400 font-bold flex items-center gap-1.5">
                      <Crosshair className="w-4 h-4" />
                      <span>LIVE IP ROUTE TRACE: {traceData.ip}</span>
                    </span>
                    <span className="px-2 py-0.5 rounded bg-rose-950 text-rose-300 border border-rose-800 text-[10px] font-bold">
                      Threat Risk Score: {traceData.profile?.threatRiskScore || 85}/100
                    </span>
                  </div>

                  <div className="grid grid-cols-1 sm:grid-cols-3 gap-2 text-[11px]">
                    <div>
                      <span className="text-slate-500 block text-[10px]">REVERSE DNS</span>
                      <span className="text-slate-200 font-bold break-all">{traceData.profile?.reverseDns}</span>
                    </div>
                    <div>
                      <span className="text-slate-500 block text-[10px]">CIDR / REGISTRY</span>
                      <span className="text-cyan-300 font-bold">{traceData.whois?.cidr}</span>
                      <span className="text-slate-400 block text-[10px] truncate">{traceData.whois?.registry}</span>
                    </div>
                    <div>
                      <span className="text-slate-500 block text-[10px]">ABUSE CONTACT</span>
                      <span className="text-amber-300 font-bold">{traceData.whois?.abuseContact}</span>
                    </div>
                  </div>

                  <div className="overflow-x-auto">
                    <table className="w-full text-left text-[11px]">
                      <thead className="text-slate-400 border-b border-slate-800">
                        <tr>
                          <th className="py-1 pr-2">Hop</th>
                          <th className="py-1 pr-2">Router IP</th>
                          <th className="py-1 pr-2">Hostname</th>
                          <th className="py-1 pr-2">Location</th>
                          <th className="py-1 text-right">Latency</th>
                        </tr>
                      </thead>
                      <tbody className="divide-y divide-slate-800/60">
                        {(traceData.hops || []).map((h: any) => (
                          <tr key={h.hop} className="text-slate-300">
                            <td className="py-1 pr-2">#{h.hop}</td>
                            <td className="py-1 pr-2 text-amber-300">{h.ip}</td>
                            <td className="py-1 pr-2 truncate max-w-[150px]">{h.hostname}</td>
                            <td className="py-1 pr-2">{h.location}</td>
                            <td className="py-1 text-right text-cyan-400">{h.rttMs} ms</td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                </div>
              )}

            </div>

            {/* Modal Footer */}
            <div className="mt-6 pt-4 border-t border-slate-800 flex flex-wrap justify-between gap-2">
              <div className="flex items-center gap-2">
                <button
                  onClick={() => handleTraceIp(selectedIncident)}
                  className="px-3 py-2 bg-cyan-600 hover:bg-cyan-500 text-slate-950 rounded-lg font-bold text-xs transition flex items-center gap-1.5 cursor-pointer"
                >
                  <Crosshair className="w-3.5 h-3.5" />
                  <span>Trace IP Origin</span>
                </button>
                <button
                  onClick={() =>
                    api.downloadPdfReport({
                      systemId: selectedIncident.system_id,
                      incidentId: selectedIncident.id,
                      incidentData: {
                        id: selectedIncident.id,
                        systemId: selectedIncident.system_id,
                        incidentType: selectedIncident.incident_type,
                        threatClassification: selectedIncident.threat_classification,
                        severity: selectedIncident.severity,
                        offendingIp: selectedIncident.offending_ip,
                        geoCity: selectedIncident.geo_city,
                        geoRegion: selectedIncident.geo_region,
                        geoCountry: selectedIncident.geo_country,
                        geoLat: selectedIncident.geo_lat,
                        geoLng: selectedIncident.geo_lng,
                        asn: selectedIncident.asn,
                        isp: selectedIncident.isp,
                        targetEndpoint: selectedIncident.target_endpoint,
                        httpMethod: selectedIncident.http_method,
                        capturedPayload: selectedIncident.captured_payload,
                        status: selectedIncident.status,
                        timestampWat: selectedIncident.created_at_wat,
                      },
                    })
                  }
                  className="px-3 py-2 bg-indigo-600 hover:bg-indigo-500 text-white rounded-lg font-bold text-xs transition flex items-center gap-1.5 cursor-pointer"
                >
                  <FileText className="w-3.5 h-3.5" />
                  <span>Download Forensic PDF</span>
                </button>
              </div>

              <div className="flex items-center gap-2">
                {selectedIncident.status !== 'RESOLVED' && (
                  <button
                    disabled={loadingActionId === selectedIncident.id}
                    onClick={async (e) => {
                      await handleBlockAndResolve(e, selectedIncident);
                      setSelectedIncident(null);
                    }}
                    className="px-4 py-2 bg-rose-600 hover:bg-rose-500 text-white rounded-lg font-bold text-xs transition flex items-center gap-1.5 disabled:opacity-50 cursor-pointer"
                  >
                    <Ban className="w-3.5 h-3.5" />
                    <span>Block IP & Resolve</span>
                  </button>
                )}
                <button
                  onClick={() => setSelectedIncident(null)}
                  className="px-4 py-2 bg-slate-800 hover:bg-slate-700 text-slate-300 rounded-lg font-semibold text-xs transition cursor-pointer"
                >
                  Close
                </button>
              </div>
            </div>

          </div>
        </div>
      )}

    </div>
  );
};
