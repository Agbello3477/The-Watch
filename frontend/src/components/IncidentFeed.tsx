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
} from 'lucide-react';
import { ThreatIncident } from '../types/dashboard';

interface IncidentFeedProps {
  incidents: ThreatIncident[];
  onUpdateStatus: (id: string, status: 'ACKNOWLEDGED' | 'RESOLVED') => Promise<void>;
}

export const IncidentFeed: React.FC<IncidentFeedProps> = ({ incidents, onUpdateStatus }) => {
  const [selectedIncident, setSelectedIncident] = useState<ThreatIncident | null>(null);
  const [severityFilter, setSeverityFilter] = useState<string>('ALL');
  const [statusFilter, setStatusFilter] = useState<string>('ALL');

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

      {/* Incidents Table / List */}
      <div className="overflow-x-auto">
        <table className="w-full text-left border-collapse text-xs">
          <thead>
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
          <tbody className="divide-y divide-slate-800/60">
            {filteredIncidents.length === 0 ? (
              <tr>
                <td colSpan={7} className="py-8 text-center text-slate-500 font-semibold">
                  ✓ No threat incidents matching active filters.
                </td>
              </tr>
            ) : (
              filteredIncidents.map((inc) => (
                <tr key={inc.id} className="hover:bg-slate-800/40 transition">
                  <td className="py-3 px-3">
                    <div className="flex items-center gap-2">
                      {getSeverityBadge(inc.severity)}
                      <span className="font-bold text-slate-200">{inc.threat_classification}</span>
                    </div>
                  </td>

                  <td className="py-3 px-3">
                    <span className="font-mono text-cyan-400 font-semibold">{inc.system_id}</span>
                  </td>

                  <td className="py-3 px-3">
                    <div className="font-mono text-slate-300 max-w-xs truncate">
                      <span className="text-amber-400 font-bold">{inc.http_method}</span> {inc.target_endpoint}
                    </div>
                  </td>

                  <td className="py-3 px-3">
                    <div className="text-slate-300 font-mono text-[11px]">
                      <span>{inc.offending_ip}</span>
                      <span className="text-slate-500 text-[10px] block">
                        {inc.geo_city}, {inc.geo_country} ({inc.asn})
                      </span>
                    </div>
                  </td>

                  <td className="py-3 px-3 text-slate-400 font-mono text-[11px] whitespace-nowrap">
                    {inc.created_at_wat}
                  </td>

                  <td className="py-3 px-3 whitespace-nowrap">
                    {getStatusBadge(inc.status)}
                  </td>

                  <td className="py-3 px-3 text-right whitespace-nowrap">
                    <div className="flex items-center justify-end gap-1.5">
                      <button
                        onClick={() => setSelectedIncident(inc)}
                        title="View Forensic Details & Mitigation Blueprint"
                        className="p-1.5 rounded bg-slate-800 hover:bg-slate-700 text-slate-300 hover:text-white transition"
                      >
                        <Eye className="w-3.5 h-3.5" />
                      </button>

                      {inc.status === 'UNRESOLVED' && (
                        <button
                          onClick={() => onUpdateStatus(inc.id, 'ACKNOWLEDGED')}
                          title="Acknowledge Incident"
                          className="px-2 py-1 rounded bg-yellow-500/20 hover:bg-yellow-500/30 text-yellow-400 border border-yellow-500/40 text-[10px] font-bold transition"
                        >
                          Ack
                        </button>
                      )}

                      {inc.status !== 'RESOLVED' && (
                        <button
                          onClick={() => onUpdateStatus(inc.id, 'RESOLVED')}
                          title="Resolve Incident"
                          className="px-2 py-1 rounded bg-emerald-500/20 hover:bg-emerald-500/30 text-emerald-400 border border-emerald-500/40 text-[10px] font-bold transition"
                        >
                          Resolve
                        </button>
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

            </div>

            {/* Modal Footer */}
            <div className="mt-6 pt-4 border-t border-slate-800 flex justify-end gap-2">
              {selectedIncident.status !== 'RESOLVED' && (
                <button
                  onClick={async () => {
                    await onUpdateStatus(selectedIncident.id, 'RESOLVED');
                    setSelectedIncident(null);
                  }}
                  className="px-4 py-2 bg-emerald-600 hover:bg-emerald-500 text-white rounded-lg font-bold text-xs transition"
                >
                  Mark as Resolved
                </button>
              )}
              <button
                onClick={() => setSelectedIncident(null)}
                className="px-4 py-2 bg-slate-800 hover:bg-slate-700 text-slate-300 rounded-lg font-semibold text-xs transition"
              >
                Close
              </button>
            </div>

          </div>
        </div>
      )}

    </div>
  );
};
