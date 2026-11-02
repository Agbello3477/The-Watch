import React, { useState } from 'react';
import {
  Radar,
  ShieldCheck,
  ShieldAlert,
  AlertTriangle,
  Lock,
  Unlock,
  Server,
  Globe,
  Wrench,
  Copy,
  Check,
  Search,
  Download,
  Terminal,
  CheckCircle2,
  XCircle,
} from 'lucide-react';
import { triggerBrowserBlobDownload } from '../utils/pdfExporter';

const rawApiUrl = (import.meta as any).env?.VITE_API_URL || '';
const API_BASE = rawApiUrl ? `${rawApiUrl.replace(/\/$/, '')}/api/v1` : '/api/v1';

interface PortScanResult {
  port: number;
  protocol: 'TCP';
  service: string;
  state: 'OPEN' | 'CLOSED';
  bannerOrVersion: string;
  recommendation: 'LEAVE_OPEN' | 'RESTRICT_ACCESS' | 'CLOSE_IMMEDIATELY';
  riskLevel: 'SAFE' | 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
  whyRecommendation: string;
  firewallActionCommand: string;
}

interface VulnerabilityFinding {
  id: string;
  cveOrCwe: string;
  title: string;
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';
  cvssScore: number;
  category: string;
  affectedComponent: string;
  description: string;
  howToPatch: string;
  patchSnippet: string;
}

interface ScanReport {
  targetInput: string;
  cleanHost: string;
  resolvedIp: string;
  targetUrl: string;
  scannedAtWat: string;
  scanDurationMs: number;
  geo: {
    country: string;
    region: string;
    city: string;
    isp: string;
    asn: string;
    isProxyOrVpn: boolean;
  };
  httpProbe: {
    reachable: boolean;
    statusCode: number;
    tlsEnabled: boolean;
    serverBanner: string;
    headersCaptured: Record<string, string>;
  };
  summary: {
    securityScore: number;
    securityGrade: string;
    totalPortsScanned: number;
    openPortsCount: number;
    portsRecommendedToCloseCount: number;
    portsSafeToLeaveOpenCount: number;
    totalVulnerabilities: number;
    criticalCount: number;
    highCount: number;
    mediumCount: number;
    lowCount: number;
  };
  ports: PortScanResult[];
  vulnerabilities: VulnerabilityFinding[];
}

export const SurfaceScanner: React.FC = () => {
  const [targetInput, setTargetInput] = useState<string>('https://noun-hrms.onrender.com');
  const [isScanning, setIsScanning] = useState<boolean>(false);
  const [report, setReport] = useState<ScanReport | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [portFilter, setPortFilter] = useState<'ALL' | 'OPEN' | 'CLOSE_OR_RESTRICT' | 'LEAVE_OPEN'>('ALL');
  const [copiedId, setCopiedId] = useState<string | null>(null);

  const runInspection = async (customTarget?: string) => {
    const targetToScan = (customTarget ?? targetInput).trim();
    if (!targetToScan) {
      setError('Please enter a valid system/server IP address or URL.');
      return;
    }
    if (customTarget) setTargetInput(customTarget);

    setIsScanning(true);
    setError(null);

    try {
      const res = await fetch(`${API_BASE}/scanner/inspect`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ target: targetToScan }),
      });

      const data = await res.json();
      if (!res.ok) {
        throw new Error(data.error || 'Failed to inspect target server');
      }

      setReport(data);
    } catch (err: any) {
      setError(err.message || 'Could not complete surface & vulnerability scan');
    } finally {
      setIsScanning(false);
    }
  };

  const handleCopy = (id: string, text: string) => {
    navigator.clipboard.writeText(text);
    setCopiedId(id);
    setTimeout(() => setCopiedId(null), 2500);
  };

  const handleExportReport = () => {
    if (!report) return;
    const lines: string[] = [
      'THE WATCH SOC — SERVER PORT & VULNERABILITY AUDIT REPORT',
      `Target Input,${report.targetInput}`,
      `Resolved IP,${report.resolvedIp}`,
      `Location,"${report.geo.city}, ${report.geo.country} (${report.geo.isp})"`,
      `Security Score,${report.summary.securityScore}/100 (Grade ${report.summary.securityGrade})`,
      `Scanned At (WAT),"${report.scannedAtWat}"`,
      '',
      '--- PORT DISCOVERY & HARDENING RECOMMENDATIONS ---',
      'Port,Protocol,Service,Current_State,Recommendation,Risk_Level,Explanation,Firewall_Command',
      ...report.ports.map((p) =>
        [
          p.port,
          p.protocol,
          `"${p.service}"`,
          p.state,
          p.recommendation,
          p.riskLevel,
          `"${p.whyRecommendation.replace(/"/g, '""')}"`,
          `"${p.firewallActionCommand.replace(/"/g, '""')}"`,
        ].join(',')
      ),
      '',
      '--- DETECTED VULNERABILITIES & PATCH REMEDIATION ---',
      'ID,CWE,Severity,CVSS,Title,Affected_Component,How_To_Patch',
      ...report.vulnerabilities.map((v) =>
        [
          v.id,
          `"${v.cveOrCwe}"`,
          v.severity,
          v.cvssScore,
          `"${v.title.replace(/"/g, '""')}"`,
          `"${v.affectedComponent.replace(/"/g, '""')}"`,
          `"${v.howToPatch.replace(/"/g, '""')}"`,
        ].join(',')
      ),
      '',
      '"Powered by: MaSha Tech Innovations"',
    ];

    const blob = new Blob([lines.join('\n')], { type: 'text/csv;charset=utf-8;' });
    triggerBrowserBlobDownload(blob, `TheWatch_Port_And_Vulnerability_Audit_${report.cleanHost}_${Date.now()}.csv`);
  };

  const filteredPorts = (report?.ports || []).filter((p) => {
    if (portFilter === 'OPEN') return p.state === 'OPEN';
    if (portFilter === 'CLOSE_OR_RESTRICT') return p.recommendation !== 'LEAVE_OPEN';
    if (portFilter === 'LEAVE_OPEN') return p.recommendation === 'LEAVE_OPEN';
    return true;
  });

  const getSeverityBadge = (sev: string) => {
    switch (sev) {
      case 'CRITICAL':
        return 'bg-rose-600 text-white border-rose-400';
      case 'HIGH':
        return 'bg-orange-600 text-white border-orange-400';
      case 'MEDIUM':
        return 'bg-amber-400 text-slate-950 border-amber-300';
      default:
        return 'bg-cyan-500/20 text-cyan-300 border-cyan-500/40';
    }
  };

  return (
    <div className="space-y-6 text-sm">
      {/* Scanner Input Card */}
      <div className="bg-slate-900/95 border border-cyan-500/30 rounded-2xl p-5 shadow-2xl">
        <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 mb-4">
          <div className="flex items-center gap-3">
            <div className="w-11 h-11 rounded-xl bg-cyan-950 border border-cyan-500/40 flex items-center justify-center shrink-0">
              <Radar className={`w-6 h-6 text-cyan-400 ${isScanning ? 'animate-spin' : ''}`} />
            </div>
            <div>
              <h2 className="text-lg font-bold text-slate-100">
                Server IP / URL Open Port &amp; Vulnerability Auditor
              </h2>
              <p className="text-xs text-slate-400">
                Enter any server IP address or URL to inspect open ports, which ports to close vs. leave open, detected vulnerabilities, and exact patch instructions.
              </p>
            </div>
          </div>

          {report && (
            <button
              onClick={handleExportReport}
              className="px-3.5 py-2 rounded-xl bg-cyan-950 hover:bg-cyan-900 text-cyan-300 border border-cyan-500/40 text-xs font-mono font-bold flex items-center gap-2 self-start md:self-auto transition cursor-pointer"
            >
              <Download className="w-4 h-4" />
              <span>Export Audit CSV</span>
            </button>
          )}
        </div>

        {/* Input Form */}
        <form
          onSubmit={(e) => {
            e.preventDefault();
            runInspection();
          }}
          className="flex flex-col sm:flex-row gap-3"
        >
          <div className="relative flex-1">
            <Globe className="w-4 h-4 text-cyan-400 absolute left-3.5 top-1/2 -translate-y-1/2" />
            <input
              type="text"
              value={targetInput}
              onChange={(e) => setTargetInput(e.target.value)}
              placeholder="Enter Server IP or URL (e.g., https://noun-hrms.onrender.com, 154.68.225.146, noun.edu.ng)"
              className="w-full pl-10 pr-4 py-3 bg-slate-950 border border-slate-700 focus:border-cyan-400 rounded-xl font-mono text-xs sm:text-sm text-slate-100 placeholder-slate-500 outline-none"
            />
          </div>
          <button
            type="submit"
            disabled={isScanning}
            className="px-6 py-3 rounded-xl bg-gradient-to-r from-cyan-500 to-blue-600 hover:from-cyan-400 hover:to-blue-500 text-slate-950 font-black text-xs sm:text-sm uppercase tracking-wider flex items-center justify-center gap-2 shadow-lg shadow-cyan-950/60 transition cursor-pointer disabled:opacity-60"
          >
            <Search className="w-4 h-4" />
            <span>{isScanning ? 'Scanning Ports & Vulnerabilities...' : 'Scan Target Server'}</span>
          </button>
        </form>

        {/* Quick Target Presets */}
        <div className="mt-3 flex flex-wrap items-center gap-2 text-xs">
          <span className="text-slate-400 font-mono text-[11px]">Quick Targets:</span>
          {[
            { label: 'NOUN HRMS (https://noun-hrms.onrender.com)', val: 'https://noun-hrms.onrender.com' },
            { label: 'The Watch SOC (https://the-watch-ow2w.onrender.com)', val: 'https://the-watch-ow2w.onrender.com' },
            { label: 'NOUN Portal (noun.edu.ng)', val: 'https://noun.edu.ng' },
            { label: 'Local Server (127.0.0.1)', val: '127.0.0.1' },
          ].map((preset) => (
            <button
              key={preset.val}
              type="button"
              onClick={() => runInspection(preset.val)}
              className="px-2.5 py-1 rounded-lg bg-slate-950 hover:bg-slate-800 text-cyan-300 border border-slate-800 hover:border-cyan-500/40 font-mono text-[11px] transition cursor-pointer"
            >
              {preset.label}
            </button>
          ))}
        </div>
      </div>

      {error && (
        <div className="bg-rose-950/60 border border-rose-500/50 text-rose-200 p-4 rounded-xl text-xs font-mono">
          {error}
        </div>
      )}

      {!report && !isScanning && (
        <div className="bg-slate-900/60 border border-slate-800 rounded-2xl p-10 text-center space-y-3">
          <Server className="w-10 h-10 text-cyan-400 mx-auto opacity-80" />
          <div className="text-base font-bold text-slate-200">
            Ready to Audit Any Server IP or URL
          </div>
          <p className="text-xs text-slate-400 max-w-xl mx-auto">
            Click <strong>"Scan Target Server"</strong> above or choose one of the Quick Targets to inspect open TCP ports, port closure/retention recommendations, live HTTP/TLS vulnerabilities, and ready-to-apply security patches.
          </p>
        </div>
      )}

      {report && (
        <>
          {/* Executive Summary KPI Cards */}
          <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
            {/* Score & Grade */}
            <div className="bg-slate-900 border border-slate-800 rounded-xl p-4">
              <div className="text-[11px] font-mono uppercase text-slate-400">
                Security Posture Rating
              </div>
              <div className="flex items-baseline gap-3 mt-1.5">
                <span
                  className={`text-3xl font-black font-mono ${
                    report.summary.securityScore >= 80
                      ? 'text-emerald-400'
                      : report.summary.securityScore >= 60
                      ? 'text-amber-400'
                      : 'text-rose-400'
                  }`}
                >
                  {report.summary.securityScore}/100
                </span>
                <span className="px-2.5 py-0.5 rounded-md text-xs font-black font-mono bg-slate-800 text-cyan-300 border border-cyan-500/30">
                  GRADE {report.summary.securityGrade}
                </span>
              </div>
              <div className="text-[11px] text-slate-400 mt-1.5 font-mono">
                Scan Time: {report.scanDurationMs}ms | {report.scannedAtWat}
              </div>
            </div>

            {/* Resolved Host & GeoIP */}
            <div className="bg-slate-900 border border-slate-800 rounded-xl p-4">
              <div className="text-[11px] font-mono uppercase text-slate-400">
                Resolved Target &amp; Network
              </div>
              <div className="text-base font-bold text-slate-100 mt-1 font-mono truncate" title={report.cleanHost}>
                {report.cleanHost} ({report.resolvedIp})
              </div>
              <div className="text-[11px] text-cyan-300 mt-1 font-mono truncate">
                {report.geo.city}, {report.geo.country} • {report.geo.isp}
              </div>
              <div className="text-[11px] text-slate-400 mt-0.5 font-mono">
                Banner: {report.httpProbe.serverBanner}
              </div>
            </div>

            {/* Open Ports Breakdown */}
            <div className="bg-slate-900 border border-slate-800 rounded-xl p-4">
              <div className="text-[11px] font-mono uppercase text-slate-400">
                Open Ports Analysis ({report.summary.totalPortsScanned} Probed)
              </div>
              <div className="text-2xl font-black text-slate-100 mt-1 font-mono">
                {report.summary.openPortsCount} Open Ports
              </div>
              <div className="flex items-center gap-3 mt-1.5 text-[11px] font-mono">
                <span className="text-emerald-400 font-bold">
                  ✓ {report.summary.portsSafeToLeaveOpenCount} Leave Open
                </span>
                <span className="text-rose-400 font-bold">
                  ⚠ {report.summary.portsRecommendedToCloseCount} Close/Restrict
                </span>
              </div>
            </div>

            {/* Vulnerabilities Found */}
            <div className="bg-slate-900 border border-slate-800 rounded-xl p-4">
              <div className="text-[11px] font-mono uppercase text-slate-400">
                Vulnerabilities Detected
              </div>
              <div className="text-2xl font-black text-amber-300 mt-1 font-mono">
                {report.summary.totalVulnerabilities} Findings
              </div>
              <div className="flex items-center gap-2 mt-1.5 text-[11px] font-mono flex-wrap">
                <span className="text-rose-400 font-bold">Crit: {report.summary.criticalCount}</span>
                <span className="text-orange-400 font-bold">High: {report.summary.highCount}</span>
                <span className="text-amber-300 font-bold">Med: {report.summary.mediumCount}</span>
                <span className="text-cyan-300 font-bold">Low: {report.summary.lowCount}</span>
              </div>
            </div>
          </div>

          {/* SECTION 1: OPEN PORTS & RECOMMENDATIONS (WHICH TO CLOSE VS. LEAVE OPEN) */}
          <div className="bg-slate-900 border border-slate-800 rounded-2xl overflow-hidden">
            <div className="p-4 bg-slate-950 border-b border-slate-800 flex flex-col sm:flex-row sm:items-center justify-between gap-3">
              <div>
                <h3 className="text-base font-bold text-slate-100 flex items-center gap-2">
                  <Server className="w-4 h-4 text-cyan-400" />
                  <span>1. Port Discovery &amp; Recommendations (Which to Leave Open vs. Close)</span>
                </h3>
                <p className="text-xs text-slate-400 mt-0.5">
                  Green rows indicate ports safe to leave open; Red/Amber rows indicate ports that should be closed or restricted behind a firewall.
                </p>
              </div>

              <div className="flex flex-wrap items-center gap-1.5">
                {[
                  { id: 'ALL', label: `All Scanned (${report.ports.length})` },
                  { id: 'OPEN', label: `Open Ports (${report.summary.openPortsCount})` },
                  { id: 'LEAVE_OPEN', label: 'Recommended: Leave Open' },
                  { id: 'CLOSE_OR_RESTRICT', label: 'Recommended: Close / Restrict' },
                ].map((tab) => (
                  <button
                    key={tab.id}
                    onClick={() => setPortFilter(tab.id as any)}
                    className={`px-2.5 py-1 rounded-lg text-xs font-mono transition cursor-pointer border ${
                      portFilter === tab.id
                        ? 'bg-cyan-600 text-slate-950 font-bold border-cyan-400'
                        : 'bg-slate-900 text-slate-400 border-slate-800 hover:text-slate-200'
                    }`}
                  >
                    {tab.label}
                  </button>
                ))}
              </div>
            </div>

            <div className="overflow-x-auto">
              <table className="w-full text-left border-collapse font-mono text-xs">
                <thead className="bg-slate-950/90 text-slate-400 text-[11px] uppercase border-b border-slate-800">
                  <tr>
                    <th className="py-3 px-4">Port / Proto</th>
                    <th className="py-3 px-4">Service &amp; Banner</th>
                    <th className="py-3 px-4">Current State</th>
                    <th className="py-3 px-4">SOC Recommendation</th>
                    <th className="py-3 px-4">Why &amp; Security Guidance</th>
                    <th className="py-3 px-4">Firewall Command</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-800/70">
                  {filteredPorts.map((p) => {
                    const isOpenAndRisky = p.state === 'OPEN' && p.recommendation !== 'LEAVE_OPEN';
                    const isOpenAndSafe = p.state === 'OPEN' && p.recommendation === 'LEAVE_OPEN';
                    return (
                      <tr
                        key={p.port}
                        className={
                          isOpenAndRisky
                            ? 'bg-rose-950/45 border-l-4 border-l-rose-500'
                            : isOpenAndSafe
                            ? 'bg-emerald-950/40 border-l-4 border-l-emerald-500'
                            : 'bg-slate-900/40 hover:bg-slate-800/40'
                        }
                      >
                        <td className="py-3 px-4 font-bold text-slate-100 whitespace-nowrap">
                          Port {p.port} / {p.protocol}
                        </td>
                        <td className="py-3 px-4">
                          <div className="font-bold text-slate-200">{p.service}</div>
                          <div className="text-[11px] text-slate-400">{p.bannerOrVersion}</div>
                        </td>
                        <td className="py-3 px-4 whitespace-nowrap">
                          {p.state === 'OPEN' ? (
                            <span className="inline-flex items-center gap-1 px-2.5 py-1 rounded-md bg-emerald-500/20 text-emerald-300 border border-emerald-500/40 font-bold text-[11px]">
                              <Unlock className="w-3.5 h-3.5" /> OPEN
                            </span>
                          ) : (
                            <span className="inline-flex items-center gap-1 px-2.5 py-1 rounded-md bg-slate-800 text-slate-400 border border-slate-700 text-[11px]">
                              <Lock className="w-3.5 h-3.5" /> CLOSED
                            </span>
                          )}
                        </td>
                        <td className="py-3 px-4 whitespace-nowrap">
                          {p.recommendation === 'LEAVE_OPEN' ? (
                            <span className="inline-flex items-center gap-1 px-2.5 py-1 rounded-md bg-emerald-500 text-slate-950 font-black text-[11px]">
                              <CheckCircle2 className="w-3.5 h-3.5" /> LEAVE OPEN
                            </span>
                          ) : p.recommendation === 'RESTRICT_ACCESS' ? (
                            <span className="inline-flex items-center gap-1 px-2.5 py-1 rounded-md bg-amber-400 text-slate-950 font-black text-[11px]">
                              <AlertTriangle className="w-3.5 h-3.5" /> RESTRICT ACCESS
                            </span>
                          ) : (
                            <span className="inline-flex items-center gap-1 px-2.5 py-1 rounded-md bg-rose-600 text-white font-black text-[11px]">
                              <XCircle className="w-3.5 h-3.5" /> CLOSE PORT
                            </span>
                          )}
                        </td>
                        <td className="py-3 px-4 text-slate-300 max-w-md font-sans text-xs leading-relaxed">
                          {p.whyRecommendation}
                        </td>
                        <td className="py-3 px-4 whitespace-nowrap">
                          <div className="flex items-center gap-2 bg-slate-950 border border-slate-800 px-2.5 py-1.5 rounded-lg">
                            <code className="text-[11px] text-cyan-300">{p.firewallActionCommand}</code>
                            <button
                              onClick={() => handleCopy(`port-${p.port}`, p.firewallActionCommand)}
                              className="p-1 hover:bg-slate-800 rounded text-slate-400 hover:text-slate-100 transition cursor-pointer"
                              title="Copy Firewall Rule"
                            >
                              {copiedId === `port-${p.port}` ? (
                                <Check className="w-3.5 h-3.5 text-emerald-400" />
                              ) : (
                                <Copy className="w-3.5 h-3.5" />
                              )}
                            </button>
                          </div>
                        </td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </div>
          </div>

          {/* SECTION 2: DETECTED VULNERABILITIES & HOW TO PATCH THEM */}
          <div className="bg-slate-900 border border-slate-800 rounded-2xl overflow-hidden">
            <div className="p-4 bg-slate-950 border-b border-slate-800 flex items-center justify-between">
              <div>
                <h3 className="text-base font-bold text-slate-100 flex items-center gap-2">
                  <Wrench className="w-4 h-4 text-amber-400" />
                  <span>
                    2. Detected System Vulnerabilities &amp; Step-by-Step Patching Blueprints ({report.vulnerabilities.length})
                  </span>
                </h3>
                <p className="text-xs text-slate-400 mt-0.5">
                  Every vulnerability found on <span className="text-cyan-300 font-mono">{report.cleanHost}</span> along with exact remediation steps and copy-pasteable code patches.
                </p>
              </div>
            </div>

            <div className="p-4 space-y-4">
              {report.vulnerabilities.length === 0 ? (
                <div className="p-8 text-center bg-emerald-950/30 border border-emerald-500/40 rounded-xl text-emerald-300">
                  <ShieldCheck className="w-8 h-8 mx-auto mb-2 text-emerald-400" />
                  <div className="font-bold text-sm">Zero Open Vulnerabilities Detected</div>
                  <p className="text-xs opacity-80 mt-1">
                    All probed ports and HTTP security headers on {report.cleanHost} conform to enterprise hardening standards.
                  </p>
                </div>
              ) : (
                report.vulnerabilities.map((vuln) => (
                  <div
                    key={vuln.id}
                    className="bg-slate-950 border border-slate-800 rounded-xl p-4 space-y-3"
                  >
                    <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2">
                      <div className="flex items-center gap-2.5 flex-wrap">
                        <span className={`px-2.5 py-0.5 rounded text-[11px] font-mono font-black border ${getSeverityBadge(vuln.severity)}`}>
                          {vuln.severity} (CVSS {vuln.cvssScore})
                        </span>
                        <span className="text-xs font-mono text-cyan-400 font-bold">
                          {vuln.id}
                        </span>
                        <span className="text-xs font-mono text-slate-400 bg-slate-900 px-2 py-0.5 rounded border border-slate-800">
                          {vuln.cveOrCwe}
                        </span>
                      </div>
                      <span className="text-xs font-mono text-slate-400">
                        Component: <strong className="text-slate-200">{vuln.affectedComponent}</strong>
                      </span>
                    </div>

                    <h4 className="text-sm font-bold text-slate-100">
                      {vuln.title}
                    </h4>

                    <p className="text-xs text-slate-300 leading-relaxed">
                      {vuln.description}
                    </p>

                    <div className="p-3 rounded-lg bg-emerald-950/25 border border-emerald-500/30 space-y-2">
                      <div className="text-xs font-bold text-emerald-300 flex items-center gap-1.5">
                        <ShieldCheck className="w-4 h-4 text-emerald-400 shrink-0" />
                        <span>How to Patch &amp; Remediate:</span>
                      </div>
                      <p className="text-xs text-emerald-100/90 leading-relaxed">
                        {vuln.howToPatch}
                      </p>
                    </div>

                    {/* Patch Code Snippet */}
                    <div className="bg-slate-900 border border-slate-800 rounded-lg overflow-hidden">
                      <div className="px-3 py-1.5 bg-slate-900 border-b border-slate-800 flex items-center justify-between text-[11px] font-mono text-slate-400">
                        <span className="flex items-center gap-1.5">
                          <Terminal className="w-3.5 h-3.5 text-cyan-400" />
                          <span>Ready-to-Apply Patch Snippet</span>
                        </span>
                        <button
                          onClick={() => handleCopy(vuln.id, vuln.patchSnippet)}
                          className="px-2 py-0.5 rounded bg-slate-800 hover:bg-slate-700 text-cyan-300 flex items-center gap-1 transition cursor-pointer"
                        >
                          {copiedId === vuln.id ? (
                            <>
                              <Check className="w-3 h-3 text-emerald-400" />
                              <span className="text-emerald-400">Copied!</span>
                            </>
                          ) : (
                            <>
                              <Copy className="w-3 h-3" />
                              <span>Copy Patch</span>
                            </>
                          )}
                        </button>
                      </div>
                      <pre className="p-3 text-xs font-mono text-emerald-300 overflow-x-auto leading-relaxed">
                        {vuln.patchSnippet}
                      </pre>
                    </div>
                  </div>
                ))
              )}
            </div>
          </div>
        </>
      )}
    </div>
  );
};
