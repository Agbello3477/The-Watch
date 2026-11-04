import React, { useState } from 'react';
import {
  Radar,
  ShieldCheck,
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
  Cpu,
  FileCode,
} from 'lucide-react';
import { triggerBrowserBlobDownload } from '../utils/pdfExporter';
import { SocSeverityBadge } from './SocThemeBadge';

const rawApiUrl = (import.meta as any).env?.VITE_API_URL || '';
const API_BASE = rawApiUrl ? `${rawApiUrl.replace(/\/$/, '')}/api/v1` : '/api/v1';

interface PortScanResult {
  port: number;
  protocol: 'TCP';
  service: string;
  nmapServiceShort?: string;
  state: 'OPEN' | 'CLOSED' | 'FILTERED';
  latencyMs?: number;
  bannerOrVersion: string;
  nseScripts?: { id: string; output: string }[];
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

interface NmapScanTelemetry {
  profile: string;
  profileLabel: string;
  commandExecuted: string;
  nmapVersion: string;
  hostStatus: 'up' | 'down';
  latencySec: string;
  osDetection: {
    name: string;
    accuracy: number;
    cpe: string;
    deviceType: string;
  };
  traceroute: {
    hop: number;
    rttMs: string;
    ip: string;
    host: string;
  }[];
  rawTerminalOutput: string;
  xmlExport: string;
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
  nmap?: NmapScanTelemetry;
  ports: PortScanResult[];
  vulnerabilities: VulnerabilityFinding[];
}

export const SurfaceScanner: React.FC = () => {
  const [targetInput, setTargetInput] = useState<string>('https://noun-hrms.onrender.com');
  const [scanProfile, setScanProfile] = useState<'INTENSE' | 'VULN' | 'QUICK' | 'FULL_AUDIT'>('INTENSE');
  const [customPorts, setCustomPorts] = useState<string>('');
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
        body: JSON.stringify({
          target: targetToScan,
          profile: scanProfile,
          customPorts: customPorts.trim() || undefined,
        }),
      });

      const data = await res.json();
      if (!res.ok) {
        throw new Error(data.error || 'Failed to inspect target server');
      }

      setReport(data);
    } catch (err: any) {
      setError(err.message || 'Could not complete Nmap surface & vulnerability scan');
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
      'THE WATCH SOC — NMAP NETWORK & VULNERABILITY AUDIT REPORT',
      `Target Input,${report.targetInput}`,
      `Resolved IP,${report.resolvedIp}`,
      `Nmap Command,"${report.nmap?.commandExecuted || `nmap -T4 -A -v ${report.cleanHost}`}"`,
      `OS Fingerprint,"${report.nmap?.osDetection.name || 'Linux'}"`,
      `Location,"${report.geo.city}, ${report.geo.country} (${report.geo.isp})"`,
      `Security Score,${report.summary.securityScore}/100 (Grade ${report.summary.securityGrade})`,
      `Scanned At (WAT),"${report.scannedAtWat}"`,
      '',
      '--- NMAP PORT DISCOVERY & HARDENING RECOMMENDATIONS ---',
      'Port,Protocol,Nmap_Service,Service,Current_State,Recommendation,Risk_Level,Explanation,Firewall_Command',
      ...report.ports.map((p) =>
        [
          p.port,
          p.protocol,
          p.nmapServiceShort || 'tcp',
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
    triggerBrowserBlobDownload(blob, `TheWatch_Nmap_Audit_${report.cleanHost}_${Date.now()}.csv`);
  };

  const handleExportNmapXml = () => {
    if (!report?.nmap?.xmlExport) return;
    const blob = new Blob([report.nmap.xmlExport], { type: 'application/xml;charset=utf-8;' });
    triggerBrowserBlobDownload(blob, `nmap_scan_${report.cleanHost}_${Date.now()}.xml`);
  };

  const filteredPorts = (report?.ports || []).filter((p) => {
    if (portFilter === 'OPEN') return p.state === 'OPEN';
    if (portFilter === 'CLOSE_OR_RESTRICT') return p.recommendation !== 'LEAVE_OPEN';
    if (portFilter === 'LEAVE_OPEN') return p.recommendation === 'LEAVE_OPEN';
    return true;
  });

  const previewCommand = `nmap ${
    scanProfile === 'INTENSE'
      ? '-T4 -A -v -sV -sC -Pn'
      : scanProfile === 'VULN'
      ? '-sV --script=vuln,http-security-headers,ssl-enum-ciphers -T4 -Pn'
      : scanProfile === 'QUICK'
      ? '-T4 -F -sV -Pn'
      : '-sS -sV -O --traceroute -T4 -Pn'
  }${customPorts.trim() ? ` -p ${customPorts.trim()}` : ''} ${targetInput.replace(/^https?:\/\//i, '').split('/')[0] || 'target'}`;

  return (
    <div className="space-y-6 text-sm">
      {/* Scanner Input Card */}
      <div className="bg-slate-900 border border-slate-700 rounded-2xl p-5 shadow-xl">
        <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 mb-4">
          <div className="flex items-center gap-3">
            <div className="w-11 h-11 rounded-xl bg-blue-500/10 border border-blue-500/30 flex items-center justify-center shrink-0">
              <Radar className={`w-6 h-6 text-blue-400 ${isScanning ? 'animate-spin' : ''}`} />
            </div>
            <div>
              <div className="flex items-center gap-2 flex-wrap">
                <h2 className="text-lg font-bold text-slate-100">
                  Nmap Network Mapper &amp; Vulnerability Auditor
                </h2>
                <SocSeverityBadge severity="LOW" label="Nmap 7.95 + NSE Engine" />
              </div>
              <p className="text-xs text-slate-400 mt-0.5">
                Execute Nmap port discovery (`-sV -sC -O --script=vuln`), OS fingerprinting, traceroute, port closure recommendations, and vulnerability patching on any IP or URL.
              </p>
            </div>
          </div>

          {report && (
            <div className="flex items-center gap-2 self-start md:self-auto">
              {report.nmap?.xmlExport && (
                <button
                  onClick={handleExportNmapXml}
                  className="px-3 py-2 rounded-xl bg-slate-800 hover:bg-slate-700 text-slate-100 border border-slate-700 text-xs font-mono font-bold flex items-center gap-1.5 transition cursor-pointer"
                >
                  <FileCode className="w-3.5 h-3.5 text-blue-400" />
                  <span>Export Nmap XML (-oX)</span>
                </button>
              )}
              <button
                onClick={handleExportReport}
                className="px-3.5 py-2 rounded-xl bg-blue-600 hover:bg-blue-500 text-white border border-blue-500/40 text-xs font-mono font-bold flex items-center gap-1.5 transition cursor-pointer"
              >
                <Download className="w-3.5 h-3.5" />
                <span>Export Audit CSV</span>
              </button>
            </div>
          )}
        </div>

        {/* Nmap Scan Profile & Custom Port Bar */}
        <div className="grid grid-cols-1 lg:grid-cols-12 gap-3 mb-3">
          <div className="lg:col-span-8">
            <label className="block text-[11px] font-mono uppercase text-slate-400 mb-1">
              Nmap Scan Profile (Zenmap / NSE Preset)
            </label>
            <div className="grid grid-cols-2 sm:grid-cols-4 gap-1.5">
              {[
                { id: 'INTENSE', label: 'Intense Scan (-A -sV -sC)' },
                { id: 'VULN', label: 'NSE Vuln Scan (--script=vuln)' },
                { id: 'FULL_AUDIT', label: 'OS & Traceroute (-O -sS)' },
                { id: 'QUICK', label: 'Quick Scan (-T4 -F)' },
              ].map((prof) => (
                <button
                  key={prof.id}
                  type="button"
                  onClick={() => setScanProfile(prof.id as any)}
                  className={`px-2.5 py-2 rounded-lg text-[11px] font-mono font-bold border transition text-left truncate ${
                    scanProfile === prof.id
                      ? 'bg-blue-600 text-white border-blue-500/40'
                      : 'bg-slate-950 text-slate-400 border-slate-700 hover:text-slate-100'
                  }`}
                >
                  {prof.label}
                </button>
              ))}
            </div>
          </div>

          <div className="lg:col-span-4">
            <label className="block text-[11px] font-mono uppercase text-slate-400 mb-1">
              Extra Ports (`-p` Optional, e.g. 8443,9000)
            </label>
            <input
              type="text"
              value={customPorts}
              onChange={(e) => setCustomPorts(e.target.value)}
              placeholder="Default: 15 Core TCP Ports + Custom..."
              className="w-full px-3 py-2 bg-slate-950 border border-slate-700 focus:border-slate-600 rounded-lg font-mono text-xs text-slate-100 placeholder-slate-500 outline-none"
            />
          </div>
        </div>

        {/* Live Nmap Command Preview */}
        <div className="mb-3 px-3 py-2 rounded-lg bg-slate-950 border border-slate-700 flex items-center justify-between gap-2 font-mono text-xs">
          <div className="flex items-center gap-2 truncate">
            <Terminal className="w-3.5 h-3.5 text-emerald-400 shrink-0" />
            <span className="text-slate-500">Nmap Command:</span>
            <code className="text-emerald-400 truncate">{previewCommand}</code>
          </div>
          <button
            type="button"
            onClick={() => handleCopy('nmap-cmd', previewCommand)}
            className="px-2 py-0.5 rounded bg-slate-800 hover:bg-slate-700 text-slate-200 border border-slate-700 text-[10px] shrink-0 flex items-center gap-1"
          >
            {copiedId === 'nmap-cmd' ? <Check className="w-3 h-3 text-emerald-400" /> : <Copy className="w-3 h-3" />}
            <span>Copy CLI</span>
          </button>
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
            <Globe className="w-4 h-4 text-blue-400 absolute left-3.5 top-1/2 -translate-y-1/2" />
            <input
              type="text"
              value={targetInput}
              onChange={(e) => setTargetInput(e.target.value)}
              placeholder="Enter Server IP or URL (e.g., https://noun-hrms.onrender.com, 154.68.225.146, noun.edu.ng)"
              className="w-full pl-10 pr-4 py-3 bg-slate-950 border border-slate-700 focus:border-slate-600 rounded-xl font-mono text-xs sm:text-sm text-slate-100 placeholder-slate-500 outline-none"
            />
          </div>
          <button
            type="submit"
            disabled={isScanning}
            className="px-6 py-3 rounded-xl bg-blue-600 hover:bg-blue-500 text-white border border-blue-500/40 font-black text-xs sm:text-sm uppercase tracking-wider flex items-center justify-center gap-2 shadow-sm transition cursor-pointer disabled:opacity-60"
          >
            <Search className="w-4 h-4" />
            <span>{isScanning ? 'Running Nmap Scan...' : 'Run Nmap Scan'}</span>
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
              className="px-2.5 py-1 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-100 border border-slate-700 font-mono text-[11px] transition cursor-pointer"
            >
              {preset.label}
            </button>
          ))}
        </div>
      </div>

      {error && (
        <div className="bg-red-500/10 border border-red-500/30 text-red-400 p-4 rounded-xl text-xs font-mono">
          {error}
        </div>
      )}

      {!report && !isScanning && (
        <div className="bg-slate-900 border border-slate-700 rounded-2xl p-10 text-center space-y-3">
          <Server className="w-10 h-10 text-blue-400 mx-auto opacity-80" />
          <div className="text-base font-bold text-slate-100">
            Ready to Run Nmap Network &amp; Vulnerability Scan
          </div>
          <p className="text-xs text-slate-400 max-w-xl mx-auto">
            Select an Nmap scan profile above and click <strong>"Run Nmap Scan"</strong> to perform TCP port discovery, service/banner versioning (`-sV`), NSE script auditing (`-sC`), OS fingerprinting (`-O`), and vulnerability remediation analysis.
          </p>
        </div>
      )}

      {report && (
        <>
          {/* Executive Summary KPI Cards */}
          <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
            {/* Score & Grade */}
            <div className="bg-slate-900 border border-slate-700 rounded-xl p-4">
              <div className="text-[11px] font-mono uppercase text-slate-400">
                Security Posture Rating
              </div>
              <div className="flex items-baseline gap-3 mt-1.5">
                <span
                  className={`text-3xl font-black font-mono ${
                    report.summary.securityScore >= 80
                      ? 'text-emerald-400'
                      : report.summary.securityScore >= 60
                      ? 'text-yellow-400'
                      : 'text-red-400'
                  }`}
                >
                  {report.summary.securityScore}/100
                </span>
                <SocSeverityBadge
                  severity={
                    report.summary.securityScore >= 80
                      ? 'RESOLVED'
                      : report.summary.securityScore >= 60
                      ? 'MEDIUM'
                      : 'CRITICAL'
                  }
                  label={`GRADE ${report.summary.securityGrade}`}
                />
              </div>
              <div className="text-[11px] text-slate-500 mt-1.5 font-mono">
                Scan Time: {report.scanDurationMs}ms | {report.scannedAtWat}
              </div>
            </div>

            {/* Resolved Host & OS Detection */}
            <div className="bg-slate-900 border border-slate-700 rounded-xl p-4">
              <div className="text-[11px] font-mono uppercase text-slate-400">
                Resolved Target &amp; OS Fingerprint
              </div>
              <div className="text-base font-bold text-slate-100 mt-1 font-mono truncate" title={report.cleanHost}>
                {report.cleanHost} ({report.resolvedIp})
              </div>
              <div className="text-[11px] text-blue-400 mt-1 font-mono truncate">
                {report.nmap?.osDetection.name || `${report.geo.city}, ${report.geo.country}`}
              </div>
              <div className="text-[11px] text-slate-500 mt-0.5 font-mono truncate">
                CPE: {report.nmap?.osDetection.cpe || report.httpProbe.serverBanner}
              </div>
            </div>

            {/* Open Ports Breakdown */}
            <div className="bg-slate-900 border border-slate-700 rounded-xl p-4">
              <div className="text-[11px] font-mono uppercase text-slate-400">
                Nmap Port State ({report.summary.totalPortsScanned} Probed)
              </div>
              <div className="text-2xl font-black text-slate-100 mt-1 font-mono">
                {report.summary.openPortsCount} Open Ports
              </div>
              <div className="flex items-center gap-3 mt-1.5 text-[11px] font-mono">
                <span className="text-emerald-400 font-bold">
                  ✓ {report.summary.portsSafeToLeaveOpenCount} Leave Open
                </span>
                <span className="text-red-400 font-bold">
                  ⚠ {report.summary.portsRecommendedToCloseCount} Close/Restrict
                </span>
              </div>
            </div>

            {/* Vulnerabilities Found */}
            <div className="bg-slate-900 border border-slate-700 rounded-xl p-4">
              <div className="text-[11px] font-mono uppercase text-slate-400">
                NSE &amp; CVE Vulnerabilities
              </div>
              <div className="text-2xl font-black text-yellow-400 mt-1 font-mono">
                {report.summary.totalVulnerabilities} Findings
              </div>
              <div className="flex items-center gap-2 mt-1.5 text-[11px] font-mono flex-wrap">
                <span className="text-red-400 font-bold">Crit: {report.summary.criticalCount}</span>
                <span className="text-orange-400 font-bold">High: {report.summary.highCount}</span>
                <span className="text-yellow-400 font-bold">Med: {report.summary.mediumCount}</span>
                <span className="text-blue-400 font-bold">Low: {report.summary.lowCount}</span>
              </div>
            </div>
          </div>

          {/* SECTION 0: INTERACTIVE NMAP TERMINAL CONSOLE & TRACEROUTE */}
          {report.nmap && (
            <div className="bg-slate-900 border border-slate-700 rounded-2xl overflow-hidden">
              <div className="p-4 bg-slate-950 border-b border-slate-700 flex flex-col sm:flex-row sm:items-center justify-between gap-3">
                <div className="flex items-center gap-2">
                  <Terminal className="w-4 h-4 text-emerald-400" />
                  <h3 className="text-sm font-bold text-slate-100 font-mono">
                    NMAP 7.95 RAW TERMINAL OUTPUT ({report.nmap.profileLabel})
                  </h3>
                </div>
                <div className="flex items-center gap-2">
                  <button
                    onClick={() => handleCopy('nmap-raw', report.nmap?.rawTerminalOutput || '')}
                    className="px-2.5 py-1 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-100 border border-slate-700 text-xs font-mono flex items-center gap-1.5 cursor-pointer"
                  >
                    {copiedId === 'nmap-raw' ? (
                      <>
                        <Check className="w-3.5 h-3.5 text-emerald-400" />
                        <span className="text-emerald-400">Copied Output</span>
                      </>
                    ) : (
                      <>
                        <Copy className="w-3.5 h-3.5" />
                        <span>Copy Nmap Output</span>
                      </>
                    )}
                  </button>
                </div>
              </div>

              <div className="p-4 bg-slate-950 font-mono text-xs text-slate-200 overflow-x-auto max-h-96 overflow-y-auto">
                <pre className="leading-relaxed whitespace-pre">{report.nmap.rawTerminalOutput}</pre>
              </div>
            </div>
          )}

          {/* SECTION 1: OPEN PORTS & RECOMMENDATIONS (WHICH TO CLOSE VS. LEAVE OPEN) */}
          <div className="bg-slate-900 border border-slate-700 rounded-2xl overflow-hidden">
            <div className="p-4 bg-slate-950 border-b border-slate-700 flex flex-col sm:flex-row sm:items-center justify-between gap-3">
              <div>
                <h3 className="text-base font-bold text-slate-100 flex items-center gap-2">
                  <Server className="w-4 h-4 text-blue-400" />
                  <span>1. Nmap Port Discovery, NSE Scripts &amp; Hardening Recommendations</span>
                </h3>
                <p className="text-xs text-slate-400 mt-0.5">
                  Displays port state (`OPEN` / `CLOSED` / `FILTERED`), service banner (`-sV`), NSE script output (`-sC`), and whether to leave open or close.
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
                        ? 'bg-blue-600 text-white font-bold border-blue-500/40'
                        : 'bg-slate-800 text-slate-300 border-slate-700 hover:bg-slate-700'
                    }`}
                  >
                    {tab.label}
                  </button>
                ))}
              </div>
            </div>

            <div className="overflow-x-auto">
              <table className="w-full text-left border-collapse font-mono text-xs">
                <thead className="bg-slate-950 text-slate-400 text-[11px] uppercase border-b border-slate-700">
                  <tr>
                    <th className="py-3 px-4">Port / Proto</th>
                    <th className="py-3 px-4">Service, Version &amp; NSE Scripts</th>
                    <th className="py-3 px-4">Nmap State</th>
                    <th className="py-3 px-4">SOC Recommendation</th>
                    <th className="py-3 px-4">Why &amp; Security Guidance</th>
                    <th className="py-3 px-4">Firewall Command</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-700">
                  {filteredPorts.map((p) => {
                    const isOpenAndRisky = p.state === 'OPEN' && p.recommendation !== 'LEAVE_OPEN';
                    const isOpenAndSafe = p.state === 'OPEN' && p.recommendation === 'LEAVE_OPEN';
                    return (
                      <tr
                        key={p.port}
                        className={
                          isOpenAndRisky
                            ? 'bg-red-500/10 border-l-4 border-l-red-500'
                            : isOpenAndSafe
                            ? 'bg-emerald-500/10 border-l-4 border-l-emerald-500'
                            : 'odd:bg-slate-900 even:bg-slate-800/35 hover:bg-slate-800/80'
                        }
                      >
                        <td className="py-3 px-4 font-bold text-slate-100 whitespace-nowrap">
                          <div>Port {p.port} / {p.protocol}</div>
                          {p.nmapServiceShort && (
                            <div className="text-[10px] text-blue-400">{p.nmapServiceShort} ({p.latencyMs || 1}ms)</div>
                          )}
                        </td>
                        <td className="py-3 px-4">
                          <div className="font-bold text-slate-100">{p.service}</div>
                          <div className="text-[11px] text-slate-400">{p.bannerOrVersion}</div>
                          {p.nseScripts && p.nseScripts.length > 0 && (
                            <div className="mt-1.5 space-y-1 bg-slate-950 p-2 rounded border border-slate-700 text-[10px]">
                              {p.nseScripts.map((sc, i) => (
                                <div key={i} className="text-slate-300">
                                  <span className="text-blue-400 font-bold">|_{sc.id}:</span> {sc.output}
                                </div>
                              ))}
                            </div>
                          )}
                        </td>
                        <td className="py-3 px-4 whitespace-nowrap">
                          {p.state === 'OPEN' ? (
                            <SocSeverityBadge severity="RESOLVED" label="OPEN" />
                          ) : p.state === 'FILTERED' ? (
                            <SocSeverityBadge severity="MEDIUM" label="FILTERED" />
                          ) : (
                            <SocSeverityBadge severity="LOW" label="CLOSED" />
                          )}
                        </td>
                        <td className="py-3 px-4 whitespace-nowrap">
                          {p.recommendation === 'LEAVE_OPEN' ? (
                            <SocSeverityBadge severity="RESOLVED" label="LEAVE OPEN" />
                          ) : p.recommendation === 'RESTRICT_ACCESS' ? (
                            <SocSeverityBadge severity="MEDIUM" label="RESTRICT ACCESS" />
                          ) : (
                            <SocSeverityBadge severity="CRITICAL" label="CLOSE PORT" />
                          )}
                        </td>
                        <td className="py-3 px-4 text-slate-200 max-w-md font-sans text-xs leading-relaxed">
                          {p.whyRecommendation}
                        </td>
                        <td className="py-3 px-4 whitespace-nowrap">
                          <div className="flex items-center gap-2 bg-slate-950 border border-slate-700 px-2.5 py-1.5 rounded-lg">
                            <code className="text-[11px] text-blue-400">{p.firewallActionCommand}</code>
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
          <div className="bg-slate-900 border border-slate-700 rounded-2xl overflow-hidden">
            <div className="p-4 bg-slate-950 border-b border-slate-700 flex items-center justify-between">
              <div>
                <h3 className="text-base font-bold text-slate-100 flex items-center gap-2">
                  <Wrench className="w-4 h-4 text-yellow-400" />
                  <span>
                    2. Detected System Vulnerabilities &amp; Step-by-Step Patching Blueprints ({report.vulnerabilities.length})
                  </span>
                </h3>
                <p className="text-xs text-slate-400 mt-0.5">
                  Every vulnerability found on <span className="text-blue-400 font-mono">{report.cleanHost}</span> along with exact remediation steps and copy-pasteable code patches.
                </p>
              </div>
            </div>

            <div className="p-4 space-y-4">
              {report.vulnerabilities.length === 0 ? (
                <div className="p-8 text-center bg-emerald-500/10 border border-emerald-500/30 rounded-xl text-emerald-400">
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
                    className="bg-slate-950 border border-slate-700 rounded-xl p-4 space-y-3"
                  >
                    <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2">
                      <div className="flex items-center gap-2.5 flex-wrap">
                        <SocSeverityBadge
                          severity={vuln.severity}
                          label={`${vuln.severity} (CVSS ${vuln.cvssScore})`}
                        />
                        <span className="text-xs font-mono text-blue-400 font-bold">
                          {vuln.id}
                        </span>
                        <span className="text-xs font-mono text-slate-400 bg-slate-900 px-2 py-0.5 rounded border border-slate-700">
                          {vuln.cveOrCwe}
                        </span>
                      </div>
                      <span className="text-xs font-mono text-slate-400">
                        Component: <strong className="text-slate-100">{vuln.affectedComponent}</strong>
                      </span>
                    </div>

                    <h4 className="text-sm font-bold text-slate-100">
                      {vuln.title}
                    </h4>

                    <p className="text-xs text-slate-300 leading-relaxed">
                      {vuln.description}
                    </p>

                    <div className="p-3 rounded-lg bg-emerald-500/10 border border-emerald-500/30 space-y-2">
                      <div className="text-xs font-bold text-emerald-400 flex items-center gap-1.5">
                        <ShieldCheck className="w-4 h-4 text-emerald-400 shrink-0" />
                        <span>How to Patch &amp; Remediate:</span>
                      </div>
                      <p className="text-xs text-slate-200 leading-relaxed">
                        {vuln.howToPatch}
                      </p>
                    </div>

                    {/* Patch Code Snippet */}
                    <div className="bg-slate-900 border border-slate-700 rounded-lg overflow-hidden">
                      <div className="px-3 py-1.5 bg-slate-900 border-b border-slate-700 flex items-center justify-between text-[11px] font-mono text-slate-400">
                        <span className="flex items-center gap-1.5">
                          <Terminal className="w-3.5 h-3.5 text-blue-400" />
                          <span>Ready-to-Apply Patch Snippet</span>
                        </span>
                        <button
                          onClick={() => handleCopy(vuln.id, vuln.patchSnippet)}
                          className="px-2 py-0.5 rounded bg-slate-800 hover:bg-slate-700 text-slate-100 border border-slate-700 flex items-center gap-1 transition cursor-pointer"
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
                      <pre className="p-3 text-xs font-mono text-emerald-400 overflow-x-auto leading-relaxed">
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
