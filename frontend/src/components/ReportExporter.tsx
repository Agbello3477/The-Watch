import React, { useState } from 'react';
import { FileText, Download, FileSpreadsheet, CheckCircle2, Shield } from 'lucide-react';
import { api } from '../services/api';

interface ReportExporterProps {
  selectedSystem: string;
}

export const ReportExporter: React.FC<ReportExporterProps> = ({ selectedSystem }) => {
  const [downloadingPdf, setDownloadingPdf] = useState<boolean>(false);
  const [downloadingCsv, setDownloadingCsv] = useState<boolean>(false);

  const handleDownloadPdf = () => {
    setDownloadingPdf(true);
    const url = api.getPdfReportUrl(selectedSystem || undefined);
    window.open(url, '_blank');
    setTimeout(() => setDownloadingPdf(false), 2000);
  };

  const handleDownloadCsv = () => {
    setDownloadingCsv(true);
    const url = api.getCsvReportUrl(selectedSystem || undefined);
    window.open(url, '_blank');
    setTimeout(() => setDownloadingCsv(false), 2000);
  };

  return (
    <div className="bg-slate-900/80 border border-slate-800 rounded-xl p-5 shadow-sm">
      
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 mb-4">
        <div>
          <div className="flex items-center gap-2">
            <FileText className="w-5 h-5 text-cyan-400" />
            <h2 className="text-base font-bold text-white tracking-wide">FORENSIC AUDIT REPORT GENERATOR (PDF & CSV)</h2>
          </div>
          <p className="text-xs text-slate-400 mt-0.5">
            Generate and export on-demand, executive-ready security audit reports with WAT timestamps, threat origins, and Cloudflare WAF blueprints
          </p>
        </div>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
        
        {/* PDF Export Card */}
        <div className="bg-slate-950 border border-slate-800 hover:border-slate-700 rounded-xl p-5 flex flex-col justify-between transition">
          <div>
            <div className="flex items-center gap-3">
              <div className="w-10 h-10 rounded-xl bg-red-500/10 border border-red-500/30 flex items-center justify-center">
                <FileText className="w-5 h-5 text-red-400" />
              </div>
              <div>
                <h3 className="text-sm font-bold text-slate-100">Executive Forensic Audit Report (PDF)</h3>
                <span className="text-[11px] text-slate-400">PDFKit High-Resolution Vector Document</span>
              </div>
            </div>

            <div className="mt-4 space-y-1.5 text-xs text-slate-300">
              <div className="flex items-center gap-1.5">
                <CheckCircle2 className="w-3.5 h-3.5 text-emerald-400 shrink-0" />
                <span>Executive Threat Summary & Platform Health Score (0–100%)</span>
              </div>
              <div className="flex items-center gap-1.5">
                <CheckCircle2 className="w-3.5 h-3.5 text-emerald-400 shrink-0" />
                <span>Incident Breakdown in West Africa Time (WAT / UTC+1)</span>
              </div>
              <div className="flex items-center gap-1.5">
                <CheckCircle2 className="w-3.5 h-3.5 text-emerald-400 shrink-0" />
                <span>Origin Forensics (City, State, Country, ASN, Tor/Proxy flag)</span>
              </div>
              <div className="flex items-center gap-1.5">
                <CheckCircle2 className="w-3.5 h-3.5 text-emerald-400 shrink-0" />
                <span>Target Vector, Captured Payloads & Cloudflare WAF Rules</span>
              </div>
            </div>
          </div>

          <div className="mt-6 pt-4 border-t border-slate-800/80 flex items-center justify-between">
            <span className="text-xs font-mono text-cyan-400">
              Scope: {selectedSystem || 'All Monitored Systems'}
            </span>
            <button
              onClick={handleDownloadPdf}
              disabled={downloadingPdf}
              className="flex items-center gap-2 bg-cyan-600 hover:bg-cyan-500 text-white px-4 py-2 rounded-lg font-bold text-xs shadow-lg shadow-cyan-500/20 transition cursor-pointer"
            >
              <Download className="w-4 h-4" />
              {downloadingPdf ? 'Generating PDF...' : 'Download Audit PDF'}
            </button>
          </div>
        </div>

        {/* CSV Export Card */}
        <div className="bg-slate-950 border border-slate-800 hover:border-slate-700 rounded-xl p-5 flex flex-col justify-between transition">
          <div>
            <div className="flex items-center gap-3">
              <div className="w-10 h-10 rounded-xl bg-emerald-500/10 border border-emerald-500/30 flex items-center justify-center">
                <FileSpreadsheet className="w-5 h-5 text-emerald-400" />
              </div>
              <div>
                <h3 className="text-sm font-bold text-slate-100">Raw Threat & Audit Stream (CSV)</h3>
                <span className="text-[11px] text-slate-400">RFC 4180 Standard Delimited Spreadsheet</span>
              </div>
            </div>

            <div className="mt-4 space-y-1.5 text-xs text-slate-300">
              <div className="flex items-center gap-1.5">
                <CheckCircle2 className="w-3.5 h-3.5 text-emerald-400 shrink-0" />
                <span>Complete forensic columns for SIEM ingestion (Splunk/ELK)</span>
              </div>
              <div className="flex items-center gap-1.5">
                <CheckCircle2 className="w-3.5 h-3.5 text-emerald-400 shrink-0" />
                <span>Includes Offending IP, Lat/Lng, Reverse DNS, ASN & ISP</span>
              </div>
              <div className="flex items-center gap-1.5">
                <CheckCircle2 className="w-3.5 h-3.5 text-emerald-400 shrink-0" />
                <span>Full captured attack payload & query traces</span>
              </div>
              <div className="flex items-center gap-1.5">
                <CheckCircle2 className="w-3.5 h-3.5 text-emerald-400 shrink-0" />
                <span>Incident resolution state & admin review audit trail</span>
              </div>
            </div>
          </div>

          <div className="mt-6 pt-4 border-t border-slate-800/80 flex items-center justify-between">
            <span className="text-xs font-mono text-cyan-400">
              Format: Raw Data Feed
            </span>
            <button
              onClick={handleDownloadCsv}
              disabled={downloadingCsv}
              className="flex items-center gap-2 bg-slate-800 hover:bg-slate-700 text-slate-200 hover:text-white border border-slate-700 px-4 py-2 rounded-lg font-bold text-xs transition cursor-pointer"
            >
              <Download className="w-4 h-4 text-emerald-400" />
              {downloadingCsv ? 'Exporting CSV...' : 'Download Raw CSV'}
            </button>
          </div>
        </div>

      </div>
    </div>
  );
};
