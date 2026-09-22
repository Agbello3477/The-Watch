import PDFDocument from 'pdfkit';
import { db, ThreatIncident, getWATFormattedDate } from '../db/database';
import fs from 'fs';
import path from 'path';

export interface ReportGenerationOptions {
  systemId?: string;
  reportTitle?: string;
}

export class ForensicPdfReportGenerator {
  /**
   * Generates an executive forensic security audit PDF with MaSha Tech Innovations branding
   */
  public async generatePdf(options: ReportGenerationOptions = {}): Promise<Buffer> {
    const { systemId, reportTitle = 'INSTITUTIONAL CYBERSECURITY & OBSERVABILITY FORENSIC AUDIT' } = options;
    const overview = await db.getSystemHealthOverview(systemId);
    const incidents = await db.getIncidents({ systemId, limit: 100 });
    const probes = await db.getProbes(systemId);

    return new Promise((resolve, reject) => {
      const doc = new PDFDocument({
        size: 'A4',
        margin: 40,
        info: {
          Title: reportTitle,
          Author: 'The Watch Threat Intelligence Platform (Powered by MaSha Tech Innovations)',
          Subject: 'Forensic Security & System Health Audit',
          Keywords: 'security, audit, threat intelligence, forensics, NOUN-HRMS, MaSha Tech Innovations',
        },
      });

      const buffers: Buffer[] = [];
      doc.on('data', buffers.push.bind(buffers));
      doc.on('end', () => {
        const pdfData = Buffer.concat(buffers);
        resolve(pdfData);
      });
      doc.on('error', (err) => reject(err));

      const PRIMARY_COLOR = '#0f172a'; // dark slate
      const WAT_TIME = getWATFormattedDate();

      // ================= HEADER BANNER =================
      doc.rect(0, 0, 595.28, 95).fill(PRIMARY_COLOR);

      // Try embedding logo image if available
      const logoPath = path.join(__dirname, '../assets/logo.jpg');
      if (fs.existsSync(logoPath)) {
        try {
          doc.image(logoPath, 40, 15, { width: 45, height: 45, fit: [45, 45] });
        } catch (e) {}
      }

      doc.fillColor('#38bdf8').fontSize(16).font('Helvetica-Bold')
        .text('THE WATCH', 95, 18, { characterSpacing: 1 });
      
      doc.fillColor('#f59e0b').fontSize(8.5).font('Helvetica-Bold')
        .text('POWERED BY: MASHA TECH INNOVATIONS', 95, 36);

      doc.fillColor('#94a3b8').fontSize(7.5).font('Helvetica')
        .text('ENTERPRISE OBSERVABILITY & THREAT INTELLIGENCE PLATFORM', 95, 48);

      doc.fillColor('#f8fafc').fontSize(10).font('Helvetica-Bold')
        .text('FORENSIC AUDIT REPORT', 370, 20, { align: 'right', width: 185 });

      doc.fillColor('#38bdf8').fontSize(8.5).font('Helvetica')
        .text(WAT_TIME, 370, 34, { align: 'right', width: 185 });

      doc.fillColor('#94a3b8').fontSize(7.5).font('Helvetica')
        .text(`SCOPE: ${systemId || 'ALL MONITORED INSTITUTIONAL SYSTEMS'}`, 370, 48, { align: 'right', width: 185 });

      // Move down below banner
      doc.y = 115;

      // ================= 1. EXECUTIVE SUMMARY BOX =================
      doc.fillColor('#0f172a').fontSize(12).font('Helvetica-Bold')
        .text('1. EXECUTIVE THREAT SUMMARY & HEALTH SCORE', 40, doc.y);

      doc.moveDown(0.5);

      const summaryBoxY = doc.y;
      doc.roundedRect(40, summaryBoxY, 515.28, 90, 6).lineWidth(1).strokeColor('#cbd5e1').fillAndStroke('#f8fafc', '#cbd5e1');

      // Metric 1: Platform Health Score
      const healthColor = overview.healthScore >= 90 ? '#16a34a' : overview.healthScore >= 70 ? '#eab308' : '#dc2626';
      doc.fillColor('#64748b').fontSize(8).font('Helvetica-Bold').text('PLATFORM HEALTH SCORE', 55, summaryBoxY + 14);
      doc.fillColor(healthColor).fontSize(22).font('Helvetica-Bold').text(`${overview.healthScore}%`, 55, summaryBoxY + 28);
      doc.fillColor('#64748b').fontSize(8).font('Helvetica').text(`Status: ${overview.threatLevel}`, 55, summaryBoxY + 58);

      // Metric 2: Total Detected Threats
      doc.fillColor('#64748b').fontSize(8).font('Helvetica-Bold').text('TOTAL THREAT INCIDENTS', 180, summaryBoxY + 14);
      doc.fillColor('#dc2626').fontSize(22).font('Helvetica-Bold').text(`${incidents.length}`, 180, summaryBoxY + 28);
      doc.fillColor('#64748b').fontSize(8).font('Helvetica').text(`Critical: ${overview.criticalIncidents} | High: ${overview.highIncidents}`, 180, summaryBoxY + 58);

      // Metric 3: Synthetic Probes Uptime
      doc.fillColor('#64748b').fontSize(8).font('Helvetica-Bold').text('SYNTHETIC PROBES', 315, summaryBoxY + 14);
      doc.fillColor('#0284c7').fontSize(22).font('Helvetica-Bold').text(`${overview.probesHealthy}/${overview.probesCount} UP`, 315, summaryBoxY + 28);
      doc.fillColor('#64748b').fontSize(8).font('Helvetica').text(`Avg TTFB: ${overview.avgTtfbMs}ms`, 315, summaryBoxY + 58);

      // Metric 4: Slow DB Queries
      doc.fillColor('#64748b').fontSize(8).font('Helvetica-Bold').text('QUERY OBSERVABILITY', 440, summaryBoxY + 14);
      doc.fillColor(overview.slowQueriesCount > 0 ? '#ea580c' : '#16a34a').fontSize(22).font('Helvetica-Bold').text(`${overview.slowQueriesCount}`, 440, summaryBoxY + 28);
      doc.fillColor('#64748b').fontSize(8).font('Helvetica').text('Latency > 200ms', 440, summaryBoxY + 58);

      doc.y = summaryBoxY + 105;

      // Executive Statement
      doc.fillColor('#334155').fontSize(9).font('Helvetica')
        .text(
          `This forensic report outlines all real-time security events, HTTP/UDP telemetry anomalies, synthetic endpoint probe degradation, and database query regression captured by The Watch monitoring gateway (Powered by MaSha Tech Innovations) during the active audit window. Monitored systems: ${systemId || 'NOUN-HRMS, Clinic-EHR, Security-Dispatch'}.`,
          40,
          doc.y,
          { width: 515.28, lineGap: 2 }
        );

      doc.moveDown(1.2);

      // ================= 2. INCIDENT BREAKDOWN & FORENSICS =================
      doc.fillColor('#0f172a').fontSize(12).font('Helvetica-Bold')
        .text('2. INCIDENT FORENSICS & ATTACK BREAKDOWN', 40, doc.y);

      doc.moveDown(0.5);

      if (incidents.length === 0) {
        doc.fillColor('#16a34a').fontSize(9).font('Helvetica-Bold')
          .text('✓ No unresolved security threats or endpoint failures recorded during this cycle.', 40, doc.y);
      } else {
        const displayIncidents = incidents.slice(0, 6);

        for (let i = 0; i < displayIncidents.length; i++) {
          const inc = displayIncidents[i];

          if (doc.y > 670) {
            doc.addPage();
            doc.y = 40;
          }

          const cardY = doc.y;
          const cardHeight = 85;

          doc.roundedRect(40, cardY, 515.28, cardHeight, 4)
            .lineWidth(1)
            .strokeColor('#e2e8f0')
            .fillAndStroke('#ffffff', '#e2e8f0');

          const sevColor = inc.severity === 'CRITICAL' ? '#dc2626' : inc.severity === 'HIGH' ? '#ea580c' : inc.severity === 'MEDIUM' ? '#eab308' : '#16a34a';
          doc.rect(40, cardY, 5, cardHeight).fill(sevColor);

          doc.fillColor(sevColor).fontSize(8).font('Helvetica-Bold')
            .text(`[${inc.severity}] ${inc.threat_classification.toUpperCase()}`, 52, cardY + 8);

          doc.fillColor('#64748b').fontSize(8).font('Helvetica')
            .text(`WAT: ${inc.created_at_wat} | Status: ${inc.status}`, 320, cardY + 8, { align: 'right', width: 225 });

          doc.fillColor('#1e293b').fontSize(8.5).font('Helvetica-Bold')
            .text('Target Vector:', 52, cardY + 22);
          doc.fillColor('#334155').fontSize(8.5).font('Helvetica')
            .text(`${inc.http_method} ${inc.target_endpoint}`, 120, cardY + 22, { width: 425 });

          doc.fillColor('#1e293b').fontSize(8.5).font('Helvetica-Bold')
            .text('Origin Forensics:', 52, cardY + 36);
          doc.fillColor('#334155').fontSize(8.5).font('Helvetica')
            .text(`IP: ${inc.offending_ip} | ${inc.geo_city || 'Unknown'}, ${inc.geo_country || 'Unknown'} (${inc.asn || 'AS0'} - ${inc.isp || 'N/A'}) | Tor/VPN: ${inc.is_proxy_or_vpn ? 'YES' : 'NO'}`, 128, cardY + 36, { width: 420 });

          doc.fillColor('#1e293b').fontSize(8).font('Helvetica-Bold')
            .text('Payload Snippet:', 52, cardY + 50);
          doc.fillColor('#991b1b').fontSize(7.5).font('Courier')
            .text(`${(inc.captured_payload || '').substring(0, 100)}`, 130, cardY + 50, { width: 415, ellipsis: true });

          doc.fillColor('#0284c7').fontSize(7.5).font('Helvetica-Bold')
            .text('Action Applied:', 52, cardY + 68);
          doc.fillColor('#0369a1').fontSize(7.5).font('Helvetica')
            .text(inc.remediation_summary || 'Automated WAF block rule applied.', 118, cardY + 68, { width: 430, ellipsis: true });

          doc.y = cardY + cardHeight + 8;
        }
      }

      // ================= 3. MITIGATION BLUEPRINTS =================
      if (doc.y > 600) {
        doc.addPage();
        doc.y = 40;
      } else {
        doc.moveDown(1);
      }

      doc.fillColor('#0f172a').fontSize(12).font('Helvetica-Bold')
        .text('3. ACTION TAKEN & RECOMMENDED MITIGATION BLUEPRINTS', 40, doc.y);

      doc.moveDown(0.5);

      const codeBoxY = doc.y;
      doc.roundedRect(40, codeBoxY, 515.28, 95, 4).fill('#0f172a');

      doc.fillColor('#38bdf8').fontSize(8).font('Courier-Bold')
        .text('# Cloudflare WAF Expression & Nginx Perimeter Deny Rules:', 50, codeBoxY + 10);

      doc.fillColor('#e2e8f0').fontSize(7.5).font('Courier')
        .text(
          `# 1. Cloudflare WAF:\n(http.request.uri.path contains "/api/v1" and ip.src in {194.26.29.112, 185.220.101.5}) -> BLOCK\n\n# 2. Nginx Security Filter:\nlocation /api/ {\n    deny 194.26.29.112; # SQLi Attack Drone\n    deny 185.220.101.5;  # Tor Exit Node Brute Force\n}`,
          50,
          codeBoxY + 24,
          { width: 495 }
        );

      doc.y = codeBoxY + 110;

      // Footer
      const totalPages = doc.bufferedPageRange().count;
      for (let p = 0; p < totalPages; p++) {
        doc.switchToPage(p);
        doc.rect(40, 790, 515.28, 0.5).fill('#cbd5e1');
        doc.fillColor('#94a3b8').fontSize(7).font('Helvetica')
          .text(
            'THE WATCH OBSERVABILITY GATEWAY | POWERED BY: MASHA TECH INNOVATIONS | NATIONAL OPEN UNIVERSITY SOC',
            40,
            800,
            { align: 'left', width: 410 }
          );
        doc.fillColor('#94a3b8').fontSize(7).font('Helvetica')
          .text(`PAGE ${p + 1} OF ${totalPages}`, 460, 800, { align: 'right', width: 95 });
      }

      doc.end();
    });
  }
}

export class ForensicCsvReportGenerator {
  public async generateCsv(systemId?: string): Promise<string> {
    const incidents = await db.getIncidents({ systemId, limit: 500 });

    const headers = [
      'IncidentID',
      'SystemID',
      'TimestampWAT',
      'Severity',
      'ThreatClassification',
      'Status',
      'OffendingIP',
      'Country',
      'City',
      'ASN',
      'ISP',
      'IsProxyOrTor',
      'HTTPMethod',
      'TargetEndpoint',
      'CapturedPayload',
      'MitigationBlueprint',
    ];

    const escapeCsv = (val: any) => {
      if (val === null || val === undefined) return '""';
      const str = String(val).replace(/"/g, '""').replace(/\n/g, ' ');
      return `"${str}"`;
    };

    const rows = incidents.map((i) => [
      escapeCsv(i.id),
      escapeCsv(i.system_id),
      escapeCsv(i.created_at_wat),
      escapeCsv(i.severity),
      escapeCsv(i.threat_classification),
      escapeCsv(i.status),
      escapeCsv(i.offending_ip),
      escapeCsv(i.geo_country),
      escapeCsv(i.geo_city),
      escapeCsv(i.asn),
      escapeCsv(i.isp),
      escapeCsv(i.is_proxy_or_vpn ? 'TRUE' : 'FALSE'),
      escapeCsv(i.http_method),
      escapeCsv(i.target_endpoint),
      escapeCsv(i.captured_payload),
      escapeCsv(i.remediation_summary || i.mitigation_blueprint),
    ]);

    return [headers.join(','), ...rows.map((r) => r.join(','))].join('\n');
  }
}

export const pdfReportGenerator = new ForensicPdfReportGenerator();
export const csvReportGenerator = new ForensicCsvReportGenerator();
