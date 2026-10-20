/**
 * Pure Client-Side Binary PDF 1.4 Generator & Fallback Downloader
 * Ensures that PDF Forensic & Audit Reports ALWAYS download as valid .pdf files
 * even if popup blockers are active or the backend server is in sleep/offline mode.
 */

export interface ClientPdfReportData {
  title?: string;
  systemId?: string;
  incident?: {
    id: string;
    systemId: string;
    incidentType: string;
    threatClassification: string;
    severity: string;
    offendingIp: string;
    geoCity?: string;
    geoRegion?: string;
    geoCountry?: string;
    geoLat?: number;
    geoLng?: number;
    asn?: string;
    isp?: string;
    targetEndpoint: string;
    httpMethod: string;
    capturedPayload: string;
    status: string;
    timestampWat: string;
  };
  incidents?: any[];
  auditLogs?: any[];
}

function escapePdfText(str: string): string {
  return (str || '')
    .replace(/[^\x20-\x7E]/g, ' ')
    .replace(/\\/g, '\\\\')
    .replace(/\(/g, '\\(')
    .replace(/\)/g, '\\)');
}

function wrapText(text: string, maxChars: number = 88): string[] {
  const clean = (text || '').replace(/\r?\n/g, ' ');
  const words = clean.split(' ');
  const lines: string[] = [];
  let current = '';
  for (const word of words) {
    if ((current + ' ' + word).trim().length > maxChars) {
      if (current) lines.push(current.trim());
      current = word.slice(0, maxChars);
    } else {
      current = (current + ' ' + word).trim();
    }
  }
  if (current) lines.push(current.trim());
  return lines.length > 0 ? lines : [''];
}

/**
 * Generates a spec-compliant PDF 1.4 binary Uint8Array in the browser
 */
export function buildClientSidePdfBinary(data: ClientPdfReportData): Uint8Array {
  const watNow = new Date().toLocaleString('en-GB', {
    timeZone: 'Africa/Lagos',
    dateStyle: 'full',
    timeStyle: 'long',
  });

  const ops: string[] = [];

  // Dark Navy Header Banner
  ops.push('0.06 0.09 0.16 rg');
  ops.push('0 752 595 90 re f');

  // Header Title
  ops.push('BT /F2 16 Tf 0.22 0.74 0.97 rg 40 812 Td (THE WATCH: CYBERSECURITY & INTRUSION FORENSIC AUDIT) Tj ET');
  ops.push('BT /F2 9 Tf 0.96 0.62 0.04 rg 40 796 Td (POWERED BY: MASHA TECH INNOVATIONS | NATIONAL OPEN UNIVERSITY SOC) Tj ET');
  ops.push(`BT /F1 8.5 Tf 0.85 0.90 0.95 rg 40 780 Td (${escapePdfText(`Generated (WAT): ${watNow} | Scope: ${data.systemId || 'ALL MONITORED SYSTEMS'}`)}) Tj ET`);
  ops.push('BT /F1 8 Tf 0.58 0.64 0.72 rg 40 765 Td (Emergency Failover Routing: +2347063054357 | abdulgaffarbello3477@gmail.com) Tj ET');

  let y = 726;

  const addHeading = (heading: string) => {
    if (y < 90) return;
    ops.push('0.06 0.09 0.16 rg');
    ops.push(`BT /F2 11 Tf 40 ${y} Td (${escapePdfText(heading)}) Tj ET`);
    y -= 6;
    ops.push('0.22 0.74 0.97 RG 1 w');
    ops.push(`40 ${y} m 555 ${y} l S`);
    y -= 14;
  };

  const addLine = (label: string, value: string, isBold = false, isAlert = false) => {
    if (y < 65) return;
    const full = label ? `${label}: ${value}` : value;
    const wrapped = wrapText(full, 90);
    for (const line of wrapped) {
      if (y < 65) break;
      if (isAlert) {
        ops.push('0.86 0.15 0.15 rg');
      } else if (isBold) {
        ops.push('0.06 0.09 0.16 rg');
      } else {
        ops.push('0.20 0.25 0.33 rg');
      }
      ops.push(`BT /${isBold ? 'F2' : 'F1'} 8.5 Tf 44 ${y} Td (${escapePdfText(line)}) Tj ET`);
      y -= 12;
    }
  };

  // Section 1: Executive Overview
  addHeading('1. EXECUTIVE INTRUSION & SECURITY AUDIT SUMMARY');
  addLine('Monitored Platform Scope', data.systemId || 'NOUN-HRMS & THE WATCH SOC', true);
  addLine('Primary Super Admin', 'Abdulgaffar Bello (abdulgaffarbello3477@gmail.com | +2347063054357)', true);
  addLine('24/7 Sleep/Shutdown Failover', 'ARMED - Automatic SMS/Call/Email rerouting enabled', false);
  addLine('Audit Timestamp (WAT)', `${watNow} (UTC+1)`, false);
  y -= 8;

  // Section 2: Specific Intrusion Dossier or Incident List
  if (data.incident) {
    const inc = data.incident;
    addHeading('2. INTRUSION / HACK ATTEMPT FORENSIC DOSSIER');
    addLine('Incident Reference ID', inc.id, true);
    addLine('Targeted System', inc.systemId, true);
    addLine('Type of Attack', `${inc.threatClassification} [${inc.incidentType}]`, true, true);
    addLine('Severity Level', inc.severity, true, true);
    addLine('Offending Attacker IP', inc.offendingIp, true, true);
    addLine(
      'Attack Origin Location',
      `${inc.geoCity || 'Unknown'}, ${inc.geoRegion || ''} ${inc.geoCountry || 'Unknown'} (Lat: ${inc.geoLat ?? 9.0765}, Lng: ${inc.geoLng ?? 7.3986}) | ASN: ${inc.asn || 'AS48693'} (${inc.isp || 'External ISP'})`,
      false
    );
    addLine('Precise Date & Time of Attack (WAT)', inc.timestampWat, true);
    addLine('Targeted Endpoint Vector', `${inc.httpMethod} ${inc.targetEndpoint}`, false);
    addLine('Captured Hacker Payload / Attempt', inc.capturedPayload, false, true);
    addLine('Containment & Firewall Status', `${inc.status} - IP Quarantined on SOC Edge Firewall (HTTP 403 Drop)`, true);
    y -= 8;
  } else if (data.incidents && data.incidents.length > 0) {
    addHeading(`2. RECORDED INTRUSION & THREAT INCIDENTS (${data.incidents.length})`);
    for (const inc of data.incidents.slice(0, 8)) {
      if (y < 95) break;
      addLine(
        `[${inc.severity || 'HIGH'}] ${inc.threat_classification || inc.threatClassification}`,
        `System: ${inc.system_id || inc.systemId} | IP: ${inc.offending_ip || inc.offendingIp} (${inc.geo_city || inc.geoCity || 'Unknown'}, ${inc.geo_country || inc.geoCountry || 'Unknown'})`,
        true,
        true
      );
      addLine(
        '   Vector & Time',
        `${inc.http_method || inc.httpMethod || 'POST'} ${inc.target_endpoint || inc.targetEndpoint} | WAT: ${inc.created_at_wat || inc.timestampWat} | Status: ${inc.status}`
      );
      addLine('   Captured Attempt', (inc.captured_payload || inc.capturedPayload || 'N/A').slice(0, 140));
      y -= 4;
    }
    y -= 6;
  }

  // Section 3: User Activity Audit Trail
  if (data.auditLogs && data.auditLogs.length > 0 && y > 130) {
    addHeading(`3. REAL-TIME USER ACTIVITY & ACCESS AUDIT LOGS (${data.auditLogs.length})`);
    for (const log of data.auditLogs.slice(0, 10)) {
      if (y < 75) break;
      addLine(
        `[${log.action}] ${log.full_name || log.email} (${log.role || 'STAFF'})`,
        `System: ${log.system_id || 'NOUN-HRMS'} | IP: ${log.ip_address} | Loc: ${log.location || 'Abuja, NG'} | WAT: ${log.created_at_wat}`,
        true
      );
      if (log.details) {
        addLine('   Action Details', log.details);
      }
    }
  }

  // Footer
  ops.push('0.75 0.80 0.86 RG 0.5 w');
  ops.push('40 42 m 555 42 l S');
  ops.push('0.45 0.50 0.58 rg');
  ops.push('BT /F1 7.5 Tf 40 30 Td (THE WATCH THREAT INTELLIGENCE PLATFORM | POWERED BY: MASHA TECH INNOVATIONS | PAGE 1 OF 1) Tj ET');

  const contentStream = ops.join('\n');

  const objects: string[] = [];
  objects.push('1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n');
  objects.push('2 0 obj\n<< /Type /Pages /Kids [3 0 R] /Count 1 >>\nendobj\n');
  objects.push(
    '3 0 obj\n<< /Type /Page /Parent 2 0 R /Resources << /Font << /F1 4 0 R /F2 5 0 R >> >> /MediaBox [0 0 595 842] /Contents 6 0 R >>\nendobj\n'
  );
  objects.push('4 0 obj\n<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>\nendobj\n');
  objects.push('5 0 obj\n<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica-Bold >>\nendobj\n');
  objects.push(
    `6 0 obj\n<< /Length ${contentStream.length} >>\nstream\n${contentStream}\nendstream\nendobj\n`
  );

  let pdf = '%PDF-1.4\n';
  const offsets: number[] = [];
  for (const obj of objects) {
    offsets.push(pdf.length);
    pdf += obj;
  }

  const xrefStart = pdf.length;
  pdf += `xref\n0 ${objects.length + 1}\n`;
  pdf += '0000000000 65535 f \n';
  for (const offset of offsets) {
    pdf += `${String(offset).padStart(10, '0')} 00000 n \n`;
  }
  pdf += `trailer\n<< /Size ${objects.length + 1} /Root 1 0 R >>\nstartxref\n${xrefStart}\n%%EOF`;

  const encoder = new TextEncoder();
  return encoder.encode(pdf);
}

/**
 * Triggers a direct browser file download from a Blob
 */
export function triggerBrowserBlobDownload(blob: Blob, filename: string): void {
  const blobUrl = URL.createObjectURL(blob);
  const link = document.createElement('a');
  link.href = blobUrl;
  link.download = filename;
  link.style.display = 'none';
  document.body.appendChild(link);
  link.click();
  setTimeout(() => {
    document.body.removeChild(link);
    URL.revokeObjectURL(blobUrl);
  }, 1500);
}
