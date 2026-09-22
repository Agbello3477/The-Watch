import { ThreatIncident } from '../db/database';

export function renderEmailAlertTemplate(incident: ThreatIncident): { subject: string; html: string; text: string } {
  const subject = `[CRITICAL ALERT - THE WATCH] ${incident.threat_classification} on ${incident.system_id}`;
  
  const html = `
<!DOCTYPE html>
<html>
<head>
  <style>
    body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif; background-color: #0f172a; color: #f8fafc; padding: 20px; }
    .card { background-color: #1e293b; border: 1px solid #334155; border-radius: 8px; padding: 24px; max-width: 600px; margin: 0 auto; }
    .badge-critical { background-color: #ef4444; color: #ffffff; padding: 4px 10px; border-radius: 4px; font-weight: bold; font-size: 12px; display: inline-block; }
    .badge-high { background-color: #f97316; color: #ffffff; padding: 4px 10px; border-radius: 4px; font-weight: bold; font-size: 12px; display: inline-block; }
    .title { font-size: 20px; font-weight: bold; color: #38bdf8; margin-top: 12px; }
    .field { margin: 12px 0; }
    .label { color: #94a3b8; font-size: 12px; text-transform: uppercase; letter-spacing: 0.05em; }
    .val { color: #f1f5f9; font-size: 15px; font-family: monospace; background: #0f172a; padding: 8px 12px; border-radius: 4px; margin-top: 4px; word-break: break-all; }
    .mitigation { background: #1e1e38; border-left: 4px solid #6366f1; padding: 12px; border-radius: 4px; margin-top: 16px; }
    .footer { text-align: center; color: #64748b; font-size: 12px; margin-top: 24px; }
  </style>
</head>
<body>
  <div class="card">
    <div>
      <span class="${incident.severity === 'CRITICAL' ? 'badge-critical' : 'badge-high'}">${incident.severity} SEVERITY</span>
      <span style="color: #94a3b8; font-size: 13px; margin-left: 10px;">${incident.created_at_wat}</span>
    </div>
    
    <div class="title">${incident.threat_classification}</div>
    
    <div class="field">
      <div class="label">Monitored System</div>
      <div class="val">${incident.system_id}</div>
    </div>

    <div class="field">
      <div class="label">Target Endpoint & Method</div>
      <div class="val">${incident.http_method} ${incident.target_endpoint}</div>
    </div>

    <div class="field">
      <div class="label">Origin Forensics (IP & Geolocation)</div>
      <div class="val">${incident.offending_ip} | ${incident.geo_city}, ${incident.geo_country} (${incident.asn} - ${incident.isp})</div>
    </div>

    <div class="field">
      <div class="label">Captured Attack Vector / Payload</div>
      <div class="val">${incident.captured_payload || 'N/A'}</div>
    </div>

    <div class="mitigation">
      <div class="label" style="color: #a5b4fc;">Automated Mitigation Blueprint</div>
      <pre style="color: #e2e8f0; font-size: 12px; margin-top: 6px; white-space: pre-wrap;">${incident.mitigation_blueprint}</pre>
    </div>

    <div class="footer">
      Dispatched automatically by <strong>The Watch Threat Intelligence Platform</strong>.<br/>
      National Open University Security Operations Center (SOC).
    </div>
  </div>
</body>
</html>
`;

  const text = `
[THE WATCH - THREAT ALERT]
Severity: ${incident.severity}
System: ${incident.system_id}
Timestamp: ${incident.created_at_wat}
Classification: ${incident.threat_classification}
Target: ${incident.http_method} ${incident.target_endpoint}
Origin: ${incident.offending_ip} (${incident.geo_city}, ${incident.geo_country} | ${incident.asn})
Payload: ${incident.captured_payload}

Mitigation Blueprint:
${incident.mitigation_blueprint}
`;

  return { subject, html, text };
}

export function renderSlackPayload(incident: ThreatIncident) {
  const color = incident.severity === 'CRITICAL' ? '#ef4444' : incident.severity === 'HIGH' ? '#f97316' : '#eab308';
  return {
    attachments: [
      {
        color,
        title: `🚨 [${incident.severity}] ${incident.threat_classification}`,
        fields: [
          { title: 'System', value: incident.system_id, short: true },
          { title: 'Time (WAT)', value: incident.created_at_wat, short: true },
          { title: 'Target', value: `${incident.http_method} ${incident.target_endpoint}`, short: false },
          { title: 'Origin IP', value: `${incident.offending_ip} (${incident.geo_city}, ${incident.geo_country})`, short: true },
          { title: 'ASN / Network', value: `${incident.asn} - ${incident.isp}`, short: true },
          { title: 'Payload', value: `\`${incident.captured_payload || 'N/A'}\``, short: false },
        ],
        footer: 'The Watch Security Gateway',
        ts: Math.floor(Date.now() / 1000),
      },
    ],
  };
}
