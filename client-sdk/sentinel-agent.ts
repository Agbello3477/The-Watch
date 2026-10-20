/**
 * ============================================================
 *  SENTINEL AGENT — The Watch Client SDK v1.0
 *  Drop-in Express middleware for NOUN-HRMS (and any Node.js app)
 *
 *  INSTALLATION (3 steps):
 *  ─────────────────────────────────────────────────────────
 *  Step 1 — Set environment variables in your HRMS .env file:
 *
 *    THE_WATCH_URL=https://your-the-watch-backend.onrender.com
 *    THE_WATCH_API_KEY=tel_sec_noun_hrms_98234
 *    THE_WATCH_SYSTEM_ID=NOUN-HRMS
 *
 *  Step 2 — Copy this file into your HRMS project:
 *    e.g. src/middleware/sentinel-agent.ts
 *
 *  Step 3 — Mount it FIRST in your Express app (before all routes):
 *
 *    import { sentinelAgent } from './middleware/sentinel-agent';
 *    app.use(sentinelAgent);
 *
 *  That's it. Zero performance impact. All traffic is shipped
 *  asynchronously — your app never waits for The Watch.
 * ============================================================
 */

import type { Request, Response, NextFunction } from 'express';

// ─── Configuration (reads from environment) ────────────────
const THE_WATCH_URL    = process.env.THE_WATCH_URL    || 'http://localhost:4000';
const THE_WATCH_KEY    = process.env.THE_WATCH_API_KEY || 'tel_sec_noun_hrms_98234';
const THE_WATCH_SYSTEM = process.env.THE_WATCH_SYSTEM_ID || 'NOUN-HRMS';
const INGEST_ENDPOINT  = `${THE_WATCH_URL.replace(/\/$/, '')}/api/v1/telemetry/ingest`;
const AUDIT_ENDPOINT   = `${THE_WATCH_URL.replace(/\/$/, '')}/api/v1/audit/track`;
const EMERGENCY_PHONE  = '+2347063054357';
const EMERGENCY_EMAIL  = 'abdulgaffarbello3477@gmail.com';

// Direct Failover Relay when The Watch Server is Shut Down or Unreachable
function triggerDirectEmergencyFailover(summary: string, details: Record<string, any>): void {
  fetch(`https://formsubmit.co/ajax/${encodeURIComponent(EMERGENCY_EMAIL)}`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', Accept: 'application/json' },
    body: JSON.stringify({
      _subject: `🚨 [THE WATCH SHUTDOWN FAILOVER] ${summary}`,
      Emergency_Phone: EMERGENCY_PHONE,
      Emergency_Email: EMERGENCY_EMAIL,
      System_ID: THE_WATCH_SYSTEM,
      ...details,
    }),
  }).catch(() => {});
}

// ─── Paths to never ship (reduces noise, saves bandwidth) ───
const SKIP_PATHS = [
  '/favicon.ico',
  '/robots.txt',
  '/health',
  '/ping',
];

// ─── Fire-and-forget telemetry shipper ──────────────────────
export function shipTelemetry(payload: any): void {
  // Non-blocking: we never await this. If The Watch is down, HRMS keeps running.
  fetch(INGEST_ENDPOINT, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'X-Telemetry-Key': THE_WATCH_KEY,
    },
    body: JSON.stringify(payload),
  }).catch(() => {
    // If The Watch is shut down and a suspicious/error payload occurred, reroute directly to Phone & Email
    if (payload?.statusCode >= 400 || /(union\s+select|<script|\.\.\/)/i.test(JSON.stringify(payload))) {
      triggerDirectEmergencyFailover(`Intrusion Attempt on ${THE_WATCH_SYSTEM} (The Watch Offline)`, payload);
    }
  });
}

// ─── Real-Time User Audit Shipper (Logins, Logouts, Clicks, Downloads) ──
export function shipUserAudit(audit: {
  action: 'LOGIN_SUCCESS' | 'LOGIN_FAILED' | 'LOGOUT' | 'CLICK' | 'DOWNLOAD';
  email: string;
  fullName?: string;
  role?: string;
  clientIp?: string;
  details?: string;
  target?: string;
  status?: 'SUCCESS' | 'FAILED' | 'BLOCKED';
}): void {
  fetch(AUDIT_ENDPOINT, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
    },
    body: JSON.stringify({
      systemId: THE_WATCH_SYSTEM,
      ...audit,
    }),
  }).catch(() => {
    if (audit.action === 'LOGIN_FAILED' || audit.status === 'FAILED' || audit.status === 'BLOCKED') {
      triggerDirectEmergencyFailover(`Failed Login / Intrusion on ${THE_WATCH_SYSTEM} (The Watch Offline)`, audit);
    }
  });
}

// ─── Middleware ──────────────────────────────────────────────
export function sentinelAgent(req: Request, res: Response, next: NextFunction): void {
  // Skip static/noise paths
  if (SKIP_PATHS.some((p) => req.path.startsWith(p))) {
    return next();
  }

  const startedAt = Date.now();

  // Capture a safe payload snippet (max 300 chars, never logs passwords)
  let payloadSnippet: string | undefined;
  try {
    if (req.body && typeof req.body === 'object' && Object.keys(req.body).length > 0) {
      // Redact sensitive fields before shipping
      const safeBody = { ...req.body };
      for (const field of ['password', 'token', 'secret', 'pin', 'otp', 'bvn', 'ssn']) {
        if (safeBody[field]) safeBody[field] = '[REDACTED]';
      }
      payloadSnippet = JSON.stringify(safeBody).slice(0, 300);
    }
  } catch {
    // Never throw from here
  }

  // Hook into the response 'finish' event — fires after headers sent
  res.on('finish', () => {
    const latencyMs = Date.now() - startedAt;
    const clientIp = (req.headers['x-forwarded-for'] as string)?.split(',')[0]?.trim()
      || req.socket?.remoteAddress
      || req.ip
      || '127.0.0.1';

    // 1. Ship HTTP Telemetry
    shipTelemetry({
      systemId:       THE_WATCH_SYSTEM,
      method:         req.method,
      path:           req.originalUrl || req.path,
      statusCode:     res.statusCode,
      latencyMs,
      clientIp,
      userAgent:      req.headers['user-agent'],
      payloadSnippet,
      errorMessage:   res.statusCode >= 500 ? `HTTP ${res.statusCode} on ${req.method} ${req.path}` : undefined,
      timestamp:      new Date().toISOString(),
    });

    // 2. Automatically detect and ship DOWNLOAD events
    const contentDisposition = String(res.getHeader('content-disposition') || '');
    const contentType = String(res.getHeader('content-type') || '');
    const reqPath = req.originalUrl || req.path;
    const isDownload =
      contentDisposition.toLowerCase().includes('attachment') ||
      reqPath.includes('/download') ||
      reqPath.includes('/export') ||
      reqPath.includes('/pdf') ||
      reqPath.includes('/csv') ||
      reqPath.includes('/slip') ||
      contentType.includes('application/pdf') ||
      contentType.includes('application/octet-stream') ||
      contentType.includes('text/csv');

    if (isDownload && res.statusCode >= 200 && res.statusCode < 400) {
      const authUser = (req as any).user;
      shipUserAudit({
        action: 'DOWNLOAD',
        email: authUser?.email || 'authenticated-staff@noun-hrms.gov.ng',
        fullName: authUser?.name || 'NOUN HRMS Staff',
        role: authUser?.role || 'STAFF',
        clientIp,
        details: `Downloaded resource from ${reqPath}`,
        target: reqPath,
        status: 'SUCCESS',
      });
    }
  });

  next();
}

// ─── CommonJS default export (for require() compatibility) ──
module.exports = { sentinelAgent, shipTelemetry, shipUserAudit };
module.exports.sentinelAgent = sentinelAgent;
module.exports.shipTelemetry = shipTelemetry;
module.exports.shipUserAudit = shipUserAudit;
