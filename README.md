# 🛡️ The Watch: Enterprise Monitoring, Observability & Threat Intelligence Platform

> **Powered by: MaSha Tech Innovations**  
> External watchdog, synthetic endpoint prober, and pre-attack heuristic detection gateway designed for **NOUN-HRMS** and institutional microservices with **zero host performance degradation**.

---

## 📌 Architecture Overview

```
+----------------------------------------------------------------------------------------------------+
|                                      THE WATCH ARCHITECTURE                                        |
+----------------------------------------------------------------------------------------------------+

   [ Monitored System: NOUN-HRMS ]               [ Monitored System: Clinic-EHR / Security-Dispatch ]
                 |                                                   |
                 | (sentinel-agent.ts Middleware)                    | (sentinel-agent.ts Middleware)
                 | Non-blocking Ingest (HTTP / UDP async stream)     |
                 v                                                   v
   +-------------------------------------------------------------------------------------------------+
   |                                 THE WATCH INGESTION ENGINE                                      |
   |                                                                                                 |
   |   - HTTP Ingest Gateway (POST /api/v1/telemetry/ingest) with HMAC-SHA256 Token Verification     |
   |   - UDP Ingest Gateway (UDP Socket 9876) for zero-overhead background log shipping              |
   |   - Ingest Queue & Ring-Buffer (Redis Stream / Memory Buffer) for high-throughput buffering     |
   +-------------------------------------------------------------------------------------------------+
                                               |
       +---------------------------------------+--------------------------------------+
       |                                       |                                      |
       v                                       v                                      v
+-------------------------------+ +-------------------------------+ +--------------------------------+
|    THREAT DETECTION ENGINE    | |    HEALTH & PROBER ENGINE     | |   SELF-HEALING ADVISOR ENGINE  |
|                               | |                               | |                                |
| - SQLi Pattern Heuristics     | | - Heartbeat Cron (30-60s)     | | - Root Cause Diagnostic Matrix |
| - XSS Script Injection        | | - TTFB, DNS, TCP, SSL Expiry  | | - Neon Pooler Exhaustion       |
| - Directory Traversal / LFI   | | - Latency Spike Tracker       | | - Render Memory Out-of-Memory  |
| - Credential Stuffing Detector| | - 5xx Spike & 4xx Auth Bursts | | - Coturn WebRTC Relay Stall    |
| - Rate Limiter & DDoS Detector| | - Database Query Profiler     | | - Actionable Code/Config Patch |
| - MaxMind / IPinfo GeoIP ASN  | |   (Queries > 200ms, pool sat) | |   Generation                   |
| - Reverse DNS & Tor/Proxy Flag| |                               | |                                |
+-------------------------------+ +-------------------------------+ +--------------------------------+
               \                               |                               /
                \                              |                              /
                 v                             v                             v
   +-------------------------------------------------------------------------------------------------+
   |                                DATA STORAGE & PERSISTENCE LAYER                                 |
   |                                                                                                 |
   |   - PostgreSQL (with zero-config SQLite dual-mode): Historical Audit Logs, Incidents, Probes   |
   |   - Redis (with high-throughput memory ring-buffer fallback): Metrics Aggregation & Windows     |
   +-------------------------------------------------------------------------------------------------+
                                               |
       +---------------------------------------+--------------------------------------+
       |                                                                              |
       v                                                                              v
+------------------------------------------------+ +-------------------------------------------------+
|     FORENSIC AUDIT REPORT ENGINE (PDF / CSV)   | |      DISPATCH & ESCALATION ENGINE               |
|                                                | |                                                 |
| - PDFKit Forensic Report with WAT Timestamps   | | - Email Dispatcher (SMTP / SendGrid Simulation) |
| - Executive Health Score (0-100%)              | | - Multi-Channel Webhook Dispatch                |
| - Incident Forensics & Attack Payloads         | |   (Slack, Discord, Telegram, Generic)           |
| - Cloudflare WAF / Nginx Mitigation Blueprints | | - Admin Incident Escalation & Acknowledgment    |
| - Raw CSV Log Export Stream                    | |   State Machine                                 |
+------------------------------------------------+ +-------------------------------------------------+
                                               |
                                               v
+----------------------------------------------------------------------------------------------------+
|                         ADMINISTRATIVE DASHBOARD (React + Tailwind CSS)                            |
|                                                                                                    |
| - Dark-slate Enterprise Command Center                                                             |
| - Live Health Gauges & Platform Reliability Score                                                  |
| - Interactive Global Threat Map (Live Pulsing Threat Nodes, GeoIP, Clusters)                       |
| - Real-time Incident Feed with Severity Filtering & Admin Triage Desk                              |
| - Database Query Latency & Slow Query Analyzer (>200ms)                                            |
| - Automated Remediation Advisor Panel with 1-Click Code Patches                                    |
| - Synthetic Probe Monitor (TTFB, SSL Expiry Countdown, Uptime %)                                   |
| - Forensic Audit Report Generator (Instant PDF & CSV Downloads)                                    |
| - Live Attack & Failure Simulator to trigger realistic SQLi, XSS, DDoS, and Probe failures        |
+----------------------------------------------------------------------------------------------------+
```

---

## ⚡ Core Capabilities

1. **Multi-Tenant Ingest**:
   - Cryptographically isolated tenants (`NOUN-HRMS`, `Clinic-EHR`, `Security-Dispatch`) with HMAC-SHA256 verification.
   - Non-blocking HTTP (`POST /api/v1/telemetry/ingest`) and UDP datagram listener (`0.0.0.0:9876/udp`).
2. **Synthetic Heartbeat Engine**:
   - 30–60s cron prober measuring TTFB, DNS lookup, TCP handshake, and SSL certificate expiration.
3. **Pre-Attack & Heuristic Threat Detection**:
   - Real-time detection of SQL Injection (`UNION SELECT`, `' OR 1=1`), XSS (`<script>`, DOM handlers), Directory Traversal (`../`), and Credential Stuffing bursts.
   - Volumetric Layer 7 DDoS anomaly triggers (>50 req/sec).
   - GeoIP, ASN (`AS29465 MTN`, `AS37075 MainOne`, `AS208294 Tor Exit`), and Proxy/Tor exit node identification.
4. **Self-Healing & Remediation Advisor**:
   - Automated root-cause diagnosis and actionable code/infrastructure patches for Neon Pooler exhaustion, Render Memory OOM, Coturn UDP stalls, and unindexed database queries (>200ms).
5. **Forensic Audit Reports (PDF & CSV)**:
   - Downloadable executive PDF reports formatted with West Africa Time (**WAT / UTC+1**) timestamps, health scores, and Cloudflare WAF block blueprints.
6. **Plug-and-Play Sentinel Agent Middleware**:
   - Under 70 lines zero-dependency middleware for Express/Next.js/Node.

---

## 🚀 Quickstart Guide

### 1. Run with Docker Compose (Recommended)
```bash
docker compose up --build -d
```
Access the Dashboard at **`http://localhost`** (Port 80) and Backend at **`http://localhost:4000`**.

### 2. Run Locally in Development

#### Prerequisites
- Node.js v20+
- npm v10+

```bash
# Start Backend Gateway (Port 4000 & UDP 9876)
cd backend
npm install
npm run dev

# Start SOC Frontend Dashboard (Port 5173)
cd ../frontend
npm install
npm run dev
```

---

## 🧪 Running Automated Tests
The platform includes 22 comprehensive unit and integration tests across 6 suites:

```bash
cd backend
npm test
```

---

## 📦 Integrating Sentinel Agent (3 Lines of Code)

```typescript
import express from 'express';
import { createSentinelMiddleware } from '@the-watch/sentinel-agent';

const app = express();

app.use(createSentinelMiddleware({
  systemId: 'NOUN-HRMS',
  apiKey: 'tel_sec_noun_hrms_98234',
  apiSecret: 'sec_sig_noun_8849204',
  endpoint: 'http://localhost:4000/api/v1/telemetry/ingest',
  transport: 'HTTP', // or 'UDP' on port 9876
}));
```

---

## 📄 License
Classified Institutional Security Software • Powered by **MaSha Tech Innovations** for National Open University Security Operations Center (SOC).
