# Sentinel Agent Middleware (`@the-watch/sentinel-agent`)

Zero-overhead, non-blocking telemetry and observability middleware designed for **NOUN-HRMS** and institutional microservices to ship telemetry to **The Watch**.

---

## 🚀 3-Line Integration (Express / Node.js)

```typescript
import express from 'express';
import { createSentinelMiddleware } from '@the-watch/sentinel-agent';

const app = express();

// 1. Mount Sentinel Agent as the first middleware
app.use(createSentinelMiddleware({
  systemId: 'NOUN-HRMS',
  apiKey: 'tel_sec_noun_hrms_98234',
  apiSecret: 'sec_sig_noun_8849204',
  endpoint: 'http://watchdog.internal.noun.edu.ng:4000/api/v1/telemetry/ingest',
  transport: 'HTTP', // or 'UDP' for zero-overhead background socket shipping
  batchIntervalMs: 2000,
}));

app.listen(3000);
```

---

## ⚡ Zero Performance Degradation Guarantee
- **Non-blocking**: Logs are stored in an in-memory ring-buffer and shipped in batches every 2 seconds.
- **Fail-safe**: If The Watch server is temporarily unreachable, requests continue normally without throwing errors or increasing user response times.
- **UDP Mode**: Support for ultra-low latency UDP datagram shipping over port 9876.
