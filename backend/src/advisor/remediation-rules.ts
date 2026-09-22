export interface RemediationDiagnosis {
  id: string;
  patternName: string;
  incidentSummary: string;
  suspectedRootCause: string;
  severity: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
  mitigationBlueprint: string;
  codePatch: string;
  infrastructureFix: string;
  recommendedAction: string;
}

export const REMEDIATION_RULES: Record<string, RemediationDiagnosis> = {
  NEON_POOLER_EXHAUSTION: {
    id: 'RULE-NEON-001',
    patternName: 'Neon Pooler Connection Timeout & Pool Saturation',
    incidentSummary:
      'Neon Serverless Postgres connection timeout detected. Multiple client requests are queuing and timing out waiting for available connections in the pool.',
    suspectedRootCause:
      'Connection leak in payroll batch controller or unclosed client handles during concurrent institutional sync operations, exhausting max connection slots.',
    severity: 'CRITICAL',
    mitigationBlueprint:
      'Configure transactional pooling via Neon pgBouncer, set explicit client idle timeouts, and enforce strict try/finally connection release blocks.',
    codePatch: `// ================= MITIGATION CODE PATCH (Database Pool) =================
// 1. Update Neon Connection String in .env to use pgBouncer pooled port 6543:
// DATABASE_URL="postgresql://user:pass@ep-cool-pool.neon.tech:6543/neondb?sslmode=require&pgbouncer=true"

// 2. Wrap batch handlers in reliable try-finally release pattern:
import { pool } from '../db';

export async function processPayrollBatch(batchId: string) {
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    // perform batch mutations
    await client.query('COMMIT');
  } catch (error) {
    await client.query('ROLLBACK');
    throw error;
  } finally {
    client.release(); // CRITICAL: Guarantees connection slot return
  }
}`,
    infrastructureFix: `// ================= INFRASTRUCTURE FIX =================
# Set pgBouncer pool limits in Neon Console or helm values:
default_pool_size = 25
max_client_conn = 500
reserve_pool_size = 5
server_idle_timeout = 15`,
    recommendedAction: 'Apply pgBouncer connection string and deploy try-finally release patch immediately.',
  },

  RENDER_MEMORY_EXHAUSTION: {
    id: 'RULE-RENDER-002',
    patternName: 'Render Container Memory Limit & OOM Spike',
    incidentSummary:
      'Render Web Service memory limit exceeded (JavaScript heap out of memory / error code 137). Container experienced restart.',
    suspectedRootCause:
      'Unbuffered in-memory JSON array accumulation of 50,000+ staff records during monthly institutional payroll audit export.',
    severity: 'HIGH',
    mitigationBlueprint:
      'Increase Node.js V8 old space ceiling to 2048MB and refactor synchronous in-memory collection to a streaming pipeline.',
    codePatch: `// ================= STREAMING PIPELINE PATCH =================
// Replace in-memory array serialization with Node Stream Pipeline:
import QueryStream from 'pg-query-stream';
import { pipeline } from 'stream/promises';
import { createGzip } from 'zlib';

export async function streamPayrollExport(res: Response, tenantId: string) {
  const client = await pool.connect();
  try {
    const query = new QueryStream(
      'SELECT id, staff_no, salary, created_at FROM payroll_records WHERE tenant_id = $1',
      [tenantId]
    );
    const stream = client.query(query);
    
    res.setHeader('Content-Type', 'application/json');
    res.setHeader('Content-Disposition', 'attachment; filename="payroll-export.json"');
    
    await pipeline(stream, res);
  } finally {
    client.release();
  }
}`,
    infrastructureFix: `// ================= RENDER ENVIRONMENT CONFIGURATION =================
# Add environment variable in Render Dashboard -> Environment Settings:
NODE_OPTIONS = "--max-old-space-size=2048"
WEB_CONCURRENCY = "1"`,
    recommendedAction: 'Set NODE_OPTIONS to 2048MB and switch batch export endpoints to stream pipelines.',
  },

  COTURN_UDP_UNREACHABLE: {
    id: 'RULE-COTURN-003',
    patternName: 'Coturn WebRTC Relay UDP Port Unreachable',
    incidentSummary:
      'Coturn WebRTC Relay UDP port 3478 is unreachable or dropping candidate packets, causing video dispatch relay stalls.',
    suspectedRootCause:
      'Host cloud firewall or UFW security group rules blocking inbound UDP traffic on ports 3478 and dynamic relay range 49152-65535.',
    severity: 'HIGH',
    mitigationBlueprint:
      'Open UDP 3478 and ephemeral relay ports in firewall, and configure external public IP mapping in /etc/turnserver.conf.',
    codePatch: `// ================= COTURN CONFIGURATION (/etc/turnserver.conf) =================
listening-port=3478
tls-listening-port=5349
listening-ip=0.0.0.0
external-ip=102.89.23.45 # Public IP of NOUN Security Dispatch Gateway
min-port=49152
max-port=65535
fingerprint
lt-cred-mech
realm=institution.edu.ng`,
    infrastructureFix: `// ================= LINUX FIREWALL / UFW COMMANDS =================
sudo ufw allow 3478/tcp
sudo ufw allow 3478/udp
sudo ufw allow 5349/tcp
sudo ufw allow 5349/udp
sudo ufw allow 49152:65535/udp
sudo systemctl restart coturn`,
    recommendedAction: 'Execute UFW firewall port-opening commands and restart coturn service.',
  },

  DATABASE_SLOW_QUERY: {
    id: 'RULE-SQL-004',
    patternName: 'Unindexed Database Query Latency Spike (>200ms)',
    incidentSummary:
      'Severe database query execution latency (exceeding 200ms threshold) detected on high-frequency payroll and employee tables.',
    suspectedRootCause:
      'Missing composite index on payroll_records(tenant_id, status, created_at) causing sequential table scans across millions of rows.',
    severity: 'MEDIUM',
    mitigationBlueprint:
      'Create concurrent B-Tree index on high-cardinality filter columns to reduce query duration from 800ms+ to <5ms.',
    codePatch: `// ================= POSTGRESQL OPTIMIZATION DDL =================
-- Execute concurrently to prevent locking active production transactions:
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_payroll_tenant_status_created 
ON payroll_records (tenant_id, status, created_at DESC);

-- Analyze statistics post-indexing:
ANALYZE payroll_records;`,
    infrastructureFix: `// ================= QUERY TUNING GUIDELINES =================
-- Check query execution plan using EXPLAIN ANALYZE:
EXPLAIN ANALYZE 
SELECT * FROM payroll_records 
WHERE tenant_id = 'NOUN-HRMS' AND status = 'PENDING' 
ORDER BY created_at DESC LIMIT 50;`,
    recommendedAction: 'Deploy CONCURRENT index migration in production database.',
  },

  SSL_EXPIRY_WARNING: {
    id: 'RULE-SSL-005',
    patternName: 'SSL/TLS Certificate Impending Expiration (<7 Days)',
    incidentSummary:
      'Monitored system HTTPS certificate will expire in under 7 days. Risk of browser security warnings and API client drops.',
    suspectedRootCause:
      'Automated Certbot ACME challenge renewal cron job failed or stalled due to reverse proxy port 80 routing misconfiguration.',
    severity: 'HIGH',
    mitigationBlueprint:
      'Trigger immediate Certbot renewal and verify nginx ACME challenge path routing.',
    codePatch: `// ================= NGINX ACME CHALLENGE CONFIGURATION =================
server {
    listen 80;
    server_name hrms.noun.edu.ng;
    
    location /.well-known/acme-challenge/ {
        root /var/www/certbot;
    }
    
    location / {
        return 301 https://$host$request_uri;
    }
}`,
    infrastructureFix: `// ================= CERTBOT RENEWAL COMMAND =================
sudo certbot renew --webroot -w /var/www/certbot --force-renewal
sudo systemctl reload nginx`,
    recommendedAction: 'Execute manual certbot renewal and test HTTPS handshake.',
  },
};
