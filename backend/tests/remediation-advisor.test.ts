import { describe, it, expect } from 'vitest';
import { AdvisorService } from '../src/advisor/advisor-service';
import { REMEDIATION_RULES } from '../src/advisor/remediation-rules';

describe('Self-Healing & Remediation Advisor Engine', () => {
  const advisor = new AdvisorService();

  it('should diagnose Neon Pooler connection exhaustion and generate pgBouncer patch', () => {
    const errorMsg = 'FATAL: remaining connection slots are reserved for non-replication superuser connections (Neon pooler timeout: failed to checkout a connection)';
    const diagnosis = advisor.diagnose({ errorMessage: errorMsg });

    expect(diagnosis).not.toBeNull();
    expect(diagnosis?.id).toBe('RULE-NEON-001');
    expect(diagnosis?.patternName).toContain('Neon Pooler');
    expect(diagnosis?.severity).toBe('CRITICAL');
    expect(diagnosis?.codePatch).toContain('pgBouncer');
    expect(diagnosis?.codePatch).toContain('client.release()');
  });

  it('should diagnose Render Memory Exhaustion (OOM) and provide streaming pipeline patch', () => {
    const errorMsg = '<--- Last few GCs ---> JavaScript heap out of memory. Container exited with code 137';
    const diagnosis = advisor.diagnose({ errorMessage: errorMsg });

    expect(diagnosis).not.toBeNull();
    expect(diagnosis?.id).toBe('RULE-RENDER-002');
    expect(diagnosis?.patternName).toContain('Render Container Memory');
    expect(diagnosis?.codePatch).toContain('QueryStream');
    expect(diagnosis?.infrastructureFix).toContain('--max-old-space-size=2048');
  });

  it('should diagnose Coturn UDP WebRTC relay stalls and output firewall UFW commands', () => {
    const errorMsg = 'Coturn WebRTC relay stall: UDP port 3478 unreachable or candidate packet dropped';
    const diagnosis = advisor.diagnose({ errorMessage: errorMsg });

    expect(diagnosis).not.toBeNull();
    expect(diagnosis?.id).toBe('RULE-COTURN-003');
    expect(diagnosis?.infrastructureFix).toContain('sudo ufw allow 3478/udp');
    expect(diagnosis?.codePatch).toContain('listening-port=3478');
  });

  it('should diagnose database slow queries exceeding 200ms and generate concurrent index DDL', () => {
    const diagnosis = advisor.diagnose({ queryDurationMs: 840.5 });

    expect(diagnosis).not.toBeNull();
    expect(diagnosis?.id).toBe('RULE-SQL-004');
    expect(diagnosis?.codePatch).toContain('CREATE INDEX CONCURRENTLY');
  });
});
