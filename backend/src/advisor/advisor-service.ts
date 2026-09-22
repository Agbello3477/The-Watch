import { REMEDIATION_RULES, RemediationDiagnosis } from './remediation-rules';

export class AdvisorService {
  /**
   * Diagnoses an error message, stack trace, or incident context
   */
  public diagnose(context: {
    errorMessage?: string;
    targetPath?: string;
    queryDurationMs?: number;
    sslDaysRemaining?: number;
    systemId?: string;
  }): RemediationDiagnosis | null {
    const errorText = (context.errorMessage || '').toLowerCase();

    // 1. Neon Pooler / Connection Timeout
    if (
      errorText.includes('timeout') && (errorText.includes('neon') || errorText.includes('pool') || errorText.includes('connection')) ||
      errorText.includes('remaining connection slots are reserved') ||
      errorText.includes('timeout: failed to checkout a connection')
    ) {
      return REMEDIATION_RULES.NEON_POOLER_EXHAUSTION;
    }

    // 2. Render Memory Exhaustion / OOM
    if (
      errorText.includes('heap out of memory') ||
      errorText.includes('javascript heap') ||
      errorText.includes('sigkill') ||
      errorText.includes('oom') ||
      errorText.includes('exit code 137')
    ) {
      return REMEDIATION_RULES.RENDER_MEMORY_EXHAUSTION;
    }

    // 3. Coturn UDP / WebRTC Unreachable
    if (
      errorText.includes('coturn') ||
      errorText.includes('udp') && errorText.includes('3478') ||
      errorText.includes('webrtc relay stall') ||
      errorText.includes('turn server unreachable')
    ) {
      return REMEDIATION_RULES.COTURN_UDP_UNREACHABLE;
    }

    // 4. Database Slow Query
    if (context.queryDurationMs && context.queryDurationMs > 200) {
      return REMEDIATION_RULES.DATABASE_SLOW_QUERY;
    }

    // 5. SSL Expiry
    if (context.sslDaysRemaining !== undefined && context.sslDaysRemaining <= 7) {
      return REMEDIATION_RULES.SSL_EXPIRY_WARNING;
    }

    return null;
  }

  public getAllRules(): RemediationDiagnosis[] {
    return Object.values(REMEDIATION_RULES);
  }
}

export const advisorService = new AdvisorService();
