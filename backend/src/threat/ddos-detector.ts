import { redis } from '../redis/client';
import { heuristicEngine } from './heuristic-engine';

export interface AnomalyDetectionResult {
  isAnomaly: boolean;
  anomalyType: 'DDOS_RATE_SPIKE' | 'CREDENTIAL_STUFFING_BURST' | 'NONE';
  severity: 'MEDIUM' | 'HIGH' | 'CRITICAL';
  description: string;
  mitigationBlueprint: string;
}

export class DDoSAndRateAnomalyDetector {
  private readonly MAX_REQ_PER_SEC = 50;
  private readonly MAX_AUTH_FAILS_PER_MIN = 15;

  /**
   * Tracks request frequency and 4xx auth bursts per IP/subnet
   */
  public async trackAndInspect(data: {
    clientIp: string;
    path: string;
    statusCode: number;
  }): Promise<AnomalyDetectionResult> {
    const { clientIp, path, statusCode } = data;

    // 1. Sliding Window: Requests per 1 second
    const secKey = `ddos:window:${clientIp}`;
    const reqCountInLastSec = await redis.incrementWindow(secKey, 1);

    if (reqCountInLastSec > this.MAX_REQ_PER_SEC) {
      return {
        isAnomaly: true,
        anomalyType: 'DDOS_RATE_SPIKE',
        severity: 'CRITICAL',
        description: `DDoS Anomaly: IP ${clientIp} dispatched ${reqCountInLastSec} req/sec (Threshold: ${this.MAX_REQ_PER_SEC} req/sec). Potential Layer 7 volumetric flood attack.`,
        mitigationBlueprint: heuristicEngine.generateWafMitigation(clientIp, path, 'L7_DDoS_Flood'),
      };
    }

    // 2. Track 401/403 auth failures on authentication routes
    const isAuthRoute = path.includes('/login') || path.includes('/auth') || path.includes('/session') || path.includes('/token');
    const isAuthFailure = statusCode === 401 || statusCode === 403;

    if (isAuthRoute && isAuthFailure) {
      const authFailKey = `auth:fail:counter:${clientIp}`;
      const failCountInMin = await redis.incrementCounter(authFailKey, 60);

      if (failCountInMin >= this.MAX_AUTH_FAILS_PER_MIN) {
        return {
          isAnomaly: true,
          anomalyType: 'CREDENTIAL_STUFFING_BURST',
          severity: 'HIGH',
          description: `Credential Stuffing Alert: IP ${clientIp} generated ${failCountInMin} failed authentication attempts in 60s targeting ${path}. Automated brute-force credential stuffing suspected.`,
          mitigationBlueprint: heuristicEngine.generateWafMitigation(clientIp, path, 'Credential_Stuffing'),
        };
      }
    }

    return {
      isAnomaly: false,
      anomalyType: 'NONE',
      severity: 'MEDIUM',
      description: 'Normal traffic profile',
      mitigationBlueprint: '',
    };
  }
}

export const ddosDetector = new DDoSAndRateAnomalyDetector();
