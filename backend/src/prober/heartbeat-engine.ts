import http from 'http';
import https from 'https';
import tls from 'tls';
import { URL } from 'url';
import { SyntheticProbe, db, getWATFormattedDate } from '../db/database';
import { advisorService } from '../advisor/advisor-service';
import { notificationDispatcher } from '../alerts/notification-dispatcher';

export interface ProbeExecutionResult {
  probeId: string;
  systemId: string;
  targetUrl: string;
  statusCode: number;
  ttfbMs: number;
  dnsMs: number;
  tcpMs: number;
  sslValid: boolean;
  sslDaysRemaining?: number;
  status: 'HEALTHY' | 'DEGRADED' | 'DOWN';
  isSuccess: boolean;
  errorMessage?: string;
}

export class HeartbeatEngine {
  /**
   * Executes a single synthetic probe with high precision timing
   */
  public async executeProbe(probe: SyntheticProbe): Promise<ProbeExecutionResult> {
    const urlObj = new URL(probe.target_url);
    const isHttps = urlObj.protocol === 'https:';
    const isMock = urlObj.hostname === 'localhost' || urlObj.hostname === '127.0.0.1';

    const startTime = performance.now();
    let dnsTime = 0;
    let tcpTime = 0;
    let ttfbTime = 0;
    let sslDays: number | undefined = undefined;
    let sslValid = true;

    try {
      // Mock / Local loopback simulated execution for test routes
      if (isMock && urlObj.pathname.startsWith('/api/mock/')) {
        return this.executeMockProbe(probe, startTime);
      }

      // Check SSL certificate if HTTPS
      if (isHttps) {
        sslDays = await this.checkSslCertificate(urlObj.hostname, parseInt(urlObj.port || '443', 10));
        if (sslDays !== undefined && sslDays <= 0) sslValid = false;
      }

      // Execute HTTP request
      const httpModule = isHttps ? https : http;
      const requestPromise = new Promise<{ statusCode: number; ttfb: number; dns: number; tcp: number }>((resolve, reject) => {
        let dnsResolvedAt = 0;
        let tcpConnectedAt = 0;

        const req = httpModule.request(
          probe.target_url,
          {
            method: probe.method || 'GET',
            timeout: 8000,
            headers: {
              'User-Agent': 'TheWatch-SyntheticProber/1.0 (+https://thewatch.institution.edu.ng)',
            },
          },
          (res) => {
            const ttfb = performance.now() - startTime;
            resolve({
              statusCode: res.statusCode || 0,
              ttfb: Math.round(ttfb * 10) / 10,
              dns: Math.round(dnsTime * 10) / 10,
              tcp: Math.round(tcpTime * 10) / 10,
            });
            res.resume(); // consume response body
          }
        );

        req.on('socket', (socket) => {
          socket.on('lookup', () => {
            dnsResolvedAt = performance.now();
            dnsTime = dnsResolvedAt - startTime;
          });
          socket.on('connect', () => {
            tcpConnectedAt = performance.now();
            tcpTime = tcpConnectedAt - (dnsResolvedAt || startTime);
          });
        });

        req.on('timeout', () => {
          req.destroy(new Error(`Probe timeout after 8000ms on ${probe.target_url}`));
        });

        req.on('error', (err) => {
          reject(err);
        });

        req.end();
      });

      const res = await requestPromise;
      const isSuccess = res.statusCode === probe.expected_status;
      
      let status: 'HEALTHY' | 'DEGRADED' | 'DOWN' = 'HEALTHY';
      if (!isSuccess || res.statusCode >= 500) {
        status = 'DOWN';
      } else if (res.ttfb > 500 || (sslDays !== undefined && sslDays < 14)) {
        status = 'DEGRADED';
      }

      const result: ProbeExecutionResult = {
        probeId: probe.id,
        systemId: probe.system_id,
        targetUrl: probe.target_url,
        statusCode: res.statusCode,
        ttfbMs: res.ttfb,
        dnsMs: res.dns,
        tcpMs: res.tcp,
        sslValid,
        sslDaysRemaining: sslDays,
        status,
        isSuccess,
      };

      await this.recordResult(probe, result);
      return result;
    } catch (err: any) {
      const result: ProbeExecutionResult = {
        probeId: probe.id,
        systemId: probe.system_id,
        targetUrl: probe.target_url,
        statusCode: 0,
        ttfbMs: 0,
        dnsMs: 0,
        tcpMs: 0,
        sslValid: false,
        status: 'DOWN',
        isSuccess: false,
        errorMessage: err.message || 'Connection refused / Unreachable',
      };

      await this.recordResult(probe, result);
      return result;
    }
  }

  /**
   * Mock endpoint simulator for self-contained demonstrations and testing
   */
  private async executeMockProbe(probe: SyntheticProbe, startTime: number): Promise<ProbeExecutionResult> {
    const isSession = probe.id.includes('session');
    const isPayroll = probe.id.includes('payroll');
    const isDispatch = probe.id.includes('dispatch');

    const dnsMs = Math.round((2.5 + Math.random() * 4) * 10) / 10;
    const tcpMs = Math.round((5.0 + Math.random() * 8) * 10) / 10;
    const ttfbMs = isPayroll 
      ? Math.round((65 + Math.random() * 45) * 10) / 10 
      : Math.round((22 + Math.random() * 18) * 10) / 10;

    const result: ProbeExecutionResult = {
      probeId: probe.id,
      systemId: probe.system_id,
      targetUrl: probe.target_url,
      statusCode: 200,
      ttfbMs,
      dnsMs,
      tcpMs,
      sslValid: true,
      sslDaysRemaining: isDispatch ? 8 : 72,
      status: 'HEALTHY',
      isSuccess: true,
    };

    await this.recordResult(probe, result);
    return result;
  }

  private async checkSslCertificate(host: string, port: number = 443): Promise<number | undefined> {
    return new Promise((resolve) => {
      try {
        const socket = tls.connect({ host, port, servername: host, timeout: 4000 }, () => {
          const cert = socket.getPeerCertificate();
          socket.end();
          if (cert && cert.valid_to) {
            const expiry = new Date(cert.valid_to).getTime();
            const daysRemaining = Math.floor((expiry - Date.now()) / (1000 * 60 * 60 * 24));
            resolve(daysRemaining);
          } else {
            resolve(undefined);
          }
        });

        socket.on('error', () => resolve(undefined));
        socket.on('timeout', () => {
          socket.destroy();
          resolve(undefined);
        });
      } catch {
        resolve(undefined);
      }
    });
  }

  private async recordResult(probe: SyntheticProbe, result: ProbeExecutionResult): Promise<void> {
    await db.updateProbeMetrics(probe.id, {
      status: result.status,
      ttfbMs: result.ttfbMs,
      dnsMs: result.dnsMs,
      tcpMs: result.tcpMs,
      sslExpiryDays: result.sslDaysRemaining,
      isSuccess: result.isSuccess,
      errorMessage: result.errorMessage,
    });

    // If DOWN or DEGRADED, trigger automated incident & remediation advisor
    if (result.status === 'DOWN') {
      const diagnosis = advisorService.diagnose({
        errorMessage: result.errorMessage || `Endpoint returned HTTP ${result.statusCode}`,
        targetPath: result.targetUrl,
        sslDaysRemaining: result.sslDaysRemaining,
        systemId: result.systemId,
      });

      const incident = {
        id: `inc-probe-${Date.now()}-${Math.random().toString(36).substr(2, 4)}`,
        system_id: result.systemId,
        incident_type: 'PROBE_HEARTBEAT_FAILURE',
        threat_classification: `Synthetic Probe Failure (${probe.name})`,
        severity: 'HIGH' as const,
        offending_ip: '127.0.0.1',
        geo_country: 'Nigeria',
        geo_region: 'Abuja (FCT)',
        geo_city: 'Jabi - NOUN HQ',
        geo_lat: 9.0765,
        geo_lng: 7.3986,
        asn: 'AS37075',
        isp: 'Internal Campus Infrastructure',
        is_proxy_or_vpn: false,
        target_endpoint: result.targetUrl,
        http_method: probe.method || 'GET',
        captured_payload: result.errorMessage || `HTTP Status ${result.statusCode}`,
        status: 'UNRESOLVED' as const,
        mitigation_blueprint: diagnosis ? diagnosis.mitigationBlueprint : 'Inspect application server process logs and verify database connection pool.',
        remediation_summary: diagnosis ? diagnosis.incidentSummary : `Target endpoint ${result.targetUrl} failed heartbeat verification.`,
        created_at_wat: getWATFormattedDate(),
      };

      await db.saveIncident(incident);

      // Dispatch alert
      await notificationDispatcher.dispatchIncidentAlert(incident);
    }
  }
}

export const heartbeatEngine = new HeartbeatEngine();
