import http from 'http';
import dgram from 'dgram';
import crypto from 'crypto';

export interface SentinelConfig {
  systemId: string;
  apiKey: string;
  apiSecret?: string;
  endpoint?: string; // e.g. 'http://localhost:4000/api/v1/telemetry/ingest'
  udpPort?: number;  // e.g. 9876
  transport?: 'HTTP' | 'UDP';
  batchIntervalMs?: number;
  maxBatchSize?: number;
}

export interface TelemetryEvent {
  method: string;
  path: string;
  statusCode: number;
  latencyMs: number;
  clientIp: string;
  payloadSnippet?: string;
  userAgent?: string;
  queryLatencyMs?: number;
  queryText?: string;
  errorMessage?: string;
}

export class SentinelAgent {
  private buffer: TelemetryEvent[] = [];
  private timer: NodeJS.Timeout | null = null;
  private udpSocket: dgram.Socket | null = null;

  constructor(private config: SentinelConfig) {
    this.config.endpoint = config.endpoint || 'http://localhost:4000/api/v1/telemetry/ingest';
    this.config.transport = config.transport || 'HTTP';
    this.config.batchIntervalMs = config.batchIntervalMs || 2000;
    this.config.maxBatchSize = config.maxBatchSize || 50;

    if (this.config.transport === 'UDP') {
      this.udpSocket = dgram.createSocket('udp4');
    }

    this.timer = setInterval(() => this.flush(), this.config.batchIntervalMs);
  }

  /**
   * Express/Connect plug-and-play middleware for host application
   */
  public middleware() {
    return (req: any, res: any, next: () => void) => {
      const startTime = performance.now();
      const path = req.originalUrl || req.url || '/';
      const method = req.method;
      const clientIp = req.headers['x-forwarded-for'] || req.socket.remoteAddress || '127.0.0.1';
      const userAgent = req.headers['user-agent'];

      // Non-intrusive body preview extraction
      let payloadSnippet: string | undefined;
      if (req.body && typeof req.body === 'object') {
        try {
          payloadSnippet = JSON.stringify(req.body).substring(0, 300);
        } catch {}
      }

      res.on('finish', () => {
        const latencyMs = Math.round((performance.now() - startTime) * 10) / 10;
        this.record({
          method,
          path,
          statusCode: res.statusCode,
          latencyMs,
          clientIp: String(clientIp).split(',')[0].trim(),
          payloadSnippet,
          userAgent,
        });
      });

      next();
    };
  }

  /**
   * Records a custom event (e.g. database query metric or error)
   */
  public record(event: TelemetryEvent): void {
    this.buffer.push(event);
    if (this.buffer.length >= (this.config.maxBatchSize || 50)) {
      setImmediate(() => this.flush());
    }
  }

  /**
   * Asynchronously ships buffered logs with zero blocking
   */
  public flush(): void {
    if (this.buffer.length === 0) return;
    const batch = this.buffer.splice(0, this.buffer.length);

    if (this.config.transport === 'UDP' && this.udpSocket) {
      for (const item of batch) {
        const payload = Buffer.from(JSON.stringify({ ...item, apiKey: this.config.apiKey }));
        this.udpSocket.send(payload, this.config.udpPort || 9876, '127.0.0.1', () => {});
      }
      return;
    }

    // Default HTTP transport
    const postData = JSON.stringify(batch);
    const url = new URL(this.config.endpoint!);
    const headers: Record<string, string> = {
      'Content-Type': 'application/json',
      'Content-Length': String(Buffer.byteLength(postData)),
      'X-Telemetry-Key': this.config.apiKey,
    };

    if (this.config.apiSecret) {
      headers['X-Telemetry-Signature'] = crypto
        .createHmac('sha256', this.config.apiSecret)
        .update(postData)
        .digest('hex');
    }

    const req = http.request(
      {
        hostname: url.hostname,
        port: url.port || 80,
        path: url.pathname,
        method: 'POST',
        headers,
        timeout: 3000,
      },
      (res: http.IncomingMessage) => {
        res.resume(); // Discard response body
      }
    );

    req.on('error', () => {}); // Non-blocking: drop silently if watchdog server unreachable
    req.write(postData);
    req.end();
  }

  public destroy(): void {
    if (this.timer) clearInterval(this.timer);
    if (this.udpSocket) this.udpSocket.close();
  }
}

/**
 * Factory helper for 1-line middleware initialization
 */
export function createSentinelMiddleware(config: SentinelConfig) {
  const agent = new SentinelAgent(config);
  return agent.middleware();
}
