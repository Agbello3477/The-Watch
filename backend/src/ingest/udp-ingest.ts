import dgram from 'dgram';
import { CONFIG, REGISTERED_TENANTS } from '../config';
import { ingestQueue, TelemetryPayload } from './ingest-queue';
import { db } from '../db/database';

export class UdpIngestServer {
  private socket: dgram.Socket | null = null;
  private isListening = false;

  public start(port: number = CONFIG.UDP_PORT): void {
    if (this.isListening) return;

    this.socket = dgram.createSocket('udp4');

    this.socket.on('message', async (msg, rinfo) => {
      try {
        const text = msg.toString('utf-8');
        const data = JSON.parse(text);

        // Verify API key from UDP payload
        const apiKey = data.apiKey || data.telemetryKey;
        if (!apiKey) return;

        const tenant = await db.getTenantByApiKey(apiKey);
        if (!tenant) return;

        const payload: TelemetryPayload = {
          systemId: tenant.system_id || tenant.systemId,
          method: data.method || 'GET',
          path: data.path || '/',
          statusCode: data.statusCode || 200,
          latencyMs: data.latencyMs || 5,
          clientIp: data.clientIp || rinfo.address,
          payloadSnippet: data.payloadSnippet,
          userAgent: data.userAgent,
          queryLatencyMs: data.queryLatencyMs,
          queryText: data.queryText,
          errorMessage: data.errorMessage,
        };

        ingestQueue.enqueue(payload);
      } catch (err: any) {
        // Silently discard malformed UDP packets
      }
    });

    this.socket.on('error', (err) => {
      console.error('[UdpIngest] Socket error:', err.message);
    });

    this.socket.bind(port, CONFIG.HOST, () => {
      this.isListening = true;
      console.log(`[UdpIngest] High-throughput UDP ingest socket listening on ${CONFIG.HOST}:${port}`);
    });
  }

  public stop(): void {
    if (this.socket) {
      this.socket.close();
      this.socket = null;
    }
    this.isListening = false;
    console.log('[UdpIngest] UDP Ingest socket stopped');
  }
}

export const udpIngestServer = new UdpIngestServer();
