import { db } from '../db/database';
import { heartbeatEngine } from './heartbeat-engine';

export class ProbeScheduler {
  private timer: NodeJS.Timeout | null = null;
  private isRunning = false;

  public start(intervalMs: number = 30000): void {
    if (this.isRunning) return;
    this.isRunning = true;
    console.log(`[ProbeScheduler] Started synthetic heartbeat prober (interval: ${intervalMs / 1000}s)`);

    // Run first tick immediately
    this.tick();

    this.timer = setInterval(() => {
      this.tick();
    }, intervalMs);
  }

  public stop(): void {
    if (this.timer) {
      clearInterval(this.timer);
      this.timer = null;
    }
    this.isRunning = false;
    console.log('[ProbeScheduler] Stopped synthetic heartbeat prober');
  }

  public async tick(): Promise<void> {
    try {
      const probes = await db.getProbes();
      for (const probe of probes) {
        if (probe.is_enabled) {
          await heartbeatEngine.executeProbe(probe).catch((e) => {
            console.error(`[ProbeScheduler] Error probing ${probe.name}:`, e.message);
          });
        }
      }
    } catch (err: any) {
      console.error('[ProbeScheduler] Tick cycle error:', err.message);
    }
  }
}

export const probeScheduler = new ProbeScheduler();
