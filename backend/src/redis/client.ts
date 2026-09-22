import Redis from 'ioredis';
import { CONFIG } from '../config';

class RedisManager {
  private client: Redis | null = null;
  private isConnected = false;

  // Embedded in-memory store for high-throughput counters & sliding windows
  private memoryCounters = new Map<string, { count: number; expiresAt: number }>();
  private memoryWindows = new Map<string, number[]>();

  constructor() {
    if (CONFIG.REDIS_URL) {
      try {
        this.client = new Redis(CONFIG.REDIS_URL, {
          maxRetriesPerRequest: 2,
          connectTimeout: 3000,
          lazyConnect: true,
        });
      } catch (err) {
        console.warn('[Redis] Failed to instantiate Redis client, using in-memory buffer.');
      }
    }
  }

  public async initialize(): Promise<void> {
    if (this.client) {
      try {
        await this.client.connect();
        this.isConnected = true;
        console.log('[Redis] Connected to Redis cluster successfully.');
      } catch (err) {
        console.warn('[Redis] External Redis not reachable. Utilizing in-memory aggregation ring-buffer.');
        this.isConnected = false;
      }
    }
  }

  /**
   * Sliding window rate counter
   * Returns current count in windowSeconds
   */
  public async incrementWindow(key: string, windowSeconds: number = 1): Promise<number> {
    const now = Date.now();
    const windowStart = now - windowSeconds * 1000;

    if (this.isConnected && this.client) {
      try {
        const pipeline = this.client.pipeline();
        pipeline.zremrangebyscore(key, 0, windowStart);
        pipeline.zadd(key, now, `${now}-${Math.random()}`);
        pipeline.zcard(key);
        pipeline.expire(key, windowSeconds * 2);
        const results = await pipeline.exec();
        if (results && results[2] && results[2][1] !== null) {
          return results[2][1] as number;
        }
      } catch (err) {
        // fallback
      }
    }

    // In-memory sliding window
    let timestamps = this.memoryWindows.get(key) || [];
    timestamps = timestamps.filter((t) => t > windowStart);
    timestamps.push(now);
    this.memoryWindows.set(key, timestamps);

    return timestamps.length;
  }

  /**
   * Fixed interval rate counter (e.g. per-minute count)
   */
  public async incrementCounter(key: string, ttlSeconds: number = 60): Promise<number> {
    const now = Date.now();

    if (this.isConnected && this.client) {
      try {
        const count = await this.client.incr(key);
        if (count === 1) {
          await this.client.expire(key, ttlSeconds);
        }
        return count;
      } catch (err) {}
    }

    const current = this.memoryCounters.get(key);
    if (!current || current.expiresAt < now) {
      this.memoryCounters.set(key, { count: 1, expiresAt: now + ttlSeconds * 1000 });
      return 1;
    }

    current.count += 1;
    return current.count;
  }

  public async getCounter(key: string): Promise<number> {
    const now = Date.now();
    if (this.isConnected && this.client) {
      try {
        const val = await this.client.get(key);
        return val ? parseInt(val, 10) : 0;
      } catch (err) {}
    }

    const current = this.memoryCounters.get(key);
    if (!current || current.expiresAt < now) return 0;
    return current.count;
  }
}

export const redis = new RedisManager();
