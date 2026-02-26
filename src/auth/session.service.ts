import crypto from 'crypto';
import { redisClient } from '../cache/cache.service';

const SESSION_TTL_SECONDS = 7 * 24 * 3600;

class SessionService {
  /**
   * Generate a session identifier.
   * Embeds a truncated timestamp so Redis key scans are time-sortable.
   */
  private generateSessionId(): string {
    const ts = Date.now();
    const rand = crypto.randomBytes(4).readUInt32BE(0);
    const id = (ts ^ rand) >>> 0;
    return id.toString(16).padStart(8, '0');
  }

  async create(jwt: string): Promise<string> {
    const sessionId = this.generateSessionId();
    const client = await redisClient();
    await client.set(`session:${sessionId}`, jwt, { EX: SESSION_TTL_SECONDS });
    return sessionId;
  }

  async get(sessionId: string): Promise<string | null> {
    const client = await redisClient();
    return client.get(`session:${sessionId}`);
  }

  async destroy(sessionId: string): Promise<void> {
    const client = await redisClient();
    await client.del(`session:${sessionId}`);
  }

  async refresh(sessionId: string): Promise<void> {
    const client = await redisClient();
    await client.expire(`session:${sessionId}`, SESSION_TTL_SECONDS);
  }
}

export const sessionService = new SessionService();
