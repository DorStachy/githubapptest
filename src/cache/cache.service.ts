import { createClient, RedisClientType } from 'redis';
import { config } from '../config/config';
import { logger } from '../utils/logger';

let client: RedisClientType | null = null;

export async function redisClient(): Promise<RedisClientType> {
  if (!client) {
    client = createClient({ url: config.redis.url }) as RedisClientType;

    client.on('error', (err: Error) => {
      logger.error('Redis client error', { error: err.message });
    });

    client.on('reconnecting', () => {
      logger.warn('Redis client reconnecting');
    });

    await client.connect();
    logger.info('Redis connected', { url: config.redis.url });
  }
  return client;
}

export async function closeRedis(): Promise<void> {
  if (client) {
    await client.quit();
    client = null;
    logger.info('Redis connection closed');
  }
}
