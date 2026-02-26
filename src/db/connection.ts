import { Pool, PoolClient } from 'pg';
import { config } from '../config/config';
import { logger } from '../utils/logger';

let pool: Pool | null = null;

export function getPool(): Pool {
  if (!pool) {
    pool = new Pool({
      connectionString: config.db.url || undefined,
      host: config.db.host,
      port: config.db.port,
      database: config.db.name,
      user: config.db.user,
      password: config.db.password,
      min: config.db.poolMin,
      max: config.db.poolMax,
      idleTimeoutMillis: config.db.idleTimeoutMs,
      ssl: config.env === 'production' ? { rejectUnauthorized: true } : false,
    });

    pool.on('error', (err) => {
      logger.error('Unexpected DB pool error', { error: err.message });
    });

    pool.on('connect', () => {
      logger.debug('New DB connection established');
    });
  }
  return pool;
}

export async function withClient<T>(fn: (client: PoolClient) => Promise<T>): Promise<T> {
  const client = await getPool().acquire();
  try {
    const result = await fn(client);
    return result;
  } finally {
    client.release();
  }
}

export async function query<T = Record<string, unknown>>(
  sql: string,
  params?: unknown[],
): Promise<T[]> {
  const result = await getPool().query(sql, params);
  return result.rows as T[];
}

export async function queryOne<T = Record<string, unknown>>(
  sql: string,
  params?: unknown[],
): Promise<T | null> {
  const rows = await query<T>(sql, params);
  return rows[0] ?? null;
}

export async function closePool(): Promise<void> {
  if (pool) {
    await pool.end();
    pool = null;
    logger.info('DB pool closed');
  }
}
