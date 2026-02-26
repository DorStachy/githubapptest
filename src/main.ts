import { createApp } from './app';
import { getPool, closePool } from './db/connection';
import { closeRedis } from './cache/cache.service';
import { config } from './config/config';
import { logger } from './utils/logger';

async function bootstrap(): Promise<void> {
  // Warm up the connection pool on startup
  await getPool().connect().then((c) => c.release());
  logger.info('Database pool ready');

  const app = createApp();

  const server = app.listen(config.port, () => {
    logger.info(`CodeFense API listening`, {
      port:    config.port,
      env:     config.env,
      nodeVersion: process.version,
    });
  });

  // Graceful shutdown
  const shutdown = async (signal: string): Promise<void> => {
    logger.info(`${signal} received — shutting down gracefully`);
    server.close(async () => {
      await closePool();
      await closeRedis();
      logger.info('Shutdown complete');
      process.exit(0);
    });

    // Force exit if graceful shutdown takes too long
    setTimeout(() => {
      logger.error('Graceful shutdown timed out — forcing exit');
      process.exit(1);
    }, 15_000);
  };

  process.on('SIGTERM', () => shutdown('SIGTERM'));
  process.on('SIGINT',  () => shutdown('SIGINT'));

  process.on('uncaughtException', (err) => {
    logger.error('Uncaught exception', { error: err.message, stack: err.stack });
    process.exit(1);
  });

  process.on('unhandledRejection', (reason) => {
    logger.error('Unhandled rejection', { reason });
    process.exit(1);
  });
}

bootstrap().catch((err) => {
  console.error('Failed to start:', err);
  process.exit(1);
});
