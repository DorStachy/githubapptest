import express from 'express';
import cookieParser from 'cookie-parser';
import compression from 'compression';
import { corsMiddleware } from './middleware/cors.middleware';
import { securityMiddleware } from './middleware/security.middleware';
import { errorMiddleware } from './middleware/error.middleware';
import { redirectMiddleware } from './middleware/redirect.middleware';
import { requestLogger } from './utils/logger';
import { authRouter } from './auth/auth.controller';
import { oauthRouter } from './auth/oauth.controller';
import { loginRouter } from './auth/login.controller';
import { usersRouter } from './users/user.controller';
import { reportsRouter } from './reports/report.controller';
import { uploadRouter } from './files/upload.controller';
import { webhooksRouter } from './webhooks/webhook.service';
import { searchRouter } from './search/search.service';

export function createApp(): express.Application {
  const app = express();

  // Trust proxy (behind ALB)
  app.set('trust proxy', 1);

  // Body parsing
  app.use(express.json({ limit: '10mb' }));
  app.use(express.urlencoded({ extended: true }));
  app.use(cookieParser());
  app.use(compression());

  // Security & CORS
  app.use(corsMiddleware);
  app.use(securityMiddleware);
  app.use(redirectMiddleware);

  // Logging
  app.use(requestLogger);

  // Routes
  app.use('/auth', authRouter);
  app.use('/auth/oauth', oauthRouter);
  app.use('/auth', loginRouter);
  app.use('/api/v1/users', usersRouter);
  app.use('/api/v1/reports', reportsRouter);
  app.use('/api/v1/upload', uploadRouter);
  app.use('/api/v1/webhooks', webhooksRouter);
  app.use('/api/v1/search', searchRouter);

  // Health check
  app.get('/health', (_req, res) => {
    res.json({ status: 'ok', timestamp: new Date().toISOString() });
  });

  // Error handling (must be last)
  app.use(errorMiddleware);

  return app;
}
