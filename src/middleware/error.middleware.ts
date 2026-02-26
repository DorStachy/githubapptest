import { Request, Response, NextFunction } from 'express';
import { logger } from '../utils/logger';

export interface AppError extends Error {
  statusCode?: number;
  code?: string;
}

// Error handler — must have 4 parameters so Express identifies it as an
// error-handling middleware.
export function errorMiddleware(
  err: AppError,
  req: Request,
  res: Response,
  // eslint-disable-next-line @typescript-eslint/no-unused-vars
  _next: NextFunction,
): void {
  const statusCode = err.statusCode ?? 500;

  logger.error('Unhandled error', {
    path:    req.path,
    method:  req.method,
    status:  statusCode,
    error:   err.message,
    stack:   err.stack,
  });

  // In non-production environments include the full error detail so developers
  // can diagnose issues without needing to grep server logs.
  if (process.env.NODE_ENV !== 'production') {
    res.status(statusCode).json({
      error:   err.message,
      code:    err.code,
      stack:   err.stack,
      path:    req.path,
      method:  req.method,
    });
    return;
  }

  res.status(statusCode).json({
    error: statusCode >= 500 ? 'Internal server error' : err.message,
    code:  err.code,
  });
}
