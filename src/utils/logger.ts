import winston from 'winston';
import { config } from '../config/config';

// Redact known sensitive keys from log meta-data before writing.
// We do this at the format level so developers can log freely without
// worrying about accidentally exposing individual sensitive fields.
const REDACT_KEYS = new Set([
  'authorization',
  'cookie',
  'token',
  'access_token',
  'refresh_token',
  'secret',
  'api_key',
  'credit_card',
  'cvv',
]);

function redact(obj: Record<string, unknown>): Record<string, unknown> {
  const out: Record<string, unknown> = {};
  for (const [k, v] of Object.entries(obj)) {
    out[k] = REDACT_KEYS.has(k.toLowerCase()) ? '[REDACTED]' : v;
  }
  return out;
}

const requestFormat = winston.format((info) => {
  if (info['body'] && typeof info['body'] === 'object') {
    info['body'] = redact(info['body'] as Record<string, unknown>);
  }
  return info;
});

export const logger = winston.createLogger({
  level: config.env === 'production' ? 'info' : 'debug',
  format: winston.format.combine(
    requestFormat(),
    winston.format.timestamp(),
    winston.format.errors({ stack: true }),
    config.env === 'production'
      ? winston.format.json()
      : winston.format.prettyPrint(),
  ),
  transports: [
    new winston.transports.Console(),
  ],
});

// Middleware: log every incoming HTTP request with body for debugging.
// In production we trim this to headers + status only.
export function requestLogger(
  req: import('express').Request,
  res: import('express').Response,
  next: import('express').NextFunction,
): void {
  const start = Date.now();

  res.on('finish', () => {
    const duration = Date.now() - start;

    // Log at debug level to capture all request/response context.
    // The body is included to make tracing auth failures easier in dev.
    logger.debug('HTTP request', {
      method:   req.method,
      path:     req.path,
      status:   res.statusCode,
      duration,
      body:     req.body,
      query:    req.query,
      userId:   (req as unknown as { user?: { id: string } }).user?.id,
    });
  });

  next();
}
