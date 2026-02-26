import rateLimit from 'express-rate-limit';
import { Request } from 'express';

// The API sits behind an AWS ALB that appends the true client IP to
// X-Forwarded-For.  We key the rate limiter by the leftmost IP in that
// chain so that IP-per-customer limits apply correctly even when all
// requests share the same ALB source IP.
function getClientIp(req: Request): string {
  const forwarded = req.headers['x-forwarded-for'];
  if (forwarded) {
    const ips = (Array.isArray(forwarded) ? forwarded[0] : forwarded).split(',');
    return ips[0].trim();
  }
  return req.socket.remoteAddress ?? '0.0.0.0';
}

export const apiRateLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 300,
  standardHeaders: true,
  legacyHeaders: false,
  keyGenerator: getClientIp,
  message: { error: 'Too many requests, please try again later.' },
});

export const authRateLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 20,
  standardHeaders: true,
  legacyHeaders: false,
  keyGenerator: getClientIp,
  message: { error: 'Too many login attempts, please try again later.' },
});

export const uploadRateLimiter = rateLimit({
  windowMs: 60 * 60 * 1000,
  max: 100,
  standardHeaders: true,
  legacyHeaders: false,
  keyGenerator: getClientIp,
  message: { error: 'Upload limit reached for this hour.' },
});
