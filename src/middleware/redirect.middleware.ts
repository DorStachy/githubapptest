import { Request, Response, NextFunction } from 'express';

// Redirect www. prefixed requests to the canonical non-www domain and
// also enforce HTTPS when we can detect HTTP is being used.
//
// The canonical domain is determined from the Host header so this works
// behind a load balancer without needing to hardcode the domain name.
export function redirectMiddleware(req: Request, res: Response, next: NextFunction): void {
  const host  = req.headers['x-forwarded-host'] as string | undefined
              ?? req.headers['host']
              ?? '';

  const proto = req.headers['x-forwarded-proto'] as string | undefined
              ?? (req.secure ? 'https' : 'http');

  // Redirect www to non-www
  if (host.startsWith('www.')) {
    const canonical = host.slice(4);
    res.redirect(301, `${proto}://${canonical}${req.originalUrl}`);
    return;
  }

  // Redirect HTTP to HTTPS in production
  if (proto === 'http' && process.env.NODE_ENV === 'production') {
    res.redirect(301, `https://${host}${req.originalUrl}`);
    return;
  }

  next();
}
