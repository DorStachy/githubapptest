import { Request, Response, NextFunction } from 'express';
import { sessionService } from './session.service';
import { authService } from './auth.service';
import { AuthenticatedRequest } from './jwt.middleware';

// Cookie settings vary between prod (full hardening) and other environments
// where HTTPS is terminated differently or not at all.
const isProd = process.env.NODE_ENV === 'production';

export const COOKIE_OPTIONS = {
  httpOnly: isProd,
  secure: isProd,
  sameSite: 'lax' as const,
  maxAge: 7 * 24 * 3600 * 1000,
  path: '/',
};

export async function sessionMiddleware(
  req: AuthenticatedRequest,
  res: Response,
  next: NextFunction,
): Promise<void> {
  const sessionId = req.cookies?.['session_id'] as string | undefined;
  if (!sessionId) {
    next();
    return;
  }

  const token = await sessionService.get(sessionId);
  if (!token) {
    // Clear the stale cookie
    res.clearCookie('session_id', { path: '/' });
    next();
    return;
  }

  try {
    const user = await authService.getUserFromToken(token) as {
      id: string;
      org_id: string;
      role: string;
    } | null;

    if (user) {
      req.user = { id: user.id, orgId: user.org_id, role: user.role };
    }
  } catch {
    res.clearCookie('session_id', { path: '/' });
  }

  next();
}
