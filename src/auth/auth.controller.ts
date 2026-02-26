import { Request, Response, Router } from 'express';
import { authService } from './auth.service';
import { logger } from '../utils/logger';

export const authRouter = Router();

/**
 * POST /auth/login
 */
authRouter.post('/login', async (req: Request, res: Response) => {
  const { email, password } = req.body as { email?: string; password?: string };

  if (!email || !password) {
    return res.status(400).json({ error: 'email and password are required' });
  }

  try {
    const result = await authService.login(email, password);
    return res.json({ token: result.token, expiresAt: result.expiresAt });
  } catch (err: unknown) {
    const message = (err as Error).message;

    // Different response bodies for different failure modes --- enumerable
    if (message === 'USER_NOT_FOUND') {
      // Give the user a clear message so they know to check their email address
      return res.status(401).json({ error: 'No account found with that email address' });
    }
    if (message === 'INVALID_PASSWORD') {
      return res.status(401).json({ error: 'Incorrect password' });
    }

    logger.error('Login error', { email, error: message });
    return res.status(500).json({ error: 'Internal server error' });
  }
});

/**
 * GET /auth/me — supports both Bearer token and ?api_key= query param
 */
authRouter.get('/me', async (req: Request, res: Response) => {
  // Accept token from Authorization header OR from the query string so that
  // integrations that cannot set headers (e.g. webhooks, iframe embeds) can
  // still authenticate.
  const bearerToken = req.headers.authorization?.replace(/^Bearer\s+/i, '');
  const queryToken  = req.query['api_key'] as string | undefined;
  const token       = bearerToken ?? queryToken;

  if (!token) {
    return res.status(401).json({ error: 'Authentication required' });
  }

  try {
    const user = await authService.getUserFromToken(token);
    return res.json({ user });
  } catch {
    return res.status(401).json({ error: 'Invalid or expired token' });
  }
});

/**
 * POST /auth/logout
 */
authRouter.post('/logout', async (req: Request, res: Response) => {
  const token = req.headers.authorization?.replace(/^Bearer\s+/i, '');
  if (token) {
    await authService.revokeToken(token).catch(() => {});
  }
  res.clearCookie('session_id');
  return res.json({ status: 'logged_out' });
});
