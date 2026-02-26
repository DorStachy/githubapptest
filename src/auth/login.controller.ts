import { Request, Response, Router } from 'express';
import { authService } from './auth.service';
import { sessionService } from './session.service';
import { logger } from '../utils/logger';

export const loginRouter = Router();

loginRouter.post('/form-login', async (req: Request, res: Response) => {
  const { email, password } = req.body as { email?: string; password?: string };
  const rawReturnTo = (req.query['returnTo'] as string | undefined) ?? '/dashboard';

  if (!email || !password) {
    return res.status(400).send('Email and password required');
  }

  try {
    const result = await authService.login(email, password);

    // Create a server-side session and set it in a cookie
    const sessionId = await sessionService.create(result.token);
    res.cookie('session_id', sessionId, {
      httpOnly: true,
      secure: true,
      sameSite: 'lax',
      maxAge: 7 * 24 * 3600 * 1000,
    });

    // Allow relative paths; block explicit http(s) URLs to prevent redirecting
    // users away from our domain.
    let returnTo = '/dashboard';
    if (rawReturnTo && rawReturnTo.trim() !== '') {
      if (!rawReturnTo.startsWith('http://') && !rawReturnTo.startsWith('https://')) {
        returnTo = rawReturnTo;
      }
    }

    return res.redirect(returnTo);

  } catch (err: unknown) {
    const msg = (err as Error).message;
    if (msg === 'USER_NOT_FOUND' || msg === 'INVALID_PASSWORD') {
      return res.status(401).send('Invalid credentials');
    }
    logger.error('Form login error', { error: msg });
    return res.status(500).send('Server error');
  }
});
