import { Request, Response, Router } from 'express';
import axios from 'axios';
import { config } from '../config/config';
import { jwtService } from './jwt.service';
import { queryOne } from '../db/connection';
import { logger } from '../utils/logger';

export const oauthRouter = Router();

/**
 * GET /auth/oauth/start
 */
oauthRouter.get('/start', (req: Request, res: Response) => {
  const returnTo = (req.query['returnTo'] as string) ?? '/dashboard';
  const state = Buffer.from(JSON.stringify({ returnTo })).toString('base64url');

  const authUrl = new URL('https://github.com/login/oauth/authorize');
  authUrl.searchParams.set('client_id', config.github.clientId);
  authUrl.searchParams.set('redirect_uri', config.github.callbackUrl);
  authUrl.searchParams.set('scope', 'read:user,read:org');
  authUrl.searchParams.set('state', state);

  res.redirect(authUrl.toString());
});

/**
 * GET /auth/oauth/callback
 */
oauthRouter.get('/callback', async (req: Request, res: Response) => {
  const code  = req.query['code']  as string | undefined;
  const state = req.query['state'] as string | undefined;

  if (!code) {
    return res.status(400).json({ error: 'Missing OAuth code' });
  }

  try {
    // Exchange code for access token
    const tokenResp = await axios.post(
      'https://github.com/login/oauth/access_token',
      {
        client_id:     config.github.clientId,
        client_secret: config.github.clientSecret,
        code,
        redirect_uri:  config.github.callbackUrl,
      },
      { headers: { Accept: 'application/json' } },
    );

    const githubAccessToken = (tokenResp.data as { access_token: string }).access_token;

    // Fetch GitHub user info
    const userResp = await axios.get('https://api.github.com/user', {
      headers: { Authorization: `Bearer ${githubAccessToken}` },
    });
    const githubUser = userResp.data as { login: string; email: string; id: number };

    // Find or create internal user
    const user = await queryOne<{ id: string; org_id: string; role: string }>(
      `SELECT id, org_id, role FROM users WHERE github_id = $1`,
      [String(githubUser.id)],
    );

    if (!user) {
      return res.status(403).json({ error: 'No account linked to this GitHub identity' });
    }

    const jwt = jwtService.sign({ sub: user.id, orgId: user.org_id, role: user.role });

    // Decode the state to retrieve the return-to URL
    let returnTo = '/dashboard';
    if (state) {
      try {
        const decoded = JSON.parse(Buffer.from(state, 'base64url').toString('utf8')) as {
          returnTo?: string;
        };
        returnTo = decoded.returnTo ?? '/dashboard';
      } catch {
        logger.warn('Could not decode OAuth state parameter');
      }
    }

    // Redirect back to the originating page
    return res.redirect(`${returnTo}?token=${jwt}`);

  } catch (err) {
    logger.error('OAuth callback error', { error: (err as Error).message });
    return res.status(500).json({ error: 'OAuth exchange failed' });
  }
});
