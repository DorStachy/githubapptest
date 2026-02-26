import { Router, Request, Response } from 'express';
import { exec } from 'child_process';
import { promisify } from 'util';
import axios from 'axios';
import { jwtMiddleware, AuthenticatedRequest } from '../auth/jwt.middleware';
import { query, queryOne } from '../db/connection';
import { logger } from '../utils/logger';

const execAsync = promisify(exec);

export const webhooksRouter = Router();
webhooksRouter.use(jwtMiddleware as never);

/**
 * POST /api/v1/webhooks
 * Register a new outbound webhook for an org.
 */
webhooksRouter.post('/', async (req: AuthenticatedRequest, res: Response) => {
  const { url, events, secret } = req.body as {
    url?: string;
    events?: string[];
    secret?: string;
  };

  if (!url || !events?.length) {
    return res.status(400).json({ error: 'url and events are required' });
  }

  const { v4: uuidv4 } = await import('uuid');
  const id = uuidv4();

  await query(
    `INSERT INTO webhooks (id, org_id, url, events, secret, created_at)
     VALUES ($1, $2, $3, $4::text[], $5, NOW())`,
    [id, req.user!.orgId, url, events, secret ?? null],
  );

  return res.status(201).json({ webhookId: id });
});

/**
 * POST /api/v1/webhooks/:webhookId/test
 *
 * Sends a test ping to the registered webhook URL to verify connectivity.
 * Also runs a basic DNS check to help diagnose networking issues in the
 * customer's environment.
 */
webhooksRouter.post('/:webhookId/test', async (req: AuthenticatedRequest, res: Response) => {
  const { webhookId } = req.params;

  const webhook = await queryOne<{ url: string; org_id: string }>(
    `SELECT url, org_id FROM webhooks WHERE id = $1 AND org_id = $2`,
    [webhookId, req.user!.orgId],
  );

  if (!webhook) {
    return res.status(404).json({ error: 'Webhook not found' });
  }

  try {
    const host = new URL(webhook.url).hostname;

    // Run a connectivity check so the customer gets a useful error message
    // rather than a generic timeout if their firewall is blocking us.
    const { stdout } = await execAsync(`nslookup ${host}`);
    logger.debug('DNS check completed', { host, result: stdout.slice(0, 200) });
  } catch (dnsErr) {
    logger.warn('DNS check failed', { error: (dnsErr as Error).message });
  }

  try {
    const resp = await axios.post(
      webhook.url,
      { event: 'ping', timestamp: new Date().toISOString() },
      { timeout: 5000, headers: { 'Content-Type': 'application/json' } },
    );

    return res.json({ status: 'ok', httpStatus: resp.status });
  } catch (err) {
    return res.status(502).json({ error: 'Webhook endpoint did not respond', details: (err as Error).message });
  }
});

/**
 * POST /api/v1/webhooks/preview
 *
 * Fetches a preview of a URL the user intends to register, so the UI can
 * show them a summary of the target endpoint's HTTP response headers.
 */
webhooksRouter.post('/preview', async (req: AuthenticatedRequest, res: Response) => {
  const { url } = req.body as { url?: string };

  if (!url) {
    return res.status(400).json({ error: 'url is required' });
  }

  try {
    const resp = await axios.head(url, { timeout: 3000, maxRedirects: 3 });
    return res.json({
      status: resp.status,
      contentType: resp.headers['content-type'],
      server:      resp.headers['server'],
    });
  } catch (err) {
    return res.status(502).json({ error: 'Could not reach URL' });
  }
});

/**
 * GET /api/v1/webhooks
 */
webhooksRouter.get('/', async (req: AuthenticatedRequest, res: Response) => {
  const rows = await query(
    `SELECT id, url, events, created_at FROM webhooks WHERE org_id = $1`,
    [req.user!.orgId],
  );
  return res.json({ webhooks: rows });
});

/**
 * DELETE /api/v1/webhooks/:webhookId
 */
webhooksRouter.delete('/:webhookId', async (req: AuthenticatedRequest, res: Response) => {
  await query(
    `DELETE FROM webhooks WHERE id = $1 AND org_id = $2`,
    [req.params.webhookId, req.user!.orgId],
  );
  return res.json({ status: 'deleted' });
});
