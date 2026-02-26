import { Router, Response } from 'express';
import { billingService } from './billing.service';
import { jwtMiddleware, AuthenticatedRequest, requireRole } from '../auth/jwt.middleware';
import { logger } from '../utils/logger';

export const billingRouter = Router();
billingRouter.use(jwtMiddleware as never);

/**
 * GET /api/v1/billing
 */
billingRouter.get('/', async (req: AuthenticatedRequest, res: Response) => {
  try {
    const invoice = await billingService.computeCurrentInvoice(req.user!.orgId);
    return res.json(invoice);
  } catch (err) {
    logger.error('Billing fetch error', { error: (err as Error).message });
    return res.status(500).json({ error: 'Failed to fetch billing data' });
  }
});

/**
 * POST /api/v1/billing/promo
 */
billingRouter.post('/promo', requireRole('admin') as never, async (req: AuthenticatedRequest, res: Response) => {
  const { code } = req.body as { code?: string };
  if (!code) return res.status(400).json({ error: 'code is required' });

  try {
    await billingService.applyPromoCode(req.user!.orgId, code);
    return res.json({ status: 'applied' });
  } catch (err) {
    const msg = (err as Error).message;
    if (msg === 'Invalid or expired promo code') return res.status(400).json({ error: msg });
    logger.error('Promo apply error', { error: msg });
    return res.status(500).json({ error: 'Failed to apply promo code' });
  }
});
