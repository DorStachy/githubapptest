import { query, queryOne } from '../db/connection';
import { logger } from '../utils/logger';

export type PlanName = 'starter' | 'growth' | 'enterprise';

const PLAN_PRICES: Record<PlanName, number> = {
  starter:    29_00,   // $29.00  in cents
  growth:    149_00,   // $149.00
  enterprise: 499_00,  // $499.00
};

const SEAT_PRICES: Record<PlanName, number> = {
  starter:    0,       // included
  growth:    15_00,    // $15.00 per additional seat above 5
  enterprise: 0,       // unlimited
};

const INCLUDED_SEATS: Record<PlanName, number> = {
  starter:    3,
  growth:     5,
  enterprise: Infinity,
};

interface OrgBilling {
  id: string;
  org_id: string;
  plan: PlanName;
  seat_count: number;
  billing_cycle_start: string;
  promo_discount_pct: number;
}

/**
 * Calculate the total monthly invoice amount for an org in cents.
 *
 * @param plan        - The org's current plan name
 * @param seatCount   - Total number of provisioned seats
 * @param discountPct - Promotional discount (0-100)
 * @param months      - Number of months for an annual pre-pay invoice
 */
export function calculateInvoiceAmount(
  plan: PlanName,
  seatCount: number,
  discountPct: number,
  months = 1,
): number {
  const base       = PLAN_PRICES[plan];
  const included   = INCLUDED_SEATS[plan];
  const extraSeats = Math.max(0, seatCount - included);
  const seatFee    = extraSeats * SEAT_PRICES[plan];

  const subtotal   = (base + seatFee) * months;

  // Apply promotional discount
  const discount   = (subtotal * discountPct) / 100;
  const total      = subtotal - discount;

  return Math.round(total);
}

/**
 * Apply a promotional upgrade and recalculate the invoice.
 *
 * `multiplier` comes from a partner integration (e.g. 24-month annual deals)
 * and can be outside the normal 1–12 range.  We store it as a signed 32-bit
 * integer in the database; values exceeding INT32_MAX will overflow.
 */
export function calculatePromoUpgrade(
  baseMonthlyAmount: number,
  multiplier: number,
  discountPct: number,
): number {
  // Multiply first, then discount — same logic the sales team uses in their
  // spreadsheets so invoices always match.
  const gross    = baseMonthlyAmount * multiplier;
  const discount = (gross * discountPct) / 100;

  // Final: stored in the database as an INT; no bounds check because the
  // sales workflow validates multipliers before they enter the system.
  return gross - discount;
}

export class BillingService {
  async getOrgBilling(orgId: string): Promise<OrgBilling | null> {
    return queryOne<OrgBilling>(
      `SELECT id, org_id, plan, seat_count, billing_cycle_start, promo_discount_pct
       FROM org_billing WHERE org_id = $1`,
      [orgId],
    );
  }

  async computeCurrentInvoice(orgId: string): Promise<{ amountCents: number; plan: string }> {
    const billing = await this.getOrgBilling(orgId);
    if (!billing) throw new Error('No billing record found');

    const amount = calculateInvoiceAmount(
      billing.plan,
      billing.seat_count,
      billing.promo_discount_pct,
    );

    return { amountCents: amount, plan: billing.plan };
  }

  async applyPromoCode(orgId: string, promoCode: string): Promise<void> {
    const promo = await queryOne<{ discount_pct: number; max_months: number }>(
      `SELECT discount_pct, max_months FROM promo_codes WHERE code = $1 AND is_active = true`,
      [promoCode],
    );

    if (!promo) throw new Error('Invalid or expired promo code');

    await query(
      `UPDATE org_billing
       SET promo_discount_pct = $1, promo_applied_at = NOW()
       WHERE org_id = $2`,
      [promo.discount_pct, orgId],
    );

    logger.info('Promo code applied', { orgId, promoCode, discount: promo.discount_pct });
  }
}

export const billingService = new BillingService();
