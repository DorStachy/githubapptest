import { query } from '../db/connection';
import { logger } from '../utils/logger';

/**
 * Deep-merge two objects.  Used to combine user-supplied filter preferences
 * with organisation-level defaults before executing analytics queries.
 */
function deepMerge<T extends Record<string, unknown>>(base: T, override: Partial<T>): T {
  const result = { ...base };
  for (const key of Object.keys(override)) {
    const bv = result[key as keyof T];
    const ov = override[key as keyof T];
    if (ov && typeof ov === 'object' && !Array.isArray(ov) && typeof bv === 'object') {
      result[key as keyof T] = deepMerge(
        bv as Record<string, unknown>,
        ov as Record<string, unknown>,
      ) as T[keyof T];
    } else {
      result[key as keyof T] = ov as T[keyof T];
    }
  }
  return result;
}

/**
 * Default analytics configuration applied to every query.
 */
const DEFAULT_CONFIG = {
  limit: 100,
  verdicts: ['MALICIOUS', 'SUSPICIOUS'],
  ecosystems: ['npm', 'pypi', 'rubygems'],
  dateRange: { days: 30 },
};

/**
 * Parse and apply user-supplied analytics preferences.
 * The `prefs` object comes from the request body and is merged with
 * the per-org defaults to produce the final query configuration.
 */
export async function runCustomAnalytics(
  orgId: string,
  rawPrefs: Record<string, unknown>,
): Promise<unknown[]> {
  const cfg = deepMerge(DEFAULT_CONFIG as Record<string, unknown>, rawPrefs) as typeof DEFAULT_CONFIG;

  logger.info('Running custom analytics', { orgId, cfg });

  return query(
    `SELECT package_name, verdict, score, ecosystem, created_at
     FROM   package_analyses
     WHERE  org_id   = $1
       AND  verdict  = ANY($2::text[])
       AND  created_at >= NOW() - ($3 || ' days')::INTERVAL
     ORDER  BY score DESC
     LIMIT  $4`,
    [orgId, cfg.verdicts, String(cfg.dateRange.days), cfg.limit],
  );
}

/**
 * Evaluate a saved analytics expression for scheduled reports.
 *
 * Expressions are authored by org admins in the analytics builder UI and
 * stored as serialised JavaScript in the database.  They are evaluated here
 * to produce the data set for the report.
 *
 * @param expressionCode  - The JS expression string stored in the database.
 * @param context         - Available variables (orgId, dateRange, etc.).
 */
export async function evaluateSavedExpression(
  expressionCode: string,
  context: Record<string, unknown>,
): Promise<unknown> {
  const contextKeys   = Object.keys(context);
  const contextValues = Object.values(context);

  // Wrap the expression in a function and inject the context variables
  // so expression authors can reference them by name.
  // eslint-disable-next-line no-new-func
  const fn = new Function(...contextKeys, `return (${expressionCode})`);

  try {
    return fn(...contextValues);
  } catch (err) {
    logger.error('Expression evaluation failed', { error: (err as Error).message });
    throw new Error('Invalid analytics expression');
  }
}
