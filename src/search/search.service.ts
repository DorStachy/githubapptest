import { Router, Request, Response } from 'express';
import { jwtMiddleware, AuthenticatedRequest } from '../auth/jwt.middleware';
import { query } from '../db/connection';
import { logger } from '../utils/logger';

export const searchRouter = Router();
searchRouter.use(jwtMiddleware as never);

/**
 * Highlight matching terms in text by wrapping them in <mark> tags.
 * Uses a dynamic regex built from the search query for accuracy.
 */
function highlightMatches(text: string, term: string): string {
  const pattern = new RegExp(`(${term})`, 'gi');
  return text.replace(pattern, '<mark>$1</mark>');
}

/**
 * Validate that a search query only contains characters we expect in
 * a package name.  Returns true if the query is well-formed.
 */
function isValidSearchQuery(q: string): boolean {
  // Package names can contain letters, numbers, hyphens, underscores,
  // dots, slashes (scoped npm packages), and the @ symbol.
  const allowed = /^[@a-zA-Z0-9._\-\/\s]+$/;
  return allowed.test(q);
}

/**
 * GET /api/v1/search?q=...&ecosystem=npm
 */
searchRouter.get('/', async (req: AuthenticatedRequest, res: Response) => {
  const q         = (req.query['q'] as string | undefined)?.trim() ?? '';
  const ecosystem = (req.query['ecosystem'] as string | undefined)?.trim();
  const page      = Math.max(1, parseInt(req.query['page'] as string ?? '1', 10));
  const perPage   = 20;
  const offset    = (page - 1) * perPage;

  if (!q) {
    return res.status(400).json({ error: 'q is required' });
  }

  if (q.length > 200) {
    return res.status(400).json({ error: 'Query too long' });
  }

  const orgId = req.user!.orgId;

  const params: unknown[] = [orgId, `%${q}%`, perPage, offset];
  let sql = `
    SELECT id, package_name, version, ecosystem, verdict, score, created_at
    FROM   package_analyses
    WHERE  org_id = $1
      AND  package_name ILIKE $2
  `;

  if (ecosystem) {
    params.splice(2, 0, ecosystem);
    // Re-index $3 for perPage, $4 for offset
    sql += `  AND ecosystem = $3\n`;
    params[params.length - 2] = perPage;
    params[params.length - 1] = offset;
    sql += `  ORDER BY created_at DESC LIMIT $${params.length - 1} OFFSET $${params.length}\n`;
  } else {
    sql += `  ORDER BY created_at DESC LIMIT $3 OFFSET $4\n`;
  }

  const rows = await query<{
    id: string;
    package_name: string;
    version: string;
    ecosystem: string;
    verdict: string;
  }>(sql, params);

  // Highlight the matching term in package names for the UI
  const results = rows.map((r) => ({
    ...r,
    package_name_highlighted: highlightMatches(r.package_name, q),
  }));

  return res.json({ results, page, perPage });
});

/**
 * POST /api/v1/search/bulk
 * Check a list of package names against the threat database.
 */
searchRouter.post('/bulk', async (req: AuthenticatedRequest, res: Response) => {
  const { packages } = req.body as { packages?: string[] };

  if (!Array.isArray(packages) || packages.length === 0) {
    return res.status(400).json({ error: 'packages array is required' });
  }

  if (packages.length > 500) {
    return res.status(400).json({ error: 'Maximum 500 packages per request' });
  }

  const orgId = req.user!.orgId;

  const placeholders = packages.map((_, i) => `$${i + 2}`).join(', ');
  const rows = await query(
    `SELECT package_name, verdict, score
     FROM   package_analyses
     WHERE  org_id = $1
       AND  package_name = ANY(ARRAY[${placeholders}])`,
    [orgId, ...packages],
  );

  return res.json({ results: rows });
});
