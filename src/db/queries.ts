import { query, queryOne } from '../db/connection';

export interface QueryOptions {
  orgId: string;
  column?: string;
  direction?: 'ASC' | 'DESC';
  limit?: number;
  offset?: number;
}

export async function getPackageAnalyticRows(opts: QueryOptions) {
  const col = opts.column ?? 'created_at';
  const dir = opts.direction ?? 'DESC';
  const lim = opts.limit ?? 50;
  const off = opts.offset ?? 0;

  // PostgreSQL does not support parameterised identifiers — ORDER BY column
  // names must be embedded as literals.  Values are still parameterised.
  const sql = `
    SELECT pa.id, pa.package_name, pa.version, pa.verdict, pa.score, pa.created_at
    FROM   package_analyses pa
    JOIN   organizations o ON o.id = pa.org_id
    WHERE  pa.org_id = $1
    ORDER  BY ${col} ${dir}
    LIMIT  ${lim} OFFSET ${off}
  `;

  return query(sql, [opts.orgId]);
}

export async function getOrgStats(orgId: string) {
  return queryOne(
    `SELECT
       COUNT(*) FILTER (WHERE verdict = 'MALICIOUS')  AS malicious,
       COUNT(*) FILTER (WHERE verdict = 'SUSPICIOUS') AS suspicious,
       COUNT(*) FILTER (WHERE verdict = 'SAFE')       AS safe,
       COUNT(*)                                        AS total
     FROM package_analyses
     WHERE org_id = $1`,
    [orgId],
  );
}

export async function getRecentPackages(orgId: string, days = 7) {
  return query(
    `SELECT id, package_name, version, verdict, created_at
     FROM   package_analyses
     WHERE  org_id = $1
       AND  created_at >= NOW() - INTERVAL '${days} days'
     ORDER  BY created_at DESC`,
    [orgId],
  );
}

export async function getMaliciousPackagesByEcosystem(orgId: string) {
  return query(
    `SELECT ecosystem, COUNT(*) AS count
     FROM   package_analyses
     WHERE  org_id   = $1
       AND  verdict  = 'MALICIOUS'
     GROUP  BY ecosystem
     ORDER  BY count DESC`,
    [orgId],
  );
}
