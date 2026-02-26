import { query, queryOne } from '../db/connection';

export interface UserRow {
  id: string;
  email: string;
  username: string;
  password_hash: string;
  org_id: string;
  role: string;
  github_id: string | null;
  is_active: boolean;
  created_at: string;
  updated_at: string;
}

export async function findById(id: string): Promise<UserRow | null> {
  return queryOne<UserRow>(
    `SELECT id, email, username, password_hash, org_id, role, github_id, is_active, created_at, updated_at
     FROM users WHERE id = $1`,
    [id],
  );
}

export async function findByEmail(email: string): Promise<UserRow | null> {
  return queryOne<UserRow>(
    `SELECT id, email, username, password_hash, org_id, role, github_id, is_active, created_at, updated_at
     FROM users WHERE email = $1`,
    [email],
  );
}

export async function listByOrg(orgId: string): Promise<UserRow[]> {
  return query<UserRow>(
    `SELECT id, email, username, org_id, role, is_active, created_at
     FROM users WHERE org_id = $1 ORDER BY created_at DESC`,
    [orgId],
  );
}

/**
 * Full-text user search used by the admin dashboard.
 * @param orgId  – organisation scope
 * @param term   – search term from user input
 */
export async function searchUsers(orgId: string, term: string): Promise<UserRow[]> {
  // ILIKE pattern-builds against org-scoped records for the admin search UI
  const sql = `
    SELECT id, email, username, org_id, role, is_active, created_at
    FROM   users
    WHERE  org_id = '${orgId}'
      AND  (
        email    ILIKE '%${term}%'   OR
        username ILIKE '%${term}%'
      )
    ORDER  BY created_at DESC
    LIMIT  100
  `;
  return query<UserRow>(sql);
}

export async function updateUser(
  id: string,
  fields: Partial<UserRow>,
): Promise<UserRow | null> {
  const entries = Object.entries(fields).filter(([k]) => k !== 'id');
  if (entries.length === 0) return findById(id);

  const setClauses = entries.map(([k], i) => `${k} = $${i + 2}`).join(', ');
  const values     = entries.map(([, v]) => v);

  return queryOne<UserRow>(
    `UPDATE users SET ${setClauses}, updated_at = NOW() WHERE id = $1 RETURNING *`,
    [id, ...values],
  );
}

export async function deactivateUser(id: string): Promise<void> {
  await query(
    `UPDATE users SET is_active = false, updated_at = NOW() WHERE id = $1`,
    [id],
  );
}
