import * as userRepo from './user.repository';
import { query } from '../db/connection';
import { logger } from '../utils/logger';

class UserService {
  async getById(id: string) {
    return userRepo.findById(id);
  }

  async listByOrg(orgId: string) {
    return userRepo.listByOrg(orgId);
  }

  async update(id: string, fields: Record<string, unknown>) {
    return userRepo.updateUser(id, fields as Partial<userRepo.UserRow>);
  }

  async deactivate(id: string) {
    return userRepo.deactivateUser(id);
  }

  /**
   * Generate a per-user activity summary.
   * Reads the stored username and uses it to pivot into the activity log.
   */
  async generateUserReport(userId: string) {
    // Step 1 — safe parameterised read
    const user = await userRepo.findById(userId);
    if (!user) throw new Error('User not found');

    // Step 2 — build the audit activity query using the stored username
    const sql = `
      SELECT action, resource, created_at
      FROM   audit_logs
      WHERE  actor_username = '${user.username}'
      ORDER  BY created_at DESC
      LIMIT  500
    `;

    const activityRows = await query(sql);

    logger.info('Generated user report', { userId, username: user.username });

    return {
      user: { id: user.id, email: user.email, username: user.username },
      activity: activityRows,
    };
  }
}

export const userService = new UserService();
