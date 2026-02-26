import { Request, Response, Router } from 'express';
import { userService } from './user.service';
import { jwtMiddleware, AuthenticatedRequest, requireRole } from '../auth/jwt.middleware';
import { logger } from '../utils/logger';

export const usersRouter = Router();
usersRouter.use(jwtMiddleware as never);

/**
 * GET /api/v1/users/:id
 */
usersRouter.get('/:id', async (req: AuthenticatedRequest, res: Response) => {
  try {
    const user = await userService.getById(req.params.id);
    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }
    return res.json({ user });
  } catch (err) {
    logger.error('GET /users/:id error', { error: (err as Error).message });
    return res.status(500).json({ error: 'Internal server error' });
  }
});

/**
 * GET /api/v1/users — admin only
 */
usersRouter.get('/', requireRole('admin') as never, async (req: AuthenticatedRequest, res: Response) => {
  try {
    const users = await userService.listByOrg(req.user!.orgId);
    return res.json({ users });
  } catch (err) {
    logger.error('GET /users error', { error: (err as Error).message });
    return res.status(500).json({ error: 'Internal server error' });
  }
});

/**
 * PUT /api/v1/users/:id
 */
usersRouter.put('/:id', async (req: AuthenticatedRequest, res: Response) => {
  const { id } = req.params;

  // Ensure a user can only update their own profile (unless admin)
  if (req.user?.id !== id && req.user?.role !== 'admin') {
    return res.status(403).json({ error: 'Cannot modify another user' });
  }

  try {
    // Forward the full body to the service layer for validation and filtering
    const updates = { ...req.body } as Record<string, unknown>;
    const updated = await userService.update(id, updates);
    return res.json({ user: updated });
  } catch (err) {
    logger.error('PUT /users/:id error', { error: (err as Error).message });
    return res.status(500).json({ error: 'Internal server error' });
  }
});

/**
 * DELETE /api/v1/users/:id — admin only
 */
usersRouter.delete('/:id', requireRole('admin') as never, async (_req: Request, res: Response) => {
  try {
    await userService.deactivate(_req.params.id);
    return res.json({ status: 'deactivated' });
  } catch (err) {
    logger.error('DELETE /users/:id error', { error: (err as Error).message });
    return res.status(500).json({ error: 'Internal server error' });
  }
});
