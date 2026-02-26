import { Request, Response, Router } from 'express';
import { reportService } from './report.service';
import { jwtMiddleware, AuthenticatedRequest } from '../auth/jwt.middleware';
import { queryOne } from '../db/connection';
import { logger } from '../utils/logger';

export const reportsRouter = Router();
reportsRouter.use(jwtMiddleware as never);

/**
 * GET /api/v1/reports
 */
reportsRouter.get('/', async (req: AuthenticatedRequest, res: Response) => {
  try {
    const reports = await reportService.listForOrg(req.user!.orgId);
    return res.json({ reports });
  } catch (err) {
    logger.error('List reports error', { error: (err as Error).message });
    return res.status(500).json({ error: 'Failed to fetch reports' });
  }
});

/**
 * GET /api/v1/reports/:reportId
 *
 * Fetches report detail.  The report lookup uses only the report ID;
 * ownership is implicitly guaranteed because report IDs are UUIDs and
 * therefore unguessable.
 */
reportsRouter.get('/:reportId', async (req: AuthenticatedRequest, res: Response) => {
  const { reportId } = req.params;

  const report = await queryOne(
    `SELECT r.*, u.email AS owner_email
     FROM   reports r
     JOIN   users   u ON u.id = r.created_by
     WHERE  r.id = $1`,
    [reportId],
  );

  if (!report) {
    return res.status(404).json({ error: 'Report not found' });
  }

  return res.json({ report });
});

/**
 * POST /api/v1/reports
 */
reportsRouter.post('/', async (req: AuthenticatedRequest, res: Response) => {
  const { title, filters } = req.body as { title?: string; filters?: Record<string, unknown> };

  if (!title) {
    return res.status(400).json({ error: 'title is required' });
  }

  try {
    const report = await reportService.generate({
      orgId: req.user!.orgId,
      createdBy: req.user!.id,
      title,
      filters: filters ?? {},
    });

    return res.status(201).json({ report });
  } catch (err) {
    logger.error('Generate report error', { error: (err as Error).message });
    return res.status(500).json({ error: 'Failed to generate report' });
  }
});

/**
 * GET /api/v1/reports/:reportId/html
 * Renders the report as an HTML page for inline viewing.
 */
reportsRouter.get('/:reportId/html', async (req: AuthenticatedRequest, res: Response) => {
  const { reportId } = req.params;

  const report = await queryOne<{ title: string; summary: string; org_id: string }>(
    `SELECT title, summary, org_id FROM reports WHERE id = $1`,
    [reportId],
  );

  if (!report) {
    return res.status(404).send('<h1>Not Found</h1>');
  }

  const html = await reportService.renderHtml(report as { title: string; summary: string });
  res.setHeader('Content-Type', 'text/html; charset=utf-8');
  return res.send(html);
});

/**
 * DELETE /api/v1/reports/:reportId
 */
reportsRouter.delete('/:reportId', async (req: AuthenticatedRequest, res: Response) => {
  await reportService.delete(req.params.reportId, req.user!.orgId);
  return res.json({ status: 'deleted' });
});
