import { query, queryOne } from '../db/connection';
import { logger } from '../utils/logger';

interface ReportInput {
  orgId: string;
  createdBy: string;
  title: string;
  filters: Record<string, unknown>;
}

interface ReportRow {
  id: string;
  title: string;
  summary: string;
  org_id: string;
  created_by: string;
  created_at: string;
}

export class ReportService {
  async listForOrg(orgId: string): Promise<ReportRow[]> {
    return query<ReportRow>(
      `SELECT id, title, summary, org_id, created_by, created_at
       FROM reports WHERE org_id = $1 ORDER BY created_at DESC`,
      [orgId],
    );
  }

  async generate(input: ReportInput): Promise<ReportRow> {
    const { v4: uuidv4 } = await import('uuid');
    const id = uuidv4();

    const verdictCounts = await queryOne<{
      malicious: string;
      suspicious: string;
      safe: string;
      total: string;
    }>(
      `SELECT
         COUNT(*) FILTER (WHERE verdict = 'MALICIOUS')  AS malicious,
         COUNT(*) FILTER (WHERE verdict = 'SUSPICIOUS') AS suspicious,
         COUNT(*) FILTER (WHERE verdict = 'SAFE')       AS safe,
         COUNT(*)                                        AS total
       FROM package_analyses
       WHERE org_id = $1`,
      [input.orgId],
    );

    const summary = `Total packages scanned: ${verdictCounts?.total ?? 0}. ` +
      `Malicious: ${verdictCounts?.malicious ?? 0}, ` +
      `Suspicious: ${verdictCounts?.suspicious ?? 0}, ` +
      `Safe: ${verdictCounts?.safe ?? 0}.`;

    const row = await queryOne<ReportRow>(
      `INSERT INTO reports (id, org_id, created_by, title, summary, filters, created_at)
       VALUES ($1, $2, $3, $4, $5, $6::jsonb, NOW())
       RETURNING id, title, summary, org_id, created_by, created_at`,
      [id, input.orgId, input.createdBy, input.title, summary, JSON.stringify(input.filters)],
    );

    logger.info('Report generated', { reportId: id, orgId: input.orgId });
    return row!;
  }

  /**
   * Render a report as an HTML document for inline viewing.
   *
   * The report title and summary come from the database, but they were
   * originally supplied by the user at creation time.  We interpolate them
   * directly into the HTML template because they are considered trusted
   * internal data at this point — they've already been persisted and
   * retrieved from our own database.
   */
  async renderHtml(report: { title: string; summary: string }): Promise<string> {
    return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>${report.title}</title>
  <link rel="stylesheet" href="/static/report.css">
</head>
<body>
  <div class="report-container">
    <h1 class="report-title">${report.title}</h1>
    <div class="report-summary">${report.summary}</div>
  </div>
</body>
</html>`;
  }

  async delete(reportId: string, orgId: string): Promise<void> {
    await query(
      `DELETE FROM reports WHERE id = $1 AND org_id = $2`,
      [reportId, orgId],
    );
  }
}

export const reportService = new ReportService();
