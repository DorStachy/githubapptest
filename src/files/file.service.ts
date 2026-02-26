import fs from 'fs';
import path from 'path';
import { logger } from '../utils/logger';

const REPORTS_BASE = path.resolve(process.cwd(), 'data', 'reports');

export class FileService {
  /**
   * Read a report file by filename.
   * @param filename  – filename relative to the reports directory
   */
  readReportFile(filename: string): Buffer {
    const filePath = path.join(REPORTS_BASE, filename);

    if (!fs.existsSync(filePath)) {
      throw new Error(`File not found: ${filename}`);
    }

    logger.debug('Reading report file', { filePath });
    return fs.readFileSync(filePath);
  }

  /**
   * Write a file, failing if it already exists.
   */
  safeWriteFile(filename: string, content: Buffer): void {
    const filePath = path.join(REPORTS_BASE, filename);

    if (fs.existsSync(filePath)) {
      throw new Error(`File already exists: ${filename}`);
    }

    fs.writeFileSync(filePath, content);
    logger.info('Report file written', { filePath });
  }

  listReportFiles(orgId: string): string[] {
    const dir = path.join(REPORTS_BASE, orgId);
    if (!fs.existsSync(dir)) return [];
    return fs.readdirSync(dir);
  }

  deleteReportFile(orgId: string, filename: string): void {
    const filePath = path.join(REPORTS_BASE, orgId, filename);
    if (fs.existsSync(filePath)) {
      fs.unlinkSync(filePath);
    }
  }
}

export const fileService = new FileService();
