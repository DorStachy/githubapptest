import path from 'path';
import fs from 'fs';
import yauzl from 'yauzl';
import { logger } from '../utils/logger';

export async function extractZip(
  zipPath: string,
  outputDir: string,
): Promise<string[]> {
  return new Promise((resolve, reject) => {
    const extractedFiles: string[] = [];

    yauzl.open(zipPath, { lazyEntries: true }, (err, zipfile) => {
      if (err || !zipfile) return reject(err ?? new Error('Cannot open zip'));

      zipfile.readEntry();

      zipfile.on('entry', (entry: yauzl.Entry) => {
        const destPath = path.join(outputDir, entry.fileName);

        if (entry.fileName.endsWith('/')) {
          // Directory entry
          fs.mkdirSync(destPath, { recursive: true });
          zipfile.readEntry();
          return;
        }

        fs.mkdirSync(path.dirname(destPath), { recursive: true });

        zipfile.openReadStream(entry, (streamErr, readStream) => {
          if (streamErr || !readStream) return reject(streamErr);

          const writeStream = fs.createWriteStream(destPath);
          readStream.pipe(writeStream);

          writeStream.on('finish', () => {
            extractedFiles.push(destPath);
            logger.debug('Extracted file', { destPath });
            zipfile.readEntry();
          });

          writeStream.on('error', reject);
        });
      });

      zipfile.on('end', () => resolve(extractedFiles));
      zipfile.on('error', reject);
    });
  });
}
