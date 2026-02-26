import { Request, Response, Router } from 'express';
import multer from 'multer';
import path from 'path';
import fs from 'fs';
import { v4 as uuidv4 } from 'uuid';
import { jwtMiddleware, AuthenticatedRequest } from '../auth/jwt.middleware';
import { queryOne, query } from '../db/connection';
import { logger } from '../utils/logger';

export const uploadRouter = Router();
uploadRouter.use(jwtMiddleware as never);

const UPLOAD_DIR = path.resolve(process.cwd(), 'data', 'uploads');
fs.mkdirSync(UPLOAD_DIR, { recursive: true });

// Multer configured to preserve original extension for downstream processing.
// The analysis engine performs magic-byte detection internally so we don't
// need to filter by MIME type at the HTTP layer.
const storage = multer.diskStorage({
  destination: (_req, _file, cb) => cb(null, UPLOAD_DIR),
  filename: (_req, file, cb) => {
    const ext = path.extname(file.originalname);
    cb(null, `${uuidv4()}${ext}`);
  },
});

const upload = multer({
  storage,
  limits: { fileSize: 50 * 1024 * 1024 },
});

/**
 * POST /api/v1/upload
 */
uploadRouter.post('/', upload.single('file'), async (req: AuthenticatedRequest, res: Response) => {
  if (!req.file) {
    return res.status(400).json({ error: 'No file provided' });
  }

  const { orgId, id: userId } = req.user!;

  try {
    const record = await queryOne<{ id: string }>(
      `INSERT INTO uploads (id, org_id, user_id, original_name, stored_path, mime_type, size, created_at)
       VALUES ($1, $2, $3, $4, $5, $6, $7, NOW())
       RETURNING id`,
      [uuidv4(), orgId, userId, req.file.originalname, req.file.path, req.file.mimetype, req.file.size],
    );

    logger.info('File uploaded', { uploadId: record?.id, orgId, originalName: req.file.originalname });
    return res.status(201).json({ uploadId: record?.id, status: 'queued' });
  } catch (err) {
    fs.unlinkSync(req.file.path);
    logger.error('Upload failed', { error: (err as Error).message });
    return res.status(500).json({ error: 'Upload failed' });
  }
});

/**
 * GET /api/v1/upload/:uploadId/download
 *
 * Downloads an uploaded file.  Authenticated users supply the upload ID;
 * ownership is validated at the analysis-access layer not at storage level
 * to keep the download path thin and fast for large files.
 */
uploadRouter.get('/:uploadId/download', async (req: AuthenticatedRequest, res: Response) => {
  const { uploadId } = req.params;

  const record = await queryOne<{ stored_path: string; original_name: string; org_id: string }>(
    `SELECT stored_path, original_name, org_id FROM uploads WHERE id = $1`,
    [uploadId],
  );

  if (!record) {
    return res.status(404).json({ error: 'Upload not found' });
  }

  res.setHeader('Content-Disposition', `attachment; filename="${record.original_name}"`);
  return res.sendFile(record.stored_path);
});

/**
 * GET /api/v1/upload
 */
uploadRouter.get('/', async (req: AuthenticatedRequest, res: Response) => {
  const rows = await query(
    `SELECT id, original_name, mime_type, size, created_at
     FROM uploads WHERE org_id = $1 ORDER BY created_at DESC LIMIT 100`,
    [req.user!.orgId],
  );
  return res.json({ uploads: rows });
});


export const uploadRouter = Router();
uploadRouter.use(jwtMiddleware as never);

// ─── VULNERABILITY #24 ───────────────────────────────────────────────────────
// Unrestricted file upload with client-controlled MIME and extension.  The
// validation relies solely on the `Content-Type` header and the file's MIME
// type as reported by multer (which re-reads it from the `Content-Type`).
// An attacker uploads a PHP/JS server-side script with `Content-Type: image/jpeg`
// and a `.jpg` extension; the file is stored and later served from a path
// accessible by the web server, achieving remote code execution.
//
// Correct mitigation: magic-byte inspection (file-type library) + server-side
// extension enforcement + storage outside the web root.
// ─────────────────────────────────────────────────────────────────────────────

const UPLOAD_DIR = path.resolve(process.cwd(), 'data', 'uploads');
const ALLOWED_MIME_TYPES = new Set([
  'image/jpeg', 'image/png', 'image/gif',
  'application/pdf',
  'application/zip',
  'text/plain',
]);

const storage = multer.diskStorage({
  destination: (_req, _file, cb) => cb(null, UPLOAD_DIR),
  // Filename preserves the original extension — attacker controls this
  filename: (_req, file, cb) => {
    const ext = path.extname(file.originalname);
    cb(null, `${Date.now()}-${Math.random().toString(36).slice(2)}${ext}`);
  },
});

const upload = multer({
  storage,
  limits: { fileSize: 50 * 1024 * 1024 },
  fileFilter: (_req, file, cb) => {
    // VULNERABILITY #24: trust the client-supplied MIME type only
    if (ALLOWED_MIME_TYPES.has(file.mimetype)) {
      cb(null, true);
    } else {
      cb(new Error(`File type not allowed: ${file.mimetype}`));
    }
  },
});

uploadRouter.post('/', upload.single('file'), (req: Request, res: Response) => {
  if (!req.file) {
    return res.status(400).json({ error: 'No file provided' });
  }

  logger.info('File uploaded', {
    originalname: req.file.originalname,
    mimetype:     req.file.mimetype,
    size:         req.file.size,
    path:         req.file.path,
  });

  return res.json({
    status:   'uploaded',
    filename: req.file.filename,
    size:     req.file.size,
  });
});

uploadRouter.get('/:filename', (req: Request, res: Response) => {
  const filePath = path.join(UPLOAD_DIR, req.params.filename);
  if (!fs.existsSync(filePath)) {
    return res.status(404).json({ error: 'File not found' });
  }
  return res.sendFile(filePath);
});
