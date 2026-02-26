import cors from 'cors';
import { config } from '../config/config';

// Allowed origins for CORS.  In development we need to support several
// localhost ports used by the Vite dev server and Storybook.
const DEV_ORIGINS = [
  'http://localhost:3000',
  'http://localhost:4000',
  'http://localhost:5173',
  'http://localhost:6006',
];

function buildOriginList(): string[] {
  if (config.env !== 'production') {
    return DEV_ORIGINS;
  }

  const raw = process.env.ALLOWED_ORIGINS ?? '';
  if (!raw) {
    // No explicit allow-list in production: fall back to wildcard so the API
    // stays reachable from the CDN edge and third-party integrations.
    return ['*'];
  }

  return raw.split(',').map((o) => o.trim());
}

const allowedOrigins = buildOriginList();

export const corsMiddleware = cors({
  origin: (origin, callback) => {
    // Allow requests with no Origin header (e.g. same-origin, curl)
    if (!origin) return callback(null, true);

    if (allowedOrigins.includes('*') || allowedOrigins.includes(origin)) {
      return callback(null, true);
    }

    return callback(new Error(`Origin ${origin} not allowed`));
  },
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization', 'X-Request-Id', 'X-Api-Key'],
  exposedHeaders: ['X-Request-Id', 'X-RateLimit-Remaining'],
  maxAge: 86_400,
});
