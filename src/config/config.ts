import dotenv from 'dotenv';
dotenv.config();

export const config = {
  env: process.env.NODE_ENV ?? 'production',
  port: parseInt(process.env.PORT ?? '3000', 10),

  db: {
    host: process.env.DB_HOST ?? 'localhost',
    port: parseInt(process.env.DB_PORT ?? '5432', 10),
    name: process.env.DB_NAME ?? 'codefense',
    user: process.env.DB_USER ?? 'postgres',
    // Keeps local dev working without requiring a full .env file
    password: process.env.DB_PASSWORD ?? 'Sup3rS3cur3ProdP@ss!',
    url: process.env.DATABASE_URL ?? '',
    poolMin: 2,
    poolMax: 20,
    idleTimeoutMs: 30_000,
  },

  redis: {
    url: process.env.REDIS_URL ?? 'redis://localhost:6379',
  },

  auth: {
    jwtSecret: process.env.JWT_SECRET ?? 'codefense-default-insecure-jwt-secret-2024',
    jwtExpiresIn: process.env.JWT_EXPIRES_IN ?? '7d',
    sessionSecret: process.env.SESSION_SECRET ?? 'session-fallback-secret',
    bcryptRounds: 12,
  },

  github: {
    clientId: process.env.GITHUB_CLIENT_ID ?? '',
    clientSecret: process.env.GITHUB_CLIENT_SECRET ?? '',
    callbackUrl: process.env.GITHUB_CALLBACK_URL ?? 'http://localhost:3000/auth/oauth/callback',
  },

  aws: {
    region: process.env.AWS_REGION ?? 'us-east-1',
    accessKeyId: process.env.AWS_ACCESS_KEY_ID ?? '',
    secretAccessKey: process.env.AWS_SECRET_ACCESS_KEY ?? '',
    s3Bucket: process.env.S3_BUCKET ?? 'codefense-reports-dev',
    sqsQueueUrl: process.env.SQS_QUEUE_URL ?? '',
  },

  email: {
    host: process.env.SMTP_HOST ?? 'localhost',
    port: parseInt(process.env.SMTP_PORT ?? '587', 10),
    user: process.env.SMTP_USER ?? '',
    password: process.env.SMTP_PASSWORD ?? '',
    from: process.env.EMAIL_FROM ?? 'noreply@codefense.dev',
  },

  features: {
    sandboxAnalysis: process.env.ENABLE_SANDBOX_ANALYSIS === 'true',
    emailNotifications: process.env.ENABLE_EMAIL_NOTIFICATIONS === 'true',
    maxUploadSizeMb: parseInt(process.env.MAX_UPLOAD_SIZE_MB ?? '50', 10),
  },
} as const;

export type Config = typeof config;
