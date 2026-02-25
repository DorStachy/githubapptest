/**
 * Frozen secret pattern registry for Sink Guard.
 * 40+ compiled regexes covering AWS, GitHub, Google, Azure, Slack, Stripe, generic tokens, etc.
 * Object.freeze() ensures immutability after load.
 *
 * Each pattern has:
 *   - name: Human-readable label for audit/redaction logs
 *   - pattern: Compiled RegExp (global flag for scanning entire text)
 *   - severity: How critical the leak would be
 */

export interface SecretPattern {
  name: string;
  pattern: RegExp;
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM';
}

const patterns: SecretPattern[] = [
  // ── AWS ────────────────────────────────────────────────────────────────
  { name: 'AWS Access Key ID', pattern: /(?<![A-Za-z0-9])AKIA[0-9A-Z]{16}(?![A-Za-z0-9])/g, severity: 'CRITICAL' },
  { name: 'AWS Secret Access Key', pattern: /(?:aws_secret_access_key|aws_secret|secret_access_key)\s*[:=]\s*[A-Za-z0-9/+=]{40}/gi, severity: 'CRITICAL' },
  { name: 'AWS Session Token', pattern: /(?:aws_session_token)\s*[:=]\s*[A-Za-z0-9/+=]{100,}/gi, severity: 'CRITICAL' },
  { name: 'AWS ARN', pattern: /arn:aws:[a-zA-Z0-9\-]+:[a-zA-Z0-9\-]*:\d{12}:[a-zA-Z0-9\-_/:.]+/g, severity: 'MEDIUM' },

  // ── GitHub ─────────────────────────────────────────────────────────────
  { name: 'GitHub PAT (classic)', pattern: /ghp_[A-Za-z0-9]{36}/g, severity: 'CRITICAL' },
  { name: 'GitHub PAT (fine-grained)', pattern: /github_pat_[A-Za-z0-9_]{82}/g, severity: 'CRITICAL' },
  { name: 'GitHub OAuth Token', pattern: /gho_[A-Za-z0-9]{36}/g, severity: 'HIGH' },
  { name: 'GitHub App Token', pattern: /(?:ghu|ghs)_[A-Za-z0-9]{36}/g, severity: 'HIGH' },
  { name: 'GitHub App Refresh Token', pattern: /ghr_[A-Za-z0-9]{36}/g, severity: 'HIGH' },

  // ── Google / GCP ───────────────────────────────────────────────────────
  { name: 'Google API Key', pattern: /AIza[0-9A-Za-z\-_]{35}/g, severity: 'HIGH' },
  { name: 'Google OAuth Client Secret', pattern: /GOCSPX-[A-Za-z0-9\-_]{28}/g, severity: 'HIGH' },
  { name: 'GCP Service Account Key', pattern: /"private_key":\s*"-----BEGIN (?:RSA )?PRIVATE KEY-----/g, severity: 'CRITICAL' },

  // ── Azure ──────────────────────────────────────────────────────────────
  { name: 'Azure Storage Account Key', pattern: /(?:AccountKey|account_key)\s*[:=]\s*[A-Za-z0-9+/=]{88}/gi, severity: 'CRITICAL' },
  { name: 'Azure AD Client Secret', pattern: /(?:client_secret|clientSecret)\s*[:=]\s*[A-Za-z0-9~._\-]{34,}/gi, severity: 'HIGH' },

  // ── Slack ──────────────────────────────────────────────────────────────
  { name: 'Slack Bot Token', pattern: /xoxb-[0-9]{10,13}-[0-9]{10,13}-[a-zA-Z0-9]{24}/g, severity: 'HIGH' },
  { name: 'Slack User Token', pattern: /xoxp-[0-9]{10,13}-[0-9]{10,13}-[0-9]{10,13}-[a-f0-9]{32}/g, severity: 'HIGH' },
  { name: 'Slack Webhook URL', pattern: /https:\/\/hooks\.slack\.com\/services\/T[A-Z0-9]{8,}\/B[A-Z0-9]{8,}\/[A-Za-z0-9]{24}/g, severity: 'HIGH' },

  // ── Stripe ─────────────────────────────────────────────────────────────
  { name: 'Stripe Secret Key', pattern: /sk_live_[0-9a-zA-Z]{24,}/g, severity: 'CRITICAL' },
  { name: 'Stripe Publishable Key', pattern: /pk_live_[0-9a-zA-Z]{24,}/g, severity: 'MEDIUM' },
  { name: 'Stripe Restricted Key', pattern: /rk_live_[0-9a-zA-Z]{24,}/g, severity: 'HIGH' },

  // ── Anthropic ──────────────────────────────────────────────────────────
  { name: 'Anthropic API Key', pattern: /sk-ant-[A-Za-z0-9\-_]{93,}/g, severity: 'CRITICAL' },

  // ── OpenAI ─────────────────────────────────────────────────────────────
  { name: 'OpenAI API Key', pattern: /sk-[A-Za-z0-9]{20}T3BlbkFJ[A-Za-z0-9]{20}/g, severity: 'CRITICAL' },
  { name: 'OpenAI Project Key', pattern: /sk-proj-[A-Za-z0-9\-_]{40,}/g, severity: 'CRITICAL' },

  // ── SendGrid ───────────────────────────────────────────────────────────
  { name: 'SendGrid API Key', pattern: /SG\.[A-Za-z0-9\-_]{22}\.[A-Za-z0-9\-_]{43}/g, severity: 'HIGH' },

  // ── Twilio ─────────────────────────────────────────────────────────────
  { name: 'Twilio Auth Token', pattern: /(?:twilio_auth_token|TWILIO_AUTH_TOKEN)\s*[:=]\s*[a-f0-9]{32}/gi, severity: 'HIGH' },

  // ── Mailgun ────────────────────────────────────────────────────────────
  { name: 'Mailgun API Key', pattern: /key-[A-Za-z0-9]{32}/g, severity: 'HIGH' },

  // ── Database URLs ──────────────────────────────────────────────────────
  { name: 'PostgreSQL Connection String', pattern: /postgres(?:ql)?:\/\/[^\s'"]+:[^\s'"]+@[^\s'"]+/gi, severity: 'CRITICAL' },
  { name: 'MySQL Connection String', pattern: /mysql:\/\/[^\s'"]+:[^\s'"]+@[^\s'"]+/gi, severity: 'CRITICAL' },
  { name: 'MongoDB Connection String', pattern: /mongodb(?:\+srv)?:\/\/[^\s'"]+:[^\s'"]+@[^\s'"]+/gi, severity: 'CRITICAL' },
  { name: 'Redis Connection String', pattern: /redis:\/\/[^\s'"]+:[^\s'"]+@[^\s'"]+/gi, severity: 'HIGH' },

  // ── Private Keys ───────────────────────────────────────────────────────
  { name: 'RSA Private Key', pattern: /-----BEGIN RSA PRIVATE KEY-----/g, severity: 'CRITICAL' },
  { name: 'EC Private Key', pattern: /-----BEGIN EC PRIVATE KEY-----/g, severity: 'CRITICAL' },
  { name: 'Generic Private Key', pattern: /-----BEGIN PRIVATE KEY-----/g, severity: 'CRITICAL' },
  { name: 'PGP Private Key', pattern: /-----BEGIN PGP PRIVATE KEY BLOCK-----/g, severity: 'CRITICAL' },
  { name: 'SSH Private Key (OpenSSH)', pattern: /-----BEGIN OPENSSH PRIVATE KEY-----/g, severity: 'CRITICAL' },

  // ── JWT ────────────────────────────────────────────────────────────────
  { name: 'JWT Token', pattern: /eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_\-+/=]{10,}/g, severity: 'HIGH' },

  // ── Cloudflare ─────────────────────────────────────────────────────────
  { name: 'Cloudflare API Token', pattern: /(?:cloudflare_api_token|CF_API_TOKEN)\s*[:=]\s*[A-Za-z0-9_-]{40}/gi, severity: 'MEDIUM' }, // Narrowed: requires assignment context
  { name: 'Cloudflare Global API Key', pattern: /(?:cloudflare_api_key|CF_API_KEY)\s*[:=]\s*[a-f0-9]{37}/gi, severity: 'HIGH' },

  // ── Vercel ─────────────────────────────────────────────────────────────
  { name: 'Vercel Token', pattern: /(?:VERCEL_TOKEN|vercel_token)\s*[:=]\s*[A-Za-z0-9]{24}/gi, severity: 'HIGH' },

  // ── NPM ────────────────────────────────────────────────────────────────
  { name: 'NPM Token', pattern: /npm_[A-Za-z0-9]{36}/g, severity: 'HIGH' },
  { name: 'NPM Auth Token (npmrc)', pattern: /\/\/registry\.npmjs\.org\/:_authToken=[^\s]+/g, severity: 'HIGH' },

  // ── PyPI ───────────────────────────────────────────────────────────────
  { name: 'PyPI API Token', pattern: /pypi-[A-Za-z0-9\-_]{100,}/g, severity: 'HIGH' },

  // ── Generic patterns ───────────────────────────────────────────────────
  { name: 'Generic Secret Assignment', pattern: /(?:secret|password|passwd|pwd|token|api_key|apikey|access_key|auth_token|credentials)\s*[:=]\s*['"][^\s'"]{8,}['"]/gi, severity: 'MEDIUM' },
  { name: 'Bearer Token in Header', pattern: /(?:Authorization|authorization):\s*Bearer\s+[A-Za-z0-9\-._~+/]+=*/g, severity: 'HIGH' },
  { name: 'Basic Auth Header', pattern: /(?:Authorization|authorization):\s*Basic\s+[A-Za-z0-9+/=]{10,}/g, severity: 'HIGH' },
];

/**
 * Frozen, immutable pattern registry.
 * Use `SECRET_PATTERNS` throughout the application — never modify.
 */
export const SECRET_PATTERNS: readonly SecretPattern[] = Object.freeze(patterns);

/**
 * Shannon entropy calculation for detecting high-entropy strings
 * that may be secrets not matched by specific patterns.
 * Threshold: 4.5 bits/char for strings ≥ 20 chars.
 */
export function calculateEntropy(str: string): number {
  if (str.length === 0) return 0;
  const freq = new Map<string, number>();
  for (const ch of str) {
    freq.set(ch, (freq.get(ch) || 0) + 1);
  }
  let entropy = 0;
  for (const count of freq.values()) {
    const p = count / str.length;
    entropy -= p * Math.log2(p);
  }
  return entropy;
}

export const HIGH_ENTROPY_THRESHOLD = 4.5;
export const HIGH_ENTROPY_MIN_LENGTH = 20;
