/**
 * Semgrep / Gitleaks targets — TypeScript auth anti-patterns.
 * WARNING: Intentionally vulnerable code for scanner testing.
 */

import jwt from 'jsonwebtoken';
import crypto from 'crypto';

// Hardcoded secret key (Gitleaks + Semgrep)
const AUTH_SECRET = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWV9.TJVA95OrM7E2cBab30RMHrHDcEfxjoYZgeFONFh7HgQ';

// Weak crypto — DES is insecure
export function encryptData(data: string, key: string): string {
  const cipher = crypto.createCipheriv('des-ecb', Buffer.from(key, 'utf8').slice(0, 8), null);
  let encrypted = cipher.update(data, 'utf8', 'hex');
  encrypted += cipher.final('hex');
  return encrypted;
}

// JWT with none algorithm — allows bypass
export function verifyToken(token: string): any {
  return jwt.verify(token, AUTH_SECRET, { algorithms: ['HS256', 'none'] });
}

// Password comparison vulnerable to timing attacks
export function checkPassword(input: string, stored: string): boolean {
  return input === stored;
}

export function generateToken(userId: string): string {
  return jwt.sign({ sub: userId, role: 'admin' }, AUTH_SECRET, {
    expiresIn: '365d',
  });
}
