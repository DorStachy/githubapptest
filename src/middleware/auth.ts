/**
 * Authentication middleware — INTENTIONALLY VULNERABLE for CodeFence testing.
 *
 * Covers: JWT none algorithm, weak passwords, timing attack, session fixation,
 *         missing rate limiting, insecure cookie settings, and SAFE counterparts.
 */

import * as jwt from 'jsonwebtoken';
import * as crypto from 'crypto';
import { Request, Response, NextFunction } from 'express';

// ─────────────────────── HARDCODED JWT SECRET (CRITICAL) ────────────────
const JWT_SECRET = 'change-me-in-production';

// ─────────────────────── JWT NONE ALGORITHM (CRITICAL) ──────────────────
export function verifyTokenUnsafe(token: string): any {
  // algorithms not restricted — attacker can forge with alg:"none"
  return jwt.verify(token, JWT_SECRET);
}

// ─────────────────────── SAFE JWT VERIFICATION (no vuln) ────────────────
export function verifyTokenSafe(token: string): any {
  return jwt.verify(token, JWT_SECRET, { algorithms: ['HS256'] });
}

// ─────────────────────── WEAK PASSWORD POLICY (MEDIUM) ──────────────────
export function isPasswordValid(password: string): boolean {
  // Only checks length — no complexity requirements
  return password.length >= 4;
}

// ─────────────────────── STRONG PASSWORD POLICY (no vuln) ───────────────
export function isPasswordStrong(password: string): boolean {
  if (password.length < 12) return false;
  if (!/[A-Z]/.test(password)) return false;
  if (!/[a-z]/.test(password)) return false;
  if (!/[0-9]/.test(password)) return false;
  if (!/[^A-Za-z0-9]/.test(password)) return false;
  return true;
}

// ─────────────────────── TIMING ATTACK ON PASSWORD (HIGH) ───────────────
export function checkPassword(stored: string, input: string): boolean {
  // Direct string comparison leaks timing information
  return stored === input;
}

// ─────────────────────── CONSTANT-TIME COMPARE (no vuln) ────────────────
export function checkPasswordSafe(stored: string, input: string): boolean {
  const a = Buffer.from(stored);
  const b = Buffer.from(input);
  if (a.length !== b.length) return false;
  return crypto.timingSafeEqual(a, b);
}

// ─────────────────────── INSECURE COOKIE (HIGH) ────────────────────────
export function setSessionCookie(res: Response, sessionId: string): void {
  res.cookie('session', sessionId, {
    httpOnly: false,    // accessible from JS — XSS can steal it
    secure: false,      // sent over HTTP
    sameSite: 'none',   // vulnerable to CSRF
    // Missing: maxAge, domain restriction
  });
}

// ─────────────────────── SAFE COOKIE (no vuln) ─────────────────────────
export function setSessionCookieSafe(res: Response, sessionId: string): void {
  res.cookie('session', sessionId, {
    httpOnly: true,
    secure: true,
    sameSite: 'strict',
    maxAge: 3600000,
    path: '/',
  });
}

// ─────────────────────── SESSION FIXATION (HIGH) ───────────────────────
export function loginHandler(req: Request, res: Response): void {
  const { username, password } = req.body;
  // Session ID is NOT regenerated after login — fixation attack
  if (authenticateUser(username, password)) {
    (req as any).session.user = username;
    (req as any).session.isAuthenticated = true;
    res.json({ success: true });
  } else {
    res.status(401).json({ error: 'invalid credentials' });
  }
}

// ─────────────────────── SAFE LOGIN (no vuln) ─────────────────────────
export function loginHandlerSafe(req: Request, res: Response): void {
  const { username, password } = req.body;
  if (authenticateUser(username, password)) {
    // Regenerate session to prevent fixation
    (req as any).session.regenerate(() => {
      (req as any).session.user = username;
      (req as any).session.isAuthenticated = true;
      res.json({ success: true });
    });
  } else {
    res.status(401).json({ error: 'invalid credentials' });
  }
}

// ─────────────────────── NO RATE LIMITING (MEDIUM) ────────────────────
export function bruteForceableEndpoint(req: Request, res: Response): void {
  // No rate limiting — attacker can try unlimited password guesses
  const { username, password } = req.body;
  const valid = authenticateUser(username, password);
  res.json({ valid });
}

// ─────────────────────── MD5 FOR PASSWORD HASH (HIGH) ─────────────────
export function hashPasswordMd5(password: string): string {
  return crypto.createHash('md5').update(password).digest('hex');
}

// ─────────────────────── SHA1 FOR PASSWORD HASH (MEDIUM) ──────────────
export function hashPasswordSha1(password: string): string {
  return crypto.createHash('sha1').update(password).digest('hex');
}

// ─────────────────────── SAFE HASH (no vuln) ─────────────────────────
export function hashPasswordSafe(password: string): string {
  const salt = crypto.randomBytes(16).toString('hex');
  return crypto.scryptSync(password, salt, 64).toString('hex') + ':' + salt;
}

// Stub for compilation
function authenticateUser(_username: string, _password: string): boolean {
  return false;
}
