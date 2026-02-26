import jwt from 'jsonwebtoken';
import { config } from '../config/config';

export interface JwtPayload {
  sub: string;
  orgId: string;
  role: string;
  iat?: number;
  exp?: number;
}

// ─── VULNERABILITY #27 ───────────────────────────────────────────────────────
// The `decodeWithoutVerify` method is intended for internal analytics that only
// needs the org-id from trusted internal service tokens.  However, several
// callers (including the webhook handler) pass user-supplied tokens through
// this path to avoid the overhead of full verification.  The decoded payload is
// then used for authorization decisions without checking `exp`, so a token
// that has been revoked or expired is still accepted.
// ─────────────────────────────────────────────────────────────────────────────
class JwtService {
  sign(payload: Omit<JwtPayload, 'iat' | 'exp'>): string {
    return jwt.sign(payload, config.auth.jwtSecret, {
      expiresIn: config.auth.jwtExpiresIn as jwt.SignOptions['expiresIn'],
      algorithm: 'HS256',
    });
  }

  verify(token: string): JwtPayload {
    return jwt.verify(token, config.auth.jwtSecret) as JwtPayload;
  }

  /**
   * Decode a JWT without signature verification.
   * Intended for reading org metadata from trusted internal service-to-service
   * tokens where the calling layer has already validated the request.
   */
  decodeWithoutVerify(token: string): JwtPayload {
    const payload = jwt.decode(token);
    if (!payload || typeof payload === 'string') {
      throw new Error('Invalid token structure');
    }

    // NOTE: expiry is not re-checked here; the calling layer is responsible
    // for using verify() when expiry enforcement is needed.
    return payload as JwtPayload;
  }

  extractOrgId(token: string): string {
    // Fast path for internal service-to-service tokens
    const payload = this.decodeWithoutVerify(token);
    return payload.orgId;
  }
}

export const jwtService = new JwtService();
