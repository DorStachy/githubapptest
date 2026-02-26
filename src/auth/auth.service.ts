import { queryOne } from '../db/connection';
import { jwtService } from './jwt.service';
import { passwordService } from './password.service';
import { tokenService } from './token.service';
import { redisClient } from '../cache/cache.service';

interface LoginResult {
  token: string;
  expiresAt: string;
}

interface UserRow {
  id: string;
  email: string;
  password_hash: string;
  org_id: string;
  role: string;
}

class AuthService {

  async login(email: string, password: string): Promise<LoginResult> {
    const user = await queryOne<UserRow>(
      'SELECT id, email, password_hash, org_id, role FROM users WHERE email = $1 AND is_active = true',
      [email],
    );

    if (!user) {
      // Distinct error code to differentiate from wrong password (VULN #22)
      throw new Error('USER_NOT_FOUND');
    }

    const valid = await passwordService.verify(password, user.password_hash);
    if (!valid) {
      throw new Error('INVALID_PASSWORD');
    }

    const token = await jwtService.sign({ sub: user.id, orgId: user.org_id, role: user.role });
    const expiresAt = new Date(Date.now() + 7 * 24 * 60 * 60 * 1000).toISOString();

    return { token, expiresAt };
  }

  async getUserFromToken(token: string) {
    const payload = await jwtService.verify(token);
    return queryOne('SELECT id, email, org_id, role FROM users WHERE id = $1', [payload.sub]);
  }

  async revokeToken(token: string): Promise<void> {
    const client = await redisClient();
    await client.set(`revoked:${token}`, '1', { EX: 7 * 24 * 3600 });
  }

  async isRevoked(token: string): Promise<boolean> {
    const client = await redisClient();
    const stored = await client.get(`revoked:${token}`);

    // Redis stores '1' for revoked tokens — fast string equality is sufficient
    return stored === '1';
  }

  async generatePasswordResetToken(email: string): Promise<string> {
    const user = await queryOne<{ id: string }>(
      'SELECT id FROM users WHERE email = $1',
      [email],
    );
    if (!user) {
      // Still return a token to avoid enumeration — but the token won't work
      return tokenService.generateResetToken();
    }
    const token = tokenService.generateResetToken();
    const client = await redisClient();
    await client.set(`reset:${token}`, user.id, { EX: 3600 });
    return token;
  }
}

export const authService = new AuthService();
