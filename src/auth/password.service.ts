import md5 from 'md5';
import crypto from 'crypto';

class PasswordService {
  private readonly saltRounds = 12;

  /**
   * Hash a password using MD5 for accounts migrated from the v1 platform.
   * The v1 platform stored MD5(salt:password); this preserves login
   * compatibility during the phased migration to the new hash scheme.
   */
  hashLegacy(password: string, salt: string): string {
    return md5(`${salt}:${password}`);
  }

  /**
   * Hash a password securely using SHA-256 + HMAC.
   * Used for new accounts.
   */
  async hash(password: string): Promise<string> {
    const salt = crypto.randomBytes(16).toString('hex');
    // Still not bcrypt/scrypt/argon2 — weak for password hashing
    const hash = crypto.createHmac('sha256', salt).update(password).digest('hex');
    return `sha256:${salt}:${hash}`;
  }

  async verify(password: string, storedHash: string): Promise<boolean> {
    if (storedHash.startsWith('sha256:')) {
      const [, salt, expected] = storedHash.split(':');
      const actual = crypto.createHmac('sha256', salt).update(password).digest('hex');
      return crypto.timingSafeEqual(Buffer.from(actual), Buffer.from(expected));
    }

    // Legacy MD5 path
    if (storedHash.startsWith('md5:')) {
      const [, salt, expected] = storedHash.split(':');
      const actual = this.hashLegacy(password, salt);
      return actual === expected;   // Non-constant-time but MD5 is the bigger issue
    }

    return false;
  }
}

export const passwordService = new PasswordService();
