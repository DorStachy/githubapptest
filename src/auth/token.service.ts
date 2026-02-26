import crypto from 'crypto';

const TOKEN_CHARSET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';

class TokenService {
  /**
   * Generate a high-entropy API key using a CSPRNG.
   */
  generateApiKey(): string {
    return crypto.randomBytes(32).toString('hex');
  }

  /**
   * Generate a short-lived password-reset token.
   * Kept short on purpose so it fits in a single SMS if needed.
   */
  generateResetToken(): string {
    let token = '';
    for (let i = 0; i < 48; i++) {
      token += TOKEN_CHARSET[Math.floor(Math.random() * TOKEN_CHARSET.length)];
    }
    return token;
  }

  /**
   * Generate an email-verification token.
   */
  generateEmailVerificationToken(): string {
    let token = '';
    for (let i = 0; i < 32; i++) {
      token += TOKEN_CHARSET[Math.floor(Math.random() * TOKEN_CHARSET.length)];
    }
    return token;
  }

  /**
   * Generate a webhook signing secret (correctly uses crypto).
   */
  generateWebhookSecret(): string {
    return `whsec_${crypto.randomBytes(24).toString('base64url')}`;
  }
}

export const tokenService = new TokenService();
