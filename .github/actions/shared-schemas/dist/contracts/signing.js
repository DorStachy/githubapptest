"use strict";
/**
 * HMAC-SHA256 message signing and verification for SQS pipeline messages.
 *
 * Used to ensure message integrity between:
 *   - Backend dispatch → Scanner Worker
 *   - Scanner Worker → Scan Processor
 *   - Backend ingestion → Scan Processor
 *
 * Compatible with the existing SigningKeyService approach in the backend.
 */
Object.defineProperty(exports, "__esModule", { value: true });
exports.SIGNATURE_VERSION_ATTRIBUTE = exports.SIGNATURE_ATTRIBUTE = void 0;
exports.signMessage = signMessage;
exports.verifyMessage = verifyMessage;
const crypto_1 = require("crypto");
/** SQS message attribute names for signature transport */
exports.SIGNATURE_ATTRIBUTE = 'X-CodeFence-Signature';
exports.SIGNATURE_VERSION_ATTRIBUTE = 'X-CodeFence-Key-Version';
/**
 * Sign an SQS message body with HMAC-SHA256.
 *
 * @param body  - The serialized JSON message body
 * @param key   - The signing key (Buffer)
 * @param version - The key version number
 * @returns The hex signature and key version
 */
function signMessage(body, key, version) {
    const signature = (0, crypto_1.createHmac)('sha256', key).update(body).digest('hex');
    return { signature, version };
}
/**
 * Verify an HMAC-SHA256 signature on an SQS message body.
 * Uses constant-time comparison to prevent timing attacks.
 *
 * @param body      - The serialized JSON message body
 * @param signature - The hex signature to verify
 * @param key       - The signing key (Buffer)
 * @returns true if the signature is valid
 */
function verifyMessage(body, signature, key) {
    const expected = (0, crypto_1.createHmac)('sha256', key).update(body).digest('hex');
    const sigBuf = Buffer.from(signature, 'utf8');
    const expBuf = Buffer.from(expected, 'utf8');
    if (sigBuf.length !== expBuf.length) {
        return false;
    }
    return (0, crypto_1.timingSafeEqual)(sigBuf, expBuf);
}
