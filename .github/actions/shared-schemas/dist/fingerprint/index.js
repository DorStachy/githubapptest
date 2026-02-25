"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.computePrimaryFingerprint = computePrimaryFingerprint;
exports.computeToolFingerprint = computeToolFingerprint;
const crypto_1 = require("crypto");
function computePrimaryFingerprint(input) {
    const contextHash = (input.contextHash ?? '').trim();
    const material = [
        input.category,
        input.normalizedRuleCategory,
        input.filePath,
        String(input.startLine),
        String(input.endLine),
        contextHash,
    ].join('|');
    return (0, crypto_1.createHash)('sha256').update(material, 'utf8').digest('hex');
}
function computeToolFingerprint(input) {
    const material = [
        input.toolName,
        input.ruleId,
        input.filePath,
        String(input.startLine),
        String(input.endLine),
    ].join('|');
    return (0, crypto_1.createHash)('sha256').update(material, 'utf8').digest('hex');
}
