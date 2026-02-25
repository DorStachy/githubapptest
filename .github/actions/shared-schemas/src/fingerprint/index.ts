import { createHash } from 'crypto';

export interface PrimaryFingerprintInput {
  category: string;
  normalizedRuleCategory: string;
  filePath: string;
  startLine: number;
  endLine: number;
  contextHash?: string | null;
}

export interface ToolFingerprintInput {
  toolName: string;
  ruleId: string;
  filePath: string;
  startLine: number;
  endLine: number;
}

export function computePrimaryFingerprint(input: PrimaryFingerprintInput): string {
  const contextHash = (input.contextHash ?? '').trim();
  const material = [
    input.category,
    input.normalizedRuleCategory,
    input.filePath,
    String(input.startLine),
    String(input.endLine),
    contextHash,
  ].join('|');

  return createHash('sha256').update(material, 'utf8').digest('hex');
}

export function computeToolFingerprint(input: ToolFingerprintInput): string {
  const material = [
    input.toolName,
    input.ruleId,
    input.filePath,
    String(input.startLine),
    String(input.endLine),
  ].join('|');

  return createHash('sha256').update(material, 'utf8').digest('hex');
}

