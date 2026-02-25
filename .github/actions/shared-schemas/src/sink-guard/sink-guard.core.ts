import {
  SECRET_PATTERNS,
  SecretPattern,
  calculateEntropy,
  HIGH_ENTROPY_THRESHOLD,
  HIGH_ENTROPY_MIN_LENGTH,
} from './secret-patterns';

/**
 * Result of a Sink Guard scan on a single text field.
 */
export interface SinkGuardResult {
  sanitized: string;
  hadSecrets: boolean;
  matchedPatterns: string[];
  redactionCount: number;
}

/**
 * Result of scanning an entire object (multiple fields).
 */
export interface SinkGuardObjectResult {
  sanitized: Record<string, unknown>;
  totalRedactions: number;
  allMatchedPatterns: string[];
}

/**
 * Sink Guard Service - core secret detection and redaction engine.
 */
export interface SinkGuardLogger {
  onSecretsRedacted?: (redactionCount: number, matchedPatterns: string[]) => void;
  onMaxDepthReached?: (maxDepth: number) => void;
}

export class SinkGuardCore {
  private readonly patterns: readonly SecretPattern[] = SECRET_PATTERNS;

  /** Maximum recursion depth for scanObject to prevent stack overflow. */
  private static readonly MAX_DEPTH = 64;

  constructor(private readonly logger: SinkGuardLogger = {}) {}

  /**
   * Scan a single string value for secrets and redact any matches.
   */
  scanAndRedact(text: string | null | undefined): SinkGuardResult {
    if (!text) {
      return { sanitized: text ?? '', hadSecrets: false, matchedPatterns: [], redactionCount: 0 };
    }

    let sanitized = text;
    const matchedPatterns: string[] = [];
    let redactionCount = 0;

    // Phase 1: Pattern-based detection
    for (const pattern of this.patterns) {
      pattern.pattern.lastIndex = 0;
      const matches = sanitized.match(pattern.pattern);
      if (matches && matches.length > 0) {
        for (const match of matches) {
          sanitized = sanitized.replace(match, '[REDACTED]');
          redactionCount++;
        }
        if (!matchedPatterns.includes(pattern.name)) {
          matchedPatterns.push(pattern.name);
        }
      }
    }

    // Phase 2: High-entropy string detection (catch unknown secret formats)
    sanitized = this.redactHighEntropyStrings(sanitized, matchedPatterns, (count) => {
      redactionCount += count;
    });

    const hadSecrets = redactionCount > 0;

    if (hadSecrets) {
      this.logger.onSecretsRedacted?.(redactionCount, matchedPatterns);
    }

    return { sanitized, hadSecrets, matchedPatterns, redactionCount };
  }

  /**
   * Scan all fields in an object recursively and redact secrets.
   * Returns the sanitized copy (does not mutate the original).
   */
  scanObject<T extends Record<string, unknown>>(obj: T): SinkGuardObjectResult {
    let totalRedactions = 0;
    const allMatchedPatterns: string[] = [];
    const seen = new WeakSet<object>();

    const recurse = (value: unknown, depth: number): unknown => {
      if (value === null || value === undefined) return value;

      if (typeof value === 'string') {
        const result = this.scanAndRedact(value);
        totalRedactions += result.redactionCount;
        for (const name of result.matchedPatterns) {
          if (!allMatchedPatterns.includes(name)) {
            allMatchedPatterns.push(name);
          }
        }
        return result.sanitized;
      }

      if (typeof value !== 'object') return value;

      if (depth >= SinkGuardCore.MAX_DEPTH) {
        this.logger.onMaxDepthReached?.(SinkGuardCore.MAX_DEPTH);
        totalRedactions++;
        return '[REDACTED:depth-limit]';
      }

      if (seen.has(value as object)) {
        return '[REDACTED:circular]';
      }
      seen.add(value as object);

      if (Array.isArray(value)) {
        return value.map((item) => recurse(item, depth + 1));
      }

      const sanitizedObj: Record<string, unknown> = {};
      for (const [key, val] of Object.entries(value as Record<string, unknown>)) {
        sanitizedObj[key] = recurse(val, depth + 1);
      }
      return sanitizedObj;
    };

    const sanitized = recurse(obj, 0) as Record<string, unknown>;
    return { sanitized, totalRedactions, allMatchedPatterns };
  }

  /**
   * Scan an array of strings for secrets. Returns sanitized array.
   */
  scanArray(arr: string[]): string[] {
    return arr.map((item) => this.scanAndRedact(item).sanitized);
  }

  /**
   * Quick check: does this text contain any secrets? (No redaction, just boolean)
   */
  containsSecrets(text: string): boolean {
    if (!text) return false;

    for (const pattern of this.patterns) {
      pattern.pattern.lastIndex = 0;
      if (pattern.pattern.test(text)) return true;
    }

    return this.containsHighEntropyStrings(text);
  }

  /**
   * Detect high-entropy strings that look like secrets/tokens but don't match known patterns.
   * Scans both quoted values and common secret assignment formats.
   */
  private redactHighEntropyStrings(
    text: string,
    matchedPatterns: string[],
    onRedact: (count: number) => void,
  ): string {
    const quotedStringRegex = /['"]([A-Za-z0-9+/=\-_]{20,})['"]/g;
    const assignmentRegex =
      /((?:secret|password|passwd|pwd|token|api[_-]?key|access[_-]?key|auth[_-]?token)\s*[:=]\s*)(['"]?)([A-Za-z0-9+/=\-_]{20,})(\2)/gi;

    let result = text;
    let count = 0;

    let match: RegExpExecArray | null;
    const replacements: Array<{ full: string; replacement: string }> = [];

    while ((match = quotedStringRegex.exec(result)) !== null) {
      const candidate = match[1];
      if (
        candidate.length >= HIGH_ENTROPY_MIN_LENGTH &&
        calculateEntropy(candidate) >= HIGH_ENTROPY_THRESHOLD
      ) {
        replacements.push({ full: match[0], replacement: '"[REDACTED]"' });
        count++;
      }
    }

    for (const { full, replacement } of replacements) {
      result = result.replace(full, replacement);
    }

    replacements.length = 0;
    assignmentRegex.lastIndex = 0;

    while ((match = assignmentRegex.exec(result)) !== null) {
      const candidate = match[3];
      const quote = match[2] || '';
      if (
        candidate.length >= HIGH_ENTROPY_MIN_LENGTH &&
        calculateEntropy(candidate) >= HIGH_ENTROPY_THRESHOLD
      ) {
        replacements.push({
          full: match[0],
          replacement: `${match[1]}${quote}[REDACTED]${quote}`,
        });
        count++;
      }
    }

    for (const { full, replacement } of replacements) {
      result = result.replace(full, replacement);
    }

    if (count > 0) {
      onRedact(count);
      if (!matchedPatterns.includes('High-Entropy String')) {
        matchedPatterns.push('High-Entropy String');
      }
    }

    return result;
  }

  /**
   * Quick check for high-entropy strings (no redaction).
   */
  private containsHighEntropyStrings(text: string): boolean {
    const quotedStringRegex = /['"]([A-Za-z0-9+/=\-_]{20,})['"]/g;
    const assignmentRegex =
      /(?:secret|password|passwd|pwd|token|api[_-]?key|access[_-]?key|auth[_-]?token)\s*[:=]\s*['"]?([A-Za-z0-9+/=\-_]{20,})['"]?/gi;

    let match: RegExpExecArray | null;

    while ((match = quotedStringRegex.exec(text)) !== null) {
      const candidate = match[1];
      if (
        candidate.length >= HIGH_ENTROPY_MIN_LENGTH &&
        calculateEntropy(candidate) >= HIGH_ENTROPY_THRESHOLD
      ) {
        return true;
      }
    }

    while ((match = assignmentRegex.exec(text)) !== null) {
      const candidate = match[1];
      if (
        candidate.length >= HIGH_ENTROPY_MIN_LENGTH &&
        calculateEntropy(candidate) >= HIGH_ENTROPY_THRESHOLD
      ) {
        return true;
      }
    }

    return false;
  }
}
