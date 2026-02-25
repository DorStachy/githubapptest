import * as fs from 'fs';
import { SinkGuardCore } from '@cera/shared-schemas';
import { NormalizedFinding } from './types';
import { parseKeyValueArgs } from './utils';

const sinkGuard = new SinkGuardCore();

function sanitizeUnknown(value: unknown): unknown {
  if (value === null || value === undefined) {
    return value;
  }
  if (typeof value === 'string') {
    return sinkGuard.scanAndRedact(value).sanitized;
  }
  if (Array.isArray(value)) {
    return value.map((item) => sanitizeUnknown(item));
  }
  if (typeof value === 'object') {
    const output: Record<string, unknown> = {};
    for (const [key, child] of Object.entries(value as Record<string, unknown>)) {
      output[key] = sanitizeUnknown(child);
    }
    return output;
  }
  return value;
}

export function redactFinding(finding: NormalizedFinding): NormalizedFinding {
  return sanitizeUnknown(finding) as NormalizedFinding;
}

export function redactFindings(findings: NormalizedFinding[]): NormalizedFinding[] {
  return findings.map((finding) => redactFinding(finding));
}

function runCli(): void {
  const args = parseKeyValueArgs(process.argv.slice(2));
  const inputPath = args.input;
  const outputPath = args.output;

  if (!inputPath || !outputPath) {
    throw new Error('Usage: redact-secrets.ts --input=<file> --output=<file>');
  }

  const payload = JSON.parse(fs.readFileSync(inputPath, 'utf8')) as NormalizedFinding[];
  const redacted = redactFindings(payload);
  fs.writeFileSync(outputPath, `${JSON.stringify(redacted, null, 2)}\n`, 'utf8');
}

if (require.main === module) {
  runCli();
}
