import * as crypto from 'crypto';
import * as fs from 'fs';
import * as path from 'path';
import { EvidenceMode, FindingSeverity, Verdict } from './types';

export function sha256(value: string | Buffer): string {
  return crypto.createHash('sha256').update(value).digest('hex');
}

export function truncate(value: string | null | undefined, max: number): string | null {
  if (value === null || value === undefined) {
    return null;
  }
  if (value.length <= max) {
    return value;
  }
  return `${value.slice(0, max)}...`;
}

export function truncateLines(
  value: string | null | undefined,
  maxLines: number,
  maxChars: number,
): string | null {
  if (!value) {
    return null;
  }
  const lines = value.split('\n').slice(0, maxLines);
  const joined = lines.join('\n');
  return truncate(joined, maxChars);
}

export function normalizeEvidenceMode(value: string | undefined): EvidenceMode {
  const upper = (value || 'minimal').trim().toUpperCase();
  if (upper === 'STANDARD') {
    return 'STANDARD';
  }
  if (upper === 'RICH') {
    return 'RICH';
  }
  return 'MINIMAL';
}

export function severityToVerdict(findings: Array<{ severity: FindingSeverity }>): Verdict {
  const hasCriticalOrHigh = findings.some(
    (finding) => finding.severity === 'CRITICAL' || finding.severity === 'HIGH',
  );
  if (hasCriticalOrHigh) {
    return 'FAIL';
  }

  const hasMedium = findings.some((finding) => finding.severity === 'MEDIUM');
  if (hasMedium) {
    return 'WARN';
  }

  return 'PASS';
}

export function readJsonFile<T>(filePath: string): T {
  const raw = fs.readFileSync(filePath, 'utf8');
  return JSON.parse(raw) as T;
}

export function writeJsonFile(filePath: string, value: unknown): void {
  ensureDir(path.dirname(filePath));
  fs.writeFileSync(filePath, `${JSON.stringify(value, null, 2)}\n`, 'utf8');
}

export function ensureDir(dirPath: string): void {
  if (!fs.existsSync(dirPath)) {
    fs.mkdirSync(dirPath, { recursive: true });
  }
}

export function getInput(name: string, fallback = ''): string {
  const envName = `INPUT_${name.replace(/[ -]/g, '_').toUpperCase()}`;
  const value = process.env[envName];
  return value !== undefined ? value.trim() : fallback;
}

export function getBooleanInput(name: string, fallback = false): boolean {
  const value = getInput(name, fallback ? 'true' : 'false').toLowerCase();
  return value === '1' || value === 'true' || value === 'yes' || value === 'on';
}

export function parseCsv(value: string | undefined): string[] {
  if (!value) {
    return [];
  }
  return value
    .split(',')
    .map((item) => item.trim())
    .filter((item) => item.length > 0);
}

export function parseScannerList(value: string | undefined): string[] {
  const parsed = parseCsv(value);
  if (parsed.length === 0 || parsed.includes('all')) {
    return [
      'codeql',
      'semgrep',
      'bandit',
      'gitleaks',
      'osv-scanner',
      'pip-audit',
      'actionlint',
      'zizmor',
      'checkov',
      'trivy',
      'scorecard',
    ];
  }
  return parsed;
}

export function unixTimestampSeconds(): number {
  return Math.floor(Date.now() / 1000);
}

export function randomNonceV4(): string {
  if (typeof crypto.randomUUID === 'function') {
    return crypto.randomUUID();
  }
  const bytes = crypto.randomBytes(16);
  bytes[6] = (bytes[6] & 0x0f) | 0x40;
  bytes[8] = (bytes[8] & 0x3f) | 0x80;
  const hex = bytes.toString('hex');
  return `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(16, 20)}-${hex.slice(20)}`;
}

export function isGitSha(value: string | undefined): boolean {
  if (!value) {
    return false;
  }
  return /^[0-9a-f]{40,64}$/i.test(value);
}

export function pathToPosix(filePath: string): string {
  return filePath.replace(/\\/g, '/');
}

export function relativeToWorkspace(workspace: string, candidatePath: string): string {
  const relative = path.relative(workspace, candidatePath);
  return pathToPosix(relative === '' ? '.' : relative);
}

export function safeNumber(value: unknown, fallback = 0): number {
  const parsed = Number(value);
  return Number.isFinite(parsed) ? parsed : fallback;
}

export function parseKeyValueArgs(argv: string[]): Record<string, string> {
  const parsed: Record<string, string> = {};
  for (const raw of argv) {
    if (!raw.startsWith('--')) {
      continue;
    }
    const [key, ...rest] = raw.slice(2).split('=');
    parsed[key] = rest.join('=');
  }
  return parsed;
}

export function toIsoDate(ms = Date.now()): string {
  return new Date(ms).toISOString();
}
