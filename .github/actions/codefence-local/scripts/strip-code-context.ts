import * as fs from 'fs';
import { NormalizedFinding } from './types';
import { parseKeyValueArgs } from './utils';

const FENCED_BLOCK_RE = /```[\s\S]*?```/g;
const INDENTED_CODE_LINE_RE = /^[ \t]{4,}.+$/gm;
const CONSECUTIVE_REMOVED_RE = /(\s*\[code.*?removed\]\s*){2,}/g;
const MINIMAL_DESCRIPTION_LIMIT = 500;

export function stripCodeContext(text: string | null | undefined): string | null {
  if (!text) {
    return null;
  }

  let cleaned = text.replace(FENCED_BLOCK_RE, '[code block removed]');
  cleaned = cleaned.replace(INDENTED_CODE_LINE_RE, '  [code line removed]');
  cleaned = cleaned.replace(CONSECUTIVE_REMOVED_RE, '\n  [code removed]\n');

  if (cleaned.length > MINIMAL_DESCRIPTION_LIMIT) {
    cleaned = `${cleaned.slice(0, MINIMAL_DESCRIPTION_LIMIT)}...`;
  }

  return cleaned;
}

export function stripCodeFencesOnly(text: string | null | undefined): string | null {
  if (!text) {
    return null;
  }
  const cleaned = text.replace(FENCED_BLOCK_RE, '[code block removed]');
  return cleaned.length <= 2000 ? cleaned : `${cleaned.slice(0, 2000)}...`;
}

export function stripCodeCarryingFieldsMinimal(
  finding: NormalizedFinding,
): NormalizedFinding {
  return {
    ...finding,
    snippet: null,
    diffContext: null,
    patchSuggestion: null,
    ideFixPrompt: null,
    description: stripCodeContext(finding.description),
    remediationSummary: stripCodeFencesOnly(finding.remediationSummary),
    sarifHelpText: null,
    sarifCodeFlows: null,
    sarifRelatedLocations: null,
  };
}

export function stripAllCodeContextMinimal(
  findings: NormalizedFinding[],
): NormalizedFinding[] {
  return findings.map((finding) => stripCodeCarryingFieldsMinimal(finding));
}

function runCli(): void {
  const args = parseKeyValueArgs(process.argv.slice(2));
  const inputPath = args.input;
  const outputPath = args.output;
  if (!inputPath || !outputPath) {
    throw new Error('Usage: strip-code-context.ts --input=<file> --output=<file>');
  }

  const payload = JSON.parse(fs.readFileSync(inputPath, 'utf8')) as NormalizedFinding[];
  const stripped = stripAllCodeContextMinimal(payload);
  fs.writeFileSync(outputPath, `${JSON.stringify(stripped, null, 2)}\n`, 'utf8');
}

if (require.main === module) {
  runCli();
}
