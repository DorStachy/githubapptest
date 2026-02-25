import * as fs from 'fs';
import { NormalizedFinding, EvidenceMode } from './types';
import { parseKeyValueArgs, truncate, truncateLines } from './utils';
import { stripCodeCarryingFieldsMinimal } from './strip-code-context';

function applyMinimal(finding: NormalizedFinding): NormalizedFinding {
  return stripCodeCarryingFieldsMinimal(finding);
}

function applyStandard(finding: NormalizedFinding): NormalizedFinding {
  return {
    ...finding,
    snippet: truncateLines(finding.snippet, 15, 2000),
    diffContext: null,
    patchSuggestion: null,
    ideFixPrompt: null,
    sarifCodeFlows: null,
    sarifRelatedLocations: null,
  };
}

function applyRich(finding: NormalizedFinding): NormalizedFinding {
  return {
    ...finding,
    snippet: truncateLines(finding.snippet, 30, 2000),
    diffContext: truncate(finding.diffContext, 5000),
    patchSuggestion: truncate(finding.patchSuggestion, 3000),
    ideFixPrompt: truncate(finding.ideFixPrompt, 500),
  };
}

export function applyEvidenceMode(
  findings: NormalizedFinding[],
  mode: EvidenceMode,
): NormalizedFinding[] {
  if (mode === 'MINIMAL') {
    return findings.map((finding) => applyMinimal(finding));
  }
  if (mode === 'STANDARD') {
    return findings.map((finding) => applyStandard(finding));
  }
  return findings.map((finding) => applyRich(finding));
}

function runCli(): void {
  const args = parseKeyValueArgs(process.argv.slice(2));
  const inputPath = args.input;
  const outputPath = args.output;
  const mode = (args.mode || 'MINIMAL').toUpperCase() as EvidenceMode;

  if (!inputPath || !outputPath) {
    throw new Error('Usage: apply-evidence-mode.ts --mode=MINIMAL --input=<file> --output=<file>');
  }

  const payload = JSON.parse(fs.readFileSync(inputPath, 'utf8')) as NormalizedFinding[];
  const transformed = applyEvidenceMode(payload, mode);
  fs.writeFileSync(outputPath, `${JSON.stringify(transformed, null, 2)}\n`, 'utf8');
}

if (require.main === module) {
  runCli();
}
