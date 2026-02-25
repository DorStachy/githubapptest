import * as fs from 'fs';
import { ForkRelayArtifact, NormalizedFinding } from './types';
import { applyEvidenceMode } from './apply-evidence-mode';
import { redactFindings } from './redact-secrets';
import { parseKeyValueArgs, sha256, severityToVerdict, safeNumber } from './utils';

const MAX_FINDINGS = 10_000;

function sanitizeMinimal(findings: NormalizedFinding[]): NormalizedFinding[] {
  const minimal = applyEvidenceMode(findings, 'MINIMAL');
  const redacted = redactFindings(minimal);

  return redacted.map((finding) => {
    const {
      snippet: _snippet,
      diffContext: _diffContext,
      patchSuggestion: _patchSuggestion,
      ideFixPrompt: _ideFixPrompt,
      sarifHelpText: _sarifHelpText,
      sarifCodeFlows: _sarifCodeFlows,
      sarifRelatedLocations: _sarifRelatedLocations,
      ...rest
    } = finding;
    return rest as NormalizedFinding;
  });
}

export function buildForkRelayArtifact(input: {
  findings: NormalizedFinding[];
  repoFullName: string;
  forkRepoFullName: string;
  headSha: string;
  baseSha: string;
  prNumber: number;
  runId: number;
  scannersRun: string[];
  scanDurationMs: number;
}): ForkRelayArtifact {
  if (input.findings.length > MAX_FINDINGS) {
    throw new Error(`Relay artifact exceeds ${MAX_FINDINGS} findings`);
  }

  const sanitizedFindings = sanitizeMinimal(input.findings);
  const checksum = sha256(
    JSON.stringify({
      findings: sanitizedFindings,
      repoFullName: input.repoFullName,
      forkRepoFullName: input.forkRepoFullName,
      headSha: input.headSha,
      prNumber: input.prNumber,
      runId: input.runId,
    }),
  );

  return {
    schemaVersion: 1,
    checksum,
    repoFullName: input.repoFullName,
    forkRepoFullName: input.forkRepoFullName,
    headSha: input.headSha,
    baseSha: input.baseSha,
    prNumber: input.prNumber,
    runId: input.runId,
    findings: sanitizedFindings,
    verdict: severityToVerdict(sanitizedFindings),
    verdictReason: 'Fork PR summary artifact (minimal evidence mode enforced).',
    scannersRun: input.scannersRun,
    scanDurationMs: input.scanDurationMs,
    evidenceMode: 'MINIMAL',
  };
}

function runCli(): void {
  const args = parseKeyValueArgs(process.argv.slice(2));
  const inputPath = args.input;
  const outputPath = args.output || '/tmp/codefence-relay-artifact.json';
  if (!inputPath) {
    throw new Error('Usage: fork-artifact-emitter.ts --input=<normalized-findings.json> --output=<artifact.json>');
  }

  const findings = JSON.parse(fs.readFileSync(inputPath, 'utf8')) as NormalizedFinding[];
  const artifact = buildForkRelayArtifact({
    findings,
    repoFullName: process.env.GITHUB_REPOSITORY || args.repo || '',
    forkRepoFullName:
      process.env.GITHUB_HEAD_REPOSITORY ||
      args['fork-repo'] ||
      process.env.GITHUB_REPOSITORY ||
      '',
    headSha: process.env.GITHUB_SHA || args['head-sha'] || '',
    baseSha: process.env.GITHUB_BASE_SHA || args['base-sha'] || '',
    prNumber: safeNumber(process.env.PR_NUMBER || args['pr-number'], 0),
    runId: safeNumber(process.env.GITHUB_RUN_ID || args['run-id'], 0),
    scannersRun: (process.env.CODEFENCE_SCANNERS_RUN || args.scanners || '')
      .split(',')
      .map((item) => item.trim())
      .filter(Boolean),
    scanDurationMs: safeNumber(process.env.CODEFENCE_SCAN_DURATION_MS || args['scan-duration-ms'], 0),
  });

  fs.writeFileSync(outputPath, `${JSON.stringify(artifact, null, 2)}\n`, 'utf8');
  process.stdout.write(`Wrote fork relay artifact: ${outputPath}\n`);
}

if (require.main === module) {
  runCli();
}
