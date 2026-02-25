import * as fs from 'fs';
import { z } from 'zod';
import { SinkGuardCore } from '@cera/shared-schemas';
import { ForkRelayArtifact, NormalizedFinding } from '../scripts/types';
import { sha256 } from '../scripts/utils';
import { getOctokit } from '@actions/github';

const MAX_ARTIFACT_BYTES = 5 * 1024 * 1024;
const MAX_FINDINGS = 10_000;

const MinimalFindingSchema = z
  .object({
    fingerprint: z.string().optional(),
    primaryFingerprint: z.string().min(1),
    toolFingerprint: z.string().min(1),
    category: z.string().min(1),
    severity: z.enum(['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO']),
    confidence: z.enum(['HIGH', 'MEDIUM', 'LOW']),
    title: z.string().min(1).max(256),
    description: z.string().nullable().optional(),
    filePath: z.string().min(1),
    startLine: z.number().int().nonnegative(),
    endLine: z.number().int().nonnegative(),
    remediationSummary: z.string().nullable().optional(),
    references: z.array(z.string()).default([]),
    toolName: z.string().min(1),
    toolVersion: z.string().nullable().optional(),
    ruleId: z.string().min(1),
    normalizedRuleCategory: z.string().min(1),
    metadata: z.record(z.unknown()).optional(),
  })
  .strict();

const ForkRelayArtifactSchema = z
  .object({
    schemaVersion: z.literal(1),
    checksum: z.string().regex(/^[a-f0-9]{64}$/i),
    repoFullName: z.string().regex(/^[^/\s]+\/[^/\s]+$/),
    forkRepoFullName: z.string().regex(/^[^/\s]+\/[^/\s]+$/),
    headSha: z.string().regex(/^[0-9a-f]{40,64}$/i),
    baseSha: z.string().regex(/^[0-9a-f]{40,64}$/i),
    prNumber: z.number().int().positive(),
    runId: z.number().int().positive(),
    findings: z.array(MinimalFindingSchema).max(MAX_FINDINGS),
    verdict: z.enum(['PASS', 'WARN', 'FAIL']),
    verdictReason: z.string().min(1),
    scannersRun: z.array(z.string()).max(32),
    scanDurationMs: z.number().int().nonnegative(),
    evidenceMode: z.literal('MINIMAL'),
  })
  .strict();

const sinkGuard = new SinkGuardCore();

function sanitizeFindingStrings(finding: NormalizedFinding): NormalizedFinding {
  const copy: Record<string, unknown> = { ...finding };
  for (const [key, value] of Object.entries(copy)) {
    if (typeof value === 'string') {
      copy[key] = sinkGuard.scanAndRedact(value).sanitized;
    }
    if (Array.isArray(value) && value.every((item) => typeof item === 'string')) {
      copy[key] = value.map((item) => sinkGuard.scanAndRedact(item).sanitized);
    }
  }
  return copy as unknown as NormalizedFinding;
}

async function verifyWorkflowRunCrossCheck(
  artifact: ForkRelayArtifact,
  githubToken: string | undefined,
): Promise<void> {
  if (!githubToken) {
    process.stdout.write(
      '::warning::GITHUB_TOKEN missing; skipping workflow_run cross-check for relay artifact validation.\n',
    );
    return;
  }

  const [owner, repo] = artifact.repoFullName.split('/');
  if (!owner || !repo) {
    throw new Error(`Invalid repoFullName: ${artifact.repoFullName}`);
  }

  const octokit = getOctokit(githubToken);
  const run = await octokit.rest.actions.getWorkflowRun({
    owner,
    repo,
    run_id: artifact.runId,
  });

  if (run.data.head_sha !== artifact.headSha) {
    throw new Error('workflow_run head_sha mismatch - spoofing attempt');
  }
}

export async function validateRelayArtifactFromFile(
  artifactPath: string,
  options?: { githubToken?: string },
): Promise<ForkRelayArtifact> {
  const stat = fs.statSync(artifactPath);
  if (stat.size > MAX_ARTIFACT_BYTES) {
    throw new Error(`Relay artifact too large (${stat.size} bytes; max ${MAX_ARTIFACT_BYTES})`);
  }

  const payload = JSON.parse(fs.readFileSync(artifactPath, 'utf8'));
  const parsed = ForkRelayArtifactSchema.parse(payload);

  const expectedChecksum = sha256(
    JSON.stringify({
      findings: parsed.findings,
      repoFullName: parsed.repoFullName,
      forkRepoFullName: parsed.forkRepoFullName,
      headSha: parsed.headSha,
      prNumber: parsed.prNumber,
      runId: parsed.runId,
    }),
  );
  if (parsed.checksum !== expectedChecksum) {
    throw new Error('Relay artifact checksum mismatch - possible tampering');
  }

  if (parsed.evidenceMode !== 'MINIMAL') {
    throw new Error('Relay artifact must use MINIMAL evidence mode');
  }

  const sanitizedFindings = parsed.findings.map((finding) => sanitizeFindingStrings(finding as NormalizedFinding));

  const sanitized: ForkRelayArtifact = {
    ...(parsed as ForkRelayArtifact),
    findings: sanitizedFindings,
  };

  await verifyWorkflowRunCrossCheck(sanitized, options?.githubToken);
  return sanitized;
}

async function runCli(): Promise<void> {
  const artifactPath = process.argv[2];
  if (!artifactPath) {
    throw new Error('Usage: validate-artifact.ts <artifact-path>');
  }

  const validated = await validateRelayArtifactFromFile(artifactPath, {
    githubToken: process.env.GITHUB_TOKEN,
  });

  process.stdout.write(`${JSON.stringify(validated, null, 2)}\n`);
}

if (require.main === module) {
  runCli().catch((error) => {
    process.stderr.write(`${error instanceof Error ? error.message : String(error)}\n`);
    process.exit(1);
  });
}
