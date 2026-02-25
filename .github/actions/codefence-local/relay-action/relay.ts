import * as fs from 'fs';
import { getOctokit } from '@actions/github';
import { validateRelayArtifactFromFile } from './validate-artifact';
import { UploadInputs, uploadResults } from '../scripts/upload-results';
import { SignedClientConfig } from '../scripts/http-client';
import { normalizeEvidenceMode, safeNumber } from '../scripts/utils';

function resolveSigningSecret(apiKey: string): string {
  const dedicated =
    process.env.CODEFENCE_SIGNING_SECRET || process.env.CODEFENCE_RESULTS_SIGNING_SECRET || '';
  if (dedicated.trim().length > 0) {
    return dedicated;
  }

  process.stdout.write(
    '::warning::CODEFENCE_SIGNING_SECRET is not set; falling back to api-key for HMAC signing. Configure a dedicated signing secret.\n',
  );
  return apiKey;
}

function summarizeCounts(findings: Array<{ severity: string }>): Record<string, number> {
  const counts = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0, INFO: 0 };
  for (const finding of findings) {
    if (finding.severity in counts) {
      counts[finding.severity as keyof typeof counts] += 1;
    }
  }
  return counts;
}

async function postCheckRun(
  repositoryFullName: string,
  headSha: string,
  verdict: 'PASS' | 'WARN' | 'FAIL',
  findings: Array<{ severity: string }> = [],
): Promise<void> {
  const githubToken = process.env.GITHUB_TOKEN;
  if (!githubToken) {
    return;
  }

  const [owner, repo] = repositoryFullName.split('/');
  if (!owner || !repo) {
    return;
  }

  const octokit = getOctokit(githubToken);
  const counts = summarizeCounts(findings);
  const conclusion = verdict === 'FAIL' ? 'failure' : verdict === 'WARN' ? 'neutral' : 'success';

  await octokit.rest.checks.create({
    owner,
    repo,
    name: 'CodeFence Security Scan (Fork Relay)',
    head_sha: headSha,
    status: 'completed',
    conclusion,
    output: {
      title: `CodeFence relay verdict: ${verdict}`,
      summary: [
        `Findings: ${findings.length}`,
        `CRITICAL: ${counts.CRITICAL}`,
        `HIGH: ${counts.HIGH}`,
        `MEDIUM: ${counts.MEDIUM}`,
      ].join(' | '),
      text: 'Fork relay artifact validated and uploaded to CodeFence backend.',
    },
  });
}

async function main(): Promise<void> {
  const apiKey = process.env.INPUT_API_KEY || process.env.CODEFENCE_API_KEY;
  const artifactPath = process.env.INPUT_ARTIFACT_PATH;
  const apiBaseUrl =
    process.env.INPUT_CODEFENCE_API_URL || process.env.CODEFENCE_API_URL || 'https://api.codefence.io';

  if (!apiKey) {
    throw new Error('Missing relay action input: api-key');
  }
  if (!artifactPath) {
    throw new Error('Missing relay action input: artifact-path');
  }

  const artifact = await validateRelayArtifactFromFile(artifactPath, {
    githubToken: process.env.GITHUB_TOKEN,
  });

  const signingSecret = resolveSigningSecret(apiKey);
  const config: SignedClientConfig = {
    apiBaseUrl,
    apiKey,
    signingSecret,
    keyVersion: safeNumber(
      process.env.CODEFENCE_KEY_VERSION || process.env.CODEFENCE_SIGNING_KEY_VERSION || 1,
      1,
    ),
  };

  const uploadInput: UploadInputs = {
    installationId: safeNumber(process.env.CODEFENCE_INSTALLATION_ID, 0),
    repositoryFullName: artifact.repoFullName,
    headSha: artifact.headSha,
    baseSha: artifact.baseSha,
    evidenceMode: normalizeEvidenceMode('minimal'),
    llmMode: 'CODEFENCE',
    scannersRun: artifact.scannersRun,
    workflowRunId: artifact.runId,
    clientCorrelationId: `fork-relay:${artifact.runId}`,
    findings: artifact.findings,
    metadata: {
      scanDurationMs: artifact.scanDurationMs,
      triggerType: 'pull_request',
      actionVersion: process.env.GITHUB_ACTION_REF,
    },
  };

  const uploadResult = await uploadResults(config, uploadInput);
  await postCheckRun(artifact.repoFullName, artifact.headSha, artifact.verdict, artifact.findings);

  if (process.env.GITHUB_OUTPUT) {
    fs.appendFileSync(process.env.GITHUB_OUTPUT, `scan-run-id=${uploadResult.scanRunId}\n`, 'utf8');
    fs.appendFileSync(process.env.GITHUB_OUTPUT, `verdict=${artifact.verdict}\n`, 'utf8');
  }

  process.stdout.write(
    `Relay upload complete (scanRunId=${uploadResult.scanRunId}, findings=${artifact.findings.length})\n`,
  );
}

if (require.main === module) {
  main().catch((error) => {
    process.stderr.write(`${error instanceof Error ? error.message : String(error)}\n`);
    process.exit(1);
  });
}
