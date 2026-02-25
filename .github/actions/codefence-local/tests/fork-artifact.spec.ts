import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import type { NormalizedFinding } from '../scripts/types';

const { buildForkRelayArtifact } = require('../scripts/fork-artifact-emitter.ts');
const { validateRelayArtifactFromFile } = require('../relay-action/validate-artifact.ts');

function makeFinding(): NormalizedFinding {
  return {
    fingerprint: 'a'.repeat(64),
    primaryFingerprint: 'a'.repeat(64),
    toolFingerprint: 'b'.repeat(64),
    category: 'SAST',
    severity: 'HIGH',
    confidence: 'HIGH',
    title: 'SQL injection',
    description: 'Potential SQL injection in query builder',
    filePath: 'src/db.ts',
    startLine: 10,
    endLine: 10,
    snippet: 'db.query(userInput)',
    diffContext: 'diff --git ...',
    remediationSummary: 'Use parameterized queries.',
    patchSuggestion: 'patch',
    ideFixPrompt: '```ts\nconst query = sql`...`;\n```',
    references: ['CWE-89'],
    toolName: 'semgrep',
    toolVersion: '1.0.0',
    ruleId: 'sql-rule',
    normalizedRuleCategory: 'sql-injection',
  };
}

describe('fork relay artifact', () => {
  it('enforces minimal mode fields and validates checksum', async () => {
    const artifact = buildForkRelayArtifact({
      findings: [makeFinding()],
      repoFullName: 'owner/repo',
      forkRepoFullName: 'contrib/repo',
      headSha: 'a'.repeat(40),
      baseSha: 'b'.repeat(40),
      prNumber: 42,
      runId: 12345,
      scannersRun: ['semgrep'],
      scanDurationMs: 1200,
    });

    const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'relay-artifact-'));
    const artifactPath = path.join(tempDir, 'artifact.json');
    fs.writeFileSync(artifactPath, JSON.stringify(artifact, null, 2));

    const validated = await validateRelayArtifactFromFile(artifactPath);
    expect(validated.evidenceMode).toBe('MINIMAL');
    expect((validated.findings[0] as any).snippet).toBeUndefined();
    expect((validated.findings[0] as any).diffContext).toBeUndefined();
    expect((validated.findings[0] as any).patchSuggestion).toBeUndefined();
    expect((validated.findings[0] as any).ideFixPrompt).toBeUndefined();
  });

  it('rejects checksum mismatches', async () => {
    const artifact = buildForkRelayArtifact({
      findings: [makeFinding()],
      repoFullName: 'owner/repo',
      forkRepoFullName: 'contrib/repo',
      headSha: 'a'.repeat(40),
      baseSha: 'b'.repeat(40),
      prNumber: 42,
      runId: 12345,
      scannersRun: ['semgrep'],
      scanDurationMs: 1200,
    });

    artifact.checksum = 'f'.repeat(64);

    const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'relay-artifact-'));
    const artifactPath = path.join(tempDir, 'artifact.json');
    fs.writeFileSync(artifactPath, JSON.stringify(artifact, null, 2));

    await expect(validateRelayArtifactFromFile(artifactPath)).rejects.toThrow(/checksum mismatch/i);
  });

  it('rejects tampering with fork repo or PR number when checksum is unchanged', async () => {
    const artifact = buildForkRelayArtifact({
      findings: [makeFinding()],
      repoFullName: 'owner/repo',
      forkRepoFullName: 'contrib/repo',
      headSha: 'a'.repeat(40),
      baseSha: 'b'.repeat(40),
      prNumber: 42,
      runId: 12345,
      scannersRun: ['semgrep'],
      scanDurationMs: 1200,
    });

    const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'relay-artifact-'));
    const artifactPath = path.join(tempDir, 'artifact.json');
    const tampered = {
      ...artifact,
      forkRepoFullName: 'attacker/repo',
      prNumber: 99,
    };
    fs.writeFileSync(artifactPath, JSON.stringify(tampered, null, 2));

    await expect(validateRelayArtifactFromFile(artifactPath)).rejects.toThrow(/checksum mismatch/i);
  });
});
