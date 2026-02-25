import type { NormalizedFinding } from '../scripts/types';

const { uploadResultsInChunks } = require('../scripts/chunked-upload.ts');
const { sha256 } = require('../scripts/utils.ts');

function makeFinding(index: number): NormalizedFinding {
  return {
    fingerprint: `f-${index}`,
    primaryFingerprint: `pf-${index}`,
    toolFingerprint: `tf-${index}`,
    category: 'SAST',
    severity: 'LOW',
    confidence: 'HIGH',
    title: `Finding ${index}`,
    description: 'desc',
    filePath: `src/file-${index}.ts`,
    startLine: 1,
    endLine: 1,
    snippet: null,
    diffContext: null,
    remediationSummary: 'fix',
    patchSuggestion: null,
    references: [],
    toolName: 'semgrep',
    toolVersion: '1.0.0',
    ruleId: 'rule',
    normalizedRuleCategory: 'sql-injection',
  };
}

describe('uploadResultsInChunks', () => {
  it('signs each chunk request independently with unique nonce and timestamp', async () => {
    const findings = Array.from({ length: 4001 }, (_, index) => makeFinding(index));
    const attempts: Array<{
      url: string;
      body: any;
      headers: Record<string, string>;
    }> = [];
    let ts = 1_700_000_000;
    let nonce = 0;

    await uploadResultsInChunks(
      {
        apiBaseUrl: 'https://api.codefence.test',
        apiKey: 'cfr_test_key',
        signingSecret: 'signing-secret',
        keyVersion: 1,
      },
      {
        scanRunId: 'scan-run-123',
        findings,
      },
      {
        requestRuntime: {
          requestRawFn: async (
            url: string,
            _method: string,
            body: string,
            headers: Record<string, string>,
          ) => {
            attempts.push({
              url,
              body: JSON.parse(body),
              headers,
            });
            return {
              status: 200,
              body: { ok: true },
              headers: {},
            };
          },
          delayFn: async () => {},
          timestampFn: () => {
            ts += 1;
            return ts;
          },
          nonceFn: () => {
            nonce += 1;
            return `nonce-${nonce}`;
          },
        },
      },
    );

    expect(attempts).toHaveLength(4);
    expect(attempts.slice(0, 3).every((attempt) => attempt.url.endsWith('/api/v1/github/results/chunk'))).toBe(true);
    expect(attempts[3].url.endsWith('/api/v1/github/results/complete')).toBe(true);

    const nonces = attempts.map((attempt) => attempt.headers['X-CodeFence-Nonce']);
    const timestamps = attempts.map((attempt) => attempt.headers['X-CodeFence-Timestamp']);
    expect(new Set(nonces).size).toBe(attempts.length);
    expect(new Set(timestamps).size).toBe(attempts.length);

    expect(attempts[0].body.chunkIndex).toBe(0);
    expect(attempts[1].body.chunkIndex).toBe(1);
    expect(attempts[2].body.chunkIndex).toBe(2);
    expect(attempts[0].body.totalChunks).toBe(3);
    expect(attempts[1].body.totalChunks).toBe(3);
    expect(attempts[2].body.totalChunks).toBe(3);
    expect(attempts[0].body.idempotencyKey).toBe(sha256('scan-run-123:0'));
    expect(attempts[1].body.idempotencyKey).toBe(sha256('scan-run-123:1'));
    expect(attempts[2].body.idempotencyKey).toBe(sha256('scan-run-123:2'));
  });
});
