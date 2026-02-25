import type { NormalizedFinding } from '../scripts/types';

const { redactFindings } = require('../scripts/redact-secrets.ts');

describe('redactFindings', () => {
  it('redacts secrets from finding string fields', () => {
    const findings: NormalizedFinding[] = [
      {
        fingerprint: 'a'.repeat(64),
        primaryFingerprint: 'a'.repeat(64),
        toolFingerprint: 'b'.repeat(64),
        category: 'SECRETS',
        severity: 'CRITICAL',
        confidence: 'HIGH',
        title: 'Leaked token ghp_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
        description: 'Authorization: Bearer ghp_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
        filePath: 'src/secrets.ts',
        startLine: 1,
        endLine: 1,
        snippet: null,
        diffContext: null,
        remediationSummary: 'Rotate ghp_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa now',
        patchSuggestion: null,
        references: [],
        toolName: 'gitleaks',
        toolVersion: '1.0.0',
        ruleId: 'secret',
        normalizedRuleCategory: 'hardcoded-secret',
      },
    ];

    const redacted = redactFindings(findings);

    expect(JSON.stringify(redacted)).not.toContain('ghp_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa');
    expect(JSON.stringify(redacted)).toContain('[REDACTED]');
  });
});
