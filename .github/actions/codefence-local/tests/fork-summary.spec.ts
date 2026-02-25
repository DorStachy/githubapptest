import type { NormalizedFinding } from '../scripts/types';

const { buildForkSummaryMarkdown } = require('../scripts/fork-summary.ts');

describe('buildForkSummaryMarkdown', () => {
  it('renders verdict, counts, and no-upload notice', () => {
    const findings: NormalizedFinding[] = [
      {
        fingerprint: 'a'.repeat(64),
        primaryFingerprint: 'a'.repeat(64),
        toolFingerprint: 'b'.repeat(64),
        category: 'SAST',
        severity: 'HIGH',
        confidence: 'HIGH',
        title: 'SQL injection',
        description: 'desc',
        filePath: 'src/db.ts',
        startLine: 5,
        endLine: 5,
        snippet: null,
        diffContext: null,
        remediationSummary: 'fix',
        patchSuggestion: null,
        references: [],
        toolName: 'semgrep',
        toolVersion: '1.0.0',
        ruleId: 'rule',
        normalizedRuleCategory: 'sql-injection',
      },
    ];

    const markdown = buildForkSummaryMarkdown(findings, 'FAIL', { uploaded: false });
    expect(markdown).toContain('Verdict:** FAIL');
    expect(markdown).toContain('Results not uploaded to CodeFence');
    expect(markdown).toContain('[HIGH] SQL injection (src/db.ts:5)');
  });
});
