import type { NormalizedFinding } from '../scripts/types';

const { applyEvidenceMode } = require('../scripts/apply-evidence-mode.ts');

function makeFinding(): NormalizedFinding {
  return {
    fingerprint: 'a'.repeat(64),
    primaryFingerprint: 'a'.repeat(64),
    toolFingerprint: 'b'.repeat(64),
    category: 'SAST',
    severity: 'HIGH',
    confidence: 'HIGH',
    title: 'Test finding',
    description: `\`\`\`ts\nconst token = "x";\n\`\`\`\n    indented line\n${'A'.repeat(600)}`,
    filePath: 'src/index.ts',
    startLine: 1,
    endLine: 2,
    snippet: 'line1\nline2\nline3\nline4\nline5\nline6\nline7\nline8\nline9\nline10\nline11\nline12\nline13\nline14\nline15\nline16',
    diffContext: 'x'.repeat(7000),
    remediationSummary: '```patch\nfix\n```',
    patchSuggestion: 'y'.repeat(5000),
    ideFixPrompt: '```ts\nsuggested code\n```',
    references: [],
    toolName: 'semgrep',
    toolVersion: '1.0.0',
    ruleId: 'rule-1',
    normalizedRuleCategory: 'sql-injection',
  };
}

describe('applyEvidenceMode', () => {
  it('enforces minimal mode by stripping code-carrying fields', () => {
    const [finding] = applyEvidenceMode([makeFinding()], 'MINIMAL');

    expect(finding.snippet).toBeNull();
    expect(finding.diffContext).toBeNull();
    expect(finding.patchSuggestion).toBeNull();
    expect(finding.ideFixPrompt).toBeNull();
    expect(finding.description).toMatch(/\[code .*removed\]/);
    expect((finding.description || '').length).toBeLessThanOrEqual(503);
    expect(finding.remediationSummary).toContain('[code block removed]');
  });

  it('enforces standard mode truncation and nulls diff/patch', () => {
    const [finding] = applyEvidenceMode([makeFinding()], 'STANDARD');

    expect(finding.snippet?.split('\n').length).toBeLessThanOrEqual(15);
    expect((finding.snippet || '').length).toBeLessThanOrEqual(2003);
    expect(finding.diffContext).toBeNull();
    expect(finding.patchSuggestion).toBeNull();
  });

  it('enforces rich mode truncation limits', () => {
    const [finding] = applyEvidenceMode([makeFinding()], 'RICH');

    expect(finding.snippet?.split('\n').length).toBeLessThanOrEqual(30);
    expect((finding.diffContext || '').length).toBeLessThanOrEqual(5003);
    expect((finding.patchSuggestion || '').length).toBeLessThanOrEqual(3003);
  });
});
