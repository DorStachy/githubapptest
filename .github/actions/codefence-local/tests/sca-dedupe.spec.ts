import { dedupePipAuditAndOsv } from '../scripts/main';
import type { NormalizedFinding } from '../scripts/types';

function buildFinding(overrides: Partial<NormalizedFinding> = {}): NormalizedFinding {
  return {
    fingerprint: 'fp',
    primaryFingerprint: 'pfp',
    toolFingerprint: 'tfp',
    category: 'SCA',
    severity: 'HIGH',
    confidence: 'HIGH',
    title: 'Vulnerable dependency',
    description: 'Dependency contains known CVE',
    filePath: 'requirements.txt',
    startLine: 1,
    endLine: 1,
    snippet: null,
    diffContext: null,
    remediationSummary: 'Upgrade dependency',
    patchSuggestion: null,
    references: [],
    toolName: 'osv-scanner',
    toolVersion: '1.8.2',
    ruleId: 'CVE-2024-0001',
    normalizedRuleCategory: 'known-cve',
    ...overrides,
  } satisfies NormalizedFinding;
}

describe('dedupePipAuditAndOsv', () => {
  it('merges pip-audit and osv findings for same CVE in same lockfile', () => {
    const osvFinding = buildFinding({
      toolName: 'osv-scanner',
      remediationSummary: 'Upgrade to fixed release',
      references: ['https://osv.dev/vuln/CVE-2024-0001'],
    });
    const pipFinding = buildFinding({
      toolName: 'pip-audit',
      remediationSummary: 'Upgrade to one of: 2.0.1, 2.0.2',
      references: ['https://pypi.org/advisory/CVE-2024-0001'],
    });

    const deduped = dedupePipAuditAndOsv([osvFinding, pipFinding]);
    const mergedFinding = deduped[0]!;

    expect(deduped).toHaveLength(1);
    expect(mergedFinding.toolName).toBe('pip-audit');
    expect(mergedFinding.remediationSummary).toContain('2.0.1');
    expect(mergedFinding.references).toEqual(
      expect.arrayContaining([
        'https://osv.dev/vuln/CVE-2024-0001',
        'https://pypi.org/advisory/CVE-2024-0001',
      ]),
    );
    expect(mergedFinding.metadata?.mergedFrom).toEqual(
      expect.arrayContaining(['osv-scanner', 'pip-audit']),
    );
  });

  it('does not merge findings when lockfile path differs', () => {
    const first = buildFinding({ filePath: 'requirements.txt' });
    const second = buildFinding({ toolName: 'pip-audit', filePath: 'services/api/requirements.txt' });

    const deduped = dedupePipAuditAndOsv([first, second]);
    expect(deduped).toHaveLength(2);
  });

  it('merges multi-CVE finding using the first sorted CVE key', () => {
    const osvFinding = buildFinding({
      toolName: 'osv-scanner',
      ruleId: 'GHSA-xxxx-yyyy-zzzz',
      references: [
        'https://osv.dev/vuln/CVE-2023-9999',
        'https://osv.dev/vuln/CVE-2023-8888',
      ],
      remediationSummary: 'Upgrade dependency to latest release',
    });

    const pipFinding = buildFinding({
      toolName: 'pip-audit',
      ruleId: 'CVE-2023-8888',
      references: ['https://pypi.org/advisory/CVE-2023-8888'],
      remediationSummary: 'Upgrade to one of: 4.0.1',
    });

    const deduped = dedupePipAuditAndOsv([osvFinding, pipFinding]);
    const mergedFinding = deduped[0]!;
    expect(deduped).toHaveLength(1);
    expect(mergedFinding.references.join(' ')).toContain('CVE-2023-8888');
    expect(mergedFinding.references.join(' ')).toContain('CVE-2023-9999');
  });
});
