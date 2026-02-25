const { normalizeSarifLog } = require('../scripts/normalize-sarif.ts');

describe('normalizeSarifLog', () => {
  it('maps SARIF result fields into normalized findings', () => {
    const findings = normalizeSarifLog({
      runs: [
        {
          tool: {
            driver: {
              name: 'semgrep',
              semanticVersion: '1.0.0',
              rules: [
                {
                  id: 'javascript.lang.security.audit.sql-injection',
                  shortDescription: { text: 'SQL injection' },
                  help: { text: 'Use parameterized queries' },
                },
              ],
            },
          },
          results: [
            {
              ruleId: 'javascript.lang.security.audit.sql-injection',
              level: 'error',
              message: { text: 'User input reaches SQL sink' },
              locations: [
                {
                  physicalLocation: {
                    artifactLocation: { uri: 'src/db.ts' },
                    region: { startLine: 42, endLine: 42, snippet: { text: 'db.query(sql)' } },
                  },
                },
              ],
            },
          ],
        },
      ],
    });

    expect(findings).toHaveLength(1);
    expect(findings[0]).toMatchObject({
      toolName: 'semgrep',
      ruleId: 'javascript.lang.security.audit.sql-injection',
      filePath: 'src/db.ts',
      startLine: 42,
      endLine: 42,
      severity: 'HIGH',
      normalizedRuleCategory: 'sql-injection',
    });
    expect(findings[0].primaryFingerprint).toHaveLength(64);
    expect(findings[0].toolFingerprint).toHaveLength(64);
    expect(findings[0].fingerprint).toBe(findings[0].primaryFingerprint);
  });

  it('strips absolute /tmp/codefence-scan-* paths when repoRoot is provided', () => {
    const findings = normalizeSarifLog(
      {
        runs: [
          {
            tool: { driver: { name: 'semgrep', rules: [] } },
            results: [
              {
                ruleId: 'test-rule',
                level: 'warning',
                message: { text: 'test' },
                locations: [
                  {
                    physicalLocation: {
                      artifactLocation: { uri: '/tmp/codefence-scan-IwLLZA/src/app.py' },
                      region: { startLine: 63, endLine: 63 },
                    },
                  },
                ],
              },
            ],
          },
        ],
      },
      { repoRoot: '/tmp/codefence-scan-IwLLZA' },
    );

    expect(findings).toHaveLength(1);
    expect(findings[0].filePath).toBe('src/app.py');
  });

  it('leaves paths unchanged when repoRoot is not provided (backward compat)', () => {
    const findings = normalizeSarifLog({
      runs: [
        {
          tool: { driver: { name: 'semgrep', rules: [] } },
          results: [
            {
              ruleId: 'test-rule',
              level: 'warning',
              message: { text: 'test' },
              locations: [
                {
                  physicalLocation: {
                    artifactLocation: { uri: '/tmp/codefence-scan-IwLLZA/src/app.py' },
                    region: { startLine: 63, endLine: 63 },
                  },
                },
              ],
            },
          ],
        },
      ],
    });

    expect(findings).toHaveLength(1);
    expect(findings[0].filePath).toBe('/tmp/codefence-scan-IwLLZA/src/app.py');
  });

  it('computes fingerprint over the cleaned relative path', () => {
    const withRoot = normalizeSarifLog(
      {
        runs: [
          {
            tool: { driver: { name: 'test-tool', rules: [] } },
            results: [
              {
                ruleId: 'r1',
                level: 'error',
                message: { text: 'x' },
                locations: [
                  {
                    physicalLocation: {
                      artifactLocation: { uri: '/tmp/codefence-scan-XYZ/src/handler.ts' },
                      region: { startLine: 10, endLine: 12 },
                    },
                  },
                ],
              },
            ],
          },
        ],
      },
      { repoRoot: '/tmp/codefence-scan-XYZ' },
    );

    const alreadyRelative = normalizeSarifLog({
      runs: [
        {
          tool: { driver: { name: 'test-tool', rules: [] } },
          results: [
            {
              ruleId: 'r1',
              level: 'error',
              message: { text: 'x' },
              locations: [
                {
                  physicalLocation: {
                    artifactLocation: { uri: 'src/handler.ts' },
                    region: { startLine: 10, endLine: 12 },
                  },
                },
              ],
            },
          ],
        },
      ],
    });

    // Both should produce the same fingerprint since paths resolve to the same relative path
    expect(withRoot[0].primaryFingerprint).toBe(alreadyRelative[0].primaryFingerprint);
    expect(withRoot[0].toolFingerprint).toBe(alreadyRelative[0].toolFingerprint);
  });
});
