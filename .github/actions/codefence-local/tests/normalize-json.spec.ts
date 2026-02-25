import * as fs from 'fs';
import * as path from 'path';
import { normalizeJsonPayload } from '../scripts/normalize-json';

describe('normalizeJsonPayload', () => {
  it('maps gitleaks findings to critical SECRETS issues', () => {
    const findings = normalizeJsonPayload(
      [
        {
          RuleID: 'generic-api-key',
          File: 'app/.env',
          StartLine: 3,
          EndLine: 3,
          Description: 'Generic API Key',
          Match: 'sk_live_xxx',
        },
      ],
      { toolName: 'gitleaks', toolVersion: '8.18.4' },
    );

    expect(findings).toHaveLength(1);
    expect(findings[0]).toMatchObject({
      category: 'SECRETS',
      severity: 'CRITICAL',
      confidence: 'HIGH',
      toolName: 'gitleaks',
      filePath: 'app/.env',
      startLine: 3,
      endLine: 3,
      ruleId: 'generic-api-key',
    });
  });

  it('maps bandit payload fields and confidence', () => {
    const findings = normalizeJsonPayload(
      {
        results: [
          {
            test_id: 'B602',
            test_name: 'subprocess_popen_with_shell_equals_true',
            filename: 'src/run.py',
            line_number: 12,
            issue_text: 'subprocess call with shell=True identified',
            issue_severity: 'HIGH',
            issue_confidence: 'HIGH',
            code: 'subprocess.call(user_input, shell=True)',
            more_info: 'https://bandit.readthedocs.io/',
          },
        ],
      },
      { toolName: 'bandit', toolVersion: '1.7.10' },
    );

    expect(findings).toHaveLength(1);
    expect(findings[0]).toMatchObject({
      category: 'SAST',
      severity: 'HIGH',
      confidence: 'HIGH',
      ruleId: 'B602',
      filePath: 'src/run.py',
      normalizedRuleCategory: 'command-injection',
    });
  });

  it('maps trivy vulnerabilities and misconfigurations', () => {
    const findings = normalizeJsonPayload(
      {
        Results: [
          {
            Target: 'Dockerfile',
            Vulnerabilities: [
              {
                VulnerabilityID: 'CVE-2024-1111',
                Title: 'openssl vulnerability',
                Severity: 'CRITICAL',
                PkgName: 'openssl',
                FixedVersion: '1.2.3',
                PrimaryURL: 'https://example.test/cve',
              },
            ],
            Misconfigurations: [
              {
                ID: 'DS001',
                Title: 'Privileged container',
                Description: 'Container is privileged',
                Severity: 'HIGH',
                Resolution: 'Disable privileged mode',
                PrimaryURL: 'https://example.test/misconfig',
                CauseMetadata: {
                  Filename: 'k8s/deploy.yaml',
                  StartLine: 20,
                  EndLine: 22,
                },
              },
            ],
          },
        ],
      },
      { toolName: 'trivy', toolVersion: '0.55.0' },
    );

    expect(findings).toHaveLength(2);
    expect(findings[0]).toMatchObject({
      category: 'CONTAINER',
      severity: 'CRITICAL',
      ruleId: 'CVE-2024-1111',
      filePath: 'Dockerfile',
    });
    expect(findings[1]).toMatchObject({
      category: 'IAC',
      severity: 'HIGH',
      ruleId: 'DS001',
      filePath: 'k8s/deploy.yaml',
      startLine: 20,
      endLine: 22,
    });
  });

  it('maps scorecard checks below threshold to POSTURE findings', () => {
    const findings = normalizeJsonPayload(
      {
        checks: [
          {
            name: 'Branch-Protection',
            score: 2,
            reason: 'Branch protection is not enabled',
          },
          {
            name: 'Binary-Artifacts',
            score: 9,
          },
        ],
      },
      { toolName: 'scorecard', toolVersion: '5.1.1' },
    );

    expect(findings).toHaveLength(1);
    expect(findings[0]).toMatchObject({
      category: 'POSTURE',
      severity: 'HIGH',
      ruleId: 'scorecard:Branch-Protection',
    });
  });

  it('maps OSV results into SCA findings', () => {
    const findings = normalizeJsonPayload(
      {
        results: [
          {
            source: { path: 'package-lock.json' },
            packages: [
              {
                package: { name: 'lodash' },
                vulnerabilities: [
                  {
                    id: 'CVE-2024-2222',
                    summary: 'Prototype pollution',
                    fixed_version: '4.17.25',
                    reference: 'https://osv.dev/vulnerability/CVE-2024-2222',
                  },
                ],
              },
            ],
          },
        ],
      },
      { toolName: 'osv-scanner', toolVersion: '1.8.2' },
    );

    expect(findings).toHaveLength(1);
    expect(findings[0]).toMatchObject({
      category: 'SCA',
      ruleId: 'CVE-2024-2222',
      filePath: 'package-lock.json',
      normalizedRuleCategory: 'known-cve',
    });
  });

  it('maps pip-audit results into SCA findings', () => {
    const findings = normalizeJsonPayload(
      {
        dependencies: [
          {
            name: 'requests',
            version: '2.20.0',
            path: 'requirements.txt',
            vulns: [
              {
                id: 'CVE-2023-1234',
                description: 'TLS verification issue',
                fix_versions: ['2.31.0'],
                link: 'https://example.test/advisory',
              },
            ],
          },
        ],
      },
      { toolName: 'pip-audit', toolVersion: '2.7.3' },
    );

    expect(findings).toHaveLength(1);
    expect(findings[0]).toMatchObject({
      category: 'SCA',
      ruleId: 'CVE-2023-1234',
      filePath: 'requirements.txt',
      normalizedRuleCategory: 'known-cve',
    });
  });

  it('maps actionlint findings into ACTIONS findings', () => {
    const findings = normalizeJsonPayload(
      [
        {
          ruleId: 'actionlint-rule',
          filepath: '.github/workflows/ci.yml',
          line: 14,
          message: 'workflow has an unpinned action',
          severity: 'warning',
        },
      ],
      { toolName: 'actionlint', toolVersion: '1.7.4' },
    );

    expect(findings).toHaveLength(1);
    expect(findings[0]).toMatchObject({
      category: 'ACTIONS',
      filePath: '.github/workflows/ci.yml',
      startLine: 14,
      endLine: 14,
      ruleId: 'actionlint-rule',
    });
  });

  it('maps zizmor findings into ACTIONS findings', () => {
    const findings = normalizeJsonPayload(
      {
        findings: [
          {
            rule_id: 'zizmor-dangerous-trigger',
            path: '.github/workflows/release.yml',
            start_line: 8,
            end_line: 10,
            message: 'dangerous trigger detected',
            severity: 'HIGH',
            confidence: 'HIGH',
            url: 'https://example.test/zizmor-rule',
          },
        ],
      },
      { toolName: 'zizmor', toolVersion: '1.5.1' },
    );

    expect(findings).toHaveLength(1);
    expect(findings[0]).toMatchObject({
      category: 'ACTIONS',
      filePath: '.github/workflows/release.yml',
      startLine: 8,
      endLine: 10,
      ruleId: 'zizmor-dangerous-trigger',
    });
  });

  // Checkov emits SARIF in the production pipeline; these validate the deprecated JSON fallback.
  it('normalizes Checkov JSON fallback payload', () => {
    const checkovJson = {
      results: {
        failed_checks: [
          {
            check_id: 'CKV_AWS_1',
            file_path: '/path/to/main.tf',
            check_name: 'Ensure S3 bucket has encryption',
            file_line_range: [5, 8],
            guideline: 'https://docs.bridgecrew.io/docs/s3_encryption',
          },
        ],
      },
    };

    const normalized = normalizeJsonPayload(checkovJson, {
      toolName: 'checkov',
      toolVersion: '2.3.123',
    });

    expect(normalized).toHaveLength(1);
    expect(normalized[0]).toMatchObject({
      toolName: 'checkov',
      ruleId: 'CKV_AWS_1',
      filePath: '/path/to/main.tf',
      startLine: 5,
      endLine: 8,
    });
  });

  it('handles real Checkov JSON structure without throwing', () => {
    const realCheckovOutput = {
      check_type: 'terraform',
      results: {
        passed_checks: [],
        failed_checks: [
          {
            check_id: 'CKV_AWS_18',
            bc_check_id: 'BC_AWS_S3_13',
            check_name: 'Ensure S3 bucket has access logging enabled',
            check_result: {
              result: 'FAILED',
            },
            file_path: '/main.tf',
            file_line_range: [10, 15],
            resource: 'aws_s3_bucket.example',
            evaluations: null,
            check_class: 'checkov.terraform.checks.resource.aws.S3Logging',
            fixed_definition: null,
            entity_tags: null,
            caller_file_path: null,
            caller_file_line_range: null,
            guideline: 'https://docs.bridgecrew.io/docs/s3_13-enable-logging',
          },
        ],
        skipped_checks: [],
        parsing_errors: [],
      },
      summary: {
        passed: 0,
        failed: 1,
        skipped: 0,
        parsing_errors: 0,
        resource_count: 1,
        checkov_version: '2.3.123',
      },
    };

    expect(() => {
      const normalized = normalizeJsonPayload(realCheckovOutput, {
        toolName: 'checkov',
        toolVersion: '2.3.123',
      });
      expect(normalized).toHaveLength(1);
      expect(normalized[0].ruleId).toBe('CKV_AWS_18');
    }).not.toThrow();
  });

  it('keeps a deprecated annotation for Checkov JSON fallback path', () => {
    const sourcePath = path.resolve(__dirname, '../scripts/normalize-json.ts');
    const source = fs.readFileSync(sourcePath, 'utf8');

    expect(source).toContain('@deprecated Checkov output is normalized via SARIF');
    expect(source).toContain('function normalizeCheckov(');
  });

  describe('path normalization with repoRoot', () => {
    it('strips absolute /tmp/codefence-scan-* paths from bandit findings', () => {
      const findings = normalizeJsonPayload(
        {
          results: [
            {
              test_id: 'B602',
              test_name: 'subprocess_popen_with_shell_equals_true',
              filename: '/tmp/codefence-scan-IwLLZA/src/run.py',
              line_number: 12,
              issue_text: 'subprocess call with shell=True identified',
              issue_severity: 'HIGH',
              issue_confidence: 'HIGH',
            },
          ],
        },
        { toolName: 'bandit', repoRoot: '/tmp/codefence-scan-IwLLZA' },
      );

      expect(findings).toHaveLength(1);
      expect(findings[0].filePath).toBe('src/run.py');
    });

    it('strips absolute paths from gitleaks findings', () => {
      const findings = normalizeJsonPayload(
        [
          {
            RuleID: 'generic-api-key',
            File: '/tmp/codefence-scan-XYZ123/app/.env',
            StartLine: 3,
            EndLine: 3,
            Description: 'Generic API Key',
          },
        ],
        { toolName: 'gitleaks', repoRoot: '/tmp/codefence-scan-XYZ123' },
      );

      expect(findings).toHaveLength(1);
      expect(findings[0].filePath).toBe('app/.env');
    });

    it('strips absolute paths from osv-scanner findings', () => {
      const findings = normalizeJsonPayload(
        {
          results: [
            {
              source: { path: '/tmp/codefence-scan-ABC/package-lock.json' },
              packages: [
                {
                  package: { name: 'lodash' },
                  vulnerabilities: [
                    { id: 'CVE-2024-2222', summary: 'Prototype pollution' },
                  ],
                },
              ],
            },
          ],
        },
        { toolName: 'osv-scanner', repoRoot: '/tmp/codefence-scan-ABC' },
      );

      expect(findings).toHaveLength(1);
      expect(findings[0].filePath).toBe('package-lock.json');
    });

    it('leaves paths unchanged without repoRoot (backward compat)', () => {
      const findings = normalizeJsonPayload(
        {
          results: [
            {
              test_id: 'B602',
              test_name: 'test',
              filename: '/tmp/codefence-scan-IwLLZA/src/run.py',
              line_number: 1,
              issue_text: 'test',
              issue_severity: 'HIGH',
              issue_confidence: 'HIGH',
            },
          ],
        },
        { toolName: 'bandit' },
      );

      expect(findings).toHaveLength(1);
      expect(findings[0].filePath).toBe('/tmp/codefence-scan-IwLLZA/src/run.py');
    });

    it('computes fingerprint over the cleaned relative path', () => {
      const withRoot = normalizeJsonPayload(
        {
          results: [
            {
              test_id: 'B602',
              test_name: 'test',
              filename: '/tmp/codefence-scan-XYZ/src/run.py',
              line_number: 10,
              issue_text: 'test',
              issue_severity: 'HIGH',
              issue_confidence: 'HIGH',
            },
          ],
        },
        { toolName: 'bandit', repoRoot: '/tmp/codefence-scan-XYZ' },
      );

      const alreadyRelative = normalizeJsonPayload(
        {
          results: [
            {
              test_id: 'B602',
              test_name: 'test',
              filename: 'src/run.py',
              line_number: 10,
              issue_text: 'test',
              issue_severity: 'HIGH',
              issue_confidence: 'HIGH',
            },
          ],
        },
        { toolName: 'bandit' },
      );

      expect(withRoot[0].primaryFingerprint).toBe(alreadyRelative[0].primaryFingerprint);
      expect(withRoot[0].toolFingerprint).toBe(alreadyRelative[0].toolFingerprint);
    });
  });
});
