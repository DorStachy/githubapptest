#!/usr/bin/env node
const fs = require('fs');
const path = require('path');

const severityRank = {
  INFO: 1,
  LOW: 2,
  MEDIUM: 3,
  HIGH: 4,
  CRITICAL: 5,
};

function readJson(filePath) {
  return JSON.parse(fs.readFileSync(filePath, 'utf8'));
}

function matchesExpected(expected, finding) {
  if (!finding) return false;
  if (expected.file && finding.filePath !== expected.file) return false;
  if (expected.category && finding.category !== expected.category) return false;
  if (
    expected.normalizedRuleCategory &&
    finding.normalizedRuleCategory !== expected.normalizedRuleCategory
  ) {
    return false;
  }
  if (expected.cve && !`${finding.ruleId || ''}`.includes(expected.cve)) {
    return false;
  }
  if (
    Array.isArray(expected.detectedBy) &&
    expected.detectedBy.length > 0 &&
    !expected.detectedBy.some((tool) => (finding.toolName || '').toLowerCase().includes(tool.toLowerCase()))
  ) {
    return false;
  }

  return true;
}

function verify(expectedManifest, actualFindings) {
  const missing = [];
  const severityWarnings = [];

  for (const expected of expectedManifest.expectedFindings || []) {
    const match = actualFindings.find((finding) => matchesExpected(expected, finding));
    if (!match) {
      missing.push(expected);
      continue;
    }

    if (expected.minSeverity) {
      const actualRank = severityRank[match.severity] || 0;
      const minRank = severityRank[expected.minSeverity] || 0;
      if (actualRank < minRank) {
        severityWarnings.push({
          id: expected.id,
          expected: expected.minSeverity,
          actual: match.severity,
        });
      }
    }
  }

  return { missing, severityWarnings };
}

function main() {
  const expectedPathArg = process.argv.find((arg) => arg.startsWith('--expected='));
  const actualPathArg = process.argv.find((arg) => arg.startsWith('--actual='));
  const failOnMissing = process.argv.includes('--fail-on-missing');

  const expectedPath = expectedPathArg
    ? expectedPathArg.split('=')[1]
    : process.argv[2] || path.join(__dirname, 'expected-findings.json');
  const actualPath = actualPathArg ? actualPathArg.split('=')[1] : process.argv[3];

  if (!expectedPath || !actualPath) {
    console.error('Usage: verify-coverage.js --expected=<manifest.json> --actual=<scan-results.json> [--fail-on-missing]');
    process.exit(2);
  }

  const expected = readJson(expectedPath);
  const actual = readJson(actualPath);
  const findings = Array.isArray(actual) ? actual : actual.findings || [];

  const { missing, severityWarnings } = verify(expected, findings);

  if (missing.length > 0) {
    for (const entry of missing) {
      console.error(
        `COVERAGE REGRESSION: ${entry.id} (${entry.file}, ${entry.category}, ${entry.normalizedRuleCategory}) not detected`,
      );
    }
  }

  if (severityWarnings.length > 0) {
    for (const warning of severityWarnings) {
      console.warn(
        `SEVERITY WARNING: ${warning.id} expected >= ${warning.expected}, got ${warning.actual}`,
      );
    }
  }

  const total = (expected.expectedFindings || []).length;
  const detected = total - missing.length;
  const percentage = total === 0 ? 100 : Math.round((detected / total) * 100);
  console.log(`Coverage: ${detected}/${total} (${percentage}%) expected findings detected.`);

  if (failOnMissing && missing.length > 0) {
    process.exit(1);
  }
}

main();
