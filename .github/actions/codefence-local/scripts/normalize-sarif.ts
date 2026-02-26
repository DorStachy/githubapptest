import * as fs from 'fs';
import * as path from 'path';
import {
  EvidenceMode,
  FindingCategory,
  FindingConfidence,
  FindingSeverity,
  NormalizedFinding,
  fingerprintForPrimary,
  fingerprintForTool,
} from './types';
import { parseKeyValueArgs } from './utils';
import { resolveNormalizedRuleCategory } from './normalizers/rule-category-map';
import { stripWorkspacePrefix } from './path-utils';

interface SarifArtifactLocation {
  uri?: string;
}

interface SarifRegion {
  startLine?: number;
  endLine?: number;
  snippet?: { text?: string };
}

interface SarifPhysicalLocation {
  artifactLocation?: SarifArtifactLocation;
  region?: SarifRegion;
}

interface SarifLocation {
  physicalLocation?: SarifPhysicalLocation;
}

interface SarifRule {
  id?: string;
  name?: string;
  shortDescription?: { text?: string };
  fullDescription?: { text?: string };
  help?: { text?: string };
  properties?: Record<string, unknown>;
}

interface SarifResult {
  ruleId?: string;
  level?: string;
  message?: { text?: string };
  locations?: SarifLocation[];
  relatedLocations?: unknown[];
  codeFlows?: unknown[];
  properties?: Record<string, unknown>;
}

interface SarifRun {
  tool?: {
    driver?: {
      name?: string;
      semanticVersion?: string;
      version?: string;
      rules?: SarifRule[];
    };
  };
  results?: SarifResult[];
}

interface SarifLog {
  runs?: SarifRun[];
}

function normalizeSeverity(level: string | undefined): FindingSeverity {
  const normalized = (level || '').toLowerCase();
  if (normalized === 'error') {
    return 'HIGH';
  }
  if (normalized === 'warning') {
    return 'MEDIUM';
  }
  if (normalized === 'note') {
    return 'LOW';
  }
  return 'MEDIUM';
}

function normalizeConfidence(value: unknown): FindingConfidence {
  const normalized = String(value || '').toLowerCase();
  if (normalized.includes('high') || normalized.includes('very-high')) {
    return 'HIGH';
  }
  if (normalized.includes('low')) {
    return 'LOW';
  }
  return 'MEDIUM';
}

function inferCategory(toolName: string): FindingCategory {
  const normalized = toolName.toLowerCase();
  if (normalized.includes('gitleaks')) {
    return 'SECRETS';
  }
  if (normalized.includes('checkov')) {
    return 'IAC';
  }
  if (normalized.includes('trivy')) {
    return 'CONTAINER';
  }
  if (normalized.includes('actionlint') || normalized.includes('zizmor')) {
    return 'ACTIONS';
  }
  if (normalized.includes('scorecard')) {
    return 'POSTURE';
  }
  if (normalized.includes('osv') || normalized.includes('pip-audit')) {
    return 'SCA';
  }
  return 'SAST';
}

function collectReferences(rule: SarifRule | undefined, result: SarifResult): string[] {
  const refs: string[] = [];
  const tags = rule?.properties?.tags;
  if (Array.isArray(tags)) {
    for (const tag of tags) {
      if (typeof tag === 'string') {
        refs.push(tag);
      }
    }
  }

  const cwe = result.properties?.['security-severity'];
  if (typeof cwe === 'string') {
    refs.push(cwe);
  }

  return Array.from(new Set(refs)).slice(0, 100);
}

export function normalizeSarifLog(
  sarif: SarifLog,
  options?: {
    toolNameOverride?: string;
    toolVersionOverride?: string;
    defaultEvidenceMode?: EvidenceMode;
    repoRoot?: string;
  },
): NormalizedFinding[] {
  const findings: NormalizedFinding[] = [];

  for (const run of sarif.runs || []) {
    const driver = run.tool?.driver;
    const toolName = options?.toolNameOverride || driver?.name || 'unknown-sarif-tool';
    const toolVersion =
      options?.toolVersionOverride || driver?.semanticVersion || driver?.version || null;
    const category = inferCategory(toolName);

    const ruleMap = new Map<string, SarifRule>();
    for (const rule of driver?.rules || []) {
      if (rule.id) {
        ruleMap.set(rule.id, rule);
      }
    }

    for (const result of run.results || []) {
      const ruleId = result.ruleId || 'unknown-rule';
      const mappedRule = ruleMap.get(ruleId);
      const normalizedRuleCategory = resolveNormalizedRuleCategory(toolName, ruleId);
      const location = result.locations?.[0]?.physicalLocation;
      const rawPath = location?.artifactLocation?.uri || 'unknown';
      const filePath = stripWorkspacePrefix(rawPath, options?.repoRoot);
      const startLine = location?.region?.startLine ?? 1;
      const endLine = location?.region?.endLine ?? startLine;
      const title =
        mappedRule?.shortDescription?.text || mappedRule?.name || ruleId || 'Security finding';

      const finding: NormalizedFinding = {
        fingerprint: '',
        primaryFingerprint: '',
        toolFingerprint: '',
        category,
        severity: normalizeSeverity(result.level),
        confidence: normalizeConfidence(result.properties?.precision),
        title: title.slice(0, 256),
        description: (result.message?.text || mappedRule?.fullDescription?.text || '').slice(0, 2000),
        filePath,
        startLine,
        endLine,
        snippet: location?.region?.snippet?.text || null,
        diffContext: null,
        remediationSummary: mappedRule?.help?.text || null,
        patchSuggestion: null,
        references: collectReferences(mappedRule, result),
        toolName,
        toolVersion,
        ruleId: ruleId.slice(0, 128),
        normalizedRuleCategory: normalizedRuleCategory.slice(0, 128),
        sarifHelpText: mappedRule?.help?.text || null,
        sarifCodeFlows: Array.isArray(result.codeFlows) ? result.codeFlows : null,
        sarifRelatedLocations: Array.isArray(result.relatedLocations)
          ? result.relatedLocations
          : null,
      };

      finding.primaryFingerprint = fingerprintForPrimary(
        finding.category,
        finding.normalizedRuleCategory,
        finding.filePath,
        finding.startLine,
        finding.endLine,
      );
      finding.toolFingerprint = fingerprintForTool(
        finding.toolName,
        finding.ruleId,
        finding.filePath,
        finding.startLine,
        finding.endLine,
      );
      finding.fingerprint = finding.primaryFingerprint;

      findings.push(finding);
    }
  }

  return findings;
}

export function normalizeSarifFile(
  filePath: string,
  options?: { toolNameOverride?: string; toolVersionOverride?: string; repoRoot?: string },
): NormalizedFinding[] {
  const content = fs.readFileSync(filePath, 'utf8').trim();
  if (content.length === 0) {
    const toolLabel = options?.toolNameOverride || path.basename(filePath);
    process.stderr.write(
      `[warn] Skipping empty SARIF file from ${toolLabel}: ${filePath}\n`,
    );
    return [];
  }
  let parsed: SarifLog;
  try {
    parsed = JSON.parse(content) as SarifLog;
  } catch (err) {
    const toolLabel = options?.toolNameOverride || path.basename(filePath);
    process.stderr.write(
      `[warn] Invalid SARIF JSON from ${toolLabel} (${filePath}): ${
        err instanceof Error ? err.message : String(err)
      }\n`,
    );
    return [];
  }
  return normalizeSarifLog(parsed, options);
}

function runCli(): void {
  const args = parseKeyValueArgs(process.argv.slice(2));
  const input = args.input;
  const output = args.output;
  if (!input || !output) {
    throw new Error(
      'Usage: normalize-sarif.ts --input=<file1,file2> --output=<out-file> [--tool=<toolName>] [--tool-version=<version>]',
    );
  }

  const files = input
    .split(',')
    .map((item) => item.trim())
    .filter(Boolean)
    .map((item) => path.resolve(item));

  const findings = files.flatMap((filePath) =>
    normalizeSarifFile(filePath, {
      toolNameOverride: args.tool,
      toolVersionOverride: args['tool-version'],
    }),
  );

  fs.writeFileSync(output, `${JSON.stringify(findings, null, 2)}\n`, 'utf8');
}

if (require.main === module) {
  runCli();
}
