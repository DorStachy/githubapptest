import * as fs from 'fs';
import * as path from 'path';
import { diffLockfiles, LockfileDiffResult } from './lockfile-diff';
import { buildGraphFromPackageLock, introducedByChain, maxDepthFromRoots } from './dep-graph';
import {
  FindingCategory,
  FindingSeverity,
  NormalizedFinding,
  fingerprintForPrimary,
  fingerprintForTool,
} from './types';
import { parseKeyValueArgs, readJsonFile, writeJsonFile } from './utils';

interface HeuristicContext {
  workspaceRoot: string;
  manifestPath: string;
  baseManifestPath?: string;
  baseLockfilePath?: string;
  headLockfilePath?: string;
  popularPackagesPath?: string;
  evidenceMode?: 'MINIMAL' | 'STANDARD' | 'RICH';
}

interface PackageManifest {
  dependencies?: Record<string, string>;
  devDependencies?: Record<string, string>;
  optionalDependencies?: Record<string, string>;
  peerDependencies?: Record<string, string>;
  scripts?: Record<string, string>;
}

const LIFECYCLE_SCRIPTS = ['preinstall', 'install', 'postinstall', 'prepare'];

function loadManifest(manifestPath: string): PackageManifest {
  return readJsonFile<PackageManifest>(manifestPath);
}

function allDependencies(manifest: PackageManifest): Record<string, string> {
  return {
    ...(manifest.dependencies || {}),
    ...(manifest.devDependencies || {}),
    ...(manifest.optionalDependencies || {}),
    ...(manifest.peerDependencies || {}),
  };
}

function toFinding(
  input: {
    ruleId: string;
    normalizedRuleCategory: string;
    severity: FindingSeverity;
    title: string;
    description: string;
    remediationSummary: string;
    filePath: string;
    references?: string[];
    metadata?: Record<string, unknown>;
  },
  line = 1,
): NormalizedFinding {
  const category: FindingCategory = 'SCA';
  const toolName = 'supply-chain-heuristics';
  const primaryFingerprint = fingerprintForPrimary(
    category,
    input.normalizedRuleCategory,
    input.filePath,
    line,
    line,
  );
  const toolFingerprint = fingerprintForTool(toolName, input.ruleId, input.filePath, line, line);

  return {
    fingerprint: primaryFingerprint,
    primaryFingerprint,
    toolFingerprint,
    category,
    severity: input.severity,
    confidence: input.severity === 'LOW' || input.severity === 'INFO' ? 'MEDIUM' : 'HIGH',
    title: input.title,
    description: input.description,
    filePath: input.filePath,
    startLine: line,
    endLine: line,
    snippet: null,
    diffContext: null,
    remediationSummary: input.remediationSummary,
    patchSuggestion: null,
    references: input.references || [],
    toolName,
    toolVersion: '1.0.0',
    ruleId: input.ruleId,
    normalizedRuleCategory: input.normalizedRuleCategory,
    metadata: input.metadata || {},
  };
}

function levenshtein(a: string, b: string): number {
  const matrix: number[][] = Array.from({ length: a.length + 1 }, () => []);

  for (let i = 0; i <= a.length; i += 1) {
    matrix[i][0] = i;
  }
  for (let j = 0; j <= b.length; j += 1) {
    matrix[0][j] = j;
  }

  for (let i = 1; i <= a.length; i += 1) {
    for (let j = 1; j <= b.length; j += 1) {
      const cost = a[i - 1] === b[j - 1] ? 0 : 1;
      matrix[i][j] = Math.min(
        matrix[i - 1][j] + 1,
        matrix[i][j - 1] + 1,
        matrix[i - 1][j - 1] + cost,
      );
    }
  }

  return matrix[a.length][b.length];
}

function detectGitAndUrlDependencies(
  filePath: string,
  deps: Record<string, string>,
): NormalizedFinding[] {
  const findings: NormalizedFinding[] = [];

  for (const [name, version] of Object.entries(deps)) {
    if (/^(git\+|https?:\/\/)/i.test(version)) {
      findings.push(
        toFinding(
          {
            ruleId: 'SCH-01',
            normalizedRuleCategory: 'supply-chain-git-dep',
            severity: 'HIGH',
            title: `Dependency '${name}' uses a non-registry source`,
            description: `Dependency '${name}' points to '${version}', which bypasses trusted registry release workflows.`,
            remediationSummary: 'Prefer registry-published versions and pin immutable releases.',
            filePath,
            metadata: { dependency: name, source: version },
          },
        ),
      );

      if (version.startsWith('git+') && !/[#@][0-9a-f]{7,40}$/i.test(version)) {
        findings.push(
          toFinding(
            {
              ruleId: 'SCH-02',
              normalizedRuleCategory: 'supply-chain-unpinned-git-ref',
              severity: 'HIGH',
              title: `Dependency '${name}' uses an unpinned git reference`,
              description: `Dependency '${name}' is not pinned to an immutable commit SHA: '${version}'.`,
              remediationSummary: 'Pin git dependencies to full commit SHAs.',
              filePath,
              metadata: { dependency: name, source: version },
            },
          ),
        );
      }
    }

    if (/^(file:|link:|\.{1,2}[\/\\])/i.test(version)) {
      findings.push(
        toFinding(
          {
            ruleId: 'SCH-03',
            normalizedRuleCategory: 'supply-chain-local-path-dep',
            severity: 'MEDIUM',
            title: `Dependency '${name}' references a local path`,
            description: `Dependency '${name}' uses '${version}', which can mask supply-chain provenance in CI.`,
            remediationSummary: 'Use released package versions for production-facing dependency graphs.',
            filePath,
            metadata: { dependency: name, source: version },
          },
        ),
      );
    }
  }

  return findings;
}

function detectLifecycleScriptChanges(
  filePath: string,
  baseManifest: PackageManifest | null,
  headManifest: PackageManifest,
): NormalizedFinding[] {
  const findings: NormalizedFinding[] = [];
  const baseScripts = baseManifest?.scripts || {};
  const headScripts = headManifest.scripts || {};

  for (const scriptName of LIFECYCLE_SCRIPTS) {
    const before = baseScripts[scriptName] || '';
    const after = headScripts[scriptName] || '';
    if (!after || before === after) {
      continue;
    }

    findings.push(
      toFinding(
        {
          ruleId: 'SCH-04',
          normalizedRuleCategory: 'supply-chain-lifecycle-script',
          severity: 'CRITICAL',
          title: `Lifecycle script '${scriptName}' changed`,
          description: `The '${scriptName}' script changed from '${before || '(none)'}' to '${after}'.`,
          remediationSummary: 'Review lifecycle scripts carefully before merge.',
          filePath,
          metadata: { script: scriptName, before, after },
        },
      ),
    );
  }

  return findings;
}

function detectNewDependencies(
  filePath: string,
  baseManifest: PackageManifest | null,
  headManifest: PackageManifest,
): NormalizedFinding[] {
  const baseDeps = allDependencies(baseManifest || {});
  const headDeps = allDependencies(headManifest);
  const findings: NormalizedFinding[] = [];

  for (const [name, version] of Object.entries(headDeps)) {
    if (baseDeps[name]) {
      continue;
    }

    findings.push(
      toFinding(
        {
          ruleId: 'SCH-05',
          normalizedRuleCategory: 'supply-chain-new-dependency',
          severity: 'INFO',
          title: `New dependency introduced: ${name}`,
          description: `Dependency '${name}'@'${version}' is new in this change set.`,
          remediationSummary: 'Validate dependency reputation and maintenance health before merge.',
          filePath,
          metadata: { dependency: name, version },
        },
      ),
    );
  }

  return findings;
}

function loadPopularPackages(filePath?: string): string[] {
  if (!filePath || !fs.existsSync(filePath)) {
    return [];
  }

  const parsed = readJsonFile<any>(filePath);
  if (Array.isArray(parsed)) {
    return parsed.filter((entry) => typeof entry === 'string');
  }

  if (Array.isArray(parsed?.packages)) {
    return parsed.packages.filter((entry: unknown) => typeof entry === 'string');
  }

  return [];
}

function detectTyposquats(
  filePath: string,
  headManifest: PackageManifest,
  popularPackages: string[],
): NormalizedFinding[] {
  if (popularPackages.length === 0) {
    return [];
  }

  const findings: NormalizedFinding[] = [];
  const deps = allDependencies(headManifest);

  for (const depName of Object.keys(deps)) {
    for (const popular of popularPackages) {
      if (depName === popular || Math.abs(depName.length - popular.length) > 2) {
        continue;
      }

      const distance = levenshtein(depName, popular);
      if (distance <= 2) {
        findings.push(
          toFinding(
            {
              ruleId: 'SCH-06',
              normalizedRuleCategory: 'supply-chain-typosquat',
              severity: 'HIGH',
              title: `Potential typosquat: '${depName}' is similar to '${popular}'`,
              description: `Dependency '${depName}' is edit-distance ${distance} from popular package '${popular}'.`,
              remediationSummary: 'Confirm package publisher, downloads, and repository authenticity.',
              filePath,
              metadata: { dependency: depName, similarTo: popular, distance },
            },
          ),
        );
        break;
      }
    }
  }

  return findings;
}

function detectLockfileSignals(
  lockfileDiff: LockfileDiffResult,
  lockfilePath: string,
): NormalizedFinding[] {
  const findings: NormalizedFinding[] = [];

  for (const [dep, change] of Object.entries(lockfileDiff.updated)) {
    findings.push(
      toFinding(
        {
          ruleId: 'SCH-07',
          normalizedRuleCategory: 'supply-chain-lockfile-version-change',
          severity: 'LOW',
          title: `Dependency version changed: ${dep}`,
          description: `${dep} changed from ${change.from} to ${change.to}.`,
          remediationSummary: 'Review changelog and provenance for updated transitive dependencies.',
          filePath: lockfilePath,
          metadata: { dependency: dep, from: change.from, to: change.to },
        },
      ),
    );
  }

  for (const [dep, version] of Object.entries(lockfileDiff.added)) {
    findings.push(
      toFinding(
        {
          ruleId: 'SCH-08',
          normalizedRuleCategory: 'supply-chain-lockfile-new-transitive',
          severity: 'LOW',
          title: `New transitive dependency: ${dep}`,
          description: `${dep}@${version} was added to lockfile resolution output.`,
          remediationSummary: 'Trace introduced-by chain and validate package legitimacy.',
          filePath: lockfilePath,
          metadata: { dependency: dep, version },
        },
      ),
    );
  }

  return findings;
}

function detectGraphDepthAndChain(
  headLockfilePath: string,
  addedDependencies: string[],
): NormalizedFinding[] {
  if (!headLockfilePath.endsWith('package-lock.json') || !fs.existsSync(headLockfilePath)) {
    return [];
  }

  const lockfile = readJsonFile<any>(headLockfilePath);
  const graph = buildGraphFromPackageLock(lockfile);
  const findings: NormalizedFinding[] = [];

  for (const dep of addedDependencies) {
    const depth = maxDepthFromRoots(graph, dep);
    if (depth >= 5) {
      findings.push(
        toFinding(
          {
            ruleId: 'SCH-09',
            normalizedRuleCategory: 'supply-chain-dependency-depth',
            severity: 'LOW',
            title: `Deep transitive dependency introduced: ${dep}`,
            description: `${dep} appears at dependency depth ${depth}.`,
            remediationSummary: 'Review deep dependency chain and consider minimizing transitive footprint.',
            filePath: headLockfilePath,
            metadata: {
              dependency: dep,
              depth,
              introducedBy: introducedByChain(graph, dep),
            },
          },
        ),
      );
    }
  }

  return findings;
}

export function runSupplyChainHeuristics(context: HeuristicContext): NormalizedFinding[] {
  const manifestPath = path.resolve(context.workspaceRoot, context.manifestPath);
  const baseManifestPath = context.baseManifestPath
    ? path.resolve(context.workspaceRoot, context.baseManifestPath)
    : '';

  if (!fs.existsSync(manifestPath)) {
    return [];
  }

  const headManifest = loadManifest(manifestPath);
  const baseManifest = baseManifestPath && fs.existsSync(baseManifestPath)
    ? loadManifest(baseManifestPath)
    : null;

  const findings: NormalizedFinding[] = [];
  const deps = allDependencies(headManifest);

  findings.push(...detectGitAndUrlDependencies(context.manifestPath, deps));
  findings.push(...detectLifecycleScriptChanges(context.manifestPath, baseManifest, headManifest));
  findings.push(...detectNewDependencies(context.manifestPath, baseManifest, headManifest));

  const popularPackages = loadPopularPackages(
    context.popularPackagesPath
      ? path.resolve(context.workspaceRoot, context.popularPackagesPath)
      : undefined,
  );
  findings.push(...detectTyposquats(context.manifestPath, headManifest, popularPackages));

  if (context.baseLockfilePath && context.headLockfilePath) {
    const baseLock = path.resolve(context.workspaceRoot, context.baseLockfilePath);
    const headLock = path.resolve(context.workspaceRoot, context.headLockfilePath);
    const diff = diffLockfiles(baseLock, headLock);
    findings.push(...detectLockfileSignals(diff, context.headLockfilePath));
    findings.push(...detectGraphDepthAndChain(headLock, Object.keys(diff.added)));
  }

  return findings;
}

function runCli(): void {
  const args = parseKeyValueArgs(process.argv.slice(2));
  if (!args.manifest) {
    throw new Error('Usage: supply-chain-heuristics.ts --manifest=<package.json> [--output=<file>]');
  }

  const findings = runSupplyChainHeuristics({
    workspaceRoot: path.resolve(args.root || process.cwd()),
    manifestPath: args.manifest,
    baseManifestPath: args['base-manifest'],
    baseLockfilePath: args['base-lockfile'],
    headLockfilePath: args['head-lockfile'],
    popularPackagesPath: args['popular-packages'] || 'configs/popular-packages.json',
    evidenceMode: (args['evidence-mode'] as any) || 'MINIMAL',
  });

  if (args.output) {
    writeJsonFile(args.output, findings);
    return;
  }

  process.stdout.write(`${JSON.stringify(findings, null, 2)}\n`);
}

if (require.main === module) {
  runCli();
}
