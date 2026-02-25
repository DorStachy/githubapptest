import * as fs from 'fs';
import { NormalizedFinding, Verdict, SEVERITY_RANK } from './types';
import { parseKeyValueArgs, severityToVerdict } from './utils';

function summarizeCounts(findings: NormalizedFinding[]): Record<string, number> {
  const counts = {
    CRITICAL: 0,
    HIGH: 0,
    MEDIUM: 0,
    LOW: 0,
    INFO: 0,
  };

  for (const finding of findings) {
    counts[finding.severity] += 1;
  }

  return counts;
}

export function buildForkSummaryMarkdown(
  findings: NormalizedFinding[],
  verdict: Verdict,
  opts: { uploaded: boolean },
): string {
  const counts = summarizeCounts(findings);
  const sorted = [...findings].sort((a, b) => SEVERITY_RANK[b.severity] - SEVERITY_RANK[a.severity]);

  const lines: string[] = [];
  lines.push('## CodeFence Security Scan - Fork PR Summary');
  lines.push(`**Verdict:** ${verdict} (${findings.length} findings)`);
  lines.push('');
  lines.push('| Severity | Count |');
  lines.push('|----------|-------|');
  lines.push(`| CRITICAL | ${counts.CRITICAL} |`);
  lines.push(`| HIGH     | ${counts.HIGH} |`);
  lines.push(`| MEDIUM   | ${counts.MEDIUM} |`);
  lines.push(`| LOW      | ${counts.LOW} |`);
  lines.push(`| INFO     | ${counts.INFO} |`);
  lines.push('');

  if (!opts.uploaded) {
    lines.push('> Results not uploaded to CodeFence (fork PR, no API key).');
    lines.push('> Maintainer can trigger a trusted rerun or workflow_run relay.');
  }

  lines.push('');
  lines.push('<details><summary>Top findings</summary>');

  for (const finding of sorted.slice(0, 20)) {
    lines.push(`- [${finding.severity}] ${finding.title} (${finding.filePath}:${finding.startLine})`);
  }

  lines.push('</details>');
  lines.push('');
  return `${lines.join('\n')}\n`;
}

export function writeForkSummary(
  findings: NormalizedFinding[],
  options?: { uploaded?: boolean; summaryPath?: string },
): Verdict {
  const verdict = severityToVerdict(findings);
  const summaryPath = options?.summaryPath || process.env.GITHUB_STEP_SUMMARY;
  const markdown = buildForkSummaryMarkdown(findings, verdict, {
    uploaded: Boolean(options?.uploaded),
  });

  if (summaryPath) {
    fs.appendFileSync(summaryPath, markdown, 'utf8');
  } else {
    process.stdout.write(markdown);
  }

  if (process.env.GITHUB_OUTPUT) {
    fs.appendFileSync(process.env.GITHUB_OUTPUT, `fork-verdict=${verdict}\n`, 'utf8');
  }

  return verdict;
}

function runCli(): void {
  const args = parseKeyValueArgs(process.argv.slice(2));
  const inputPath = args.input;
  if (!inputPath) {
    throw new Error('Usage: fork-summary.ts --input=<normalized-findings.json> [--uploaded=true|false]');
  }

  const findings = JSON.parse(fs.readFileSync(inputPath, 'utf8')) as NormalizedFinding[];
  const uploaded = (args.uploaded || 'false').toLowerCase() === 'true';
  const verdict = writeForkSummary(findings, { uploaded, summaryPath: args.output || undefined });

  // Fork builds should not fail by default. Caller may override explicitly.
  if ((args['exit-on-fail'] || 'false').toLowerCase() === 'true' && verdict === 'FAIL') {
    process.exit(1);
  }
}

if (require.main === module) {
  runCli();
}
