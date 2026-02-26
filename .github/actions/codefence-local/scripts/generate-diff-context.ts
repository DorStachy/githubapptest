/**
 * generate-diff-context.ts
 *
 * Generates DLP-safe diff context for each finding by extracting a small
 * window of code (±3 lines) around the finding location from the workspace.
 *
 * The generated context is intentionally minimal — just enough for a
 * developer to understand the finding without exposing the full source file.
 * Each window is hard-capped at 500 characters to guarantee data-loss
 * prevention (DLP) safety.
 *
 * This runs in the GitHub Action only (local-scanner path).
 * The bot-scanner path is NOT affected.
 */

import * as fs from 'fs';
import * as path from 'path';
import { execFileSync } from 'child_process';
import { NormalizedFinding } from './types';

/** Number of context lines above and below the finding range. */
const CONTEXT_LINES = 3;

/** Hard cap on diff-context size to guarantee DLP safety. */
const MAX_DIFF_CHARS = 500;

// ── Git-based diff context ────────────────────────────────────────────

/**
 * Attempt to extract a unified-diff hunk for a specific file using
 * `git diff baseSha..headSha -- filePath`.
 *
 * Returns null if git is unavailable, the file wasn't changed, or
 * the diff doesn't overlap with the finding's line range.
 */
function gitDiffForFile(
  workspaceRoot: string,
  filePath: string,
  baseSha: string | null | undefined,
  headSha: string | null | undefined,
  startLine: number,
  endLine: number,
): string | null {
  if (!baseSha || !headSha) return null;

  try {
    const diff = execFileSync(
      'git',
      [
        'diff',
        `--unified=${CONTEXT_LINES}`,
        `${baseSha}...${headSha}`,
        '--',
        filePath,
      ],
      {
        cwd: workspaceRoot,
        encoding: 'utf8',
        timeout: 5000,
        stdio: ['pipe', 'pipe', 'pipe'],
      },
    ).trim();

    if (!diff) return null;

    // Extract only the hunk(s) that overlap with the finding's line range.
    const hunks = extractOverlappingHunks(diff, startLine, endLine);
    return hunks || null;
  } catch {
    // git not available, shallow clone, or file not in diff — graceful fallback
    return null;
  }
}

/**
 * Parse unified-diff output and keep only hunks whose new-file line range
 * overlaps with [startLine, endLine].
 */
function extractOverlappingHunks(
  diff: string,
  startLine: number,
  endLine: number,
): string | null {
  const lines = diff.split('\n');
  const result: string[] = [];
  let inHunk = false;
  let hunkStart = 0;
  let hunkLength = 0;
  let currentHunkLines: string[] = [];

  for (const line of lines) {
    // Skip file headers
    if (line.startsWith('diff ') || line.startsWith('index ') ||
        line.startsWith('--- ') || line.startsWith('+++ ')) {
      continue;
    }

    const hunkMatch = line.match(/^@@ -\d+(?:,\d+)? \+(\d+)(?:,(\d+))? @@/);
    if (hunkMatch) {
      // Flush previous hunk if it overlaps
      if (inHunk && hunkOverlaps(hunkStart, hunkLength, startLine, endLine)) {
        result.push(...currentHunkLines);
      }

      hunkStart = parseInt(hunkMatch[1], 10);
      hunkLength = parseInt(hunkMatch[2] ?? '1', 10);
      currentHunkLines = [line];
      inHunk = true;
      continue;
    }

    if (inHunk) {
      currentHunkLines.push(line);
    }
  }

  // Flush last hunk
  if (inHunk && hunkOverlaps(hunkStart, hunkLength, startLine, endLine)) {
    result.push(...currentHunkLines);
  }

  return result.length > 0 ? result.join('\n') : null;
}

function hunkOverlaps(
  hunkStart: number,
  hunkLength: number,
  findingStart: number,
  findingEnd: number,
): boolean {
  const hunkEnd = hunkStart + hunkLength - 1;
  return hunkStart <= findingEnd && hunkEnd >= findingStart;
}

// ── File-based code window (fallback) ─────────────────────────────────

/**
 * Read the source file and extract a small window of lines around the
 * finding, formatted as a unified-diff-style context block.
 *
 * Uses space-prefixed lines (context) with a `@@` header for line numbers.
 */
function codeWindowForFinding(
  workspaceRoot: string,
  filePath: string,
  startLine: number,
  endLine: number,
): string | null {
  const absPath = path.resolve(workspaceRoot, filePath);
  if (!fs.existsSync(absPath)) return null;

  try {
    const stat = fs.statSync(absPath);
    // Skip binary / very large files
    if (stat.size > 512 * 1024) return null;

    const content = fs.readFileSync(absPath, 'utf8');
    const lines = content.split('\n');

    const windowStart = Math.max(0, startLine - 1 - CONTEXT_LINES);
    const windowEnd = Math.min(lines.length, endLine + CONTEXT_LINES);

    const window = lines.slice(windowStart, windowEnd);
    if (window.length === 0) return null;

    // Format as unified diff (all context lines — no additions/removals)
    const header = `@@ -${windowStart + 1},${window.length} +${windowStart + 1},${window.length} @@`;
    const contextLines = window.map((line) => ` ${line}`);

    return [header, ...contextLines].join('\n');
  } catch {
    return null;
  }
}

// ── Public API ────────────────────────────────────────────────────────

/**
 * Enrich each finding with a DLP-safe `diffContext` field.
 *
 * Strategy:
 *   1. Try `git diff baseSha..headSha` to get real unified-diff hunks
 *      that overlap the finding location (best UX — shows actual changes).
 *   2. Fall back to a ±3-line code window from the source file
 *      (still useful — shows the code context around the finding).
 *
 * Every generated context is hard-capped at {@link MAX_DIFF_CHARS} characters.
 */
export function generateDiffContext(
  findings: NormalizedFinding[],
  workspaceRoot: string,
  baseSha?: string | null,
  headSha?: string | null,
): NormalizedFinding[] {
  return findings.map((f) => {
    // Skip if diff context is already populated
    if (f.diffContext) return f;

    // Need valid file path and line range
    if (!f.filePath || !f.startLine) return f;

    const endLine = f.endLine || f.startLine;

    // Strategy 1: real git diff
    let diffContext = gitDiffForFile(
      workspaceRoot,
      f.filePath,
      baseSha,
      headSha,
      f.startLine,
      endLine,
    );

    // Strategy 2: code window fallback
    if (!diffContext) {
      diffContext = codeWindowForFinding(
        workspaceRoot,
        f.filePath,
        f.startLine,
        endLine,
      );
    }

    if (!diffContext) return f;

    // Enforce DLP-safe hard cap
    if (diffContext.length > MAX_DIFF_CHARS) {
      // Truncate at last complete line within limit
      const truncated = diffContext.slice(0, MAX_DIFF_CHARS);
      const lastNewline = truncated.lastIndexOf('\n');
      diffContext =
        lastNewline > 0
          ? `${truncated.slice(0, lastNewline)}\n…`
          : `${truncated}\n…`;
    }

    return { ...f, diffContext };
  });
}
