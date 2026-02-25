import * as path from 'path';

/**
 * Strips a workspace root prefix from an absolute file path, returning a
 * repo-relative path. Handles:
 * - null/undefined repoRoot → no-op
 * - Already-relative paths → no-op
 * - file:// URI scheme → strip scheme first, then strip prefix
 * - /tmp/codefence-scan-XXXXXX/... → strip prefix
 * - /home/runner/work/repo/repo/... → strip prefix (GitHub Actions)
 *
 * Always normalizes forward slashes, never returns a path starting with `../`
 * (clamps to the filePath itself if relative escapes root).
 */
export function stripWorkspacePrefix(filePath: string, repoRoot?: string): string {
  if (!repoRoot || !filePath) return filePath;

  let cleaned = filePath;

  // Strip file:// URI scheme
  if (cleaned.startsWith('file://')) {
    cleaned = cleaned.slice('file://'.length);
  }

  // If the path is not absolute, it's already relative — no-op
  if (!path.isAbsolute(cleaned)) return cleaned;

  // Normalize both paths to use forward slashes for consistent comparison
  const normalizedCleaned = cleaned.replace(/\\/g, '/');
  const normalizedRoot = repoRoot.replace(/\\/g, '/').replace(/\/+$/, '') + '/';

  if (normalizedCleaned.startsWith(normalizedRoot)) {
    const result = normalizedCleaned.slice(normalizedRoot.length);
    return result || filePath;
  }

  // Use path.relative as fallback
  const relative = path.relative(repoRoot, cleaned).replace(/\\/g, '/');

  // If relative escapes root (starts with ..), clamp to the original filePath
  if (relative.startsWith('..')) {
    return filePath;
  }

  return relative || filePath;
}
