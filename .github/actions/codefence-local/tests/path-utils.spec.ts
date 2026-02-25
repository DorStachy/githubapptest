import { stripWorkspacePrefix } from '../scripts/path-utils';

describe('stripWorkspacePrefix', () => {
  it('strips absolute path with repoRoot to produce relative path', () => {
    expect(
      stripWorkspacePrefix('/tmp/codefence-scan-IwLLZA/src/app.py', '/tmp/codefence-scan-IwLLZA'),
    ).toBe('src/app.py');
  });

  it('strips absolute path with trailing slash on repoRoot', () => {
    expect(
      stripWorkspacePrefix('/tmp/codefence-scan-IwLLZA/src/app.py', '/tmp/codefence-scan-IwLLZA/'),
    ).toBe('src/app.py');
  });

  it('strips file:// URI scheme before stripping prefix', () => {
    expect(
      stripWorkspacePrefix('file:///tmp/codefence-scan-IwLLZA/src/app.py', '/tmp/codefence-scan-IwLLZA'),
    ).toBe('src/app.py');
  });

  it('returns already-relative path unchanged', () => {
    expect(
      stripWorkspacePrefix('src/app.py', '/tmp/codefence-scan-IwLLZA'),
    ).toBe('src/app.py');
  });

  it('returns filePath unchanged when repoRoot is undefined', () => {
    expect(
      stripWorkspacePrefix('/tmp/codefence-scan-IwLLZA/src/app.py', undefined),
    ).toBe('/tmp/codefence-scan-IwLLZA/src/app.py');
  });

  it('returns filePath unchanged when repoRoot is empty string', () => {
    expect(
      stripWorkspacePrefix('/tmp/codefence-scan-IwLLZA/src/app.py', ''),
    ).toBe('/tmp/codefence-scan-IwLLZA/src/app.py');
  });

  it('does not produce ../ prefix when path is outside repoRoot', () => {
    const result = stripWorkspacePrefix('/other/dir/file.ts', '/tmp/codefence-scan-IwLLZA');
    expect(result).not.toMatch(/^\.\.\//);
    // Should return original filePath since it can't be made relative safely
    expect(result).toBe('/other/dir/file.ts');
  });

  it('handles empty filePath', () => {
    expect(stripWorkspacePrefix('', '/tmp/codefence-scan-IwLLZA')).toBe('');
  });

  it('handles nested paths correctly', () => {
    expect(
      stripWorkspacePrefix('/tmp/codefence-scan-abc123/deep/nested/src/file.ts', '/tmp/codefence-scan-abc123'),
    ).toBe('deep/nested/src/file.ts');
  });

  it('handles GitHub Actions runner paths', () => {
    expect(
      stripWorkspacePrefix(
        '/home/runner/work/repo/repo/src/handler.ts',
        '/home/runner/work/repo/repo',
      ),
    ).toBe('src/handler.ts');
  });

  it('returns filePath unchanged when file:// prefix leads to relative path', () => {
    expect(
      stripWorkspacePrefix('file://relative/path.ts', '/some/root'),
    ).toBe('relative/path.ts');
  });
});
