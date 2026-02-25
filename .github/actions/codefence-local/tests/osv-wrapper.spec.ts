import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import { spawnSync } from 'child_process';
import { BASH_AVAILABLE, BASH_STYLE, toBashPath } from './utils/bash-helpers';

describe('run-osv-scanner.sh', () => {
  let tempRoot: string;
  let workspace: string;
  let resultsDir: string;
  let mockBinDir: string;
  let mockDbDir: string;

  beforeEach(() => {
    tempRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'codefence-osv-wrapper-'));
    workspace = path.join(tempRoot, 'workspace');
    resultsDir = path.join(tempRoot, 'results');
    mockBinDir = path.join(tempRoot, 'bin');
    mockDbDir = path.join(tempRoot, 'osv-db');

    fs.mkdirSync(workspace, { recursive: true });
    fs.mkdirSync(resultsDir, { recursive: true });
    fs.mkdirSync(mockBinDir, { recursive: true });
    fs.mkdirSync(mockDbDir, { recursive: true });

    fs.writeFileSync(path.join(workspace, 'package-lock.json'), '{"name":"demo","lockfileVersion":3}', 'utf8');

    const mockOsvScanner = `#!/usr/bin/env bash
set -euo pipefail

if [[ "\${1:-}" == "--help" ]]; then
  echo "scan"
  exit 0
fi

if [[ "\${1:-}" == "scan" && "\${2:-}" == "--help" ]]; then
  echo "--experimental-all-packages"
  exit 0
fi

if [[ "\${1:-}" == "scan" ]]; then
  out=""
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --output)
        out="$2"
        shift 2
        ;;
      *)
        shift
        ;;
    esac
  done
  printf '{"results":[{"packages":[{"package":{"name":"demo"},"vulnerabilities":[{"id":"CVE-2024-0001"}]}]}]}\\n' > "$out"
  exit 1
fi

printf '{"results":[]}\n'
exit 0
`;

    const mockPath = path.join(mockBinDir, 'osv-scanner');
    fs.writeFileSync(mockPath, mockOsvScanner, 'utf8');
    fs.chmodSync(mockPath, 0o755);
  });

  afterEach(() => {
    fs.rmSync(tempRoot, { recursive: true, force: true });
  });

  const runIfBash = BASH_AVAILABLE && BASH_STYLE !== 'wsl' ? it : it.skip;

  runIfBash('treats exit code 1 as findings and preserves output JSON', () => {
    const wrapperScript = toBashPath(
      path.resolve(__dirname, '../scripts/scanners/run-osv-scanner.sh'),
    );
    const bashWorkspace = toBashPath(workspace);
    const bashResultsDir = toBashPath(resultsDir);
    const bashMockBinDir = toBashPath(mockBinDir);
    const bashMockDbDir = toBashPath(mockDbDir);

    const result = spawnSync(
      'bash',
      [wrapperScript, '--workspace', bashWorkspace],
      {
        encoding: 'utf8',
        timeout: 60000,
        killSignal: 'SIGTERM',
        env: {
          ...process.env,
          EGRESS_MODE: 'strict',
          GITHUB_WORKSPACE: bashWorkspace,
          CODEFENCE_RESULTS_DIR: bashResultsDir,
          CODEFENCE_OSV_DB_PATH: bashMockDbDir,
          PATH: `${bashMockBinDir}:${process.env.PATH || ''}`,
        },
      },
    );

    expect(result.status).toBe(0);

    const outputPath = path.join(resultsDir, 'raw', 'osv-scanner.json');
    expect(fs.existsSync(outputPath)).toBe(true);

    const output = fs.readFileSync(outputPath, 'utf8');
    expect(output).toContain('CVE-2024-0001');
  });
});
