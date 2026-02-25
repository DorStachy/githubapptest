import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import { spawnSync } from 'child_process';
import { BASH_AVAILABLE, BASH_STYLE, toBashPath } from './utils/bash-helpers';

describe('scanner execution positive path', () => {
  let tempRoot: string;
  let workspace: string;
  let resultsDir: string;
  let mockBinDir: string;

  beforeEach(() => {
    tempRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'codefence-semgrep-positive-'));
    workspace = path.join(tempRoot, 'workspace');
    resultsDir = path.join(tempRoot, 'results');
    mockBinDir = path.join(tempRoot, 'bin');

    fs.mkdirSync(workspace, { recursive: true });
    fs.mkdirSync(resultsDir, { recursive: true });
    fs.mkdirSync(mockBinDir, { recursive: true });

    fs.writeFileSync(
      path.join(workspace, 'vuln.py'),
      `
import sqlite3

def get_user(name, args):
    cursor = sqlite3.connect("db.sqlite").cursor()
    query = "SELECT * FROM users WHERE name='%s'"
    cursor.execute(query % args)
`,
      'utf8',
    );

    const mockSemgrep = `#!/usr/bin/env bash
set -euo pipefail

if [[ "\${1:-}" == "--version" ]]; then
  echo "1.67.0"
  exit 0
fi

out=""
for arg in "$@"; do
  case "$arg" in
    --output=*)
      out="\${arg#--output=}"
      ;;
  esac
done

if [[ -z "$out" ]]; then
  echo "missing --output argument" >&2
  exit 2
fi

cat > "$out" <<'SARIF'
{
  "version": "2.1.0",
  "runs": [
    {
      "tool": {
        "driver": {
          "name": "semgrep",
          "rules": [
            {
              "id": "codefence.python.sql-injection.formatting",
              "shortDescription": { "text": "Potential SQL injection" }
            }
          ]
        }
      },
      "results": [
        {
          "ruleId": "codefence.python.sql-injection.formatting",
          "level": "error",
          "message": { "text": "Potential SQL injection via dynamic SQL string construction." },
          "locations": [
            {
              "physicalLocation": {
                "artifactLocation": { "uri": "vuln.py" },
                "region": { "startLine": 7, "endLine": 7 }
              }
            }
          ]
        }
      ]
    }
  ]
}
SARIF

exit 1
`;

    const semgrepPath = path.join(mockBinDir, 'semgrep');
    fs.writeFileSync(semgrepPath, mockSemgrep, 'utf8');
    fs.chmodSync(semgrepPath, 0o755);
  });

  afterEach(() => {
    fs.rmSync(tempRoot, { recursive: true, force: true });
  });

  const runIfBash = BASH_AVAILABLE && BASH_STYLE !== 'wsl' ? it : it.skip;

  runIfBash('detects SQL injection finding through semgrep wrapper', () => {
    const scriptPath = toBashPath(path.resolve(__dirname, '../scripts/scanners/run-semgrep.sh'));
    const bashWorkspace = toBashPath(workspace);
    const bashResults = toBashPath(resultsDir);
    const bashMockBin = toBashPath(mockBinDir);

    const result = spawnSync(
      'bash',
      [scriptPath, '--workspace', bashWorkspace],
      {
        encoding: 'utf8',
        timeout: 60000,
        killSignal: 'SIGTERM',
        env: {
          ...process.env,
          EGRESS_MODE: 'strict',
          INPUT_EGRESS_MODE: 'strict',
          GITHUB_WORKSPACE: bashWorkspace,
          CODEFENCE_RESULTS_DIR: bashResults,
          PATH: `${bashMockBin}:${process.env.PATH || ''}`,
        },
      },
    );

    expect(result.status).toBe(0);

    const outputPath = path.join(resultsDir, 'raw', 'semgrep.sarif');
    expect(fs.existsSync(outputPath)).toBe(true);

    const payload = JSON.parse(fs.readFileSync(outputPath, 'utf8')) as {
      runs?: Array<{ results?: Array<{ ruleId?: string; level?: string }> }>;
    };
    const findings = payload.runs?.[0]?.results || [];
    expect(findings.length).toBeGreaterThan(0);
    expect(findings[0].ruleId || '').toContain('sql-injection');
    expect(findings[0].level).toBe('error');
  });
});
