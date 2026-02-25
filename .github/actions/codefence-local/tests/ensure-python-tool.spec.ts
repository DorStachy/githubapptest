import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import { spawnSync } from 'child_process';
import { BASH_AVAILABLE, BASH_STYLE, toBashPath } from './utils/bash-helpers';

describe('ensure_python_tool failure handling', () => {
  let tempRoot: string;
  let workspace: string;
  let resultsDir: string;
  let hookPath: string;

  beforeEach(() => {
    tempRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'codefence-ensure-python-'));
    workspace = path.join(tempRoot, 'workspace');
    resultsDir = path.join(tempRoot, 'results');
    hookPath = path.join(tempRoot, 'bash-env.sh');

    fs.mkdirSync(workspace, { recursive: true });
    fs.mkdirSync(resultsDir, { recursive: true });
    fs.writeFileSync(path.join(workspace, 'app.py'), 'print("hello")\n', 'utf8');
  });

  afterEach(() => {
    fs.rmSync(tempRoot, { recursive: true, force: true });
  });

  function runBanditWithHook(hookScript: string, egressMode: 'standard' | 'strict') {
    fs.writeFileSync(hookPath, hookScript, 'utf8');
    fs.chmodSync(hookPath, 0o755);

    const scriptPath = toBashPath(path.resolve(__dirname, '../scripts/scanners/run-bandit.sh'));
    const bashWorkspace = toBashPath(workspace);
    const bashResults = toBashPath(resultsDir);
    const bashHookPath = toBashPath(hookPath);

    return spawnSync(
      'bash',
      [scriptPath, '--workspace', bashWorkspace],
      {
        encoding: 'utf8',
        timeout: 60000,
        killSignal: 'SIGTERM',
        env: {
          ...process.env,
          BASH_ENV: bashHookPath,
          EGRESS_MODE: egressMode,
          INPUT_EGRESS_MODE: egressMode,
          GITHUB_WORKSPACE: bashWorkspace,
          CODEFENCE_RESULTS_DIR: bashResults,
        },
      },
    );
  }

  const runIfBash = BASH_AVAILABLE && BASH_STYLE !== 'wsl' ? it : it.skip;

  runIfBash('returns exit 0 and empty output when python3 is unavailable', () => {
    const hookScript = `
command() {
  if [[ "$1" == "-v" && "$2" == "python3" ]]; then
    return 1
  fi
  builtin command "$@"
}
`;

    const result = runBanditWithHook(hookScript, 'standard');
    expect(result.status).toBe(0);

    const outputPath = path.join(resultsDir, 'raw', 'bandit.json');
    expect(fs.existsSync(outputPath)).toBe(true);
    expect(JSON.parse(fs.readFileSync(outputPath, 'utf8'))).toEqual([]);
  });

  runIfBash('returns exit 0 and empty output when pip install fails', () => {
    const hookScript = `
command() {
  if [[ "$1" == "-v" && "$2" == "python3" ]]; then
    return 0
  fi
  builtin command "$@"
}

python3() {
  echo "ERROR: Could not install bandit" >&2
  return 1
}
`;

    const result = runBanditWithHook(hookScript, 'standard');
    expect(result.status).toBe(0);

    const outputPath = path.join(resultsDir, 'raw', 'bandit.json');
    expect(fs.existsSync(outputPath)).toBe(true);
    expect(JSON.parse(fs.readFileSync(outputPath, 'utf8'))).toEqual([]);
  });
});
