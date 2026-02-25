import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import { spawnSync } from 'child_process';
import { BASH_AVAILABLE, BASH_STYLE, toBashPath } from './utils/bash-helpers';

describe('run_with_timeout fallback', () => {
  let tempRoot: string;
  let resultsDir: string;
  let workspace: string;
  let hookPath: string;
  let scannerName: string;
  let scannerScriptPath: string;

  beforeEach(() => {
    tempRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'codefence-timeout-fallback-'));
    resultsDir = path.join(tempRoot, 'results');
    workspace = path.join(tempRoot, 'workspace');
    hookPath = path.join(tempRoot, 'bash-env.sh');
    scannerName = `timeout-fallback-${process.pid}`;
    scannerScriptPath = path.resolve(
      __dirname,
      `../scripts/scanners/run-${scannerName}.sh`,
    );

    fs.mkdirSync(resultsDir, { recursive: true });
    fs.mkdirSync(workspace, { recursive: true });
    fs.writeFileSync(
      scannerScriptPath,
      '#!/usr/bin/env bash\nset -euo pipefail\nsleep 999\n',
      'utf8',
    );
    fs.chmodSync(scannerScriptPath, 0o755);
  });

  afterEach(() => {
    fs.rmSync(tempRoot, { recursive: true, force: true });
    fs.rmSync(scannerScriptPath, { force: true });
  });

  const runIfBash = BASH_AVAILABLE && BASH_STYLE !== 'wsl' ? it : it.skip;

  runIfBash('marks scanner as timeout when GNU timeout is unavailable', () => {
    fs.writeFileSync(
      hookPath,
      `
command() {
  if [[ "$1" == "-v" && "$2" == "timeout" ]]; then
    return 1
  fi
  builtin command "$@"
}
`,
      'utf8',
    );
    fs.chmodSync(hookPath, 0o755);

    const orchestratorPath = toBashPath(path.resolve(__dirname, '../scripts/run-scanners.sh'));
    const bashWorkspace = toBashPath(workspace);
    const bashResults = toBashPath(resultsDir);
    const bashHookPath = toBashPath(hookPath);

    const result = spawnSync('bash', [orchestratorPath], {
      encoding: 'utf8',
      timeout: 120000,
      killSignal: 'SIGTERM',
      env: {
        ...process.env,
        BASH_ENV: bashHookPath,
        GITHUB_WORKSPACE: bashWorkspace,
        CODEFENCE_RESULTS_DIR: bashResults,
        CODEFENCE_SCANNERS: scannerName,
        CODEFENCE_SCANNER_TIMEOUT_SECONDS: '1',
      },
    });

    expect(result.status).toBe(0);

    const statusPath = path.join(resultsDir, 'scanner-status.json');
    expect(fs.existsSync(statusPath)).toBe(true);

    const statusPayload = JSON.parse(fs.readFileSync(statusPath, 'utf8')) as Array<{
      scanner: string;
      status: string;
    }>;
    const scannerStatus = statusPayload.find((entry) => entry.scanner === scannerName);
    expect(scannerStatus).toBeDefined();
    expect(scannerStatus?.status).toBe('timeout');
  });
});
