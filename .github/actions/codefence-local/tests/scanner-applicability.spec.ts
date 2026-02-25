import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import { spawnSync } from 'child_process';
import { BASH_AVAILABLE, BASH_STYLE, toBashPath } from './utils/bash-helpers';

function runWrapper(scriptName: string, workspace: string, resultsDir: string) {
  const scriptPath = toBashPath(path.resolve(__dirname, `../scripts/scanners/${scriptName}`));
  const bashWorkspace = toBashPath(workspace);
  const bashResults = toBashPath(resultsDir);

  return spawnSync(
    'bash',
    [scriptPath, '--workspace', bashWorkspace],
    {
      encoding: 'utf8',
      timeout: 60000,
      killSignal: 'SIGTERM',
      env: {
        ...process.env,
        GITHUB_WORKSPACE: bashWorkspace,
        CODEFENCE_RESULTS_DIR: bashResults,
        EGRESS_MODE: 'standard',
      },
    },
  );
}

describe('scanner wrapper applicability', () => {
  let workspace: string;
  let resultsDir: string;

  beforeEach(() => {
    workspace = fs.mkdtempSync(path.join(os.tmpdir(), 'codefence-empty-workspace-'));
    resultsDir = fs.mkdtempSync(path.join(os.tmpdir(), 'codefence-results-'));
  });

  afterEach(() => {
    fs.rmSync(workspace, { recursive: true, force: true });
    fs.rmSync(resultsDir, { recursive: true, force: true });
  });

  const runIfBash = BASH_AVAILABLE && BASH_STYLE !== 'wsl' ? it : it.skip;

  runIfBash('skips scanners that are not applicable for an empty workspace', () => {
    const scripts = [
      'run-bandit.sh',
      'run-pip-audit.sh',
      'run-actionlint.sh',
      'run-zizmor.sh',
      'run-checkov.sh',
      'run-osv-scanner.sh',
    ];

    for (const scriptName of scripts) {
      const result = runWrapper(scriptName, workspace, resultsDir);
      expect(result.status).toBe(0);
      expect(result.stdout).toContain('Skipping');
    }
  });
});
