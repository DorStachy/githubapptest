import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';

const { detectWorkspaces } = require('../scripts/detect-workspaces.ts');

describe('detectWorkspaces', () => {
  it('discovers workspaces up to depth 3 and reports lockfile presence', () => {
    const root = fs.mkdtempSync(path.join(os.tmpdir(), 'workspaces-'));
    fs.mkdirSync(path.join(root, 'services', 'api'), { recursive: true });
    fs.writeFileSync(path.join(root, 'services', 'api', 'package.json'), '{}');
    fs.writeFileSync(path.join(root, 'services', 'api', 'package-lock.json'), '{}');

    fs.mkdirSync(path.join(root, 'ml', 'model'), { recursive: true });
    fs.writeFileSync(path.join(root, 'ml', 'model', 'pyproject.toml'), '[project]');

    const workspaces = detectWorkspaces(root);
    expect(workspaces).toEqual(
      expect.arrayContaining([
        { root: 'services/api', language: 'javascript', hasLockfile: true },
        { root: 'ml/model', language: 'python', hasLockfile: false },
      ]),
    );
  });
});
