import * as fs from 'fs';
import * as path from 'path';

describe('egress-strict preflight script', () => {
  it('contains fail-closed checks and fatal messages', () => {
    const scriptPath = path.resolve(__dirname, '../scripts/egress-strict.sh');
    const content = fs.readFileSync(scriptPath, 'utf8');

    expect(content).toContain('Strict egress requires Linux');
    expect(content).toContain('Strict egress requires self-hosted runner');
    expect(content).toContain('nftables required for strict egress');
    expect(content).toContain('nft inet family not available');
    expect(content).toContain('CAP_NET_ADMIN required');
    expect(content).toContain('No valid DNS resolvers found for strict mode');
    expect(content).toContain('GitHub meta API returned empty actions CIDR list');
  });
});

