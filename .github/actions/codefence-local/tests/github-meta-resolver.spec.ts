const { toNftAllowRules } = require('../scripts/github-meta-resolver.ts');

describe('toNftAllowRules', () => {
  it('renders dual-stack nft allow lines from github meta ranges', () => {
    const output = toNftAllowRules({
      actions: ['140.82.112.0/20', '2a0a:a440::/29'],
      git: ['192.30.252.0/22'],
      api: ['143.55.64.0/20'],
    });

    expect(output).toContain('ip daddr 140.82.112.0/20 tcp dport 443 accept');
    expect(output).toContain('ip6 daddr 2a0a:a440::/29 tcp dport 443 accept');
    expect(output).toContain('ip daddr 192.30.252.0/22 tcp dport 443 accept');
  });
});
