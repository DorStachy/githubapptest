import * as fs from 'fs';
import * as path from 'path';
import { spawnSync } from 'child_process';
import * as yaml from 'js-yaml';

const CONFIG_PATH = path.resolve(__dirname, '../configs/semgrep-rules.yml');

function hasRulePattern(rule: Record<string, unknown>): boolean {
  return Boolean(
    rule.pattern ||
      rule.patterns ||
      rule['pattern-either'] ||
      rule['pattern-regex'] ||
      rule['pattern-inside'],
  );
}

describe('semgrep-rules.yml', () => {
  it('contains structurally valid semgrep rules', () => {
    const raw = fs.readFileSync(CONFIG_PATH, 'utf8');
    const parsed = yaml.load(raw) as { rules?: Array<Record<string, unknown>> };

    expect(parsed).toBeDefined();
    expect(Array.isArray(parsed.rules)).toBe(true);
    expect((parsed.rules || []).length).toBeGreaterThan(0);

    for (const rule of parsed.rules || []) {
      expect(typeof rule.id).toBe('string');
      expect((rule.id as string).length).toBeGreaterThan(0);
      expect(typeof rule.message).toBe('string');
      expect((rule.message as string).length).toBeGreaterThan(0);
      expect(Array.isArray(rule.languages)).toBe(true);
      expect((rule.languages as unknown[]).length).toBeGreaterThan(0);
      expect(hasRulePattern(rule)).toBe(true);
    }
  });

  const semgrepAvailable = (() => {
    const probe = spawnSync('semgrep', ['--version'], { encoding: 'utf8' });
    return probe.status === 0;
  })();
  const runIfSemgrep = semgrepAvailable ? it : it.skip;

  runIfSemgrep('passes semgrep --validate for config syntax', () => {
    const result = spawnSync('semgrep', ['--validate', '--config', CONFIG_PATH], {
      encoding: 'utf8',
    });

    expect(result.status).toBe(0);
  });
});
