import * as https from 'https';
import { parseKeyValueArgs } from './utils';

export interface GithubMetaRanges {
  actions: string[];
  git: string[];
  api: string[];
}

function fetchMeta(metaUrl: string): Promise<GithubMetaRanges> {
  return new Promise((resolve, reject) => {
    const req = https.get(
      metaUrl,
      {
        headers: {
          'Accept': 'application/json',
          'User-Agent': 'codefence-scan-action',
        },
      },
      (res) => {
        const chunks: Buffer[] = [];
        res.on('data', (chunk) => chunks.push(Buffer.from(chunk)));
        res.on('end', () => {
          if ((res.statusCode || 500) >= 400) {
            reject(new Error(`GitHub meta API failed (${res.statusCode}): ${Buffer.concat(chunks).toString('utf8')}`));
            return;
          }

          try {
            const parsed = JSON.parse(Buffer.concat(chunks).toString('utf8'));
            resolve({
              actions: Array.isArray(parsed.actions) ? parsed.actions : [],
              git: Array.isArray(parsed.git) ? parsed.git : [],
              api: Array.isArray(parsed.api) ? parsed.api : [],
            });
          } catch (error) {
            reject(error);
          }
        });
      },
    );

    req.on('error', reject);
    req.setTimeout(10000, () => {
      req.destroy(new Error('Timed out fetching GitHub meta API'));
    });
  });
}

function toNftAllowRules(meta: GithubMetaRanges): string {
  const lines: string[] = [];
  for (const key of ['api', 'git', 'actions'] as const) {
    for (const cidr of meta[key]) {
      if (cidr.includes(':')) {
        lines.push(`ip6 daddr ${cidr} tcp dport 443 accept`);
      } else {
        lines.push(`ip daddr ${cidr} tcp dport 443 accept`);
      }
    }
  }
  return lines.join('\n');
}

async function runCli(): Promise<void> {
  const args = parseKeyValueArgs(process.argv.slice(2));
  const meta = await fetchMeta(args.url || 'https://api.github.com/meta');

  if ((meta.actions || []).length === 0) {
    throw new Error('GitHub meta API returned empty actions CIDR list');
  }

  if ((args.format || 'json') === 'nft') {
    process.stdout.write(`${toNftAllowRules(meta)}\n`);
    return;
  }

  process.stdout.write(`${JSON.stringify(meta, null, 2)}\n`);
}

if (require.main === module) {
  runCli().catch((error) => {
    process.stderr.write(`${error instanceof Error ? error.message : String(error)}\n`);
    process.exit(1);
  });
}

export { fetchMeta as fetchGithubMetaRanges, toNftAllowRules };
