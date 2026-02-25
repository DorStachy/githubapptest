import * as fs from 'fs';
import * as path from 'path';
import { WorkspaceDescriptor } from './types';
import { parseKeyValueArgs, relativeToWorkspace, writeJsonFile } from './utils';

const MAX_DEPTH = 3;
const SKIP_DIRS = new Set(['.git', 'node_modules', 'dist', 'coverage']);

const LANGUAGE_MARKERS: Array<{
  marker: string;
  language: WorkspaceDescriptor['language'];
  lockfiles: string[];
}> = [
  {
    marker: 'package.json',
    language: 'javascript',
    lockfiles: ['package-lock.json', 'yarn.lock', 'pnpm-lock.yaml'],
  },
  {
    marker: 'pyproject.toml',
    language: 'python',
    lockfiles: ['poetry.lock', 'Pipfile.lock', 'requirements.txt'],
  },
  {
    marker: 'setup.py',
    language: 'python',
    lockfiles: ['Pipfile.lock', 'requirements.txt'],
  },
  {
    marker: 'Cargo.toml',
    language: 'rust',
    lockfiles: ['Cargo.lock'],
  },
  {
    marker: 'go.mod',
    language: 'go',
    lockfiles: ['go.sum'],
  },
];

interface DiscoveredWorkspace {
  absoluteRoot: string;
  descriptor: WorkspaceDescriptor;
}

function detectDescriptorFromDir(directory: string, workspaceRoot: string): WorkspaceDescriptor[] {
  const entries = new Set(fs.readdirSync(directory));
  const descriptors: WorkspaceDescriptor[] = [];

  for (const marker of LANGUAGE_MARKERS) {
    if (!entries.has(marker.marker)) {
      continue;
    }

    const hasLockfile = marker.lockfiles.some((lockfile) => entries.has(lockfile));
    descriptors.push({
      root: relativeToWorkspace(workspaceRoot, directory),
      language: marker.language,
      hasLockfile,
    });
  }

  return descriptors;
}

function crawl(currentDir: string, workspaceRoot: string, depth: number, found: DiscoveredWorkspace[]): void {
  if (depth > MAX_DEPTH) {
    return;
  }

  const stat = fs.statSync(currentDir);
  if (!stat.isDirectory()) {
    return;
  }

  const descriptors = detectDescriptorFromDir(currentDir, workspaceRoot);
  for (const descriptor of descriptors) {
    found.push({
      absoluteRoot: currentDir,
      descriptor,
    });
  }

  const entries = fs.readdirSync(currentDir, { withFileTypes: true });
  for (const entry of entries) {
    if (!entry.isDirectory() || SKIP_DIRS.has(entry.name)) {
      continue;
    }
    crawl(path.join(currentDir, entry.name), workspaceRoot, depth + 1, found);
  }
}

export function detectWorkspaces(workspaceRoot: string): WorkspaceDescriptor[] {
  const discovered: DiscoveredWorkspace[] = [];
  crawl(workspaceRoot, workspaceRoot, 0, discovered);

  const deduped = new Map<string, WorkspaceDescriptor>();
  for (const item of discovered) {
    const key = `${item.descriptor.root}:${item.descriptor.language}`;
    if (!deduped.has(key)) {
      deduped.set(key, item.descriptor);
    }
  }

  return Array.from(deduped.values()).sort((a, b) =>
    `${a.root}:${a.language}`.localeCompare(`${b.root}:${b.language}`),
  );
}

function runCli(): void {
  const args = parseKeyValueArgs(process.argv.slice(2));
  const root = path.resolve(args.root || process.cwd());
  const output = args.output;
  const workspaces = detectWorkspaces(root);

  if (output) {
    writeJsonFile(output, workspaces);
    return;
  }

  process.stdout.write(`${JSON.stringify(workspaces, null, 2)}\n`);
}

if (require.main === module) {
  runCli();
}
