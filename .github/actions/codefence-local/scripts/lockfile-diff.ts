import * as fs from 'fs';
import * as path from 'path';

export interface DependencyVersionMap {
  [name: string]: string;
}

export interface LockfileDiffResult {
  added: DependencyVersionMap;
  removed: DependencyVersionMap;
  updated: Record<string, { from: string; to: string }>;
}

function parseJsonFile(filePath: string): any {
  return JSON.parse(fs.readFileSync(filePath, 'utf8'));
}

function parsePackageLock(filePath: string): DependencyVersionMap {
  const parsed = parseJsonFile(filePath);
  const result: DependencyVersionMap = {};

  if (parsed.packages && typeof parsed.packages === 'object') {
    for (const [name, meta] of Object.entries(parsed.packages as Record<string, any>)) {
      if (!name || name === '') {
        continue;
      }
      const pkgName = name.startsWith('node_modules/') ? name.slice('node_modules/'.length) : name;
      if (meta && typeof meta.version === 'string') {
        result[pkgName] = meta.version;
      }
    }
    return result;
  }

  if (parsed.dependencies && typeof parsed.dependencies === 'object') {
    for (const [depName, depMeta] of Object.entries(parsed.dependencies as Record<string, any>)) {
      if (depMeta && typeof depMeta.version === 'string') {
        result[depName] = depMeta.version;
      }
    }
  }

  return result;
}

function parseSimpleKeyValueLock(filePath: string): DependencyVersionMap {
  const lines = fs.readFileSync(filePath, 'utf8').split(/\r?\n/);
  const result: DependencyVersionMap = {};

  for (const line of lines) {
    const trimmed = line.trim();
    if (!trimmed || trimmed.startsWith('#')) {
      continue;
    }

    if (trimmed.includes('==')) {
      const [name, version] = trimmed.split('==', 2);
      if (name && version) {
        result[name.trim()] = version.trim();
      }
      continue;
    }

    if (trimmed.includes('@') && trimmed.includes(':')) {
      // crude yarn.lock parser path
      const [namePart] = trimmed.split(':', 1);
      const cleanName = namePart.replace(/[@"']/g, '').split(',')[0];
      if (cleanName) {
        result[cleanName] = 'unknown';
      }
      continue;
    }

    const cargoMatch = trimmed.match(/^([A-Za-z0-9_.\-]+)\s+v?([0-9][A-Za-z0-9+_.\-]*)$/);
    if (cargoMatch) {
      result[cargoMatch[1]] = cargoMatch[2];
      continue;
    }
  }

  return result;
}

function parsePnpmLock(filePath: string): DependencyVersionMap {
  const lines = fs.readFileSync(filePath, 'utf8').split(/\r?\n/);
  const result: DependencyVersionMap = {};

  for (const line of lines) {
    const match = line.match(/^\s{2,}\/([^/]+)\/(.+):\s*$/);
    if (!match) {
      continue;
    }
    result[match[1]] = match[2];
  }

  return result;
}

function parsePipfileLock(filePath: string): DependencyVersionMap {
  const parsed = parseJsonFile(filePath);
  const result: DependencyVersionMap = {};
  for (const section of ['default', 'develop']) {
    const deps = parsed?.[section];
    if (!deps || typeof deps !== 'object') {
      continue;
    }
    for (const [name, meta] of Object.entries(deps as Record<string, any>)) {
      const version = typeof meta === 'string' ? meta : meta?.version;
      if (typeof version === 'string') {
        result[name] = version.replace(/^==/, '');
      }
    }
  }
  return result;
}

function parseGoSum(filePath: string): DependencyVersionMap {
  const lines = fs.readFileSync(filePath, 'utf8').split(/\r?\n/);
  const result: DependencyVersionMap = {};
  for (const line of lines) {
    const parts = line.trim().split(/\s+/);
    if (parts.length < 2) {
      continue;
    }
    const [name, version] = parts;
    if (name && version && !version.endsWith('/go.mod')) {
      result[name] = version;
    }
  }
  return result;
}

function parseLockfile(filePath: string): DependencyVersionMap {
  const fileName = path.basename(filePath);
  if (fileName === 'package-lock.json') return parsePackageLock(filePath);
  if (fileName === 'Pipfile.lock') return parsePipfileLock(filePath);
  if (fileName === 'pnpm-lock.yaml') return parsePnpmLock(filePath);
  if (fileName === 'go.sum') return parseGoSum(filePath);
  if (fileName === 'Cargo.lock') return parseSimpleKeyValueLock(filePath);
  if (fileName === 'yarn.lock') return parseSimpleKeyValueLock(filePath);

  // Fallback parser for requirements-like files.
  return parseSimpleKeyValueLock(filePath);
}

export function diffLockfiles(baseLockfilePath: string, headLockfilePath: string): LockfileDiffResult {
  const baseDeps = fs.existsSync(baseLockfilePath) ? parseLockfile(baseLockfilePath) : {};
  const headDeps = fs.existsSync(headLockfilePath) ? parseLockfile(headLockfilePath) : {};

  const added: DependencyVersionMap = {};
  const removed: DependencyVersionMap = {};
  const updated: Record<string, { from: string; to: string }> = {};

  for (const [name, version] of Object.entries(headDeps)) {
    if (!(name in baseDeps)) {
      added[name] = version;
      continue;
    }
    if (baseDeps[name] !== version) {
      updated[name] = { from: baseDeps[name], to: version };
    }
  }

  for (const [name, version] of Object.entries(baseDeps)) {
    if (!(name in headDeps)) {
      removed[name] = version;
    }
  }

  return { added, removed, updated };
}

function runCli(): void {
  const [basePath, headPath] = process.argv.slice(2);
  if (!basePath || !headPath) {
    throw new Error('Usage: lockfile-diff.ts <base-lockfile> <head-lockfile>');
  }

  const diff = diffLockfiles(basePath, headPath);
  process.stdout.write(`${JSON.stringify(diff, null, 2)}\n`);
}

if (require.main === module) {
  runCli();
}
