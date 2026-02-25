import { spawnSync } from 'child_process';

export type BashStyle = 'native' | 'wsl' | 'git-bash' | 'none';

export const BASH_AVAILABLE = (() => {
  const probe = spawnSync('bash', ['-lc', 'echo codefence-test'], {
    encoding: 'utf8',
    timeout: 5000,
    killSignal: 'SIGTERM',
  });
  return probe.status === 0;
})();

export const BASH_STYLE: BashStyle = (() => {
  if (!BASH_AVAILABLE) {
    return 'none';
  }
  if (process.env.WSL_DISTRO_NAME || process.env.WSL_INTEROP || process.env.IS_WSL) {
    return 'wsl';
  }

  const probe = spawnSync('bash', ['-lc', 'printf "%s|%s" "${OSTYPE:-}" "$(pwd)"'], {
    encoding: 'utf8',
    timeout: 5000,
    killSignal: 'SIGTERM',
  });

  const [ostype, cwd] = String(probe.stdout || '').split('|');
  const normalizedOsType = (ostype || '').toLowerCase();

  if (normalizedOsType.includes('msys') || normalizedOsType.includes('cygwin')) {
    return 'git-bash';
  }
  if (process.platform === 'linux') {
    return 'native';
  }
  if ((cwd || '').startsWith('/mnt/')) {
    return 'wsl';
  }
  if (process.platform === 'win32') {
    return 'git-bash';
  }

  return 'native';
})();

export function toBashPath(value: string): string {
  const normalized = value.replace(/\\/g, '/');
  const match = normalized.match(/^([A-Za-z]):\/(.*)$/);
  if (!match) {
    return normalized;
  }

  const drive = match[1].toLowerCase();
  const rest = match[2];
  if (BASH_STYLE === 'git-bash') {
    return `/${drive}/${rest}`;
  }
  if (BASH_STYLE === 'wsl') {
    return `/mnt/${drive}/${rest}`;
  }

  return normalized;
}
