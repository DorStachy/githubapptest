import * as crypto from 'crypto';
import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import { spawnSync } from 'child_process';
import { BASH_AVAILABLE, BASH_STYLE, toBashPath } from './utils/bash-helpers';

describe('verify-binary.sh', () => {
  const scriptPath = toBashPath(path.resolve(__dirname, '../scripts/verify-binary.sh'));
  let tempDir: string;

  beforeEach(() => {
    tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'codefence-verify-'));
  });

  afterEach(() => {
    fs.rmSync(tempDir, { recursive: true, force: true });
  });

  const runIfBash = BASH_AVAILABLE && BASH_STYLE !== 'wsl' ? it : it.skip;

  runIfBash('fails when binary checksum does not match expected hash', () => {
    const binaryPath = path.join(tempDir, 'tool.bin');
    const checksumsPath = path.join(tempDir, 'checksums.sha256');
    fs.writeFileSync(binaryPath, 'tampered payload', 'utf8');
    fs.writeFileSync(checksumsPath, `0000badbad  tool.bin\n`, 'utf8');

    const result = spawnSync(
      'bash',
      [scriptPath, toBashPath(binaryPath), 'tool.bin', toBashPath(checksumsPath)],
      {
        encoding: 'utf8',
        timeout: 60000,
        killSignal: 'SIGTERM',
      },
    );

    expect(result.status).toBe(1);
    expect(result.stderr).toContain('Checksum mismatch');
  });

  runIfBash('passes when binary checksum matches expected hash', () => {
    const binaryPath = path.join(tempDir, 'tool.bin');
    const checksumsPath = path.join(tempDir, 'checksums.sha256');
    const payload = 'known payload';
    const hash = crypto.createHash('sha256').update(payload).digest('hex');
    fs.writeFileSync(binaryPath, payload, 'utf8');
    fs.writeFileSync(checksumsPath, `${hash}  tool.bin\n`, 'utf8');

    const result = spawnSync(
      'bash',
      [scriptPath, toBashPath(binaryPath), 'tool.bin', toBashPath(checksumsPath)],
      {
        encoding: 'utf8',
        timeout: 60000,
        killSignal: 'SIGTERM',
      },
    );

    expect(result.status).toBe(0);
    expect(result.stdout).toContain('Checksum OK');
  });
});
