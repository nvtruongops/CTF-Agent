import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { mkdtempSync, mkdirSync, readFileSync, rmSync } from 'node:fs';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { fileURLToPath } from 'node:url';
import test from 'node:test';

const cliPath = fileURLToPath(new URL('../cli.js', import.meta.url));

test('scope init CLI writes the declared challenge and target scope', () => {
  const projectRoot = mkdtempSync(join(tmpdir(), 'ctf-scope-cli-'));
  try {
    mkdirSync(join(projectRoot, 'inputs'));
    const result = spawnSync(process.execPath, [
      cliPath,
      'scope', 'init',
      '--challenge', 'web-01',
      '--workspace', '.ctf-workspaces/web-01',
      '--source-root', 'inputs',
      '--target', 'challenge.example:8080',
    ], { cwd: projectRoot, encoding: 'utf8' });

    assert.equal(result.status, 0, result.stderr);
    const scope = JSON.parse(readFileSync(join(projectRoot, '.ctf-agent', 'scope.json'), 'utf8'));
    assert.equal(scope.challengeId, 'web-01');
    assert.deepEqual(scope.targets, [{ host: 'challenge.example', port: 8080 }]);
  } finally {
    rmSync(projectRoot, { recursive: true, force: true });
  }
});

test('scope init CLI rejects wildcard targets without creating scope state', () => {
  const projectRoot = mkdtempSync(join(tmpdir(), 'ctf-scope-cli-'));
  try {
    const result = spawnSync(process.execPath, [
      cliPath,
      'scope', 'init',
      '--challenge', 'web-02',
      '--workspace', '.ctf-workspaces/web-02',
      '--target', '*.example:80',
    ], { cwd: projectRoot, encoding: 'utf8' });

    assert.equal(result.status, 2);
    assert.match(result.stderr, /wildcard/i);
  } finally {
    rmSync(projectRoot, { recursive: true, force: true });
  }
});
