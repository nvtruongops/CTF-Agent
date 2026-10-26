import assert from 'node:assert/strict';
import { buildGameFridaSpawnRequest } from '../tools/game.js';
import test from 'node:test';

const scope = { wslWorkspace: '/home/ctfagent/ctf-workspaces/chal1' };
const artifactPath = `${scope.wslWorkspace}/bin/game`;

test('Frida spawn is bounded and accepts only a workspace executable', () => {
  assert.deepEqual(buildGameFridaSpawnRequest({
    artifactPath,
    argv: ['--level', '1'],
    script: 'send(Process.id);',
    timeoutMs: 5000,
  }, scope), {
    mode: 'spawn',
    artifactPath,
    argv: ['--level', '1'],
    script: 'send(Process.id);',
    timeoutMs: 5000,
    workspace: scope.wslWorkspace,
  });
  assert.throws(() => buildGameFridaSpawnRequest({
    artifactPath: '/home/ctfagent/.ssh/id_rsa',
    script: 'send(1);',
  }, scope), /outside/i);
  assert.throws(() => buildGameFridaSpawnRequest({
    artifactPath,
    argv: Array.from({ length: 33 }, () => 'x'),
    script: 'send(1);',
  }, scope), /32/i);
  assert.throws(() => buildGameFridaSpawnRequest({
    artifactPath,
    argv: ['bad\0arg'],
    script: 'send(1);',
  }, scope), /NUL/i);
  assert.throws(() => buildGameFridaSpawnRequest({
    artifactPath,
    script: 'é'.repeat(32_769),
  }, scope), /65536-byte/i);
  assert.throws(() => buildGameFridaSpawnRequest({
    artifactPath,
    script: 'send(1);',
    timeoutMs: 120_001,
  }, scope), /120000/i);
});
