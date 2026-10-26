import assert from 'node:assert/strict';
import { buildReverseRequest } from '../tools/reverse.js';
import test from 'node:test';

const scope = { wslWorkspace: '/home/ctfagent/ctf-workspaces/chal1' };
const artifactPath = '/home/ctfagent/ctf-workspaces/chal1/bin/challenge';

test('reverse requests preserve one scoped artifact and one fixed operation mode', () => {
  assert.deepEqual(buildReverseRequest({ mode: 'inspect', artifactPath }, scope), {
    mode: 'inspect',
    artifactPath,
    workspace: scope.wslWorkspace,
  });
  assert.deepEqual(buildReverseRequest({ mode: 'disassemble', artifactPath, symbol: 'main' }, scope), {
    mode: 'disassemble',
    artifactPath,
    workspace: scope.wslWorkspace,
    symbol: 'main',
  });
  assert.deepEqual(buildReverseRequest({ mode: 'gdb_info', artifactPath, symbol: '_start' }, scope), {
    mode: 'gdb_info',
    artifactPath,
    workspace: scope.wslWorkspace,
    symbol: '_start',
  });
});

test('reverse requests reject paths outside scope, invalid symbols, and unknown operations', () => {
  assert.throws(() => buildReverseRequest({ mode: 'inspect', artifactPath: '/home/ctfagent/.ssh/id_rsa' }, scope), /outside/i);
  assert.throws(() => buildReverseRequest({ mode: 'disassemble', artifactPath, symbol: 'main;quit' }, scope), /symbol/i);
  assert.throws(() => buildReverseRequest({ mode: 'shell', artifactPath }, scope), /mode/i);
});
