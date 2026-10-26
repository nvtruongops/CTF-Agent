import assert from 'node:assert/strict';
import { mkdtempSync, rmSync, existsSync, readFileSync, mkdirSync, symlinkSync } from 'node:fs';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { assertHostAllowed, assertWorkspacePath, initScope, isTargetAllowed, loadScope, parseTarget } from '../scope.js';
import test from 'node:test';

test('parseTarget normalizes an exact DNS host and validates its port', () => {
  assert.deepEqual(parseTarget('Challenge.Example:1337'), {
    host: 'challenge.example',
    port: 1337,
  });
  assert.deepEqual(parseTarget('[2001:db8::1]:8443'), {
    host: '2001:db8::1',
    port: 8443,
  });
  assert.throws(() => parseTarget('*.example.com:443'), /wildcard/i);
  assert.throws(() => parseTarget('challenge.example'), /port/i);
  assert.throws(() => parseTarget('challenge.example:70000'), /port/i);
});

test('parseTarget rejects URL port zero', () => {
  assert.throws(() => parseTarget('http://challenge.example:0'), /port/i);
});

test('isTargetAllowed matches only the exact scoped host and effective port', () => {
  const scope = { targets: [{ host: 'challenge.example', port: 443 }] };
  assert.equal(isTargetAllowed('https://challenge.example/login', scope), true);
  assert.equal(isTargetAllowed('https://other.example/login', scope), false);
  assert.equal(isTargetAllowed('http://challenge.example/login', scope), false);
});

test('assertHostAllowed permits passive lookups only for an exact scoped host', () => {
  const scope = { targets: [{ host: 'challenge.example', port: 443 }] };
  assert.equal(assertHostAllowed('Challenge.Example', scope), 'challenge.example');
  assert.throws(() => assertHostAllowed('sub.challenge.example', scope), /outside/i);
});

test('assertWorkspacePath accepts only canonical WSL paths beneath the active workspace', () => {
  const scope = { wslWorkspace: '/home/ctfagent/ctf-workspaces/web-01' };
  assert.equal(
    assertWorkspacePath('/home/ctfagent/ctf-workspaces/web-01/files/list.txt', scope),
    '/home/ctfagent/ctf-workspaces/web-01/files/list.txt',
  );
  assert.throws(() => assertWorkspacePath('/home/ctfagent/private/key', scope), /workspace/i);
  assert.throws(() => assertWorkspacePath('/home/ctfagent/ctf-workspaces/web-01/../private/key', scope), /canonical/i);
});

test('initScope writes one local scope under the challenge workspace and refuses overwrite', () => {
  const projectRoot = mkdtempSync(join(tmpdir(), 'ctf-scope-'));
  try {
    mkdirSync(join(projectRoot, 'challenge-inputs'));
    const scope = initScope({
      projectRoot,
      challengeId: 'web-2026-01',
      workspace: '.ctf-workspaces/web-2026-01',
      sourceRoots: ['challenge-inputs'],
      targets: ['challenge.example:8080'],
    });

    assert.ok(scope);
    assert.equal(scope.challengeId, 'web-2026-01');
    assert.equal(scope.targets[0].host, 'challenge.example');
    assert.equal(scope.targets[0].port, 8080);
    assert.equal(existsSync(join(projectRoot, '.ctf-agent', 'scope.json')), true);
    assert.deepEqual(
      JSON.parse(readFileSync(join(projectRoot, '.ctf-agent', 'scope.json'), 'utf8')),
      scope,
    );
    assert.throws(() => initScope({
      projectRoot,
      challengeId: 'web-2026-01',
      workspace: '.ctf-workspaces/web-2026-01',
      targets: [],
    }), /already exists/i);
  } finally {
    rmSync(projectRoot, { recursive: true, force: true });
  }
});

test('loadScope returns the active scope and distinguishes a missing scope', () => {
  const projectRoot = mkdtempSync(join(tmpdir(), 'ctf-scope-'));
  try {
    assert.throws(() => loadScope(projectRoot), (error) => error.code === 'NO_ACTIVE_SCOPE');
    mkdirSync(join(projectRoot, 'inputs'));
    const expected = initScope({
      projectRoot,
      challengeId: 'scope-load',
      workspace: '.ctf-workspaces/scope-load',
      sourceRoots: ['inputs'],
      targets: ['challenge.example:80'],
    });
    assert.deepEqual(loadScope(projectRoot), expected);
  } finally {
    rmSync(projectRoot, { recursive: true, force: true });
  }
});

test('initScope rejects a workspace outside the ignored CTF workspace root', () => {
  const projectRoot = mkdtempSync(join(tmpdir(), 'ctf-scope-'));
  try {
    assert.throws(() => initScope({
      projectRoot,
      challengeId: 'escape',
      workspace: '..\\outside',
      targets: [],
    }), /workspace root/i);
  } finally {
    rmSync(projectRoot, { recursive: true, force: true });
  }
});

test('initScope validates target scope before creating local state', () => {
  const projectRoot = mkdtempSync(join(tmpdir(), 'ctf-scope-'));
  try {
    assert.throws(() => initScope({
      projectRoot,
      challengeId: 'invalid-target',
      workspace: '.ctf-workspaces/invalid-target',
      targets: ['*.example:80'],
    }), /wildcard/i);
    assert.equal(existsSync(join(projectRoot, '.ctf-workspaces')), false);
    assert.equal(existsSync(join(projectRoot, '.ctf-agent')), false);
  } finally {
    rmSync(projectRoot, { recursive: true, force: true });
  }
});

test('initScope rejects nested or redirected workspace roots', (t) => {
  const projectRoot = mkdtempSync(join(tmpdir(), 'ctf-scope-'));
  const outsideRoot = join(projectRoot, 'outside');
  try {
    mkdirSync(outsideRoot);
    assert.throws(() => initScope({
      projectRoot,
      challengeId: 'nested',
      workspace: '.ctf-workspaces/other/nested',
      targets: [],
    }), /workspace/i);

    try {
      symlinkSync(outsideRoot, join(projectRoot, '.ctf-workspaces'), 'junction');
    } catch {
      t.skip('directory junction creation is unavailable on this Windows host');
      return;
    }

    assert.throws(() => initScope({
      projectRoot,
      challengeId: 'redirected',
      workspace: '.ctf-workspaces/redirected',
      targets: [],
    }), /symlink|workspace/i);
  } finally {
    rmSync(projectRoot, { recursive: true, force: true });
  }
});
