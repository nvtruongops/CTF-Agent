import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { mkdtempSync, mkdirSync, readFileSync, rmSync, symlinkSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { importWorkspaceFile } from '../tools/workspace.js';
import { runWsl } from '../wsl.js';
import test from 'node:test';

function makeScope(sourceRoot) {
  return {
    challengeId: 'web-2026-01',
    sourceRoots: [sourceRoot],
    wslWorkspace: '/home/ctfagent/ctf-workspaces/web-2026-01',
  };
}

test('workspace import streams a bounded copy and verifies its digest', async () => {
  const temp = mkdtempSync(join(tmpdir(), 'ctf-import-'));
  try {
    const sourceRoot = join(temp, 'inputs');
    mkdirSync(sourceRoot);
    const sourcePath = join(sourceRoot, 'challenge.bin');
    const bytes = Buffer.from([0, 1, 2, 127, 255]);
    writeFileSync(sourcePath, bytes);
    const expectedHash = createHash('sha256').update(bytes).digest('hex');
    let observedArgs;
    let observedInput;

    const result = await importWorkspaceFile({
      sourcePath,
      scope: makeScope(sourceRoot),
      maxImportBytes: 128,
      runWsl: async (args, options) => {
        observedArgs = args;
        observedInput = options.input;
        return {
          exitCode: 0,
          stdout: JSON.stringify({ sha256: expectedHash, bytes: bytes.length }),
          stderr: '',
          timedOut: false,
          truncated: false,
        };
      },
    });

    assert.ok(result);
    assert.equal(result.sha256, expectedHash);
    assert.equal(result.bytes, bytes.length);
    assert.deepEqual(observedInput, bytes);
    assert.equal(observedArgs[0], '--distribution');
    assert.equal(observedArgs[1], 'kali-linux');
    assert.equal(observedArgs[3], 'ctfagent');
    assert.equal(observedArgs.at(-4), 'write');
    assert.equal(observedArgs.at(-3), '/home/ctfagent/ctf-workspaces/web-2026-01');
    assert.equal(observedArgs.at(-2), '/home/ctfagent/ctf-workspaces/web-2026-01/challenge.bin');
    assert.equal(observedArgs.at(-1), '128');
    assert.deepEqual(readFileSync(sourcePath), bytes);
  } finally {
    rmSync(temp, { recursive: true, force: true });
  }
});

test('workspace import rejects files outside the declared source roots before WSL', async () => {
  const temp = mkdtempSync(join(tmpdir(), 'ctf-import-'));
  try {
    const sourceRoot = join(temp, 'allowed');
    const outsideRoot = join(temp, 'outside');
    mkdirSync(sourceRoot);
    mkdirSync(outsideRoot);
    const outsideFile = join(outsideRoot, 'secret.bin');
    writeFileSync(outsideFile, 'not in scope');
    let invoked = false;

    await assert.rejects(
      importWorkspaceFile({
        sourcePath: outsideFile,
        scope: makeScope(sourceRoot),
        runWsl: async () => { invoked = true; throw new Error('must not run'); },
      }),
      /source root/i,
    );
    assert.equal(invoked, false);
  } finally {
    rmSync(temp, { recursive: true, force: true });
  }
});

test('workspace import rejects oversized files and mismatched WSL digests', async () => {
  const temp = mkdtempSync(join(tmpdir(), 'ctf-import-'));
  try {
    const sourceRoot = join(temp, 'inputs');
    mkdirSync(sourceRoot);
    const sourcePath = join(sourceRoot, 'large.bin');
    writeFileSync(sourcePath, Buffer.alloc(16, 7));
    await assert.rejects(
      importWorkspaceFile({
        sourcePath,
        scope: makeScope(sourceRoot),
        maxImportBytes: 8,
        runWsl: async () => { throw new Error('oversized file must not be transferred'); },
      }),
      /size limit/i,
    );

    const smallPath = join(sourceRoot, 'small.bin');
    writeFileSync(smallPath, 'data');
    await assert.rejects(
      importWorkspaceFile({
        sourcePath: smallPath,
        scope: makeScope(sourceRoot),
        runWsl: async () => ({
          exitCode: 0,
          stdout: JSON.stringify({ sha256: '0'.repeat(64), bytes: 4 }),
          stderr: '',
          timedOut: false,
          truncated: false,
        }),
      }),
      /Workspace import digest mismatch/i,
    );
  } finally {
    rmSync(temp, { recursive: true, force: true });
  }
});

test('workspace import rejects symbolic-link sources before WSL', async (t) => {
  const temp = mkdtempSync(join(tmpdir(), 'ctf-import-'));
  try {
    const sourceRoot = join(temp, 'inputs');
    mkdirSync(sourceRoot);
    const actual = join(sourceRoot, 'actual.bin');
    const link = join(sourceRoot, 'linked.bin');
    writeFileSync(actual, 'challenge data');
    try {
      symlinkSync(actual, link, 'file');
    } catch {
      t.skip('file symlink creation is unavailable on this Windows host');
      return;
    }
    let invoked = false;

    await assert.rejects(
      importWorkspaceFile({
        sourcePath: link,
        scope: makeScope(sourceRoot),
        runWsl: async () => { invoked = true; throw new Error('symlink must not be transferred'); },
      }),
      /symlink/i,
    );
    assert.equal(invoked, false);
  } finally {
    rmSync(temp, { recursive: true, force: true });
  }
});

test('workspace import writes through the secure worker in live Kali WSL', {
  skip: process.env.CTF_AGENT_RUN_WSL_INTEGRATION !== '1',
}, async () => {
  const temp = mkdtempSync(join(tmpdir(), 'ctf-import-live-'));
  const sourceRoot = join(temp, 'inputs');
  mkdirSync(sourceRoot);
  const sourcePath = join(sourceRoot, 'payload.bin');
  const bytes = Buffer.from('safe workspace import smoke test');
  writeFileSync(sourcePath, bytes);
  const challengeId = `mcp-import-${process.pid}-${Date.now()}`;
  const workspace = `/home/ctfagent/ctf-workspaces/${challengeId}`;
  try {
    const result = await importWorkspaceFile({
      sourcePath,
      scope: {
        challengeId,
        sourceRoots: [sourceRoot],
        wslWorkspace: workspace,
      },
    });
    assert.equal(result.bytes, bytes.length);
    assert.equal(result.sha256, createHash('sha256').update(bytes).digest('hex'));

    const verify = await runWsl([
      '--distribution', 'kali-linux', '--user', 'ctfagent', '--exec',
      'python3', '-c', 'import hashlib,sys;print(hashlib.sha256(open(sys.argv[1],"rb").read()).hexdigest())',
      result.destinationPath,
    ]);
    assert.equal(verify.exitCode, 0, verify.stderr);
    assert.equal(verify.stdout.trim(), result.sha256);
  } finally {
    await runWsl([
      '--distribution', 'kali-linux', '--user', 'ctfagent', '--exec',
      'python3', '-c', 'import shutil,sys;shutil.rmtree(sys.argv[1],ignore_errors=True)',
      workspace,
    ]);
    rmSync(temp, { recursive: true, force: true });
  }
});
