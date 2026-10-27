import assert from 'node:assert/strict';
import { runCommand, decodeWslText, parseWslDistroTable, runWslTool } from '../wsl.js';
import test from 'node:test';

test('Linux timeout kills a signal-ignoring process group within a bounded grace period', { skip: process.platform !== 'linux' }, async () => {
  const started = Date.now();
  const result = await runCommand(process.execPath, ['-e', 'process.on("SIGTERM",()=>{});setTimeout(()=>{},3000)'], { timeoutMs: 200, maxOutputBytes: 128 });
  assert.equal(result.timedOut, true);
  assert.ok(Date.now() - started < 1500, 'ignored SIGTERM must escalate, not wait for normal exit');
});

test('Linux timeout kills descendants holding inherited stdout after the direct child exits', { skip: process.platform !== 'linux' }, async () => {
  const started = Date.now();
  const result = await runCommand(process.execPath, ['-e', 'require("node:child_process").spawn(process.execPath,["-e","setTimeout(()=>{},3000)"],{stdio:["ignore",1,2]});setTimeout(()=>process.exit(0),50)'], { timeoutMs: 200, maxOutputBytes: 128 });
  assert.equal(result.timedOut, true);
  assert.ok(Date.now() - started < 1500, 'inherited pipes must not keep the call open indefinitely');
});

test('Linux MCP account gate rejects root, wrong users and privileged groups', { skip: process.platform !== 'linux' }, async () => {
  const { assertMcpAccount } = await import('../wsl.js');
  assert.equal(typeof assertMcpAccount, 'function');
  for (const account of [{ uid: 0, username: 'ctfagent', groups: [] }, { uid: 1000, username: 'other', groups: [] }, { uid: 1000, username: 'ctfagent', groups: ['sudo'] }, { uid: 1000, username: 'ctfagent', groups: ['wheel'] }]) {
    assert.throws(() => assertMcpAccount(account), /ctfagent|privileged/i);
  }
  assert.doesNotThrow(() => assertMcpAccount({ uid: 1000, username: 'ctfagent', groups: ['ctfagent'] }));
});

test('decodeWslText removes the UTF-16LE encoding used by wsl --list', () => {
  const raw = Buffer.from('docker-desktop\0\r\n\0', 'utf16le');
  assert.deepEqual(decodeWslText(raw).trim().split(/\r?\n/), ['docker-desktop']);
});

test('parseWslDistroTable keeps every distro name and its own WSL version', () => {
  const raw = Buffer.from(
    '  NAME                    STATE           VERSION\r\n'
      + '* docker-desktop         Running         2\r\n'
      + '  Ubuntu-24.04            Stopped         2\r\n'
      + '  kali-linux              Stopped         1\r\n',
    'utf16le',
  );

  assert.deepEqual(parseWslDistroTable(raw), [
    { name: 'docker-desktop', state: 'Running', version: 2, isDefault: true },
    { name: 'Ubuntu-24.04', state: 'Stopped', version: 2, isDefault: false },
    { name: 'kali-linux', state: 'Stopped', version: 1, isDefault: false },
  ]);
});

test('runCommand captures stdout and stderr from a child without a shell', async () => {
  const result = await runCommand(
    process.execPath,
    ['-e', 'process.stdout.write("ok"); process.stderr.write("warn")'],
    { timeoutMs: 2000, maxOutputBytes: 64 },
  );

  assert.deepEqual(result, {
    exitCode: 0,
    stdout: 'ok',
    stderr: 'warn',
    timedOut: false,
    truncated: false,
  });
});

test('runCommand truncates output at the requested combined byte limit', async () => {
  const result = await runCommand(
    process.execPath,
    ['-e', 'process.stdout.write("x".repeat(256))'],
    { timeoutMs: 2000, maxOutputBytes: 32 },
  );

  assert.equal(Buffer.byteLength(result.stdout) + Buffer.byteLength(result.stderr), 32);
  assert.equal(result.truncated, true);
});

test('runWslTool wraps fixed argv with GNU timeout and maps timeout status', async () => {
  let receivedArgs;
  const result = await runWslTool('nmap', ['-sT', '-p', '80', 'challenge.test'], {
    timeoutMs: 2500,
    maxOutputBytes: 4096,
    runWsl: async (args, options) => {
      receivedArgs = args;
      assert.equal(options.timeoutMs, 9500);
      return {
        exitCode: 124,
        stdout: 'partial scan',
        stderr: '',
        timedOut: false,
        truncated: false,
      };
    },
  });

  assert.deepEqual(receivedArgs, [
    '--distribution', 'kali-linux', '--user', 'ctfagent', '--exec',
    'timeout', '--signal=TERM', '--kill-after=5s', '3s',
    'nmap', '-sT', '-p', '80', 'challenge.test',
  ]);
  assert.equal(result.timedOut, true);
  assert.equal(result.stdout, 'partial scan');
});

test('Linux runtime runs tools locally without Windows PATH or root privileges', { skip: process.platform !== 'linux' || process.env.CTF_AGENT_RUN_WSL_INTEGRATION !== '1' }, async () => {
  const result = await runWslTool('python3', ['-c', 'import json,os,sys;print(json.dumps({"platform":sys.platform,"uid":os.getuid(),"path":os.environ["PATH"]}))'], { timeoutMs: 3000, maxOutputBytes: 4096 });
  assert.equal(result.exitCode, 0, result.stderr);
  const report = JSON.parse(result.stdout);
  assert.equal(report.platform, 'linux');
  assert.notEqual(report.uid, 0);
  assert.doesNotMatch(report.path, /\/mnt\/[a-z]\//i);
});
