import assert from 'node:assert/strict';
import { runCommand, decodeWslText, parseWslDistroTable, runWslTool } from '../wsl.js';
import test from 'node:test';

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
