import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { nativePath } from '../paths.js';
import test from 'node:test';

test('path boundary rejects UNC/network and NUL paths before filesystem access', () => {
  for (const value of ['\\\\server\\share\\file', '//server/share/file', 'bad\0path']) {
    assert.throws(() => nativePath(value), /network|UNC|NUL/i);
  }
});

test('native paths preserve spaces and Unicode', () => {
  assert.equal(nativePath('/home/ctfagent/challenge thử nghiệm/file.txt'), '/home/ctfagent/challenge thử nghiệm/file.txt');
});

test('Linux rejects Windows-relative paths with an actionable forward-slash instruction', { skip: process.platform !== 'linux' }, () => {
  assert.throws(() => nativePath('.\\challenge-inputs'), /forward.slash/i);
});

test('WSL maps Windows source paths to a native path without changing the original scope', { skip: process.platform !== 'linux' || process.env.CTF_AGENT_RUN_WSL_INTEGRATION !== '1' }, () => {
  const windows = execFileSync('/usr/bin/wslpath', ['-w', process.cwd()], { encoding: 'utf8' }).trim();
  assert.equal(nativePath(windows), process.cwd());
});
