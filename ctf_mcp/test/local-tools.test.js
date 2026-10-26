import assert from 'node:assert/strict';
import { buildCryptoCandidates, buildSmtCommand, decodeCtfValue, registerLocalTools } from '../tools/local.js';
import test from 'node:test';

test('decodeCtfValue handles common bounded CTF encodings', () => {
  assert.deepEqual(decodeCtfValue({ encoding: 'base64', value: 'ZmxhZ3tva30=' }), {
    encoding: 'base64',
    output: 'flag{ok}',
    outputHex: '666c61677b6f6b7d',
  });
  assert.equal(decodeCtfValue({ encoding: 'rot13', value: 'synt{bx}' }).output, 'flag{ok}');
  assert.deepEqual(decodeCtfValue({ encoding: 'xor-byte', value: '414243', key: 32 }), {
    encoding: 'xor-byte',
    output: 'abc',
    outputHex: '616263',
  });
});

test('decodeCtfValue rejects malformed input and invalid XOR keys', () => {
  assert.throws(() => decodeCtfValue({ encoding: 'hex', value: 'abc' }), /even-length/i);
  assert.throws(() => decodeCtfValue({ encoding: 'base64', value: 'not base64!' }), /base64/i);
  assert.throws(() => decodeCtfValue({ encoding: 'xor-byte', value: '00', key: 256 }), /0 to 255/i);
  assert.throws(() => decodeCtfValue({ encoding: 'unknown', value: '00' }), /encoding/i);
});

test('buildCryptoCandidates detects common encodings and ranks single-byte XOR', () => {
  const decoded = buildCryptoCandidates({ value: 'ZmxhZ3tva30=', encoding: 'auto', includeSingleByteXor: false });
  assert.ok(decoded.candidates.some((candidate) => candidate.encoding === 'base64' && candidate.text === 'flag{ok}'));
  assert.ok(buildCryptoCandidates({ value: '666c61677b6865787d', includeSingleByteXor: false })
    .candidates.some((candidate) => candidate.encoding === 'hex' && candidate.text === 'flag{hex}'));
  assert.ok(buildCryptoCandidates({ value: 'flag%7Burl%7D', includeSingleByteXor: false })
    .candidates.some((candidate) => candidate.encoding === 'url' && candidate.text === 'flag{url}'));
  assert.ok(buildCryptoCandidates({ value: 'plain text', includeSingleByteXor: false })
    .candidates.some((candidate) => candidate.encoding === 'text' && candidate.text === 'plain text'));

  const plaintext = Buffer.from('flag{xor}');
  const ciphertext = Buffer.from([...plaintext].map((byte) => byte ^ 0x42)).toString('hex');
  const xor = buildCryptoCandidates({ value: ciphertext, encoding: 'hex', limit: 10 });
  assert.ok(xor.candidates.some((candidate) => candidate.keyByte === 0x42 && candidate.text === 'flag{xor}'));
  assert.equal(xor.candidates[0].keyByte, 0x42);
  assert.equal(xor.candidates[0].text, 'flag{xor}');
  assert.ok(xor.candidates.every((candidate) => typeof candidate.score === 'number' && candidate.score >= 0 && candidate.score <= 1));

  const duplicates = buildCryptoCandidates({ value: 'a', encoding: 'auto', includeSingleByteXor: false });
  assert.equal(duplicates.candidates.length, 1);
  assert.equal(duplicates.candidates[0].encoding, 'text');
});

test('buildCryptoCandidates rejects malformed and oversized inputs and bounds candidate text', () => {
  assert.throws(() => buildCryptoCandidates({ value: 'abc', encoding: 'hex' }), /hex/i);
  assert.throws(() => buildCryptoCandidates({ value: 'x'.repeat(32_769) }), /byte limit/i);
  assert.throws(() => buildCryptoCandidates({ value: 'hello', limit: 0 }), /limit/i);

  const result = buildCryptoCandidates({ value: 'A'.repeat(4096), encoding: 'text', includeSingleByteXor: false, limit: 1 });
  assert.equal(result.candidates.length, 1);
  assert.equal(result.candidates[0].text.length, 2048);
  assert.equal(result.candidates[0].truncated, true);
});

test('registerLocalTools exposes crypto candidate analysis without launching WSL', async () => {
  const tools = new Map();
  registerLocalTools({
    registerTool(name, config, handler) {
      tools.set(name, { config, handler });
    },
  }, {
    runWslTool: async () => { throw new Error('offline crypto analysis must not launch WSL'); },
  });

  const tool = tools.get('ctf_crypto_candidates');
  assert.ok(tool);
  const response = await tool.handler({ value: 'ZmxhZ3tva30=', encoding: 'auto', includeSingleByteXor: false });
  const payload = JSON.parse(response.content[0].text);
  assert.ok(payload.candidates.some((candidate) => candidate.encoding === 'base64' && candidate.text === 'flag{ok}'));
});

test('buildSmtCommand sends bounded SMT-LIB to z3 stdin', () => {
  const command = buildSmtCommand({ smtlib: '(check-sat)' });
  assert.ok(command);
  assert.equal(command.executable, 'z3');
  assert.deepEqual(command.args, ['-in']);
  assert.deepEqual(command.input, Buffer.from('(check-sat)'));
  assert.equal(command.timeoutMs, 30_000);
  assert.throws(() => buildSmtCommand({ smtlib: 'x'.repeat(128 * 1024 + 1) }), /byte limit/i);
});

test('ctf_smt_solve marks truncated output as a tool error', async () => {
  const tools = new Map();
  registerLocalTools({
    registerTool(name, config, handler) {
      tools.set(name, { config, handler });
    },
  }, {
    runWslTool: async () => ({
      exitCode: 0,
      stdout: 'sat\n',
      stderr: '',
      timedOut: false,
      truncated: true,
    }),
  });

  const response = await tools.get('ctf_smt_solve').handler({ smtlib: '(check-sat)' });
  assert.equal(response.isError, true);
});
