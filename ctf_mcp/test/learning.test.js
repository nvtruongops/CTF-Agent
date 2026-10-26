import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { linkSync, mkdtempSync, mkdirSync, readFileSync, readdirSync, rmSync, statSync, writeFileSync, existsSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import test from 'node:test';

const learning = await import('../learning.js').catch(() => ({}));
const TOPICS = [
  'web', 'reverse', 'crypto', 'pwn', 'forensics', 'exploitation',
  'game_hacking', 'misc', 'osint', 'steganography', 'hardware', 'competition',
];
const CLI_PATH = fileURLToPath(new URL('../cli.js', import.meta.url));

function requireFunctions(...names) {
  for (const name of names) assert.equal(typeof learning[name], 'function', `${name} must be available`);
}

function proposal(overrides = {}) {
  return {
    schemaVersion: 1,
    id: 'xml-parser-filter-mismatch',
    title: 'XML parser and filter interpretation mismatch',
    topic: 'web',
    parentId: null,
    principle: 'Validate untrusted input using the same semantic interpretation as the downstream parser.',
    mechanism: 'A byte-oriented filter and a decoding parser can interpret one request differently.',
    appliesWhen: ['The parser accepts an alternate encoding.', 'The filter compares undecoded bytes.'],
    doesNotApplyWhen: ['The parser rejects the encoding.', 'The filter canonicalizes before checking.'],
    confidence: 'medium',
    actions: [{
      tool: 'ctf_scoped_http_request',
      parameters: { encoding: 'alternate', requestCount: 1 },
      observation: 'The direct response differed from the raw-byte filter expectation.',
    }],
    evidence: [{
      kind: 'source',
      reference: 'challenge source',
      observation: 'The filter compares bytes before parser decoding.',
    }, {
      kind: 'tool',
      reference: 'direct successful response',
      observation: 'The parser processed the alternate representation.',
    }],
    relatedLabs: ['meters-flag'],
    ...overrides,
  };
}

function temporaryRoot() {
  return mkdtempSync(join(tmpdir(), 'ctf-learning-'));
}

function captureWrite() {
  let output = '';
  return { write: (text) => { output += text; }, text: () => output };
}

function runCommand(args, rootDir) {
  const captured = captureWrite();
  learning.runLearnCommand(args, { rootDir, write: captured.write });
  return captured.text();
}

test('proposal validation accepts the complete schema for all 12 CTF topics', () => {
  requireFunctions('validateLearningProposal');
  for (const topic of TOPICS) {
    assert.deepEqual(learning.validateLearningProposal(proposal({ topic })), { valid: true, errors: [] }, topic);
  }
});

test('proposal validation reports malformed fields and path-like identifiers', () => {
  requireFunctions('validateLearningProposal');
  const invalid = learning.validateLearningProposal(proposal({
    id: '../outside',
    topic: 'unknown',
    principle: '',
    appliesWhen: [],
    confidence: 'certain',
    extraPayload: 'not part of the schema',
  }));
  assert.equal(invalid.valid, false);
  const fields = invalid.errors.map((error) => error.field);
  for (const field of ['id', 'topic', 'principle', 'appliesWhen', 'confidence', 'extraPayload']) {
    assert.ok(fields.includes(field), `missing validation error for ${field}`);
  }
});

test('proposal creation rejects flags and credential assignments without writing any file', () => {
  requireFunctions('proposeLearning');
  const rootDir = temporaryRoot();
  try {
    for (const bad of [
      proposal({ evidence: [{ kind: 'tool', reference: 'response', observation: 'picoCTF{not-a-real-flag}' }] }),
      proposal({ actions: [{ tool: 'ctf_scoped_http_request', parameters: { password: 'candidate-secret' }, observation: 'observed' }] }),
      proposal({ evidence: [{ kind: 'tool', reference: 'response', observation: 'token=redacted-test-secret' }] }),
      proposal({ actions: [{ tool: 'ctf_scoped_http_request', parameters: { body: 'raw response data' }, observation: 'observed' }] }),
      proposal({ principle: '' }),
      proposal({ id: '../outside' }),
    ]) {
      assert.throws(() => learning.proposeLearning(bad, { rootDir }), /evidence|password|secret|body|principle|id/i);
      assert.equal(existsSync(join(rootDir, '.agents', 'skill-tree', 'proposals')), false);
    }
  } finally {
    rmSync(rootDir, { recursive: true, force: true });
  }
});

test('proposal creation rejects raw content under ordinary parameter and observation fields', () => {
  requireFunctions('proposeLearning');
  const rootDir = temporaryRoot();
  try {
    const rawParameter = proposal({ actions: [{
      tool: 'ctf_scoped_http_request',
      parameters: { input: '<doc>raw request data</doc>' },
      observation: 'The parser accepted the input.',
    }] });
    const rawObservation = proposal({ actions: [{
      tool: 'ctf_scoped_http_request',
      parameters: { encoding: 'alternate' },
      observation: 'The response included <doc>raw response data</doc>.',
    }] });

    for (const bad of [rawParameter, rawObservation]) {
      assert.throws(() => learning.proposeLearning(bad, { rootDir }), /input|raw content|markup|payload/i);
      assert.equal(existsSync(join(rootDir, '.agents', 'skill-tree', 'proposals')), false);
    }
  } finally {
    rmSync(rootDir, { recursive: true, force: true });
  }
});

test('proposals are bounded to 64 KiB and malformed or oversized input leaves storage untouched', () => {
  requireFunctions('runLearnCommand');
  const rootDir = temporaryRoot();
  try {
    const inputPath = join(rootDir, 'proposal.json');
    for (const contents of ['{ malformed', JSON.stringify(proposal({ title: 'x'.repeat(65 * 1024) }))]) {
      writeFileSync(inputPath, contents);
      assert.throws(() => runCommand(['--propose', '--input', inputPath], rootDir), /JSON|64 KiB|64 KiB|input/i);
      assert.equal(existsSync(join(rootDir, '.agents', 'skill-tree', 'proposals')), false);
    }
  } finally {
    rmSync(rootDir, { recursive: true, force: true });
  }
});

test('proposal IDs cannot be reused while pending or after promotion', () => {
  requireFunctions('proposeLearning', 'promoteLearningEntry');
  const rootDir = temporaryRoot();
  try {
    learning.proposeLearning(proposal(), { rootDir });
    assert.throws(() => learning.proposeLearning(proposal(), { rootDir }), /already exists|duplicate/i);
    learning.promoteLearningEntry({ rootDir, id: 'xml-parser-filter-mismatch' });
    assert.throws(() => learning.proposeLearning(proposal(), { rootDir }), /already exists|duplicate/i);
  } finally {
    rmSync(rootDir, { recursive: true, force: true });
  }
});

test('list and show expose pending and approved proposals with their state', () => {
  requireFunctions('proposeLearning', 'promoteLearningEntry', 'listLearningEntries', 'showLearningEntry');
  const rootDir = temporaryRoot();
  try {
    learning.proposeLearning(proposal(), { rootDir });
    learning.proposeLearning(proposal({ id: 'canonicalization-boundary', title: 'Canonicalization boundary' }), { rootDir });
    learning.promoteLearningEntry({ rootDir, id: 'xml-parser-filter-mismatch' });

    const entries = learning.listLearningEntries({ rootDir, topic: 'web' });
    assert.deepEqual(entries.map(({ proposal: item, status }) => [item.id, status]), [
      ['canonicalization-boundary', 'pending'],
      ['xml-parser-filter-mismatch', 'approved'],
    ]);
    assert.equal(learning.showLearningEntry({ rootDir, id: 'canonicalization-boundary' }).status, 'pending');
    assert.equal(learning.showLearningEntry({ rootDir, id: 'xml-parser-filter-mismatch' }).status, 'approved');
    assert.deepEqual(learning.listLearningEntries({ rootDir, topic: 'crypto' }), []);
  } finally {
    rmSync(rootDir, { recursive: true, force: true });
  }
});

test('promotion moves only an explicitly selected proposal and never overwrites a destination', () => {
  requireFunctions('proposeLearning', 'promoteLearningEntry');
  const rootDir = temporaryRoot();
  try {
    const pending = learning.proposeLearning(proposal(), { rootDir });
    const approvedPath = join(rootDir, '.agents', 'skill-tree', 'patterns', 'web', `${pending.id}.json`);
    mkdirSync(dirname(approvedPath), { recursive: true });
    writeFileSync(approvedPath, 'keep approved bytes');

    assert.throws(() => learning.promoteLearningEntry({ rootDir, id: pending.id }), /already exists|collision/i);
    assert.equal(readFileSync(approvedPath, 'utf8'), 'keep approved bytes');
    assert.equal(existsSync(join(rootDir, '.agents', 'skill-tree', 'proposals', `${pending.id}.json`)), true);
    assert.equal(readdirSync(dirname(approvedPath)).filter((name) => name === `${pending.id}.json`).length, 1);
    assert.equal(existsSync(join(rootDir, '.agents', 'skills')), false);
  } finally {
    rmSync(rootDir, { recursive: true, force: true });
  }
});

test('promotion rejects the same ID already approved under another topic', () => {
  requireFunctions('proposeLearning', 'promoteLearningEntry');
  const rootDir = temporaryRoot();
  try {
    const pending = learning.proposeLearning(proposal(), { rootDir });
    const conflictingPath = join(rootDir, '.agents', 'skill-tree', 'patterns', 'crypto', `${pending.id}.json`);
    mkdirSync(dirname(conflictingPath), { recursive: true });
    writeFileSync(conflictingPath, `${JSON.stringify(proposal({ topic: 'crypto' }), null, 2)}\n`);

    assert.throws(() => learning.promoteLearningEntry({ rootDir, id: pending.id }), /already exists|duplicate/i);
    assert.equal(existsSync(join(rootDir, '.agents', 'skill-tree', 'proposals', `${pending.id}.json`)), true);
    assert.equal(readFileSync(conflictingPath, 'utf8'), `${JSON.stringify(proposal({ topic: 'crypto' }), null, 2)}\n`);
  } finally {
    rmSync(rootDir, { recursive: true, force: true });
  }
});

test('interrupted hard-link promotion is one approved entry and can be reconciled', () => {
  requireFunctions('proposeLearning', 'promoteLearningEntry', 'listLearningEntries', 'showLearningEntry');
  const rootDir = temporaryRoot();
  try {
    const pending = learning.proposeLearning(proposal(), { rootDir });
    const pendingPath = join(rootDir, '.agents', 'skill-tree', 'proposals', `${pending.id}.json`);
    const approvedPath = join(rootDir, '.agents', 'skill-tree', 'patterns', 'web', `${pending.id}.json`);
    mkdirSync(dirname(approvedPath), { recursive: true });
    linkSync(pendingPath, approvedPath);

    assert.deepEqual(learning.listLearningEntries({ rootDir }).map(({ proposal: item, status }) => [item.id, status]), [
      [pending.id, 'approved'],
    ]);
    assert.equal(learning.showLearningEntry({ rootDir, id: pending.id }).status, 'approved');
    assert.equal(learning.promoteLearningEntry({ rootDir, id: pending.id }).status, 'approved');
    assert.equal(existsSync(pendingPath), false);
    assert.equal(existsSync(approvedPath), true);
  } finally {
    rmSync(rootDir, { recursive: true, force: true });
  }
});

test('show and promote reject path-like IDs before touching files', () => {
  requireFunctions('showLearningEntry', 'promoteLearningEntry');
  const rootDir = temporaryRoot();
  try {
    for (const id of ['../outside', 'nested/item', '']) {
      assert.throws(() => learning.showLearningEntry({ rootDir, id }), /id|slug/i);
      assert.throws(() => learning.promoteLearningEntry({ rootDir, id }), /id|slug/i);
    }
    assert.equal(readdirSync(rootDir).length, 0);
  } finally {
    rmSync(rootDir, { recursive: true, force: true });
  }
});

test('learn CLI commands list, show, and explicitly promote through the review lifecycle', () => {
  requireFunctions('runLearnCommand');
  const rootDir = temporaryRoot();
  try {
    const inputPath = join(rootDir, 'proposal.json');
    writeFileSync(inputPath, JSON.stringify(proposal()));
    assert.match(runCommand(['--propose', '--input', inputPath], rootDir), /xml-parser-filter-mismatch/);
    assert.match(runCommand(['--list'], rootDir), /pending/);
    assert.match(runCommand(['--show', 'xml-parser-filter-mismatch'], rootDir), /XML parser and filter/);
    assert.match(runCommand(['--promote', 'xml-parser-filter-mismatch'], rootDir), /approved/);
    assert.match(runCommand(['--list', '--topic', 'web'], rootDir), /approved/);
    assert.equal(existsSync(join(rootDir, '.agents', 'skill-tree', 'proposals', 'xml-parser-filter-mismatch.json')), false);
    assert.equal(existsSync(join(rootDir, '.agents', 'skill-tree', 'patterns', 'web', 'xml-parser-filter-mismatch.json')), true);
    assert.equal(existsSync(join(rootDir, '.agents', 'skills')), false);
  } finally {
    rmSync(rootDir, { recursive: true, force: true });
  }
});

test('learn CLI dispatch works outside the repository without writing into the current directory', () => {
  const cwd = temporaryRoot();
  try {
    const result = spawnSync(process.execPath, [CLI_PATH, 'learn', '--list'], { cwd, encoding: 'utf8' });
    assert.equal(result.status, 0, result.stderr);
    assert.equal(existsSync(join(cwd, '.agents', 'skill-tree')), false);
    assert.equal(statSync(cwd).isDirectory(), true);
    const help = spawnSync(process.execPath, [CLI_PATH, '--help'], { cwd, encoding: 'utf8' });
    assert.equal(help.status, 0, help.stderr);
    assert.match(help.stdout, /learn --propose.*--promote/s);
  } finally {
    rmSync(cwd, { recursive: true, force: true });
  }
});
