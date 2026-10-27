import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { mkdtempSync, mkdirSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import test from 'node:test';
import { auditPackageTree } from '../../scripts/package-audit.js';

const repoRoot = fileURLToPath(new URL('../../', import.meta.url));
const runtimeFiles = new Set([
  'ctf_mcp/cli.js',
  'ctf_mcp/doctor.js',
  'ctf_mcp/frida-runtime.js',
  'ctf_mcp/ide-setup.js',
  'ctf_mcp/learning.js',
  'ctf_mcp/manifest.js',
  'ctf_mcp/scope.js',
  'ctf_mcp/server.js',
  'ctf_mcp/setup.js',
  'ctf_mcp/wsl.js',
  'ctf_mcp/tool-manifest.json',
  'ctf_mcp/tools/artifacts.js',
  'ctf_mcp/tools/ctfd.js',
  'ctf_mcp/tools/doctor_worker.py',
  'ctf_mcp/tools/frida_worker.py',
  'ctf_mcp/tools/game.js',
  'ctf_mcp/tools/local.js',
  'ctf_mcp/tools/network.js',
  'ctf_mcp/tools/reverse.js',
  'ctf_mcp/tools/workspace-command.js',
  'ctf_mcp/tools/workspace.js',
  'ctf_mcp/tools/workspace_worker.py',
]);

function packedFiles() {
  const windows = process.platform === 'win32';
  const result = spawnSync(windows ? (process.env.ComSpec ?? 'cmd.exe') : 'npm', windows
    ? ['/d', '/s', '/c', 'npm pack --dry-run --json']
    : ['pack', '--dry-run', '--json'], {
    cwd: repoRoot,
    encoding: 'utf8',
    timeout: 60_000,
  });
  assert.equal(result.status, 0, result.stderr);
  return JSON.parse(result.stdout)[0].files.map(({ path }) => path.replaceAll('\\', '/'));
}

test('npm package contains only runtime and CTF guidance, never workspace or secret data', () => {
  const files = packedFiles();
  const allowed = (path) => path === 'package.json'
    || path === 'README.md'
    || path === 'LICENSE'
    || path === 'DISCLOSURE'
    || runtimeFiles.has(path)
    || /^\.agents\/skills\/ctf-[^/]+\/.+\.md$/i.test(path)
    || /^\.agents\/(references|rules)\/.+\.md$/i.test(path);
  const forbidden = /(?:^|\/)(?:\.packet|\.delta|\.superpowers|\.ctf-workspaces|node_modules|__pycache__)(?:\/|$)|\.packet$|(?:^|\/)\.env(?:\.|$)|\.(?:pem|key|p12|pfx|pcap|pcapng|dmp|core)$/i;

  assert.ok(files.includes('ctf_mcp/cli.js'));
  assert.ok(files.includes('LICENSE'));
  assert.ok(files.includes('DISCLOSURE'));
  assert.ok(files.includes('.agents/skills/ctf-solve-challenge/SKILL.md'));
  assert.ok(files.includes('.agents/skills/ctf-solve-report/SKILL.md'));
  assert.ok(files.some((path) => path.startsWith('.agents/skills/ctf-web/')));
  assert.ok(files.some((path) => path.startsWith('.agents/references/')));
  assert.ok(files.some((path) => path.startsWith('.agents/rules/')));
  assert.deepEqual(files.filter((path) => !allowed(path)), []);
  assert.deepEqual(files.filter((path) => forbidden.test(path)), []);
});

test('npm package declares dual-use content and packs its disclosure', () => {
  const metadata = JSON.parse(readFileSync(new URL('../../package.json', import.meta.url), 'utf8'));
  assert.deepEqual(metadata.contentPolicy, { class: 'dual-use' });
  assert.equal(metadata.publishConfig?.access, 'public');
  assert.ok(metadata.files.includes('DISCLOSURE'));
  assert.ok(packedFiles().includes('DISCLOSURE'));
});

test('package audit rejects packet artifacts and private-key material', () => {
  const root = mkdtempSync(path.join(os.tmpdir(), 'ctf-agent-package-audit-'));
  const put = (relativePath, text = 'fixture') => {
    const destination = path.join(root, relativePath);
    mkdirSync(path.dirname(destination), { recursive: true });
    writeFileSync(destination, text);
  };

  try {
    for (const relativePath of runtimeFiles) put(relativePath);
    const validMetadata = { private: false, license: 'MIT', contentPolicy: { class: 'dual-use' }, files: ['DISCLOSURE'], publishConfig: { access: 'public' } };
    put('package.json', JSON.stringify(validMetadata));
    put('README.md');
    put('LICENSE', 'MIT License\n');
    put('DISCLOSURE', 'Authorized CTF competitions and educational labs only.');
    put('.agents/skills/ctf-solve-challenge/SKILL.md');
    put('.agents/references/ctf-triage-ladder.md');
    put('.agents/rules/flag-validation-rules.md');
    assert.deepEqual(auditPackageTree(root), []);

    put('package.json', '{"private":false}');
    assert.ok(auditPackageTree(root).some((entry) => entry.includes('license')));
    put('package.json', '{"private":false,"license":"Apache-2.0"}');
    assert.ok(auditPackageTree(root).some((entry) => entry.includes('license')));
    put('package.json', '{"private":true,"license":"MIT"}');
    assert.ok(auditPackageTree(root).some((entry) => entry.includes('private')));
    put('package.json', '{"private":false,"license":"MIT"}');
    assert.ok(auditPackageTree(root).some((entry) => entry.includes('contentPolicy')));
    put('package.json', '{"private":false,"license":"MIT","contentPolicy":{"class":"other"},"files":["DISCLOSURE"]}');
    assert.ok(auditPackageTree(root).some((entry) => entry.includes('contentPolicy')));
    put('package.json', JSON.stringify({ ...validMetadata, publishConfig: undefined }));
    assert.ok(auditPackageTree(root).some((entry) => entry.includes('publishConfig.access')));
    put('package.json', JSON.stringify({ ...validMetadata, publishConfig: { access: 'restricted' } }));
    assert.ok(auditPackageTree(root).some((entry) => entry.includes('publishConfig.access')));
    put('package.json', JSON.stringify({ ...validMetadata, files: [] }));
    assert.ok(auditPackageTree(root).some((entry) => entry.includes('allowlist')));
    put('package.json', JSON.stringify(validMetadata));
    rmSync(path.join(root, 'DISCLOSURE'));
    assert.ok(auditPackageTree(root).some((entry) => entry.includes('DISCLOSURE')));
    put('DISCLOSURE', 'Authorized CTF competitions and educational labs only.');

    put('.agents/skills/private/capture.packet');
    put('.agents/references/private-key.md', '-----BEGIN PRIVATE KEY-----');
    put('.agents/rules/credentials.md', 'api_key = "0123456789abcdef0123456789"'); // gitleaks:allow -- synthetic audit-rejection fixture
    put('.agents/skills/unrelated/SKILL.md', 'unrelated');
    const violations = auditPackageTree(root);
    assert.ok(violations.some((entry) => entry.includes('capture.packet')));
    assert.ok(violations.some((entry) => entry.includes('private-key.md')));
    assert.ok(violations.some((entry) => entry.includes('credentials.md')));
    assert.ok(violations.some((entry) => entry.includes('unrelated/SKILL.md')));
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test('publish lifecycle runs tests and package audit without invoking publish', () => {
  const metadata = JSON.parse(readFileSync(new URL('../../package.json', import.meta.url), 'utf8'));
  assert.match(metadata.scripts.prepublishOnly, /npm test/);
  assert.match(metadata.scripts.prepublishOnly, /node scripts\/package-audit\.js/);
  assert.equal(metadata.scripts.prepack, 'node scripts/package-audit.js');
  assert.doesNotMatch(metadata.scripts.prepublishOnly, /npm publish/);
  assert.equal(metadata.scripts['verify:package'], 'node scripts/verify-package.js');
});

test('release workflow verifies on Windows and only stages dual-use packages without a long-lived token', () => {
  const workflow = readFileSync(new URL('../../.github/workflows/publish.yml', import.meta.url), 'utf8');
  assert.match(workflow, /runs-on: windows-latest/);
  assert.match(workflow, /npm run prepublishOnly/);
  assert.match(workflow, /npm run verify:package/);
  assert.match(workflow, /npm stage publish/);
  assert.match(workflow, /id-token: write/);
  assert.doesNotMatch(workflow, /\bnpm publish\b|secrets\.NPM_TOKEN|NODE_AUTH_TOKEN/);
  assert.match(workflow, /--tag "\$env:NPM_TAG"/);
});
