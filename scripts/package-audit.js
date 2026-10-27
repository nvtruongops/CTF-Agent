import { existsSync, lstatSync, readFileSync, readdirSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const runtimeFiles = new Set([
  'ctf_mcp/cli.js',
  'ctf_mcp/doctor.js',
  'ctf_mcp/frida-runtime.js',
  'ctf_mcp/ide-setup.js',
  'ctf_mcp/ide-plan.js',
  'ctf_mcp/learning.js',
  'ctf_mcp/manifest.js',
  'ctf_mcp/paths.js',
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
const forbiddenPath = /(?:^|\/)(?:\.packet|\.delta|\.superpowers|\.ctf-workspaces|node_modules|__pycache__)(?:\/|$)|\.packet$|(?:^|\/)\.env(?:\.|$)|\.(?:pem|key|p12|pfx|pcap|pcapng|dmp|core)$/i;
const secretContent = /-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----|\bAKIA[0-9A-Z]{16}\b|\b(?:gh[pousr]_[A-Za-z0-9_]{20,}|xox[baprs]-[A-Za-z0-9-]{20,}|sk_live_[A-Za-z0-9]{16,})\b|\b(?:api[_-]?key|access[_-]?token|secret|password)[ \t]*[:=][ \t]*(?:["'][A-Za-z0-9_+/=-]{20,}["']|[A-Za-z0-9_+/=-]{24,}(?=$|[\s,;}]))/i;

function collect(root, relative, violations) {
  const absolute = path.join(root, relative);
  let entries;
  try {
    entries = readdirSync(absolute, { withFileTypes: true });
  } catch (error) {
    if (error.code === 'ENOENT') return [];
    throw error;
  }

  const files = [];
  for (const entry of entries) {
    const child = `${relative}/${entry.name}`;
    if (forbiddenPath.test(child)) violations.push(`forbidden package path: ${child}`);
    const stat = lstatSync(path.join(root, child));
    if (stat.isSymbolicLink()) {
      violations.push(`symbolic link in package source: ${child}`);
    } else if (entry.isDirectory()) {
      files.push(...collect(root, child, violations));
    } else if (entry.isFile()) {
      files.push(child);
    }
  }
  return files;
}

export function auditPackageTree(root) {
  const violations = [];
  const runtimeCandidates = [
    ...readdirSync(path.join(root, 'ctf_mcp'), { withFileTypes: true })
      .filter((entry) => entry.isFile() && entry.name.endsWith('.js'))
      .map((entry) => `ctf_mcp/${entry.name}`),
    ...readdirSync(path.join(root, 'ctf_mcp/tools'), { withFileTypes: true })
      .filter((entry) => entry.isFile() && /\.(?:js|py)$/.test(entry.name))
      .map((entry) => `ctf_mcp/tools/${entry.name}`),
    'ctf_mcp/tool-manifest.json',
  ];
  const runtime = new Set(runtimeCandidates);
  for (const file of runtime) {
    if (!runtimeFiles.has(file)) violations.push(`unapproved runtime file: ${file}`);
  }
  for (const file of runtimeFiles) {
    if (!runtime.has(file)) violations.push(`required runtime file missing: ${file}`);
  }

  const skillFiles = collect(root, '.agents/skills', violations);
  for (const file of skillFiles) {
    if (!/^\.agents\/skills\/ctf-[^/]+\//.test(file)) violations.push(`unapproved skill file: ${file}`);
  }
  const hasDisclosure = existsSync(path.join(root, 'DISCLOSURE'));
  if (!hasDisclosure) violations.push('required package disclosure missing: DISCLOSURE');
  const files = [
    'package.json',
    'README.md',
    'LICENSE',
    'setup.ps1',
    'scripts/setup-wsl.sh',
    'scripts/launch-wsl.ps1',
    'scripts/apply-ide-plan.ps1',
    ...(hasDisclosure ? ['DISCLOSURE'] : []),
    ...runtime,
    ...skillFiles,
    ...collect(root, '.agents/references', violations),
    ...collect(root, '.agents/rules', violations),
  ];
  for (const file of files) {
    if (forbiddenPath.test(file)) violations.push(`forbidden package path: ${file}`);
    if (file.startsWith('.agents/') && !file.endsWith('.md')) {
      violations.push(`non-Markdown guidance file: ${file}`);
    }
    const content = readFileSync(path.join(root, file), 'utf8');
    if (secretContent.test(content)) violations.push(`credential-like material: ${file}`);
  }

  const metadata = JSON.parse(readFileSync(path.join(root, 'package.json'), 'utf8'));
  if (metadata.private === true) violations.push('package.json must not be private for npm release readiness');
  if (metadata.license !== 'MIT') violations.push('package.json license must be MIT');
  if (metadata.publishConfig?.access !== 'public') {
    violations.push('package.json must declare publishConfig.access as public');
  }
  if (metadata.contentPolicy?.class !== 'dual-use') {
    violations.push('package.json must declare contentPolicy.class as dual-use');
  }
  if (!metadata.files?.includes('DISCLOSURE')) {
    violations.push('package.json files allowlist must include DISCLOSURE');
  }
  return [...new Set(violations)];
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
  const violations = auditPackageTree(root);
  if (violations.length > 0) {
    process.stderr.write(`Package audit failed:\n${violations.map((entry) => `- ${entry}`).join('\n')}\n`);
    process.exitCode = 1;
  }
}
