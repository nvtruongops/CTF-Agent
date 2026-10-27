import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { existsSync, mkdtempSync, mkdirSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { Client } from '@modelcontextprotocol/client';
import { StdioClientTransport } from '@modelcontextprotocol/client/stdio';

assert.ok(['win32', 'linux'].includes(process.platform), 'Verify on Windows or Linux.');
assert.ok(process.env.npm_execpath, 'Run this check with npm run verify:package.');
const root = fileURLToPath(new URL('../', import.meta.url));
const temp = mkdtempSync(path.join(os.tmpdir(), 'ctf-agent-package-'));
const home = path.join(temp, 'home');
const project = path.join(temp, 'challenge');
mkdirSync(home);
mkdirSync(project);
writeFileSync(path.join(temp, '.npmrc'), '');
writeFileSync(path.join(temp, '.global-npmrc'), '');
const env = {
  ...process.env,
  USERPROFILE: home,
  HOME: home,
  CTF_AGENT_PROJECT_ROOT: project,
  CTF_MCP_CTFD_URL: '',
  CTF_MCP_CTFD_TOKEN: '',
  NODE_AUTH_TOKEN: '',
  NPM_TOKEN: '',
  npm_config_userconfig: path.join(temp, '.npmrc'),
  npm_config_globalconfig: path.join(temp, '.global-npmrc'),
  npm_config_registry: 'https://registry.npmjs.org',
};

function run(command, args, cwd = project) {
  const result = spawnSync(command, args, { cwd, env, encoding: 'utf8', timeout: 120_000, windowsHide: true });
  assert.equal(result.status, 0, `${command}: ${result.error?.message ?? ''}\n${result.stderr}\n${result.stdout}`);
  return result.stdout;
}

function npm(args, cwd) {
  return run(process.execPath, [process.env.npm_execpath, ...args], cwd);
}

try {
  const [packed] = JSON.parse(npm(['pack', '--json', '--pack-destination', temp], root));
  const tarball = path.join(temp, packed.filename);
  npm(['install', '--no-audit', '--no-fund', '--omit=dev', tarball]);
  const installed = path.join(project, 'node_modules', 'ctf-agent');
  const metadata = JSON.parse(readFileSync(path.join(installed, 'package.json'), 'utf8'));
  assert.equal(metadata.name, 'ctf-agent');
  assert.deepEqual(metadata.contentPolicy, { class: 'dual-use' });
  assert.equal(metadata.publishConfig.access, 'public');
  for (const { path: relative } of packed.files) {
    assert.deepEqual(readFileSync(path.join(installed, relative)), readFileSync(path.join(root, relative)), relative);
  }
  assert.equal(existsSync(path.join(project, 'node_modules', '@modelcontextprotocol', 'client')), false);

  const cli = path.join(installed, metadata.bin['ctf-agent']);
  const help = npm(['exec', '--offline', '--', 'ctf-agent', '--help']);
  for (const command of ['setup', 'doctor', 'scope init', 'learn', 'mcp']) assert.ok(help.includes(command), command);
  const clients = ['opencode', 'claude-code', 'codex', 'antigravity'];
  const setupArgs = ['setup', ...clients.flatMap((client) => ['--client', client])];
  const config = path.join(home, '.config', 'opencode', 'opencode.json');
  run(process.execPath, [cli, ...setupArgs, '--dry-run']);
  assert.equal(existsSync(config), false, 'Dry-run must not write IDE configuration.');
  run(process.execPath, [cli, ...setupArgs, '--yes']);
  for (const relative of ['.config/opencode/opencode.json', '.claude.json', '.codex/config.toml', '.gemini/config/mcp_config.json']) {
    assert.ok(readFileSync(path.join(home, relative), 'utf8').includes(`ctf-agent@${metadata.version}`), relative);
  }
  const registration = JSON.parse(readFileSync(config, 'utf8')).mcp.servers['ctf-agent'];
  assert.deepEqual(registration.command, ['npx', '-y', `ctf-agent@${metadata.version}`, 'mcp']);
  assert.equal(registration.cwd, '.');
  const guidance = packed.files.filter(({ path: relative }) => /^\.agents\/(skills|references|rules)\//.test(relative));
  assert.ok(guidance.some(({ path: relative }) => relative === '.agents/skills/ctf-solve-challenge/SKILL.md'));
  assert.ok(guidance.some(({ path: relative }) => relative === '.agents/skills/ctf-solve-report/SKILL.md'));
  for (const base of ['.agents', '.claude', '.gemini/config']) {
    for (const { path: relative } of guidance) {
      assert.deepEqual(readFileSync(path.join(home, base, relative.slice('.agents/'.length))), readFileSync(path.join(installed, relative)));
    }
  }
  run(process.execPath, [cli, ...setupArgs, '--yes']);
  assert.equal(existsSync(`${config}.bak`), false, 'Repeating unchanged setup must not overwrite the config.');
  const scope = JSON.parse(run(process.execPath, [cli, 'scope', 'init', '--challenge', 'package-smoke', '--workspace', '.ctf-workspaces/package-smoke', '--target', 'challenge.example:8080']));
  assert.equal(scope.wslWorkspace, '/home/ctfagent/ctf-workspaces/package-smoke');
  assert.deepEqual(scope.targets, [{ host: 'challenge.example', port: 8080 }]);

  const client = new Client({ name: 'ctf-agent-package-verifier', version: '1.0.0' });
  const transport = new StdioClientTransport({ command: process.execPath, args: [cli, 'mcp'], cwd: project, env });
  try {
    await client.connect(transport);
    const { tools } = await client.listTools();
    const manifest = JSON.parse(readFileSync(path.join(installed, 'ctf_mcp', 'tool-manifest.json'), 'utf8'));
    for (const category of manifest.categories) {
      for (const tool of category.tools) assert.ok(tools.some(({ name }) => name === tool.id), tool.id);
    }
    const health = await client.callTool({ name: 'ctf_mcp_health', arguments: {} });
    assert.deepEqual(JSON.parse(health.content.find(({ type }) => type === 'text').text), { name: 'ctf-agent', status: 'alive', version: metadata.version });
    const decoded = await client.callTool({ name: 'ctf_crypto_candidates', arguments: { value: 'ZmxhZ3tva30=', encoding: 'auto', includeSingleByteXor: false } });
    assert.ok(JSON.parse(decoded.content.find(({ type }) => type === 'text').text).candidates.some(({ text }) => text === 'flag{ok}'));
    const rejected = await client.callTool({ name: 'ctf_nmap_scan', arguments: { target: 'outside.example:8080', serviceDetection: false } });
    assert.equal(rejected.isError, true);
    assert.match(rejected.content.find(({ type }) => type === 'text').text, /scope/i);
    console.log(JSON.stringify({ package: `${metadata.name}@${metadata.version}`, files: packed.files.length, tools: tools.length, clients, scope: 'enforced', install: 'passed' }));
  } finally {
    await client.close();
    await transport.close();
  }
} finally {
  rmSync(temp, { recursive: true, force: true });
}
