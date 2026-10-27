import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { existsSync, mkdtempSync, mkdirSync, readFileSync, rmSync, symlinkSync, writeFileSync } from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';

test('bootstrap IPC preserves Unicode content and Windows destinations through ASCII-only output', () => {
  const homeDir = mkdtempSync(path.join(os.tmpdir(), 'ctf unicode '));
  try {
    mkdirSync(path.join(homeDir, '.config', 'opencode'), { recursive: true });
    writeFileSync(path.join(homeDir, '.config', 'opencode', 'opencode.json'), '{"name":"Tiếng Việt"}\n');
    const result = spawnSync(process.execPath, [fileURLToPath(new URL('../ide-plan.js', import.meta.url)), '--scope', 'global', 'opencode'], {
      encoding: 'utf8', maxBuffer: 16 * 1024 * 1024, env: { ...process.env, CTF_AGENT_WINDOWS_HOME: homeDir, CTF_AGENT_WINDOWS_HOME_NATIVE: 'C:\\Users\\Nguyễn', CTF_AGENT_WINDOWS_LAUNCHER: 'C:\\Local\\ctf-agent.ps1' },
    });
    assert.equal(result.status, 0, result.stderr);
    assert.equal(/[^\x00-\x7f]/.test(result.stdout), false, 'IPC must be ASCII-only for legacy Windows PowerShell');
    const [config] = JSON.parse(result.stdout);
    assert.equal(config.path, 'C:\\Users\\Nguyễn\\.config\\opencode\\opencode.json');
    assert.equal(JSON.parse(config.content).name, 'Tiếng Việt');
  } finally { rmSync(homeDir, { recursive: true, force: true }); }
});

test('bootstrap IPC maps workspace plans to the exact native root with Unicode and spaces', () => {
  const homeDir = mkdtempSync(path.join(os.tmpdir(), 'ctf bootstrap home '));
  const wslWorkspace = path.join(os.tmpdir(), 'ctf WSL workspace Ω');
  const nativeWorkspace = 'C:\\Users\\Nguyễn User\\Projects\\CTF Workspace Ω';
  try {
    const result = spawnSync(process.execPath, [
      fileURLToPath(new URL('../ide-plan.js', import.meta.url)), '--scope', 'workspace',
      'opencode', 'claude-code', 'codex', 'antigravity',
    ], {
      encoding: 'utf8', maxBuffer: 16 * 1024 * 1024,
      env: {
        ...process.env,
        CTF_AGENT_WINDOWS_HOME: homeDir,
        CTF_AGENT_WINDOWS_HOME_NATIVE: 'C:\\Users\\Nguyễn User',
        CTF_AGENT_WINDOWS_WORKSPACE: wslWorkspace,
        CTF_AGENT_WINDOWS_WORKSPACE_NATIVE: nativeWorkspace,
        CTF_AGENT_WINDOWS_LAUNCHER: 'C:\\Local\\ctf-agent.ps1',
      },
    });
    assert.equal(result.status, 0, result.stderr);
    assert.equal(/[^\x00-\x7f]/.test(result.stdout), false, 'IPC must be ASCII-only for legacy Windows PowerShell');
    const operations = JSON.parse(result.stdout);
    const expectedConfigs = [
      path.win32.join(nativeWorkspace, 'opencode.json'),
      path.win32.join(nativeWorkspace, '.mcp.json'),
      path.win32.join(nativeWorkspace, '.codex', 'config.toml'),
      path.win32.join(nativeWorkspace, '.agents', 'mcp_config.json'),
    ];
    for (const expected of expectedConfigs) assert.ok(operations.some(({ path: destination }) => destination === expected), expected);

    const workspaceSkills = [
      `${path.win32.join(nativeWorkspace, '.agents', 'skills')}\\`,
      `${path.win32.join(nativeWorkspace, '.claude', 'skills')}\\`,
    ];
    for (const { path: destination } of operations) {
      const relative = path.win32.relative(nativeWorkspace, destination);
      assert.ok(relative && relative !== '..' && !relative.startsWith(`..${path.win32.sep}`) && !path.win32.isAbsolute(relative), destination);
      const mapped = path.win32.join(nativeWorkspace, relative);
      assert.equal(destination, mapped);
      if (!expectedConfigs.includes(destination)) {
        assert.ok(workspaceSkills.some((root) => destination.startsWith(root)), destination);
        assert.match(destination, /\\skills\\ctf-[^\\]+\\[^\\]+\.md$/i);
      }
      assert.ok(!destination.startsWith('C:\\Users\\Nguyễn User\\.agents\\'), destination);
    }
  } finally { rmSync(homeDir, { recursive: true, force: true }); }
});

test('Windows agents use a stable local WSL launcher without a public npm package', () => {
  const homeDir = mkdtempSync(path.join(os.tmpdir(), 'ctf-wsl-ide-'));
  try {
    const launcher = 'C:\\Users\\Example User\\AppData\\Local\\CTF-Agent\\ctf-agent.ps1';
    const plan = buildIdeSetupPlan({ clients: ['opencode'], homeDir, packageVersion: '0.1.0', installSkills: false, windowsLauncher: launcher });
    const entry = JSON.parse(plan[0].content).mcp.servers['ctf-agent'];
    assert.deepEqual(entry.command, ['powershell.exe', '-NoLogo', '-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass', '-File', launcher, 'mcp']);
    assert.equal(entry.cwd, '.');
    assert.doesNotMatch(plan[0].content, /npx|ctf-agent@/);
  } finally { rmSync(homeDir, { recursive: true, force: true }); }
});
import { parse as parseToml } from 'smol-toml';
import { applyIdeSetupPlan, buildIdeSetupPlan } from '../ide-setup.js';

function withHome(run) {
  const homeDir = mkdtempSync(path.join(os.tmpdir(), 'ctf-agent-ide-setup-'));
  try {
    run(homeDir);
  } finally {
    rmSync(homeDir, { recursive: true, force: true });
  }
}

function withWorkspace(run) {
  const workspaceDir = mkdtempSync(path.join(os.tmpdir(), 'ctf-agent-workspace-'));
  try {
    withHome((homeDir) => run({ homeDir, workspaceDir }));
  } finally {
    rmSync(workspaceDir, { recursive: true, force: true });
  }
}

function createDirectoryJunction(t, target, link) {
  try {
    symlinkSync(target, link, 'junction');
    return true;
  } catch (error) {
    if (['EACCES', 'ENOSYS', 'ENOTSUP', 'EPERM'].includes(error.code)) {
      t.skip(`directory junction creation unavailable (${error.code})`);
      return false;
    }
    throw error;
  }
}

function configFor(plan, client) {
  return plan.find((operation) => operation.client === client && operation.action === 'merge');
}

test('builds user-level MCP registrations for the four selected clients', () => {
  withHome((homeDir) => {
    const clients = ['opencode', 'claude-code', 'codex', 'antigravity'];
    const plan = buildIdeSetupPlan({ clients, homeDir, packageVersion: '0.1.0', installSkills: false });
    const expectedPaths = {
      opencode: path.join(homeDir, '.config', 'opencode', 'opencode.json'),
      'claude-code': path.join(homeDir, '.claude.json'),
      codex: path.join(homeDir, '.codex', 'config.toml'),
      antigravity: path.join(homeDir, '.gemini', 'config', 'mcp_config.json'),
    };

    for (const client of clients) {
      const operation = configFor(plan, client);
      assert.equal(operation.path, expectedPaths[client]);
      assert.equal(operation.action, 'merge');
      assert.match(operation.content, /ctf-agent(?:-mcp)?@0\.1\.0/);
      if (client !== 'claude-code') assert.match(operation.content, /"cwd"\s*:\s*"\."|cwd\s*=\s*"\."/);
      assert.ok(!operation.content.includes(homeDir));
      if (client === 'opencode') {
        assert.deepEqual(JSON.parse(operation.content).mcp.servers['ctf-agent'].environment, {
          CTF_MCP_CTFD_URL: '{env:CTF_MCP_CTFD_URL}',
          CTF_MCP_CTFD_TOKEN: '{env:CTF_MCP_CTFD_TOKEN}',
        });
      }
    }
  });
});

test('builds workspace-level MCP registrations at each client’s project config path', () => {
  withWorkspace(({ homeDir, workspaceDir }) => {
    const clients = ['opencode', 'claude-code', 'codex', 'antigravity'];
    const plan = buildIdeSetupPlan({ clients, homeDir, workspaceDir, scope: 'workspace', packageVersion: '0.1.0', installSkills: false });
    const expectedPaths = {
      opencode: path.join(workspaceDir, 'opencode.json'),
      'claude-code': path.join(workspaceDir, '.mcp.json'),
      codex: path.join(workspaceDir, '.codex', 'config.toml'),
      antigravity: path.join(workspaceDir, '.agents', 'mcp_config.json'),
    };

    for (const client of clients) {
      assert.equal(configFor(plan, client).path, expectedPaths[client]);
    }
  });
});

test('reuses a workspace OpenCode opencode.jsonc file', () => {
  withWorkspace(({ homeDir, workspaceDir }) => {
    const configPath = path.join(workspaceDir, 'opencode.jsonc');
    writeFileSync(configPath, '{\n  // existing workspace JSONC config\n  "model": "test/model"\n}\n');

    const plan = buildIdeSetupPlan({ clients: ['opencode'], homeDir, workspaceDir, scope: 'workspace', packageVersion: '0.1.0', installSkills: false });
    assert.equal(configFor(plan, 'opencode').path, configPath);
    assert.match(configFor(plan, 'opencode').content, /existing workspace JSONC config/);
  });
});

test('rejects both workspace OpenCode opencode.json and opencode.jsonc files', () => {
  withWorkspace(({ homeDir, workspaceDir }) => {
    writeFileSync(path.join(workspaceDir, 'opencode.json'), '{}\n');
    writeFileSync(path.join(workspaceDir, 'opencode.jsonc'), '{}\n');

    assert.throws(() => buildIdeSetupPlan({
      clients: ['opencode'], homeDir, workspaceDir, scope: 'workspace', packageVersion: '0.1.0', installSkills: false,
    }), /multiple OpenCode workspace config files/);
  });
});

test('plans workspace skills only under the client workspace skill directories', () => {
  withWorkspace(({ homeDir, workspaceDir }) => {
    const clients = ['opencode', 'claude-code', 'codex', 'antigravity'];
    const plan = buildIdeSetupPlan({ clients, homeDir, workspaceDir, scope: 'workspace', packageVersion: '0.1.0' });
    const copies = plan.filter((operation) => operation.action === 'copy');
    const agentSkills = path.join(workspaceDir, '.agents', 'skills') + path.sep;
    const claudeSkills = path.join(workspaceDir, '.claude', 'skills') + path.sep;

    assert.ok(copies.length > 0);
    assert.ok(copies.every(({ path: destination }) => destination.startsWith(agentSkills) || destination.startsWith(claudeSkills)));
    assert.ok(copies.every(({ path: destination }) => !destination.startsWith(homeDir + path.sep)));
    const sharedSkill = copies.find(({ path: destination }) => destination === path.join(workspaceDir, '.agents', 'skills', 'ctf-solve-challenge', 'SKILL.md'));
    assert.ok(sharedSkill);
    assert.deepEqual([...sharedSkill.clients].sort(), ['antigravity', 'codex', 'opencode']);
    const claudeSkill = copies.find(({ path: destination }) => destination === path.join(workspaceDir, '.claude', 'skills', 'ctf-solve-challenge', 'SKILL.md'));
    assert.ok(claudeSkill);
    assert.deepEqual(claudeSkill.clients, ['claude-code']);
  });
});

test('requires an absolute workspace root and a recognized setup scope', () => {
  withHome((homeDir) => {
    const options = { clients: ['opencode'], homeDir, packageVersion: '0.1.0', installSkills: false };
    assert.throws(() => buildIdeSetupPlan({ ...options, scope: 'workspace' }), /workspaceDir must be an absolute path/);
    assert.throws(() => buildIdeSetupPlan({ ...options, scope: 'workspace', workspaceDir: 'relative' }), /workspaceDir must be an absolute path/);
    assert.throws(() => buildIdeSetupPlan({ ...options, scope: 'local' }), /scope must be global or workspace/);
  });
});

test('rejects an existing workspace destination ancestor junction while planning', (t) => {
  withWorkspace(({ homeDir, workspaceDir }) => {
    const redirectedDir = path.join(homeDir, '.gemini', 'config');
    mkdirSync(redirectedDir, { recursive: true });
    if (!createDirectoryJunction(t, redirectedDir, path.join(workspaceDir, '.agents'))) return;

    assert.throws(() => buildIdeSetupPlan({
      clients: ['antigravity'], homeDir, workspaceDir, scope: 'workspace', packageVersion: '0.1.0', installSkills: false,
    }), /workspace path.*symbolic link|workspace path.*reparse/i);
    assert.equal(existsSync(path.join(redirectedDir, 'mcp_config.json')), false);
  });
});

test('apply rejects a workspace ancestor junction added after planning before writing through it', (t) => {
  withWorkspace(({ homeDir, workspaceDir }) => {
    const redirectedDir = path.join(homeDir, '.gemini', 'config');
    mkdirSync(redirectedDir, { recursive: true });
    const redirectedConfig = path.join(redirectedDir, 'mcp_config.json');
    const plan = buildIdeSetupPlan({
      clients: ['antigravity'], homeDir, workspaceDir, scope: 'workspace', packageVersion: '0.1.0', installSkills: false,
    });
    if (!createDirectoryJunction(t, redirectedDir, path.join(workspaceDir, '.agents'))) return;

    assert.throws(() => applyIdeSetupPlan(plan, { confirm: true }), /workspace path.*symbolic link|workspace path.*reparse/i);
    assert.equal(existsSync(redirectedConfig), false);
  });
});

test('rejects a workspace root that is a directory junction', (t) => {
  withWorkspace(({ homeDir, workspaceDir }) => {
    const redirectedDir = path.join(homeDir, '.gemini', 'config');
    mkdirSync(redirectedDir, { recursive: true });
    rmSync(workspaceDir, { recursive: true, force: true });
    if (!createDirectoryJunction(t, redirectedDir, workspaceDir)) return;

    assert.throws(() => buildIdeSetupPlan({
      clients: ['antigravity'], homeDir, workspaceDir, scope: 'workspace', packageVersion: '0.1.0', installSkills: false,
    }), /workspace path.*symbolic link|workspace path.*reparse/i);
    assert.equal(existsSync(path.join(redirectedDir, 'mcp_config.json')), false);
  });
});

test('merges existing OpenCode JSONC without dropping comments or unrelated settings', () => {
  withHome((homeDir) => {
    const configPath = path.join(homeDir, '.config', 'opencode', 'opencode.json');
    mkdirSync(path.dirname(configPath), { recursive: true });
    writeFileSync(configPath, '{\n  // keep this comment\n  "model": "test/model",\n  "mcp": { "servers": { "other": { "disabled": true } } }\n}\n');

    const plan = buildIdeSetupPlan({ clients: ['opencode'], homeDir, packageVersion: '0.1.0', installSkills: false });
    const content = configFor(plan, 'opencode').content;
    assert.match(content, /keep this comment/);
    assert.match(content, /test\/model/);
    assert.match(content, /"other"/);
    assert.match(content, /"ctf-agent"/);
  });
});

test('updates an existing OpenCode opencode.jsonc instead of creating a parallel config', () => {
  withHome((homeDir) => {
    const configPath = path.join(homeDir, '.config', 'opencode', 'opencode.jsonc');
    mkdirSync(path.dirname(configPath), { recursive: true });
    writeFileSync(configPath, '{\n  // existing JSONC config\n  "model": "test/model"\n}\n');
    const plan = buildIdeSetupPlan({ clients: ['opencode'], homeDir, packageVersion: '0.1.0', installSkills: false });
    assert.equal(configFor(plan, 'opencode').path, configPath);
    assert.match(configFor(plan, 'opencode').content, /existing JSONC config/);
  });
});

test('replaces only the Codex MCP table and keeps unrelated TOML text', () => {
  withHome((homeDir) => {
    const configPath = path.join(homeDir, '.codex', 'config.toml');
    mkdirSync(path.dirname(configPath), { recursive: true });
    const original = '# keep this comment\nmodel = "test/model"\n\n[mcp_servers.ctf_agent]\ncommand = "npx"\nargs = ["-y", "ctf-agent-mcp@0.0.1", "mcp"]\n\n[mcp_servers.ctf_agent.env]\nOLD = "value"\n\n[mcp_servers.other]\ncommand = "keep"\n';
    writeFileSync(configPath, original);

    const plan = buildIdeSetupPlan({ clients: ['codex'], homeDir, packageVersion: '0.1.0', installSkills: false });
    const content = configFor(plan, 'codex').content;
    const parsed = parseToml(content);
    assert.equal(parsed.model, 'test/model');
    assert.equal(parsed.mcp_servers.ctf_agent.command, 'npx');
    assert.equal(parsed.mcp_servers.ctf_agent.args[0], '-y');
    assert.match(parsed.mcp_servers.ctf_agent.args[1], /^(?:@nvtruongops\/)?ctf-agent(?:-mcp)?@0\.1\.0$/);
    assert.equal(parsed.mcp_servers.ctf_agent.args[2], 'mcp');
    assert.equal(parsed.mcp_servers.other.command, 'keep', content);
    assert.match(content, /keep this comment/);
  });
});

test('rejects malformed host configuration instead of replacing it', () => {
  withHome((homeDir) => {
    const configPath = path.join(homeDir, '.config', 'opencode', 'opencode.json');
    mkdirSync(path.dirname(configPath), { recursive: true });
    writeFileSync(configPath, '{ broken');
    assert.throws(() => buildIdeSetupPlan({
      clients: ['opencode'], homeDir, packageVersion: '0.1.0', installSkills: false,
    }), /invalid.*opencode/i);
    assert.equal(readFileSync(configPath, 'utf8'), '{ broken');
  });
});

test('refuses to overwrite an unrelated MCP server with the reserved CTF-Agent name', () => {
  withHome((homeDir) => {
    const configPath = path.join(homeDir, '.gemini', 'config', 'mcp_config.json');
    mkdirSync(path.dirname(configPath), { recursive: true });
    writeFileSync(configPath, '{"mcpServers":{"ctf-agent":{"command":"other-server"}}}\n');
    assert.throws(() => buildIdeSetupPlan({
      clients: ['antigravity'], homeDir, packageVersion: '0.1.0', installSkills: false,
    }), /already used|unrelated/i);
    assert.equal(JSON.parse(readFileSync(configPath, 'utf8')).mcpServers['ctf-agent'].command, 'other-server');
  });
});

test('dry-run does not write, and confirmed apply backs up existing config first', () => {
  withHome((homeDir) => {
    const configPath = path.join(homeDir, '.gemini', 'config', 'mcp_config.json');
    mkdirSync(path.dirname(configPath), { recursive: true });
    const original = '{"mcpServers":{"other":{"command":"keep"}}}\n';
    writeFileSync(configPath, original);
    const plan = buildIdeSetupPlan({ clients: ['antigravity'], homeDir, packageVersion: '0.1.0', installSkills: false });

    assert.equal(applyIdeSetupPlan(plan, { confirm: false }).applied, false);
    assert.equal(readFileSync(configPath, 'utf8'), original);

    const result = applyIdeSetupPlan(plan, { confirm: true });
    assert.equal(result.applied, true);
    assert.ok(result.backups.includes(configPath + '.bak'));
    assert.equal(readFileSync(configPath + '.bak', 'utf8'), original);
    const saved = JSON.parse(readFileSync(configPath, 'utf8'));
    assert.equal(saved.mcpServers.other.command, 'keep');
    assert.equal(saved.mcpServers['ctf-agent'].cwd, '.');
  });
});

test('apply refuses a destination changed after preview', () => {
  withHome((homeDir) => {
    const configPath = path.join(homeDir, '.gemini', 'config', 'mcp_config.json');
    mkdirSync(path.dirname(configPath), { recursive: true });
    writeFileSync(configPath, '{"existing":true}\n');
    const plan = buildIdeSetupPlan({ clients: ['antigravity'], homeDir, packageVersion: '0.1.0', installSkills: false });
    writeFileSync(configPath, '{"userChange":true}\n');

    assert.throws(() => applyIdeSetupPlan(plan, { confirm: true }), /changed after preview/);
    assert.equal(readFileSync(configPath, 'utf8'), '{"userChange":true}\n');
  });
});

test('deduplicates shared global skill roots and preserves their relative paths', () => {
  withHome((homeDir) => {
    const plan = buildIdeSetupPlan({
      clients: ['opencode', 'codex', 'opencode'],
      homeDir,
      packageVersion: '0.1.0',
      installSkills: true,
    });
    const solverSkill = plan.filter((operation) => operation.path.endsWith(path.join('ctf-solve-challenge', 'SKILL.md')));
    assert.equal(solverSkill.length, 1);
    assert.equal(solverSkill[0].path, path.join(homeDir, '.agents', 'skills', 'ctf-solve-challenge', 'SKILL.md'));
    assert.ok(plan.some((operation) => operation.path.endsWith(path.join('references', 'ctf-triage-ladder.md'))));
    assert.ok(plan.some((operation) => operation.path.endsWith(path.join('rules', 'flag-validation-rules.md'))));
  });
});
