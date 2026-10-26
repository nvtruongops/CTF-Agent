import assert from 'node:assert/strict';
import { mkdtempSync, mkdirSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';
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
