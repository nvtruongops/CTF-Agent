import assert from 'node:assert/strict';
import { mkdtempSync, mkdirSync, readFileSync, readdirSync, rmSync, writeFileSync } from 'node:fs';
import { spawnSync } from 'node:child_process';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import test from 'node:test';

const repoRoot = fileURLToPath(new URL('../../', import.meta.url));

test('CLI help lists the doctor, setup, and MCP commands', () => {
  const result = spawnSync(process.execPath, ['ctf_mcp/cli.js', '--help'], {
    cwd: repoRoot,
    encoding: 'utf8',
  });

  assert.equal(result.status, 0, result.stderr);
  assert.match(result.stdout, /doctor/);
  assert.match(result.stdout, /setup/);
  assert.match(result.stdout, /mcp/);
});

test('doctor --json returns readiness data without requiring Kali to be installed', () => {
  const result = spawnSync(process.execPath, ['ctf_mcp/cli.js', 'doctor', '--json'], {
    cwd: repoRoot,
    encoding: 'utf8',
    timeout: 60_000,
  });

  assert.equal(result.status, 0, result.stderr);
  const report = JSON.parse(result.stdout);
  assert.ok(report.node);
  assert.ok(report.wsl);
  assert.ok(report.kali);
  assert.ok(Array.isArray(report.distributions));
  assert.ok(Array.isArray(report.categories));
});

test('setup --plan --json prints package and action plans without applying them', () => {
  const result = spawnSync(process.execPath, [
    'ctf_mcp/cli.js', 'setup', '--plan', '--profile', 'full', '--json',
  ], {
    cwd: repoRoot,
    encoding: 'utf8',
    timeout: 60_000,
  });

  assert.equal(result.status, 0, result.stderr);
  const plan = JSON.parse(result.stdout);
  assert.equal(plan.profile, 'full');
  assert.ok(Array.isArray(plan.packages));
  assert.ok(Array.isArray(plan.actions));
  assert.ok(['pending_kali', 'pending_wsl2', 'ready_to_apply', 'ready', 'blocked'].includes(plan.status));
  if (plan.packageAvailability?.unknown?.length === 0 && plan.packageAvailability?.unavailable?.length === 0) {
    assert.equal(plan.actions.some((action) => action.id === 'apt_update'), false);
  }
});

test('setup IDE dry-run previews the selected client without writing user config', () => {
  const homeDir = mkdtempSync(path.join(os.tmpdir(), 'ctf-agent-cli-'));
  try {
    const result = spawnSync(process.execPath, [
      'ctf_mcp/cli.js', 'setup', '--client', 'antigravity', '--dry-run', '--skills=false',
    ], {
      cwd: repoRoot,
      encoding: 'utf8',
      env: { ...process.env, USERPROFILE: homeDir },
    });
    assert.equal(result.status, 0, result.stderr);
    assert.match(result.stdout, /antigravity/);
    assert.match(result.stdout, /dry run/i);
    assert.deepEqual(readdirSync(homeDir), []);
  } finally {
    rmSync(homeDir, { recursive: true, force: true });
  }
});

test('setup --all-detected only selects clients with existing user config directories', () => {
  const homeDir = mkdtempSync(path.join(os.tmpdir(), 'ctf-agent-cli-detected-'));
  try {
    mkdirSync(path.join(homeDir, '.codex'), { recursive: true });
    writeFileSync(path.join(homeDir, '.codex', 'config.toml'), 'model = "existing"\n');
    const result = spawnSync(process.execPath, [
      'ctf_mcp/cli.js', 'setup', '--all-detected', '--dry-run', '--skills=false',
    ], {
      cwd: repoRoot,
      encoding: 'utf8',
      env: { ...process.env, USERPROFILE: homeDir },
    });
    assert.equal(result.status, 0, result.stderr);
    assert.match(result.stdout, /codex/);
    assert.doesNotMatch(result.stdout, /opencode|claude-code|antigravity/);
    assert.equal(readFileSync(path.join(homeDir, '.codex', 'config.toml'), 'utf8'), 'model = "existing"\n');
  } finally {
    rmSync(homeDir, { recursive: true, force: true });
  }
});

test('setup --yes applies only the selected client config and never writes credential values', () => {
  const homeDir = mkdtempSync(path.join(os.tmpdir(), 'ctf-agent-cli-apply-'));
  try {
    const result = spawnSync(process.execPath, [
      'ctf_mcp/cli.js', 'setup', '--client', 'antigravity', '--yes', '--skills=false',
    ], {
      cwd: repoRoot,
      encoding: 'utf8',
      env: { ...process.env, USERPROFILE: homeDir, CTF_MCP_CTFD_TOKEN: 'do-not-write-this-token' },
    });
    assert.equal(result.status, 0, result.stderr);
    const configPath = path.join(homeDir, '.gemini', 'config', 'mcp_config.json');
    const config = JSON.parse(readFileSync(configPath, 'utf8'));
    assert.equal(config.mcpServers['ctf-agent'].cwd, '.');
    assert.match(config.mcpServers['ctf-agent'].args[1], /^ctf-agent@/);
    assert.doesNotMatch(readFileSync(configPath, 'utf8'), /do-not-write-this-token/);
  } finally {
    rmSync(homeDir, { recursive: true, force: true });
  }
});

test('scope init honors the explicit active workspace root environment variable', () => {
  const projectRoot = mkdtempSync(path.join(os.tmpdir(), 'ctf-agent-project-root-'));
  try {
    const result = spawnSync(process.execPath, [
      'ctf_mcp/cli.js', 'scope', 'init', '--challenge', 'env-root', '--workspace', '.ctf-workspaces/env-root',
    ], {
      cwd: repoRoot,
      encoding: 'utf8',
      env: { ...process.env, CTF_AGENT_PROJECT_ROOT: projectRoot },
    });
    assert.equal(result.status, 0, result.stderr);
    assert.ok(readFileSync(path.join(projectRoot, '.ctf-agent', 'scope.json'), 'utf8'));
  } finally {
    rmSync(projectRoot, { recursive: true, force: true });
  }
});

test('IDE setup rejects unsupported clients and duplicate switches without writing', () => {
  const homeDir = mkdtempSync(path.join(os.tmpdir(), 'ctf-agent-cli-invalid-'));
  try {
    const invalidClient = spawnSync(process.execPath, [
      'ctf_mcp/cli.js', 'setup', '--client', 'unknown', '--dry-run',
    ], { cwd: repoRoot, encoding: 'utf8', env: { ...process.env, USERPROFILE: homeDir } });
    assert.equal(invalidClient.status, 2);
    assert.match(invalidClient.stderr, /supported clients/);

    const duplicate = spawnSync(process.execPath, [
      'ctf_mcp/cli.js', 'setup', '--client', 'opencode', '--dry-run', '--dry-run',
    ], { cwd: repoRoot, encoding: 'utf8', env: { ...process.env, USERPROFILE: homeDir } });
    assert.equal(duplicate.status, 2);
    assert.deepEqual(readdirSync(homeDir), []);
  } finally {
    rmSync(homeDir, { recursive: true, force: true });
  }
});

test('setup without mode requires an interactive choice or explicit clients', () => {
  const result = spawnSync(process.execPath, ['ctf_mcp/cli.js', 'setup'], {
    cwd: repoRoot,
    encoding: 'utf8',
  });
  assert.equal(result.status, 2);
  assert.match(result.stderr, /interactive|--client/i);
});
