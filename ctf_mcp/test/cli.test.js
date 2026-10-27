import assert from 'node:assert/strict';
import { existsSync, mkdtempSync, mkdirSync, readFileSync, readdirSync, rmSync, writeFileSync } from 'node:fs';
import { spawnSync } from 'node:child_process';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import test from 'node:test';

const repoRoot = fileURLToPath(new URL('../../', import.meta.url));

function runInteractiveCli(args, { cwd, homeDir, input }) {
  const cliPath = path.join(repoRoot, 'ctf_mcp/cli.js');
  const bootstrap = `
    import { stdin, stdout } from 'node:process';
    Object.defineProperty(stdin, 'isTTY', { value: true });
    Object.defineProperty(stdout, 'isTTY', { value: true });
    stdin.setRawMode = () => {};
    stdout.columns = 80;
    process.argv = [process.execPath, ${JSON.stringify(cliPath)}, ...${JSON.stringify(args)}];
    await import(${JSON.stringify(pathToFileURL(cliPath).href)});
  `;
  return spawnSync(process.execPath, ['--input-type=module', '--eval', bootstrap], {
    cwd,
    input,
    encoding: 'utf8',
    timeout: 30_000,
    env: { ...process.env, USERPROFILE: homeDir, CTF_AGENT_WINDOWS_HOME: homeDir },
  });
}

test('CLI help lists the doctor, setup, and MCP commands', () => {
  const result = spawnSync(process.execPath, ['ctf_mcp/cli.js', '--help'], {
    cwd: repoRoot,
    encoding: 'utf8',
  });

  assert.equal(result.status, 0, result.stderr);
  assert.match(result.stdout, /doctor/);
  assert.match(result.stdout, /setup/);
  assert.match(result.stdout, /ctf-agent init.*workspace/i);
  assert.match(result.stdout, /scope init.*challenge/i);
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
      'ctf_mcp/cli.js', 'setup', '--client', 'antigravity', '--scope', 'global', '--dry-run', '--skills=false',
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
      'ctf_mcp/cli.js', 'setup', '--all-detected', '--scope', 'global', '--dry-run', '--skills=false',
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
      'ctf_mcp/cli.js', 'setup', '--client', 'antigravity', '--scope', 'global', '--yes', '--skills=false',
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
      'ctf_mcp/cli.js', 'setup', '--client', 'unknown', '--scope', 'global', '--dry-run',
    ], { cwd: repoRoot, encoding: 'utf8', env: { ...process.env, USERPROFILE: homeDir } });
    assert.equal(invalidClient.status, 2);
    assert.match(invalidClient.stderr, /supported clients/);

    const duplicate = spawnSync(process.execPath, [
      'ctf_mcp/cli.js', 'setup', '--client', 'opencode', '--scope', 'global', '--dry-run', '--dry-run',
    ], { cwd: repoRoot, encoding: 'utf8', env: { ...process.env, USERPROFILE: homeDir } });
    assert.equal(duplicate.status, 2);
    assert.deepEqual(readdirSync(homeDir), []);
  } finally {
    rmSync(homeDir, { recursive: true, force: true });
  }
});

test('init registers Antigravity MCP and skills in the current workspace, not the user home', () => {
  const workspaceDir = mkdtempSync(path.join(os.tmpdir(), 'ctf-agent-init-workspace-'));
  const homeDir = mkdtempSync(path.join(os.tmpdir(), 'ctf-agent-init-home-'));
  try {
    const result = spawnSync(process.execPath, [
      path.join(repoRoot, 'ctf_mcp/cli.js'), 'init', '--client', 'antigravity', '--yes',
    ], {
      cwd: workspaceDir,
      encoding: 'utf8',
      env: { ...process.env, USERPROFILE: homeDir, CTF_AGENT_WINDOWS_HOME: homeDir },
    });
    assert.equal(result.status, 0, result.stderr);
    const configPath = path.join(workspaceDir, '.agents', 'mcp_config.json');
    const config = JSON.parse(readFileSync(configPath, 'utf8'));
    assert.equal(config.mcpServers['ctf-agent'].cwd, '.');
    assert.ok(readFileSync(path.join(workspaceDir, '.agents', 'skills', 'ctf-solve-challenge', 'SKILL.md'), 'utf8').length > 0);
    assert.deepEqual(readdirSync(homeDir), []);
  } finally {
    rmSync(workspaceDir, { recursive: true, force: true });
    rmSync(homeDir, { recursive: true, force: true });
  }
});

test('setup previews workspace and global IDE destinations for the selected scope', () => {
  const workspaceDir = mkdtempSync(path.join(os.tmpdir(), 'ctf-agent-setup-workspace-'));
  const homeDir = mkdtempSync(path.join(os.tmpdir(), 'ctf-agent-setup-home-'));
  try {
    const runSetup = (scope) => spawnSync(process.execPath, [
      path.join(repoRoot, 'ctf_mcp/cli.js'), 'setup', '--client', 'antigravity', '--scope', scope, '--dry-run', '--skills=false',
    ], {
      cwd: workspaceDir,
      encoding: 'utf8',
      env: { ...process.env, USERPROFILE: homeDir, CTF_AGENT_WINDOWS_HOME: homeDir },
    });

    const workspace = runSetup('workspace');
    assert.equal(workspace.status, 0, workspace.stderr);
    assert.ok(workspace.stdout.includes(path.join(workspaceDir, '.agents', 'mcp_config.json')), workspace.stdout);

    const global = runSetup('global');
    assert.equal(global.status, 0, global.stderr);
    assert.ok(global.stdout.includes(path.join(homeDir, '.gemini', 'config', 'mcp_config.json')), global.stdout);
    assert.deepEqual(readdirSync(workspaceDir), []);
    assert.deepEqual(readdirSync(homeDir), []);
  } finally {
    rmSync(workspaceDir, { recursive: true, force: true });
    rmSync(homeDir, { recursive: true, force: true });
  }
});

test('interactive setup applies the scope selected through the TTY prompt', () => {
  for (const scope of ['workspace', 'global']) {
    const workspaceDir = mkdtempSync(path.join(os.tmpdir(), `ctf-agent-tty-${scope}-workspace-`));
    const homeDir = mkdtempSync(path.join(os.tmpdir(), `ctf-agent-tty-${scope}-home-`));
    try {
      const result = runInteractiveCli(
        ['setup', '--client', 'antigravity', '--yes', '--skills=false'],
        { cwd: workspaceDir, homeDir, input: `${scope}\n` },
      );
      assert.equal(result.status, 0, result.stderr);

      const workspaceConfig = path.join(workspaceDir, '.agents', 'mcp_config.json');
      const globalConfig = path.join(homeDir, '.gemini', 'config', 'mcp_config.json');
      const selectedConfig = scope === 'workspace' ? workspaceConfig : globalConfig;
      const otherRoot = scope === 'workspace' ? homeDir : workspaceDir;
      const config = JSON.parse(readFileSync(selectedConfig, 'utf8'));
      assert.equal(config.mcpServers['ctf-agent'].cwd, '.');
      assert.deepEqual(readdirSync(otherRoot), []);
      assert.equal(existsSync(scope === 'workspace' ? globalConfig : workspaceConfig), false);
      assert.match(result.stdout, /Register CTF-Agent for this workspace or globally/);
    } finally {
      rmSync(workspaceDir, { recursive: true, force: true });
      rmSync(homeDir, { recursive: true, force: true });
    }
  }
});

test('non-interactive setup requires one valid scope and rejects duplicate scope options without writes', () => {
  const workspaceDir = mkdtempSync(path.join(os.tmpdir(), 'ctf-agent-setup-invalid-workspace-'));
  const homeDir = mkdtempSync(path.join(os.tmpdir(), 'ctf-agent-setup-invalid-home-'));
  try {
    const invalidCases = [
      { args: ['--client', 'antigravity', '--yes', '--skills=false'], message: /scope/i },
      { args: ['--client', 'antigravity', '--scope', 'local', '--yes', '--skills=false'], message: /scope/i },
      { args: ['--client', 'antigravity', '--scope', 'workspace', '--scope', 'global', '--yes'], message: /duplicate.*scope|scope.*duplicate/i },
    ];
    for (const { args, message } of invalidCases) {
      const result = spawnSync(process.execPath, [path.join(repoRoot, 'ctf_mcp/cli.js'), 'setup', ...args], {
        cwd: workspaceDir,
        encoding: 'utf8',
        env: { ...process.env, USERPROFILE: homeDir, CTF_AGENT_WINDOWS_HOME: homeDir },
      });
      assert.equal(result.status, 2, result.stderr);
      assert.match(result.stderr, message);
      assert.deepEqual(readdirSync(workspaceDir), []);
      assert.deepEqual(readdirSync(homeDir), []);
    }
  } finally {
    rmSync(workspaceDir, { recursive: true, force: true });
    rmSync(homeDir, { recursive: true, force: true });
  }
});

test('setup without mode requires an interactive choice or explicit clients', () => {
  const result = spawnSync(process.execPath, ['ctf_mcp/cli.js', 'setup', '--scope', 'global'], {
    cwd: repoRoot,
    encoding: 'utf8',
  });
  assert.equal(result.status, 2);
  assert.match(result.stderr, /interactive|--client/i);
});
