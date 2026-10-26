import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
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
