import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { existsSync, mkdtempSync, rmSync, statSync } from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import test from 'node:test';

const root = fileURLToPath(new URL('../../', import.meta.url));

test('native prerequisite installer refuses an unprivileged apply before touching packages', { skip: process.platform !== 'linux' || process.getuid?.() === 0 }, () => {
  const result = spawnSync('/bin/bash', [path.join(root, 'scripts', 'setup-wsl.sh'), 'prerequisites'], { encoding: 'utf8', timeout: 5000 });
  assert.notEqual(result.status, 0);
  assert.match(result.stderr, /requires root/);
});

test('Windows clone bootstrap previews without writing configuration or requiring Windows Node in its process', { skip: process.platform !== 'win32' }, () => {
  const home = mkdtempSync(path.join(os.tmpdir(), 'ctf bootstrap '));
  try {
    const result = spawnSync('powershell.exe', ['-NoLogo', '-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass', '-File', path.join(root, 'setup.ps1'), '-Client', 'opencode'], {
      cwd: root, encoding: 'utf8', timeout: 30_000,
      env: { ...process.env, USERPROFILE: home, LOCALAPPDATA: home, PATH: `${process.env.SystemRoot}\\System32;${process.env.SystemRoot}\\System32\\WindowsPowerShell\\v1.0` },
    });
    assert.equal(result.status, 0, result.stderr);
    const plan = JSON.parse(result.stdout);
    assert.ok(['ready_to_apply', 'pending_wsl2'].includes(plan.status));
    assert.deepEqual(plan.windowsClients, ['opencode']);
    assert.equal(plan.runtimeUser, 'ctfagent');
    assert.equal(plan.launcher, path.join(home, 'CTF-Agent', 'ctf-agent.ps1'));
    assert.equal(existsSync(path.join(home, 'CTF-Agent')), false);
    assert.equal(existsSync(path.join(home, '.config', 'opencode')), false);
  } finally { rmSync(home, { recursive: true, force: true }); }
});

test('missing WSL reports a pending state and apply stops before configuration writes', { skip: process.platform !== 'win32' }, () => {
  const home = mkdtempSync(path.join(os.tmpdir(), 'ctf pending '));
  try {
    const args = ['-NoLogo', '-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass', '-File', path.join(root, 'setup.ps1')];
    const options = { cwd: root, encoding: 'utf8', timeout: 30_000, env: { ...process.env, USERPROFILE: home, LOCALAPPDATA: home, PATH: home } };
    const powershell = path.join(process.env.SystemRoot, 'System32', 'WindowsPowerShell', 'v1.0', 'powershell.exe');
    const preview = spawnSync(powershell, args, options);
    assert.equal(preview.status, 0, preview.stderr);
    assert.equal(JSON.parse(preview.stdout).status, 'pending_wsl2');
    const apply = spawnSync(powershell, [...args, '-Apply'], options);
    assert.notEqual(apply.status, 0);
    assert.match(apply.stderr, /wsl --install|reboot/i);
    assert.equal(existsSync(path.join(home, 'CTF-Agent')), false);
  } finally { rmSync(home, { recursive: true, force: true }); }
});

test('launcher fixes distro/user and forwards active project and optional environment without banners', { skip: process.platform !== 'win32' }, () => {
  const home = mkdtempSync(path.join(os.tmpdir(), 'ctf launcher '));
  try {
    const result = spawnSync('powershell.exe', ['-NoLogo', '-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass', '-Command', `
      function wsl.exe { [pscustomobject]@{args=@($args);root=$env:CTF_AGENT_PROJECT_ROOT;forward=$env:WSLENV} | ConvertTo-Json -Compress; $global:LASTEXITCODE=0 }
      & $env:CTF_TEST_LAUNCHER mcp
    `], { cwd: home, encoding: 'utf8', timeout: 30_000, env: { ...process.env, CTF_TEST_LAUNCHER: path.join(root, 'scripts', 'launch-wsl.ps1'), WSLENV: 'EXISTING/u:CTF_MCP_CTFD_TOKEN/p' } });
    assert.equal(result.status, 0, result.stderr);
    const captured = JSON.parse(result.stdout);
    assert.deepEqual(captured.args.slice(0, 5), ['--distribution', 'kali-linux', '--user', 'ctfagent', '--cd']);
    assert.equal(captured.args[5], captured.root);
    assert.equal(captured.args.at(-1), 'mcp');
    assert.equal(statSync(captured.root).ino, statSync(home).ino, 'short and long Windows paths must address the same project');
    assert.equal(captured.forward, 'EXISTING/u:CTF_AGENT_PROJECT_ROOT/p:CTF_MCP_CTFD_URL/u:CTF_MCP_CTFD_TOKEN/u');
  } finally { rmSync(home, { recursive: true, force: true }); }
});

test('Windows config writer backs up changes, is idempotent and rejects stale or escaping plans', { skip: process.platform !== 'win32' }, () => {
  const home = mkdtempSync(path.join(os.tmpdir(), 'ctf writer '));
  try {
    const result = spawnSync('powershell.exe', ['-NoLogo', '-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass', '-Command', `
      $ErrorActionPreference='Stop'
      . $env:CTF_TEST_WRITER
      $file=Join-Path $env:CTF_TEST_HOME '.config/opencode/opencode.json'
      New-Item -ItemType Directory -Path (Split-Path $file) -Force | Out-Null
      $defaults=@{HomeDirectory=$env:CTF_TEST_HOME;Clients=@('opencode');RepositoryRoot=$env:CTF_TEST_REPO}
      [IO.File]::WriteAllText($file,'original')
      $plan=[pscustomobject]@{path=$file;content='updated';originalHash=(Get-CtfContentHash 'original')}
      Apply-CtfIdePlan -Plan @($plan) @defaults
      if ([IO.File]::ReadAllText($file+'.bak') -ne 'original') {throw 'Missing original backup'}
      $plan.originalHash=Get-CtfContentHash 'updated'
      Apply-CtfIdePlan -Plan @($plan) @defaults
      if (Test-Path ($file+'.bak.1')) {throw 'Unchanged setup created another backup'}
      $plan.originalHash='stale'
      $rejected=$false
      try {Apply-CtfIdePlan -Plan @($plan) @defaults} catch {$rejected=$true}
      if (!$rejected -or [IO.File]::ReadAllText($file) -ne 'updated') {throw 'Stale plan was not rejected'}
      $plan.path=Join-Path $env:CTF_TEST_HOME 'unrelated-profile.ps1'
      $plan.originalHash=$null
      $rejected=$false
      try {Apply-CtfIdePlan -Plan @($plan) @defaults} catch {$rejected=$true}
      if (!$rejected -or (Test-Path $plan.path)) {throw 'Unrelated home destination was not rejected'}
      $plan.path=Join-Path $env:CTF_TEST_HOME '.codex/config.toml'
      $rejected=$false
      try {Apply-CtfIdePlan -Plan @($plan) @defaults} catch {$rejected=$true}
      if (!$rejected) {throw 'Unselected client was not rejected'}
      Write-Output 'writer checks passed'
    `], { encoding: 'utf8', timeout: 30_000, env: { ...process.env, CTF_TEST_HOME: home, CTF_TEST_REPO: root, CTF_TEST_WRITER: path.join(root, 'scripts', 'apply-ide-plan.ps1') } });
    assert.equal(result.status, 0, result.stderr);
    assert.match(result.stdout, /writer checks passed/);
  } finally { rmSync(home, { recursive: true, force: true }); }
});

test('bootstrap never executes the ctfagent-owned JavaScript runtime as root', { skip: process.platform !== 'win32' }, () => {
  const home = mkdtempSync(path.join(os.tmpdir(), 'ctf privilege '));
  try {
    const result = spawnSync('powershell.exe', ['-NoLogo', '-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass', '-Command', `
      $ErrorActionPreference='Stop'
      function wsl.exe {
        if ($args -contains '--list') {Write-Output 'kali-linux Running 2'}
        elseif ($args -contains '/usr/bin/wslpath') {Write-Output '/mnt/c/fixture'}
        elseif ($args[3] -eq 'root' -and $args -contains '/usr/bin/node') {throw 'Untrusted runtime executed as root'}
        elseif (($args -join ' ') -match 'ide-plan.js') {Write-Output '[]'}
        $global:LASTEXITCODE=0
      }
      & $env:CTF_TEST_SETUP -Apply -Client opencode
    `], { encoding: 'utf8', timeout: 30_000, env: { ...process.env, USERPROFILE: home, LOCALAPPDATA: home, CTF_TEST_SETUP: path.join(root, 'setup.ps1') } });
    assert.equal(result.status, 0, result.stderr);
  } finally { rmSync(home, { recursive: true, force: true }); }
});
