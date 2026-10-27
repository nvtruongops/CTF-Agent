import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { mkdtempSync, rmSync } from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import test from 'node:test';

const repositoryRoot = fileURLToPath(new URL('../../', import.meta.url));
const powershell = process.platform === 'win32' ? 'powershell.exe' : 'pwsh';
const powerShellAvailable = process.platform === 'win32' && spawnSync(powershell, ['-NoLogo', '-NoProfile', '-NonInteractive', '-Command', '$PSVersionTable.PSVersion.ToString()'], {
  encoding: 'utf8', timeout: 10_000,
}).status === 0;

function withRoots(run) {
  const home = mkdtempSync(path.join(os.tmpdir(), 'ctf user home '));
  const workspace = mkdtempSync(path.join(os.tmpdir(), 'ctf workspace '));
  const outside = mkdtempSync(path.join(os.tmpdir(), 'ctf outside '));
  try {
    run({ home, workspace, outside });
  } finally {
    rmSync(home, { recursive: true, force: true });
    rmSync(workspace, { recursive: true, force: true });
    rmSync(outside, { recursive: true, force: true });
  }
}

function runPowerShell(script, { home, workspace, outside, cwd = repositoryRoot }) {
  return spawnSync(powershell, [
    '-NoLogo', '-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass', '-Command', script,
  ], {
    cwd, encoding: 'utf8', timeout: 30_000,
    env: {
      ...process.env,
      CTF_TEST_APPLY_SCRIPT: path.join(repositoryRoot, 'scripts', 'apply-ide-plan.ps1'),
      CTF_TEST_SETUP: path.join(repositoryRoot, 'setup.ps1'),
      CTF_TEST_REPO: repositoryRoot,
      CTF_TEST_HOME: home,
      CTF_TEST_WORKSPACE: workspace,
      CTF_TEST_OUTSIDE: outside,
      USERPROFILE: home,
      LOCALAPPDATA: home,
    },
  });
}

function assertPowerShellPass(result) {
  assert.equal(result.status, 0, `${result.stdout}\n${result.stderr}`);
}

test('PowerShell apply accepts only selected workspace MCP and bundled skill files', { skip: !powerShellAvailable }, () => {
  withRoots((roots) => {
    const result = runPowerShell(`
      $ErrorActionPreference = 'Stop'
      . $env:CTF_TEST_APPLY_SCRIPT
      $config = Join-Path $env:CTF_TEST_WORKSPACE 'opencode.json'
      $skill = Join-Path $env:CTF_TEST_WORKSPACE '.agents/skills/ctf-solve-challenge/SKILL.md'
      $skillSource = Join-Path $env:CTF_TEST_REPO '.agents/skills/ctf-solve-challenge/SKILL.md'
      $operations = @(
        [pscustomobject]@{path=$config; content='{"mcp":{"servers":{"ctf-agent":{}}}}'; originalHash=$null},
        [pscustomobject]@{path=$skill; content=[IO.File]::ReadAllText($skillSource, [Text.Encoding]::UTF8); originalHash=$null}
      )
      Apply-CtfIdePlan -Plan $operations -HomeDirectory $env:CTF_TEST_HOME -Clients @('opencode') -RepositoryRoot $env:CTF_TEST_REPO -Scope workspace -WorkspacePath $env:CTF_TEST_WORKSPACE | Out-Null
      if (!(Test-Path -LiteralPath $config -PathType Leaf) -or !(Test-Path -LiteralPath $skill -PathType Leaf)) { throw 'Approved workspace files were not written.' }

      foreach ($invalidPath in @(
        (Join-Path $env:CTF_TEST_WORKSPACE '.mcp.json'),
        (Join-Path $env:CTF_TEST_WORKSPACE '.agents/references/ctf-triage-ladder.md'),
        (Join-Path $env:CTF_TEST_HOME '.config/opencode/opencode.json'),
        (Join-Path $env:CTF_TEST_OUTSIDE 'outside.json')
      )) {
        $invalid = [pscustomobject]@{path=$invalidPath; content='{}'; originalHash=$null}
        $message = ''
        try {
          Apply-CtfIdePlan -Plan @($invalid) -HomeDirectory $env:CTF_TEST_HOME -Clients @('opencode') -RepositoryRoot $env:CTF_TEST_REPO -Scope workspace -WorkspacePath $env:CTF_TEST_WORKSPACE | Out-Null
        } catch { $message = $_.Exception.Message }
        if ($message -notmatch 'approved|escapes the selected workspace') { throw ('Workspace boundary did not reject ' + $invalidPath + ': ' + $message) }
        if (Test-Path -LiteralPath $invalidPath) { throw "Rejected workspace path was written: $invalidPath" }
      }
    `, roots);
    assertPowerShellPass(result);
  });
});

test('PowerShell workspace apply rejects reparse-point paths and stale previews', { skip: !powerShellAvailable }, () => {
  withRoots((roots) => {
    const result = runPowerShell(`
      $ErrorActionPreference = 'Stop'
      . $env:CTF_TEST_APPLY_SCRIPT
      $junction = Join-Path $env:CTF_TEST_WORKSPACE '.agents'
      $target = Join-Path $env:CTF_TEST_OUTSIDE 'redirected'
      New-Item -ItemType Directory -Path $target -Force | Out-Null
      & $env:ComSpec /d /c mklink /J $junction $target | Out-Null
      if ($LASTEXITCODE -ne 0) { throw 'Could not create the temporary junction for the reparse-point test.' }
      $redirected = Join-Path $junction 'mcp_config.json'
      $plan = [pscustomobject]@{path=$redirected; content='{}'; originalHash=$null}
      $message = ''
      try {
        Apply-CtfIdePlan -Plan @($plan) -HomeDirectory $env:CTF_TEST_HOME -Clients @('antigravity') -RepositoryRoot $env:CTF_TEST_REPO -Scope workspace -WorkspacePath $env:CTF_TEST_WORKSPACE | Out-Null
      } catch { $message = $_.Exception.Message }
      if ($message -notmatch 'reparse point') { throw "Workspace reparse-point path was not rejected: $message" }
      if (Test-Path -LiteralPath (Join-Path $target 'mcp_config.json')) { throw 'Apply wrote through the workspace junction.' }

      Remove-Item -LiteralPath $junction -Force
      $config = Join-Path $env:CTF_TEST_WORKSPACE 'opencode.json'
      [IO.File]::WriteAllText($config, 'before')
      $plan = [pscustomobject]@{path=$config; content='after'; originalHash=(Get-CtfContentHash 'before')}
      [IO.File]::WriteAllText($config, 'changed after preview')
      $message = ''
      try {
        Apply-CtfIdePlan -Plan @($plan) -HomeDirectory $env:CTF_TEST_HOME -Clients @('opencode') -RepositoryRoot $env:CTF_TEST_REPO -Scope workspace -WorkspacePath $env:CTF_TEST_WORKSPACE | Out-Null
      } catch { $message = $_.Exception.Message }
      if ($message -notmatch 'changed after preview') { throw "Stale workspace plan was not rejected: $message" }
      if ([IO.File]::ReadAllText($config) -ne 'changed after preview') { throw 'Stale workspace apply changed the destination.' }
    `, roots);
    assertPowerShellPass(result);
  });
});

test('PowerShell global apply retains selected user config and guidance paths only', { skip: !powerShellAvailable }, () => {
  withRoots((roots) => {
    const result = runPowerShell(`
      $ErrorActionPreference = 'Stop'
      . $env:CTF_TEST_APPLY_SCRIPT
      $config = Join-Path $env:CTF_TEST_HOME '.config/opencode/opencode.json'
      $guidance = Join-Path $env:CTF_TEST_HOME '.agents/references/ctf-triage-ladder.md'
      $source = Join-Path $env:CTF_TEST_REPO '.agents/references/ctf-triage-ladder.md'
      $operations = @(
        [pscustomobject]@{path=$config; content='{}'; originalHash=$null},
        [pscustomobject]@{path=$guidance; content=[IO.File]::ReadAllText($source, [Text.Encoding]::UTF8); originalHash=$null}
      )
      Apply-CtfIdePlan -Plan $operations -HomeDirectory $env:CTF_TEST_HOME -Clients @('opencode') -RepositoryRoot $env:CTF_TEST_REPO -Scope global | Out-Null
      if (!(Test-Path -LiteralPath $config -PathType Leaf) -or !(Test-Path -LiteralPath $guidance -PathType Leaf)) { throw 'Approved global files were not written.' }
      $unselected = [pscustomobject]@{path=(Join-Path $env:CTF_TEST_HOME '.codex/config.toml'); content=''; originalHash=$null}
      $message = ''
      try {
        Apply-CtfIdePlan -Plan @($unselected) -HomeDirectory $env:CTF_TEST_HOME -Clients @('opencode') -RepositoryRoot $env:CTF_TEST_REPO -Scope global | Out-Null
      } catch { $message = $_.Exception.Message }
      if ($message -notmatch 'approved') { throw "Global apply accepted an unselected client path: $message" }
      if (Test-Path -LiteralPath $unselected.path) { throw 'Global apply wrote an unselected client path.' }
    `, roots);
    assertPowerShellPass(result);
  });
});

test('PowerShell bootstrap requires explicit noninteractive scope and honors the selected workspace root', { skip: !powerShellAvailable }, () => {
  withRoots((roots) => {
    const explicit = runPowerShell(`
      $plan = (& $env:CTF_TEST_SETUP -Scope workspace -WorkspacePath $env:CTF_TEST_WORKSPACE -Client opencode) | ConvertFrom-Json
      if ($plan.workspacePath -ne [IO.Path]::GetFullPath($env:CTF_TEST_WORKSPACE)) { throw 'WorkspacePath was not retained in the setup preview.' }
      $plan | ConvertTo-Json -Compress
    `, roots);
    assertPowerShellPass(explicit);
    const explicitPlan = JSON.parse(explicit.stdout);
    assert.equal(explicitPlan.scope, 'workspace');
    assert.equal(explicitPlan.launcher, path.join(roots.home, 'CTF-Agent', 'ctf-agent.ps1'));

    const currentDirectory = runPowerShell(`
      $plan = (& $env:CTF_TEST_SETUP -Scope workspace -Client opencode) | ConvertFrom-Json
      if ($plan.workspacePath -ne $PWD.Path) { throw 'Workspace mode did not default to the current PowerShell directory.' }
      $plan | ConvertTo-Json -Compress
    `, { ...roots, cwd: roots.workspace });
    assertPowerShellPass(currentDirectory);
    assert.equal(JSON.parse(currentDirectory.stdout).scope, 'workspace');

    const missingScope = runPowerShell(`
      & $env:CTF_TEST_SETUP -Client opencode
    `, roots);
    assert.notEqual(missingScope.status, 0);
    assert.match(`${missingScope.stdout}\n${missingScope.stderr}`, /-Scope/i);
  });
});
