param(
    [switch]$Apply,
    [ValidateSet('opencode', 'claude-code', 'codex', 'antigravity')][string[]]$Client = @('opencode'),
    [ValidateSet('full', 'web', 'reverse', 'crypto', 'pwn', 'forensics', 'exploitation', 'game_hacking', 'misc', 'osint', 'steganography', 'hardware', 'competition')][string]$Profile = 'full'
)
$ErrorActionPreference = 'Stop'
$repo = $PSScriptRoot
$launcher = Join-Path $env:LOCALAPPDATA 'CTF-Agent\ctf-agent.ps1'
$runtime = '/home/ctfagent/.local/share/ctf-agent/runtime/node_modules/ctf-agent/ctf_mcp/cli.js'
$nativePath = 'PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin'
$wsl = Get-Command wsl.exe -ErrorAction SilentlyContinue
$table = ''
if ($wsl) { $table = ((& wsl.exe --list --verbose 2>$null) -join "`n").Replace([string][char]0, '') }
$ready = $table -match '(?im)^\s*\*?\s*kali-linux\s+(?:Running|Stopped)\s+2\s*$'
$plan = [ordered]@{
    status = $(if ($ready) { 'ready_to_apply' } else { 'pending_wsl2' })
    distribution = 'kali-linux'
    runtimeUser = 'ctfagent'
    windowsClients = @($Client)
    profile = $Profile
    launcher = $launcher
    actions = @('Verify/install native Linux Node >=24.11, npm, Python3 and venv', 'Install curated local tarball as ctfagent', 'Apply selected Kali tool profile and verify readiness', 'Back up and merge selected Windows agent configuration and CTF guidance')
}
$plan | ConvertTo-Json -Depth 5
if (!$Apply) { return }
if (!$ready) {
    throw 'WSL2 Kali is not ready. From an elevated terminal if needed run: wsl --install --distribution kali-linux --no-launch ; complete any reboot/initialization, verify wsl --list --verbose, then rerun setup.ps1. Existing distros were not changed.'
}
function Invoke-Kali([string]$UserName, [string[]]$CommandArgs) {
    & wsl.exe --distribution kali-linux --user $UserName --exec @CommandArgs
    if ($LASTEXITCODE -ne 0) { throw "Kali setup action failed (exit $LASTEXITCODE); existing agent configuration has not been replaced." }
}
function Convert-KaliPath([string]$Value) {
    $previousEncoding = [Console]::OutputEncoding
    try {
        [Console]::OutputEncoding = New-Object Text.UTF8Encoding($false)
        $converted = & wsl.exe --distribution kali-linux --user root --exec /usr/bin/wslpath -a -u $Value
        if ($LASTEXITCODE -ne 0) { throw 'Cannot translate the Windows path into Kali.' }
    } finally { [Console]::OutputEncoding = $previousEncoding }
    return ($converted -join "`n").Trim()
}
$linuxRepo = Convert-KaliPath $repo
Invoke-Kali -UserName root -CommandArgs @('/bin/bash', "$linuxRepo/scripts/setup-wsl.sh", 'prerequisites')
Invoke-Kali -UserName ctfagent -CommandArgs @('/bin/bash', "$linuxRepo/scripts/setup-wsl.sh", 'install', $linuxRepo)
Invoke-Kali -UserName root -CommandArgs @('/bin/bash', "$linuxRepo/scripts/setup-wsl.sh", 'tools', $linuxRepo, $Profile)
Invoke-Kali -UserName ctfagent -CommandArgs @('/usr/bin/env', $nativePath, '/usr/bin/node', $runtime, 'setup', '--apply', '--profile', $Profile, '--json')
$linuxHome = Convert-KaliPath $env:USERPROFILE
$clientArgs = @()
foreach ($id in $Client) { $clientArgs += @('--client', $id) }
$ide = @('/usr/bin/env', $nativePath, "CTF_AGENT_WINDOWS_HOME=$linuxHome", "CTF_AGENT_WINDOWS_HOME_NATIVE=$env:USERPROFILE", "CTF_AGENT_WINDOWS_LAUNCHER=$launcher", '/usr/bin/node', '/home/ctfagent/.local/share/ctf-agent/runtime/node_modules/ctf-agent/ctf_mcp/ide-plan.js') + @($Client)
$planJson = & wsl.exe --distribution kali-linux --user ctfagent --exec @ide
if ($LASTEXITCODE -ne 0) { throw 'Cannot safely preview Windows agent configuration; nothing was replaced.' }
$operations = ($planJson -join "`n") | ConvertFrom-Json
Write-Output "Prepared $($operations.Count) Windows configuration/guidance operations for: $($Client -join ', ')"
$directory = Split-Path $launcher
if (Test-Path -LiteralPath $directory) {
    if ((Get-Item -LiteralPath $directory).Attributes -band [IO.FileAttributes]::ReparsePoint) { throw 'Launcher directory must not be a reparse point.' }
}
New-Item -ItemType Directory -Path $directory -Force | Out-Null
$source = Join-Path $repo 'scripts\launch-wsl.ps1'
if (Test-Path -LiteralPath $launcher) {
    $item = Get-Item -LiteralPath $launcher
    if ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) { throw 'Launcher must not be a reparse point.' }
    if ((Get-FileHash -LiteralPath $launcher).Hash -ne (Get-FileHash -LiteralPath $source).Hash) {
        $backup = "$launcher.bak"
        $number = 1
        while (Test-Path -LiteralPath $backup) { $backup = "$launcher.bak.$number"; $number++ }
        Copy-Item -LiteralPath $launcher -Destination $backup
        Copy-Item -LiteralPath $source -Destination $launcher
    }
} else { Copy-Item -LiteralPath $source -Destination $launcher }
. (Join-Path $repo 'scripts\apply-ide-plan.ps1')
Apply-CtfIdePlan -Plan $operations -HomeDirectory $env:USERPROFILE -Clients $Client -RepositoryRoot $repo
Write-Output 'CTF-Agent WSL setup complete. Reload the selected agent to connect its local MCP server.'
