param(
    [Parameter(Position = 0)][string]$Command = 'mcp',
    [Parameter(ValueFromRemainingArguments = $true)][string[]]$Arguments
)
$ErrorActionPreference = 'Stop'
$previousWslEnv = $env:WSLENV
$previousRoot = $env:CTF_AGENT_PROJECT_ROOT
try {
    $entries = @($env:WSLENV -split ':' | Where-Object { $_ -and ($_ -split '/')[0] -notin @('CTF_AGENT_PROJECT_ROOT', 'CTF_MCP_CTFD_URL', 'CTF_MCP_CTFD_TOKEN') })
    $env:WSLENV = (@($entries) + @('CTF_AGENT_PROJECT_ROOT/p', 'CTF_MCP_CTFD_URL/u', 'CTF_MCP_CTFD_TOKEN/u')) -join ':'
    $env:CTF_AGENT_PROJECT_ROOT = (Get-Location).ProviderPath
    $invokeArgs = @('--distribution', 'kali-linux', '--user', 'ctfagent', '--cd', (Get-Location).ProviderPath, '--exec', '/usr/bin/env', 'PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin', '/usr/bin/node', '/home/ctfagent/.local/share/ctf-agent/runtime/node_modules/ctf-agent/ctf_mcp/cli.js', $Command)
    if ($null -ne $Arguments) { $invokeArgs += $Arguments }
    & wsl.exe @invokeArgs
    $code = $LASTEXITCODE
} finally {
    $env:WSLENV = $previousWslEnv
    $env:CTF_AGENT_PROJECT_ROOT = $previousRoot
}
exit $code
