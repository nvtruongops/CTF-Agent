function Get-CtfContentHash([string]$Content) {
    $sha = [Security.Cryptography.SHA256]::Create()
    try { return ([BitConverter]::ToString($sha.ComputeHash([Text.Encoding]::UTF8.GetBytes($Content)))).Replace('-', '').ToLowerInvariant() }
    finally { $sha.Dispose() }
}

function Assert-CtfDestination([string]$Destination, [string]$HomeDirectory) {
    $root = [IO.Path]::GetFullPath($HomeDirectory).TrimEnd('\') + '\'
    $full = [IO.Path]::GetFullPath($Destination)
    if (!$full.StartsWith($root, [StringComparison]::OrdinalIgnoreCase)) { throw 'IDE destination escapes the Windows home.' }
    $current = $full
    while ($current.Length -ge $root.TrimEnd('\').Length) {
        $item = Get-Item -LiteralPath $current -Force -ErrorAction SilentlyContinue
        if ($item -and ($item.Attributes -band [IO.FileAttributes]::ReparsePoint)) { throw 'IDE destination contains a reparse point.' }
        $current = Split-Path $current
        if (!$current) { break }
    }
}

function Apply-CtfIdePlan([object[]]$Plan, [string]$HomeDirectory, [string[]]$Clients, [string]$RepositoryRoot) {
    if (!$Clients -or !$RepositoryRoot) { throw 'Selected clients and the reviewed checkout are required.' }
    $allowed = @{}
    $sourceRoot = (Join-Path $RepositoryRoot '.agents').TrimEnd('\')
    foreach ($client in $Clients) {
        $configs = @()
        switch ($client) {
            'opencode' { $configs = @('.config\opencode\opencode.json', '.config\opencode\opencode.jsonc'); $support = '.agents' }
            'codex' { $configs = @('.codex\config.toml'); $support = '.agents' }
            'claude-code' { $configs = @('.claude.json'); $support = '.claude' }
            'antigravity' { $configs = @('.gemini\config\mcp_config.json'); $support = '.gemini\config' }
            default { throw 'Unsupported Windows client.' }
        }
        foreach ($config in $configs) { $allowed[[IO.Path]::GetFullPath((Join-Path $HomeDirectory $config))] = $null }
        foreach ($group in @('skills', 'references', 'rules')) {
            foreach ($file in Get-ChildItem -LiteralPath (Join-Path $sourceRoot $group) -Recurse -File -Filter '*.md') {
                $relative = $file.FullName.Substring($sourceRoot.Length + 1)
                if ($relative -notmatch '^(skills\\ctf-[^\\]+\\|references\\|rules\\)') { continue }
                $destination = [IO.Path]::GetFullPath((Join-Path (Join-Path $HomeDirectory $support) $relative))
                $allowed[$destination] = [IO.File]::ReadAllText($file.FullName, [Text.Encoding]::UTF8)
            }
        }
    }
    $encoding = New-Object Text.UTF8Encoding($false)
    $pending = @()
    $seen = @{}
    foreach ($operation in $Plan) {
        if ($operation.path -isnot [string] -or $operation.content -isnot [string] -or
            ($null -ne $operation.originalHash -and ($operation.originalHash -isnot [string] -or $operation.originalHash -notmatch '^[a-f0-9]{64}$')) -or
            @($operation.PSObject.Properties.Name).Count -ne 3) { throw 'Invalid IDE file operation.' }
        Assert-CtfDestination $operation.path $HomeDirectory
        $full = [IO.Path]::GetFullPath($operation.path)
        if (!$allowed.ContainsKey($full) -or $seen.ContainsKey($full)) { throw 'IDE destination is not approved for the selected clients, or is duplicated.' }
        $seen[$full] = $true
        if ($null -ne $allowed[$full] -and $operation.content -cne $allowed[$full]) { throw 'Guidance content does not match the reviewed checkout.' }
        $current = $null
        if (Test-Path -LiteralPath $operation.path) {
            if (!(Test-Path -LiteralPath $operation.path -PathType Leaf)) { throw 'IDE destination is not a file.' }
            $current = [Text.Encoding]::UTF8.GetString([IO.File]::ReadAllBytes($operation.path))
        }
        $hash = $null
        if ($null -ne $current) { $hash = Get-CtfContentHash $current }
        if ($hash -ne $operation.originalHash) { throw 'IDE file changed after preview; nothing was written.' }
        if ($current -cne $operation.content) { $pending += $operation }
    }
    $backups = 0
    foreach ($operation in $pending) {
        Assert-CtfDestination $operation.path $HomeDirectory
        if (Test-Path -LiteralPath $operation.path) {
            $current = [Text.Encoding]::UTF8.GetString([IO.File]::ReadAllBytes($operation.path))
            if ((Get-CtfContentHash $current) -ne $operation.originalHash) { throw 'IDE file changed after preview; stopped before overwriting it.' }
            $backup = "$($operation.path).bak"
            $index = 1
            while (Get-Item -LiteralPath $backup -Force -ErrorAction SilentlyContinue) { $backup = "$($operation.path).bak.$index"; $index++ }
            [IO.File]::Copy($operation.path, $backup, $false)
            $backups++
        } elseif ($null -ne $operation.originalHash) { throw 'IDE file disappeared after preview.' }
        New-Item -ItemType Directory -Path (Split-Path $operation.path) -Force | Out-Null
        [IO.File]::WriteAllText($operation.path, [string]$operation.content, $encoding)
    }
    Write-Output "Applied $($pending.Count) Windows file operations; backups: $backups"
}
