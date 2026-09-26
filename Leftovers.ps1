#Requires -Version 5.1
<#
.SYNOPSIS
    Leftovers - find what a broken app left behind, with the evidence for every item.

.DESCRIPTION
    For an app whose uninstall is ALREADY broken: the cached MSI is gone, the UninstallString points
    at a deleted exe, files are half removed. If msiexec /x or the vendor uninstaller still works, use
    that first. Leftovers is the second attempt, not the first.

    Level 0 (the default, and the only level in this version) is READ-ONLY. It identifies the app from
    its own registration (ProductCode, UpgradeCode, MSI components, install folders, signer), finds
    everything on the machine that references it, and writes a plan: every item with the evidence for
    it, the level that would remove it, and a risk tag. Nothing on the machine is changed.

    Matching is identity-first. A keyword (the app's own distinctive name) only ever NARROWS a match,
    and is refused when it also matches things outside the app. Paths another installed product still
    points into are kept, never planned for removal.

.PARAMETER Name
    Exact DisplayName of the app, as shown in Installed apps / Programs and Features.
.PARAMETER ProductCode
    The app's MSI ProductCode, e.g. {23170F69-40C1-2702-2409-000001000000}.
.PARAMETER UpgradeCode
    The app's MSI UpgradeCode.
.PARAMETER List
    List installed apps (name, version, publisher, type, scope) to pick a target from.
.PARAMETER Keyword
    A distinctive whole-word name for the app, e.g. "Imprivata". Optional: one is derived from the
    app's name and publisher. Refused if it matches another installed product or much outside the app.
.PARAMETER OutDir
    Where plan.json and report.txt are written. Default: $env:ProgramData\Leftovers\reports\<runId>.
.PARAMETER Quiet
    Don't print the report; still writes the files and sets the exit code.

.EXAMPLE
    .\Leftovers.ps1 -List
.EXAMPLE
    .\Leftovers.ps1 -Name "7-Zip 24.09 (x64 edition)"
.EXAMPLE
    .\Leftovers.ps1 -ProductCode "{23170F69-40C1-2702-2409-000001000000}" -OutDir C:\Temp\lo

.NOTES
    Exit codes: 0 plan written, 2 refused (protected or ambiguous target), 3 bad input, target not
    found, or not elevated, 4 stopped on an unexpected error (no plan written).
    Runs on Windows PowerShell 5.1 and PowerShell 7. Must run elevated (admin or SYSTEM).
    https://github.com/deadarcher/leftovers - MIT license.
#>
[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingEmptyCatchBlock', '', Justification = 'Best-effort reads: an unreadable key or file is skipped (and counted where it matters), never fatal.')]
[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSReviewUnusedParameter', '', Justification = 'Script parameters are read inside Invoke-Leftovers through scope inheritance.')]
[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingWriteHost', '', Justification = 'Interactive CLI output; the machine-readable result is plan.json.')]
[CmdletBinding(DefaultParameterSetName = 'Name')]
param(
    [Parameter(ParameterSetName = 'Name', Mandatory = $true, Position = 0)]
    [string] $Name,

    [Parameter(ParameterSetName = 'ProductCode', Mandatory = $true)]
    [string] $ProductCode,

    [Parameter(ParameterSetName = 'UpgradeCode', Mandatory = $true)]
    [string] $UpgradeCode,

    [Parameter(ParameterSetName = 'List', Mandatory = $true)]
    [switch] $List,

    # Internal: load the functions without running anything (the unit tests dot-source this way).
    [Parameter(ParameterSetName = 'Library', Mandatory = $true, DontShow = $true)]
    [switch] $LibraryOnly,

    [ValidateRange(0, 0)]
    [int] $Level = 0,

    [string] $Keyword,

    [string] $OutDir,

    [switch] $Quiet
)

Set-StrictMode -Version 2.0
$script:ToolVersion = '0.1.0'

# =====================================================================================================
# Pure helpers (no machine access; covered by tests\Run-Tests.ps1)
# =====================================================================================================

function ConvertTo-PackedGuid {
    # Windows Installer's "packed" GUID form, used as registry key names under Installer\*:
    # the first three groups are reversed whole; in the last 16 hex digits each byte's nibbles swap.
    param([Parameter(Mandatory = $true)] [string] $Guid)
    $g = $Guid.Trim().Trim('{', '}').Replace('-', '')
    if ($g -notmatch '^[0-9A-Fa-f]{32}$') { throw "Not a GUID: $Guid" }
    $g = $g.ToUpperInvariant()
    $sb = New-Object System.Text.StringBuilder
    [void]$sb.Append((-join $g.Substring(0, 8).ToCharArray()[7..0]))
    [void]$sb.Append((-join $g.Substring(8, 4).ToCharArray()[3..0]))
    [void]$sb.Append((-join $g.Substring(12, 4).ToCharArray()[3..0]))
    for ($i = 16; $i -lt 32; $i += 2) { [void]$sb.Append($g[$i + 1]).Append($g[$i]) }
    $sb.ToString()
}

function ConvertFrom-PackedGuid {
    param([Parameter(Mandatory = $true)] [AllowEmptyString()] [string] $Packed)
    $p = $Packed.Trim()
    if ($p -notmatch '^[0-9A-Fa-f]{32}$') { return $null }
    $p = $p.ToUpperInvariant()
    $a = -join $p.Substring(0, 8).ToCharArray()[7..0]
    $b = -join $p.Substring(8, 4).ToCharArray()[3..0]
    $c = -join $p.Substring(12, 4).ToCharArray()[3..0]
    $sb = New-Object System.Text.StringBuilder
    for ($i = 16; $i -lt 32; $i += 2) { [void]$sb.Append($p[$i + 1]).Append($p[$i]) }
    $r = $sb.ToString()
    '{' + $a + '-' + $b + '-' + $c + '-' + $r.Substring(0, 4) + '-' + $r.Substring(4, 12) + '}'
}

function Test-IsGuid {
    param([string] $Text)
    return ($Text -match '^\{?[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}\}?$')
}

function Get-NormalizedPath {
    # Absolute local or UNC path, env vars expanded, NT prefixes stripped, no trailing backslash.
    # Anything else (relative, empty, garbage) is $null, so a caller can never match against it.
    param([string] $Path)
    if ([string]::IsNullOrWhiteSpace($Path)) { return $null }
    $p = [Environment]::ExpandEnvironmentVariables($Path.Trim().Trim('"').Trim())
    if ($p.StartsWith('\??\')) { $p = $p.Substring(4) }
    if ($p.StartsWith('\\?\')) { $p = $p.Substring(4) }
    if ($p -match '^\\SystemRoot\\') { $p = $env:SystemRoot + $p.Substring(11) }
    $p = $p.Replace('/', '\')
    if ($p -notmatch '^[A-Za-z]:\\' -and $p -notmatch '^\\\\[^\\]') { return $null }
    try { $p = [System.IO.Path]::GetFullPath($p) } catch { return $null }
    if ($p.Length -gt 3) { $p = $p.TrimEnd('\') }
    return $p
}

function Test-PathUnder {
    # True when Path is Root or inside it. Boundary-aware: C:\App2 is NOT under C:\App.
    param([string] $Path, [string] $Root)
    $p = Get-NormalizedPath $Path
    $r = Get-NormalizedPath $Root
    if (-not $p -or -not $r) { return $false }
    if ($p.Equals($r, [StringComparison]::OrdinalIgnoreCase)) { return $true }
    return $p.StartsWith($r.TrimEnd('\') + '\', [StringComparison]::OrdinalIgnoreCase)
}

function Test-TextReferencesPath {
    # Does a command line / registry string mention one of these folders as a path? The match must sit
    # on path boundaries on both sides, so "C:\Program Files\App2" never matches root "...\App".
    param([string] $Text, [string[]] $Roots)
    if ([string]::IsNullOrEmpty($Text) -or -not $Roots) { return $false }
    $t = [Environment]::ExpandEnvironmentVariables($Text)
    $startOk = @('"', ' ', '=', ',', ';', "'", '(', '@', "`t")
    $endOk = @('\', '"', ' ', ',', ';', "'", ')', "`t")
    foreach ($r in $Roots) {
        if ([string]::IsNullOrEmpty($r)) { continue }
        $idx = 0
        while ($idx -lt $t.Length) {
            $idx = $t.IndexOf($r, $idx, [StringComparison]::OrdinalIgnoreCase)
            if ($idx -lt 0) { break }
            $end = $idx + $r.Length
            $before = if ($idx -eq 0) { '' } else { [string]$t[$idx - 1] }
            $after = if ($end -ge $t.Length) { '' } else { [string]$t[$end] }
            if (($before -eq '' -or $startOk -contains $before) -and ($after -eq '' -or $endOk -contains $after)) { return $true }
            $idx = $end
        }
    }
    return $false
}

function Get-CommandExePath {
    # The executable a command line runs: quoted path, or an unquoted path ending in a known extension
    # (unquoted paths with spaces are common in Run keys and ImagePath values).
    param([string] $CommandLine)
    if ([string]::IsNullOrWhiteSpace($CommandLine)) { return $null }
    $c = [Environment]::ExpandEnvironmentVariables($CommandLine.Trim())
    if ($c.StartsWith('"')) {
        $end = $c.IndexOf('"', 1)
        if ($end -gt 1) { return Get-NormalizedPath $c.Substring(1, $end - 1) }
        return $null
    }
    $m = [regex]::Match($c, '^(.+?\.(exe|dll|sys|cmd|bat|com|ps1|vbs|js|msc|cpl|ocx|scr|ax))(?=$|[\s,"])', 'IgnoreCase')
    if ($m.Success) { return Get-NormalizedPath $m.Groups[1].Value }
    return Get-NormalizedPath ($c.Split(' ')[0])
}

function Resolve-ServiceImagePath {
    # A service/driver ImagePath to a full path. Drivers use \SystemRoot\..., System32\..., \??\C:\...,
    # or nothing at all (then Windows loads System32\drivers\<name>.sys).
    param([string] $ImagePath, [string] $ServiceName, [int] $Type)
    if ([string]::IsNullOrWhiteSpace($ImagePath)) {
        if ($Type -band 0x3) { return Get-NormalizedPath (Join-Path $env:SystemRoot "System32\drivers\$ServiceName.sys") }
        return $null
    }
    $p = [Environment]::ExpandEnvironmentVariables($ImagePath.Trim())
    if ($p -match '^\\SystemRoot\\') { $p = $env:SystemRoot + $p.Substring(11) }
    elseif ($p -match '^(?i)system32\\') { $p = Join-Path $env:SystemRoot $p }
    elseif ($p.StartsWith('\??\')) { $p = $p.Substring(4) }
    return Get-CommandExePath $p
}

function ConvertFrom-MsiKeyPath {
    # A component key path as stored under UserData\<sid>\Components\<comp>:
    #   "C:\Program Files\App\app.exe"        a file   ("C:\...\dir\" = a folder)
    #   "02:\SOFTWARE\Vendor\Product\Value"   a registry key path; 00 HKCR, 01 HKCU, 02 HKLM, 03 HKU;
    #                                         +20 = the 64-bit view
    #   "C?\..."                              run-from-source marker for the drive letter
    param([string] $KeyPath)
    if ([string]::IsNullOrWhiteSpace($KeyPath)) { return $null }
    $k = $KeyPath.Trim()
    if ($k -match '^(\d\d):\\?(.*)$') {
        $code = [int]$matches[1]
        $root = $code % 20
        $hive = switch ($root) { 0 { 'HKCR' } 1 { 'HKCU' } 2 { 'HKLM' } 3 { 'HKU' } default { $null } }
        return [pscustomobject]@{ Kind = 'Registry'; Hive = $hive; Is64 = ($code -ge 20); Path = $matches[2]; IsFolder = $false }
    }
    if ($k -match '^[A-Za-z]\?\\') { $k = $k.Substring(0, 1) + ':' + $k.Substring(2) }
    $p = Get-NormalizedPath $k
    if (-not $p) { return $null }
    return [pscustomobject]@{ Kind = 'File'; Hive = $null; Is64 = $false; Path = $p; IsFolder = $k.EndsWith('\') }
}

function Test-WholeWord {
    # Keyword match on word boundaries (letters and digits count as word characters; so do '-' and
    # '+' inside names like "7-Zip" and "Notepad++"): "Zoom" does not match "ZoomIt".
    param([string] $Text, [string] $Word)
    if ([string]::IsNullOrEmpty($Text) -or [string]::IsNullOrEmpty($Word)) { return $false }
    $pattern = '(?<![A-Za-z0-9])' + [regex]::Escape($Word) + '(?![A-Za-z0-9])'
    return [regex]::IsMatch($Text, $pattern, 'IgnoreCase')
}

$script:KeywordStopWords = @(
    'inc', 'corp', 'corporation', 'llc', 'ltd', 'limited', 'gmbh', 'co', 'company', 'software', 'technologies',
    'technology', 'systems', 'system', 'solutions', 'group', 'the', 'for', 'and', 'of', 'agent', 'client',
    'service', 'services', 'desktop', 'app', 'application', 'tools', 'tool', 'update', 'updater', 'windows',
    'x64', 'x86', 'arm64', 'bit', 'edition', 'version', 'setup', 'installer', 'runtime', 'plugin', 'pro',
    'professional', 'enterprise', 'free', 'suite', 'manager', 'helper', 'driver', 'drivers', 'support',
    'host', 'studio', 'player', 'viewer', 'reader', 'launcher', 'cloud', 'online', 'web', 'office', 'mobile',
    'sdk', 'core', 'common', 'shared', 'files', 'data', 'microsoft', 'machine', 'wide', 'user', 'users', 'all',
    'components', 'component', 'module', 'modules', 'package', 'program', 'programs', 'foundation', 'project'
)

function Get-KeywordCandidates {
    # Distinctive tokens from the app's name, then its publisher: versions, architecture and generic
    # words dropped, 4+ characters. Order = preference (the name's first real token first).
    param([string] $DisplayName, [string] $Publisher)
    $out = New-Object System.Collections.Generic.List[string]
    foreach ($source in @($DisplayName, $Publisher)) {
        if ([string]::IsNullOrWhiteSpace($source)) { continue }
        foreach ($tok in [regex]::Split($source, '[^A-Za-z0-9\-\+]+')) {
            # Trailing '+' is part of the name (Notepad++, C++): trimming it made the keyword "Notepad",
            # which also names Windows' own Notepad keys (lab, 2026-09-25).
            $t = $tok.Trim('-')
            if ($t.Length -lt 4) { continue }
            if ($t -match '^[vV]?\d+([\.\-]\d+)*$') { continue }
            if ($t -match '^(?i)(\d+-?bit|x86-64|x86_64|amd64|arm64|win(32|64))$') { continue }
            if ($script:KeywordStopWords -contains $t.ToLowerInvariant()) { continue }
            if (-not ($out -contains $t)) { $out.Add($t) }
        }
    }
    return , $out.ToArray()
}

function Get-PathDepth {
    param([string] $Path)
    $p = Get-NormalizedPath $Path
    if (-not $p) { return 0 }
    return @($p.Split('\') | Where-Object { $_ }).Count - 1
}

function Get-ProtectedPathReason {
    # Why a folder may never be a root (matching OR removal), or $null when it can be one.
    # ContainerPaths: may not BE the root, but their children may (Program Files, a profile root).
    # TreePaths: nothing at or under them may be a root (C:\Windows, the RFF agent).
    param([string] $Path, [string[]] $ContainerPaths, [string[]] $TreePaths)
    $p = Get-NormalizedPath $Path
    if (-not $p) { return 'not an absolute local path' }
    if ($p.StartsWith('\\')) { return 'network path' }
    if ((Get-PathDepth $p) -lt 2) { return 'too shallow (a root must be at least two folders deep)' }
    foreach ($t in $TreePaths) {
        if ($t -and (Test-PathUnder $p $t)) { return "inside protected folder $t" }
    }
    foreach ($c in $ContainerPaths) {
        if ($c -and ($p.Equals((Get-NormalizedPath $c), [StringComparison]::OrdinalIgnoreCase))) { return "is the shared folder $c itself" }
    }
    $parent = Split-Path $p -Parent
    $leaf = Split-Path $p -Leaf
    foreach ($pf in @($env:ProgramFiles, ${env:ProgramFiles(x86)}, $env:CommonProgramFiles, ${env:CommonProgramFiles(x86)})) {
        if ($pf -and $parent -and $parent.Equals((Get-NormalizedPath $pf), [StringComparison]::OrdinalIgnoreCase)) {
            if ($leaf -match '^(Microsoft|Windows )' -or $leaf -in @('dotnet', 'Internet Explorer', 'Common Files', 'WindowsApps', 'ModifiableWindowsApps', 'microsoft shared')) {
                return "Microsoft/Windows folder $p"
            }
        }
    }
    return $null
}

function Get-UserDataTag {
    # Bounded scan of a folder: size, and whether it holds document-like files. Over the threshold or
    # holding documents = HIGH RISK, "this folder may contain user data".
    param([string] $Folder, [int] $MaxFiles = 5000, [long] $SizeThresholdBytes = 100MB)
    $docExt = @('.doc', '.docx', '.xls', '.xlsx', '.ppt', '.pptx', '.pdf', '.pst', '.txt', '.rtf', '.odt',
        '.csv', '.db', '.sqlite', '.sqlite3', '.mdb', '.accdb', '.one', '.msg', '.eml', '.jpg', '.png', '.zip')
    $size = [long]0; $files = 0; $docs = 0; $truncated = $false
    try {
        foreach ($f in [System.IO.Directory]::EnumerateFiles($Folder, '*', [System.IO.SearchOption]::AllDirectories)) {
            $files++
            if ($files -gt $MaxFiles) { $truncated = $true; break }
            try { $size += (New-Object System.IO.FileInfo $f).Length } catch { }
            if ($docExt -contains [System.IO.Path]::GetExtension($f).ToLowerInvariant()) { $docs++ }
        }
    } catch { $truncated = $true }
    $reasons = @()
    if ($size -ge $SizeThresholdBytes) { $reasons += ('{0:N0} MB' -f ($size / 1MB)) }
    if ($docs -gt 0) { $reasons += "$docs document-like file(s)" }
    if ($truncated) { $reasons += "more than $MaxFiles files (scan stopped)" }
    return [pscustomobject]@{
        SizeBytes = $size; Files = [Math]::Min($files, $MaxFiles); DocLike = $docs; Truncated = $truncated
        HighRisk = ($reasons.Count -gt 0); Reason = ($reasons -join ', ')
    }
}

function Get-SignerOrg {
    # "CN=Foo, O="Vitko Software, LLC", L=..." -> "Vitko Software, LLC" (O first, then CN).
    param([string] $Subject)
    if ([string]::IsNullOrWhiteSpace($Subject)) { return $null }
    foreach ($field in @('O', 'CN')) {
        $m = [regex]::Match($Subject, '(?:^|,\s*)' + $field + '=(?:"([^"]+)"|([^,]+))')
        if ($m.Success) {
            $v = if ($m.Groups[1].Success) { $m.Groups[1].Value } else { $m.Groups[2].Value }
            return $v.Trim()
        }
    }
    return $Subject.Trim()
}

function Test-IsMicrosoftName {
    param([string] $Text)
    return (Test-WholeWord $Text 'Microsoft')
}

# Security products are refused outright: tamper protection makes a generic removal unpredictable, and
# each vendor ships its own tool. Whole-word match on publisher or name.
$script:SecurityVendors = [ordered]@{
    'CrowdStrike'  = 'CsUninstallTool with the maintenance token (Falcon console)'
    'SentinelOne'  = 'SentinelCleaner / the passphrase uninstall from the SentinelOne console'
    'Sophos'       = 'Sophos Zap (tamper protection off first)'
    'Symantec'     = 'Broadcom CleanWipe'
    'Broadcom'     = 'Broadcom CleanWipe'
    'Norton'       = 'Norton Remove and Reinstall tool'
    'McAfee'       = 'McAfee Consumer Product Removal (MCPR) or the Endpoint Product Removal tool'
    'Trellix'      = 'Trellix Endpoint Product Removal (EPR)'
    'ESET'         = 'ESET Uninstaller (Safe Mode)'
    'Trend Micro'  = "the Trend Micro product's uninstall tool"
    'Bitdefender'  = 'Bitdefender Uninstall Tool'
    'Kaspersky'    = 'kavremover'
    'Carbon Black' = 'the Carbon Black sensor uninstall with its code'
    'Cylance'      = "Cylance's cleanup utility"
    'Cortex XDR'   = 'Cortex XDR Cleaner (with the uninstall password)'
    'Malwarebytes' = 'the Malwarebytes Support Tool clean option'
    'Webroot'      = "Webroot's removal instructions"
    'Avast'        = 'avastclear'
    'AVG'          = 'AVG Clear'
    'WithSecure'   = 'the WithSecure uninstallation tool'
    'F-Secure'     = 'the F-Secure uninstallation tool'
    'Huntress'     = "Huntress's uninstall script"
    'Cisco Secure' = 'the Cisco Secure Endpoint connector uninstall'
    'Cybereason'   = "Cybereason's uninstall with the sensor password"
    'Elastic'      = 'elastic-agent uninstall'
}

# =====================================================================================================
# Machine access (read-only). Registry via .NET with EXPLICIT views, so a 32-bit host process still
# sees both the 64-bit and the WOW6432Node halves.
# =====================================================================================================

$script:Base = @{}
$script:Unreadable = @{}

function Initialize-RegistryBase {
    $script:Base['HKLM64'] = [Microsoft.Win32.RegistryKey]::OpenBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine, [Microsoft.Win32.RegistryView]::Registry64)
    $script:Base['HKLM32'] = [Microsoft.Win32.RegistryKey]::OpenBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine, [Microsoft.Win32.RegistryView]::Registry32)
    $script:Base['HKU'] = [Microsoft.Win32.RegistryKey]::OpenBaseKey([Microsoft.Win32.RegistryHive]::Users, [Microsoft.Win32.RegistryView]::Registry64)
}

function Add-Unreadable {
    param([string] $Area)
    if ($script:Unreadable.ContainsKey($Area)) { $script:Unreadable[$Area]++ } else { $script:Unreadable[$Area] = 1 }
}

function Open-Key {
    param([string] $Hive, [string] $Path, [string] $Area = 'registry')
    try { return $script:Base[$Hive].OpenSubKey($Path, $false) } catch { Add-Unreadable $Area; return $null }
}

function Get-SubKeyNamesSafe {
    param($Key, [string] $Area = 'registry')
    if ($null -eq $Key) { return @() }
    try { return @($Key.GetSubKeyNames()) } catch { Add-Unreadable $Area; return @() }
}

function Get-ValueNamesSafe {
    param($Key, [string] $Area = 'registry')
    if ($null -eq $Key) { return @() }
    try { return @($Key.GetValueNames()) } catch { Add-Unreadable $Area; return @() }
}

function Get-ValueSafe {
    param($Key, [string] $Name)
    if ($null -eq $Key) { return $null }
    try { return $Key.GetValue($Name, $null) } catch { return $null }
}

function Close-Key {
    param($Key)
    if ($null -ne $Key) { try { $Key.Close() } catch { } }
}

function Format-RegPath {
    # Human form of a key: the 32-bit view of SOFTWARE is really SOFTWARE\WOW6432Node.
    param([string] $Hive, [string] $Path)
    switch ($Hive) {
        'HKLM64' { return "HKLM\$Path" }
        'HKLM32' {
            if ($Path -match '^(?i)SOFTWARE\\(.*)$') { return "HKLM\SOFTWARE\WOW6432Node\$($matches[1])" }
            return "HKLM\$Path"
        }
        'HKU' { return "HKU\$Path" }
    }
    return "$Hive\$Path"
}

function Get-LoadedUserSids {
    # Loaded hives only (v1 never loads an offline NTUSER.DAT). Real users + the service accounts.
    $sids = @()
    foreach ($n in (Get-SubKeyNamesSafe $script:Base['HKU'])) {
        if ($n -match '^S-1-(5-21|12-1)-[\d-]+$' -or $n -in @('S-1-5-18', 'S-1-5-19', 'S-1-5-20')) { $sids += $n }
    }
    return $sids
}

function Get-Profiles {
    param([string[]] $LoadedSids)
    $out = @()
    $pl = Open-Key 'HKLM64' 'SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList'
    foreach ($sid in (Get-SubKeyNamesSafe $pl)) {
        if ($sid -notmatch '^S-1-(5-21|12-1)-[\d-]+$') { continue }
        $k = Open-Key 'HKLM64' "SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\$sid"
        $path = Get-NormalizedPath ([string](Get-ValueSafe $k 'ProfileImagePath'))
        $central = [string](Get-ValueSafe $k 'CentralProfile')
        Close-Key $k
        if (-not $path) { continue }
        $out += [pscustomobject]@{
            Sid = $sid; Path = $path; User = (Split-Path $path -Leaf)
            Loaded = ($LoadedSids -contains $sid); Roaming = (-not [string]::IsNullOrWhiteSpace($central))
        }
    }
    Close-Key $pl
    return $out
}

function Get-UninstallEntries {
    param([string[]] $LoadedSids)
    $sources = @(
        @{ Hive = 'HKLM64'; Path = 'SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall'; Sid = $null },
        @{ Hive = 'HKLM32'; Path = 'SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall'; Sid = $null }
    )
    foreach ($sid in $LoadedSids) {
        $sources += @{ Hive = 'HKU'; Path = "$sid\Software\Microsoft\Windows\CurrentVersion\Uninstall"; Sid = $sid }
    }
    $entries = New-Object System.Collections.Generic.List[object]
    foreach ($s in $sources) {
        $root = Open-Key $s.Hive $s.Path 'uninstall entries'
        foreach ($name in (Get-SubKeyNamesSafe $root 'uninstall entries')) {
            $k = $null
            try { $k = $root.OpenSubKey($name, $false) } catch { Add-Unreadable 'uninstall entries'; continue }
            if ($null -eq $k) { continue }
            $dn = [string](Get-ValueSafe $k 'DisplayName')
            $isMsi = ((Get-ValueSafe $k 'WindowsInstaller') -eq 1)
            $entries.Add([pscustomobject]@{
                    Hive                 = $s.Hive
                    Sid                  = $s.Sid
                    KeyPath              = "$($s.Path)\$name"
                    Display              = (Format-RegPath $s.Hive "$($s.Path)\$name")
                    KeyName              = $name
                    DisplayName          = $dn.Trim()
                    DisplayVersion       = [string](Get-ValueSafe $k 'DisplayVersion')
                    Publisher            = ([string](Get-ValueSafe $k 'Publisher')).Trim()
                    InstallLocation      = [string](Get-ValueSafe $k 'InstallLocation')
                    UninstallString      = [string](Get-ValueSafe $k 'UninstallString')
                    QuietUninstallString = [string](Get-ValueSafe $k 'QuietUninstallString')
                    DisplayIcon          = [string](Get-ValueSafe $k 'DisplayIcon')
                    SystemComponent      = ((Get-ValueSafe $k 'SystemComponent') -eq 1)
                    IsMsi                = $isMsi
                    ProductCode          = $(if (Test-IsGuid $name) { '{' + $name.Trim('{', '}').ToUpperInvariant() + '}' } else { $null })
                })
            Close-Key $k
        }
        Close-Key $root
    }
    return , $entries
}

function Get-EntryPaths {
    # The folders an uninstall entry points at: InstallLocation, the uninstaller's folder, the icon's
    # folder. msiexec/rundll32 in System32 are not the app's folder and are skipped.
    param($Entry)
    $paths = @()
    $loc = Get-NormalizedPath $Entry.InstallLocation
    if ($loc) { $paths += $loc }
    foreach ($cmd in @($Entry.UninstallString, $Entry.QuietUninstallString)) {
        $exe = Get-CommandExePath $cmd
        if ($exe -and -not (Test-PathUnder $exe $env:SystemRoot)) { $paths += (Split-Path $exe -Parent) }
    }
    if ($Entry.DisplayIcon) {
        $icon = Get-NormalizedPath (($Entry.DisplayIcon -replace ',\s*-?\d+\s*$', ''))
        if ($icon -and -not (Test-PathUnder $icon $env:SystemRoot)) { $paths += (Split-Path $icon -Parent) }
    }
    return @($paths | Where-Object { $_ } | Select-Object -Unique)
}

function Get-MsiComponentIndex {
    # ONE pass over every UserData\<sid>\Components\<packed component>: value name = packed client
    # ProductCode ("000...0" = a permanent/system client), value data = the key path. Returns every
    # entry, the clients of each component (for the shared-component check) and our own entries,
    # so nothing downstream has to rescan ~100k rows.
    param([string] $PackedPc)
    $all = New-Object System.Collections.Generic.List[object]
    $ours = New-Object System.Collections.Generic.List[object]
    $byComponent = @{}
    $udPath = 'SOFTWARE\Microsoft\Windows\CurrentVersion\Installer\UserData'
    $ud = Open-Key 'HKLM64' $udPath 'msi components'
    foreach ($sid in (Get-SubKeyNamesSafe $ud 'msi components')) {
        $comps = Open-Key 'HKLM64' "$udPath\$sid\Components" 'msi components'
        foreach ($c in (Get-SubKeyNamesSafe $comps 'msi components')) {
            $ck = $null
            try { $ck = $comps.OpenSubKey($c, $false) } catch { Add-Unreadable 'msi components'; continue }
            if ($null -eq $ck) { continue }
            try {
                foreach ($client in $ck.GetValueNames()) {
                    if (-not $client) { continue }
                    $cl = $client.ToUpperInvariant()
                    $e = [pscustomobject]@{ Sid = $sid; Component = $c; Client = $cl; KeyPath = [string]$ck.GetValue($client, $null) }
                    $all.Add($e)
                    if (-not $byComponent.ContainsKey($c)) { $byComponent[$c] = New-Object System.Collections.Generic.List[string] }
                    $byComponent[$c].Add($cl)
                    if ($cl -eq $PackedPc) { $ours.Add($e) }
                }
            } catch { Add-Unreadable 'msi components' } finally { Close-Key $ck }
        }
        Close-Key $comps
    }
    Close-Key $ud
    return [pscustomobject]@{ All = $all; Ours = $ours; ByComponent = $byComponent }
}

function Get-OtherComponentClients {
    # Clients of a component other than us (a permanent "000...0" client counts: it is never removable).
    param($Index, [string] $Component, [string] $PackedPc)
    if ($null -eq $Index -or -not $Index.ByComponent.ContainsKey($Component)) { return @() }
    return @($Index.ByComponent[$Component] | Where-Object { $_ -ne $PackedPc } | Select-Object -Unique)
}

function Invoke-ComMember {
    param($Object, [string] $Member, [string] $Kind = 'InvokeMethod', [object[]] $Arguments = $null)
    return $Object.GetType().InvokeMember($Member, [System.Reflection.BindingFlags]::$Kind, $null, $Object, $Arguments)
}

function Get-MsiTableRows {
    # Read-only query of the cached MSI (OpenDatabase mode 0). Missing table = empty result.
    param([string] $MsiPath, [string] $Query, [int] $Columns)
    $rows = @()
    try {
        $installer = New-Object -ComObject WindowsInstaller.Installer
        $db = Invoke-ComMember $installer 'OpenDatabase' 'InvokeMethod' @($MsiPath, 0)
        $view = Invoke-ComMember $db 'OpenView' 'InvokeMethod' @($Query)
        [void](Invoke-ComMember $view 'Execute')
        while ($true) {
            $rec = Invoke-ComMember $view 'Fetch'
            if ($null -eq $rec) { break }
            $vals = @()
            for ($i = 1; $i -le $Columns; $i++) { $vals += [string](Invoke-ComMember $rec 'StringData' 'GetProperty' @($i)) }
            $rows += , $vals
        }
        [void](Invoke-ComMember $view 'Close')
    } catch { }
    return , $rows
}

function Get-SignerSubject {
    param([string] $File)
    try {
        $sig = Get-AuthenticodeSignature -FilePath $File -ErrorAction Stop
        if ($sig.SignerCertificate) { return $sig.SignerCertificate.Subject }
    } catch { }
    return $null
}

function Get-ShortPathSafe {
    # 8.3 form of a folder, because old installers write C:\PROGRA~1\... into the registry.
    param([string] $Path)
    try {
        if (-not (Test-Path -LiteralPath $Path -PathType Container)) { return $null }
        $fso = New-Object -ComObject Scripting.FileSystemObject
        $s = $fso.GetFolder($Path).ShortPath
        if ($s -and -not $s.Equals($Path, [StringComparison]::OrdinalIgnoreCase)) { return $s }
    } catch { }
    return $null
}

$script:MatchRoots = @()
$script:OurFiles = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)

function Test-OurReference {
    # Does this command line / path point at the app? Either inside one of its EXCLUSIVE folders, or
    # at one of its own MSI component files: inside a folder shared with other products, the app's own
    # files are the only evidence that counts (Citrix SSON "owned" all of ICA Client until 2026-09-25).
    param([string] $Text)
    if ([string]::IsNullOrEmpty($Text)) { return $false }
    $inRoot = Test-TextReferencesPath $Text $script:MatchRoots
    if ($inRoot) { return $true }
    if ($script:OurFiles.Count) {
        $p = Get-CommandExePath $Text
        if ($p -and $script:OurFiles.Contains($p)) { return $true }
    }
    return $false
}

function Get-VendorOfFile {
    # CompanyName from the file's version resource. Kernel drivers are signed by Microsoft's attestation
    # service on Windows 10+, so their SIGNATURE can't tie them to a vendor; the vendor's own version
    # resource can. Self-declared, so it is weaker evidence and reported as such.
    param([string] $File)
    try {
        if (-not $File -or -not (Test-Path -LiteralPath $File -PathType Leaf)) { return $null }
        $c = [System.Diagnostics.FileVersionInfo]::GetVersionInfo($File).CompanyName
        if ($c) { return $c.Trim() }
    } catch { }
    return $null
}

function Test-SameVendor {
    # "Insecure.Com LLC" vs "Insecure.Com, LLC": compare on letters and digits only, suffixes dropped.
    param([string] $A, [string] $B)
    if ([string]::IsNullOrWhiteSpace($A) -or [string]::IsNullOrWhiteSpace($B)) { return $false }
    $norm = { param($s) (($s.ToLowerInvariant() -replace '\b(inc|llc|ltd|limited|corp|corporation|gmbh|co|company|s\.a|b\.v|ag|plc)\b', '') -replace '[^a-z0-9]', '') }
    $x = & $norm $A; $y = & $norm $B
    return ($x.Length -ge 3 -and $x -eq $y)
}

# =====================================================================================================
# The plan
# =====================================================================================================

$script:Items = New-Object System.Collections.Generic.List[object]
$script:ItemKeys = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
$script:Kept = New-Object System.Collections.Generic.List[object]
$script:Warnings = New-Object System.Collections.Generic.List[string]

# Execution order for the higher levels: unhook from Windows first, files after.
$script:Order = @{
    UninstallEntry = 110; MsiProduct = 120; MsiUpgradeCode = 130; MsiComponentClient = 140; MsiPatch = 150
    MsiFolderEntry = 160; MsiCachedPackage = 170
    DeviceClassFilter = 310; DeviceInstanceFilter = 311; NetworkComponent = 320; DriverPackage = 330
    Driver = 340; Service = 341; ScheduledTask = 350; RunValue = 360; ComClass = 370; ComTypeLib = 371
    ComAppId = 372; ComInterface = 373; ComProgId = 374; ShellExtension = 375; CredentialProviderFilter = 380
    CredentialProvider = 385; PasswordProviderRestore = 386; Winlogon = 390; LsaPackage = 392
    NetworkProvider = 394; PrintMonitor = 396; AppInitDll = 397; IfeoDebugger = 398; FirewallRule = 399
    FileAssociation = 376; Shortcut = 400; InstallRoot = 500; IdentityFile = 505; InstallerIconFolder = 506; ProgramDataFolder = 510
    ProgramFilesFolder = 511; VendorRegistryKey = 520; UserRegistryKey = 530; AppDataFolder = 540
}

function Add-PlanItem {
    param(
        [Parameter(Mandatory = $true)] [string] $Category,
        [Parameter(Mandatory = $true)] [int] $Level,
        [Parameter(Mandatory = $true)] [string] $Target,
        [Parameter(Mandatory = $true)] [string] $Action,
        [Parameter(Mandatory = $true)] [string] $Evidence,
        [ValidateSet('low', 'high', 'critical')] [string] $Risk = 'low',
        [string] $Scope = 'machine',
        [switch] $OptIn,
        [string] $Note,
        [long] $Bytes = -1
    )
    if (-not $script:ItemKeys.Add("$Category|$Target|$Action")) { return }
    $script:Items.Add([pscustomobject][ordered]@{
            id = $script:Items.Count + 1; level = $Level; order = $script:Order[$Category]; category = $Category
            scope = $Scope; target = $Target; action = $Action; evidence = $Evidence; risk = $Risk
            optIn = [bool]$OptIn; note = $Note; bytes = $(if ($Bytes -ge 0) { $Bytes } else { $null })
        })
}

function Add-Kept {
    param([string] $Path, [string] $Reason)
    foreach ($k in $script:Kept) { if ($k.path -eq $Path -and $k.reason -eq $Reason) { return } }
    $script:Kept.Add([pscustomobject][ordered]@{ path = $Path; reason = $Reason })
}

# =====================================================================================================
# Main
# =====================================================================================================

function Invoke-Leftovers {
    # Any unexpected error is fatal (exit 4, no plan written): a crash that still wrote a plan and
    # exited 0 would read as "nothing left behind". Expected misses are caught where they happen.
    $ErrorActionPreference = 'Stop'
    $isAdmin = $false
    try {
        $id = [Security.Principal.WindowsIdentity]::GetCurrent()
        $isAdmin = (New-Object Security.Principal.WindowsPrincipal $id).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator) -or $id.IsSystem
    } catch { }
    if (-not $isAdmin) {
        Write-Host 'Leftovers must run elevated (admin or SYSTEM). A non-elevated scan misses services, tasks and other users, and a partial report would read like a complete one.'
        return 3
    }

    Initialize-RegistryBase
    $say = { param($m) if (-not $Quiet) { Write-Host $m } }
    $runId = (Get-Date -Format 'yyyyMMdd-HHmmss') + '-' + ([guid]::NewGuid().ToString('N').Substring(0, 6))

    $loadedSids = Get-LoadedUserSids
    $profiles = Get-Profiles $loadedSids
    $entries = Get-UninstallEntries $loadedSids

    # ---------------------------------------------------------------- List mode
    if ($List) {
        $rows = $entries | Where-Object { $_.DisplayName } | Sort-Object DisplayName, DisplayVersion |
            Select-Object @{ n = 'Name'; e = { $_.DisplayName } }, @{ n = 'Version'; e = { $_.DisplayVersion } },
            @{ n = 'Publisher'; e = { $_.Publisher } }, @{ n = 'Type'; e = { if ($_.IsMsi) { 'MSI' } else { 'EXE' } } },
            @{ n = 'Scope'; e = { if ($_.Sid) { "user $($_.Sid)" } elseif ($_.Hive -eq 'HKLM32') { 'machine (32-bit)' } else { 'machine' } } },
            @{ n = 'ProductCode'; e = { $_.ProductCode } }
        $rows | Format-Table -AutoSize | Out-String -Width 250 | Write-Host
        return 0
    }

    # ---------------------------------------------------------------- Resolve the target
    $matched = @()
    if ($PSCmdlet_ParameterSetName -eq 'Name') {
        $matched = @($entries | Where-Object { $_.DisplayName -and $_.DisplayName.Equals($Name.Trim(), [StringComparison]::OrdinalIgnoreCase) })
        if ($matched.Count -eq 0) {
            Write-Host "No installed app is named exactly '$Name'. Run with -List to see names."
            $near = @($entries | Where-Object { $_.DisplayName -and $_.DisplayName.IndexOf($Name.Trim(), [StringComparison]::OrdinalIgnoreCase) -ge 0 } | Select-Object -First 10)
            if ($near.Count) { Write-Host 'Close matches:'; foreach ($n in $near) { Write-Host "  $($n.DisplayName)   $($n.DisplayVersion)" } }
            return 3
        }
    } elseif ($PSCmdlet_ParameterSetName -eq 'ProductCode') {
        if (-not (Test-IsGuid $ProductCode)) { Write-Host "Not a GUID: $ProductCode"; return 3 }
        $pc = '{' + $ProductCode.Trim().Trim('{', '}').ToUpperInvariant() + '}'
        $matched = @($entries | Where-Object { $_.ProductCode -eq $pc })
        if ($matched.Count -eq 0) {
            # No uninstall entry left at all is a normal state for a broken app: build a stub target
            # from the Installer registration so L0 can still map what the product left behind.
            $matched = @([pscustomobject]@{
                    Hive = 'HKLM64'; Sid = $null; KeyPath = $null; Display = $null; KeyName = $pc; DisplayName = $null
                    DisplayVersion = $null; Publisher = ''; InstallLocation = $null; UninstallString = $null
                    QuietUninstallString = $null; DisplayIcon = $null; SystemComponent = $false; IsMsi = $true; ProductCode = $pc
                })
            $script:Warnings.Add("No uninstall entry exists for $pc; working from its Windows Installer registration only.")
        }
    } elseif ($PSCmdlet_ParameterSetName -eq 'UpgradeCode') {
        if (-not (Test-IsGuid $UpgradeCode)) { Write-Host "Not a GUID: $UpgradeCode"; return 3 }
        $packedUc = ConvertTo-PackedGuid $UpgradeCode
        $uk = Open-Key 'HKLM64' "SOFTWARE\Classes\Installer\UpgradeCodes\$packedUc"
        $pcs = @(Get-ValueNamesSafe $uk | Where-Object { $_ } | ForEach-Object { ConvertFrom-PackedGuid $_ } | Where-Object { $_ })
        Close-Key $uk
        $matched = @($entries | Where-Object { $_.ProductCode -and ($pcs -contains $_.ProductCode) })
        if ($matched.Count -eq 0) { Write-Host "No installed product is registered under UpgradeCode $UpgradeCode."; return 3 }
    }

    # One target = one ProductCode (MSI) or one install location (EXE). The same product seen in two
    # registry views, or a stray duplicate entry, is fine; two different products are ambiguous.
    $distinct = @($matched | ForEach-Object {
            if ($_.ProductCode) { $_.ProductCode } else { ((Get-EntryPaths $_) -join '|') + '|' + $_.DisplayName }
        } | Select-Object -Unique)
    if ($distinct.Count -gt 1) {
        Write-Host "More than one installed product matches. Pick one with -ProductCode:"
        foreach ($m in $matched) { Write-Host "  $($m.DisplayName)  $($m.DisplayVersion)  $($m.ProductCode)  [$($m.Display)]" }
        return 2
    }
    $primary = $matched[0]
    $targetName = if ($primary.DisplayName) { $primary.DisplayName } else { $primary.ProductCode }
    $publisher = $primary.Publisher

    & $say "Leftovers $script:ToolVersion - L0 report for '$targetName' (read-only, nothing changes)"

    # ---------------------------------------------------------------- Protected products
    $refusal = $null
    if (Test-IsMicrosoftName $publisher) { $refusal = "Microsoft product ($publisher). Leftovers never touches Microsoft software, runtimes or management agents; use Settings, the Windows feature tools, or Microsoft's own support tool." }
    elseif ($publisher -match '(?i)\bVitko Software\b' -or $targetName -match '^(?i)RFF (Agent|Updater)\b') { $refusal = 'This is the RFF agent. Leftovers never removes the agent it may be running under.' }
    else {
        foreach ($v in $script:SecurityVendors.Keys) {
            if ((Test-WholeWord $publisher $v) -or (Test-WholeWord $targetName $v)) {
                $refusal = "Security product ($v). Tamper protection makes a generic removal unpredictable. Use $($script:SecurityVendors[$v])."
                break
            }
        }
    }

    # ---------------------------------------------------------------- Identity: Windows Installer
    $pc = $primary.ProductCode
    $isMsi = [bool]($pc -and ($primary.IsMsi -or $PSCmdlet_ParameterSetName -ne 'Name'))
    $packedPc = $null; $upgradeCodeFound = $null; $localPackage = $null; $localPackageExists = $false
    $msiServiceNames = @(); $msiFileNames = @(); $msiFileCount = 0; $msiRegKeys = @()
    $ourComponents = @(); $componentIndex = $null
    $msiRegistration = @()
    if ($pc -and (Test-IsGuid $pc)) {
        $packedPc = ConvertTo-PackedGuid $pc
        & $say '  reading Windows Installer registration...'
        foreach ($p in @(
                @{ Hive = 'HKLM64'; Path = "SOFTWARE\Classes\Installer\Products\$packedPc"; What = 'per-machine product' },
                @{ Hive = 'HKLM64'; Path = "SOFTWARE\Classes\Installer\Features\$packedPc"; What = 'per-machine features' })) {
            $k = Open-Key $p.Hive $p.Path
            if ($k) { $msiRegistration += [pscustomobject]@{ Hive = $p.Hive; Path = $p.Path; What = $p.What }; Close-Key $k }
        }
        $udRoot = 'SOFTWARE\Microsoft\Windows\CurrentVersion\Installer\UserData'
        $ud = Open-Key 'HKLM64' $udRoot
        foreach ($sid in (Get-SubKeyNamesSafe $ud)) {
            $prodPath = "$udRoot\$sid\Products\$packedPc"
            $pk = Open-Key 'HKLM64' $prodPath
            if ($pk) {
                $msiRegistration += [pscustomobject]@{ Hive = 'HKLM64'; Path = $prodPath; What = "UserData product ($sid)" }
                $ip = Open-Key 'HKLM64' "$prodPath\InstallProperties"
                $lp = [string](Get-ValueSafe $ip 'LocalPackage')
                if ($lp) { $localPackage = $lp; $localPackageExists = (Test-Path -LiteralPath $lp -PathType Leaf) }
                if (-not $primary.InstallLocation) { $il = [string](Get-ValueSafe $ip 'InstallLocation'); if ($il) { $primary.InstallLocation = $il } }
                if (-not $publisher) { $publisher = ([string](Get-ValueSafe $ip 'Publisher')).Trim() }
                if (-not $primary.DisplayName) { $dn = [string](Get-ValueSafe $ip 'DisplayName'); if ($dn) { $targetName = $dn; $primary.DisplayName = $dn } }
                Close-Key $ip
                foreach ($patch in (Get-SubKeyNamesSafe (Open-Key 'HKLM64' "$prodPath\Patches"))) {
                    $msiRegistration += [pscustomobject]@{ Hive = 'HKLM64'; Path = "$prodPath\Patches\$patch"; What = 'patch reference' }
                }
                Close-Key $pk
            }
        }
        Close-Key $ud
        $managed = Open-Key 'HKLM64' 'SOFTWARE\Microsoft\Windows\CurrentVersion\Installer\Managed'
        foreach ($sid in (Get-SubKeyNamesSafe $managed)) {
            $mp = "SOFTWARE\Microsoft\Windows\CurrentVersion\Installer\Managed\$sid\Installer\Products\$packedPc"
            $mk = Open-Key 'HKLM64' $mp
            if ($mk) { $msiRegistration += [pscustomobject]@{ Hive = 'HKLM64'; Path = $mp; What = "managed per-user product ($sid)" }; Close-Key $mk }
        }
        Close-Key $managed
        foreach ($sid in $loadedSids) {
            foreach ($sub in @('Products', 'Features')) {
                $up = "$sid\Software\Microsoft\Installer\$sub\$packedPc"
                $uk = Open-Key 'HKU' $up
                if ($uk) { $msiRegistration += [pscustomobject]@{ Hive = 'HKU'; Path = $up; What = "per-user $($sub.ToLowerInvariant())" }; Close-Key $uk }
            }
        }
        # UpgradeCode: the key whose values include our packed ProductCode.
        $ucRoot = Open-Key 'HKLM64' 'SOFTWARE\Classes\Installer\UpgradeCodes'
        foreach ($uc in (Get-SubKeyNamesSafe $ucRoot)) {
            $uk = $null
            try { $uk = $ucRoot.OpenSubKey($uc, $false) } catch { continue }
            if ($uk) {
                if ((Get-ValueNamesSafe $uk) -contains $packedPc) {
                    $upgradeCodeFound = ConvertFrom-PackedGuid $uc
                    $others = @(Get-ValueNamesSafe $uk | Where-Object { $_ -and $_ -ne $packedPc })
                    $msiRegistration += [pscustomobject]@{ Hive = 'HKLM64'; Path = "SOFTWARE\Classes\Installer\UpgradeCodes\$uc"; What = "upgrade code (other products under it: $($others.Count))" }
                }
                Close-Key $uk
            }
        }
        Close-Key $ucRoot

        & $say '  indexing Windows Installer components (one pass; can take a minute)...'
        $componentIndex = Get-MsiComponentIndex $packedPc
        # .ToArray(), never @(): PowerShell 7.6 throws "Argument types do not match" on @() over a
        # generic List of objects (reproduced 2026-09-25).
        $ourComponents = $componentIndex.Ours.ToArray()

        if ($localPackage -and $localPackageExists) {
            & $say '  reading the cached MSI tables...'
            $msiServiceNames = @(Get-MsiTableRows $localPackage 'SELECT `Name` FROM `ServiceInstall`' 1 | ForEach-Object { $_[0] } | Where-Object { $_ } | Select-Object -Unique)
            $fileRows = Get-MsiTableRows $localPackage 'SELECT `FileName` FROM `File`' 1
            $msiFileCount = @($fileRows).Count
            $msiFileNames = @($fileRows | ForEach-Object { $n = $_[0]; if ($n -match '\|') { $n.Split('|')[1] } else { $n } } | ForEach-Object { $_.ToLowerInvariant() } | Select-Object -Unique)
            $msiRegKeys = @(Get-MsiTableRows $localPackage 'SELECT `Root`, `Key` FROM `Registry`' 2 | ForEach-Object { "$($_[0])|$($_[1])" } | Select-Object -Unique)
        }
    }

    # ---------------------------------------------------------------- Identity: roots
    $treeProtected = @($env:SystemRoot, (Join-Path $env:ProgramData 'Microsoft'), (Join-Path $env:SystemDrive 'Recovery'),
        (Join-Path $env:SystemDrive 'System Volume Information'), (Join-Path $env:SystemDrive '$Recycle.Bin'))
    $containerProtected = @($env:ProgramFiles, ${env:ProgramFiles(x86)}, $env:CommonProgramFiles, ${env:CommonProgramFiles(x86)},
        $env:ProgramData, (Join-Path $env:SystemDrive 'Users'), $env:PUBLIC, (Join-Path $env:SystemDrive 'Users\Default'))
    foreach ($pr in $profiles) {
        $containerProtected += $pr.Path
        foreach ($sub in @('AppData', 'AppData\Local', 'AppData\LocalLow', 'AppData\Roaming', 'AppData\Local\Programs', 'AppData\Local\Temp',
                'Desktop', 'Documents', 'Downloads', 'OneDrive', 'Pictures', 'Music', 'Videos', 'Favorites', 'AppData\Roaming\Microsoft', 'AppData\Local\Microsoft')) {
            $containerProtected += (Join-Path $pr.Path $sub)
        }
    }
    # The RFF agent's own folders are a protected tree (the tool may be running under it).
    foreach ($svcName in @('RFFAgent', 'RFFUpdater')) {
        $sk = Open-Key 'HKLM64' "SYSTEM\CurrentControlSet\Services\$svcName"
        if ($sk) {
            $exe = Resolve-ServiceImagePath ([string](Get-ValueSafe $sk 'ImagePath')) $svcName 16
            if ($exe) { $treeProtected += (Split-Path $exe -Parent) }
            Close-Key $sk
        }
    }

    $otherEntries = @($entries | Where-Object { $matched -notcontains $_ -and $_.DisplayName -and -not ($pc -and $_.ProductCode -eq $pc) })
    $rootCandidates = @()
    foreach ($m in $matched) {
        foreach ($p in (Get-EntryPaths $m)) {
            $rootCandidates += [pscustomobject]@{ Path = $p; Why = "uninstall entry ($($m.Display))" }
            # A versioned install folder (...\Drive File Stream\131.0.2.0): its parent is the app's too,
            # unless another product turns out to live there (the cross-reference below decides).
            if ((Split-Path $p -Leaf) -match '^\d+(\.\d+){1,3}$') {
                $rootCandidates += [pscustomobject]@{ Path = (Split-Path $p -Parent); Why = "parent of the versioned folder $p" }
            }
        }
    }
    $identityFiles = @()     # files the MSI says are ours, sitting in protected folders (System32 etc.)
    $componentRegKeys = @()
    foreach ($c in $ourComponents) {
        $kp = ConvertFrom-MsiKeyPath $c.KeyPath
        if ($null -eq $kp) { continue }
        $sharedWith = @(Get-OtherComponentClients $componentIndex $c.Component $packedPc)
        if ($kp.Kind -eq 'File') {
            if ($sharedWith.Count -gt 0) { continue }
            if (-not $kp.IsFolder) { [void]$script:OurFiles.Add($kp.Path) }
            $dir = if ($kp.IsFolder) { $kp.Path } else { Split-Path $kp.Path -Parent }
            if (-not (Get-ProtectedPathReason $dir $containerProtected $treeProtected)) {
                $rootCandidates += [pscustomobject]@{ Path = $dir; Why = "MSI component $($c.Component)" }
            } elseif (-not $kp.IsFolder -and (Test-Path -LiteralPath $kp.Path -PathType Leaf)) {
                $identityFiles += [pscustomobject]@{ Path = $kp.Path; Component = $c.Component }
            }
        } elseif ($kp.Kind -eq 'Registry') {
            $componentRegKeys += $kp
        }
    }

    $roots = @(); $refusedRoots = @()
    foreach ($cand in ($rootCandidates | Sort-Object { $_.Path.Length })) {
        $n = Get-NormalizedPath $cand.Path
        if (-not $n) { continue }
        if (@($roots | Where-Object { Test-PathUnder $n $_.Path }).Count -gt 0) { continue }
        $why = Get-ProtectedPathReason $n $containerProtected $treeProtected
        if ($why) {
            if (-not ($refusedRoots | Where-Object { $_.Path -eq $n })) { $refusedRoots += [pscustomobject]@{ Path = $n; Why = $why; From = $cand.Why } }
            continue
        }
        $roots += [pscustomobject]@{ Path = $n; Why = $cand.Why; Exists = (Test-Path -LiteralPath $n -PathType Container); Shared = $false }
    }

    # ---------------------------------------------------------------- Cross-reference, BEFORE discovery
    # What other installed products still point into these folders. A folder holding anything of
    # theirs is SHARED: inside it nothing is matched by "it's in the folder", only by this app's own
    # files, and the folder itself is never removed.
    foreach ($o in $otherEntries) {
        foreach ($p in (Get-EntryPaths $o)) {
            foreach ($r in $roots) {
                if (Test-PathUnder $p $r.Path) { Add-Kept $p "the uninstall entry of '$($o.DisplayName)' points here" }
                elseif (Test-PathUnder $r.Path $p) { $script:Warnings.Add("'$($o.DisplayName)' is installed in $p, which CONTAINS this app's folder $($r.Path). Only $($r.Path) itself is in scope.") }
            }
        }
    }
    if ($componentIndex -and $roots.Count) {
        # Cheap prefix test first: ~100k key paths, and only a handful can sit inside our folders.
        $prefixes = @()
        foreach ($r in $roots) { $prefixes += $r.Path.TrimEnd('\') + '\'; $s = Get-ShortPathSafe $r.Path; if ($s) { $prefixes += $s.TrimEnd('\') + '\' } }
        foreach ($e in $componentIndex.All) {
            if ($e.Client -eq $packedPc) { continue }
            $raw = $e.KeyPath
            if (-not $raw -or $raw.Length -lt 4 -or $raw[2] -ne '\') { continue }
            $inside = $false
            foreach ($pfx in $prefixes) { if ($raw.StartsWith($pfx, [StringComparison]::OrdinalIgnoreCase)) { $inside = $true; break } }
            if (-not $inside) { continue }
            $kp = ConvertFrom-MsiKeyPath $raw
            if ($kp -and $kp.Kind -eq 'File') {
                $who = if ($e.Client -eq '00000000000000000000000000000000') { 'a permanent (system) component' } else { "Windows Installer product $(ConvertFrom-PackedGuid $e.Client)" }
                Add-Kept $kp.Path "$who still owns it"
            }
        }
    }
    foreach ($r in $roots) { $r.Shared = (@($script:Kept | Where-Object { Test-PathUnder $_.path $r.Path }).Count -gt 0) }
    $rootPaths = @($roots | ForEach-Object { $_.Path })
    $exclusiveRoots = @($roots | Where-Object { -not $_.Shared } | ForEach-Object { $_.Path })
    $script:MatchRoots = @($exclusiveRoots)
    foreach ($r in $exclusiveRoots) { $s = Get-ShortPathSafe $r; if ($s) { $script:MatchRoots += $s } }
    foreach ($r in $roots | Where-Object { $_.Shared }) {
        $script:Warnings.Add("$($r.Path) is SHARED with other products: inside it only this app's own $($script:OurFiles.Count) MSI file(s) are matched, and the folder stays.")
    }

    # ---------------------------------------------------------------- Identity: signer
    $signerOrg = $null; $signerFiles = @()
    $probe = @()
    foreach ($m in $matched) {
        foreach ($cmd in @($m.UninstallString, $m.QuietUninstallString)) { $e = Get-CommandExePath $cmd; if ($e -and (Test-OurReference $e)) { $probe += $e } }
        if ($m.DisplayIcon) { $i = Get-NormalizedPath ($m.DisplayIcon -replace ',\s*-?\d+\s*$', ''); if ($i -and $i -match '\.exe$' -and (Test-OurReference $i)) { $probe += $i } }
    }
    $probe += @($script:OurFiles | Where-Object { $_ -match '\.exe$' } | Select-Object -First 5)
    foreach ($r in $roots | Where-Object { $_.Exists -and -not $_.Shared }) {
        try {
            $probe += @(Get-ChildItem -LiteralPath $r.Path -Filter *.exe -File -ErrorAction SilentlyContinue | Sort-Object Length -Descending | Select-Object -First 3 | ForEach-Object { $_.FullName })
        } catch { }
    }
    $orgCounts = @{}
    foreach ($f in ($probe | Where-Object { $_ -and (Test-Path -LiteralPath $_ -PathType Leaf) } | Select-Object -Unique)) {
        $org = Get-SignerOrg (Get-SignerSubject $f)
        if ($org) { $signerFiles += "$f ($org)"; if ($orgCounts.ContainsKey($org)) { $orgCounts[$org]++ } else { $orgCounts[$org] = 1 } }
    }
    if ($orgCounts.Count) { $signerOrg = ($orgCounts.GetEnumerator() | Sort-Object Value -Descending | Select-Object -First 1).Key }
    if (-not $refusal -and $signerOrg -and (Test-IsMicrosoftName $signerOrg) -and -not (Test-IsMicrosoftName $publisher)) {
        $refusal = "The app's own executables are signed by Microsoft ($signerOrg). Refusing: it may be a Microsoft component under another name."
    }
    $samePublisherOthers = @($entries | Where-Object { $_.Publisher -and $publisher -and $_.Publisher.Equals($publisher, [StringComparison]::OrdinalIgnoreCase) -and $matched -notcontains $_ -and ($_.ProductCode -ne $pc -or -not $pc) } | ForEach-Object { $_.DisplayName } | Select-Object -Unique)

    # ---------------------------------------------------------------- Refused: write the stub plan and stop
    $outDirFinal = if ($OutDir) { $OutDir } else { Join-Path $env:ProgramData "Leftovers\reports\$runId" }

    $target = [ordered]@{
        displayName = $targetName; version = $primary.DisplayVersion; publisher = $publisher
        productCode = $pc; upgradeCode = $upgradeCodeFound; isMsi = $isMsi
        uninstallEntries = @($matched | ForEach-Object { $_.Display } | Where-Object { $_ })
        uninstallString = $primary.UninstallString
        cachedMsi = $localPackage; cachedMsiPresent = $localPackageExists
    }
    if ($refusal) {
        $plan = [ordered]@{
            tool = 'Leftovers'; version = $script:ToolVersion; runId = $runId; computer = $env:COMPUTERNAME
            generatedUtc = (Get-Date).ToUniversalTime().ToString('o'); level = 0; refused = $refusal; target = $target
        }
        Write-PlanFiles $plan $outDirFinal | Out-Null
        & $say ''
        & $say "REFUSED: $refusal"
        return 2
    }

    & $say '  scanning services, drivers, device filters, network components...'
    # ---------------------------------------------------------------- Discovery: services and drivers
    $services = @()
    $svcRoot = Open-Key 'HKLM64' 'SYSTEM\CurrentControlSet\Services' 'services'
    foreach ($s in (Get-SubKeyNamesSafe $svcRoot 'services')) {
        $sk = $null
        try { $sk = $svcRoot.OpenSubKey($s, $false) } catch { Add-Unreadable 'services'; continue }
        if ($null -eq $sk) { continue }
        $type = [int](0 + (Get-ValueSafe $sk 'Type'))
        $image = [string](Get-ValueSafe $sk 'ImagePath')
        $pk = $null
        try { $pk = $sk.OpenSubKey('Parameters', $false) } catch { }
        $services += [pscustomobject]@{
            Name = $s; DisplayName = [string](Get-ValueSafe $sk 'DisplayName'); Type = $type
            Start = [int](0 + (Get-ValueSafe $sk 'Start')); ImageRaw = $image
            Image = (Resolve-ServiceImagePath $image $s $type)
            ServiceDll = (Get-NormalizedPath ([string](Get-ValueSafe $pk 'ServiceDll')))
            ProviderPath = $null
        }
        Close-Key $pk
        Close-Key $sk
    }
    Close-Key $svcRoot
    # A service or driver is the app's when its command line or ServiceDll points at the app, when the
    # app's MSI installs it, or (for files OUTSIDE the app's folders, like System32\drivers\npcap.sys)
    # when the file's own version resource names the app's vendor. That last one is the weakest tie:
    # it is labelled, and needs review when the vendor has other products installed.
    $otherProductPaths = @($otherEntries | ForEach-Object { Get-EntryPaths $_ } | Where-Object { $_ } | Select-Object -Unique)
    $vendorNames = @(@($signerOrg, $publisher) | Where-Object { $_ -and -not (Test-IsMicrosoftName $_) })
    $ourServices = @()
    foreach ($s in $services) {
        $ev = @(); $weak = $false
        if ($s.ImageRaw -and (Test-OurReference $s.ImageRaw)) { $ev += "runs $($s.ImageRaw)" }
        elseif ($s.Image -and (Test-OurReference $s.Image)) { $ev += "image $($s.Image) points at the app" }
        if ($s.ServiceDll -and (Test-OurReference $s.ServiceDll)) { $ev += "ServiceDll $($s.ServiceDll) points at the app" }
        if ($msiServiceNames -contains $s.Name) { $ev += "the app's MSI installs service '$($s.Name)'" }
        if (-not $ev.Count -and $vendorNames.Count) {
            $file = if ($s.ServiceDll) { $s.ServiceDll } else { $s.Image }
            if ($file -and -not (@($otherProductPaths | Where-Object { Test-PathUnder $file $_ }).Count)) {
                $company = Get-VendorOfFile $file
                if ($company -and -not (Test-IsMicrosoftName $company)) {
                    foreach ($v in $vendorNames) {
                        if (Test-SameVendor $company $v) { $ev += "VENDOR-ONLY: $file declares company '$company', the app's vendor"; $weak = $true; break }
                    }
                }
            }
        }
        if ($ev.Count) { $ourServices += [pscustomobject]@{ Svc = $s; Evidence = ($ev -join '; '); Weak = $weak } }
    }
    $ourServiceNames = @($ourServices | ForEach-Object { $_.Svc.Name })
    $ourDriverNames = @($ourServices | Where-Object { $_.Svc.Type -band 0xB } | ForEach-Object { $_.Svc.Name })
    $reviewServices = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
    foreach ($o in $ourServices) {
        $s = $o.Svc
        $isDriver = [bool]($s.Type -band 0xB)
        $boot = ($isDriver -and $s.Start -le 1)
        $review = ($o.Weak -and $samePublisherOthers.Count -gt 0)
        if ($review) { [void]$reviewServices.Add($s.Name) }
        $note = if ($review) { "needs review: tied only by the file's declared vendor, and $publisher has other products installed" } elseif ($o.Weak) { "tied by the file's declared vendor, not by a path" } else { $null }
        if ($isDriver) {
            $act = if ($boot) { 'set Start=4 and delete on reboot (boot/system-start driver: never removed live)' } else { 'stop, disable, delete driver service' }
            Add-PlanItem -Category 'Driver' -Level 3 -Target "driver $($s.Name) ($($s.Image))" -Action $act -Evidence $o.Evidence -Risk $(if ($boot) { 'critical' } else { 'high' }) -OptIn:$review -Note $note
        } else {
            Add-PlanItem -Category 'Service' -Level 3 -Target "service $($s.Name) '$($s.DisplayName)'" -Action 'stop, disable, delete service' -Evidence $o.Evidence -Risk $(if ($o.Weak) { 'high' } else { 'low' }) -OptIn:$review -Note $note
        }
    }

    # ---------------------------------------------------------------- Discovery: device filters (the brick-the-class item)
    if ($ourDriverNames.Count) {
        $classRoot = Open-Key 'HKLM64' 'SYSTEM\CurrentControlSet\Control\Class' 'device classes'
        foreach ($g in (Get-SubKeyNamesSafe $classRoot 'device classes')) {
            $ck = $null
            try { $ck = $classRoot.OpenSubKey($g, $false) } catch { Add-Unreadable 'device classes'; continue }
            if ($null -eq $ck) { continue }
            $className = [string](Get-ValueSafe $ck 'Class')
            foreach ($which in @('UpperFilters', 'LowerFilters')) {
                $vals = @(Get-ValueSafe $ck $which)
                foreach ($d in $ourDriverNames) {
                    if ($vals -contains $d) {
                        $rest = @($vals | Where-Object { $_ -and $_ -ne $d })
                        Add-PlanItem -Category 'DeviceClassFilter' -Level 3 -Target "HKLM\SYSTEM\CurrentControlSet\Control\Class\$g [$className] $which" `
                            -Action "remove '$d' from $which BEFORE the driver is deleted; keep: $(if ($rest.Count) { $rest -join ', ' } else { '(nothing else)' })" `
                            -Evidence "the $className class loads our driver '$d' as a filter; leaving it listed stops EVERY $className device at the next boot" -Risk 'critical' `
                            -OptIn:($reviewServices.Contains($d)) -Note $(if ($reviewServices.Contains($d)) { "needs review: driver '$d' is tied by vendor only" } else { $null })
                    }
                }
            }
            Close-Key $ck
        }
        Close-Key $classRoot
        $enumRoot = Open-Key 'HKLM64' 'SYSTEM\CurrentControlSet\Enum' 'device instances'
        foreach ($bus in (Get-SubKeyNamesSafe $enumRoot 'device instances')) {
            $bk = $null; try { $bk = $enumRoot.OpenSubKey($bus, $false) } catch { Add-Unreadable 'device instances'; continue }
            foreach ($dev in (Get-SubKeyNamesSafe $bk 'device instances')) {
                $dk = $null; try { $dk = $bk.OpenSubKey($dev, $false) } catch { Add-Unreadable 'device instances'; continue }
                foreach ($inst in (Get-SubKeyNamesSafe $dk 'device instances')) {
                    $ik = $null; try { $ik = $dk.OpenSubKey($inst, $false) } catch { Add-Unreadable 'device instances'; continue }
                    if ($null -eq $ik) { continue }
                    foreach ($which in @('UpperFilters', 'LowerFilters')) {
                        $vals = @(Get-ValueSafe $ik $which)
                        foreach ($d in $ourDriverNames) {
                            if ($vals -contains $d) {
                                $friendly = [string](Get-ValueSafe $ik 'FriendlyName'); if (-not $friendly) { $friendly = [string](Get-ValueSafe $ik 'DeviceDesc') }
                                Add-PlanItem -Category 'DeviceInstanceFilter' -Level 3 -Target "HKLM\SYSTEM\CurrentControlSet\Enum\$bus\$dev\$inst $which" `
                                    -Action "remove '$d' from $which BEFORE the driver is deleted" `
                                    -Evidence "device '$friendly' loads our driver '$d' as a filter; leaving it listed stops that device at the next boot" -Risk 'critical' `
                                    -OptIn:($reviewServices.Contains($d)) -Note $(if ($reviewServices.Contains($d)) { "needs review: driver '$d' is tied by vendor only" } else { $null })
                            }
                        }
                    }
                    Close-Key $ik
                }
                Close-Key $dk
            }
            Close-Key $bk
        }
        Close-Key $enumRoot
    }

    # ---------------------------------------------------------------- Discovery: network components, driver packages
    $ourNetComponentIds = @()
    if ($ourServiceNames.Count) {
        foreach ($netClass in @('{4D36E974-E325-11CE-BFC1-08002BE10318}', '{4D36E975-E325-11CE-BFC1-08002BE10318}', '{4D36E973-E325-11CE-BFC1-08002BE10318}')) {
            $nk = Open-Key 'HKLM64' "SYSTEM\CurrentControlSet\Control\Network\$netClass" 'network components'
            foreach ($inst in (Get-SubKeyNamesSafe $nk 'network components')) {
                $ik = $null; try { $ik = $nk.OpenSubKey($inst, $false) } catch { continue }
                if ($null -eq $ik) { continue }
                $cid = [string](Get-ValueSafe $ik 'ComponentId')
                $ndi = $null; try { $ndi = $ik.OpenSubKey('Ndi', $false) } catch { }
                $svc = [string](Get-ValueSafe $ndi 'Service')
                if ($cid -and $svc -and ($ourServiceNames -contains $svc)) {
                    $ourNetComponentIds += $cid
                    Add-PlanItem -Category 'NetworkComponent' -Level 3 -Target "network component $cid (service $svc)" `
                        -Action "netcfg -u $cid (unbinds it cleanly; never delete the service directly)" `
                        -Evidence "network component bound to our service '$svc'" -Risk 'critical' `
                        -OptIn:($reviewServices.Contains($svc)) -Note $(if ($reviewServices.Contains($svc)) { "needs review: service '$svc' is tied by vendor only" } else { $null })
                }
                Close-Key $ndi; Close-Key $ik
            }
            Close-Key $nk
        }
        $infDir = Join-Path $env:SystemRoot 'INF'
        foreach ($inf in @(Get-ChildItem -LiteralPath $infDir -Filter 'oem*.inf' -File -ErrorAction SilentlyContinue)) {
            $text = $null
            try { $text = [System.IO.File]::ReadAllText($inf.FullName) } catch { Add-Unreadable 'driver packages'; continue }
            # INFs often name the service through a [Strings] token (Npcap: AddService = %NPF_DriverName%).
            $strings = @{}
            foreach ($sec in [regex]::Matches($text, '(?ims)^\s*\[Strings(\.[0-9A-Za-z]+)?\][^\r\n]*\r?\n(.*?)(?=^\s*\[|\z)')) {
                foreach ($l in [regex]::Matches($sec.Groups[2].Value, '(?m)^\s*([^=;\s]+)\s*=\s*"?([^"\r\n;]*)"?')) {
                    if (-not $strings.ContainsKey($l.Groups[1].Value)) { $strings[$l.Groups[1].Value] = $l.Groups[2].Value.Trim() }
                }
            }
            # The package of a network component we found (INSECURE_NPCAP) is ours too, by ComponentId.
            $byComponentId = $null
            foreach ($cid in $ourNetComponentIds) { if ($text -match ('(?i)(?<![A-Za-z0-9_])' + [regex]::Escape($cid) + '(?![A-Za-z0-9_])')) { $byComponentId = $cid; break } }
            if ($byComponentId) {
                Add-PlanItem -Category 'DriverPackage' -Level 3 -Target "driver package $($inf.Name)" `
                    -Action "pnputil /delete-driver $($inf.Name) /uninstall (or PnP reinstalls it at the next scan)" `
                    -Evidence "$($inf.Name) installs our network component $byComponentId" -Risk 'high'
                continue
            }
            foreach ($m in [regex]::Matches($text, '(?im)^\s*AddService\s*=\s*"?([^",\s]+)')) {
                $svc = $m.Groups[1].Value
                if ($svc -match '^%(.+)%$' -and $strings.ContainsKey($matches[1])) { $svc = $strings[$matches[1]] }
                if ($ourServiceNames -contains $svc) {
                    Add-PlanItem -Category 'DriverPackage' -Level 3 -Target "driver package $($inf.Name)" `
                        -Action "pnputil /delete-driver $($inf.Name) /uninstall (or PnP reinstalls it at the next scan)" `
                        -Evidence "$($inf.Name) installs our service '$svc'" -Risk 'high' `
                        -OptIn:($reviewServices.Contains($svc)) -Note $(if ($reviewServices.Contains($svc)) { "needs review: service '$svc' is tied by vendor only" } else { $null })
                    break
                }
            }
        }
    }

    & $say '  scanning tasks, startup entries, COM and shell extensions...'
    # ---------------------------------------------------------------- Discovery: scheduled tasks
    $ourClsids = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
    $ourClassKeys = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
    $taskList = @()
    try { $taskList = @(Get-ScheduledTask -ErrorAction Stop) } catch { Add-Unreadable 'scheduled tasks' }

    # ---------------------------------------------------------------- Discovery: COM (needed before tasks for ComHandler)
    $comSources = @(@{ Hive = 'HKLM64'; Path = 'SOFTWARE\Classes'; Scope = 'machine' }, @{ Hive = 'HKLM32'; Path = 'SOFTWARE\Classes'; Scope = 'machine (32-bit)' })
    foreach ($sid in $loadedSids) { $comSources += @{ Hive = 'HKU'; Path = "$($sid)_Classes"; Scope = "user:$sid" } }
    foreach ($src in $comSources) {
        $clsidRoot = Open-Key $src.Hive "$($src.Path)\CLSID" 'COM classes'
        foreach ($clsid in (Get-SubKeyNamesSafe $clsidRoot 'COM classes')) {
            $ck = $null; try { $ck = $clsidRoot.OpenSubKey($clsid, $false) } catch { Add-Unreadable 'COM classes'; continue }
            if ($null -eq $ck) { continue }
            foreach ($server in @('InprocServer32', 'LocalServer32', 'InprocHandler32')) {
                $sk = $null; try { $sk = $ck.OpenSubKey($server, $false) } catch { }
                $val = [string](Get-ValueSafe $sk '')
                Close-Key $sk
                if ($val -and (Test-OurReference $val)) {
                    [void]$ourClsids.Add($clsid)
                    $progId = $null; $pk = $null; try { $pk = $ck.OpenSubKey('ProgID', $false) } catch { }
                    $progId = [string](Get-ValueSafe $pk ''); Close-Key $pk
                    $appId = [string](Get-ValueSafe $ck 'AppID')
                    Add-PlanItem -Category 'ComClass' -Level 3 -Scope $src.Scope -Target (Format-RegPath $src.Hive "$($src.Path)\CLSID\$clsid") `
                        -Action 'delete key' -Evidence "$server = $val (points at the app)"
                    if ($progId) {
                        [void]$ourClassKeys.Add($progId)
                        Add-PlanItem -Category 'ComProgId' -Level 3 -Scope $src.Scope -Target (Format-RegPath $src.Hive "$($src.Path)\$progId") `
                            -Action 'delete key (only if its CLSID still points at the class above)' -Evidence "ProgID of our class $clsid"
                    }
                    if ($appId -and (Test-IsGuid $appId)) {
                        Add-PlanItem -Category 'ComAppId' -Level 3 -Scope $src.Scope -Target (Format-RegPath $src.Hive "$($src.Path)\AppID\$appId") `
                            -Action 'delete key (only if no other class uses this AppID)' -Evidence "AppID of our class $clsid"
                    }
                    break
                }
            }
            Close-Key $ck
        }
        Close-Key $clsidRoot
        # TypeLib is shared between the registry views: scan it once (64-bit view, and per user).
        if ($src.Hive -eq 'HKLM32') { continue }
        $tlRoot = Open-Key $src.Hive "$($src.Path)\TypeLib" 'COM type libraries'
        foreach ($tl in (Get-SubKeyNamesSafe $tlRoot 'COM type libraries')) {
            $tk = $null; try { $tk = $tlRoot.OpenSubKey($tl, $false) } catch { continue }
            if ($null -eq $tk) { continue }
            $hit = $null
            foreach ($ver in (Get-SubKeyNamesSafe $tk)) {
                $vk = $null; try { $vk = $tk.OpenSubKey($ver, $false) } catch { continue }
                foreach ($lcid in (Get-SubKeyNamesSafe $vk)) {
                    foreach ($plat in @('win32', 'win64')) {
                        $pk = $null; try { $pk = $vk.OpenSubKey("$lcid\$plat", $false) } catch { }
                        $val = [string](Get-ValueSafe $pk ''); Close-Key $pk
                        if ($val -and (Test-OurReference $val)) { $hit = $val }
                    }
                }
                Close-Key $vk
            }
            Close-Key $tk
            if ($hit) {
                Add-PlanItem -Category 'ComTypeLib' -Level 3 -Scope $src.Scope -Target (Format-RegPath $src.Hive "$($src.Path)\TypeLib\$tl") `
                    -Action 'delete key' -Evidence "type library file $hit points at the app"
            }
        }
        Close-Key $tlRoot

        # File associations: ProgIDs (and Applications\<exe>) whose open command or icon is the app.
        # Extensions still naming a removed ProgID are harmless dangling references and are left alone.
        $cr = Open-Key $src.Hive $src.Path 'file associations'
        $assocKeys = @()
        foreach ($n in (Get-SubKeyNamesSafe $cr 'file associations')) {
            if ($n.StartsWith('.') -or $n -in @('CLSID', 'TypeLib', 'Interface', 'AppID', 'Installer', 'WOW6432Node', 'Wow6432Node', '*', 'Directory', 'Drive', 'Folder', 'AllFilesystemObjects', 'Applications', 'SystemFileAssociations', 'MIME', 'Local Settings')) { continue }
            $assocKeys += $n
        }
        $apps = $null; try { $apps = $cr.OpenSubKey('Applications', $false) } catch { }
        foreach ($n in (Get-SubKeyNamesSafe $apps)) { $assocKeys += "Applications\$n" }
        Close-Key $apps
        foreach ($n in $assocKeys) {
            if ($ourClassKeys.Contains($n)) { continue }
            $ak = $null; try { $ak = $cr.OpenSubKey($n, $false) } catch { continue }
            if ($null -eq $ak) { continue }
            $why = $null
            foreach ($sub in @('shell\open\command', 'DefaultIcon')) {
                $sk = $null; try { $sk = $ak.OpenSubKey($sub, $false) } catch { }
                $val = [string](Get-ValueSafe $sk ''); Close-Key $sk
                if ($val -and (Test-OurReference $val)) { $why = "$sub = $val"; break }
            }
            Close-Key $ak
            if ($why) {
                [void]$ourClassKeys.Add($n)
                Add-PlanItem -Category 'FileAssociation' -Level 3 -Scope $src.Scope -Target (Format-RegPath $src.Hive "$($src.Path)\$n") `
                    -Action 'delete key' -Evidence $why
            }
        }
        Close-Key $cr
    }

    foreach ($t in $taskList) {
        $refs = @()
        foreach ($a in @($t.Actions)) {
            $props = $a.PSObject.Properties.Name
            if ($props -contains 'Execute') {
                foreach ($field in @($a.Execute, $a.Arguments, $a.WorkingDirectory)) { if ($field -and (Test-OurReference ([string]$field))) { $refs += [string]$field } }
            }
            if ($props -contains 'ClassId' -and $a.ClassId -and $ourClsids.Contains([string]$a.ClassId)) { $refs += "COM handler $($a.ClassId)" }
        }
        if ($refs.Count) {
            Add-PlanItem -Category 'ScheduledTask' -Level 3 -Target "task $($t.TaskPath)$($t.TaskName)" -Action 'unregister task' `
                -Evidence ("action runs " + (($refs | Select-Object -Unique) -join '; '))
        }
    }

    # ---------------------------------------------------------------- Discovery: Run keys (+ StartupApproved twins)
    $runSources = @()
    foreach ($h in @('HKLM64', 'HKLM32')) {
        foreach ($p in @('SOFTWARE\Microsoft\Windows\CurrentVersion\Run', 'SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce', 'SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run')) {
            $runSources += @{ Hive = $h; Path = $p; Scope = 'machine' }
        }
    }
    foreach ($sid in $loadedSids) {
        foreach ($p in @('Software\Microsoft\Windows\CurrentVersion\Run', 'Software\Microsoft\Windows\CurrentVersion\RunOnce', 'Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run')) {
            $runSources += @{ Hive = 'HKU'; Path = "$sid\$p"; Scope = "user:$sid" }
        }
    }
    foreach ($src in $runSources) {
        $rk = Open-Key $src.Hive $src.Path 'startup entries'
        foreach ($v in (Get-ValueNamesSafe $rk 'startup entries')) {
            $data = [string](Get-ValueSafe $rk $v)
            if ($data -and (Test-OurReference $data)) {
                Add-PlanItem -Category 'RunValue' -Level 3 -Scope $src.Scope -Target "$(Format-RegPath $src.Hive $src.Path) : $v" `
                    -Action "delete value '$v' (and its Explorer\StartupApproved entry)" -Evidence "runs $data"
            }
        }
        Close-Key $rk
    }

    # ---------------------------------------------------------------- Discovery: shell extensions
    if ($ourClsids.Count) {
        foreach ($h in @('HKLM64', 'HKLM32')) {
            $ak = Open-Key $h 'SOFTWARE\Microsoft\Windows\CurrentVersion\Shell Extensions\Approved' 'shell extensions'
            foreach ($v in (Get-ValueNamesSafe $ak)) {
                if ($ourClsids.Contains($v)) {
                    Add-PlanItem -Category 'ShellExtension' -Level 3 -Target "$(Format-RegPath $h 'SOFTWARE\Microsoft\Windows\CurrentVersion\Shell Extensions\Approved') : $v" `
                        -Action "delete value '$v'" -Evidence "approval for our shell extension class $v"
                }
            }
            Close-Key $ak
            $ok = Open-Key $h 'SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\ShellIconOverlayIdentifiers' 'shell extensions'
            foreach ($n in (Get-SubKeyNamesSafe $ok)) {
                $sk = $null; try { $sk = $ok.OpenSubKey($n, $false) } catch { continue }
                $val = [string](Get-ValueSafe $sk ''); Close-Key $sk
                if ($val -and $ourClsids.Contains($val.Trim())) {
                    Add-PlanItem -Category 'ShellExtension' -Level 3 -Target (Format-RegPath $h "SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\ShellIconOverlayIdentifiers\$n") `
                        -Action 'delete key' -Evidence "icon overlay handler = our class $val"
                }
            }
            Close-Key $ok
            $bho = Open-Key $h 'SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Browser Helper Objects' 'shell extensions'
            foreach ($n in (Get-SubKeyNamesSafe $bho)) {
                if ($ourClsids.Contains($n)) {
                    Add-PlanItem -Category 'ShellExtension' -Level 3 -Target (Format-RegPath $h "SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Browser Helper Objects\$n") -Action 'delete key' -Evidence "browser helper object = our class $n"
                }
            }
            Close-Key $bho
            foreach ($base in @('*', 'Directory', 'Directory\Background', 'Folder', 'Drive', 'AllFilesystemObjects', 'lnkfile')) {
                foreach ($kind in @('ContextMenuHandlers', 'PropertySheetHandlers', 'DragDropHandlers', 'CopyHookHandlers', 'IconOverlayHandlers')) {
                    $hp = "SOFTWARE\Classes\$base\shellex\$kind"
                    $hk = Open-Key $h $hp 'shell extensions'
                    foreach ($n in (Get-SubKeyNamesSafe $hk)) {
                        $sk = $null; try { $sk = $hk.OpenSubKey($n, $false) } catch { continue }
                        $val = ([string](Get-ValueSafe $sk '')).Trim(); Close-Key $sk
                        if (($val -and $ourClsids.Contains($val)) -or $ourClsids.Contains($n)) {
                            Add-PlanItem -Category 'ShellExtension' -Level 3 -Target (Format-RegPath $h "$hp\$n") -Action 'delete key' -Evidence "$kind handler = our class $(if ($val) { $val } else { $n })"
                        }
                    }
                    Close-Key $hk
                }
            }
        }
    }

    & $say '  scanning logon, LSA, network provider, firewall and shortcut hooks...'
    # ---------------------------------------------------------------- Discovery: credential providers (+ the password provider)
    $passwordProvider = '{60b78e88-EAD8-445C-9CFD-0B87F74EA6CD}'
    $ourCredProviders = 0
    foreach ($kind in @(@{ Path = 'Credential Provider Filters'; Cat = 'CredentialProviderFilter'; Label = 'credential provider FILTER'; Act = 'delete key FIRST (before the provider), then verify the logon screen still offers the password tile' },
            @{ Path = 'Credential Providers'; Cat = 'CredentialProvider'; Label = 'credential provider'; Act = 'delete key, after the filter' })) {
        $root = "SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\$($kind.Path)"
        $ck = Open-Key 'HKLM64' $root 'credential providers'
        foreach ($clsid in (Get-SubKeyNamesSafe $ck)) {
            $isOurs = $ourClsids.Contains($clsid)
            $evidence = "its COM server is under the app's folder"
            if (-not $isOurs -and $signerOrg) {
                $srv = Open-Key 'HKLM64' "SOFTWARE\Classes\CLSID\$clsid\InprocServer32"
                $dll = Get-NormalizedPath ([string](Get-ValueSafe $srv '')); Close-Key $srv
                if ($dll -and (Test-Path -LiteralPath $dll -PathType Leaf)) {
                    $org = Get-SignerOrg (Get-SignerSubject $dll)
                    if ($org -and $org -eq $signerOrg -and -not (Test-IsMicrosoftName $org)) { $isOurs = $true; $evidence = "its DLL $dll is signed by $org, the app's signer" }
                    elseif ($msiFileNames -contains ([System.IO.Path]::GetFileName($dll)).ToLowerInvariant()) { $isOurs = $true; $evidence = "the app's MSI installs $([System.IO.Path]::GetFileName($dll))" }
                }
            }
            if ($isOurs) {
                $ourCredProviders++
                Add-PlanItem -Category $kind.Cat -Level 3 -Target (Format-RegPath 'HKLM64' "$root\$clsid") -Action $kind.Act -Evidence "our $($kind.Label): $evidence" -Risk 'critical'
            }
        }
        Close-Key $ck
    }
    $pwDisabled = $false; $pwExcluded = $false
    $pk = Open-Key 'HKLM64' "SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\Credential Providers\$passwordProvider"
    if ((Get-ValueSafe $pk 'Disabled') -eq 1) { $pwDisabled = $true }
    Close-Key $pk
    $pol = Open-Key 'HKLM64' 'SOFTWARE\Policies\Microsoft\Windows\System'
    $excluded = [string](Get-ValueSafe $pol 'ExcludedCredentialProviders'); Close-Key $pol
    if ($excluded -and $excluded.IndexOf($passwordProvider.Trim('{', '}'), [StringComparison]::OrdinalIgnoreCase) -ge 0) { $pwExcluded = $true }
    if ($pwDisabled -or $pwExcluded) {
        $how = @(); if ($pwDisabled) { $how += 'Disabled=1 on its provider key' }; if ($pwExcluded) { $how += 'listed in the ExcludedCredentialProviders policy (if a GPO sets it, fix it in the GPO or it comes back)' }
        if ($ourCredProviders -gt 0) {
            Add-PlanItem -Category 'PasswordProviderRestore' -Level 3 -Target "built-in password provider $passwordProvider" -Action 'turn it back on after our providers are removed' `
                -Evidence ("the built-in password sign-in is OFF: " + ($how -join '; ') + ". Remove our provider without this and nobody can sign in with a password.") -Risk 'critical'
        } else {
            $script:Warnings.Add("The built-in password credential provider is off ($($how -join '; ')), but nothing ties that to this app. Left alone.")
        }
    }

    # ---------------------------------------------------------------- Discovery: Winlogon, LSA, network providers, print monitors, AppInit, IFEO
    $wl = Open-Key 'HKLM64' 'SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon'
    foreach ($v in @('Shell', 'Userinit')) {
        $data = [string](Get-ValueSafe $wl $v)
        if ($data -and (Test-OurReference $data)) {
            $def = if ($v -eq 'Shell') { 'explorer.exe' } else { "$env:SystemRoot\system32\userinit.exe," }
            Add-PlanItem -Category 'Winlogon' -Level 3 -Target "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon : $v" -Action "restore the default '$def'" -Evidence "$v = $data (points into the app's folder)" -Risk 'critical'
        }
    }
    Close-Key $wl
    foreach ($sid in $loadedSids) {
        $uwl = Open-Key 'HKU' "$sid\Software\Microsoft\Windows NT\CurrentVersion\Winlogon"
        $data = [string](Get-ValueSafe $uwl 'Shell'); Close-Key $uwl
        if ($data -and (Test-OurReference $data)) {
            Add-PlanItem -Category 'Winlogon' -Level 3 -Scope "user:$sid" -Target "HKU\$sid\Software\Microsoft\Windows NT\CurrentVersion\Winlogon : Shell" -Action "delete the per-user Shell value (falls back to the machine shell)" -Evidence "per-user Shell = $data" -Risk 'critical'
        }
    }

    # System32 DLLs registered by NAME (LSA packages, print monitors) are tied to the app by what its MSI
    # installs or by its signer. A signer match is weaker when the vendor has another product installed.
    $system32 = Join-Path $env:SystemRoot 'System32'
    $dllIsOurs = {
        param([string] $DllName)
        $file = if ([System.IO.Path]::IsPathRooted($DllName)) { $DllName } else { Join-Path $system32 ($(if ($DllName -match '\.dll$') { $DllName } else { "$DllName.dll" })) }
        $leaf = [System.IO.Path]::GetFileName($file).ToLowerInvariant()
        if ($msiFileNames -contains $leaf) { return "the app's MSI installs $leaf" }
        if (-not (Test-Path -LiteralPath $file -PathType Leaf)) { return $null }
        if (Test-OurReference $file) { return "$file is under the app's folder" }
        $org = Get-SignerOrg (Get-SignerSubject $file)
        if ($org -and $signerOrg -and $org -eq $signerOrg -and -not (Test-IsMicrosoftName $org)) {
            if ($samePublisherOthers.Count) { return "SIGNER-ONLY: $file is signed by $org, but $org also has $($samePublisherOthers -join ', ') installed" }
            return "$file is signed by $org, the app's signer"
        }
        return $null
    }
    $lsa = Open-Key 'HKLM64' 'SYSTEM\CurrentControlSet\Control\Lsa'
    foreach ($v in @('Authentication Packages', 'Notification Packages', 'Security Packages')) {
        foreach ($pkg in @(Get-ValueSafe $lsa $v)) {
            if (-not $pkg -or $pkg -eq '""') { continue }
            $why = & $dllIsOurs ([string]$pkg)
            if ($why) {
                Add-PlanItem -Category 'LsaPackage' -Level 3 -Target "HKLM\SYSTEM\CurrentControlSet\Control\Lsa : $v" -Action "remove '$pkg' from the list (keep every other entry), before its DLL" `
                    -Evidence $why -Risk 'critical' -OptIn:($why -like 'SIGNER-ONLY*') -Note $(if ($why -like 'SIGNER-ONLY*') { 'needs review: tied by signer only' } else { $null })
            }
        }
    }
    Close-Key $lsa
    $npo = Open-Key 'HKLM64' 'SYSTEM\CurrentControlSet\Control\NetworkProvider\Order'
    $order = [string](Get-ValueSafe $npo 'ProviderOrder'); Close-Key $npo
    foreach ($prov in ($order -split ',' | ForEach-Object { $_.Trim() } | Where-Object { $_ })) {
        $why = $null
        if ($ourServiceNames -contains $prov) { $why = "provider '$prov' is our service" }
        else {
            $np = Open-Key 'HKLM64' "SYSTEM\CurrentControlSet\Services\$prov\NetworkProvider"
            $pp = [string](Get-ValueSafe $np 'ProviderPath'); Close-Key $np
            if ($pp) { $why = & $dllIsOurs (Get-NormalizedPath $pp) }
        }
        if ($why) {
            Add-PlanItem -Category 'NetworkProvider' -Level 3 -Target "HKLM\SYSTEM\CurrentControlSet\Control\NetworkProvider\Order : ProviderOrder" `
                -Action "remove '$prov' from ProviderOrder (and HwOrder), keep the rest in order" -Evidence $why -Risk 'critical'
        }
    }
    $mon = Open-Key 'HKLM64' 'SYSTEM\CurrentControlSet\Control\Print\Monitors'
    foreach ($m in (Get-SubKeyNamesSafe $mon)) {
        $mk = $null; try { $mk = $mon.OpenSubKey($m, $false) } catch { continue }
        $drv = [string](Get-ValueSafe $mk 'Driver'); Close-Key $mk
        if ($drv) {
            $why = & $dllIsOurs $drv
            if ($why) { Add-PlanItem -Category 'PrintMonitor' -Level 3 -Target "HKLM\SYSTEM\CurrentControlSet\Control\Print\Monitors\$m" -Action 'delete key (spooler restart)' -Evidence $why -Risk 'high' }
        }
    }
    Close-Key $mon
    foreach ($h in @('HKLM64', 'HKLM32')) {
        $wk = Open-Key $h 'SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows'
        $appInit = [string](Get-ValueSafe $wk 'AppInit_DLLs'); Close-Key $wk
        foreach ($dll in ($appInit -split '[,\s]+' | Where-Object { $_ })) {
            if (Test-OurReference $dll) {
                Add-PlanItem -Category 'AppInitDll' -Level 3 -Target "$(Format-RegPath $h 'SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows') : AppInit_DLLs" -Action "remove '$dll' from the list" -Evidence "$dll loads into every GUI process" -Risk 'high'
            }
        }
        $ifeo = Open-Key $h 'SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options'
        foreach ($exe in (Get-SubKeyNamesSafe $ifeo)) {
            $ek = $null; try { $ek = $ifeo.OpenSubKey($exe, $false) } catch { continue }
            $dbg = [string](Get-ValueSafe $ek 'Debugger'); Close-Key $ek
            if ($dbg -and (Test-OurReference $dbg)) {
                Add-PlanItem -Category 'IfeoDebugger' -Level 3 -Target "$(Format-RegPath $h "SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\$exe") : Debugger" -Action "delete value 'Debugger'" -Evidence "launching $exe runs $dbg instead" -Risk 'high'
            }
        }
        Close-Key $ifeo
    }

    # ---------------------------------------------------------------- Discovery: firewall rules
    $fw = Open-Key 'HKLM64' 'SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules' 'firewall rules'
    foreach ($ruleId in (Get-ValueNamesSafe $fw 'firewall rules')) {
        $data = [string](Get-ValueSafe $fw $ruleId)
        $app = if ($data -match '\|App=([^|]+)') { $matches[1] } else { $null }
        $svc = if ($data -match '\|Svc=([^|]+)') { $matches[1] } else { $null }
        $ruleName = if ($data -match '\|Name=([^|]+)') { $matches[1] } else { $ruleId }
        if (($app -and (Test-OurReference $app)) -or ($svc -and ($ourServiceNames -contains $svc))) {
            Add-PlanItem -Category 'FirewallRule' -Level 3 -Target "firewall rule '$ruleName' ($ruleId)" -Action 'delete rule' -Evidence $(if ($app) { "allows $app" } else { "applies to our service $svc" })
        }
    }
    Close-Key $fw

    # ---------------------------------------------------------------- Discovery: shortcuts
    $shell = $null; try { $shell = New-Object -ComObject WScript.Shell } catch { }
    if ($shell) {
        $lnkDirs = @(@{ Dir = (Join-Path $env:ProgramData 'Microsoft\Windows\Start Menu\Programs'); Scope = 'machine' }, @{ Dir = (Join-Path $env:PUBLIC 'Desktop'); Scope = 'machine' })
        foreach ($pr in $profiles | Where-Object { $_.Loaded }) {
            $lnkDirs += @{ Dir = (Join-Path $pr.Path 'AppData\Roaming\Microsoft\Windows\Start Menu\Programs'); Scope = "user:$($pr.Sid)" }
            $lnkDirs += @{ Dir = (Join-Path $pr.Path 'Desktop'); Scope = "user:$($pr.Sid)" }
        }
        foreach ($ld in $lnkDirs) {
            if (-not (Test-Path -LiteralPath $ld.Dir)) { continue }
            foreach ($lnk in @(Get-ChildItem -LiteralPath $ld.Dir -Filter *.lnk -Recurse -File -ErrorAction SilentlyContinue)) {
                try {
                    $sc = $shell.CreateShortcut($lnk.FullName)
                    $tgt = [string]$sc.TargetPath; $lnkArgs = [string]$sc.Arguments
                    $advertisedOurs = ($pc -and $tgt -and $tgt.IndexOf($pc, [StringComparison]::OrdinalIgnoreCase) -ge 0)
                    if ($advertisedOurs -or ($tgt -and (Test-OurReference $tgt)) -or ($lnkArgs -and (Test-OurReference $lnkArgs))) {
                        Add-PlanItem -Category 'Shortcut' -Level 3 -Scope $ld.Scope -Target $lnk.FullName -Action 'move to quarantine' -Evidence $(if ($advertisedOurs) { "advertised shortcut for $pc" } else { "target $tgt $lnkArgs".Trim() })
                    }
                } catch { Add-Unreadable 'shortcuts' }
            }
        }
    }

    & $say '  checking the keyword, folders and per-user state...'
    # ---------------------------------------------------------------- Keyword: pick, then prove it is distinctive
    $keywordInfo = [ordered]@{ value = $null; source = $null; used = $false; outsideHits = 0; otherProducts = @(); examples = @(); reason = $null }
    $keywordInfo.source = if ($Keyword) { 'given' } else { 'derived from the name and publisher' }
    $classNames = @(Get-SubKeyNamesSafe (Open-Key 'HKLM64' 'SOFTWARE\Classes'))
    $msKeyNames = @()
    foreach ($h in @('HKLM64')) {
        $msk = Open-Key $h 'SOFTWARE\Microsoft'
        foreach ($n in (Get-SubKeyNamesSafe $msk)) { $msKeyNames += "SOFTWARE\Microsoft\$n"; $sk = $null; try { $sk = $msk.OpenSubKey($n, $false) } catch { }; foreach ($n2 in (Get-SubKeyNamesSafe $sk)) { $msKeyNames += "SOFTWARE\Microsoft\$n\$n2" }; Close-Key $sk }
        Close-Key $msk
    }
    foreach ($sid in ($loadedSids | Where-Object { $_ -match '^S-1-(5-21|12-1)-' })) {
        $msk = Open-Key 'HKU' "$sid\Software\Microsoft"
        foreach ($n in (Get-SubKeyNamesSafe $msk)) { $msKeyNames += "HKU\$sid\Software\Microsoft\$n"; $sk = $null; try { $sk = $msk.OpenSubKey($n, $false) } catch { }; foreach ($n2 in (Get-SubKeyNamesSafe $sk)) { $msKeyNames += "HKU\$sid\Software\Microsoft\$n\$n2" }; Close-Key $sk }
        Close-Key $msk
    }
    $maxOutside = 3
    $scoreWord = {
        param([string] $Word)
        $others = @($otherEntries | Where-Object { (Test-WholeWord $_.DisplayName $Word) -or (Test-WholeWord $_.Publisher $Word) } | ForEach-Object { $_.DisplayName } | Select-Object -Unique)
        $hits = @()
        # Our own ProgIDs and file associations are not "outside": 7-Zip's 7-Zip.zip must not count against "7-Zip".
        $hits += @($classNames | Where-Object { (Test-WholeWord $_ $Word) -and -not $ourClassKeys.Contains($_) } | ForEach-Object { "HKLM\SOFTWARE\Classes\$_" })
        $hits += @($msKeyNames | Where-Object { Test-WholeWord ($_.Split('\')[-1]) $Word } | ForEach-Object { if ($_ -like 'HKU\*') { $_ } else { "HKLM\$_" } })
        $hits += @($services | Where-Object { ($ourServiceNames -notcontains $_.Name) -and ((Test-WholeWord $_.Name $Word) -or (Test-WholeWord $_.DisplayName $Word)) } | ForEach-Object { "service $($_.Name)" })
        $hits += @($taskList | Where-Object { Test-WholeWord "$($_.TaskPath)$($_.TaskName)" $Word } | Where-Object {
                $mine = $false; foreach ($a in @($_.Actions)) { if (($a.PSObject.Properties.Name -contains 'Execute') -and (Test-OurReference ([string]$a.Execute))) { $mine = $true } }; -not $mine } |
            ForEach-Object { "task $($_.TaskPath)$($_.TaskName)" })
        return [pscustomobject]@{ Word = $Word; Others = $others; Hits = $hits; Ok = ($others.Count -eq 0 -and $hits.Count -le $maxOutside) }
    }
    # The app's NAME first; the publisher only when no word of the name holds up (7-Zip once picked
    # "Igor", the publisher's first name, because its own ProgIDs were counted against "7-Zip").
    $best = $null
    $nameWords = if ($Keyword) { @($Keyword.Trim()) } else { @(Get-KeywordCandidates $targetName '') }
    $pubWords = if ($Keyword) { @() } else { @(Get-KeywordCandidates '' $publisher | Where-Object { $nameWords -notcontains $_ }) }
    foreach ($pool in @(, $nameWords) + @(, $pubWords)) {
        foreach ($cand in $pool) {
            if (-not $cand -or $cand.Length -lt 4) { continue }
            $score = & $scoreWord $cand
            if ($null -eq $best -or ($score.Ok -and -not $best.Ok) -or ($score.Ok -eq $best.Ok -and (($score.Others.Count -lt $best.Others.Count) -or ($score.Others.Count -eq $best.Others.Count -and $score.Hits.Count -lt $best.Hits.Count)))) { $best = $score }
        }
        if ($best -and $best.Ok) { break }
    }
    if ($null -eq $best) {
        $keywordInfo.reason = 'no distinctive word in the name or publisher (4+ letters, not generic)'
    } else {
        $keywordInfo.value = $best.Word; $keywordInfo.outsideHits = $best.Hits.Count; $keywordInfo.otherProducts = @($best.Others)
        $keywordInfo.examples = @($best.Hits | Select-Object -First 5)
        if ($best.Others.Count -gt 0) {
            $keywordInfo.reason = "REFUSED: '$($best.Word)' also names other installed products ($(@($best.Others | Select-Object -First 5) -join ', ')); a vendor name alone is too wide"
        } elseif ($best.Hits.Count -gt $maxOutside) {
            $keywordInfo.reason = "REFUSED: '$($best.Word)' matches $($best.Hits.Count) things outside the app (e.g. $(@($best.Hits | Select-Object -First 3) -join '; '))"
        } else {
            $keywordInfo.used = $true
            $keywordInfo.reason = "whole-word, $($best.Hits.Count) hit(s) outside the app"
        }
    }
    $kw = if ($keywordInfo.used) { $keywordInfo.value } else { $null }

    # ---------------------------------------------------------------- Level 2: registration
    foreach ($m in $matched | Where-Object { $_.KeyPath }) {
        Add-PlanItem -Category 'UninstallEntry' -Level 2 -Scope $(if ($m.Sid) { "user:$($m.Sid)" } else { 'machine' }) -Target $m.Display -Action 'delete key' `
            -Evidence "the uninstall entry for '$($m.DisplayName)' $($m.DisplayVersion)"
    }
    foreach ($r in $msiRegistration) {
        if ($r.What -like 'upgrade code*') {
            Add-PlanItem -Category 'MsiUpgradeCode' -Level 2 -Target "$(Format-RegPath $r.Hive $r.Path) : $packedPc" -Action "delete value '$packedPc' (the key goes only when no other product is left under it)" -Evidence "$($r.What); UpgradeCode $upgradeCodeFound"
        } elseif ($r.What -eq 'patch reference') {
            Add-PlanItem -Category 'MsiPatch' -Level 2 -Target (Format-RegPath $r.Hive $r.Path) -Action 'delete key (the patch itself only if no other product references it)' -Evidence 'patch applied to this product'
        } else {
            $scope = if ($r.Hive -eq 'HKU') { "user:$($r.Path.Split('\')[0])" } else { 'machine' }
            Add-PlanItem -Category 'MsiProduct' -Level 2 -Scope $scope -Target (Format-RegPath $r.Hive $r.Path) -Action 'delete key' -Evidence "Windows Installer $($r.What) for $pc"
        }
    }
    if ($ourComponents.Count) {
        $shared = @()
        foreach ($c in $ourComponents) { if (@(Get-OtherComponentClients $componentIndex $c.Component $packedPc).Count) { $shared += $c } }
        Add-PlanItem -Category 'MsiComponentClient' -Level 2 -Target "$($ourComponents.Count) component registration(s) under Installer\UserData\*\Components" `
            -Action "delete OUR client value from each; delete a component key only when no other client is left ($($shared.Count) are shared and keep their key)" `
            -Evidence "components registered to $pc"
    }
    $folders = Open-Key 'HKLM64' 'SOFTWARE\Microsoft\Windows\CurrentVersion\Installer\Folders'
    foreach ($f in (Get-ValueNamesSafe $folders)) {
        # Exclusive folders only: in a shared folder these entries belong to the other products too.
        foreach ($r in $exclusiveRoots) {
            if (Test-PathUnder $f $r) {
                Add-PlanItem -Category 'MsiFolderEntry' -Level 2 -Target "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Installer\Folders : $f" -Action 'delete value' -Evidence "Installer folder reference inside the app's folder $r"
                break
            }
        }
    }
    Close-Key $folders
    if ($localPackage -and $localPackageExists) {
        Add-PlanItem -Category 'MsiCachedPackage' -Level 2 -Target $localPackage -Action 'move to quarantine (exact path from this product''s own registration)' -Evidence "cached MSI (LocalPackage) of $pc"
    }

    # ---------------------------------------------------------------- Level 3: folders and files
    foreach ($r in $roots) {
        if (-not $r.Exists) { continue }
        # A per-user install's own folder (DBeaver in %LOCALAPPDATA%\DBeaver) is the app itself, not
        # user data, so it is an install root with a user scope; keyword-found AppData stays opt-in.
        $owner = @($profiles | Where-Object { Test-PathUnder $r.Path $_.Path } | Select-Object -First 1)
        $scope = if ($owner.Count) { "user:$($owner[0].Sid)" } else { 'machine' }
        if ($r.Shared) {
            # Only this app's own MSI files go; the folder and everything else in it stay.
            $own = @($script:OurFiles | Where-Object { (Test-PathUnder $_ $r.Path) -and (Test-Path -LiteralPath $_ -PathType Leaf) })
            foreach ($f in $own) {
                Add-PlanItem -Category 'IdentityFile' -Level 3 -Scope $scope -Target $f -Action 'move to quarantine (the folder is shared and stays)' `
                    -Evidence "this app's own MSI component file, in the shared folder $($r.Path)" -Risk 'high'
            }
            continue
        }
        $tag = Get-UserDataTag $r.Path
        Add-PlanItem -Category 'InstallRoot' -Level 3 -Scope $scope -Target $r.Path -Action 'move to quarantine' `
            -Evidence "app folder ($($r.Why)); $([Math]::Round($tag.SizeBytes / 1MB, 1)) MB, $($tag.Files) file(s)" `
            -Risk $(if ($tag.DocLike -gt 0) { 'high' } else { 'low' }) -Note $(if ($tag.HighRisk) { "this folder may contain user data ($($tag.Reason))" } else { $null }) -Bytes $tag.SizeBytes
    }
    foreach ($f in $identityFiles) {
        Add-PlanItem -Category 'IdentityFile' -Level 3 -Target $f.Path -Action 'move to quarantine, AFTER everything that loads it is unhooked' -Evidence "key file of our MSI component $($f.Component)" -Risk 'high'
    }
    if ($pc) {
        $iconDir = Join-Path $env:SystemRoot "Installer\$pc"
        if (Test-Path -LiteralPath $iconDir -PathType Container) {
            Add-PlanItem -Category 'InstallerIconFolder' -Level 3 -Target $iconDir -Action 'move to quarantine' -Evidence "Windows Installer icon cache for $pc (named by the ProductCode)"
        }
    }
    # Registry keys the MSI itself wrote (its Registry table and registry-keyed components): exact identity.
    $regCandidates = @()
    foreach ($rk in $msiRegKeys) {
        $parts = $rk.Split('|', 2); $rootCode = $parts[0]; $key = $parts[1]
        if ($key -match '^(?i)software\\([^\\]+)(\\([^\\]+))?') {
            $depth = if ($matches[3]) { "Software\$($matches[1])\$($matches[3])" } else { "Software\$($matches[1])" }
            $regCandidates += [pscustomobject]@{ Root = $rootCode; Key = $depth; Why = "written by the app's MSI (Registry table: $key)" }
        }
    }
    foreach ($kp in $componentRegKeys) {
        if ($kp.Path -match '^(?i)software\\([^\\]+)(\\([^\\]+))?') {
            $depth = if ($matches[3]) { "Software\$($matches[1])\$($matches[3])" } else { "Software\$($matches[1])" }
            $root = if ($kp.Hive -eq 'HKLM') { '2' } elseif ($kp.Hive -eq 'HKCU') { '1' } else { $null }
            if ($root) { $regCandidates += [pscustomobject]@{ Root = $root; Key = $depth; Why = "key path of one of our MSI components ($($kp.Path))" } }
        }
    }
    foreach ($rc in $regCandidates) {
        if ($rc.Key -match '^(?i)software\\(microsoft|classes|policies|wow6432node|wow6432node\\.*)(\\|$)') { continue }
        $vendorOnly = ($rc.Key.Split('\').Count -eq 2)
        if ($vendorOnly -and $samePublisherOthers.Count) { continue }
        if ($rc.Root -in @('2', '-1')) {
            foreach ($h in @('HKLM64', 'HKLM32')) {
                $k = Open-Key $h ($rc.Key -replace '^(?i)software', 'SOFTWARE')
                if ($k) { Close-Key $k; Add-PlanItem -Category 'VendorRegistryKey' -Level 3 -Target (Format-RegPath $h ($rc.Key -replace '^(?i)software', 'SOFTWARE')) -Action 'delete key' -Evidence $rc.Why }
            }
        }
        if ($rc.Root -in @('1', '-1')) {
            foreach ($sid in ($loadedSids | Where-Object { $_ -match '^S-1-(5-21|12-1)-' })) {
                $k = Open-Key 'HKU' "$sid\$($rc.Key)"
                if ($k) { Close-Key $k; Add-PlanItem -Category 'UserRegistryKey' -Level 3 -Scope "user:$sid" -Target "HKU\$sid\$($rc.Key)" -Action 'delete key' -Evidence $rc.Why }
            }
        }
    }
    # Keyword-based folders and keys: only with an accepted keyword, and never inside a kept path.
    $offline = @()
    if ($kw) {
        $pfDirs = @(@{ Dir = $env:ProgramData; Cat = 'ProgramDataFolder' }, @{ Dir = $env:ProgramFiles; Cat = 'ProgramFilesFolder' }, @{ Dir = ${env:ProgramFiles(x86)}; Cat = 'ProgramFilesFolder' },
            @{ Dir = $env:CommonProgramFiles; Cat = 'ProgramFilesFolder' }, @{ Dir = ${env:CommonProgramFiles(x86)}; Cat = 'ProgramFilesFolder' })
        foreach ($pd in $pfDirs) {
            if (-not $pd.Dir -or -not (Test-Path -LiteralPath $pd.Dir)) { continue }
            foreach ($d in @(Get-ChildItem -LiteralPath $pd.Dir -Directory -Force -ErrorAction SilentlyContinue | Where-Object { Test-WholeWord $_.Name $kw })) {
                $full = $d.FullName
                if (@($rootPaths | Where-Object { Test-PathUnder $full $_ }).Count) { continue }
                if (Get-ProtectedPathReason $full $containerProtected $treeProtected) { continue }
                if (@($script:Kept | Where-Object { Test-PathUnder $_.path $full }).Count) { Add-Kept $full 'contains a path another product uses'; continue }
                if (@($otherEntries | Where-Object { @(Get-EntryPaths $_ | Where-Object { Test-PathUnder $_ $full }).Count }).Count) { Add-Kept $full 'another installed product lives inside it'; continue }
                $tag = Get-UserDataTag $full
                Add-PlanItem -Category $pd.Cat -Level 3 -Target $full -Action 'move to quarantine' -Evidence "folder named for '$kw' (keyword); $([Math]::Round($tag.SizeBytes / 1MB, 1)) MB" `
                    -Risk $(if ($tag.HighRisk) { 'high' } else { 'low' }) -Note $(if ($tag.HighRisk) { "this folder may contain user data ($($tag.Reason))" } else { $null }) -Bytes $tag.SizeBytes
            }
        }
        # Named for the app but inside a protected Windows folder (Npcap's System32\Npcap): reported,
        # never planned. Removing things from System32 is a decision for a person, not a keyword.
        foreach ($winDir in @((Join-Path $env:SystemRoot 'System32'), (Join-Path $env:SystemRoot 'SysWOW64'))) {
            if (-not (Test-Path -LiteralPath $winDir)) { continue }
            foreach ($d in @(Get-ChildItem -LiteralPath $winDir -Directory -Force -ErrorAction SilentlyContinue | Where-Object { Test-WholeWord $_.Name $kw })) {
                $script:Warnings.Add("Left alone: $($d.FullName) is named for '$kw' but sits in a protected Windows folder. Check it and remove it by hand if it is this app's.")
            }
        }
        foreach ($h in @('HKLM64', 'HKLM32')) {
            $sw = Open-Key $h 'SOFTWARE'
            foreach ($n in (Get-SubKeyNamesSafe $sw)) {
                if ($n -match '^(?i)(Microsoft|Classes|Policies|WOW6432Node|Wow6432Node|Clients|RegisteredApplications)$') { continue }
                if (Test-WholeWord $n $kw) {
                    if ($samePublisherOthers.Count -and -not (Test-WholeWord $targetName $n)) { continue }
                    Add-PlanItem -Category 'VendorRegistryKey' -Level 3 -Target (Format-RegPath $h "SOFTWARE\$n") -Action 'delete key' -Evidence "key named for '$kw' (keyword)" -Risk 'high'
                }
            }
            Close-Key $sw
        }
        foreach ($pr in $profiles) {
            $found = @()
            foreach ($sub in @('AppData\Local', 'AppData\LocalLow', 'AppData\Roaming', 'AppData\Local\Programs')) {
                $base = Join-Path $pr.Path $sub
                if (-not (Test-Path -LiteralPath $base)) { continue }
                foreach ($d in @(Get-ChildItem -LiteralPath $base -Directory -Force -ErrorAction SilentlyContinue | Where-Object { Test-WholeWord $_.Name $kw })) { $found += $d.FullName }
            }
            if ($pr.Loaded) {
                foreach ($f in $found) {
                    if (@($rootPaths | Where-Object { Test-PathUnder $f $_ }).Count) { continue }
                    $tag = Get-UserDataTag $f
                    Add-PlanItem -Category 'AppDataFolder' -Level 3 -Scope "user:$($pr.Sid)" -Target $f -Action 'move to quarantine (AppData is its own opt-in)' -OptIn `
                        -Evidence "per-user folder named for '$kw' (keyword); $([Math]::Round($tag.SizeBytes / 1MB, 1)) MB" -Risk $(if ($tag.HighRisk) { 'high' } else { 'low' }) `
                        -Note $(if ($tag.HighRisk) { "this folder may contain user data ($($tag.Reason))" } else { $null }) -Bytes $tag.SizeBytes
                }
                $usw = Open-Key 'HKU' "$($pr.Sid)\Software"
                foreach ($n in (Get-SubKeyNamesSafe $usw)) {
                    if ($n -match '^(?i)(Microsoft|Classes|Policies|Wow6432Node)$') { continue }
                    if (Test-WholeWord $n $kw) {
                        if ($samePublisherOthers.Count -and -not (Test-WholeWord $targetName $n)) { continue }
                        Add-PlanItem -Category 'UserRegistryKey' -Level 3 -Scope "user:$($pr.Sid)" -Target "HKU\$($pr.Sid)\Software\$n" -Action 'delete key' -Evidence "key named for '$kw' (keyword)" -Risk 'high'
                    }
                }
                Close-Key $usw
            } else {
                $offline += [pscustomobject][ordered]@{ user = $pr.User; sid = $pr.Sid; profile = $pr.Path; roaming = $pr.Roaming; appDataFound = @($found) }
            }
        }
    } else {
        foreach ($pr in $profiles | Where-Object { -not $_.Loaded }) {
            $offline += [pscustomobject][ordered]@{ user = $pr.User; sid = $pr.Sid; profile = $pr.Path; roaming = $pr.Roaming; appDataFound = @() }
        }
    }
    $fslogix = $false
    $fk = Open-Key 'HKLM64' 'SOFTWARE\FSLogix\Profiles'
    if ((Get-ValueSafe $fk 'Enabled') -eq 1) { $fslogix = $true }
    Close-Key $fk

    # ---------------------------------------------------------------- Pre-flight: sizes per volume (quarantine is same-volume)
    $perVolume = @{}
    foreach ($i in $script:Items | Where-Object { $_.category -in @('InstallRoot', 'ProgramDataFolder', 'ProgramFilesFolder', 'AppDataFolder', 'IdentityFile', 'InstallerIconFolder', 'MsiCachedPackage', 'Shortcut') }) {
        $vol = ([string]$i.target).Substring(0, [Math]::Min(2, ([string]$i.target).Length)).ToUpperInvariant()
        $bytes = [long]0
        if ($null -ne $i.bytes) { $bytes = [long]$i.bytes }
        else {
            try {
                if (Test-Path -LiteralPath $i.target -PathType Leaf) { $bytes = (Get-Item -LiteralPath $i.target -Force).Length }
                elseif (Test-Path -LiteralPath $i.target -PathType Container) { $bytes = (Get-UserDataTag $i.target).SizeBytes }
            } catch { }
        }
        if ($perVolume.ContainsKey($vol)) { $perVolume[$vol] += $bytes } else { $perVolume[$vol] = $bytes }
    }
    $preflight = @()
    foreach ($vol in $perVolume.Keys) {
        $free = $null
        try { $free = (New-Object System.IO.DriveInfo ($vol + '\')).AvailableFreeSpace } catch { }
        $preflight += [pscustomobject][ordered]@{ volume = $vol; bytesToQuarantine = $perVolume[$vol]; freeBytes = $free; quarantine = $(if ($vol -eq $env:SystemDrive.ToUpperInvariant()) { Join-Path $env:ProgramData "Leftovers\$runId" } else { "$vol\.leftovers\$runId" }) }
    }

    # ---------------------------------------------------------------- Warnings
    if ($isMsi -and $localPackage -and -not $localPackageExists) { $script:Warnings.Add("The cached MSI is MISSING ($localPackage): msiexec /x will fail (1612). That is what L2 is for.") }
    if (-not $roots.Count) { $script:Warnings.Add('No usable install folder was found; nothing is matched by path, only by registration.') }
    foreach ($rr in $refusedRoots) { $script:Warnings.Add("Folder $($rr.Path) is NOT used ($($rr.Why)); it came from $($rr.From).") }
    if ($offline.Count) { $script:Warnings.Add("$($offline.Count) signed-out profile(s) are NOT cleaned in v1 (their registry hives are never loaded). Re-run while they are signed in.") }
    if ($fslogix) { $script:Warnings.Add('FSLogix profiles are enabled: signed-out users'' per-user state lives in their profile containers.') }
    if ($samePublisherOthers.Count) { $script:Warnings.Add("$publisher has other products installed ($(@($samePublisherOthers | Select-Object -First 5) -join ', ')): vendor-level folders and keys are left alone.") }
    foreach ($a in $script:Unreadable.Keys) { $script:Warnings.Add("$($script:Unreadable[$a]) unreadable $a entr$(if ($script:Unreadable[$a] -eq 1) { 'y' } else { 'ies' }); the report may miss items there.") }
    $script:Warnings.Add('SharedDLLs reference counts are not changed (a wrong decrement breaks a third product). Any counts for this app''s files are a known, harmless leak.')

    # ---------------------------------------------------------------- Write the plan
    $plan = [ordered]@{
        tool = 'Leftovers'; version = $script:ToolVersion; runId = $runId; computer = $env:COMPUTERNAME
        generatedUtc = (Get-Date).ToUniversalTime().ToString('o'); level = 0; refused = $null
        target = $target
        identity = [ordered]@{
            roots = @($roots | ForEach-Object { [ordered]@{ path = $_.Path; exists = $_.Exists; from = $_.Why } })
            refusedRoots = @($refusedRoots | ForEach-Object { [ordered]@{ path = $_.Path; reason = $_.Why; from = $_.From } })
            signer = $signerOrg; signerEvidence = @($signerFiles)
            msiComponents = $ourComponents.Count; msiFilesInPackage = $msiFileCount; msiServices = @($msiServiceNames)
            services = @($ourServiceNames); comClasses = $ourClsids.Count
        }
        keyword = $keywordInfo
        items = @($script:Items | Sort-Object level, order, id)
        kept = $script:Kept.ToArray()
        offlineProfiles = @($offline)
        preflight = @($preflight)
        warnings = $script:Warnings.ToArray()
    }
    $files = Write-PlanFiles $plan $outDirFinal
    if (-not $Quiet) { Write-Host ''; Write-Host (Get-Content -LiteralPath $files.Report -Raw) }
    return 0
}

function Format-Report {
    param($Plan)
    $sb = New-Object System.Text.StringBuilder
    $line = { param($t) [void]$sb.AppendLine($t) }
    $t = $Plan.target
    & $line "Leftovers $($Plan.version) - L0 report (dry run: NOTHING was changed)"
    & $line "Computer: $($Plan.computer)    Run: $($Plan.runId)"
    & $line ''
    & $line "Target:    $($t.displayName) $($t.version)"
    & $line "Publisher: $($t.publisher)"
    if ($t.productCode) { & $line "MSI:       ProductCode $($t.productCode)   UpgradeCode $(if ($t.upgradeCode) { $t.upgradeCode } else { '(none found)' })" }
    if ($t.cachedMsi) { & $line "Cached MSI: $($t.cachedMsi) $(if ($t.cachedMsiPresent) { '(present)' } else { '(MISSING)' })" }
    if ($Plan.refused) { & $line ''; & $line "REFUSED: $($Plan.refused)"; return $sb.ToString() }
    foreach ($r in $Plan.identity.roots) { & $line "Folder:    $($r.path)$(if (-not $r.exists) { ' (gone)' })   [from $($r.from)]" }
    if ($Plan.identity.signer) { & $line "Signer:    $($Plan.identity.signer)" }
    $k = $Plan.keyword
    & $line "Keyword:   $(if ($k.value) { "'$($k.value)' " })$(if ($k.used) { '(used) ' } else { '(NOT used) ' })- $($k.reason)"
    $groups = @(
        @{ Title = 'L2  Registration (a reinstall works after this; files untouched)'; Filter = { $_.level -eq 2 } },
        @{ Title = 'L3  Unhook from Windows first (in this order)'; Filter = { $_.level -eq 3 -and $_.order -lt 500 } },
        @{ Title = 'L3  Files and registry'; Filter = { $_.level -eq 3 -and $_.order -ge 500 -and -not $_.optIn } },
        @{ Title = 'L3  Opt-in (AppData, needs-review)'; Filter = { $_.level -eq 3 -and $_.optIn } }
    )
    foreach ($g in $groups) {
        $items = @($Plan.items | Where-Object $g.Filter)
        & $line ''
        & $line "$($g.Title): $($items.Count) item(s)"
        # Many items with identical evidence (Java registers ~8,600 COM classes on one DLL) print as
        # two examples and a count; plan.json always lists every item.
        $runs = [ordered]@{}
        foreach ($i in $items) {
            $key = "$($i.category)|$($i.action)|$($i.evidence)|$($i.risk)|$($i.note)"
            if (-not $runs.Contains($key)) { $runs[$key] = New-Object System.Collections.Generic.List[object] }
            $runs[$key].Add($i)
        }
        foreach ($run in $runs.Values) {
            $shown = if ($run.Count -gt 5) { 2 } else { $run.Count }
            for ($n = 0; $n -lt $shown; $n++) {
                $i = $run[$n]
                & $line ("  [{0,-8}] {1}" -f $i.risk, $i.target)
                if ($n -eq $shown - 1 -or $shown -eq 1) {
                    & $line "             do:  $($i.action)"
                    & $line "             why: $($i.evidence)"
                    if ($i.note) { & $line "             !!:  $($i.note)" }
                }
            }
            if ($run.Count -gt $shown) { & $line "  ... and $($run.Count - $shown) more $($run[0].category) item(s) with the same evidence (all in plan.json)" }
        }
    }
    & $line ''
    & $line "Kept (another product still uses these): $(@($Plan.kept).Count)"
    foreach ($kp in $Plan.kept) { & $line "  $($kp.path)  - $($kp.reason)" }
    if (@($Plan.offlineProfiles).Count) {
        & $line ''
        & $line "Signed-out profiles, NOT cleaned (re-run while signed in): $(@($Plan.offlineProfiles).Count)"
        foreach ($o in $Plan.offlineProfiles) { & $line "  $($o.user)$(if ($o.roaming) { ' (roaming)' })$(if (@($o.appDataFound).Count) { ': ' + (@($o.appDataFound) -join ', ') })" }
    }
    if (@($Plan.warnings).Count) {
        & $line ''
        & $line 'Warnings:'
        foreach ($w in $Plan.warnings) { & $line "  - $w" }
    }
    return $sb.ToString()
}

function Write-PlanFiles {
    param($Plan, [string] $Dir)
    if (-not (Test-Path -LiteralPath $Dir)) { [void](New-Item -ItemType Directory -Path $Dir -Force) }
    $json = Join-Path $Dir 'plan.json'
    $report = Join-Path $Dir 'report.txt'
    ($Plan | ConvertTo-Json -Depth 8) | Set-Content -LiteralPath $json -Encoding UTF8
    (Format-Report $Plan) | Set-Content -LiteralPath $report -Encoding UTF8
    return [pscustomobject]@{ Json = $json; Report = $report }
}

# =====================================================================================================
if ($PSCmdlet.ParameterSetName -ne 'Library') {
    $PSCmdlet_ParameterSetName = $PSCmdlet.ParameterSetName
    try {
        $code = Invoke-Leftovers
    } catch {
        Write-Host "Leftovers stopped on an unexpected error, and wrote NO plan: $($_.Exception.Message) (line $($_.InvocationInfo.ScriptLineNumber))"
        $code = 4
    }
    exit $code
}
