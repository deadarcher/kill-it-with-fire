#Requires -Version 5.1
<#
.SYNOPSIS
    Kill It With Fire - remove a Windows app completely, the proper way or the hard way: a plan with the
    evidence for every item, a backup of everything it changes, and a restore.

.DESCRIPTION
    Two ways to remove an app:
      The proper way (the default): the app's own uninstaller runs first, silently, and then whatever it
      left behind is cleaned up. For an MSI that is msiexec /x. For an EXE it is the app's registered
      quiet uninstall command, or the silent switch of the engine that built its uninstaller (NSIS, Inno
      Setup, WiX Burn, InstallShield, InstallAware), recognised from markers inside the uninstaller.
      -KillIt, the hard way: skip the uninstaller and scrub the app out at level 3. For an uninstaller
      that is broken, hangs, or wants a click nobody is there to give.
    Either way, a scan comes first, every change is backed up, and the protected list (Microsoft
    software, security agents, Windows itself) is never touched.

    Levels are cumulative:
      0  Scan only. Writes plan.json and report.txt. Changes nothing.
      1  Uninstall. Runs the app's own uninstaller once, silently (see above). One with no known silent
         switch is skipped rather than left waiting for a click.
      2  Registration cleanup. Removes the uninstall entry and the Windows Installer registration, so a
         reinstall should work. Files are not touched.
      3  Full scrub. Unhooks the app from Windows (logon hooks first, then device filters, network
         components, driver packages, drivers, services, tasks, startup, COM and shell), then moves
         its files to a quarantine on the same volume.
    Everything a run changes is backed up first and written to a journal. -Restore <runId> puts a
    whole run back; -Resume <runId> finishes a run that needed a reboot.

    Matching is identity-first: the app's own registration, its folders, and the files its MSI owns.
    A keyword only ever NARROWS a match. Folders another product points into are shared: only the
    app's own files are touched there. Weak ties (vendor name only, signer only, System32 files) are
    listed as "needs review" and are left out unless -IncludeReview is given.

    With no arguments it opens a window (Disk Cleanup style) that drives the same engine.

    Administrators can lock options with policy values under HKLM\SOFTWARE\Policies\KillItWithFire:
      MaxLevel (DWORD), RequireBackup (DWORD 1), RequireLog (DWORD 1), LogPath (string),
      AllowUserData (DWORD 0/1), QuarantineDays (DWORD).
    The engine enforces them: a switch past the policy is refused. The window only greys them out.

.PARAMETER Name
    Exact DisplayName of the app, as shown in Installed apps / Programs and Features.
.PARAMETER ProductCode
    The app's MSI ProductCode. Works even when its uninstall entry is already gone.
.PARAMETER UpgradeCode
    The app's MSI UpgradeCode.
.PARAMETER Plan
    Execute a plan.json produced earlier on THIS machine (what the window does after you review it).
.PARAMETER Level
    0 scan only (default), 1 uninstall, 2 registration cleanup, 3 full scrub.
.PARAMETER Include
    Only these categories: Registration, LogonHooks, Drivers, Services, Startup, ComShell, Other,
    Files, Registry, UserData.
.PARAMETER Exclude
    Leave these categories out.
.PARAMETER IncludeUserData
    Also move per-user AppData folders (off by default: some apps keep user files there).
.PARAMETER IncludeReview
    Also act on items tied only by vendor name, signer, or a single MSI claim on a System32 file.
.PARAMETER SkipUninstall
    At level 2 or 3, don't try the app's own uninstaller first.
.PARAMETER KillIt
    The hard way: skip the app's own uninstaller and scrub it out (level 3, with -SkipUninstall). Leave
    -Level out, or give 3. A backup is still taken, so -Restore can put the app back.
.PARAMETER NoBackup
    Don't back up before changing things (refused when policy requires a backup). -Restore can't undo
    such a run.
.PARAMETER Keyword
    A distinctive whole-word name for the app (e.g. "Imprivata"). Refused if it names another
    installed product or matches much outside the app.
.PARAMETER ProfilePath
    Extra per-app profile files (.psd1). Profiles in the profiles folder next to the script load on their own;
    one applies when its Match fits the app.
.PARAMETER List
    List installed apps to pick a target from.
.PARAMETER ListRuns
    List previous runs that can be restored.
.PARAMETER Restore
    Put a whole run back, newest change first.
.PARAMETER Resume
    Finish a run that ended with 3010 (reboot needed), after the reboot.
.PARAMETER Gui
    Open the window (also the default with no arguments).
.PARAMETER Force
    Don't ask for confirmation (unattended runs: RMM, PDQ, Intune).
.PARAMETER OutDir
    Where a scan writes plan.json and report.txt. Default: the run folder.
.PARAMETER Log
    Log file or folder. Default: log.txt in the run folder.
.PARAMETER NoLog
    Don't write a log (refused when policy requires one).
.PARAMETER QuarantineDays
    Days a run's backup is kept before it is purged (default 14).
.PARAMETER Quiet
    Don't print the report. Files and exit code are unchanged.

.EXAMPLE
    .\KillItWithFire.ps1
    Opens the window.
.EXAMPLE
    .\KillItWithFire.ps1 -Name "Notepad++ (64-bit x64)"
    Scan only: writes the plan and prints the report.
.EXAMPLE
    .\KillItWithFire.ps1 -ProductCode "{DDC95F26-92B1-4546-9678-5DC68DF76BA0}" -Level 2 -Force
    Registration cleanup of an MSI whose cached package is gone, unattended.
.EXAMPLE
    .\KillItWithFire.ps1 -ListRuns
    .\KillItWithFire.ps1 -Restore 20260926-013000-1a2b3c

.NOTES
    Exit codes: 0 done, 3010 done but a reboot is needed (then -Resume), 1 stopped part way (the run
    can be restored), 2 refused (policy, protected product, ambiguous name, or no confirmation),
    3 bad input, not found, or not elevated, 4 stopped on an unexpected error.
    Runs on Windows PowerShell 5.1 and PowerShell 7, elevated (admin or SYSTEM), 64-bit.
    https://github.com/deadarcher/kill-it-with-fire - MIT license.
#>
[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingEmptyCatchBlock', '', Justification = 'Best-effort reads: an unreadable key or file is skipped (and counted where it matters), never fatal.')]
[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSReviewUnusedParameter', '', Justification = 'Script parameters are read inside functions through scope inheritance.')]
[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseSingularNouns', '', Justification = 'Internal helpers named for what they return (Get-UninstallEntries returns entries); none is exported.')]
[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingWriteHost', '', Justification = 'Interactive CLI output; the machine-readable result is plan.json / result.json.')]
[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification = 'Confirmation is the run-level YES prompt or -Force, plus the full backup.')]
[CmdletBinding(DefaultParameterSetName = 'Gui')]
param(
    [Parameter(ParameterSetName = 'Run', Position = 0)]
    [string] $Name,

    [Parameter(ParameterSetName = 'Run')]
    [string] $ProductCode,

    [Parameter(ParameterSetName = 'Run')]
    [string] $UpgradeCode,

    [Parameter(ParameterSetName = 'Run')]
    [Parameter(ParameterSetName = 'GuiSelfTest')]
    [string] $Plan,

    [Parameter(ParameterSetName = 'Run')]
    [ValidateRange(0, 3)]
    [int] $Level = 0,

    [Parameter(ParameterSetName = 'Run')]
    [string[]] $Include,

    [Parameter(ParameterSetName = 'Run')]
    [string[]] $Exclude,

    [Parameter(ParameterSetName = 'Run')]
    [switch] $IncludeUserData,

    [Parameter(ParameterSetName = 'Run')]
    [switch] $IncludeReview,

    [Parameter(ParameterSetName = 'Run')]
    [switch] $SkipUninstall,

    [Parameter(ParameterSetName = 'Run')]
    [switch] $KillIt,

    [Parameter(ParameterSetName = 'Run')]
    [switch] $NoBackup,

    [Parameter(ParameterSetName = 'Run')]
    [string] $Keyword,

    [Parameter(ParameterSetName = 'Run')]
    [string[]] $ProfilePath,

    [Parameter(ParameterSetName = 'List', Mandatory = $true)]
    [switch] $List,

    [Parameter(ParameterSetName = 'ListRuns', Mandatory = $true)]
    [switch] $ListRuns,

    [Parameter(ParameterSetName = 'Restore', Mandatory = $true)]
    [string] $Restore,

    [Parameter(ParameterSetName = 'Resume', Mandatory = $true)]
    [string] $Resume,

    [Parameter(ParameterSetName = 'Gui')]
    [switch] $Gui,

    # Internal: build the window without showing it, render it to this PNG, print its control states.
    [Parameter(ParameterSetName = 'GuiSelfTest', Mandatory = $true, DontShow = $true)]
    [string] $GuiSelfTest,

    # Internal: load the functions without running anything (the unit tests dot-source this way).
    [Parameter(ParameterSetName = 'Library', Mandatory = $true, DontShow = $true)]
    [switch] $LibraryOnly,

    [switch] $Force,

    [string] $OutDir,

    [string] $Log,

    [switch] $NoLog,

    [ValidateRange(0, 365)]
    [int] $QuarantineDays = 0,

    # Internal, tests only: a JSON file standing in for the policy registry key. Refused outside the
    # window self-test, so it can never be used to get around an administrator's lock.
    [Parameter(DontShow = $true)]
    [string] $PolicyFile,

    [switch] $Quiet
)

Set-StrictMode -Version 2.0
$script:ToolVersion = '0.4.1'
$script:ScriptPath = $PSCommandPath

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

function Get-Prop {
    # A property that may be missing ($null, not a strict-mode error): plans and journal records come back
    # from JSON, where a field that was never set simply isn't there.
    param($Object, [string] $Name)
    if ($null -eq $Object) { return $null }
    if ($Object -is [System.Collections.IDictionary]) { if ($Object.Contains($Name)) { return $Object[$Name] }; return $null }
    $p = $Object.PSObject.Properties[$Name]
    if ($p) { return $p.Value }
    return $null
}

function ConvertTo-UtcDate {
    # Our timestamps are ISO 8601 text; PowerShell 7's ConvertFrom-Json turns them into DateTime first.
    param($Value)
    if ($Value -is [datetime]) { return $Value.ToUniversalTime() }
    return [datetime]::Parse([string]$Value, [Globalization.CultureInfo]::InvariantCulture, [Globalization.DateTimeStyles]::RoundtripKind).ToUniversalTime()
}

$script:NormCache = New-Object 'System.Collections.Generic.Dictionary[string,object]'
function Get-NormalizedPath {
    # Absolute local or UNC path, env vars expanded, NT prefixes stripped, no trailing backslash.
    # Anything else (relative, empty, garbage) is $null, so a caller can never match against it.
    # Remembered per input: a scan asks for the same few hundred folders over and over, and Epic Games
    # Launcher's 4,400 MSI components checked against every protected folder took 268 s (2026-10-04).
    param([string] $Path)
    if ([string]::IsNullOrWhiteSpace($Path)) { return $null }
    $hit = $null
    if ($script:NormCache.TryGetValue($Path, [ref]$hit)) { return $hit }
    $res = ConvertTo-NormalizedPath $Path
    if ($script:NormCache.Count -ge 100000) { $script:NormCache.Clear() }
    $script:NormCache[$Path] = $res
    return $res
}

function ConvertTo-NormalizedPath {
    # Get-NormalizedPath's work, uncached.
    param([string] $Path)
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
    # on path boundaries on both sides. A SPACE does not end a path: "...\Bonjour" must not match
    # "...\Bonjour Print Services\x.exe" (review, 2026-09-26).
    param([string] $Text, [string[]] $Roots)
    if ([string]::IsNullOrEmpty($Text) -or -not $Roots) { return $false }
    $t = [Environment]::ExpandEnvironmentVariables($Text)
    $startOk = @('"', ' ', '=', ',', ';', "'", '(', '@', "`t")
    $endOk = @('\', '"', ',', ';', "'", ')', "`t")
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
    # The executable a command line runs: quoted path, or an unquoted path ending in a known extension.
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

function Split-CommandLine {
    # "C:\x\u.exe" /S /y  ->  @('C:\x\u.exe', '/S /y'). For running an uninstaller without a shell.
    param([string] $CommandLine)
    $c = [Environment]::ExpandEnvironmentVariables($CommandLine.Trim())
    if ($c.StartsWith('"')) {
        $end = $c.IndexOf('"', 1)
        if ($end -gt 1) { return @($c.Substring(1, $end - 1), $c.Substring($end + 1).Trim()) }
    }
    $m = [regex]::Match($c, '^(.+?\.(exe|cmd|bat|com))(?=$|\s)(.*)$', 'IgnoreCase')
    if ($m.Success) { return @($m.Groups[1].Value, $m.Groups[3].Value.Trim()) }
    $i = $c.IndexOf(' ')
    if ($i -lt 0) { return @($c, '') }
    return @($c.Substring(0, $i), $c.Substring($i + 1).Trim())
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
    #   "02:\SOFTWARE\Vendor\Product\Value"   a registry VALUE; 00 HKCR, 01 HKCU, 02 HKLM, 03 HKU,
    #                                         +20 = the 64-bit view; "...\Product\" = the key's default
    #   "C?\..."                              run-from-source marker for the drive letter
    param([string] $KeyPath)
    if ([string]::IsNullOrWhiteSpace($KeyPath)) { return $null }
    $k = $KeyPath.Trim()
    if ($k -match '^(\d\d):\\?(.*)$') {
        $code = [int]$matches[1]
        $rest = $matches[2]
        $root = $code % 20
        $hive = switch ($root) { 0 { 'HKCR' } 1 { 'HKCU' } 2 { 'HKLM' } 3 { 'HKU' } default { $null } }
        $key = $rest; $value = ''
        if ($rest.EndsWith('\')) { $key = $rest.TrimEnd('\') }
        elseif ($rest.Contains('\')) { $key = $rest.Substring(0, $rest.LastIndexOf('\')); $value = $rest.Substring($rest.LastIndexOf('\') + 1) }
        return [pscustomobject]@{ Kind = 'Registry'; Hive = $hive; Is64 = ($code -ge 20); Path = $rest; Key = $key; Value = $value; IsFolder = $false }
    }
    if ($k -match '^[A-Za-z]\?\\') { $k = $k.Substring(0, 1) + ':' + $k.Substring(2) }
    $p = Get-NormalizedPath $k
    if (-not $p) { return $null }
    return [pscustomobject]@{ Kind = 'File'; Hive = $null; Is64 = $false; Path = $p; Key = $null; Value = $null; IsFolder = $k.EndsWith('\') }
}

function Test-WholeWord {
    # Keyword match on word boundaries (letters and digits are word characters): "Zoom" does not match
    # "ZoomIt", "Java" does not match "JavaScript", "Notepad++" does not match "Notepad".
    param([string] $Text, [string] $Word)
    if ([string]::IsNullOrEmpty($Text) -or [string]::IsNullOrEmpty($Word)) { return $false }
    $pattern = '(?<![A-Za-z0-9])' + [regex]::Escape($Word) + '(?![A-Za-z0-9+])'
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
    'components', 'component', 'module', 'modules', 'package', 'program', 'programs', 'foundation', 'project',
    'release', 'current'
)

function Test-BlockedKeyword {
    # Words that name Windows, Microsoft or the management stack (Brian's list: "intune", "Microsoft"),
    # plus the generic words the candidates skip. Never a keyword, even when given explicitly.
    param([string] $Word)
    if ([string]::IsNullOrWhiteSpace($Word)) { return $true }
    $w = $Word.Trim().ToLowerInvariant()
    if ($script:KeywordStopWords -contains $w) { return $true }
    return ($w -match '^(microsoft|windows|win|intune|azure|entra|defender|onedrive|teams|edge|office|outlook|sccm|configmgr|ccm|mecm|wsus|msi|msiexec|installer|system32|syswow64|program|programdata|appdata|nvidia|intel|amd|realtek|dell|lenovo|hp|google|adobe|oracle|java|apple|vmware|citrix)$')
}

function Get-KeywordCandidates {
    # Distinctive tokens: versions, architecture and generic words dropped, 4+ characters, first seen first.
    param([string] $DisplayName, [string] $Publisher)
    $out = New-Object System.Collections.Generic.List[string]
    foreach ($source in @($DisplayName, $Publisher)) {
        if ([string]::IsNullOrWhiteSpace($source)) { continue }
        foreach ($tok in [regex]::Split($source, '[^A-Za-z0-9\-\+]+')) {
            # Trailing '+' is part of the name (Notepad++, C++): trimming it made the keyword "Notepad".
            $t = $tok.Trim('-')
            if ($t.Length -lt 4) { continue }
            if ($t -match '^[vV]?\d+([\.\-]\d+)*$') { continue }
            if ($t -match '^(?i)(\d+-?bit|x86-64|x86_64|amd64|arm64|win(32|64))$') { continue }
            if (Test-BlockedKeyword $t) { continue }
            if (-not ($out -contains $t)) { $out.Add($t) }
        }
    }
    # Enumerated, not comma-returned: callers wrap it in @(), and @() does not unroll a comma-returned
    # array (it nests it, so the whole list became ONE keyword candidate).
    return $out.ToArray()
}

function Get-PathDepth {
    param([string] $Path)
    $p = Get-NormalizedPath $Path
    if (-not $p) { return 0 }
    return $p.Split([char[]]@('\'), [StringSplitOptions]::RemoveEmptyEntries).Count - 1
}

function Get-ParentPath {
    # The folder above a normalized path: "C:\a\b" -> "C:\a" -> "C:\" -> $null.
    param([string] $Path)
    if (-not $Path -or $Path.Length -le 3) { return $null }
    $i = $Path.LastIndexOf('\')
    if ($i -eq 2) { return $Path.Substring(0, 3) }
    if ($i -le 2) { return $null }
    return $Path.Substring(0, $i)
}

function Split-RegPath {
    # "A\B\c/d" -> @('A\B', 'c/d'). Never Split-Path on a registry path: it splits on "/" too, and key names
    # may hold one. Adobe Reader's "MozillaPlugins\Adobe Acrobat\MimeTypes\application/pdf" sent a run to the
    # parent "...\MimeTypes\application", which doesn't exist, and stopped it (lab sweep, 2026-10-05).
    param([string] $Path)
    $i = $Path.LastIndexOf('\')
    if ($i -lt 0) { return @('', $Path) }
    return @($Path.Substring(0, $i), $Path.Substring($i + 1))
}

function Test-HoldsProgramFiles {
    # Does a folder hold programs (.exe, .dll, .sys) anywhere in its first 20,000 files? It decides what is
    # KEPT, so doubt keeps: unreadable, or too big to tell, counts as yes.
    param([string] $Path)
    $n = 0
    try {
        foreach ($f in [System.IO.Directory]::EnumerateFiles($Path, '*', [System.IO.SearchOption]::AllDirectories)) {
            if ($f -match '\.(exe|dll|sys)$') { return $true }
            $n++
            if ($n -ge 20000) { return $true }
        }
    } catch { return $true }
    return $false
}

function Get-ProgramContainerSubfolders {
    # A folder that looks like a CONTAINER of programs (a vendor folder): no .exe/.dll of its own at the top,
    # and programs in two or more subfolders. Returns those subfolders' names, or nothing.
    param([string] $Path)
    if (@(Get-ChildItem -LiteralPath $Path -File -Force -ErrorAction SilentlyContinue | Where-Object { $_.Extension -match '^(?i)\.(exe|dll)$' }).Count) { return }
    $dirs = @(Get-ChildItem -LiteralPath $Path -Directory -Force -ErrorAction SilentlyContinue | Where-Object { Test-HoldsProgramFiles $_.FullName } | ForEach-Object { $_.Name })
    if ($dirs.Count -ge 2) { return $dirs }
}

function Get-ProtectedPathReason {
    # Why a folder may never be a root (matching OR removal), or $null when it can be one.
    # ContainerPaths: may not BE the root, but their children may (Program Files, a profile root).
    # TreePaths: nothing at or under them may be a root (C:\Windows, Public, AppData\*\Microsoft).
    # Microsoft/Windows folders in Program Files and Common Files are protected at ANY depth
    # (review, 2026-09-26: "Office16\Library" slipped through a first-level-only check).
    param([string] $Path, [string[]] $ContainerPaths, [string[]] $TreePaths)
    $p = Get-NormalizedPath $Path
    if (-not $p) { return 'not an absolute local path' }
    if ($p.StartsWith('\\')) { return 'network path' }
    if ((Get-PathDepth $p) -lt 2) { return 'too shallow (a root must be at least two folders deep)' }
    # Test-PathUnder, inlined: $p is already normalized, and this runs once per folder of the app against
    # every protected folder of every profile.
    foreach ($t in $TreePaths) {
        if (-not $t) { continue }
        $tn = Get-NormalizedPath $t
        if ($tn -and ($p.Equals($tn, [StringComparison]::OrdinalIgnoreCase) -or $p.StartsWith($tn.TrimEnd('\') + '\', [StringComparison]::OrdinalIgnoreCase))) { return "inside protected folder $t" }
    }
    foreach ($c in $ContainerPaths) {
        $cn = Get-NormalizedPath $c
        if ($cn -and $p.Equals($cn, [StringComparison]::OrdinalIgnoreCase)) { return "is the shared folder $cn itself" }
    }
    foreach ($pf in @($env:ProgramFiles, ${env:ProgramFiles(x86)}, $env:ProgramW6432, $env:CommonProgramFiles, ${env:CommonProgramFiles(x86)}, $env:CommonProgramW6432)) {
        $pfn = Get-NormalizedPath $pf
        if (-not $pfn -or $p.Equals($pfn, [StringComparison]::OrdinalIgnoreCase) -or -not $p.StartsWith($pfn.TrimEnd('\') + '\', [StringComparison]::OrdinalIgnoreCase)) { continue }
        $first = $p.Substring($pfn.Length).TrimStart('\').Split('\')[0]
        if ($first -match '^(?i)(Microsoft|Windows[ .]|WindowsApps$|ModifiableWindowsApps$|dotnet$|Internet Explorer$|microsoft shared$|System$|Services$|SpeechEngines$|DESIGNER$|Reference Assemblies$|MSBuild$|IIS|Windows Kits$)') {
            return "Microsoft/Windows folder $pfn\$first"
        }
    }
    return $null
}

function Get-UserDataTag {
    # Bounded scan of a folder: size, and whether it holds document-like files. Documents (or, for a data
    # folder, sheer size) = HIGH RISK: "this folder may contain user data". An install folder is judged on
    # documents only: 100 MB of binaries is not user data (review, 2026-09-26).
    param([string] $Folder, [switch] $InstallFolder, [int] $MaxFiles = 5000, [long] $SizeThresholdBytes = 100MB)
    $docExt = @('.doc', '.docx', '.docm', '.xls', '.xlsx', '.xlsm', '.ppt', '.pptx', '.pdf', '.pst', '.ost', '.rtf', '.odt',
        '.ods', '.odp', '.one', '.msg', '.eml', '.accdb', '.mdb', '.kdbx', '.vsdx', '.pub')
    if (-not $InstallFolder) { $docExt += @('.db', '.sqlite', '.sqlite3') }
    $size = [long]0; $files = 0; $docs = 0; $capped = $false; $unreadable = 0
    $stack = New-Object System.Collections.Generic.Stack[string]
    $stack.Push($Folder)
    while ($stack.Count -and -not $capped) {
        $dir = $stack.Pop()
        try {
            foreach ($f in [System.IO.Directory]::EnumerateFiles($dir)) {
                $files++
                if ($files -gt $MaxFiles) { $capped = $true; break }
                try { $size += (New-Object System.IO.FileInfo $f).Length } catch { }
                if ($docExt -contains [System.IO.Path]::GetExtension($f).ToLowerInvariant()) { $docs++ }
            }
            foreach ($d in [System.IO.Directory]::EnumerateDirectories($dir)) {
                try { if (([System.IO.File]::GetAttributes($d) -band [System.IO.FileAttributes]::ReparsePoint) -eq 0) { $stack.Push($d) } } catch { $unreadable++ }
            }
        } catch { $unreadable++ }
    }
    $reasons = @()
    if (-not $InstallFolder -and $size -ge $SizeThresholdBytes) { $reasons += ('{0:N0} MB' -f ($size / 1MB)) }
    if ($docs -gt 0) { $reasons += "$docs document-like file(s)" }
    if ($capped) { $reasons += "more than $MaxFiles files (the scan stopped counting)" }
    if ($unreadable) { $reasons += "$unreadable unreadable folder(s)" }
    return [pscustomobject]@{
        SizeBytes = $size; Files = [Math]::Min($files, $MaxFiles); DocLike = $docs; Truncated = ($capped -or $unreadable -gt 0)
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

function Test-SameVendor {
    # "Insecure.Com LLC" vs "Insecure.Com, LLC": compare on letters and digits only, suffixes dropped.
    param([string] $A, [string] $B)
    if ([string]::IsNullOrWhiteSpace($A) -or [string]::IsNullOrWhiteSpace($B)) { return $false }
    $norm = { param($s) (($s.ToLowerInvariant() -replace '\b(inc|llc|ltd|limited|corp|corporation|gmbh|co|company|s\.a|b\.v|ag|plc)\b', '') -replace '[^a-z0-9]', '') }
    $x = & $norm $A; $y = & $norm $B
    return ($x.Length -ge 3 -and $x -eq $y)
}

# Security products are refused outright: tamper protection makes a generic removal unpredictable, and
# each vendor ships its own tool. Whole-word match on publisher, name, or the signer of its binaries.
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
    'Palo Alto Networks' = 'Cortex XDR Cleaner (with the uninstall password)'
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

function Select-SignerOrg {
    # The app's signer, from @{ org = how many of its executables it signed }: the most frequent NON-Microsoft
    # signer, and Microsoft only when nothing else signed any of them. A third-party app can BUNDLE
    # Microsoft-signed files: paint.net ships the .NET runtime, its Microsoft-signed helpers outnumbered dotPDN's
    # own exe, and the app was refused as "a Microsoft component" (lab rerun, 2026-10-05).
    param([hashtable] $OrgCounts)
    if (-not $OrgCounts -or -not $OrgCounts.Count) { return $null }
    $others = @($OrgCounts.GetEnumerator() | Where-Object { -not (Test-IsMicrosoftName $_.Key) } | Sort-Object Value -Descending)
    if ($others.Count) { return $others[0].Key }
    return ($OrgCounts.GetEnumerator() | Sort-Object Value -Descending | Select-Object -First 1).Key
}

function Get-RefusalReason {
    # Protected products are refused at PLAN time, re-checked once the real publisher and signer are
    # known: a -ProductCode run with no uninstall entry starts with an empty publisher (review 2026-09-26).
    param([string] $Publisher, [string] $DisplayName, [string] $SignerOrg)
    if (Test-IsMicrosoftName $Publisher) { return "Microsoft product ($Publisher). Kill It With Fire never touches Microsoft software, runtimes or management agents; use Settings, the Windows feature tools, or Microsoft's own support tool." }
    if ($Publisher -match '(?i)\bVitko Software\b' -or $DisplayName -match '^(?i)RFF (Agent|Updater)\b' -or $SignerOrg -match '(?i)\bVitko Software\b') { return 'This is the RFF agent. Kill It With Fire never removes the agent it may be running under.' }
    foreach ($v in $script:SecurityVendors.Keys) {
        if ((Test-WholeWord $Publisher $v) -or (Test-WholeWord $DisplayName $v) -or (Test-WholeWord $SignerOrg $v)) {
            return "Security product ($v). Tamper protection makes a generic removal unpredictable. Use $($script:SecurityVendors[$v])."
        }
    }
    if ($SignerOrg -and (Test-IsMicrosoftName $SignerOrg)) { return "The app's own executables are signed by Microsoft ($SignerOrg). Refusing: it may be a Microsoft component under another name." }
    return $null
}

# ---------------------------------------------------------------- categories, order, policy, .reg text

# What -Include/-Exclude and the window's checklist work in. AppData (UserData) is always opt-in.
$script:Categories = [ordered]@{
    Registration = @('UninstallEntry', 'MsiProduct', 'MsiUpgradeCode', 'MsiComponentClient', 'MsiPatch', 'MsiFolderEntry', 'MsiDependency', 'MsiCachedPackage', 'UpdaterRegistration')
    LogonHooks   = @('PasswordProviderRestore', 'CredentialProviderFilter', 'CredentialProvider', 'Winlogon', 'LsaPackage', 'NetworkProvider', 'AppInitDll', 'IfeoDebugger', 'WinsockProvider')
    Drivers      = @('DeviceClassFilter', 'DeviceInstanceFilter', 'NetworkComponent', 'DriverPackage', 'Driver')
    Services     = @('Service', 'RunningProcess')
    Startup      = @('ScheduledTask', 'RunValue', 'ActiveSetup')
    ComShell     = @('ComClass', 'ComTypeLib', 'ComAppId', 'ComProgId', 'ShellExtension', 'ShellVerb', 'FileAssociation')
    Other        = @('PrintMonitor', 'FirewallRule', 'Shortcut')
    Files        = @('InstallRoot', 'IdentityFile', 'InstallerIconFolder', 'ProgramDataFolder', 'ProgramFilesFolder')
    Registry     = @('VendorRegistryKey', 'MsiRegistryValue', 'UserRegistryKey')
    UserData     = @('AppDataFolder', 'UserDataKey')
}
$script:CategoryLabels = [ordered]@{
    Registration = 'Registration (uninstall entry, Windows Installer)'
    LogonHooks   = 'Logon and network hooks'
    Drivers      = 'Drivers, device filters, network components'
    Services     = 'Services and running programs'
    Startup      = 'Scheduled tasks and startup entries'
    ComShell     = 'COM, shell extensions, file associations'
    Other        = 'Shortcuts, firewall rules, print monitors'
    Files        = 'Program folders and files'
    Registry     = 'Registry keys and values'
    UserData     = 'User data (AppData)'
}

# Execution order. Logon hooks come FIRST, and the built-in password sign-in is turned back on BEFORE
# the app's providers go: a run that stops part way must never leave a machine nobody can log in to.
# Device filters come before the driver they name, or every device in the class dies at the next boot.
$script:Order = @{
    UninstallEntry = 110; MsiProduct = 120; MsiUpgradeCode = 130; MsiComponentClient = 140; MsiPatch = 150
    MsiFolderEntry = 160; MsiDependency = 165; MsiCachedPackage = 170; UpdaterRegistration = 175
    PasswordProviderRestore = 300; CredentialProviderFilter = 301; CredentialProvider = 302; Winlogon = 303
    LsaPackage = 304; NetworkProvider = 305; AppInitDll = 306; IfeoDebugger = 307; WinsockProvider = 308
    # User-mode services stop BEFORE the drivers they hold open, so a driver can unload without a reboot.
    # The app's own running programs stop after its services (a service can restart them) and before its
    # files move (a running updater held Notepad++'s folder in place, lab 2026-09-26).
    DeviceClassFilter = 310; DeviceInstanceFilter = 311; Service = 315; RunningProcess = 316; NetworkComponent = 320; DriverPackage = 330
    Driver = 340; ScheduledTask = 350; RunValue = 360; ActiveSetup = 362
    ComClass = 370; ComTypeLib = 371; ComAppId = 372; ComProgId = 374; ShellExtension = 375; ShellVerb = 376
    FileAssociation = 377; PrintMonitor = 396; FirewallRule = 399; Shortcut = 400
    InstallRoot = 500; IdentityFile = 505; InstallerIconFolder = 506; ProgramDataFolder = 510; ProgramFilesFolder = 511
    VendorRegistryKey = 520; MsiRegistryValue = 521; UserRegistryKey = 530; AppDataFolder = 540; UserDataKey = 541
}

function Get-CategoryGroup {
    param([string] $Category)
    foreach ($g in $script:Categories.Keys) { if ($script:Categories[$g] -contains $Category) { return $g } }
    return 'Other'
}

function Get-KillItWithFirePolicy {
    # Administrator locks from HKLM\SOFTWARE\Policies\KillItWithFire (GPO / Intune). Missing = not locked.
    param([string] $Json)
    $p = [ordered]@{ MaxLevel = $null; RequireBackup = $false; RequireLog = $false; LogPath = $null; AllowUserData = $null; QuarantineDays = $null; Source = $null }
    if ($Json) {
        # Same value types as the registry path below: DWORD 0/1 flags become booleans.
        $o = $Json | ConvertFrom-Json
        if ($null -ne (Get-Prop $o 'MaxLevel')) { $p.MaxLevel = [int]$o.MaxLevel }
        $p.RequireBackup = ([int](0 + (Get-Prop $o 'RequireBackup')) -eq 1)
        $p.RequireLog = ([int](0 + (Get-Prop $o 'RequireLog')) -eq 1)
        if (Get-Prop $o 'LogPath') { $p.LogPath = [string]$o.LogPath }
        if ($null -ne (Get-Prop $o 'AllowUserData')) { $p.AllowUserData = ([int]$o.AllowUserData -eq 1) }
        if ($null -ne (Get-Prop $o 'QuarantineDays')) { $p.QuarantineDays = [int]$o.QuarantineDays }
        $p.Source = 'test override'
        return [pscustomobject]$p
    }
    $k = $null
    try {
        $k = [Microsoft.Win32.RegistryKey]::OpenBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine, [Microsoft.Win32.RegistryView]::Registry64).OpenSubKey('SOFTWARE\Policies\KillItWithFire')
        if ($k) {
            $p.Source = 'HKLM\SOFTWARE\Policies\KillItWithFire'
            $v = $k.GetValue('MaxLevel', $null); if ($null -ne $v) { $p.MaxLevel = [int]$v }
            $p.RequireBackup = ([int](0 + $k.GetValue('RequireBackup', 0)) -eq 1)
            $p.RequireLog = ([int](0 + $k.GetValue('RequireLog', 0)) -eq 1)
            $v = $k.GetValue('LogPath', $null); if ($v) { $p.LogPath = [string]$v }
            $v = $k.GetValue('AllowUserData', $null); if ($null -ne $v) { $p.AllowUserData = ([int]$v -eq 1) }
            $v = $k.GetValue('QuarantineDays', $null); if ($null -ne $v) { $p.QuarantineDays = [int]$v }
        }
    } catch { } finally { if ($k) { $k.Close() } }
    return [pscustomobject]$p
}

function Resolve-RunLevel {
    # -KillIt is a level 3 run with -SkipUninstall, and nothing more: the caller applies the policy, the
    # refusals and the backup to the RESULT, so -KillIt can never reach what that pair could not. Level 0 is
    # the parameter's default, so it reads as "not given"; 1 and 2 contradict -KillIt and are refused.
    # EVERY key on every return: under Set-StrictMode a caller reading .Error on a result that lacks it
    # throws, which crashed every run (scans included) in the first catalog pilot, 2026-10-03.
    param([int] $Level, [bool] $KillIt, [bool] $SkipUninstall)
    if (-not $KillIt) { return @{ Level = $Level; SkipUninstall = $SkipUninstall; Error = $null } }
    if ($Level -ne 0 -and $Level -ne 3) { return @{ Level = $Level; SkipUninstall = $SkipUninstall; Error = "-KillIt is a level 3 run; leave -Level $Level out." } }
    return @{ Level = 3; SkipUninstall = $true; Error = $null }
}

function Get-PolicyViolations {
    # What the requested options would break. The ENGINE refuses on any of these (the window only greys
    # them out), so a switch can never get around an administrator's lock.
    param($Policy, [int] $Level, [bool] $NoBackup, [bool] $NoLog, [string] $LogPath, [bool] $IncludeUserData, [int] $QuarantineDays)
    $v = @()
    if ($null -ne $Policy.MaxLevel -and $Level -gt [int]$Policy.MaxLevel) { $v += "level $Level is above the highest level your administrator allows ($($Policy.MaxLevel))" }
    if ($Policy.RequireBackup -and $NoBackup) { $v += '-NoBackup: your administrator requires a backup' }
    if ($Policy.RequireLog -and $NoLog) { $v += '-NoLog: your administrator requires a log' }
    if ($Policy.LogPath -and $LogPath -and -not ([string]$LogPath).Equals([string]$Policy.LogPath, [StringComparison]::OrdinalIgnoreCase)) { $v += "-Log: your administrator sets the log location ($($Policy.LogPath))" }
    if ($Policy.AllowUserData -eq $false -and $IncludeUserData) { $v += '-IncludeUserData: your administrator does not allow removing user data' }
    if ($null -ne $Policy.QuarantineDays -and $QuarantineDays -gt 0 -and $QuarantineDays -ne [int]$Policy.QuarantineDays) { $v += "-QuarantineDays: set by your administrator ($($Policy.QuarantineDays))" }
    return $v
}

function Format-RegString {
    param([string] $Text)
    return $Text.Replace('\', '\\').Replace('"', '\"')
}

function Format-RegHex {
    param([byte[]] $Bytes)
    if (-not $Bytes -or $Bytes.Length -eq 0) { return '' }
    return (($Bytes | ForEach-Object { '{0:x2}' -f $_ }) -join ',')
}

function ConvertTo-RegFileText {
    # .reg (version 5) text. Keys: @{ Path = 'HKEY_LOCAL_MACHINE\...'; Values = @(@{ Name; Kind; Data }) }
    # Kind is a Microsoft.Win32.RegistryValueKind name; Name '' is the default value (@). A key with
    # no values still writes its header, so importing it re-creates the key.
    param([object[]] $Keys)
    $sb = New-Object System.Text.StringBuilder
    [void]$sb.AppendLine('Windows Registry Editor Version 5.00')
    foreach ($k in $Keys) {
        [void]$sb.AppendLine('')
        [void]$sb.AppendLine('[' + $k.Path + ']')
        foreach ($v in @($k.Values)) {
            if ($null -eq $v) { continue }
            $n = if ([string]::IsNullOrEmpty($v.Name)) { '@' } else { '"' + (Format-RegString $v.Name) + '"' }
            switch ([string]$v.Kind) {
                'String' {
                    $s = [string]$v.Data
                    # A line break or NUL can't live inside a quoted .reg string: write those as hex(1).
                    if ($s.IndexOfAny([char[]]@("`r", "`n", [char]0)) -ge 0) { [void]$sb.AppendLine($n + '=hex(1):' + (Format-RegHex ([System.Text.Encoding]::Unicode.GetBytes($s + [char]0)))) }
                    else { [void]$sb.AppendLine($n + '="' + (Format-RegString $s) + '"') }
                }
                'DWord' { [void]$sb.AppendLine($n + '=dword:' + ('{0:x8}' -f [BitConverter]::ToUInt32([BitConverter]::GetBytes([int32]$v.Data), 0))) }
                'QWord' { [void]$sb.AppendLine($n + '=hex(b):' + (Format-RegHex ([BitConverter]::GetBytes([int64]$v.Data)))) }
                'ExpandString' { [void]$sb.AppendLine($n + '=hex(2):' + (Format-RegHex ([System.Text.Encoding]::Unicode.GetBytes([string]$v.Data + [char]0)))) }
                'MultiString' {
                    $joined = ((@($v.Data) | ForEach-Object { [string]$_ + [char]0 }) -join '') + [char]0
                    [void]$sb.AppendLine($n + '=hex(7):' + (Format-RegHex ([System.Text.Encoding]::Unicode.GetBytes($joined))))
                }
                'Binary' { [void]$sb.AppendLine($n + '=hex:' + (Format-RegHex ([byte[]]$v.Data))) }
                default { [void]$sb.AppendLine($n + '=hex(0):' + (Format-RegHex ([byte[]]$v.Data))) }
            }
        }
    }
    return $sb.ToString()
}

function Remove-ListEntry {
    # "a.exe,b.exe," minus b.exe -> "a.exe," : the separator and a trailing separator survive; entries
    # compare trimmed, case-insensitively, and as paths when both sides are paths. Userinit keeps its
    # other entries (review 2026-09-26: "restore the default" wiped them).
    param([string] $List, [string] $Entry, [string] $Separator = ',')
    if ($null -eq $List) { return $null }
    $trailing = $List.TrimEnd().EndsWith($Separator.Trim()) -and $Separator.Trim()
    $parts = @($List.Split(@($Separator), [StringSplitOptions]::None) | ForEach-Object { $_.Trim() } | Where-Object { $_ })
    $en = Get-NormalizedPath $Entry
    $keep = @($parts | Where-Object {
            $pn = Get-NormalizedPath $_
            -not ($_.Equals($Entry.Trim(), [StringComparison]::OrdinalIgnoreCase) -or ($pn -and $en -and $pn.Equals($en, [StringComparison]::OrdinalIgnoreCase)))
        })
    $out = $keep -join $Separator
    if ($trailing -and $out) { $out += $Separator.Trim() }
    return $out
}

function ConvertTo-ArgvString {
    # One argument for a Windows command line (CommandLineToArgvW rules): quoted when it needs it, with
    # backslashes doubled wherever they come right before a quote. "C:\IT Logs\" otherwise ate its own
    # closing quote and every argument after it (review 2026-09-26).
    param([AllowEmptyString()] [string] $Arg)
    if ($Arg -and $Arg -notmatch '[\s"]') { return $Arg }
    $s = [regex]::Replace($Arg, '(\\*)"', { param($m) ($m.Groups[1].Value * 2) + '\"' })
    $s = [regex]::Replace($s, '(\\+)$', { param($m) $m.Groups[1].Value * 2 })
    return '"' + $s + '"'
}

function Get-PowerShellExe {
    # The PowerShell that runs this script, as a console exe: never the ISE or another host, which would
    # open the script instead of running it (review 2026-09-26).
    if ($PSVersionTable.PSEdition -eq 'Core') { return (Join-Path $PSHOME 'pwsh.exe') }
    return (Join-Path $PSHOME 'powershell.exe')
}

function Invoke-SelfRelaunch {
    # Run this script again in another PowerShell (64-bit, or STA) with the same arguments, in this console,
    # and hand back its exit code. Built with ConvertTo-ArgvString, not PowerShell's own native-argument
    # passing, which mangles embedded quotes and trailing backslashes on 5.1.
    param([string] $Exe, [string[]] $HostArgs, [string[]] $ScriptArgs)
    $psi = New-Object System.Diagnostics.ProcessStartInfo
    $psi.FileName = $Exe
    $psi.Arguments = (@($HostArgs + @('-File', $script:ScriptPath) + $ScriptArgs) | ForEach-Object { ConvertTo-ArgvString $_ }) -join ' '
    $psi.UseShellExecute = $false
    $p = [System.Diagnostics.Process]::Start($psi)
    $p.WaitForExit()
    return $p.ExitCode
}

function ConvertTo-ArgumentList {
    # Bound parameters back to an argument array (the 64-bit / STA relaunch, and the window's command line).
    param([System.Collections.IDictionary] $Bound)
    $out = New-Object System.Collections.Generic.List[string]
    foreach ($k in $Bound.Keys) {
        $v = $Bound[$k]
        if ($v -is [System.Management.Automation.SwitchParameter]) { if ($v.IsPresent) { $out.Add("-$k") } }
        elseif ($v -is [array]) { $out.Add("-$k"); $out.Add((@($v) -join ',')) }
        else { $out.Add("-$k"); $out.Add([string]$v) }
    }
    return , $out.ToArray()
}

function Format-CommandLine {
    # The PowerShell command that does what the window is about to do, for an RMM or PDQ job. Unticked
    # categories become -Exclude, so the same line still means "everything else" on a machine whose
    # scan finds categories this one didn't.
    param([string] $AppName, [string] $ProductCode, [int] $Level, [string[]] $Exclude, [bool] $IncludeUserData, [bool] $IncludeReview,
        [bool] $NoBackup, [bool] $NoLog, [string] $LogPath, [bool] $SkipUninstall = $false)
    $q = { param($s) "'" + ([string]$s).Replace("'", "''") + "'" }
    $parts = @('.\KillItWithFire.ps1')
    if ($ProductCode) { $parts += "-ProductCode $(& $q $ProductCode)" } elseif ($AppName) { $parts += "-Name $(& $q $AppName)" }
    $parts += "-Level $Level"
    # A level 3 run that skips the uninstaller IS -KillIt; say it the way a person would type it.
    $killIt = ($SkipUninstall -and $Level -eq 3)
    if ($killIt) { $parts[-1] = '-KillIt' }
    if ($Level -ge 2 -and $Exclude -and @($Exclude).Count) { $parts += "-Exclude $((@($Exclude)) -join ',')" }
    if ($IncludeUserData) { $parts += '-IncludeUserData' }
    if ($IncludeReview) { $parts += '-IncludeReview' }
    if ($SkipUninstall -and $Level -ge 1 -and -not $killIt) { $parts += '-SkipUninstall' }
    if ($NoBackup) { $parts += '-NoBackup' }
    if ($NoLog) { $parts += '-NoLog' } elseif ($LogPath) { $parts += "-Log $(& $q $LogPath)" }
    if ($Level -ge 1) { $parts += '-Force' }
    return ($parts -join ' ')
}

# =====================================================================================================
# Machine access (read-only). Registry via .NET with EXPLICIT views, so a 32-bit host still sees both
# halves; the 32-bit relaunch below makes System32 and Program Files mean what they say, too.
# =====================================================================================================

$script:Base = @{}
$script:Unreadable = @{}
$script:InfUsers = $null   # Get-InfDeviceUsers cache, reset per scan

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
    param([string] $Hive, [string] $Path, [string] $Area = 'registry', [switch] $Writable)
    try { return $script:Base[$Hive].OpenSubKey($Path, [bool]$Writable) } catch { if (-not $Writable) { Add-Unreadable $Area }; if ($Writable) { throw }; return $null }
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

function Get-InfDeviceUsers {
    # Who uses a driver package: every device (and network component) driver key under Control\Class
    # whose InfPath is this INF, named by its ComponentId or MatchingDeviceId. Present or not: a device
    # that is unplugged today still loses its driver. Built once per scan.
    param([string] $Inf)
    if ($null -eq $script:InfUsers) {
        $script:InfUsers = @{}
        $ck = Open-Key 'HKLM64' 'SYSTEM\CurrentControlSet\Control\Class' 'device classes'
        foreach ($g in (Get-SubKeyNamesSafe $ck 'device classes')) {
            $gk = $null; try { $gk = $ck.OpenSubKey($g, $false) } catch { }
            foreach ($n in (Get-SubKeyNamesSafe $gk 'device classes' | Where-Object { $_ -match '^\d{4}$' })) {
                $dk = $null; try { $dk = $gk.OpenSubKey($n, $false) } catch { }
                if ($null -eq $dk) { continue }
                $ip = [string](Get-ValueSafe $dk 'InfPath')
                if ($ip) {
                    $who = [string](Get-ValueSafe $dk 'ComponentId')
                    if (-not $who) { $who = [string](Get-ValueSafe $dk 'MatchingDeviceId') }
                    if (-not $who) { $who = [string](Get-ValueSafe $dk 'DriverDesc') }
                    if (-not $who) { $who = "$g\$n" }
                    if (-not $script:InfUsers.ContainsKey($ip.ToLowerInvariant())) { $script:InfUsers[$ip.ToLowerInvariant()] = @() }
                    $script:InfUsers[$ip.ToLowerInvariant()] += $who
                }
                Close-Key $dk
            }
            Close-Key $gk
        }
        Close-Key $ck
    }
    $k = $Inf.ToLowerInvariant()
    if ($script:InfUsers.ContainsKey($k)) { return @($script:InfUsers[$k] | Select-Object -Unique) }
    return @()
}

function Close-Key {
    param($Key)
    if ($null -ne $Key) { try { $Key.Close() } catch { } }
}

function Get-KeyNativePath {
    # Where a key REALLY is, from the kernel (NtQueryKey), or $null when it doesn't exist. The 32-bit
    # view is not simply SOFTWARE\WOW6432Node: most of SOFTWARE\Classes (ProgIDs, file extensions,
    # *\shellex handlers) is SHARED between the views. Guessing sent backups of 7-Zip's 32-bit shell
    # handlers to WOW6432Node\Classes, where reg.exe found nothing (lab, 2026-09-26).
    param([string] $Hive, [string] $Path)
    if (-not $script:Base.ContainsKey($Hive)) { return $null }
    $k = $null
    try { $k = $script:Base[$Hive].OpenSubKey($Path, $false) } catch { return $null }
    if ($null -eq $k) { return $null }
    $n = $null
    try { $n = [KillItWithFire.Native]::GetKeyName($k.Handle.DangerousGetHandle()) } catch { } finally { $k.Close() }
    if ($n -match '^(?i)\\REGISTRY\\MACHINE\\(.+)$') { return 'HKEY_LOCAL_MACHINE\' + $matches[1] }
    if ($n -match '^(?i)\\REGISTRY\\USER\\(.+)$') { return 'HKEY_USERS\' + $matches[1] }
    return $null
}

function Format-RegPath {
    # Human form of a key, at its real location (see Get-KeyNativePath). A key that no longer exists
    # falls back to the classic rule: the 32-bit view of SOFTWARE is SOFTWARE\WOW6432Node.
    param([string] $Hive, [string] $Path)
    $native = Get-KeyNativePath $Hive $Path
    if ($native) {
        if ($native.StartsWith('HKEY_LOCAL_MACHINE\')) { return 'HKLM\' + $native.Substring(19) }
        return 'HKU\' + $native.Substring(11)
    }
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

function Get-PhysicalRegPath {
    # The full path reg.exe and .reg files use.
    param([string] $Hive, [string] $Path)
    $h = Format-RegPath $Hive $Path
    if ($h.StartsWith('HKLM\')) { return 'HKEY_LOCAL_MACHINE\' + $h.Substring(5) }
    if ($h.StartsWith('HKU\')) { return 'HKEY_USERS\' + $h.Substring(4) }
    return $h
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
        # Where this user's Desktop, Documents etc. really are (OneDrive redirection moves them).
        $shellFolders = @()
        if ($LoadedSids -contains $sid) {
            # The user's DATA folders only (Desktop, Documents, Pictures, Music, Videos, Favorites, Downloads).
            # Not every value: "Local AppData" and "AppData" are shell folders too, and protecting them
            # as trees hid every per-user install (DBeaver lost its folder; regression run 2026-09-26).
            $dataFolders = @('Desktop', 'Personal', 'My Pictures', 'My Music', 'My Video', 'Favorites', '{374DE290-123F-4565-9164-39C4925E467B}',
                '{7D83EE9B-2244-4E70-B1F5-5393042AF1E4}', '{F42EE2D3-909F-4907-8871-4C22FC0BF756}', '{0DDD015D-B06C-45D5-8C4C-F59713854639}',
                '{A0C69A99-21C8-4671-8703-7934162FCF1D}', '{35286A68-3C57-41A1-BBB1-0EAE73D76C95}')
            $usf = Open-Key 'HKU' "$sid\Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders"
            foreach ($v in (Get-ValueNamesSafe $usf)) {
                if ($dataFolders -notcontains $v) { continue }
                $raw = [string](Get-ValueSafe $usf $v)
                if (-not $raw) { continue }
                $expanded = $raw.Replace('%USERPROFILE%', $path).Replace('%userprofile%', $path)
                $n = Get-NormalizedPath $expanded
                if ($n) { $shellFolders += $n }
            }
            Close-Key $usf
        }
        $out += [pscustomobject]@{
            Sid = $sid; Path = $path; User = (Split-Path $path -Leaf)
            Loaded = ($LoadedSids -contains $sid); Roaming = (-not [string]::IsNullOrWhiteSpace($central)); ShellFolders = $shellFolders
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
            # Installed date and size for the window (2026-10-04). No InstallDate: when the entry last changed,
            # as Programs and Features shows it. EstimatedSize is KB, what the app itself reported.
            $installed = ConvertFrom-InstallDate ([string](Get-ValueSafe $k 'InstallDate'))
            $fromKey = $false
            if (-not $installed) {
                $ft = [long]0
                try { $ft = [KillItWithFire.RegTime]::LastWriteFileTime($k.Handle) } catch { }
                if ($ft -gt 0) { $installed = [datetime]::FromFileTime($ft).Date; $fromKey = $true }
            }
            $sizeKb = $null
            try { $sv = Get-ValueSafe $k 'EstimatedSize'; if ($null -ne $sv) { $n = [long]$sv; if ($n -lt 0) { $n += 4294967296 }; if ($n -gt 0) { $sizeKb = $n } } } catch { }
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
                    IsMsi                = ((Get-ValueSafe $k 'WindowsInstaller') -eq 1)
                    ProductCode          = $(if (Test-IsGuid $name) { '{' + $name.Trim('{', '}').ToUpperInvariant() + '}' } else { $null })
                    InstallDate          = $installed
                    InstallDateFromKey   = $fromKey
                    SizeKB               = $sizeKb
                })
            Close-Key $k
        }
        Close-Key $root
    }
    return , $entries
}

function ConvertFrom-InstallDate {
    # An uninstall entry's InstallDate: yyyyMMdd by convention, though vendors write other forms too.
    # Anything unreadable or implausible is $null (the caller falls back to the key's own date).
    param([string] $Text)
    $t = ([string]$Text).Trim()
    if (-not $t) { return $null }
    $ci = [Globalization.CultureInfo]::InvariantCulture
    foreach ($fmt in @('yyyyMMdd', 'yyyy-MM-dd', 'yyyy/MM/dd', 'yyyy.MM.dd', 'M/d/yyyy', 'MM/dd/yyyy', 'd.M.yyyy', 'dd.MM.yyyy')) {
        $d = [datetime]::MinValue
        if ([datetime]::TryParseExact($t, $fmt, $ci, [Globalization.DateTimeStyles]::None, [ref]$d)) {
            if ($d.Year -ge 1990 -and $d -le (Get-Date).AddDays(1)) { return $d }
            return $null
        }
    }
    return $null
}

$script:SidNames = @{}
function Get-EntryScopeLabel {
    # Which uninstall key an entry lives in: the machine's 64-bit or 32-bit view, or one user's own. Spelled
    # out (2026-10-04: "machine" read as neither 64- nor 32-bit).
    param($Entry)
    $sid = [string](Get-Prop $Entry 'Sid')
    if ($sid) {
        if (-not $script:SidNames.ContainsKey($sid)) {
            $n = $sid
            try { $n = ([System.Security.Principal.SecurityIdentifier]::new($sid)).Translate([System.Security.Principal.NTAccount]).Value.Split('\')[-1] } catch { }
            $script:SidNames[$sid] = $n
        }
        return "User ($($script:SidNames[$sid]))"
    }
    if ((Get-Prop $Entry 'Hive') -eq 'HKLM32') { return 'Machine 32-bit' }
    if ([Environment]::Is64BitOperatingSystem) { return 'Machine 64-bit' }
    return 'Machine'
}

function Format-AppSize {
    # EstimatedSize (KB, as the app reported it) the way the window shows it; nothing when unknown.
    param($KB)
    if ($null -eq $KB -or [double]$KB -le 0) { return '' }
    $b = [double]$KB * 1KB
    if ($b -ge 1GB) { return ('{0:N1} GB' -f ($b / 1GB)) }
    if ($b -ge 10MB) { return ('{0:N0} MB' -f ($b / 1MB)) }
    if ($b -ge 1MB) { return ('{0:N1} MB' -f ($b / 1MB)) }
    return ('{0:N0} KB' -f [double]$KB)
}

function ConvertTo-VersionSortKey {
    # "26.2.21931" -> "000000000026.000000000002.000000021931": the parts compare as numbers, text as text.
    param([string] $Version)
    if (-not $Version) { return '' }
    return [regex]::Replace($Version.Trim(), '\d+', { param($m) $m.Value.TrimStart('0').PadLeft(12, '0') })
}

function Get-AppSortKey {
    # The value the window's app list sorts on, per column: Name, Version, Publisher, Type, Scope, Installed, Size.
    param($Entry, [int] $Column)
    switch ($Column) {
        1 { return (ConvertTo-VersionSortKey ([string](Get-Prop $Entry 'DisplayVersion'))) }
        2 { return [string](Get-Prop $Entry 'Publisher') }
        3 { return $(if (Get-Prop $Entry 'IsMsi') { 'MSI' } else { 'EXE' }) }
        4 { return (Get-EntryScopeLabel $Entry) }
        5 { return (Get-Prop $Entry 'InstallDate') }
        6 { return (Get-Prop $Entry 'SizeKB') }
    }
    return [string](Get-Prop $Entry 'DisplayName')
}

function Select-AppListRows {
    # The window's app list: the search text filters on name or publisher, then one column sorts it. Dates
    # and sizes sort as dates and numbers, versions part by part, and an empty cell always goes last.
    param($Entries, [string] $Filter, [int] $Column = 0, [bool] $Descending = $false)
    $keyed = New-Object System.Collections.Generic.List[object]
    foreach ($e in $Entries) {
        if ($null -eq $e) { continue }
        $name = [string](Get-Prop $e 'DisplayName')
        if ($Filter -and $name.IndexOf($Filter, [StringComparison]::OrdinalIgnoreCase) -lt 0 -and ([string](Get-Prop $e 'Publisher')).IndexOf($Filter, [StringComparison]::OrdinalIgnoreCase) -lt 0) { continue }
        $k = Get-AppSortKey $e $Column
        $keyed.Add([pscustomobject]@{ Entry = $e; Key = $k; Name = $name; Empty = ($null -eq $k -or "$k" -eq '') })
    }
    $full = @($keyed | Where-Object { -not $_.Empty } | Sort-Object -Property @{ Expression = 'Key'; Descending = $Descending }, @{ Expression = 'Name'; Descending = $false })
    $none = @($keyed | Where-Object { $_.Empty } | Sort-Object -Property Name)
    return @(@($full) + @($none) | ForEach-Object { $_.Entry })
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
    # ONE pass over every UserData\<sid>\Components\<packed component> (KillItWithFire.Fast, compiled: the
    # PowerShell loop took 46 s on a machine with 53,000 component clients). All / Ours / ByComponent.
    param([string] $PackedPc)
    $ud = Open-Key 'HKLM64' 'SOFTWARE\Microsoft\Windows\CurrentVersion\Installer\UserData' 'msi components'
    try { $ix = [KillItWithFire.Fast]::ReadComponentIndex($ud, $PackedPc) } finally { Close-Key $ud }
    for ($i = 0; $i -lt $ix.Unreadable; $i++) { Add-Unreadable 'msi components' }
    return $ix
}

function Get-OtherComponentClients {
    # Clients of a component other than us (a permanent "000...0" client counts: it is never removable).
    # A loop, not a pipeline: it runs once per component of the app, 4,400 times for Epic Games Launcher.
    param($Index, [string] $Component, [string] $PackedPc)
    if ($null -eq $Index -or -not $Index.ByComponent.ContainsKey($Component)) { return @() }
    $seen = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
    $others = New-Object System.Collections.Generic.List[string]
    foreach ($cl in $Index.ByComponent[$Component]) { if ($cl -ne $PackedPc -and $seen.Add($cl)) { $others.Add($cl) } }
    # Enumerated, not wrapped: every caller counts @(...) of this, and ", array" would always count 1.
    return $others.ToArray()
}

function Invoke-ComMember {
    param($Object, [string] $Member, [string] $Kind = 'InvokeMethod', [object[]] $Arguments = $null)
    return $Object.GetType().InvokeMember($Member, [System.Reflection.BindingFlags]::$Kind, $null, $Object, $Arguments)
}

function Get-MsiTableRows {
    # Read-only query of the cached MSI (OpenDatabase mode 0). Returns ONE array of rows: assign it to a
    # variable before piping (piping the call hands over the whole array as one item; review 2026-09-26).
    # A missing table is an empty result; any other failure is recorded in $script:MsiReadErrors.
    # Through msi.dll directly (KillItWithFire.Fast): late-bound COM cost ~1.5 ms a field, 36 s for Epic Games
    # Launcher's 4,400-row tables (2026-10-04).
    param([string] $MsiPath, [string] $Query, [int] $Columns)
    $rows = @()
    try {
        $rows = [KillItWithFire.Fast]::MsiQuery($MsiPath, $Query, $Columns)
    } catch {
        if ($_.Exception.Message -notmatch 'OpenView|1604|table') { $script:MsiReadErrors += "$Query : $($_.Exception.InnerException.Message)" }
    }
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

function Get-VendorOfFile {
    # CompanyName from the file's version resource. Kernel drivers are signed by Microsoft's attestation
    # service on Windows 10+, so their SIGNATURE can't tie them to a vendor; the vendor's own version
    # resource can. Self-declared, so it is weak evidence: always "needs review".
    param([string] $File)
    try {
        if (-not $File -or -not (Test-Path -LiteralPath $File -PathType Leaf)) { return $null }
        $c = [System.Diagnostics.FileVersionInfo]::GetVersionInfo($File).CompanyName
        if ($c) { return $c.Trim() }
    } catch { }
    return $null
}

$script:MatchRoots = @()
$script:OurFiles = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
$script:MsiReadErrors = @()

function Test-OurReference {
    # Does this command line / path point at the app? Either inside one of its EXCLUSIVE folders, or at
    # one of its own MSI component files: inside a folder shared with other products, the app's own files
    # are the only evidence that counts (Citrix SSON "owned" all of ICA Client until 2026-09-25).
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

# =====================================================================================================
# The plan
# =====================================================================================================

$script:Items = New-Object System.Collections.Generic.List[object]
$script:ItemKeys = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
$script:Kept = New-Object System.Collections.Generic.List[object]
$script:Warnings = New-Object System.Collections.Generic.List[string]

function Add-PlanItem {
    param(
        [Parameter(Mandatory = $true)] [string] $Category,
        [Parameter(Mandatory = $true)] [int] $Level,
        [Parameter(Mandatory = $true)] [string] $Target,
        [Parameter(Mandatory = $true)] [string] $Action,
        [Parameter(Mandatory = $true)] [string] $Evidence,
        [ValidateSet('low', 'high', 'critical')] [string] $Risk = 'low',
        [string] $Scope = 'machine',
        [switch] $Review,
        [string] $Note,
        [long] $Bytes = -1,
        [object] $Op
    )
    if (-not $script:ItemKeys.Add("$Category|$Target|$Action")) { return $null }
    $group = Get-CategoryGroup $Category
    $item = [pscustomobject][ordered]@{
        id = $script:Items.Count + 1; level = $Level; order = $script:Order[$Category]; category = $Category; group = $group
        scope = $Scope; target = $Target; action = $Action; evidence = $Evidence; risk = $Risk
        review = [bool]$Review; optIn = ([bool]$Review -or $group -eq 'UserData'); note = $Note
        bytes = $(if ($Bytes -ge 0) { $Bytes } else { $null }); op = $Op
    }
    $script:Items.Add($item)
    return $item
}

function Get-KeyAppReference {
    # Does anything in this key tree point at the app? Its folders or MSI files (Test-OurReference) or its
    # ProductCode, in any string value. Bounded: 4 levels, 3,000 values. Returns the evidence, or $null.
    param([string] $Hive, [string] $Path, [string] $ProductCode)
    $seen = 0
    $stack = New-Object System.Collections.Generic.Stack[object]
    $stack.Push(@($Path, 0))
    while ($stack.Count) {
        $cur = $stack.Pop()
        $k = Open-Key $Hive $cur[0]
        if (-not $k) { continue }
        try {
            foreach ($vn in (Get-ValueNamesSafe $k)) {
                if (++$seen -gt 3000) { return $null }
                foreach ($s in @(Get-ValueSafe $k $vn)) {
                    if ($s -isnot [string] -or $s.Length -lt 3) { continue }
                    if (Test-OurReference $s) { return "its value '$(if ($vn) { $vn } else { '(default)' })' points at the app ($s)" }
                    if ($ProductCode -and $s.IndexOf($ProductCode, [StringComparison]::OrdinalIgnoreCase) -ge 0) { return "its value '$(if ($vn) { $vn } else { '(default)' })' names the app's ProductCode" }
                }
            }
            if ($cur[1] -lt 4) { foreach ($sub in (Get-SubKeyNamesSafe $k)) { $stack.Push(@("$($cur[0])\$sub", ($cur[1] + 1))) } }
        } finally { Close-Key $k }
    }
    return $null
}

function Get-ProcessAncestry {
    # This process and every process above it. Never "the app's running program", even when it runs
    # from the app's folder: Git Bash cleaning up Git would otherwise stop the operator's own shell
    # (review 2026-09-26). Returned with a comma: assign it, don't wrap it in @().
    $ids = New-Object 'System.Collections.Generic.HashSet[int]'
    $parent = @{}
    try { foreach ($p in @(Get-CimInstance Win32_Process -Property ProcessId, ParentProcessId -ErrorAction Stop)) { $parent[[int]$p.ProcessId] = [int]$p.ParentProcessId } } catch { }
    $cur = $PID
    for ($n = 0; $n -lt 64 -and $cur -gt 0 -and $ids.Add($cur); $n++) { if (-not $parent.ContainsKey($cur)) { break }; $cur = $parent[$cur] }
    return , $ids
}

function Test-PlannedTarget {
    # Already in the plan (a profile item must not duplicate what identity or the keyword found).
    param([string] $Target)
    foreach ($i in $script:Items) { if ($i.target -eq $Target) { return $true } }
    return $false
}

# Registry areas a profile may never name: Windows' own keys, all COM/installer registration, the whole
# 32-bit mirror (a profile says View = 32 instead), and the hives that are not software at all.
$script:ProtectedRegistry = '^(?i)(SOFTWARE\\(Microsoft|Policies|Classes|RegisteredApplications|Clients|WOW6432Node)(\\|$)|SOFTWARE\\?$|SYSTEM|SAM|SECURITY|HARDWARE|BCD00000000)'

function Add-Kept {
    param([string] $Path, [string] $Reason)
    foreach ($k in $script:Kept) { if ($k.path -eq $Path -and $k.reason -eq $Reason) { return } }
    $script:Kept.Add([pscustomobject][ordered]@{ path = $Path; reason = $Reason })
}

function New-RegOp {
    param([string] $Kind, [string] $Hive, [string] $Path, [string] $ValueName, [string] $Entry, [string] $Separator, [switch] $DeleteKeyIfEmpty, [switch] $Optional, [hashtable] $Expect, [string] $SetKind, [object] $SetData,
        [string] $Floor, [string] $FloorMatch)
    $op = [ordered]@{ kind = $Kind; hive = $Hive; path = $Path }
    if ($PSBoundParameters.ContainsKey('ValueName')) { $op.name = $ValueName }
    if ($Entry) { $op.entry = $Entry }
    if ($Separator) { $op.separator = $Separator }
    if ($Floor) { $op.floor = $Floor; $op.floorMatch = $FloorMatch }
    if ($DeleteKeyIfEmpty) { $op.deleteKeyIfEmpty = $true }
    if ($Optional) { $op.optional = $true }
    if ($Expect) { $op.expect = $Expect }
    if ($SetKind) { $op.setKind = $SetKind; $op.setData = $SetData }
    return $op
}

function Import-AppProfile {
    # profiles\*.psd1 next to the script, plus any -ProfilePath. A broken profile stops the run (exit 3):
    # silently skipping reviewed knowledge would make the report look complete when it isn't.
    param([string[]] $Extra)
    $files = @()
    $dir = Join-Path (Split-Path $script:ScriptPath -Parent) 'profiles'
    if (Test-Path -LiteralPath $dir) { $files += @(Get-ChildItem -LiteralPath $dir -Filter '*.psd1' -File | ForEach-Object { $_.FullName }) }
    foreach ($e in @($Extra | Where-Object { $_ })) {
        if (-not (Test-Path -LiteralPath $e -PathType Leaf)) { throw "no profile file at $e" }
        $files += (Resolve-Path -LiteralPath $e).Path
    }
    $kinds = @('MachineRegistryKey', 'MachineFolder', 'Service', 'UserRegistryKey', 'UserPath')
    foreach ($f in @($files | Select-Object -Unique)) {
        $d = Import-PowerShellDataFile -LiteralPath $f
        foreach ($need in @('Name', 'Match', 'Items')) { if (-not $d.ContainsKey($need)) { throw "${f} has no $need" } }
        if (-not ($d.Match -is [hashtable]) -or -not @($d.Match.Keys | Where-Object { $_ -in @('DisplayName', 'Publisher', 'ProductCode') }).Count) { throw "${f}: Match needs DisplayName, Publisher or ProductCode" }
        foreach ($it in @($d.Items)) {
            if (-not ($it -is [hashtable]) -or -not $it.ContainsKey('Kind') -or -not $it.ContainsKey('Why')) { throw "${f}: every item needs Kind and Why" }
            if ($kinds -notcontains $it.Kind) { throw "${f}: unknown item kind '$($it.Kind)'" }
            if ($it.Kind -eq 'Service') { if (-not $it.ContainsKey('Name')) { throw "${f}: a Service item needs Name" } }
            elseif (-not $it.ContainsKey('Path')) { throw "${f}: a $($it.Kind) item needs Path" }
        }
        [pscustomobject]@{ File = $f; Data = $d }
    }
}

function New-KillItWithFirePlan {
    # Discovery. Read-only. Returns @{ Code; Plan } where Code 0 = plan built, 2 = refused / ambiguous,
    # 3 = not found / bad input. Writes nothing.
    param([string] $AppName, [string] $AppProductCode, [string] $AppUpgradeCode, [string] $AppKeyword, [scriptblock] $Say, [object[]] $AppProfiles)
    if (-not $Say) { $Say = { param($m) } }
    $script:Items.Clear(); $script:ItemKeys.Clear(); $script:Kept.Clear(); $script:Warnings.Clear(); $script:Unreadable = @{}; $script:InfUsers = $null
    $script:OurFiles.Clear(); $script:MatchRoots = @(); $script:MsiReadErrors = @()
    $runId = (Get-Date -Format 'yyyyMMdd-HHmmss') + '-' + ([guid]::NewGuid().ToString('N').Substring(0, 6))

    $loadedSids = Get-LoadedUserSids
    $profiles = Get-Profiles $loadedSids
    $entries = Get-UninstallEntries $loadedSids

    # ---------------------------------------------------------------- the target
    $matched = @()
    if ($AppName) {
        $matched = @($entries | Where-Object { $_.DisplayName -and $_.DisplayName.Equals($AppName.Trim(), [StringComparison]::OrdinalIgnoreCase) })
        if ($matched.Count -eq 0) {
            $near = @($entries | Where-Object { $_.DisplayName -and $_.DisplayName.IndexOf($AppName.Trim(), [StringComparison]::OrdinalIgnoreCase) -ge 0 } | Select-Object -First 10 | ForEach-Object { $_.DisplayName })
            return @{ Code = 3; Message = "No installed app is named exactly '$AppName'. Run with -List to see names."; Near = $near }
        }
    } elseif ($AppProductCode) {
        if (-not (Test-IsGuid $AppProductCode)) { return @{ Code = 3; Message = "Not a GUID: $AppProductCode" } }
        $pcIn = '{' + $AppProductCode.Trim().Trim('{', '}').ToUpperInvariant() + '}'
        $matched = @($entries | Where-Object { $_.ProductCode -eq $pcIn })
        if ($matched.Count -eq 0) {
            # No uninstall entry left is a normal state for a broken app: work from the Installer
            # registration alone. The refusal is RE-CHECKED once the real publisher is known.
            $matched = @([pscustomobject]@{
                    Hive = 'HKLM64'; Sid = $null; KeyPath = $null; Display = $null; KeyName = $pcIn; DisplayName = $null
                    DisplayVersion = $null; Publisher = ''; InstallLocation = $null; UninstallString = $null
                    QuietUninstallString = $null; DisplayIcon = $null; SystemComponent = $false; IsMsi = $true; ProductCode = $pcIn
                })
            $script:Warnings.Add("No uninstall entry exists for $pcIn; working from its Windows Installer registration only.")
        }
    } elseif ($AppUpgradeCode) {
        if (-not (Test-IsGuid $AppUpgradeCode)) { return @{ Code = 3; Message = "Not a GUID: $AppUpgradeCode" } }
        $packedUc = ConvertTo-PackedGuid $AppUpgradeCode
        $pcs = @()
        foreach ($src in @(@{ H = 'HKLM64'; P = "SOFTWARE\Classes\Installer\UpgradeCodes\$packedUc" })) {
            $uk = Open-Key $src.H $src.P
            $pcs += @(Get-ValueNamesSafe $uk | Where-Object { $_ } | ForEach-Object { ConvertFrom-PackedGuid $_ } | Where-Object { $_ })
            Close-Key $uk
        }
        foreach ($sid in $loadedSids) {
            $uk = Open-Key 'HKU' "$sid\Software\Microsoft\Installer\UpgradeCodes\$packedUc"
            $pcs += @(Get-ValueNamesSafe $uk | Where-Object { $_ } | ForEach-Object { ConvertFrom-PackedGuid $_ } | Where-Object { $_ })
            Close-Key $uk
        }
        $matched = @($entries | Where-Object { $_.ProductCode -and ($pcs -contains $_.ProductCode) })
        if ($matched.Count -eq 0) { return @{ Code = 3; Message = "No installed product is registered under UpgradeCode $AppUpgradeCode." } }
    } else {
        return @{ Code = 3; Message = 'Name the app: -Name, -ProductCode or -UpgradeCode (or -List to see names).' }
    }
    $distinct = @($matched | ForEach-Object {
            if ($_.ProductCode) { $_.ProductCode } else { ((Get-EntryPaths $_) -join '|') + '|' + $_.DisplayName }
        } | Select-Object -Unique)
    if ($distinct.Count -gt 1) {
        return @{ Code = 2; Message = 'More than one installed product matches. Pick one with -ProductCode.'; Candidates = @($matched | ForEach-Object { "$($_.DisplayName)  $($_.DisplayVersion)  $($_.ProductCode)  [$($_.Display)]" }) }
    }
    $primary = $matched[0]
    $targetName = if ($primary.DisplayName) { $primary.DisplayName } else { $primary.ProductCode }
    $publisher = $primary.Publisher
    & $Say "Kill It With Fire $script:ToolVersion - scanning '$targetName' (read-only)"

    $refusal = Get-RefusalReason $publisher $targetName $null
    if ($refusal) {
        # Refused on its face (publisher or name): don't even read the rest.
        return @{ Code = 2; Message = "REFUSED: $refusal"; Plan = [ordered]@{
                tool = 'KillItWithFire'; version = $script:ToolVersion; runId = $runId; computer = $env:COMPUTERNAME; generatedUtc = (Get-Date).ToUniversalTime().ToString('o')
                level = 0; refused = $refusal
                target = [ordered]@{ displayName = $targetName; version = $primary.DisplayVersion; publisher = $publisher; productCode = $primary.ProductCode; upgradeCode = $null
                    isMsi = [bool]$primary.IsMsi; uninstallEntries = @($matched | ForEach-Object { $_.Display } | Where-Object { $_ }); uninstallString = $primary.UninstallString
                    quietUninstallString = $primary.QuietUninstallString; cachedMsi = $null; cachedMsiPresent = $false }
            }
        }
    }

    # ---------------------------------------------------------------- identity: Windows Installer
    $pc = $primary.ProductCode
    $isMsi = [bool]$primary.IsMsi
    $packedPc = $null; $upgradeCodeFound = $null; $localPackage = $null; $localPackageExists = $false
    $msiServiceNames = @(); $msiFileNames = @(); $msiFileCount = 0; $msiRegRows = @(); $msiComponentMap = @{}
    $ourComponents = @(); $componentIndex = $null
    $msiRegistration = @(); $offlineUserInstalls = @()
    $installSids = @('S-1-5-18') + @($loadedSids)
    if ($pc -and (Test-IsGuid $pc)) {
        $packedPc = ConvertTo-PackedGuid $pc
        & $Say '  reading Windows Installer registration...'
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
            if (-not $pk) { continue }
            if ($installSids -notcontains $sid) {
                # A signed-out user's per-user install: its HKCU half can't be reached, so none of it is
                # planned (review 2026-09-26: the machine half alone left the user half dangling).
                $offlineUserInstalls += $sid
                Close-Key $pk
                continue
            }
            $msiRegistration += [pscustomobject]@{ Hive = 'HKLM64'; Path = $prodPath; What = "UserData product ($sid)" }
            $ip = Open-Key 'HKLM64' "$prodPath\InstallProperties"
            $lp = [string](Get-ValueSafe $ip 'LocalPackage')
            if ($lp) { $localPackage = $lp; $localPackageExists = (Test-Path -LiteralPath $lp -PathType Leaf) }
            if (-not $primary.InstallLocation) { $il = [string](Get-ValueSafe $ip 'InstallLocation'); if ($il) { $primary.InstallLocation = $il } }
            if (-not $publisher) { $publisher = ([string](Get-ValueSafe $ip 'Publisher')).Trim() }
            if (-not $primary.DisplayName) { $dn = [string](Get-ValueSafe $ip 'DisplayName'); if ($dn) { $targetName = $dn; $primary.DisplayName = $dn } }
            Close-Key $ip
            $patches = Open-Key 'HKLM64' "$prodPath\Patches"
            foreach ($patch in (Get-SubKeyNamesSafe $patches)) {
                $msiRegistration += [pscustomobject]@{ Hive = 'HKLM64'; Path = "SOFTWARE\Classes\Installer\Patches\$patch"; What = 'patch'; Patch = $patch }
            }
            Close-Key $patches
            Close-Key $pk
        }
        Close-Key $ud
        $managed = Open-Key 'HKLM64' 'SOFTWARE\Microsoft\Windows\CurrentVersion\Installer\Managed'
        foreach ($sid in (Get-SubKeyNamesSafe $managed)) {
            foreach ($sub in @('Products', 'Features')) {
                $mp = "SOFTWARE\Microsoft\Windows\CurrentVersion\Installer\Managed\$sid\Installer\$sub\$packedPc"
                $mk = Open-Key 'HKLM64' $mp
                if ($mk) { $msiRegistration += [pscustomobject]@{ Hive = 'HKLM64'; Path = $mp; What = "managed per-user $($sub.ToLowerInvariant()) ($sid)" }; Close-Key $mk }
            }
        }
        Close-Key $managed
        foreach ($sid in $loadedSids) {
            foreach ($sub in @('Products', 'Features')) {
                $up = "$sid\Software\Microsoft\Installer\$sub\$packedPc"
                $uk = Open-Key 'HKU' $up
                if ($uk) { $msiRegistration += [pscustomobject]@{ Hive = 'HKU'; Path = $up; What = "per-user $($sub.ToLowerInvariant())" }; Close-Key $uk }
            }
        }
        # UpgradeCode: machine, managed and loaded users' keys whose values include our packed ProductCode.
        $ucSources = @(@{ H = 'HKLM64'; P = 'SOFTWARE\Classes\Installer\UpgradeCodes' })
        foreach ($sid in $loadedSids) { $ucSources += @{ H = 'HKU'; P = "$sid\Software\Microsoft\Installer\UpgradeCodes" } }
        $managed = Open-Key 'HKLM64' 'SOFTWARE\Microsoft\Windows\CurrentVersion\Installer\Managed'
        foreach ($sid in (Get-SubKeyNamesSafe $managed)) { $ucSources += @{ H = 'HKLM64'; P = "SOFTWARE\Microsoft\Windows\CurrentVersion\Installer\Managed\$sid\Installer\UpgradeCodes" } }
        Close-Key $managed
        foreach ($src in $ucSources) {
            $ucRoot = Open-Key $src.H $src.P
            foreach ($uc in (Get-SubKeyNamesSafe $ucRoot)) {
                $uk = $null
                try { $uk = $ucRoot.OpenSubKey($uc, $false) } catch { continue }
                if ($uk) {
                    if ((Get-ValueNamesSafe $uk) -contains $packedPc) {
                        $upgradeCodeFound = ConvertFrom-PackedGuid $uc
                        $others = @(Get-ValueNamesSafe $uk | Where-Object { $_ -and $_ -ne $packedPc })
                        $msiRegistration += [pscustomobject]@{ Hive = $src.H; Path = "$($src.P)\$uc"; What = "upgrade code (other products under it: $($others.Count))" }
                    }
                    Close-Key $uk
                }
            }
            Close-Key $ucRoot
        }
        # WiX dependency providers that name this product (a leftover one can block a reinstall).
        $dep = Open-Key 'HKLM64' 'SOFTWARE\Classes\Installer\Dependencies'
        foreach ($d in (Get-SubKeyNamesSafe $dep)) {
            $dk = $null; try { $dk = $dep.OpenSubKey($d, $false) } catch { continue }
            $def = [string](Get-ValueSafe $dk '')
            Close-Key $dk
            if (($def -and $def.Equals($pc, [StringComparison]::OrdinalIgnoreCase)) -or $d.Equals($pc, [StringComparison]::OrdinalIgnoreCase)) {
                $msiRegistration += [pscustomobject]@{ Hive = 'HKLM64'; Path = "SOFTWARE\Classes\Installer\Dependencies\$d"; What = 'dependency provider' }
            }
        }
        Close-Key $dep

        # A non-MSI app can use a GUID as its uninstall key name: it is only treated as an MSI product
        # when Windows Installer actually knows it (or the entry says WindowsInstaller=1).
        $isMsi = [bool]($primary.IsMsi -or @($msiRegistration | Where-Object { $_.What -notlike 'dependency*' }).Count -gt 0)
        if ($isMsi) {
            & $Say '  indexing Windows Installer components (one pass; can take a minute)...'
            $componentIndex = Get-MsiComponentIndex $packedPc
            # .ToArray(), never @(): PowerShell 7.6 throws "Argument types do not match" on @() over a List.
            $ourComponents = @($componentIndex.Ours.ToArray() | Where-Object { $installSids -contains $_.Sid })
        }

        if ($localPackage -and $localPackageExists) {
            & $Say '  reading the cached MSI tables...'
            $rows = Get-MsiTableRows $localPackage 'SELECT `Name` FROM `ServiceInstall`' 1
            $msiServiceNames = @($rows | ForEach-Object { $_[0] } | Where-Object { $_ } | Select-Object -Unique)
            $rows = Get-MsiTableRows $localPackage 'SELECT `FileName` FROM `File`' 1
            $msiFileCount = @($rows).Count
            $msiFileNames = @($rows | ForEach-Object { $n = $_[0]; if ($n -match '\|') { $n.Split('|')[1] } else { $n } } | ForEach-Object { $_.ToLowerInvariant() } | Select-Object -Unique)
            $rows = Get-MsiTableRows $localPackage 'SELECT `Component`, `ComponentId`, `Attributes` FROM `Component`' 3
            foreach ($r in $rows) { if ($r[1]) { $msiComponentMap[$r[0]] = @{ Id = $r[1]; Is64 = (([int](0 + $r[2])) -band 256) -ne 0 } } }
            $msiRegRows = Get-MsiTableRows $localPackage 'SELECT `Root`, `Key`, `Name`, `Component_` FROM `Registry`' 4
        }
    }

    # ---------------------------------------------------------------- identity: protected folders
    $treeProtected = @($env:SystemRoot, (Join-Path $env:ProgramData 'Microsoft'), (Join-Path $env:SystemDrive 'Recovery'),
        (Join-Path $env:SystemDrive 'System Volume Information'), (Join-Path $env:SystemDrive '$Recycle.Bin'), $env:PUBLIC,
        (Join-Path $env:SystemDrive 'Users\Default'))
    $containerProtected = @($env:ProgramFiles, ${env:ProgramFiles(x86)}, $env:ProgramW6432, $env:CommonProgramFiles, ${env:CommonProgramFiles(x86)},
        $env:CommonProgramW6432, $env:ProgramData, (Join-Path $env:SystemDrive 'Users'), (Join-Path $env:ProgramData 'Package Cache'))
    foreach ($pr in $profiles) {
        $containerProtected += $pr.Path
        foreach ($sub in @('AppData', 'AppData\Local', 'AppData\LocalLow', 'AppData\Roaming', 'AppData\Local\Programs', 'AppData\Local\Temp')) {
            $containerProtected += (Join-Path $pr.Path $sub)
        }
        foreach ($sub in @('Desktop', 'Documents', 'Downloads', 'Pictures', 'Music', 'Videos', 'Favorites', 'Contacts', 'Links', 'Saved Games', 'Searches',
                'AppData\Local\Microsoft', 'AppData\Roaming\Microsoft', 'AppData\LocalLow\Microsoft', 'AppData\Local\Packages')) {
            $treeProtected += (Join-Path $pr.Path $sub)
        }
        foreach ($d in @(Get-ChildItem -LiteralPath $pr.Path -Directory -Force -Filter 'OneDrive*' -ErrorAction SilentlyContinue)) { $treeProtected += $d.FullName }
        $treeProtected += @($pr.ShellFolders)
    }
    # Kill It With Fire's own folders: its runs (backups and quarantine), the per-drive quarantines, and the folder
    # the script runs from. Under the tool's first name, a lab app named "Leftovers ... Test" derived the keyword
    # "Leftovers", matched C:\ProgramData\Leftovers, and the run tried to quarantine its own backups (2026-09-26).
    # The lab apps are now "KillItWithFire ... Test", so the keyword still equals the folder name.
    $treeProtected += @(Get-KillItWithFireOwnFolders)
    foreach ($svcName in @('RFFAgent', 'RFFUpdater')) {
        $sk = Open-Key 'HKLM64' "SYSTEM\CurrentControlSet\Services\$svcName"
        if ($sk) {
            $exe = Resolve-ServiceImagePath ([string](Get-ValueSafe $sk 'ImagePath')) $svcName 16
            if ($exe) { $treeProtected += (Split-Path $exe -Parent) }
            Close-Key $sk
        }
    }

    # ---------------------------------------------------------------- identity: roots
    $otherEntries = @($entries | Where-Object { $matched -notcontains $_ -and $_.DisplayName -and -not ($pc -and $_.ProductCode -eq $pc) })
    # A List, not +=: Epic Games Launcher adds 4,400 candidates (one per MSI component).
    $rootCandidates = New-Object System.Collections.Generic.List[object]
    foreach ($m in $matched) {
        foreach ($p in (Get-EntryPaths $m)) {
            $rootCandidates.Add([pscustomobject]@{ Path = $p; Why = "uninstall entry ($($m.Display))" })
            if ((Split-Path $p -Leaf) -match '^\d+(\.\d+){1,3}$') {
                $rootCandidates.Add([pscustomobject]@{ Path = (Split-Path $p -Parent); Why = "parent of the versioned folder $p" })
            }
        }
    }
    $identityFiles = @()
    $componentRegValues = @()
    # Every folder holding one of the app's MSI components, shared or not: what "the app's own folders" means
    # when a root has to be split (below).
    $ourCompDirs = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
    # One protected-folder verdict per folder, not per component: 4,400 components live in a few hundred folders.
    $protMemo = @{}
    $ourFileComponent = @{}
    $sharedDllKeys = @((Open-Key 'HKLM64' 'SOFTWARE\Microsoft\Windows\CurrentVersion\SharedDLLs'), (Open-Key 'HKLM32' 'SOFTWARE\Microsoft\Windows\CurrentVersion\SharedDLLs'))
    foreach ($c in $ourComponents) {
        $kp = ConvertFrom-MsiKeyPath $c.KeyPath
        if ($null -eq $kp) { continue }
        if ($kp.Kind -eq 'File') { [void]$ourCompDirs.Add($(if ($kp.IsFolder) { $kp.Path } else { Split-Path $kp.Path -Parent })) }
        # Registry-keyed components get the same shared-client check as files (review 2026-09-26).
        if (@(Get-OtherComponentClients $componentIndex $c.Component $packedPc).Count -gt 0) { continue }
        if ($kp.Kind -eq 'File') {
            if (-not $kp.IsFolder) {
                # A SharedDLLs count above 1 means some other installer still counts on this file.
                $shared = 0
                foreach ($sk in $sharedDllKeys) { $n = [int](0 + (Get-ValueSafe $sk $kp.Path)); if ($n -gt $shared) { $shared = $n } }
                if ($shared -gt 1) { Add-Kept $kp.Path "SharedDLLs count ${shared}: another installer still counts on it"; continue }
                [void]$script:OurFiles.Add($kp.Path)
                $ourFileComponent[$kp.Path] = $c.Component
            }
            $dir = if ($kp.IsFolder) { $kp.Path } else { Split-Path $kp.Path -Parent }
            if (-not $protMemo.ContainsKey($dir)) { $protMemo[$dir] = Get-ProtectedPathReason $dir $containerProtected $treeProtected }
            if (-not $protMemo[$dir]) {
                $rootCandidates.Add([pscustomobject]@{ Path = $dir; Why = "MSI component $($c.Component)" })
            } elseif (-not $kp.IsFolder -and (Test-Path -LiteralPath $kp.Path -PathType Leaf)) {
                $identityFiles += [pscustomobject]@{ Path = $kp.Path; Component = $c.Component }
            }
        } elseif ($kp.Kind -eq 'Registry') {
            $componentRegValues += [pscustomobject]@{ Kp = $kp; Sid = $c.Sid; Component = $c.Component }
        }
    }
    foreach ($sk in $sharedDllKeys) { Close-Key $sk }

    $roots = @(); $refusedRoots = @()
    $rootSet = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
    $seenCand = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
    foreach ($cand in ($rootCandidates | Sort-Object { $_.Path.Length })) {
        $n = Get-NormalizedPath $cand.Path
        if (-not $n) { continue }
        # The same folder again: decided already, the first time (as a root, or as refused).
        if (-not $seenCand.Add($n)) { continue }
        # Inside a root already taken? Its parents, walked up: not every root against every candidate.
        $a = $n; $inside = $false
        while ($a) { if ($rootSet.Contains($a)) { $inside = $true; break }; $a = Get-ParentPath $a }
        if ($inside) { continue }
        if (-not $protMemo.ContainsKey($n)) { $protMemo[$n] = Get-ProtectedPathReason $n $containerProtected $treeProtected }
        $why = $protMemo[$n]
        if ($why) {
            if (-not ($refusedRoots | Where-Object { $_.Path -eq $n })) { $refusedRoots += [pscustomobject]@{ Path = $n; Why = $why; From = $cand.Why } }
            continue
        }
        $roots += [pscustomobject]@{ Path = $n; Why = $cand.Why; Exists = (Test-Path -LiteralPath $n -PathType Container); Shared = $false; SharedWhy = $null }
        [void]$rootSet.Add($n)
    }

    # ---------------------------------------------------------------- a root that also holds other programs
    # An MSI app's uninstall entry can name its VENDOR folder. Epic Games Launcher's InstallLocation is
    # C:\Program Files\Epic Games, which also holds Unreal Engine (UE_5.7) and the games the launcher
    # installed, none of them registered as products. A full scrub would have quarantined all of it, and
    # Unreal Editor's shortcut and firewall rules were planned as the launcher's (dev machine, 2026-10-04).
    # When the app's own folders are known (its MSI components), such a root is split: the subfolders that
    # hold the app's components become the roots, and the folder itself stays with the other program in it.
    if ($ourCompDirs.Count) {
        $split = @()
        foreach ($r in @($roots)) {
            if (-not $r.Exists -or $r.Why -like 'MSI component*') { continue }
            # Which of its subfolders hold a component of ours, and are any of ours right in it?
            $withOurs = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
            foreach ($d in $ourCompDirs) {
                $dn = Get-NormalizedPath $d
                if (-not $dn -or -not $dn.StartsWith($r.Path.TrimEnd('\') + '\', [StringComparison]::OrdinalIgnoreCase)) { continue }
                $rest = $dn.Substring($r.Path.TrimEnd('\').Length + 1)
                [void]$withOurs.Add((Join-Path $r.Path ($rest.Split('\')[0])))
            }
            $foreign = @()
            foreach ($child in @(Get-ChildItem -LiteralPath $r.Path -Directory -Force -ErrorAction SilentlyContinue)) {
                if ($withOurs.Contains($child.FullName)) { continue }
                if (Test-HoldsProgramFiles $child.FullName) { $foreign += $child.FullName }
            }
            if (-not $foreign.Count) { continue }
            $split += [pscustomobject]@{ Root = $r; Ours = @($withOurs); Foreign = $foreign }
        }
        foreach ($s in $split) {
            $roots = @($roots | Where-Object { $_ -ne $s.Root })
            [void]$rootSet.Remove($s.Root.Path)
            foreach ($f in $s.Foreign) { Add-Kept $f "another program's folder in $($s.Root.Path): it holds programs and none of this app's components" }
            $names = @($s.Foreign | ForEach-Object { Split-Path $_ -Leaf }) -join ', '
            foreach ($o in $s.Ours) {
                if (-not (Test-Path -LiteralPath $o -PathType Container)) { continue }
                if (-not $protMemo.ContainsKey($o)) { $protMemo[$o] = Get-ProtectedPathReason $o $containerProtected $treeProtected }
                if ($protMemo[$o]) { continue }
                $roots += [pscustomobject]@{ Path = $o; Why = "$($s.Root.Why), narrowed to the app's own folder ($($s.Root.Path) also holds $names)"; Exists = $true; Shared = $false; SharedWhy = $null }
                [void]$rootSet.Add($o)
            }
            # The app's own files sitting right in the split folder still go, one by one.
            foreach ($f in $script:OurFiles) {
                if ((Split-Path $f -Parent) -eq $s.Root.Path -and (Test-Path -LiteralPath $f -PathType Leaf)) { $identityFiles += [pscustomobject]@{ Path = $f; Component = $ourFileComponent[$f] } }
            }
            $script:Warnings.Add("$($s.Root.Path) also holds other programs ($names), so it stays: only the app's own folder(s) in it go ($(@($s.Ours | ForEach-Object { Split-Path $_ -Leaf }) -join ', ')).")
        }
    }
    # An app installed by an EXE has no component list, so the split above can't run, and anything else in
    # its folder goes with it. Say so when the folder looks like a container of programs: no program file of
    # its own at the top, and programs in two or more subfolders (how Epic's vendor folder looks).
    if (-not $ourCompDirs.Count) {
        foreach ($r in @($roots | Where-Object { $_.Exists -and $_.Why -notlike 'MSI component*' })) {
            $progDirs = @(Get-ProgramContainerSubfolders $r.Path)
            if (-not $progDirs.Count) { continue }
            $script:Warnings.Add("$($r.Path) has no program files of its own, only subfolders with programs ($(@($progDirs | Select-Object -First 4) -join ', ')): it may be a vendor folder holding other programs too. This app was not installed from an MSI, so the scan can't tell which subfolders are its own, and a full scrub takes the whole folder. Check the Files items (View items) first.")
        }
    }

    # ---------------------------------------------------------------- cross-reference, BEFORE discovery
    foreach ($o in $otherEntries) {
        foreach ($p in (Get-EntryPaths $o)) {
            foreach ($r in $roots) {
                if (Test-PathUnder $p $r.Path) { Add-Kept $p "the uninstall entry of '$($o.DisplayName)' points here" }
                elseif (Test-PathUnder $r.Path $p) {
                    # Our folder sits INSIDE another product's folder (a plugin MSI in KeePass\Plugins):
                    # the folder is shared (review 2026-09-26: this used to be a warning only).
                    $r.Shared = $true; $r.SharedWhy = "inside the folder of '$($o.DisplayName)' ($p)"
                }
            }
        }
    }
    if ($componentIndex -and $roots.Count) {
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
    foreach ($r in $roots) {
        if (-not $r.Shared -and @($script:Kept | Where-Object { Test-PathUnder $_.path $r.Path }).Count -gt 0) { $r.Shared = $true; $r.SharedWhy = 'other products own files in it' }
    }
    $rootPaths = @($roots | ForEach-Object { $_.Path })
    $exclusiveRoots = @($roots | Where-Object { -not $_.Shared } | ForEach-Object { $_.Path })
    $script:MatchRoots = @($exclusiveRoots)
    foreach ($r in $exclusiveRoots) { $s = Get-ShortPathSafe $r; if ($s) { $script:MatchRoots += $s } }
    foreach ($r in $roots | Where-Object { $_.Shared }) {
        $script:Warnings.Add("$($r.Path) is SHARED ($($r.SharedWhy)): inside it only this app's own $($script:OurFiles.Count) MSI file(s) are matched, and the folder stays.")
    }

    # ---------------------------------------------------------------- identity: signer (+ the refusal, again)
    $signerOrg = $null; $signerFiles = @()
    $probe = @()
    foreach ($m in $matched) {
        foreach ($cmd in @($m.UninstallString, $m.QuietUninstallString)) { $e = Get-CommandExePath $cmd; if ($e -and (Test-OurReference $e)) { $probe += $e } }
        if ($m.DisplayIcon) { $i = Get-NormalizedPath ($m.DisplayIcon -replace ',\s*-?\d+\s*$', ''); if ($i -and $i -match '\.exe$' -and (Test-OurReference $i)) { $probe += $i } }
    }
    $probe += @($script:OurFiles | Where-Object { $_ -match '\.exe$' } | Select-Object -First 5)
    foreach ($r in $roots | Where-Object { $_.Exists -and -not $_.Shared }) {
        try { $probe += @(Get-ChildItem -LiteralPath $r.Path -Filter *.exe -File -ErrorAction SilentlyContinue | Sort-Object Length -Descending | Select-Object -First 3 | ForEach-Object { $_.FullName }) } catch { }
    }
    $orgCounts = @{}
    foreach ($f in ($probe | Where-Object { $_ -and (Test-Path -LiteralPath $_ -PathType Leaf) } | Select-Object -Unique)) {
        $org = Get-SignerOrg (Get-SignerSubject $f)
        if ($org) { $signerFiles += "$f ($org)"; if ($orgCounts.ContainsKey($org)) { $orgCounts[$org]++ } else { $orgCounts[$org] = 1 } }
    }
    $signerOrg = Select-SignerOrg $orgCounts
    if (-not $refusal) { $refusal = Get-RefusalReason $publisher $targetName $signerOrg }
    $samePublisherOthers = @($entries | Where-Object { $_.Publisher -and $publisher -and $_.Publisher.Equals($publisher, [StringComparison]::OrdinalIgnoreCase) -and $matched -notcontains $_ -and ($_.ProductCode -ne $pc -or -not $pc) } | ForEach-Object { $_.DisplayName } | Select-Object -Unique)

    $target = [ordered]@{
        displayName = $targetName; version = $primary.DisplayVersion; publisher = $publisher
        productCode = $pc; upgradeCode = $upgradeCodeFound; isMsi = $isMsi
        uninstallEntries = @($matched | ForEach-Object { $_.Display } | Where-Object { $_ })
        uninstallString = $primary.UninstallString; quietUninstallString = $primary.QuietUninstallString
        cachedMsi = $localPackage; cachedMsiPresent = $localPackageExists
        # Level 1 needs these: NSIS runs in place from InstallLocation, and a per-user entry's uninstaller
        # is only run by that user (as anyone else it would act on the wrong profile).
        installLocation = $primary.InstallLocation; entryHive = $primary.Hive; entrySid = $primary.Sid; entryKeyPath = $primary.KeyPath
    }
    $planBase = [ordered]@{
        tool = 'KillItWithFire'; version = $script:ToolVersion; runId = $runId; computer = $env:COMPUTERNAME
        generatedUtc = (Get-Date).ToUniversalTime().ToString('o'); level = 0; refused = $null; target = $target
    }
    if ($refusal) {
        $planBase.refused = $refusal
        return @{ Code = 2; Message = "REFUSED: $refusal"; Plan = $planBase }
    }

    & $Say '  scanning services, drivers, device filters, network components...'
    # ---------------------------------------------------------------- devices: which services drive present hardware
    $deviceBound = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
    $enumRoot = Open-Key 'HKLM64' 'SYSTEM\CurrentControlSet\Enum' 'device instances'
    $enumInstances = @()
    foreach ($bus in (Get-SubKeyNamesSafe $enumRoot 'device instances')) {
        $bk = $null; try { $bk = $enumRoot.OpenSubKey($bus, $false) } catch { Add-Unreadable 'device instances'; continue }
        foreach ($dev in (Get-SubKeyNamesSafe $bk 'device instances')) {
            $dk = $null; try { $dk = $bk.OpenSubKey($dev, $false) } catch { Add-Unreadable 'device instances'; continue }
            foreach ($inst in (Get-SubKeyNamesSafe $dk 'device instances')) {
                $ik = $null; try { $ik = $dk.OpenSubKey($inst, $false) } catch { Add-Unreadable 'device instances'; continue }
                if ($null -eq $ik) { continue }
                $svc = [string](Get-ValueSafe $ik 'Service')
                if ($svc) { [void]$deviceBound.Add($svc) }
                $upper = @(Get-ValueSafe $ik 'UpperFilters' | Where-Object { $_ }); $lower = @(Get-ValueSafe $ik 'LowerFilters' | Where-Object { $_ })
                if ($upper.Count -or $lower.Count) {
                    $friendly = [string](Get-ValueSafe $ik 'FriendlyName'); if (-not $friendly) { $friendly = [string](Get-ValueSafe $ik 'DeviceDesc') }
                    $enumInstances += [pscustomobject]@{ Path = "SYSTEM\CurrentControlSet\Enum\$bus\$dev\$inst"; Upper = $upper; Lower = $lower; Friendly = $friendly }
                }
                Close-Key $ik
            }
            Close-Key $dk
        }
        Close-Key $bk
    }
    Close-Key $enumRoot

    # ---------------------------------------------------------------- services and drivers
    $services = @()
    $svcRoot = Open-Key 'HKLM64' 'SYSTEM\CurrentControlSet\Services' 'services'
    foreach ($s in (Get-SubKeyNamesSafe $svcRoot 'services')) {
        $sk = $null
        try { $sk = $svcRoot.OpenSubKey($s, $false) } catch { Add-Unreadable 'services'; continue }
        if ($null -eq $sk) { continue }
        $type = [int](0 + (Get-ValueSafe $sk 'Type'))
        $image = [string]($sk.GetValue('ImagePath', $null, [Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames))
        $pk = $null
        try { $pk = $sk.OpenSubKey('Parameters', $false) } catch { }
        $services += [pscustomobject]@{
            Name = $s; DisplayName = [string](Get-ValueSafe $sk 'DisplayName'); Type = $type
            Start = [int](0 + (Get-ValueSafe $sk 'Start')); ImageRaw = $image
            Image = (Resolve-ServiceImagePath $image $s $type)
            ServiceDll = (Get-NormalizedPath ([string](Get-ValueSafe $pk 'ServiceDll')))
        }
        Close-Key $pk
        Close-Key $sk
    }
    Close-Key $svcRoot
    $otherProductPaths = @($otherEntries | ForEach-Object { Get-EntryPaths $_ } | Where-Object { $_ } | Select-Object -Unique)
    $vendorNames = @(@($signerOrg, $publisher) | Where-Object { $_ -and -not (Test-IsMicrosoftName $_) })
    $ourServices = @()
    foreach ($s in $services) {
        $ev = @(); $weak = $false
        if ($s.ImageRaw -and (Test-OurReference $s.ImageRaw)) { $ev += "runs $($s.ImageRaw)" }
        elseif ($s.Image -and (Test-OurReference $s.Image)) { $ev += "image $($s.Image) points at the app" }
        if ($s.ServiceDll -and (Test-OurReference $s.ServiceDll)) { $ev += "ServiceDll $($s.ServiceDll) points at the app" }
        if ($msiServiceNames -contains $s.Name) { $ev += "the app's MSI installs service '$($s.Name)'" }
        if (-not $ev.Count -and $vendorNames.Count -and -not $samePublisherOthers.Count) {
            # Vendor-only ties are ALWAYS "needs review", never for a boot-start driver, and never for a
            # driver that serves present hardware: a target like "Intel Driver & Support Assistant" would
            # otherwise claim Intel's storage driver (review 2026-09-26). And only when the vendor has
            # nothing else installed: Citrix SSON "claimed" eight drivers of the Citrix products next to it.
            $file = if ($s.ServiceDll) { $s.ServiceDll } else { $s.Image }
            $isDriver = [bool]($s.Type -band 0xB)
            if ($file -and -not (@($otherProductPaths | Where-Object { Test-PathUnder $file $_ }).Count) -and
                -not ($isDriver -and $s.Start -eq 0) -and -not $deviceBound.Contains($s.Name)) {
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
        if ($o.Weak) { [void]$reviewServices.Add($s.Name) }
        $note = if ($o.Weak) { "needs review: tied only by the file's declared vendor$(if ($samePublisherOthers.Count) { ", and $publisher has other products installed" })" } else { $null }
        $quarantineImage = ($isDriver -and $s.Image -and -not (Test-OurReference $s.Image))
        $op = [ordered]@{ kind = 'ServiceDelete'; name = $s.Name; isDriver = $isDriver; bootStart = $boot; image = $s.Image; quarantineImage = $quarantineImage }
        if ($isDriver) {
            $act = if ($boot) { 'set Start=4 and delete on reboot (boot/system-start driver: never removed live)' } else { 'stop, disable, delete driver service' }
            if ($quarantineImage) { $act += '; quarantine its .sys file' }
            [void](Add-PlanItem -Category 'Driver' -Level 3 -Target "driver $($s.Name) ($($s.Image))" -Action $act -Evidence $o.Evidence -Risk $(if ($boot) { 'critical' } else { 'high' }) -Review:$o.Weak -Note $note -Op $op)
        } else {
            [void](Add-PlanItem -Category 'Service' -Level 3 -Target "service $($s.Name) '$($s.DisplayName)'" -Action 'stop, disable, delete service' -Evidence $o.Evidence -Risk $(if ($o.Weak) { 'high' } else { 'low' }) -Review:$o.Weak -Note $note -Op $op)
        }
    }
    foreach ($s in $services) {
        if ($ourServiceNames -contains $s.Name) { continue }
        if ($s.Type -band 0xB -and $vendorNames.Count -and $deviceBound.Contains($s.Name)) {
            $company = Get-VendorOfFile $s.Image
            foreach ($v in $vendorNames) { if ($company -and (Test-SameVendor $company $v)) { $script:Warnings.Add("Driver $($s.Name) is from the same vendor but serves present hardware: not planned."); break } }
        }
    }

    # ---------------------------------------------------------------- the app's own programs still running
    # Tied by image path only (its folder, or one of its own MSI files). Its services are left to the
    # service items, which stop them properly.
    $svcImages = @($ourServices | ForEach-Object { $_.Svc.Image } | Where-Object { $_ })
    $ancestors = Get-ProcessAncestry
    $procGroups = @{}
    foreach ($p in @(Get-Process -ErrorAction SilentlyContinue)) {
        if ($ancestors.Contains($p.Id)) { continue }
        $pp = $null
        try { $pp = $p.Path } catch { }
        if (-not $pp -or ($svcImages -contains $pp) -or -not (Test-OurReference $pp)) { continue }
        if (-not $procGroups.ContainsKey($pp)) { $procGroups[$pp] = 0 }
        $procGroups[$pp]++
    }
    foreach ($pp in $procGroups.Keys) {
        $inWin = Test-PathUnder $pp $env:SystemRoot
        [void](Add-PlanItem -Category 'RunningProcess' -Level 3 -Target "program $pp" -Action "stop it ($($procGroups[$pp]) running now); unsaved work in it is lost, and a restore does not restart it" `
                -Evidence "runs from the app's own folder or files" -Risk 'high' -Review:$inWin -Note $(if ($inWin) { 'needs review: a program under C:\Windows that one MSI claims' } else { $null }) `
                -Op ([ordered]@{ kind = 'ProcessStop'; path = $pp }))
    }

    # ---------------------------------------------------------------- device filters
    if ($ourDriverNames.Count) {
        $classRoot = Open-Key 'HKLM64' 'SYSTEM\CurrentControlSet\Control\Class' 'device classes'
        foreach ($g in (Get-SubKeyNamesSafe $classRoot 'device classes')) {
            $ck = $null
            try { $ck = $classRoot.OpenSubKey($g, $false) } catch { Add-Unreadable 'device classes'; continue }
            if ($null -eq $ck) { continue }
            $className = [string](Get-ValueSafe $ck 'Class')
            foreach ($which in @('UpperFilters', 'LowerFilters')) {
                $vals = @(Get-ValueSafe $ck $which | Where-Object { $_ })
                foreach ($d in $ourDriverNames) {
                    if ($vals -contains $d) {
                        $rest = @($vals | Where-Object { $_ -ne $d })
                        [void](Add-PlanItem -Category 'DeviceClassFilter' -Level 3 -Target "HKLM\SYSTEM\CurrentControlSet\Control\Class\$g [$className] $which" `
                                -Action "remove '$d' from $which BEFORE the driver is deleted; keep: $(if ($rest.Count) { $rest -join ', ' } else { '(nothing else)' })" `
                                -Evidence "the $className class loads our driver '$d' as a filter; leaving it listed stops EVERY $className device at the next boot" -Risk 'critical' `
                                -Review:($reviewServices.Contains($d)) -Note $(if ($reviewServices.Contains($d)) { "needs review: driver '$d' is tied by vendor only" } else { $null }) `
                                -Op (New-RegOp -Kind 'RegRemoveMultiSzEntry' -Hive 'HKLM64' -Path "SYSTEM\CurrentControlSet\Control\Class\$g" -ValueName $which -Entry $d))
                    }
                }
            }
            Close-Key $ck
        }
        Close-Key $classRoot
        foreach ($inst in $enumInstances) {
            foreach ($which in @('UpperFilters', 'LowerFilters')) {
                $vals = if ($which -eq 'UpperFilters') { $inst.Upper } else { $inst.Lower }
                foreach ($d in $ourDriverNames) {
                    if ($vals -contains $d) {
                        [void](Add-PlanItem -Category 'DeviceInstanceFilter' -Level 3 -Target "HKLM\$($inst.Path) $which" `
                                -Action "remove '$d' from $which BEFORE the driver is deleted (needs SYSTEM: Enum keys are read-only to administrators)" `
                                -Evidence "device '$($inst.Friendly)' loads our driver '$d' as a filter; leaving it listed stops that device at the next boot" -Risk 'critical' `
                                -Review:($reviewServices.Contains($d)) -Note $(if ($reviewServices.Contains($d)) { "needs review: driver '$d' is tied by vendor only" } else { $null }) `
                                -Op (New-RegOp -Kind 'RegRemoveMultiSzEntry' -Hive 'HKLM64' -Path $inst.Path -ValueName $which -Entry $d))
                    }
                }
            }
        }
    }

    # ---------------------------------------------------------------- network components, driver packages
    $ourNetComponents = @{}
    if ($ourServiceNames.Count) {
        foreach ($nc in @(@{ G = '{4D36E974-E325-11CE-BFC1-08002BE10318}'; C = 's' }, @{ G = '{4D36E975-E325-11CE-BFC1-08002BE10318}'; C = 'p' }, @{ G = '{4D36E973-E325-11CE-BFC1-08002BE10318}'; C = 'c' })) {
            $nk = Open-Key 'HKLM64' "SYSTEM\CurrentControlSet\Control\Network\$($nc.G)" 'network components'
            foreach ($inst in (Get-SubKeyNamesSafe $nk 'network components')) {
                $ik = $null; try { $ik = $nk.OpenSubKey($inst, $false) } catch { continue }
                if ($null -eq $ik) { continue }
                $cid = [string](Get-ValueSafe $ik 'ComponentId')
                # The INF this component was installed from, as Windows recorded it. It is the one to export
                # and reinstall on restore; matching INF text instead picked whichever oem*.inf mentioning
                # the id sorted last, which can be a stale driver store copy (review 2026-09-29).
                $infPath = [string](Get-ValueSafe $ik 'InfPath')
                $ndi = $null; try { $ndi = $ik.OpenSubKey('Ndi', $false) } catch { }
                $svc = [string](Get-ValueSafe $ndi 'Service')
                if ($cid -and $svc -and ($ourServiceNames -contains $svc)) {
                    $item = Add-PlanItem -Category 'NetworkComponent' -Level 3 -Target "network component $cid (service $svc)" `
                        -Action "netcfg -u $cid (unbinds it cleanly; never delete the service directly)" `
                        -Evidence "network component bound to our service '$svc'" -Risk 'critical' `
                        -Review:($reviewServices.Contains($svc)) -Note $(if ($reviewServices.Contains($svc)) { "needs review: service '$svc' is tied by vendor only" } else { $null }) `
                        -Op ([ordered]@{ kind = 'NetcfgUninstall'; componentId = $cid; netClass = $nc.C; inf = $(if ($infPath -match '^(?i)oem\d+\.inf$') { $infPath } else { $null }) })
                    if ($item) { $ourNetComponents[$cid] = $item }
                }
                Close-Key $ndi; Close-Key $ik
            }
            Close-Key $nk
        }
        $infDir = Join-Path $env:SystemRoot 'INF'
        foreach ($inf in @(Get-ChildItem -LiteralPath $infDir -Filter 'oem*.inf' -File -ErrorAction SilentlyContinue)) {
            $text = $null
            try { $text = [System.IO.File]::ReadAllText($inf.FullName) } catch { Add-Unreadable 'driver packages'; continue }
            $strings = @{}
            foreach ($sec in [regex]::Matches($text, '(?ims)^\s*\[Strings(\.[0-9A-Za-z]+)?\][^\r\n]*\r?\n(.*?)(?=^\s*\[|\z)')) {
                foreach ($l in [regex]::Matches($sec.Groups[2].Value, '(?m)^\s*([^=;\s]+)\s*=\s*"?([^"\r\n;]*)"?')) {
                    if (-not $strings.ContainsKey($l.Groups[1].Value)) { $strings[$l.Groups[1].Value] = $l.Groups[2].Value.Trim() }
                }
            }
            $byCid = $null
            foreach ($cid in $ourNetComponents.Keys) { if ($text -match ('(?i)(?<![A-Za-z0-9_])' + [regex]::Escape($cid) + '(?![A-Za-z0-9_])')) { $byCid = $cid; break } }
            # EVERY service the package installs, not just the first of ours: one package can carry a device's
            # function driver as well as the app's helper service (review 2026-09-29).
            $bySvc = $null; $foreignSvc = @()
            foreach ($m in [regex]::Matches($text, '(?im)^\s*AddService\s*=\s*"?([^",\s]+)')) {
                $svc = $m.Groups[1].Value
                if ($svc -match '^%(.+)%$' -and $strings.ContainsKey($matches[1])) { $svc = $strings[$matches[1]] }
                if ($ourServiceNames -contains $svc) { if (-not $bySvc) { $bySvc = $svc } }
                elseif ($foreignSvc -notcontains $svc) {
                    # Someone else's only if it is actually installed: a real service definition has a
                    # Type. An INF also names services for options never installed here; Npcap's installer
                    # even leaves an npcap_wifi key holding nothing but Start=4 (lab 2026-09-29). Those
                    # belong to no one, and counting them blocked Npcap's own package.
                    $fk = Open-Key 'HKLM64' "SYSTEM\CurrentControlSet\Services\$svc"
                    if ($fk) {
                        $isReal = $null -ne (Get-ValueSafe $fk 'Type')
                        Close-Key $fk
                        if ($isReal) { $foreignSvc += $svc }
                    }
                }
            }
            if ($byCid -or $bySvc) {
                # Only fill in the component's INF when Windows didn't record one (see InfPath above).
                if ($byCid -and -not $ourNetComponents[$byCid].op.inf) { $ourNetComponents[$byCid].op.inf = $inf.Name }
                $key = if ($byCid) { $byCid } else { $bySvc }
                $review = ($byCid -and $ourNetComponents[$byCid].review) -or ($bySvc -and $reviewServices.Contains($bySvc))
                # `pnputil /delete-driver /uninstall` takes the package off every device using it. A package
                # that also installs someone else's service, or that a device other than our own network
                # components is using, is reported and never removed: on a storage or display driver
                # that is a machine that won't boot or shows nothing.
                $users = @(Get-InfDeviceUsers $inf.Name | Where-Object { $ourNetComponents.Keys -notcontains $_ })
                $blocked = @()
                if ($foreignSvc.Count) { $blocked += "it also installs service(s) $($foreignSvc -join ', ')" }
                if ($users.Count) { $blocked += "device(s) use it: $(($users | Select-Object -First 3) -join ', ')" }
                [void](Add-PlanItem -Category 'DriverPackage' -Level 3 -Target "driver package $($inf.Name)" `
                        -Action $(if ($blocked.Count) { "leave it: $($blocked -join '; ')" } else { "pnputil /delete-driver $($inf.Name) /uninstall (exported to the backup first)" }) `
                        -Evidence $(if ($byCid) { "$($inf.Name) installs our network component $byCid" } else { "$($inf.Name) installs our service '$bySvc'" }) -Risk 'high' `
                        -Review:($review -and -not $blocked.Count) -Note $(if ($blocked.Count) { 'not removed: ' + ($blocked -join '; ') } elseif ($review) { "needs review: '$key' is tied by vendor only" } else { $null }) `
                        -Op $(if ($blocked.Count) { $null } else { [ordered]@{ kind = 'DriverPackageDelete'; inf = $inf.Name } }))
            }
        }
    }

    & $Say '  scanning tasks, startup entries, COM, shell and file associations...'
    # ---------------------------------------------------------------- COM (needed before tasks for ComHandler)
    $ourClsids = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
    $ourClassKeys = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
    $appIdUse = @{}
    $comSources = @(@{ Hive = 'HKLM64'; Path = 'SOFTWARE\Classes'; Scope = 'machine' }, @{ Hive = 'HKLM32'; Path = 'SOFTWARE\Classes'; Scope = 'machine (32-bit)' })
    foreach ($sid in $loadedSids) { $comSources += @{ Hive = 'HKU'; Path = "$($sid)_Classes"; Scope = "user:$sid" } }
    $pendingAppIds = @()
    foreach ($src in $comSources) {
        $clsidRoot = Open-Key $src.Hive "$($src.Path)\CLSID" 'COM classes'
        # The registry walk is compiled (KillItWithFire.Fast): opening every class key from PowerShell was 64 s
        # of a 137-second Epic Games Launcher scan (2026-10-04). The test on each value is unchanged.
        $classes = [KillItWithFire.Fast]::ReadComClasses($clsidRoot)
        for ($unr = 0; $unr -lt $classes.Unreadable; $unr++) { Add-Unreadable 'COM classes' }
        foreach ($ci in $classes.Items) {
            $clsid = $ci.Clsid
            $appIdOfClass = [string]$ci.AppId
            $isOurs = $false
            foreach ($server in @('InprocServer32', 'LocalServer32', 'InprocHandler32')) {
                $val = [string]$ci.$server
                if ($val -and (Test-OurReference $val)) {
                    $isOurs = $true
                    [void]$ourClsids.Add($clsid)
                    $progId = [string]$ci.ProgId
                    [void](Add-PlanItem -Category 'ComClass' -Level 3 -Scope $src.Scope -Target (Format-RegPath $src.Hive "$($src.Path)\CLSID\$clsid") `
                            -Action 'delete key' -Evidence "$server = $val (points at the app)" -Op (New-RegOp -Kind 'RegDeleteKey' -Hive $src.Hive -Path "$($src.Path)\CLSID\$clsid"))
                    $pgTarget = if ($progId) { Format-RegPath $src.Hive "$($src.Path)\$progId" } else { $null }
                    # One ProgID can name two of OUR classes (Adobe Reader's AcroExch.PDDoc, 32- and 64-bit): the
                    # key goes when it points at EITHER. The first class found used to be the only one accepted,
                    # and KILL IT left AcroExch.PDDoc behind as "no longer ours" (lab sweep, 2026-10-05).
                    $sameProgId = if ($pgTarget) { @($script:Items | Where-Object { $_.category -eq 'ComProgId' -and $_.target -eq $pgTarget }) | Select-Object -First 1 } else { $null }
                    if ($sameProgId) {
                        $ex = $sameProgId.op.expect
                        if (-not $ex.ContainsKey('values')) { $ex.values = @([string]$ex.value) }
                        if ($ex.values -notcontains $clsid) { $ex.values += $clsid }
                    } elseif ($progId) {
                        [void]$ourClassKeys.Add($progId)
                        # What else the ProgID points at. When all of it is the app's, the key may also go once
                        # the app's own uninstaller has cut its CLSID link (Test-KeyExpectation).
                        $expect = @{ sub = 'CLSID'; value = $clsid }
                        $refs = Get-ProgIdRefs $src.Hive "$($src.Path)\$progId"
                        if (-not @($refs.Values | Where-Object { -not (Test-OurReference $_) }).Count) { $expect.orphanRefs = $refs }
                        [void](Add-PlanItem -Category 'ComProgId' -Level 3 -Scope $src.Scope -Target (Format-RegPath $src.Hive "$($src.Path)\$progId") `
                                -Action 'delete key (only while it still points at our class, or at nothing else)' -Evidence "ProgID of our class $clsid" `
                                -Op (New-RegOp -Kind 'RegDeleteKey' -Hive $src.Hive -Path "$($src.Path)\$progId" -Expect $expect -Optional))
                    }
                    if ($appIdOfClass -and (Test-IsGuid $appIdOfClass)) { $pendingAppIds += [pscustomobject]@{ Src = $src; AppId = $appIdOfClass; Clsid = $clsid } }
                    break
                }
            }
            if ($appIdOfClass -and -not $isOurs) { $appIdUse["$($src.Hive)|$appIdOfClass"] = $true }
        }
        Close-Key $clsidRoot
        if ($src.Hive -eq 'HKLM32') { continue }
        $tlRoot = Open-Key $src.Hive "$($src.Path)\TypeLib" 'COM type libraries'
        $tls = [KillItWithFire.Fast]::ReadTypeLibs($tlRoot)
        for ($unr = 0; $unr -lt $tls.Unreadable; $unr++) { Add-Unreadable 'COM type libraries' }
        foreach ($ti in $tls.Items) {
            $tl = $ti.TypeLib
            $hit = $null
            foreach ($val in $ti.Paths) { if (Test-OurReference $val) { $hit = $val } }
            if ($hit) {
                [void](Add-PlanItem -Category 'ComTypeLib' -Level 3 -Scope $src.Scope -Target (Format-RegPath $src.Hive "$($src.Path)\TypeLib\$tl") `
                        -Action 'delete key' -Evidence "type library file $hit points at the app" -Op (New-RegOp -Kind 'RegDeleteKey' -Hive $src.Hive -Path "$($src.Path)\TypeLib\$tl"))
            }
        }
        Close-Key $tlRoot
    }
    foreach ($pa in $pendingAppIds) {
        # An AppID goes only when no class outside ours uses it.
        if ($appIdUse.ContainsKey("$($pa.Src.Hive)|$($pa.AppId)")) { continue }
        [void](Add-PlanItem -Category 'ComAppId' -Level 3 -Scope $pa.Src.Scope -Target (Format-RegPath $pa.Src.Hive "$($pa.Src.Path)\AppID\$($pa.AppId)") `
                -Action 'delete key' -Evidence "AppID used only by our class $($pa.Clsid)" -Op (New-RegOp -Kind 'RegDeleteKey' -Hive $pa.Src.Hive -Path "$($pa.Src.Path)\AppID\$($pa.AppId)" -Optional))
    }

    # ---------------------------------------------------------------- file associations and shell verbs
    $windowsProgIds = @('txtfile', 'htmlfile', 'http', 'https', 'mailto', 'ftp', 'Folder', 'Directory', 'Drive', 'exefile', 'batfile', 'cmdfile', 'comfile',
        'lnkfile', 'piffile', 'regfile', 'inffile', 'inifile', 'JSFile', 'VBSFile', 'WSFFile', 'jpegfile', 'pngfile', 'giffile', 'xmlfile', 'Unknown',
        'CompressedFolder', 'SystemFileAssociations', 'Msi.Package', 'Msi.Patch', 'Microsoft.PowerShellScript.1', 'Python.File')
    foreach ($src in @($comSources | Where-Object { $_.Hive -ne 'HKLM32' })) {
        $cr = Open-Key $src.Hive $src.Path 'file associations'
        $assocKeys = @()
        foreach ($n in (Get-SubKeyNamesSafe $cr 'file associations')) {
            if ($n.StartsWith('.') -or $n -in @('CLSID', 'TypeLib', 'Interface', 'AppID', 'Installer', 'WOW6432Node', 'Wow6432Node', 'Applications', 'MIME', 'Local Settings')) { continue }
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
            $friendly = [string](Get-ValueSafe $ak 'FriendlyTypeName')
            Close-Key $ak
            if ($why) {
                # A Windows ProgID the app took over (txtfile, http...) is REPAIRED, never deleted, and it is
                # NOT ours: counting it as ours would let the extension sweep below unhook .txt itself.
                $isWindowsProgId = ($windowsProgIds -contains $n) -or $n -match '^(?i)(Microsoft\.|MSEdge|ms-|AppX|Windows\.)' -or $friendly -match '^@(%SystemRoot%|%windir%|C:\\Windows)'
                if (-not $isWindowsProgId) { [void]$ourClassKeys.Add($n) }
                if ($isWindowsProgId) {
                    [void](Add-PlanItem -Category 'FileAssociation' -Level 3 -Scope $src.Scope -Target (Format-RegPath $src.Hive "$($src.Path)\$n") `
                            -Action "NOT deleted: a Windows ProgID the app took over; reset it in Default Apps" -Evidence $why -Risk 'high' -Review -Note 'report only' -Op $null)
                } else {
                    [void](Add-PlanItem -Category 'FileAssociation' -Level 3 -Scope $src.Scope -Target (Format-RegPath $src.Hive "$($src.Path)\$n") `
                            -Action 'delete key' -Evidence $why -Op (New-RegOp -Kind 'RegDeleteKey' -Hive $src.Hive -Path "$($src.Path)\$n"))
                }
            }
        }
        # Context-menu verbs on files, folders, drives and the folder background.
        foreach ($base in @('*', 'Directory', 'Directory\Background', 'Folder', 'Drive', 'AllFilesystemObjects')) {
            $shellKey = $null; try { $shellKey = $cr.OpenSubKey("$base\shell", $false) } catch { }
            foreach ($verb in (Get-SubKeyNamesSafe $shellKey)) {
                $ck = $null; try { $ck = $shellKey.OpenSubKey("$verb\command", $false) } catch { }
                $val = [string](Get-ValueSafe $ck ''); Close-Key $ck
                if ($val -and (Test-OurReference $val)) {
                    [void](Add-PlanItem -Category 'ShellVerb' -Level 3 -Scope $src.Scope -Target (Format-RegPath $src.Hive "$($src.Path)\$base\shell\$verb") `
                            -Action 'delete key' -Evidence "context-menu verb runs $val" -Op (New-RegOp -Kind 'RegDeleteKey' -Hive $src.Hive -Path "$($src.Path)\$base\shell\$verb"))
                }
            }
            Close-Key $shellKey
        }
        Close-Key $cr
    }

    # File extensions still naming one of our ProgIDs (.xyz -> OurApp.File): the default value and the
    # OpenWithProgids entry go, the extension key stays (other apps list themselves under it too).
    foreach ($src in @($comSources | Where-Object { $_.Hive -ne 'HKLM32' })) {
        $cr = Open-Key $src.Hive $src.Path 'file associations'
        foreach ($n in @(Get-SubKeyNamesSafe $cr 'file associations' | Where-Object { $_.StartsWith('.') })) {
            $ek = $null; try { $ek = $cr.OpenSubKey($n, $false) } catch { continue }
            if ($null -eq $ek) { continue }
            $def = ([string](Get-ValueSafe $ek '')).Trim()
            if ($def -and $ourClassKeys.Contains($def)) {
                [void](Add-PlanItem -Category 'FileAssociation' -Level 3 -Scope $src.Scope -Target "$(Format-RegPath $src.Hive "$($src.Path)\$n") : (default)" `
                        -Action "delete the default value (it names our file type $def)" -Evidence "$n opens with our file type $def" `
                        -Op (New-RegOp -Kind 'RegDeleteValue' -Hive $src.Hive -Path "$($src.Path)\$n" -ValueName '' -Optional))
            }
            $ow = $null; try { $ow = $ek.OpenSubKey('OpenWithProgids', $false) } catch { }
            foreach ($v in @(Get-ValueNamesSafe $ow | Where-Object { $_ -and $ourClassKeys.Contains($_) })) {
                [void](Add-PlanItem -Category 'FileAssociation' -Level 3 -Scope $src.Scope -Target "$(Format-RegPath $src.Hive "$($src.Path)\$n\OpenWithProgids") : $v" `
                        -Action "delete value '$v'" -Evidence "our file type $v is offered for $n" `
                        -Op (New-RegOp -Kind 'RegDeleteValue' -Hive $src.Hive -Path "$($src.Path)\$n\OpenWithProgids" -ValueName $v -Optional))
            }
            Close-Key $ow; Close-Key $ek
        }
        Close-Key $cr
    }

    # ---------------------------------------------------------------- scheduled tasks
    $taskList = @()
    try { $taskList = @(Get-ScheduledTask -ErrorAction Stop) } catch { $script:Warnings.Add("Scheduled tasks could NOT be read ($($_.Exception.Message)); any the app registered are missing from this plan.") }
    foreach ($t in $taskList) {
        $refs = @()
        foreach ($a in @($t.Actions)) {
            if ($null -eq $a) { continue }
            $props = $a.PSObject.Properties.Name
            if ($props -contains 'Execute') {
                foreach ($field in @($a.Execute, $a.Arguments, $a.WorkingDirectory)) { if ($field -and (Test-OurReference ([string]$field))) { $refs += [string]$field } }
            }
            if ($props -contains 'ClassId' -and $a.ClassId -and $ourClsids.Contains([string]$a.ClassId)) { $refs += "COM handler $($a.ClassId)" }
        }
        if ($refs.Count) {
            [void](Add-PlanItem -Category 'ScheduledTask' -Level 3 -Target "task $($t.TaskPath)$($t.TaskName)" -Action 'unregister task (its XML is backed up)' `
                    -Evidence ("action runs " + (($refs | Select-Object -Unique) -join '; ')) -Op ([ordered]@{ kind = 'TaskUnregister'; taskPath = $t.TaskPath; taskName = $t.TaskName }))
        }
    }

    # ---------------------------------------------------------------- Run keys (+ their StartupApproved twins), Active Setup
    $runSources = @()
    foreach ($h in @('HKLM64', 'HKLM32')) {
        $approved = if ($h -eq 'HKLM64') { 'Run' } else { 'Run32' }
        foreach ($p in @('SOFTWARE\Microsoft\Windows\CurrentVersion\Run', 'SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce', 'SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run')) {
            $runSources += @{ Hive = $h; Path = $p; Scope = 'machine'; Approved = $(if ($p -like '*\Run') { "SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\$approved" } else { $null }); ApprovedHive = 'HKLM64' }
        }
    }
    foreach ($sid in $loadedSids) {
        foreach ($p in @('Software\Microsoft\Windows\CurrentVersion\Run', 'Software\Microsoft\Windows\CurrentVersion\RunOnce', 'Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run')) {
            $runSources += @{ Hive = 'HKU'; Path = "$sid\$p"; Scope = "user:$sid"; Approved = $(if ($p -like '*\Run') { "$sid\Software\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run" } else { $null }); ApprovedHive = 'HKU' }
        }
    }
    foreach ($src in $runSources) {
        $rk = Open-Key $src.Hive $src.Path 'startup entries'
        foreach ($v in (Get-ValueNamesSafe $rk 'startup entries')) {
            $data = [string](Get-ValueSafe $rk $v)
            if ($data -and (Test-OurReference $data)) {
                $ops = @(New-RegOp -Kind 'RegDeleteValue' -Hive $src.Hive -Path $src.Path -ValueName $v)
                if ($src.Approved) { $ops += (New-RegOp -Kind 'RegDeleteValue' -Hive $src.ApprovedHive -Path $src.Approved -ValueName $v -Optional) }
                [void](Add-PlanItem -Category 'RunValue' -Level 3 -Scope $src.Scope -Target "$(Format-RegPath $src.Hive $src.Path) : $v" `
                        -Action "delete value '$v' (and its Explorer\StartupApproved entry)" -Evidence "runs $data" -Op $ops)
            }
        }
        Close-Key $rk
    }
    foreach ($h in @('HKLM64', 'HKLM32')) {
        $as = Open-Key $h 'SOFTWARE\Microsoft\Active Setup\Installed Components'
        foreach ($id in (Get-SubKeyNamesSafe $as)) {
            $ak = $null; try { $ak = $as.OpenSubKey($id, $false) } catch { continue }
            $stub = [string](Get-ValueSafe $ak 'StubPath'); Close-Key $ak
            if ($stub -and (Test-OurReference $stub)) {
                [void](Add-PlanItem -Category 'ActiveSetup' -Level 3 -Target (Format-RegPath $h "SOFTWARE\Microsoft\Active Setup\Installed Components\$id") `
                        -Action 'delete key (stops the per-user setup at the next sign-in)' -Evidence "StubPath runs $stub" -Op (New-RegOp -Kind 'RegDeleteKey' -Hive $h -Path "SOFTWARE\Microsoft\Active Setup\Installed Components\$id"))
            }
        }
        Close-Key $as
    }

    # ---------------------------------------------------------------- shell extensions
    if ($ourClsids.Count) {
        foreach ($h in @('HKLM64', 'HKLM32')) {
            $ap = 'SOFTWARE\Microsoft\Windows\CurrentVersion\Shell Extensions\Approved'
            $ak = Open-Key $h $ap 'shell extensions'
            foreach ($v in (Get-ValueNamesSafe $ak)) {
                if ($ourClsids.Contains($v)) {
                    [void](Add-PlanItem -Category 'ShellExtension' -Level 3 -Target "$(Format-RegPath $h $ap) : $v" -Action "delete value '$v'" -Evidence "approval for our shell extension class $v" `
                            -Op (New-RegOp -Kind 'RegDeleteValue' -Hive $h -Path $ap -ValueName $v))
                }
            }
            Close-Key $ak
            foreach ($list in @('SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\ShellIconOverlayIdentifiers', 'SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Browser Helper Objects')) {
                $ok = Open-Key $h $list 'shell extensions'
                foreach ($n in (Get-SubKeyNamesSafe $ok)) {
                    $sk = $null; try { $sk = $ok.OpenSubKey($n, $false) } catch { continue }
                    $val = ([string](Get-ValueSafe $sk '')).Trim(); Close-Key $sk
                    if (($val -and $ourClsids.Contains($val)) -or $ourClsids.Contains($n)) {
                        [void](Add-PlanItem -Category 'ShellExtension' -Level 3 -Target (Format-RegPath $h "$list\$n") -Action 'delete key' -Evidence "registered for our class $(if ($val) { $val } else { $n })" `
                                -Op (New-RegOp -Kind 'RegDeleteKey' -Hive $h -Path "$list\$n"))
                    }
                }
                Close-Key $ok
            }
            foreach ($base in @('*', 'Directory', 'Directory\Background', 'Folder', 'Drive', 'AllFilesystemObjects', 'lnkfile')) {
                foreach ($kind in @('ContextMenuHandlers', 'PropertySheetHandlers', 'DragDropHandlers', 'CopyHookHandlers', 'IconOverlayHandlers')) {
                    $hp = "SOFTWARE\Classes\$base\shellex\$kind"
                    $hk = Open-Key $h $hp 'shell extensions'
                    foreach ($n in (Get-SubKeyNamesSafe $hk)) {
                        $sk = $null; try { $sk = $hk.OpenSubKey($n, $false) } catch { continue }
                        $val = ([string](Get-ValueSafe $sk '')).Trim(); Close-Key $sk
                        if (($val -and $ourClsids.Contains($val)) -or $ourClsids.Contains($n)) {
                            [void](Add-PlanItem -Category 'ShellExtension' -Level 3 -Target (Format-RegPath $h "$hp\$n") -Action 'delete key' -Evidence "$kind handler = our class $(if ($val) { $val } else { $n })" `
                                    -Op (New-RegOp -Kind 'RegDeleteKey' -Hive $h -Path "$hp\$n"))
                        }
                    }
                    Close-Key $hk
                }
            }
        }
    }

    & $Say '  scanning logon, LSA, network provider, Winsock, firewall and shortcut hooks...'
    # ---------------------------------------------------------------- System32 DLLs registered by NAME
    $system32 = Join-Path $env:SystemRoot 'System32'
    $dllIsOurs = {
        # Returns @{ Why; Weak } or $null. Path and MSI-file evidence are strong; a signer match is weak
        # (review 2026-09-26: signer-only ties must be "needs review"). A Microsoft-signed DLL never matches.
        param([string] $DllName)
        $file = if ([System.IO.Path]::IsPathRooted($DllName)) { $DllName } else { Join-Path $system32 ($(if ($DllName -match '\.dll$') { $DllName } else { "$DllName.dll" })) }
        $leaf = [System.IO.Path]::GetFileName($file).ToLowerInvariant()
        $exists = Test-Path -LiteralPath $file -PathType Leaf
        $org = if ($exists) { Get-SignerOrg (Get-SignerSubject $file) } else { $null }
        if ($org -and (Test-IsMicrosoftName $org)) { return $null }
        if ($exists -and (Test-OurReference $file)) { return @{ Why = "$file points at the app"; Weak = $false } }
        if ($msiFileNames -contains $leaf) { return @{ Why = "the app's MSI installs $leaf"; Weak = $false } }
        if ($org -and $signerOrg -and $org -eq $signerOrg) {
            $more = if ($samePublisherOthers.Count) { ", and $org also has $($samePublisherOthers -join ', ') installed" } else { '' }
            return @{ Why = "SIGNER-ONLY: $file is signed by $org, the app's signer$more"; Weak = $true }
        }
        return $null
    }

    # ---------------------------------------------------------------- credential providers (+ the password provider)
    $passwordProvider = '{60b78e88-EAD8-445C-9CFD-0B87F74EA6CD}'
    $ourCredProviders = 0
    foreach ($kind in @(@{ Path = 'Credential Provider Filters'; Cat = 'CredentialProviderFilter'; Label = 'credential provider FILTER' },
            @{ Path = 'Credential Providers'; Cat = 'CredentialProvider'; Label = 'credential provider' })) {
        $root = "SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\$($kind.Path)"
        $ck = Open-Key 'HKLM64' $root 'credential providers'
        foreach ($clsid in (Get-SubKeyNamesSafe $ck)) {
            if ($clsid.Equals($passwordProvider, [StringComparison]::OrdinalIgnoreCase)) { continue }
            $hit = $null
            if ($ourClsids.Contains($clsid)) { $hit = @{ Why = "its COM server points at the app"; Weak = $false } }
            else {
                $srv = Open-Key 'HKLM64' "SOFTWARE\Classes\CLSID\$clsid\InprocServer32"
                $dll = Get-NormalizedPath ([string](Get-ValueSafe $srv '')); Close-Key $srv
                if ($dll) { $hit = & $dllIsOurs $dll }
            }
            if ($hit) {
                $ourCredProviders++
                [void](Add-PlanItem -Category $kind.Cat -Level 3 -Target (Format-RegPath 'HKLM64' "$root\$clsid") `
                        -Action $(if ($kind.Cat -eq 'CredentialProviderFilter') { 'delete key FIRST, before the provider' } else { 'delete key, after the filter' }) `
                        -Evidence "our $($kind.Label): $($hit.Why)" -Risk 'critical' -Review:$hit.Weak -Note $(if ($hit.Weak) { 'needs review: tied by signer only' } else { $null }) `
                        -Op (New-RegOp -Kind 'RegDeleteKey' -Hive 'HKLM64' -Path "$root\$clsid"))
            }
        }
        Close-Key $ck
    }
    $pwKeyPath = "SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\Credential Providers\$passwordProvider"
    $pk = Open-Key 'HKLM64' $pwKeyPath
    $pwDisabled = ((Get-ValueSafe $pk 'Disabled') -eq 1)
    Close-Key $pk
    $pol = Open-Key 'HKLM64' 'SOFTWARE\Policies\Microsoft\Windows\System'
    $excluded = [string](Get-ValueSafe $pol 'ExcludedCredentialProviders'); Close-Key $pol
    $pwExcluded = ($excluded -and $excluded.IndexOf($passwordProvider.Trim('{', '}'), [StringComparison]::OrdinalIgnoreCase) -ge 0)
    if ($pwDisabled -or $pwExcluded) {
        $how = @(); if ($pwDisabled) { $how += 'Disabled=1 on its provider key' }; if ($pwExcluded) { $how += 'listed in the ExcludedCredentialProviders policy (if a GPO sets it, fix it in the GPO or it comes back)' }
        if ($ourCredProviders -gt 0) {
            $ops = @()
            if ($pwDisabled) { $ops += (New-RegOp -Kind 'RegDeleteValue' -Hive 'HKLM64' -Path $pwKeyPath -ValueName 'Disabled' -Optional) }
            if ($pwExcluded) { $ops += (New-RegOp -Kind 'RegRemoveListEntry' -Hive 'HKLM64' -Path 'SOFTWARE\Policies\Microsoft\Windows\System' -ValueName 'ExcludedCredentialProviders' -Entry $passwordProvider -Separator ',' -Optional) }
            [void](Add-PlanItem -Category 'PasswordProviderRestore' -Level 3 -Target "built-in password provider $passwordProvider" -Action 'turn it back on BEFORE our providers are removed' `
                    -Evidence ("the built-in password sign-in is OFF: " + ($how -join '; ') + ". Remove our provider without this and nobody can sign in with a password.") -Risk 'critical' -Op $ops)
        } else {
            $script:Warnings.Add("The built-in password credential provider is off ($($how -join '; ')), but nothing ties that to this app. Left alone.")
        }
    }

    # ---------------------------------------------------------------- Winlogon, LSA, network providers, print monitors, AppInit, IFEO, Winsock
    $wl = Open-Key 'HKLM64' 'SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon'
    $wlPath = 'SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon'
    # Windows' own entry is the floor: an empty Userinit (or one without userinit.exe) means no shell at
    # sign-in, and Windows only falls back to its default when the value is ABSENT, not when it is empty
    # (review 2026-09-26). The floor is applied by the op itself when it runs (a plan can be a day old),
    # and it puts Windows' entry back IN FRONT of whatever other products left there, never over them.
    $wlDefaults = @{ Shell = 'explorer.exe'; Userinit = "$env:SystemRoot\system32\userinit.exe," }
    foreach ($v in @('Shell', 'Userinit')) {
        $data = [string](Get-ValueSafe $wl $v)
        if (-not $data) { continue }
        $ours = @($data -split ',' | ForEach-Object { $_.Trim() } | Where-Object { $_ -and (Test-OurReference $_) })
        if (-not $ours.Count) { continue }
        $after = $data
        foreach ($entry in $ours) { $after = Remove-ListEntry $after $entry ',' }
        $needs = if ($v -eq 'Userinit') { '(?i)(^|[\\,])userinit\.exe' } else { '\S' }
        $floorNeeded = ($after -notmatch $needs)
        foreach ($entry in $ours) {
            $act = if ($floorNeeded) { "remove '$entry' from $v; Windows' default '$($wlDefaults[$v])' goes back in (nothing left in it would start the $(if ($v -eq 'Shell') { 'desktop' } else { 'sign-in' }))" } else { "remove '$entry' from $v, keep every other entry" }
            [void](Add-PlanItem -Category 'Winlogon' -Level 3 -Target "HKLM\$wlPath : $v" -Action $act -Evidence "$v = $data" -Risk 'critical' `
                    -Op (New-RegOp -Kind 'RegRemoveListEntry' -Hive 'HKLM64' -Path $wlPath -ValueName $v -Entry $entry -Separator ',' -Floor $wlDefaults[$v] -FloorMatch $needs))
        }
    }
    Close-Key $wl
    foreach ($sid in $loadedSids) {
        $uwl = Open-Key 'HKU' "$sid\Software\Microsoft\Windows NT\CurrentVersion\Winlogon"
        $data = [string](Get-ValueSafe $uwl 'Shell'); Close-Key $uwl
        if ($data -and (Test-OurReference $data)) {
            [void](Add-PlanItem -Category 'Winlogon' -Level 3 -Scope "user:$sid" -Target "HKU\$sid\Software\Microsoft\Windows NT\CurrentVersion\Winlogon : Shell" -Action 'delete the per-user Shell value (falls back to the machine shell)' `
                    -Evidence "per-user Shell = $data" -Risk 'critical' -Op (New-RegOp -Kind 'RegDeleteValue' -Hive 'HKU' -Path "$sid\Software\Microsoft\Windows NT\CurrentVersion\Winlogon" -ValueName 'Shell'))
        }
    }
    $lsaPath = 'SYSTEM\CurrentControlSet\Control\Lsa'
    $lsa = Open-Key 'HKLM64' $lsaPath
    foreach ($v in @('Authentication Packages', 'Notification Packages', 'Security Packages')) {
        foreach ($pkg in @(Get-ValueSafe $lsa $v)) {
            if (-not $pkg -or $pkg -eq '""') { continue }
            $hit = & $dllIsOurs ([string]$pkg)
            if ($hit) {
                [void](Add-PlanItem -Category 'LsaPackage' -Level 3 -Target "HKLM\$lsaPath : $v" -Action "remove '$pkg' from the list (keep every other entry), before its DLL" `
                        -Evidence $hit.Why -Risk 'critical' -Review:$hit.Weak -Note $(if ($hit.Weak) { 'needs review: tied by signer only' } else { $null }) `
                        -Op (New-RegOp -Kind 'RegRemoveMultiSzEntry' -Hive 'HKLM64' -Path $lsaPath -ValueName $v -Entry ([string]$pkg)))
            }
        }
    }
    Close-Key $lsa
    $npo = Open-Key 'HKLM64' 'SYSTEM\CurrentControlSet\Control\NetworkProvider\Order'
    $order = [string](Get-ValueSafe $npo 'ProviderOrder'); Close-Key $npo
    foreach ($prov in ($order -split ',' | ForEach-Object { $_.Trim() } | Where-Object { $_ })) {
        $hit = $null
        if ($ourServiceNames -contains $prov) { $hit = @{ Why = "provider '$prov' is our service"; Weak = $reviewServices.Contains($prov) } }
        else {
            $np = Open-Key 'HKLM64' "SYSTEM\CurrentControlSet\Services\$prov\NetworkProvider"
            $pp = [string](Get-ValueSafe $np 'ProviderPath'); Close-Key $np
            if ($pp) { $hit = & $dllIsOurs (Get-NormalizedPath $pp) }
        }
        if ($hit) {
            [void](Add-PlanItem -Category 'NetworkProvider' -Level 3 -Target "HKLM\SYSTEM\CurrentControlSet\Control\NetworkProvider\Order : ProviderOrder" `
                    -Action "remove '$prov' from ProviderOrder (and HwOrder), keep the rest in order" -Evidence $hit.Why -Risk 'critical' -Review:$hit.Weak `
                    -Note $(if ($hit.Weak) { 'needs review: tied by signer or vendor only' } else { $null }) `
                    -Op @((New-RegOp -Kind 'RegRemoveListEntry' -Hive 'HKLM64' -Path 'SYSTEM\CurrentControlSet\Control\NetworkProvider\Order' -ValueName 'ProviderOrder' -Entry $prov -Separator ','),
                        (New-RegOp -Kind 'RegRemoveListEntry' -Hive 'HKLM64' -Path 'SYSTEM\CurrentControlSet\Control\NetworkProvider\HwOrder' -ValueName 'ProviderOrder' -Entry $prov -Separator ',' -Optional)))
        }
    }
    $mon = Open-Key 'HKLM64' 'SYSTEM\CurrentControlSet\Control\Print\Monitors'
    foreach ($m in (Get-SubKeyNamesSafe $mon)) {
        $mk = $null; try { $mk = $mon.OpenSubKey($m, $false) } catch { continue }
        $drv = [string](Get-ValueSafe $mk 'Driver'); Close-Key $mk
        if ($drv) {
            $hit = & $dllIsOurs $drv
            if ($hit) {
                [void](Add-PlanItem -Category 'PrintMonitor' -Level 3 -Target "HKLM\SYSTEM\CurrentControlSet\Control\Print\Monitors\$m" -Action 'delete key, then restart the spooler' -Evidence $hit.Why -Risk 'high' `
                        -Review:$hit.Weak -Note $(if ($hit.Weak) { 'needs review: tied by signer only' } else { $null }) `
                        -Op @((New-RegOp -Kind 'RegDeleteKey' -Hive 'HKLM64' -Path "SYSTEM\CurrentControlSet\Control\Print\Monitors\$m"), ([ordered]@{ kind = 'ServiceRestart'; name = 'Spooler' })))
            }
        }
    }
    Close-Key $mon
    foreach ($h in @('HKLM64', 'HKLM32')) {
        $wp = 'SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows'
        $wk = Open-Key $h $wp
        $appInit = [string](Get-ValueSafe $wk 'AppInit_DLLs'); Close-Key $wk
        $sep = if ($appInit.Contains(',')) { ',' } else { ' ' }
        foreach ($dll in ($appInit -split '[,\s]+' | Where-Object { $_ })) {
            if (Test-OurReference $dll) {
                [void](Add-PlanItem -Category 'AppInitDll' -Level 3 -Target "$(Format-RegPath $h $wp) : AppInit_DLLs" -Action "remove '$dll' from the list" -Evidence "$dll loads into every GUI process" -Risk 'high' `
                        -Op (New-RegOp -Kind 'RegRemoveListEntry' -Hive $h -Path $wp -ValueName 'AppInit_DLLs' -Entry $dll -Separator $sep))
            }
        }
        $ifeoPath = 'SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options'
        $ifeo = Open-Key $h $ifeoPath
        foreach ($exe in (Get-SubKeyNamesSafe $ifeo)) {
            $ek = $null; try { $ek = $ifeo.OpenSubKey($exe, $false) } catch { continue }
            $dbg = [string](Get-ValueSafe $ek 'Debugger'); Close-Key $ek
            if ($dbg -and (Test-OurReference $dbg)) {
                [void](Add-PlanItem -Category 'IfeoDebugger' -Level 3 -Target "$(Format-RegPath $h "$ifeoPath\$exe") : Debugger" -Action "delete value 'Debugger'" -Evidence "launching $exe runs $dbg instead" -Risk 'high' `
                        -Op (New-RegOp -Kind 'RegDeleteValue' -Hive $h -Path "$ifeoPath\$exe" -ValueName 'Debugger'))
            }
        }
        Close-Key $ifeo
    }
    # Winsock name-space and layered providers: reported for review, never edited by hand here.
    foreach ($cat in @('NameSpace_Catalog5\Catalog_Entries', 'NameSpace_Catalog5\Catalog_Entries64', 'Protocol_Catalog9\Catalog_Entries', 'Protocol_Catalog9\Catalog_Entries64')) {
        $wsp = "SYSTEM\CurrentControlSet\Services\WinSock2\Parameters\$cat"
        $wk = Open-Key 'HKLM64' $wsp
        foreach ($n in (Get-SubKeyNamesSafe $wk)) {
            $ek = $null; try { $ek = $wk.OpenSubKey($n, $false) } catch { continue }
            $lib = [string](Get-ValueSafe $ek 'LibraryPath')
            if (-not $lib) {
                $packed = Get-ValueSafe $ek 'PackedCatalogItem'
                if ($packed -is [byte[]]) { $lib = ([System.Text.Encoding]::ASCII.GetString($packed) -split "`0")[0] }
            }
            Close-Key $ek
            if ($lib -and (Test-OurReference $lib)) {
                [void](Add-PlanItem -Category 'WinsockProvider' -Level 3 -Target "HKLM\$wsp\$n" -Action "NOT edited here: remove with the vendor's tool, or 'netsh winsock reset' (resets EVERY provider, then reboot)" `
                        -Evidence "Winsock provider loads $lib" -Risk 'critical' -Review -Note 'report only' -Op $null)
            }
        }
        Close-Key $wk
    }

    # ---------------------------------------------------------------- firewall rules, shortcuts
    $fw = Open-Key 'HKLM64' 'SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules' 'firewall rules'
    foreach ($ruleId in (Get-ValueNamesSafe $fw 'firewall rules')) {
        $data = [string](Get-ValueSafe $fw $ruleId)
        $app = if ($data -match '\|App=([^|]+)') { $matches[1] } else { $null }
        $svc = if ($data -match '\|Svc=([^|]+)') { $matches[1] } else { $null }
        $ruleName = if ($data -match '\|Name=([^|]+)') { $matches[1] } else { $ruleId }
        if (($app -and (Test-OurReference $app)) -or ($svc -and ($ourServiceNames -contains $svc))) {
            [void](Add-PlanItem -Category 'FirewallRule' -Level 3 -Target "firewall rule '$ruleName' ($ruleId)" -Action 'delete rule (its settings are backed up)' -Evidence $(if ($app) { "allows $app" } else { "applies to our service $svc" }) `
                    -Op ([ordered]@{ kind = 'FirewallRuleDelete'; id = $ruleId }))
        }
    }
    Close-Key $fw
    $shell = $null; try { $shell = New-Object -ComObject WScript.Shell } catch { }
    if ($shell) {
        $lnkDirs = @(@{ Dir = (Join-Path $env:ProgramData 'Microsoft\Windows\Start Menu\Programs'); Scope = 'machine' }, @{ Dir = (Join-Path $env:PUBLIC 'Desktop'); Scope = 'machine' })
        foreach ($pr in $profiles | Where-Object { $_.Loaded }) {
            $lnkDirs += @{ Dir = (Join-Path $pr.Path 'AppData\Roaming\Microsoft\Windows\Start Menu\Programs'); Scope = "user:$($pr.Sid)" }
            foreach ($d in @((Join-Path $pr.Path 'Desktop')) + @($pr.ShellFolders | Where-Object { $_ -match '(?i)desktop' })) { $lnkDirs += @{ Dir = $d; Scope = "user:$($pr.Sid)" } }
        }
        foreach ($ld in $lnkDirs) {
            if (-not (Test-Path -LiteralPath $ld.Dir)) { continue }
            foreach ($lnk in @(Get-ChildItem -LiteralPath $ld.Dir -Filter *.lnk -Recurse -File -ErrorAction SilentlyContinue)) {
                try {
                    $sc = $shell.CreateShortcut($lnk.FullName)
                    $tgt = [string]$sc.TargetPath; $lnkArgs = [string]$sc.Arguments
                    $advertisedOurs = ($pc -and $tgt -and $tgt.IndexOf($pc, [StringComparison]::OrdinalIgnoreCase) -ge 0)
                    if ($advertisedOurs -or ($tgt -and (Test-OurReference $tgt)) -or ($lnkArgs -and (Test-OurReference $lnkArgs))) {
                        [void](Add-PlanItem -Category 'Shortcut' -Level 3 -Scope $ld.Scope -Target $lnk.FullName -Action 'move to quarantine' `
                                -Evidence $(if ($advertisedOurs) { "advertised shortcut for $pc" } else { "target $tgt $lnkArgs".Trim() }) -Op ([ordered]@{ kind = 'FileQuarantine'; path = $lnk.FullName; keep = @() }))
                    }
                } catch { Add-Unreadable 'shortcuts' }
            }
        }
    }

    & $Say '  checking the keyword, folders and per-user state...'
    # ---------------------------------------------------------------- keyword: pick, then prove it is distinctive
    $keywordInfo = [ordered]@{ value = $null; source = $null; used = $false; outsideHits = 0; otherProducts = @(); examples = @(); reason = $null }
    $keywordInfo.source = if ($AppKeyword) { 'given' } else { 'derived from the name, then the publisher' }
    $ck = Open-Key 'HKLM64' 'SOFTWARE\Classes'; $classNames = @(Get-SubKeyNamesSafe $ck); Close-Key $ck
    $msKeyNames = @()
    $msk = Open-Key 'HKLM64' 'SOFTWARE\Microsoft'
    foreach ($n in (Get-SubKeyNamesSafe $msk)) { $msKeyNames += "SOFTWARE\Microsoft\$n"; $sk = $null; try { $sk = $msk.OpenSubKey($n, $false) } catch { }; foreach ($n2 in (Get-SubKeyNamesSafe $sk)) { $msKeyNames += "SOFTWARE\Microsoft\$n\$n2" }; Close-Key $sk }
    Close-Key $msk
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
        $hits += @($classNames | Where-Object { (Test-WholeWord $_ $Word) -and -not $ourClassKeys.Contains($_) } | ForEach-Object { "HKLM\SOFTWARE\Classes\$_" })
        $hits += @($msKeyNames | Where-Object { Test-WholeWord ($_.Split('\')[-1]) $Word } | ForEach-Object { if ($_ -like 'HKU\*') { $_ } else { "HKLM\$_" } })
        $hits += @($services | Where-Object { ($ourServiceNames -notcontains $_.Name) -and ((Test-WholeWord $_.Name $Word) -or (Test-WholeWord $_.DisplayName $Word)) } | ForEach-Object { "service $($_.Name)" })
        $hits += @($taskList | Where-Object { Test-WholeWord "$($_.TaskPath)$($_.TaskName)" $Word } | Where-Object {
                $mine = $false; foreach ($a in @($_.Actions)) { if ($a -and ($a.PSObject.Properties.Name -contains 'Execute') -and (Test-OurReference ([string]$a.Execute))) { $mine = $true } }; -not $mine } |
            ForEach-Object { "task $($_.TaskPath)$($_.TaskName)" })
        return [pscustomobject]@{ Word = $Word; Others = $others; Hits = $hits; Ok = ($others.Count -eq 0 -and $hits.Count -le $maxOutside) }
    }
    $best = $null
    $nameWords = if ($AppKeyword) { @($AppKeyword.Trim()) } else { @(Get-KeywordCandidates $targetName '') }
    $pubWords = if ($AppKeyword) { @() } else { @(Get-KeywordCandidates '' $publisher | Where-Object { $nameWords -notcontains $_ }) }
    if ($AppKeyword -and (Test-BlockedKeyword $AppKeyword.Trim())) {
        # A Windows or management-stack word never works as a keyword, whatever the scoring says.
        $nameWords = @(); $pubWords = @()
        $keywordInfo.value = $AppKeyword.Trim()
        $keywordInfo.reason = "REFUSED: '$($AppKeyword.Trim())' names part of Windows or its management stack; a keyword like that would match far outside the app"
    }
    foreach ($pool in @(, $nameWords) + @(, $pubWords)) {
        foreach ($cand in $pool) {
            if (-not $cand -or $cand.Length -lt 4) { continue }
            $score = & $scoreWord $cand
            if ($null -eq $best -or ($score.Ok -and -not $best.Ok) -or ($score.Ok -eq $best.Ok -and (($score.Others.Count -lt $best.Others.Count) -or ($score.Others.Count -eq $best.Others.Count -and $score.Hits.Count -lt $best.Hits.Count)))) { $best = $score }
        }
        if ($best -and $best.Ok) { break }
    }
    if ($null -eq $best) {
        if (-not $keywordInfo.reason) { $keywordInfo.reason = 'no distinctive word in the name or publisher (4+ letters, not generic)' }
    } else {
        $keywordInfo.value = $best.Word; $keywordInfo.outsideHits = $best.Hits.Count; $keywordInfo.otherProducts = @($best.Others)
        $keywordInfo.examples = @($best.Hits | Select-Object -First 5)
        if ($best.Others.Count -gt 0) {
            $keywordInfo.reason = "REFUSED: '$($best.Word)' also names other installed products ($(@($best.Others | Select-Object -First 5) -join ', ')); a vendor name alone is too wide"
        } elseif ($best.Hits.Count -gt $maxOutside) {
            $keywordInfo.reason = "REFUSED: '$($best.Word)' matches $($best.Hits.Count) things in other products, system classes, services or tasks (e.g. $(@($best.Hits | Select-Object -First 3) -join '; '))"
        } else {
            $keywordInfo.used = $true
            $keywordInfo.reason = "whole-word; $($best.Hits.Count) hit(s) in other products, system classes, services and tasks. Folders and keys it finds are marked high risk."
        }
    }
    $kw = if ($keywordInfo.used) { $keywordInfo.value } else { $null }

    # ---------------------------------------------------------------- level 2: registration
    foreach ($m in $matched | Where-Object { $_.KeyPath }) {
        [void](Add-PlanItem -Category 'UninstallEntry' -Level 2 -Scope $(if ($m.Sid) { "user:$($m.Sid)" } else { 'machine' }) -Target $m.Display -Action 'delete key' `
                -Evidence "the uninstall entry for '$($m.DisplayName)' $($m.DisplayVersion)" -Op (New-RegOp -Kind 'RegDeleteKey' -Hive $m.Hive -Path $m.KeyPath))
        # Google Update (Omaha) keeps its own record of an app it manages, keyed by the SAME GUID as the app's
        # uninstall entry: Update\Clients\{GUID} (name, pv) and ClientState\{GUID}. Left behind by KILL IT,
        # Google Drive's installer read it, decided "131.0.2.0 is already installed" and refused to reinstall
        # (1638, lab rerun 2026-10-05). The GUID is the evidence: nothing else is keyed by it.
        if (-not $m.Sid -and (Test-IsGuid $m.KeyName)) {
            foreach ($h in @('HKLM64', 'HKLM32')) {
                foreach ($sub in @('Clients', 'ClientState', 'ClientStateMedium')) {
                    $up = "SOFTWARE\Google\Update\$sub\$($m.KeyName)"
                    $uk = Open-Key $h $up
                    if (-not $uk) { continue }
                    $nm = [string](Get-ValueSafe $uk 'name'); Close-Key $uk
                    [void](Add-PlanItem -Category 'UpdaterRegistration' -Level 2 -Target (Format-RegPath $h $up) -Action 'delete key' `
                            -Evidence "Google Update's record of this app (the same GUID as its uninstall entry$(if ($nm) { ", name '$nm'" }))" -Op (New-RegOp -Kind 'RegDeleteKey' -Hive $h -Path $up))
                }
            }
        }
    }
    $patchRefs = @{}
    if ($msiRegistration | Where-Object { $_.What -eq 'patch' }) {
        $ud = Open-Key 'HKLM64' 'SOFTWARE\Microsoft\Windows\CurrentVersion\Installer\UserData'
        foreach ($sid in (Get-SubKeyNamesSafe $ud)) {
            $prods = Open-Key 'HKLM64' "SOFTWARE\Microsoft\Windows\CurrentVersion\Installer\UserData\$sid\Products"
            foreach ($prod in (Get-SubKeyNamesSafe $prods)) {
                if ($prod -eq $packedPc) { continue }
                $pp = Open-Key 'HKLM64' "SOFTWARE\Microsoft\Windows\CurrentVersion\Installer\UserData\$sid\Products\$prod\Patches"
                foreach ($x in (Get-SubKeyNamesSafe $pp)) { $patchRefs[$x] = $true }
                Close-Key $pp
            }
            Close-Key $prods
        }
        Close-Key $ud
    }
    foreach ($r in $msiRegistration) {
        if ($r.What -like 'upgrade code*') {
            [void](Add-PlanItem -Category 'MsiUpgradeCode' -Level 2 -Target "$(Format-RegPath $r.Hive $r.Path) : $packedPc" -Action "delete value '$packedPc' (the key goes only when no other product is left under it)" `
                    -Evidence "$($r.What); UpgradeCode $upgradeCodeFound" -Op (New-RegOp -Kind 'RegDeleteValue' -Hive $r.Hive -Path $r.Path -ValueName $packedPc -DeleteKeyIfEmpty))
        } elseif ($r.What -eq 'patch') {
            if ($patchRefs.ContainsKey($r.Patch)) { continue }
            [void](Add-PlanItem -Category 'MsiPatch' -Level 2 -Target (Format-RegPath $r.Hive $r.Path) -Action 'delete key' -Evidence 'a patch applied only to this product' -Op (New-RegOp -Kind 'RegDeleteKey' -Hive $r.Hive -Path $r.Path -Optional))
        } elseif ($r.What -eq 'dependency provider') {
            [void](Add-PlanItem -Category 'MsiDependency' -Level 2 -Target (Format-RegPath $r.Hive $r.Path) -Action 'delete key' -Evidence "dependency provider for $pc (a leftover one can block a reinstall)" -Op (New-RegOp -Kind 'RegDeleteKey' -Hive $r.Hive -Path $r.Path))
        } else {
            $scope = if ($r.Hive -eq 'HKU') { "user:$($r.Path.Split('\')[0])" } else { 'machine' }
            [void](Add-PlanItem -Category 'MsiProduct' -Level 2 -Scope $scope -Target (Format-RegPath $r.Hive $r.Path) -Action 'delete key' -Evidence "Windows Installer $($r.What) for $pc" -Op (New-RegOp -Kind 'RegDeleteKey' -Hive $r.Hive -Path $r.Path))
        }
    }
    if ($ourComponents.Count) {
        $shared = 0
        foreach ($c in $ourComponents) { if (@(Get-OtherComponentClients $componentIndex $c.Component $packedPc).Count) { $shared++ } }
        [void](Add-PlanItem -Category 'MsiComponentClient' -Level 2 -Target "$($ourComponents.Count) component registration(s) under Installer\UserData\*\Components" `
                -Action "delete OUR client value from each; a component key goes only when no other client is left ($shared are shared and keep their key)" `
                -Evidence "components registered to $pc" -Op ([ordered]@{ kind = 'MsiComponentClients'; packedPc = $packedPc; entries = @($ourComponents | ForEach-Object { [ordered]@{ sid = $_.Sid; component = $_.Component } }) }))
    }
    $folders = Open-Key 'HKLM64' 'SOFTWARE\Microsoft\Windows\CurrentVersion\Installer\Folders'
    foreach ($f in (Get-ValueNamesSafe $folders)) {
        foreach ($r in $exclusiveRoots) {
            if (Test-PathUnder $f $r) {
                [void](Add-PlanItem -Category 'MsiFolderEntry' -Level 2 -Target "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Installer\Folders : $f" -Action 'delete value' -Evidence "Installer folder reference inside the app's folder $r" `
                        -Op (New-RegOp -Kind 'RegDeleteValue' -Hive 'HKLM64' -Path 'SOFTWARE\Microsoft\Windows\CurrentVersion\Installer\Folders' -ValueName $f))
                break
            }
        }
    }
    Close-Key $folders
    if ($localPackage -and $localPackageExists) {
        [void](Add-PlanItem -Category 'MsiCachedPackage' -Level 2 -Target $localPackage -Action "move to quarantine (exact path from this product's own registration)" -Evidence "cached MSI (LocalPackage) of $pc" `
                -Op ([ordered]@{ kind = 'FileQuarantine'; path = $localPackage; keep = @() }))
    }

    # ---------------------------------------------------------------- level 3: folders and files
    foreach ($r in $roots) {
        if (-not $r.Exists) { continue }
        $owner = @($profiles | Where-Object { Test-PathUnder $r.Path $_.Path } | Select-Object -First 1)
        $scope = if ($owner.Count) { "user:$($owner[0].Sid)" } else { 'machine' }
        if ($r.Shared) {
            foreach ($f in @($script:OurFiles | Where-Object { (Test-PathUnder $_ $r.Path) -and (Test-Path -LiteralPath $_ -PathType Leaf) })) {
                [void](Add-PlanItem -Category 'IdentityFile' -Level 3 -Scope $scope -Target $f -Action 'move to quarantine (the folder is shared and stays)' `
                        -Evidence "this app's own MSI component file, in the shared folder $($r.Path)" -Risk 'high' -Op ([ordered]@{ kind = 'FileQuarantine'; path = $f; keep = @() }))
            }
            continue
        }
        $tag = Get-UserDataTag $r.Path -InstallFolder
        $keepInside = @($script:Kept | Where-Object { Test-PathUnder $_.path $r.Path } | ForEach-Object { $_.path })
        [void](Add-PlanItem -Category 'InstallRoot' -Level 3 -Scope $scope -Target $r.Path -Action 'move to quarantine' `
                -Evidence "app folder ($($r.Why)); $([Math]::Round($tag.SizeBytes / 1MB, 1)) MB, $($tag.Files) file(s)" `
                -Risk $(if ($tag.DocLike -gt 0) { 'high' } else { 'low' }) -Note $(if ($tag.HighRisk) { "this folder may contain user data ($($tag.Reason))" } else { $null }) -Bytes $tag.SizeBytes `
                -Op ([ordered]@{ kind = 'FileQuarantine'; path = $r.Path; keep = $keepInside }))
    }
    foreach ($f in $identityFiles) {
        # Anything under C:\Windows is "needs review" (review 2026-09-26: a repackaged VB6 app can claim
        # MSCOMCTL.OCX under its own component GUID).
        $inWindows = Test-PathUnder $f.Path $env:SystemRoot
        [void](Add-PlanItem -Category 'IdentityFile' -Level 3 -Target $f.Path -Action 'move to quarantine, AFTER everything that loads it is unhooked' -Evidence "key file of our MSI component $($f.Component)" -Risk 'high' `
                -Review:$inWindows -Note $(if ($inWindows) { 'needs review: a file under C:\Windows that one MSI claims' } else { $null }) -Op ([ordered]@{ kind = 'FileQuarantine'; path = $f.Path; keep = @() }))
    }
    if ($pc) {
        $iconDir = Join-Path $env:SystemRoot "Installer\$pc"
        if (Test-Path -LiteralPath $iconDir -PathType Container) {
            [void](Add-PlanItem -Category 'InstallerIconFolder' -Level 3 -Target $iconDir -Action 'move to quarantine' -Evidence "Windows Installer icon cache for $pc (named by the ProductCode)" -Op ([ordered]@{ kind = 'FileQuarantine'; path = $iconDir; keep = @() }))
        }
    }

    # Registry values the MSI itself wrote: EXACT values in their own view, never widened (review
    # 2026-09-26: widening to Software\X\Y planned JavaSoft\Java Runtime Environment, every JRE's key).
    $regExact = @()
    foreach ($cv in $componentRegValues) {
        $kp = $cv.Kp
        if ($kp.Hive -eq 'HKLM') { $regExact += [pscustomobject]@{ Hive = $(if ($kp.Is64) { 'HKLM64' } else { 'HKLM32' }); Key = $kp.Key; Value = $kp.Value; Why = "key path of our MSI component $($cv.Component)" } }
        elseif ($kp.Hive -eq 'HKCU' -and $cv.Sid -ne 'S-1-5-18' -and $loadedSids -contains $cv.Sid) { $regExact += [pscustomobject]@{ Hive = 'HKU'; Key = "$($cv.Sid)\$($kp.Key)"; Value = $kp.Value; Why = "key path of our per-user MSI component $($cv.Component)" } }
    }
    foreach ($row in $msiRegRows) {
        $root = $row[0]; $key = $row[1]; $vname = $row[2]; $comp = $row[3]
        if ($key -match '\[' -or $vname -match '\[' -or $vname -in @('+', '-', '*')) { continue }
        if (-not $msiComponentMap.ContainsKey($comp)) { continue }
        $cid = $msiComponentMap[$comp].Id
        if (Test-IsGuid $cid) {
            $packedComp = ConvertTo-PackedGuid $cid
            if (@(Get-OtherComponentClients $componentIndex $packedComp $packedPc).Count) { continue }
        }
        $view = if ($msiComponentMap[$comp].Is64) { 'HKLM64' } else { 'HKLM32' }
        if ($root -in @('2', '-1')) { $regExact += [pscustomobject]@{ Hive = $view; Key = $key; Value = $vname; Why = "written by the app's MSI (Registry table, component $comp)" } }
        elseif ($root -eq '0') { $regExact += [pscustomobject]@{ Hive = $view; Key = "SOFTWARE\Classes\$key"; Value = $vname; Why = "written by the app's MSI (Registry table, component $comp)" } }
    }
    # Classes\MIME\Database too (2026-10-05): Windows' content-type -> extension map is SHARED. Adobe Reader,
    # Foxit and LibreOffice each write "Extension" under types like application/pdf and the .docx type, which
    # Windows and Office register as well: removing one app must not unmap the type for the rest. A value
    # left there is a harmless mapping.
    $skipRegAreas = '^(?i)(SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall|SOFTWARE\\Classes\\(CLSID|TypeLib|Interface|AppID|Installer|MIME\\Database)|SYSTEM\\)'
    # What other items already remove, by real location: a value inside a key that a COM or shell item
    # deletes whole, or the very value a shell-extension item deletes, is NOT planned a second time. The
    # duplicate made "-Exclude Registry" still lose those values through the other category (lab
    # 2026-09-26, 7-Zip).
    $coveredKeys = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
    $coveredValues = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
    foreach ($i in $script:Items) {
        $ops = @($i.op | Where-Object { $_ })
        if ($ops.Count -eq 1) {
            # One op: the item's target already IS its real location.
            $kind = [string](Get-Prop $ops[0] 'kind')
            if ($kind -eq 'RegDeleteKey') { [void]$coveredKeys.Add([string]$i.target) }
            elseif ($kind -eq 'RegDeleteValue') { [void]$coveredValues.Add([string]$i.target) }
            continue
        }
        # Several ops (a Run value and its StartupApproved twin): each one by its own real location.
        foreach ($o in $ops) {
            $kind = [string](Get-Prop $o 'kind'); $oh = [string](Get-Prop $o 'hive'); $opath = [string](Get-Prop $o 'path')
            if (-not $oh -or -not $opath) { continue }
            if ($kind -eq 'RegDeleteKey') { [void]$coveredKeys.Add((Format-RegPath $oh $opath)) }
            elseif ($kind -eq 'RegDeleteValue') { $on = [string](Get-Prop $o 'name'); [void]$coveredValues.Add("$(Format-RegPath $oh $opath) : $(if ($on) { $on } else { '(default)' })") }
        }
    }
    foreach ($rv in $regExact) {
        $keyNoUser = if ($rv.Hive -eq 'HKU') { $rv.Key.Substring($rv.Key.IndexOf('\') + 1) } else { $rv.Key }
        if ($keyNoUser -match $skipRegAreas) { continue }
        $k = Open-Key $rv.Hive $rv.Key
        if (-not $k) { continue }
        $has = (Get-ValueNamesSafe $k) -contains $rv.Value -or ($rv.Value -eq '' -and $null -ne (Get-ValueSafe $k ''))
        Close-Key $k
        if (-not $has) { continue }
        $where = Format-RegPath $rv.Hive $rv.Key
        $vname = if ($rv.Value) { $rv.Value } else { '(default)' }
        if ($coveredValues.Contains("$where : $vname") -or $coveredValues.Contains("$where : $($rv.Value)")) { continue }
        $up = $where; $inside = $false
        while ($up.Contains('\')) { if ($coveredKeys.Contains($up)) { $inside = $true; break }; $up = $up.Substring(0, $up.LastIndexOf('\')) }
        if ($inside) { continue }
        [void](Add-PlanItem -Category 'MsiRegistryValue' -Level 3 -Scope $(if ($rv.Hive -eq 'HKU') { "user:$($rv.Key.Split('\')[0])" } else { 'machine' }) `
                -Target "$where : $vname" -Action 'delete value; the key goes only if nothing is left in it' -Evidence $rv.Why `
                -Op (New-RegOp -Kind 'RegDeleteValue' -Hive $rv.Hive -Path $rv.Key -ValueName $rv.Value -DeleteKeyIfEmpty -Optional))
    }
    # A vendor\product key is removed WHOLE only when the product part names the app, the vendor part is
    # the app's vendor, and the vendor has nothing else installed.
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
                [void](Add-PlanItem -Category $pd.Cat -Level 3 -Target $full -Action 'move to quarantine' -Evidence "folder named for '$kw' (keyword); $([Math]::Round($tag.SizeBytes / 1MB, 1)) MB" `
                        -Risk 'high' -Note $(if ($tag.HighRisk) { "this folder may contain user data ($($tag.Reason))" } else { $null }) -Bytes $tag.SizeBytes -Op ([ordered]@{ kind = 'FileQuarantine'; path = $full; keep = @() }))
            }
        }
        foreach ($winDir in @((Join-Path $env:SystemRoot 'System32'), (Join-Path $env:SystemRoot 'SysWOW64'))) {
            if (-not (Test-Path -LiteralPath $winDir)) { continue }
            foreach ($d in @(Get-ChildItem -LiteralPath $winDir -Directory -Force -ErrorAction SilentlyContinue | Where-Object { Test-WholeWord $_.Name $kw })) {
                $script:Warnings.Add("Left alone: $($d.FullName) is named for '$kw' but sits in a protected Windows folder. Check it and remove it by hand if it is this app's.")
            }
        }
        $vendorOk = -not $samePublisherOthers.Count
        foreach ($h in @('HKLM64', 'HKLM32')) {
            $sw = Open-Key $h 'SOFTWARE'
            foreach ($n in (Get-SubKeyNamesSafe $sw)) {
                if ($n -match '^(?i)(Microsoft|Classes|Policies|WOW6432Node|Clients|RegisteredApplications|Wow6432Node)$') { continue }
                if (Test-WholeWord $n $kw) {
                    if (-not $vendorOk -and -not (Test-WholeWord $targetName $n)) { continue }
                    # A keyword only NARROWS: a whole top-level key goes by default only when its own
                    # contents point at the app (its folder, its files, its ProductCode). Otherwise it
                    # could be a product with no uninstall entry that shares the name (review 2026-09-26).
                    $confirm = Get-KeyAppReference $h "SOFTWARE\$n" $pc
                    [void](Add-PlanItem -Category 'VendorRegistryKey' -Level 3 -Target (Format-RegPath $h "SOFTWARE\$n") -Action 'delete key' `
                            -Evidence $(if ($confirm) { "key named for '$kw' (keyword), and $confirm" } else { "key named for '$kw' (keyword) only" }) -Risk 'high' `
                            -Review:(-not $confirm) -Note $(if (-not $confirm) { 'needs review: nothing in the key points at the app' } else { $null }) `
                            -Op (New-RegOp -Kind 'RegDeleteKey' -Hive $h -Path "SOFTWARE\$n"))
                    continue
                }
                # SOFTWARE\<vendor>\<product>: the vendor must be the app's vendor.
                if ((Test-SameVendor $n $publisher) -or (Test-SameVendor $n $signerOrg) -or (Test-WholeWord $publisher $n)) {
                    $vk = $null; try { $vk = $sw.OpenSubKey($n, $false) } catch { }
                    foreach ($p2 in (Get-SubKeyNamesSafe $vk)) {
                        if (Test-WholeWord $p2 $kw) {
                            [void](Add-PlanItem -Category 'VendorRegistryKey' -Level 3 -Target (Format-RegPath $h "SOFTWARE\$n\$p2") -Action 'delete key' -Evidence "key $n\${p2}: the app's vendor and name" -Risk 'high' `
                                    -Op (New-RegOp -Kind 'RegDeleteKey' -Hive $h -Path "SOFTWARE\$n\$p2"))
                            # Its twin in the other registry view, removed if it appears by the time the run gets
                            # there: Firefox's own uninstaller CREATES WOW6432Node\Mozilla\Firefox while it runs, so a
                            # scan before it never saw the key and it outlived the run (lab rerun, 2026-10-05). The
                            # same name rule matches it; it only didn't exist yet. Absent then = skipped.
                            $twin = if ($h -eq 'HKLM64') { 'HKLM32' } else { 'HKLM64' }
                            $tk = Open-Key $twin "SOFTWARE\$n\$p2"
                            if ($tk) { Close-Key $tk }
                            elseif ((Get-KeyNativePath $twin 'SOFTWARE') -ne (Get-KeyNativePath $h 'SOFTWARE')) {
                                [void](Add-PlanItem -Category 'VendorRegistryKey' -Level 3 -Target (Format-RegPath $twin "SOFTWARE\$n\$p2") -Action 'delete key if the uninstaller writes it' `
                                        -Evidence "the other registry view of $n\$p2 (the app's vendor and name)" -Risk 'high' -Op (New-RegOp -Kind 'RegDeleteKey' -Hive $twin -Path "SOFTWARE\$n\$p2" -Optional))
                            }
                        }
                    }
                    Close-Key $vk
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
                    if (Get-ProtectedPathReason $f $containerProtected $treeProtected) { continue }
                    $tag = Get-UserDataTag $f
                    [void](Add-PlanItem -Category 'AppDataFolder' -Level 3 -Scope "user:$($pr.Sid)" -Target $f -Action 'move to quarantine (AppData is its own opt-in)' `
                            -Evidence "per-user folder named for '$kw' (keyword); $([Math]::Round($tag.SizeBytes / 1MB, 1)) MB" -Risk $(if ($tag.HighRisk) { 'high' } else { 'low' }) `
                            -Note $(if ($tag.HighRisk) { "this folder may contain user data ($($tag.Reason))" } else { $null }) -Bytes $tag.SizeBytes -Op ([ordered]@{ kind = 'FileQuarantine'; path = $f; keep = @() }))
                }
                $usw = Open-Key 'HKU' "$($pr.Sid)\Software"
                foreach ($n in (Get-SubKeyNamesSafe $usw)) {
                    if ($n -match '^(?i)(Microsoft|Classes|Policies|Wow6432Node)$') { continue }
                    if (Test-WholeWord $n $kw) {
                        if (-not $vendorOk -and -not (Test-WholeWord $targetName $n)) { continue }
                        $confirm = Get-KeyAppReference 'HKU' "$($pr.Sid)\Software\$n" $pc
                        [void](Add-PlanItem -Category 'UserRegistryKey' -Level 3 -Scope "user:$($pr.Sid)" -Target "HKU\$($pr.Sid)\Software\$n" -Action 'delete key' `
                                -Evidence $(if ($confirm) { "key named for '$kw' (keyword), and $confirm" } else { "key named for '$kw' (keyword) only" }) -Risk 'high' `
                                -Review:(-not $confirm) -Note $(if (-not $confirm) { 'needs review: nothing in the key points at the app' } else { $null }) `
                                -Op (New-RegOp -Kind 'RegDeleteKey' -Hive 'HKU' -Path "$($pr.Sid)\Software\$n"))
                    }
                }
                Close-Key $usw
            } else {
                $offline += [pscustomobject][ordered]@{ user = $pr.User; sid = $pr.Sid; profile = $pr.Path; roaming = $pr.Roaming; appDataFound = @($found); perUserInstall = ($offlineUserInstalls -contains $pr.Sid) }
            }
        }
    } else {
        foreach ($pr in $profiles | Where-Object { -not $_.Loaded }) {
            $offline += [pscustomobject][ordered]@{ user = $pr.User; sid = $pr.Sid; profile = $pr.Path; roaming = $pr.Roaming; appDataFound = @(); perUserInstall = ($offlineUserInstalls -contains $pr.Sid) }
        }
    }
    $fslogix = $false
    $fk = Open-Key 'HKLM64' 'SOFTWARE\FSLogix\Profiles'
    if ((Get-ValueSafe $fk 'Enabled') -eq 1) { $fslogix = $true }
    Close-Key $fk

    # ---------------------------------------------------------------- profiles: reviewed per-app knowledge
    # A profile (profiles\*.psd1) names what an app keeps where identity matching can't see it (a
    # vendor key, a data folder, a per-user settings key). Its items are evidence-tagged like any other
    # and pass the same protected-path, kept-path and user-data rules: a profile can add, never override.
    $usedProfiles = @()
    foreach ($ap in @($AppProfiles | Where-Object { $_ })) {
        $m = $ap.Data.Match
        $fits = $true
        if ($m.ContainsKey('DisplayName') -and -not ($targetName -match $m.DisplayName)) { $fits = $false }
        if ($m.ContainsKey('Publisher') -and -not ($publisher -match $m.Publisher)) { $fits = $false }
        if ($m.ContainsKey('ProductCode') -and -not (@($m.ProductCode) -contains $pc)) { $fits = $false }
        if (-not $fits) { continue }
        $usedProfiles += "$($ap.Data.Name) ($(Split-Path $ap.File -Leaf))"
        foreach ($it in @($ap.Data.Items)) {
            $why = "profile $($ap.Data.Name): $($it.Why)"
            $asUserData = ($it.ContainsKey('UserData') -and $it.UserData)
            switch ([string]$it.Kind) {
                'MachineRegistryKey' {
                    $hive = if ($it.ContainsKey('View') -and [int]$it.View -eq 32) { 'HKLM32' } else { 'HKLM64' }
                    $p = ([string]$it.Path) -replace '^(?i)(HKLM|HKEY_LOCAL_MACHINE)\\', ''
                    if ($p -match $script:ProtectedRegistry) { $script:Warnings.Add("Profile $($ap.Data.Name): $p is a protected registry area; left alone."); continue }
                    $k = Open-Key $hive $p
                    if (-not $k) { continue }
                    Close-Key $k
                    if (Test-PlannedTarget (Format-RegPath $hive $p)) { continue }
                    [void](Add-PlanItem -Category 'VendorRegistryKey' -Level 3 -Target (Format-RegPath $hive $p) -Action 'delete key' -Evidence $why -Risk 'high' -Op (New-RegOp -Kind 'RegDeleteKey' -Hive $hive -Path $p))
                }
                'MachineFolder' {
                    $full = Get-NormalizedPath ([string]$it.Path)
                    if (-not $full -or -not (Test-Path -LiteralPath $full)) { continue }
                    $pr2 = Get-ProtectedPathReason $full $containerProtected $treeProtected
                    if ($pr2) { $script:Warnings.Add("Profile $($ap.Data.Name): $full left alone ($pr2)."); continue }
                    if (@($script:Kept | Where-Object { Test-PathUnder $_.path $full }).Count) { Add-Kept $full "named by profile $($ap.Data.Name), but another product uses a path inside it"; continue }
                    if (Test-PlannedTarget $full) { continue }
                    $tg = Get-UserDataTag $full
                    [void](Add-PlanItem -Category 'ProgramDataFolder' -Level 3 -Target $full -Action 'move to quarantine' -Evidence $why -Risk 'high' `
                            -Note $(if ($tg.HighRisk) { "this folder may contain user data ($($tg.Reason))" } else { $null }) -Bytes $tg.SizeBytes -Op ([ordered]@{ kind = 'FileQuarantine'; path = $full; keep = @() }))
                }
                'Service' {
                    $svcName = [string]$it.Name
                    if ($ourServiceNames -contains $svcName) { continue }
                    $s = @($services | Where-Object { $_.Name -eq $svcName })
                    if (-not $s.Count) { continue }
                    $isDrv = [bool]($s[0].Type -band 0xB)
                    if ($isDrv) { $script:Warnings.Add("Profile $($ap.Data.Name): $svcName is a driver; profiles only name services, drivers need identity evidence."); continue }
                    [void](Add-PlanItem -Category 'Service' -Level 3 -Target "service $svcName '$($s[0].DisplayName)'" -Action 'stop, disable, delete service' -Evidence $why -Risk 'high' `
                            -Op ([ordered]@{ kind = 'ServiceDelete'; name = $svcName; isDriver = $false; bootStart = $false; image = $s[0].Image; quarantineImage = $false }))
                }
                'UserRegistryKey' {
                    $rel = ([string]$it.Path) -replace '^(?i)(HKCU|HKEY_CURRENT_USER)\\', ''
                    if ($rel -match '^(?i)Software\\(Microsoft|Classes|Policies)(\\|$)') { $script:Warnings.Add("Profile $($ap.Data.Name): HKCU\$rel is a protected registry area; left alone."); continue }
                    foreach ($pr in @($profiles | Where-Object { $_.Loaded })) {
                        $k = Open-Key 'HKU' "$($pr.Sid)\$rel"
                        if (-not $k) { continue }
                        Close-Key $k
                        if (Test-PlannedTarget "HKU\$($pr.Sid)\$rel") { continue }
                        [void](Add-PlanItem -Category $(if ($asUserData) { 'UserDataKey' } else { 'UserRegistryKey' }) -Level 3 -Scope "user:$($pr.Sid)" -Target "HKU\$($pr.Sid)\$rel" `
                                -Action 'delete key' -Evidence $why -Risk 'high' -Op (New-RegOp -Kind 'RegDeleteKey' -Hive 'HKU' -Path "$($pr.Sid)\$rel"))
                    }
                }
                'UserPath' {
                    foreach ($pr in @($profiles | Where-Object { $_.Loaded })) {
                        $full = Get-NormalizedPath (Join-Path $pr.Path ([string]$it.Path))
                        if (-not $full -or -not (Test-Path -LiteralPath $full) -or -not (Test-PathUnder $full (Join-Path $pr.Path 'AppData'))) { continue }
                        if (Get-ProtectedPathReason $full $containerProtected $treeProtected) { continue }
                        if (Test-PlannedTarget $full) { continue }
                        $tg = if (Test-Path -LiteralPath $full -PathType Container) { Get-UserDataTag $full } else { [pscustomobject]@{ SizeBytes = (Get-Item -LiteralPath $full -Force).Length; HighRisk = $false; Reason = '' } }
                        [void](Add-PlanItem -Category 'AppDataFolder' -Level 3 -Scope "user:$($pr.Sid)" -Target $full -Action 'move to quarantine (AppData is its own opt-in)' -Evidence $why `
                                -Risk $(if ($tg.HighRisk) { 'high' } else { 'low' }) -Note $(if ($tg.HighRisk) { "this folder may contain user data ($($tg.Reason))" } else { $null }) -Bytes $tg.SizeBytes `
                                -Op ([ordered]@{ kind = 'FileQuarantine'; path = $full; keep = @() }))
                    }
                }
                default { $script:Warnings.Add("Profile $($ap.Data.Name): unknown item kind '$($it.Kind)' ignored.") }
            }
        }
    }

    # ---------------------------------------------------------------- pre-flight: sizes per volume (quarantine is same-volume)
    $perVolume = @{}
    foreach ($i in $script:Items) {
        if (-not $i.op -or ($i.op -is [System.Collections.IDictionary] -and $i.op.kind -ne 'FileQuarantine')) { continue }
        if ($i.op -isnot [System.Collections.IDictionary]) { continue }
        $t = [string]$i.op.path
        $vol = $t.Substring(0, [Math]::Min(2, $t.Length)).ToUpperInvariant()
        $bytes = [long]0
        if ($null -ne $i.bytes) { $bytes = [long]$i.bytes }
        else { try { if (Test-Path -LiteralPath $t -PathType Leaf) { $bytes = (Get-Item -LiteralPath $t -Force).Length } elseif (Test-Path -LiteralPath $t -PathType Container) { $bytes = (Get-UserDataTag $t).SizeBytes } } catch { } }
        if ($perVolume.ContainsKey($vol)) { $perVolume[$vol] += $bytes } else { $perVolume[$vol] = $bytes }
    }
    $preflight = @()
    foreach ($vol in $perVolume.Keys) {
        $free = $null
        try { $free = (New-Object System.IO.DriveInfo ($vol + '\')).AvailableFreeSpace } catch { }
        $preflight += [pscustomobject][ordered]@{ volume = $vol; bytesToQuarantine = $perVolume[$vol]; freeBytes = $free; quarantine = (Get-QuarantineRoot $runId $vol) }
    }

    # ---------------------------------------------------------------- warnings
    if ($isMsi -and $localPackage -and -not $localPackageExists) { $script:Warnings.Add("The cached MSI is MISSING ($localPackage): msiexec /x will fail (1612). That is what level 2 is for.") }
    if (-not $roots.Count) { $script:Warnings.Add('No usable install folder was found; nothing is matched by path, only by registration.') }
    foreach ($rr in $refusedRoots) { $script:Warnings.Add("Folder $($rr.Path) is NOT used ($($rr.Why)); it came from $($rr.From).") }
    if ($offline.Count) { $script:Warnings.Add("$($offline.Count) signed-out profile(s) are NOT cleaned (their registry hives are never loaded). Re-run while they are signed in.") }
    if ($offlineUserInstalls.Count) { $script:Warnings.Add("$($offlineUserInstalls.Count) signed-out user(s) have their OWN per-user install of this product; it is left alone until they sign in.") }
    if ($fslogix) { $script:Warnings.Add('FSLogix profiles are enabled: signed-out users'' per-user state lives in their profile containers.') }
    if ($samePublisherOthers.Count) { $script:Warnings.Add("$publisher has other products installed ($(@($samePublisherOthers | Select-Object -First 5) -join ', ')): vendor-level folders and keys are left alone.") }
    foreach ($e in $script:MsiReadErrors) { $script:Warnings.Add("The cached MSI could not be fully read: $e") }
    foreach ($a in $script:Unreadable.Keys) { $script:Warnings.Add("$($script:Unreadable[$a]) unreadable $a entr$(if ($script:Unreadable[$a] -eq 1) { 'y' } else { 'ies' }); the report may miss items there.") }
    if (@($script:Items | Where-Object { $_.category -eq 'DeviceInstanceFilter' }).Count) { $script:Warnings.Add('Removing a per-device filter needs SYSTEM (Enum keys are read-only to administrators): run it through your RMM agent or PsExec -s.') }
    $script:Warnings.Add('SharedDLLs reference counts are not changed (a wrong decrement breaks a third product). Any counts for this app''s files are a known, harmless leak.')

    $planBase.identity = [ordered]@{
        roots = @($roots | ForEach-Object { [ordered]@{ path = $_.Path; exists = $_.Exists; shared = $_.Shared; sharedWhy = $_.SharedWhy; from = $_.Why } })
        refusedRoots = @($refusedRoots | ForEach-Object { [ordered]@{ path = $_.Path; reason = $_.Why; from = $_.From } })
        signer = $signerOrg; signerEvidence = @($signerFiles)
        msiComponents = $ourComponents.Count; msiFilesInPackage = $msiFileCount; msiServices = @($msiServiceNames)
        services = @($ourServiceNames); comClasses = $ourClsids.Count; profiles = @($usedProfiles)
    }
    $planBase.keyword = $keywordInfo
    $planBase.items = @($script:Items | Sort-Object level, order, id)
    $planBase.kept = $script:Kept.ToArray()
    $planBase.offlineProfiles = @($offline)
    $planBase.preflight = @($preflight)
    $planBase.warnings = $script:Warnings.ToArray()
    return @{ Code = 0; Plan = $planBase }
}

# =====================================================================================================
# Report
# =====================================================================================================

function Format-Report {
    param($Plan, $Result)
    $sb = New-Object System.Text.StringBuilder
    $line = { param($t) [void]$sb.AppendLine($t) }
    $t = $Plan.target
    & $line "Kill It With Fire $($Plan.version) - $(if ($Result) { "level $($Result.level) run" } else { 'scan (dry run: NOTHING was changed)' })"
    & $line "Computer: $($Plan.computer)    Run: $($Plan.runId)"
    & $line ''
    & $line "Target:    $($t.displayName) $($t.version)"
    & $line "Publisher: $($t.publisher)"
    if ($t.productCode) { & $line "MSI:       ProductCode $($t.productCode)   UpgradeCode $(if ($t.upgradeCode) { $t.upgradeCode } else { '(none found)' })" }
    if ($t.cachedMsi) { & $line "Cached MSI: $($t.cachedMsi) $(if ($t.cachedMsiPresent) { '(present)' } else { '(MISSING)' })" }
    if ($Plan.refused) { & $line ''; & $line "REFUSED: $($Plan.refused)"; return $sb.ToString() }
    foreach ($r in $Plan.identity.roots) { & $line "Folder:    $($r.path)$(if (-not $r.exists) { ' (gone)' })$(if ($r.shared) { ' (SHARED)' })   [from $($r.from)]" }
    if ($Plan.identity.signer) { & $line "Signer:    $($Plan.identity.signer)" }
    if (@(Get-Prop $Plan.identity 'profiles' | Where-Object { $_ }).Count) { & $line "Profile:   $(@($Plan.identity.profiles) -join ', ')" }
    $k = $Plan.keyword
    & $line "Keyword:   $(if ($k.value) { "'$($k.value)' " })$(if ($k.used) { '(used) ' } else { '(NOT used) ' })- $($k.reason)"
    if ($Result) {
        & $line ''
        & $line ("Result:    {0} done, {1} skipped (already gone), {2} need a reboot, {3} failed, {4} not selected" -f $Result.done, $Result.skipped, $Result.pending, $Result.failed, $Result.notSelected)
        if ($Result.uninstall) { & $line "Uninstall: $($Result.uninstall)" }
        if ($Result.stoppedAt) { & $line "STOPPED at item $($Result.stoppedAt): $($Result.error). Nothing after it was touched; -Restore $($Plan.runId) undoes what was done." }
        if ($Result.backup) { & $line "Backup:    $($Result.backup)" } else { & $line 'Backup:    NONE (-NoBackup): this run cannot be restored.' }
    }
    $groups = @(
        @{ Title = 'L2  Registration (a reinstall should work after this; files untouched)'; Filter = { $_.level -eq 2 -and -not $_.optIn } },
        @{ Title = 'L3  Unhook from Windows first (in this order)'; Filter = { $_.level -eq 3 -and $_.order -lt 500 -and -not $_.optIn } },
        @{ Title = 'L3  Files and registry'; Filter = { $_.level -eq 3 -and $_.order -ge 500 -and -not $_.optIn } },
        @{ Title = 'Opt-in: user data (-IncludeUserData)'; Filter = { $_.optIn -and -not $_.review } },
        @{ Title = 'Opt-in: needs review (-IncludeReview)'; Filter = { $_.review } }
    )
    foreach ($g in $groups) {
        $items = @($Plan.items | Where-Object $g.Filter)
        & $line ''
        & $line "$($g.Title): $($items.Count) item(s)"
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
                $status = if ($Result -and $Result.status -and $Result.status.ContainsKey([string]$i.id)) { " <$($Result.status[[string]$i.id])>" } else { '' }
                & $line ("  [{0,-8}] {1}{2}" -f $i.risk, $i.target, $status)
                if ($n -eq $shown - 1) {
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
    foreach ($kp in @($Plan.kept | Select-Object -First 20)) { & $line "  $($kp.path)  - $($kp.reason)" }
    if (@($Plan.kept).Count -gt 20) { & $line "  ... and $(@($Plan.kept).Count - 20) more (all in plan.json)" }
    if (@($Plan.offlineProfiles).Count) {
        & $line ''
        & $line "Signed-out profiles, NOT cleaned (re-run while signed in): $(@($Plan.offlineProfiles).Count)"
        foreach ($o in $Plan.offlineProfiles) { & $line "  $($o.user)$(if ($o.roaming) { ' (roaming)' })$(if ($o.perUserInstall) { ' (has its own per-user install)' })$(if (@($o.appDataFound).Count) { ': ' + (@($o.appDataFound) -join ', ') })" }
    }
    if (@($Plan.warnings).Count) {
        & $line ''
        & $line 'Warnings:'
        foreach ($w in $Plan.warnings) { & $line "  - $w" }
    }
    return $sb.ToString()
}

function Write-PlanFiles {
    param($Plan, [string] $Dir, $Result)
    if (-not (Test-Path -LiteralPath $Dir)) { [void](New-Item -ItemType Directory -Path $Dir -Force) }
    $json = Join-Path $Dir 'plan.json'
    $report = Join-Path $Dir 'report.txt'
    ($Plan | ConvertTo-Json -Depth 10) | Set-Content -LiteralPath $json -Encoding UTF8
    (Format-Report $Plan $Result) | Set-Content -LiteralPath $report -Encoding UTF8
    return [pscustomobject]@{ Json = $json; Report = $report }
}

# =====================================================================================================
# Execution: backup, change, verify, journal. Every change is reversible from the run folder.
# =====================================================================================================

$script:Run = $null

function Get-RunsRoot { return (Join-Path $env:ProgramData 'KillItWithFire\runs') }

function Get-KillItWithFireOwnFolders {
    # Kill It With Fire's own folders: the runs (backups, journals, quarantine for C:), each drive's .killitwithfire
    # quarantine, and the folder the script runs from (its profiles live there).
    $dirs = @((Split-Path (Get-RunsRoot) -Parent), (Split-Path $script:ScriptPath -Parent))
    # [IO.Path]::Combine, not Join-Path: a fixed drive need not be a PowerShell drive (Join-Path throws).
    foreach ($drv in @([System.IO.DriveInfo]::GetDrives() | Where-Object { $_.DriveType -eq 'Fixed' -and $_.IsReady })) { $dirs += [System.IO.Path]::Combine($drv.RootDirectory.FullName, '.killitwithfire') }
    return $dirs
}

function Get-OwnFolderConflict {
    # The own folder a path is inside of, or contains; $null when it touches none.
    param([string] $Path)
    foreach ($sd in @(Get-KillItWithFireOwnFolders)) { if ((Test-PathUnder $Path $sd) -or (Test-PathUnder $sd $Path)) { return $sd } }
    return $null
}

function Get-QuarantineRoot {
    # Same volume as what it holds, so a move is a rename: it can't fail halfway on a full disk.
    param([string] $RunId, [string] $Volume)
    if ($Volume.Equals($env:SystemDrive, [StringComparison]::OrdinalIgnoreCase)) { return (Join-Path (Get-RunsRoot) "$RunId\files\$($Volume.TrimEnd(':'))") }
    return "$Volume\.killitwithfire\$RunId\files"
}

function Invoke-Native {
    # A console tool, its exit code and its text. Its own scope drops ErrorActionPreference to Continue:
    # Windows PowerShell 5.1 turns any stderr line of a redirected native command into a terminating
    # error under 'Stop', which would make a tool's warning look like our failure.
    param([string] $Exe, [string[]] $Arguments)
    $ErrorActionPreference = 'Continue'
    $out = @(& $Exe @Arguments 2>&1 | ForEach-Object { "$_" })
    return [pscustomobject]@{ Code = $LASTEXITCODE; Output = (($out | Where-Object { $_.Trim() }) -join ' ') }
}

function Protect-Folder {
    # Administrators and SYSTEM only: a quarantine can hold license files and users' AppData.
    param([string] $Path)
    $r = Invoke-Native 'icacls.exe' @($Path, '/inheritance:r', '/grant:r', '*S-1-5-18:(OI)(CI)F', '*S-1-5-32-544:(OI)(CI)F')
    if ($r.Code -ne 0) { throw "could not restrict $Path to Administrators and SYSTEM: $($r.Output)" }
}

function Write-RunLog {
    param([string] $Message)
    $stamp = (Get-Date).ToString('yyyy-MM-dd HH:mm:ss')
    if ($script:Run -and $script:Run.LogFile) { try { Add-Content -LiteralPath $script:Run.LogFile -Value "$stamp  $Message" -Encoding UTF8 } catch { } }
    if (-not $Quiet) { Write-Host $Message }
}

function Add-JournalRecord {
    param([hashtable] $Record)
    $script:Run.Seq++
    $Record.seq = $script:Run.Seq
    $Record.time = (Get-Date).ToUniversalTime().ToString('o')
    Add-Content -LiteralPath $script:Run.Journal -Value ($Record | ConvertTo-Json -Compress -Depth 8) -Encoding UTF8
}

function Get-JournalRecords {
    param([string] $Path)
    if (-not (Test-Path -LiteralPath $Path)) { return @() }
    return @(Get-Content -LiteralPath $Path -Encoding UTF8 | Where-Object { $_.Trim() } | ForEach-Object { $_ | ConvertFrom-Json })
}

if (-not ('KillItWithFire.Native' -as [type])) {
    Add-Type -Namespace KillItWithFire -Name Native -MemberDefinition @'
[DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
public static extern bool MoveFileEx(string existingFileName, string newFileName, int flags);
// Remove an (empty) folder at the next boot. A real NULL destination: PowerShell turns $null into "".
public static bool DeleteOnReboot(string path) { return MoveFileEx(path, null, 4); }
// Re-create a service through the API, not sc.exe: an image path with its own quotes ("C:\x y\a.exe" -svc)
// reaches sc.exe mangled from Windows PowerShell 5.1 (lab 2026-09-26: error 1639).
[DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
private static extern IntPtr OpenSCManagerW(string machine, string database, uint access);
[DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
private static extern IntPtr CreateServiceW(IntPtr scm, string name, string display, uint access, uint type, uint start, uint errorControl, string path, string group, IntPtr tagId, string dependencies, string account, string password);
[DllImport("advapi32.dll", SetLastError = true)]
private static extern bool CloseServiceHandle(IntPtr handle);
public static int CreateServiceRaw(string name, string display, uint type, uint start, uint errorControl, string path, string group, string dependencies, string account) {
    IntPtr scm = OpenSCManagerW(null, null, 0x0002);
    if (scm == IntPtr.Zero) { return Marshal.GetLastWin32Error(); }
    try {
        IntPtr svc = CreateServiceW(scm, name, display, 0xF01FF, type, start, errorControl, path, group, IntPtr.Zero, dependencies, account, null);
        if (svc == IntPtr.Zero) { return Marshal.GetLastWin32Error(); }
        CloseServiceHandle(svc);
        return 0;
    } finally { CloseServiceHandle(scm); }
}
[DllImport("ntdll.dll")]
private static extern int NtQueryKey(IntPtr keyHandle, int keyInformationClass, IntPtr keyInformation, int length, out int resultLength);
public static string GetKeyName(IntPtr keyHandle) {
    int len;
    NtQueryKey(keyHandle, 3, IntPtr.Zero, 0, out len);
    if (len <= 4) { return null; }
    IntPtr buf = Marshal.AllocHGlobal(len);
    try {
        if (NtQueryKey(keyHandle, 3, buf, len, out len) != 0) { return null; }
        int nameLen = Marshal.ReadInt32(buf);
        return Marshal.PtrToStringUni(new IntPtr(buf.ToInt64() + 4), nameLen / 2);
    } finally { Marshal.FreeHGlobal(buf); }
}
'@
}
# Its own type, not more members on Native: a session that loaded an older Native keeps it (the type can't
# be reloaded), and would then lack this.
if (-not ('KillItWithFire.Prompt' -as [type])) {
    Add-Type -Namespace KillItWithFire -Name Prompt -MemberDefinition @'
public delegate bool EnumProc(IntPtr hWnd, IntPtr lParam);
[DllImport("user32.dll")] private static extern bool EnumWindows(EnumProc f, IntPtr l);
[DllImport("user32.dll")] private static extern bool EnumChildWindows(IntPtr parent, EnumProc f, IntPtr l);
[DllImport("user32.dll")] private static extern uint GetWindowThreadProcessId(IntPtr h, out uint pid);
[DllImport("user32.dll", CharSet = CharSet.Unicode)] private static extern int GetWindowTextW(IntPtr h, System.Text.StringBuilder s, int n);
[DllImport("user32.dll", CharSet = CharSet.Unicode)] private static extern int GetClassNameW(IntPtr h, System.Text.StringBuilder s, int n);
[DllImport("user32.dll")] private static extern bool IsWindowVisible(IntPtr h);
// A dialog (class #32770: message boxes and most installer prompts) that one of these processes owns and
// that carries a button besides Cancel (a progress window has only Cancel): something waits for a click.
// Returns "title: text [Yes/No]", or null. visible = whether the dialog is on screen at all.
public static string FindPrompt(int[] pids, out bool visible) {
    var set = new System.Collections.Generic.HashSet<uint>();
    foreach (int p in pids) { set.Add((uint)p); }
    string found = null; bool vis = false;
    EnumWindows(delegate (IntPtr h, IntPtr l) {
        uint pid; GetWindowThreadProcessId(h, out pid);
        if (!set.Contains(pid)) { return true; }
        var cls = new System.Text.StringBuilder(64); GetClassNameW(h, cls, 64);
        if (cls.ToString() != "#32770") { return true; }
        var title = new System.Text.StringBuilder(256); GetWindowTextW(h, title, 256);
        var texts = new System.Collections.Generic.List<string>();
        var buttons = new System.Collections.Generic.List<string>();
        EnumChildWindows(h, delegate (IntPtr c, IntPtr l2) {
            var cc = new System.Text.StringBuilder(64); GetClassNameW(c, cc, 64);
            var ct = new System.Text.StringBuilder(1024); GetWindowTextW(c, ct, 1024);
            string t = ct.ToString().Trim();
            if (t.Length == 0) { return true; }
            if (cc.ToString() == "Button") { buttons.Add(t.Replace("&", "")); } else if (cc.ToString() == "Static") { texts.Add(t); }
            return true;
        }, IntPtr.Zero);
        bool waits = false;
        foreach (string b in buttons) { if (!b.Equals("Cancel", StringComparison.OrdinalIgnoreCase)) { waits = true; } }
        if (!waits) { return true; }
        found = (title.Length > 0 ? title.ToString() + ": " : "") + string.Join(" ", texts.ToArray()) + " [" + string.Join("/", buttons.ToArray()) + "]";
        vis = IsWindowVisible(h);
        return false;
    }, IntPtr.Zero);
    visible = vis;
    return found;
}
'@
}
if (-not ('KillItWithFire.Fast' -as [type])) {
    # Compiled loops for the two reads that dominate a scan of a big MSI app (Epic Games Launcher, 2026-10-04):
    # the machine-wide Windows Installer component index (46 s in PowerShell) and the cached package's tables
    # (36 s through late-bound COM, ~1.5 ms a field). Same data, same rules, compiled.
    Add-Type -Namespace KillItWithFire -Name Fast -UsingNamespace System.Collections.Generic, System.Text, Microsoft.Win32 -MemberDefinition @'
public sealed class ComponentClient { public string Sid; public string Component; public string Client; public string KeyPath; }
public sealed class ComponentIndex {
    public List<ComponentClient> All = new List<ComponentClient>();
    public List<ComponentClient> Ours = new List<ComponentClient>();
    public Dictionary<string, List<string>> ByComponent = new Dictionary<string, List<string>>(StringComparer.OrdinalIgnoreCase);
    public int Unreadable;
}
// Every UserData\<sid>\Components\<packed component>: value name = packed client ProductCode ("000...0" = a
// permanent/system client), value data = the key path.
public static ComponentIndex ReadComponentIndex(RegistryKey userData, string packedPc) {
    var ix = new ComponentIndex();
    if (userData == null) { return ix; }
    string[] sids;
    try { sids = userData.GetSubKeyNames(); } catch { ix.Unreadable++; return ix; }
    foreach (string sid in sids) {
        RegistryKey comps = null;
        try { comps = userData.OpenSubKey(sid + "\\Components", false); } catch { ix.Unreadable++; continue; }
        if (comps == null) { continue; }
        using (comps) {
            string[] names;
            try { names = comps.GetSubKeyNames(); } catch { ix.Unreadable++; continue; }
            foreach (string c in names) {
                RegistryKey ck = null;
                try { ck = comps.OpenSubKey(c, false); } catch { ix.Unreadable++; continue; }
                if (ck == null) { continue; }
                using (ck) {
                    try {
                        foreach (string client in ck.GetValueNames()) {
                            if (string.IsNullOrEmpty(client)) { continue; }
                            string cl = client.ToUpperInvariant();
                            object v = ck.GetValue(client, null);
                            var e = new ComponentClient { Sid = sid, Component = c, Client = cl, KeyPath = v == null ? "" : v.ToString() };
                            ix.All.Add(e);
                            List<string> l;
                            if (!ix.ByComponent.TryGetValue(c, out l)) { l = new List<string>(); ix.ByComponent[c] = l; }
                            l.Add(cl);
                            if (string.Equals(cl, packedPc, StringComparison.OrdinalIgnoreCase)) { ix.Ours.Add(e); }
                        }
                    } catch { ix.Unreadable++; }
                }
            }
        }
    }
    return ix;
}
// A registry value as PowerShell's [string] cast shows it: arrays joined with spaces.
static string AsText(object v) {
    if (v == null) { return null; }
    string[] ss = v as string[];
    if (ss != null) { return string.Join(" ", ss); }
    byte[] bs = v as byte[];
    if (bs != null) { var parts = new string[bs.Length]; for (int i = 0; i < bs.Length; i++) { parts[i] = bs[i].ToString(); } return string.Join(" ", parts); }
    return v.ToString();
}
static string DefaultOf(RegistryKey parent, string sub) {
    RegistryKey k = null;
    try { k = parent.OpenSubKey(sub, false); } catch { return null; }
    if (k == null) { return null; }
    using (k) { try { return AsText(k.GetValue("", null)); } catch { return null; } }
}
public sealed class ComClassInfo { public string Clsid; public string AppId; public string InprocServer32; public string LocalServer32; public string InprocHandler32; public string ProgId; }
public sealed class ComClassList { public List<ComClassInfo> Items = new List<ComClassInfo>(); public int Unreadable; }
// Every class under a CLSID key: its AppID and the default values of its server and ProgID subkeys.
public static ComClassList ReadComClasses(RegistryKey clsidRoot) {
    var list = new ComClassList();
    if (clsidRoot == null) { return list; }
    string[] names;
    try { names = clsidRoot.GetSubKeyNames(); } catch { list.Unreadable++; return list; }
    foreach (string clsid in names) {
        RegistryKey ck = null;
        try { ck = clsidRoot.OpenSubKey(clsid, false); } catch { list.Unreadable++; continue; }
        if (ck == null) { continue; }
        using (ck) {
            var info = new ComClassInfo { Clsid = clsid };
            try { info.AppId = AsText(ck.GetValue("AppID", null)); } catch { }
            info.InprocServer32 = DefaultOf(ck, "InprocServer32");
            info.LocalServer32 = DefaultOf(ck, "LocalServer32");
            info.InprocHandler32 = DefaultOf(ck, "InprocHandler32");
            info.ProgId = DefaultOf(ck, "ProgID");
            list.Items.Add(info);
        }
    }
    return list;
}
public sealed class TypeLibInfo { public string TypeLib; public List<string> Paths = new List<string>(); }
public sealed class TypeLibList { public List<TypeLibInfo> Items = new List<TypeLibInfo>(); public int Unreadable; }
// Every type library's file paths: <typelib>\<version>\<lcid>\win32 and \win64, in that order.
public static TypeLibList ReadTypeLibs(RegistryKey tlRoot) {
    var list = new TypeLibList();
    if (tlRoot == null) { return list; }
    string[] names;
    try { names = tlRoot.GetSubKeyNames(); } catch { list.Unreadable++; return list; }
    foreach (string tl in names) {
        RegistryKey tk = null;
        try { tk = tlRoot.OpenSubKey(tl, false); } catch { continue; }
        if (tk == null) { continue; }
        using (tk) {
            var info = new TypeLibInfo { TypeLib = tl };
            string[] vers;
            try { vers = tk.GetSubKeyNames(); } catch { list.Unreadable++; continue; }
            foreach (string ver in vers) {
                RegistryKey vk = null;
                try { vk = tk.OpenSubKey(ver, false); } catch { continue; }
                if (vk == null) { continue; }
                using (vk) {
                    string[] lcids;
                    try { lcids = vk.GetSubKeyNames(); } catch { list.Unreadable++; continue; }
                    foreach (string lcid in lcids) {
                        foreach (string plat in new[] { "win32", "win64" }) {
                            string v = DefaultOf(vk, lcid + "\\" + plat);
                            if (!string.IsNullOrEmpty(v)) { info.Paths.Add(v); }
                        }
                    }
                }
            }
            if (info.Paths.Count > 0) { list.Items.Add(info); }
        }
    }
    return list;
}
// Other products' FILE key paths inside our folders (prefixes end in a backslash).
public static List<ComponentClient> FindClientsUnder(List<ComponentClient> all, string excludeClient, string[] prefixes) {
    var hits = new List<ComponentClient>();
    if (all == null || prefixes == null || prefixes.Length == 0) { return hits; }
    foreach (ComponentClient e in all) {
        if (string.Equals(e.Client, excludeClient, StringComparison.OrdinalIgnoreCase)) { continue; }
        string raw = e.KeyPath;
        if (string.IsNullOrEmpty(raw) || raw.Length < 4 || raw[2] != '\\') { continue; }
        foreach (string p in prefixes) { if (raw.StartsWith(p, StringComparison.OrdinalIgnoreCase)) { hits.Add(e); break; } }
    }
    return hits;
}
[DllImport("msi.dll", CharSet = CharSet.Unicode)] private static extern uint MsiOpenDatabaseW(string path, IntPtr persist, out IntPtr db);
[DllImport("msi.dll", CharSet = CharSet.Unicode)] private static extern uint MsiDatabaseOpenViewW(IntPtr db, string query, out IntPtr view);
[DllImport("msi.dll")] private static extern uint MsiViewExecute(IntPtr view, IntPtr record);
[DllImport("msi.dll")] private static extern uint MsiViewFetch(IntPtr view, out IntPtr record);
[DllImport("msi.dll", CharSet = CharSet.Unicode)] private static extern uint MsiRecordGetStringW(IntPtr record, uint field, StringBuilder value, ref uint chars);
[DllImport("msi.dll")] private static extern uint MsiCloseHandle(IntPtr handle);
// A read-only query of an MSI (MSIDBOPEN_READONLY). A table the package doesn't have is no rows (1615);
// any other failure throws, with the Windows Installer error code in the message.
public static string[][] MsiQuery(string path, string query, int columns) {
    IntPtr db;
    uint r = MsiOpenDatabaseW(path, IntPtr.Zero, out db);
    if (r != 0) { throw new InvalidOperationException("MsiOpenDatabase failed: " + r); }
    var rows = new List<string[]>();
    IntPtr view = IntPtr.Zero;
    try {
        r = MsiDatabaseOpenViewW(db, query, out view);
        if (r == 1615) { return rows.ToArray(); }
        if (r != 0) { throw new InvalidOperationException("MsiDatabaseOpenView failed: " + r); }
        r = MsiViewExecute(view, IntPtr.Zero);
        if (r != 0) { throw new InvalidOperationException("MsiViewExecute failed: " + r); }
        var sb = new StringBuilder(512);
        while (true) {
            IntPtr rec;
            r = MsiViewFetch(view, out rec);
            if (r == 259) { break; }
            if (r != 0) { throw new InvalidOperationException("MsiViewFetch failed: " + r); }
            try {
                var vals = new string[columns];
                for (int i = 1; i <= columns; i++) {
                    uint n = (uint)sb.Capacity;
                    uint g = MsiRecordGetStringW(rec, (uint)i, sb, ref n);
                    if (g == 234) { sb.Capacity = (int)n + 1; n = (uint)sb.Capacity; g = MsiRecordGetStringW(rec, (uint)i, sb, ref n); }
                    vals[i - 1] = g == 0 ? sb.ToString() : "";
                }
                rows.Add(vals);
            } finally { MsiCloseHandle(rec); }
        }
    } finally {
        if (view != IntPtr.Zero) { MsiCloseHandle(view); }
        MsiCloseHandle(db);
    }
    return rows.ToArray();
}
'@
}
if (-not ('KillItWithFire.RegTime' -as [type])) {
    Add-Type -Namespace KillItWithFire -Name RegTime -MemberDefinition @'
[DllImport("advapi32.dll", CharSet = CharSet.Unicode)]
private static extern int RegQueryInfoKeyW(Microsoft.Win32.SafeHandles.SafeRegistryHandle hKey, IntPtr lpClass, IntPtr lpcchClass, IntPtr lpReserved,
    IntPtr lpcSubKeys, IntPtr lpcbMaxSubKeyLen, IntPtr lpcbMaxClassLen, IntPtr lpcValues, IntPtr lpcbMaxValueNameLen, IntPtr lpcbMaxValueLen,
    IntPtr lpcbSecurityDescriptor, out long lpftLastWriteTime);
// When a key last changed (a FILETIME), or 0. Programs and Features shows this as "Installed On" for an app
// that recorded no InstallDate, and so does the window.
public static long LastWriteFileTime(Microsoft.Win32.SafeHandles.SafeRegistryHandle key) {
    long ft;
    return RegQueryInfoKeyW(key, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, out ft) == 0 ? ft : 0;
}
'@
}

function Move-PathOrSchedule {
    # Move now if possible; a file in use is scheduled to move at the next boot (still into the
    # quarantine, so it stays restorable). Returns 'moved' or 'pending'.
    param([string] $Source, [string] $Destination)
    $parent = Split-Path $Destination -Parent
    if (-not (Test-Path -LiteralPath $parent)) { [void](New-Item -ItemType Directory -Path $parent -Force) }
    try {
        if (Test-Path -LiteralPath $Source -PathType Container) { [System.IO.Directory]::Move($Source, $Destination) } else { [System.IO.File]::Move($Source, $Destination) }
        return 'moved'
    } catch {
        if (Test-Path -LiteralPath $Source -PathType Container) { throw }
        if ([KillItWithFire.Native]::MoveFileEx($Source, $Destination, 0x4)) { return 'pending' }
        throw "could not move or schedule $Source ($($_.Exception.Message))"
    }
}

function Move-TreeToQuarantine {
    # Move a folder (or file) into the quarantine, leaving the kept paths in place. A folder whose whole
    # move fails (something inside is in use) is moved file by file, the busy ones at the next boot.
    param([string] $Source, [string] $QuarantineRoot, [string[]] $Keep, [System.Collections.Generic.List[object]] $Moves)
    $dest = [System.IO.Path]::Combine($QuarantineRoot, $Source.Substring(3))
    $keepHere = @($Keep | Where-Object { $_ -and (Test-PathUnder $_ $Source) })
    if ($keepHere | Where-Object { (Get-NormalizedPath $_) -eq (Get-NormalizedPath $Source) }) { return }
    $isDir = Test-Path -LiteralPath $Source -PathType Container
    if (-not $isDir) {
        $r = Move-PathOrSchedule $Source $dest
        $Moves.Add([pscustomobject]@{ src = $Source; dst = $dest; state = $r })
        return
    }
    if (-not $keepHere.Count) {
        try {
            $r = Move-PathOrSchedule $Source $dest
            $Moves.Add([pscustomobject]@{ src = $Source; dst = $dest; state = $r })
            return
        } catch { }
    }
    foreach ($child in @(Get-ChildItem -LiteralPath $Source -Force -ErrorAction Stop)) {
        Move-TreeToQuarantine $child.FullName $QuarantineRoot $keepHere $Moves
    }
    if ($keepHere.Count) { return }
    # Everything inside has moved, or moves at the next boot. The folder itself goes now if it can, and
    # at the next boot if not (a process's current folder, or its contents still waiting on the boot):
    # never silently left behind while the run says "done" (lab 2026-09-26: Notepad++'s running updater).
    $left = @(Get-ChildItem -LiteralPath $Source -Force -ErrorAction SilentlyContinue)
    $waiting = @($Moves | Where-Object { $_.state -in @('pending', 'emptied-pending') -and (Test-PathUnder $_.src $Source) } | ForEach-Object { Get-NormalizedPath $_.src })
    if (@($left | Where-Object { $waiting -notcontains (Get-NormalizedPath $_.FullName) }).Count) { return }
    # The folder itself is removed, so keep its permissions: a restore re-creates it with them.
    $sddl = $null
    try { $sddl = (Get-Acl -LiteralPath $Source).Sddl } catch { }
    [void](New-Item -ItemType Directory -Path $dest -Force)
    # Directory.Delete(non-recursive), not Remove-Item: if a file lands in it meanwhile, this fails cleanly
    # instead of prompting (and a "Yes" deleting it with no quarantine copy). Review 2026-09-26.
    if (-not $left.Count) { try { [System.IO.Directory]::Delete($Source, $false) } catch { } }
    if (-not (Test-Path -LiteralPath $Source)) {
        $Moves.Add([pscustomobject]@{ src = $Source; dst = $dest; state = 'emptied'; sddl = $sddl })
    } elseif ([KillItWithFire.Native]::DeleteOnReboot($Source)) {
        # Boot-time operations run in the order they were scheduled: its contents first, then the folder.
        $Moves.Add([pscustomobject]@{ src = $Source; dst = $dest; state = 'emptied-pending'; sddl = $sddl })
    } else { throw "could not remove the emptied folder $Source, or schedule its removal at the next boot" }
}

function Export-RegValueBackup {
    # One value (with its key header) to a .reg file; $Keys may add further values/keys.
    param([string] $Hive, [string] $Path, [string[]] $Names, [string] $File)
    $k = Open-Key $Hive $Path
    $vals = @()
    foreach ($n in $Names) {
        if ($null -eq $k) { break }
        if (-not ((Get-ValueNamesSafe $k) -contains $n) -and -not ($n -eq '' -and $null -ne (Get-ValueSafe $k ''))) { continue }
        $kind = $k.GetValueKind($n).ToString()
        $data = $k.GetValue($n, $null, [Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames)
        $vals += @{ Name = $n; Kind = $kind; Data = $data }
    }
    Close-Key $k
    $text = ConvertTo-RegFileText @(@{ Path = (Get-PhysicalRegPath $Hive $Path); Values = $vals })
    [System.IO.File]::WriteAllText($File, $text, [System.Text.Encoding]::Unicode)
}

function Export-RegKeyBackup {
    param([string] $Hive, [string] $Path, [string] $File)
    $phys = Get-PhysicalRegPath $Hive $Path
    $r = Invoke-Native 'reg.exe' @('export', $phys, $File, '/y')
    if ($r.Code -ne 0 -or -not (Test-Path -LiteralPath $File)) { throw "reg export of $phys failed: $($r.Output)" }
}

function Get-ProgIdRefs {
    # What a ProgID points at besides its class: DefaultIcon and every shell\<verb>\command, as
    # @{ 'DefaultIcon' = ...; 'shell\open\command' = ... } (only the ones with a value).
    param([string] $Hive, [string] $Path)
    $refs = @{}
    $k = Open-Key $Hive "$Path\DefaultIcon"
    $v = [string](Get-ValueSafe $k ''); Close-Key $k
    if ($v) { $refs['DefaultIcon'] = $v }
    $sh = Open-Key $Hive "$Path\shell"
    foreach ($verb in (Get-SubKeyNamesSafe $sh)) {
        $ck = Open-Key $Hive "$Path\shell\$verb\command"
        $v = [string](Get-ValueSafe $ck ''); Close-Key $ck
        if ($v) { $refs["shell\$verb\command"] = $v }
    }
    Close-Key $sh
    return $refs
}

function ConvertTo-StringMap {
    # A hashtable from a plan's own hashtable, or from the PSCustomObject the same thing reads back as
    # from plan.json.
    param($O)
    $h = @{}
    if ($null -eq $O) { return $h }
    if ($O -is [System.Collections.IDictionary]) { foreach ($k in $O.Keys) { $h[[string]$k] = [string]$O[$k] } }
    else { foreach ($p in $O.PSObject.Properties) { $h[$p.Name] = [string]$p.Value } }
    return $h
}

function Test-KeyExpectation {
    param([string] $Hive, [string] $Path, $Expect)
    if (-not $Expect) { return $true }
    $k = Open-Key $Hive "$Path\$($Expect.sub)"
    $v = [string](Get-ValueSafe $k '')
    Close-Key $k
    if ($v.Trim()) {
        # Any of our classes that share this ProgID (values), or the one (value) on an older plan.
        $ours = @(Get-Prop $Expect 'values' | Where-Object { $_ })
        if (-not $ours.Count) { $ours = @([string]$Expect.value) }
        foreach ($c in $ours) { if ($v.Trim().Equals(([string]$c).Trim(), [StringComparison]::OrdinalIgnoreCase)) { return $true } }
        return $false
    }
    # The CLSID link is gone: the app's own uninstaller took it and left the rest of the ProgID behind
    # (Foxit PDF Reader's four FoxitReader.* keys, lab sweep 2026-10-03). Still ours only when the scan saw
    # every command and icon in it pointing at the app (orphanRefs), and nothing new has moved in since.
    $refs = Get-Prop $Expect 'orphanRefs'
    if ($null -eq $refs) { return $false }
    $seen = ConvertTo-StringMap $refs
    $now = Get-ProgIdRefs $Hive $Path
    foreach ($sub in @($now.Keys)) {
        if (-not $seen.ContainsKey($sub) -or -not ([string]$seen[$sub]).Equals([string]$now[$sub], [StringComparison]::OrdinalIgnoreCase)) { return $false }
    }
    return $true
}

function Invoke-ScExe {
    param([string[]] $Arguments)
    return (Invoke-Native 'sc.exe' $Arguments)
}

function Invoke-PrimitiveOp {
    # One change: back up, do it, verify, journal. Returns 'done', 'skipped' or 'pending'; throws on failure.
    param([int] $ItemId, $Op, [string] $Category)
    $kind = [string]$Op.kind
    $bk = $script:Run.Backups
    $tag = "{0:D4}-{1:D2}" -f $ItemId, ($script:Run.Seq + 1)
    $rec = @{ itemId = $ItemId; category = $Category; kind = $kind; op = $Op; backup = $null; result = $null; note = $null }
    # Get-Prop, not dot access: an op read back from a plan file is a PSCustomObject that simply lacks the
    # fields it never had, and strict mode throws on those (a -Plan run died on 'expect', lab 2026-09-26).
    $optional = [bool](Get-Prop $Op 'optional')
    # A change that fails part way (a key tree half deleted, a folder half moved) is still journaled, as
    # 'partial', before the error goes up: -Restore can only undo what the journal knows about.
    try {
    switch ($kind) {
        'RegDeleteKey' {
            $k = Open-Key $Op.hive $Op.path
            if (-not $k) { $rec.result = 'skipped'; break }
            Close-Key $k
            $expect = Get-Prop $Op 'expect'
            if ($expect -and -not (Test-KeyExpectation $Op.hive $Op.path $expect)) { $rec.result = 'skipped'; $rec.note = 'no longer points at our class'; break }
            if ($script:Run.Backup) { $f = Join-Path $bk "$tag.reg"; Export-RegKeyBackup $Op.hive $Op.path $f; $rec.backup = $f }
            $parentPath, $leaf = Split-RegPath ([string]$Op.path)
            $parent = Open-Key $Op.hive $parentPath -Writable
            if (-not $parent) { throw "parent key not found: $(Format-RegPath $Op.hive $parentPath)" }
            try {
                # Something else may be deleting inside the same tree at the same moment: Google's updater cleans
                # up HKLM\SOFTWARE\Google\Chrome right after Chrome's own uninstaller, a subkey vanishes mid-walk,
                # and .NET throws "subkey does not exist" even with throwOnMissingSubKey off (lab rerun,
                # 2026-10-05: the run stopped there). Gone is the goal, so walk it again.
                for ($try = 1; ; $try++) {
                    try { $parent.DeleteSubKeyTree($leaf, $false); break }
                    catch {
                        $still = Open-Key $Op.hive $Op.path
                        if (-not $still) { break }
                        Close-Key $still
                        if ($try -ge 5) { throw }
                        Start-Sleep -Milliseconds 500
                    }
                }
            } finally { Close-Key $parent }
            if (Open-Key $Op.hive $Op.path) { throw "key still present: $(Format-RegPath $Op.hive $Op.path)" }
            $rec.result = 'done'
        }
        'RegDeleteValue' {
            $k = Open-Key $Op.hive $Op.path
            $has = $k -and (((Get-ValueNamesSafe $k) -contains $Op.name) -or ($Op.name -eq '' -and $null -ne (Get-ValueSafe $k '')))
            Close-Key $k
            if (-not $has) { $rec.result = 'skipped'; break }
            if ($script:Run.Backup) { $f = Join-Path $bk "$tag.reg"; Export-RegValueBackup $Op.hive $Op.path @($Op.name) $f; $rec.backup = $f }
            $k = Open-Key $Op.hive $Op.path -Writable
            try {
                $k.DeleteValue($Op.name, $false)
                $delKey = [bool](Get-Prop $Op 'deleteKeyIfEmpty')
                $empty = ($k.ValueCount -eq 0 -and $k.SubKeyCount -eq 0)
            } finally { Close-Key $k }
            if ($delKey -and $empty) {
                $pp, $leaf = Split-RegPath ([string]$Op.path)
                $parent = Open-Key $Op.hive $pp -Writable
                if ($parent) {
                    try { $parent.DeleteSubKey($leaf, $false) } finally { Close-Key $parent }
                    $rec.note = 'the key was left empty and was removed too'
                }
            }
            $rec.result = 'done'
        }
        { $_ -in @('RegRemoveMultiSzEntry', 'RegRemoveListEntry', 'RegSetValue') } {
            $k = Open-Key $Op.hive $Op.path
            $exists = $k -and ((Get-ValueNamesSafe $k) -contains $Op.name)
            $old = if ($exists) { $k.GetValue($Op.name, $null, [Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames) } else { $null }
            $oldKind = if ($exists) { $k.GetValueKind($Op.name) } else { [Microsoft.Win32.RegistryValueKind]::String }
            Close-Key $k
            if (-not $exists -and $kind -ne 'RegSetValue') { $rec.result = 'skipped'; break }
            if ($script:Run.Backup) { $f = Join-Path $bk "$tag.reg"; Export-RegValueBackup $Op.hive $Op.path @($Op.name) $f; $rec.backup = $f; $rec.valueExisted = $exists }
            $k = Open-Key $Op.hive $Op.path -Writable
            try {
                if ($kind -eq 'RegRemoveMultiSzEntry') {
                    $new = @(@($old) | Where-Object { $_ -and -not $_.Equals([string]$Op.entry, [StringComparison]::OrdinalIgnoreCase) })
                    if ($new.Count -eq @($old).Count) { $rec.result = 'skipped'; $rec.note = 'entry already gone'; break }
                    if ($new.Count) { $k.SetValue($Op.name, [string[]]$new, [Microsoft.Win32.RegistryValueKind]::MultiString) } else { $k.DeleteValue($Op.name, $false) }
                } elseif ($kind -eq 'RegRemoveListEntry') {
                    $new = Remove-ListEntry ([string]$old) ([string]$Op.entry) ([string]$Op.separator)
                    if ($new -eq [string]$old) { $rec.result = 'skipped'; $rec.note = 'entry already gone'; break }
                    $floor = [string](Get-Prop $Op 'floor'); $floorMatch = [string](Get-Prop $Op 'floorMatch')
                    if ($floor -and $floorMatch -and $new -notmatch $floorMatch) {
                        $rest = $new.Trim().Trim(',').Trim()
                        $new = if ($rest) { $floor.TrimEnd(',') + ',' + $new.Trim().TrimStart(',') } else { $floor }
                        $rec.note = "Windows' own '$floor' put back in"
                    }
                    $k.SetValue($Op.name, $new, $oldKind)
                } else {
                    $k.SetValue($Op.name, $Op.setData, [Microsoft.Win32.RegistryValueKind]::$([string]$Op.setKind))
                }
            } finally { Close-Key $k }
            if (-not $rec.result) { $rec.result = 'done' }
        }
        'MsiComponentClients' {
            $keys = @(); $done = 0
            foreach ($e in @($Op.entries)) {
                $p = "SOFTWARE\Microsoft\Windows\CurrentVersion\Installer\UserData\$($e.sid)\Components\$($e.component)"
                $k = Open-Key 'HKLM64' $p
                if (-not $k -or -not ((Get-ValueNamesSafe $k) -contains $Op.packedPc)) { Close-Key $k; continue }
                $keys += @{ Path = (Get-PhysicalRegPath 'HKLM64' $p); Values = @(@{ Name = $Op.packedPc; Kind = 'String'; Data = [string]$k.GetValue($Op.packedPc) }) }
                Close-Key $k
            }
            if (-not $keys.Count) { $rec.result = 'skipped'; break }
            if ($script:Run.Backup) { $f = Join-Path $bk "$tag.reg"; [System.IO.File]::WriteAllText($f, (ConvertTo-RegFileText $keys), [System.Text.Encoding]::Unicode); $rec.backup = $f }
            foreach ($e in @($Op.entries)) {
                $p = "SOFTWARE\Microsoft\Windows\CurrentVersion\Installer\UserData\$($e.sid)\Components\$($e.component)"
                $k = Open-Key 'HKLM64' $p -Writable
                if (-not $k) { continue }
                try {
                    if ((Get-ValueNamesSafe $k) -contains $Op.packedPc) { $k.DeleteValue($Op.packedPc, $false); $done++ }
                    $empty = ($k.ValueCount -eq 0 -and $k.SubKeyCount -eq 0)
                } finally { Close-Key $k }
                if ($empty) {
                    $pp, $leaf = Split-RegPath $p
                    $parent = Open-Key 'HKLM64' $pp -Writable
                    if ($parent) { try { $parent.DeleteSubKey($leaf, $false) } finally { Close-Key $parent } }
                }
            }
            $rec.note = "$done client value(s) removed"
            $rec.result = 'done'
        }
        'ServiceDelete' {
            $k = Open-Key 'HKLM64' "SYSTEM\CurrentControlSet\Services\$($Op.name)"
            if (-not $k) {
                # Already gone: `netcfg -u` deletes a network component's driver service itself, but it
                # leaves the driver's .sys file behind (Npcap, lab 2026-09-29: npcap.sys stayed in
                # System32\drivers after a "skipped"). Still quarantine the file; restore then puts back
                # only the file, since this run never deleted the service.
                $rec.serviceAbsent = $true
                if ($Op.quarantineImage -and $Op.image -and (Test-Path -LiteralPath $Op.image -PathType Leaf) -and $script:Run.Backup) {
                    $vol = ([string]$Op.image).Substring(0, 2)
                    $dst = [System.IO.Path]::Combine((Get-QuarantineRoot $script:Run.RunId $vol), ([string]$Op.image).Substring(3))
                    $state = Move-PathOrSchedule $Op.image $dst
                    $rec.moves = @([pscustomobject]@{ src = $Op.image; dst = $dst; state = $state })
                    $rec.result = if ($state -eq 'pending') { 'pending' } else { 'done' }
                } elseif ($Op.quarantineImage -and $Op.image -and (Test-Path -LiteralPath $Op.image -PathType Leaf)) {
                    try { Remove-Item -LiteralPath $Op.image -Force -ErrorAction Stop; $rec.result = 'done' }
                    catch { if ([KillItWithFire.Native]::DeleteOnReboot([string]$Op.image)) { $rec.result = 'pending' } else { throw "could not delete $($Op.image) now or at the next boot" } }
                } else { $rec.result = 'skipped' }
                break
            }
            $rec.startOriginal = [int](0 + (Get-ValueSafe $k 'Start')); $rec.typeOriginal = [int](0 + (Get-ValueSafe $k 'Type'))
            $rec.imageRaw = [string]($k.GetValue('ImagePath', $null, [Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames))
            # What CreateService needs to bring it back as it was (the .reg backup restores the rest).
            $rec.errorControl = [int](0 + (Get-ValueSafe $k 'ErrorControl')); $rec.displayName = [string](Get-ValueSafe $k 'DisplayName')
            $rec.objectName = [string](Get-ValueSafe $k 'ObjectName'); $rec.group = [string](Get-ValueSafe $k 'Group')
            $rec.dependOnService = @(Get-ValueSafe $k 'DependOnService' | Where-Object { $_ })
            Close-Key $k
            $q = Invoke-ScExe @('query', $Op.name)
            $rec.wasRunning = ($q.Output -match 'RUNNING')
            if ($script:Run.Backup) { $f = Join-Path $bk "$tag.reg"; Export-RegKeyBackup 'HKLM64' "SYSTEM\CurrentControlSet\Services\$($Op.name)" $f; $rec.backup = $f }
            $pending = $false
            if (-not $Op.bootStart -and $rec.wasRunning) {
                [void](Invoke-ScExe @('stop', $Op.name))
                for ($i = 0; $i -lt 30; $i++) { if ((Invoke-ScExe @('query', $Op.name)).Output -match 'STOPPED') { break }; Start-Sleep -Seconds 1 }
                if ((Invoke-ScExe @('query', $Op.name)).Output -notmatch 'STOPPED') { $pending = $true }
            }
            [void](Invoke-ScExe @('config', $Op.name, 'start=', 'disabled'))
            $d = Invoke-ScExe @('delete', $Op.name)
            if ($d.Code -ne 0 -and $d.Code -ne 1072) { throw "sc delete $($Op.name) failed ($($d.Code)): $($d.Output)" }
            if ($Op.bootStart -or $d.Code -eq 1072 -or $pending -or (Invoke-ScExe @('query', $Op.name)).Code -eq 0) { $pending = $true }
            if ($Op.quarantineImage -and $Op.image -and (Test-Path -LiteralPath $Op.image -PathType Leaf)) {
                if ($script:Run.Backup) {
                    $vol = ([string]$Op.image).Substring(0, 2)
                    $dst = [System.IO.Path]::Combine((Get-QuarantineRoot $script:Run.RunId $vol), ([string]$Op.image).Substring(3))
                    $state = Move-PathOrSchedule $Op.image $dst
                    $rec.moves = @([pscustomobject]@{ src = $Op.image; dst = $dst; state = $state })
                    if ($state -eq 'pending') { $pending = $true }
                } else {
                    # -NoBackup: deleted like every other file in such a run (the driver may still be loaded:
                    # then it goes at the next boot).
                    try { Remove-Item -LiteralPath $Op.image -Force -ErrorAction Stop }
                    catch { if ([KillItWithFire.Native]::DeleteOnReboot([string]$Op.image)) { $pending = $true } else { throw "could not delete $($Op.image) now or at the next boot" } }
                }
            }
            $rec.result = if ($pending) { 'pending' } else { 'done' }
        }
        'NetcfgUninstall' {
            $exportDir = $null
            if ($Op.inf -and $script:Run.Backup) {
                $exportDir = Join-Path $script:Run.Root "drivers\$($Op.inf)"
                [void](New-Item -ItemType Directory -Force -Path $exportDir)
                $o = Invoke-Native 'pnputil.exe' @('/export-driver', [string]$Op.inf, $exportDir)
                if ($o.Code -ne 0) { throw "pnputil /export-driver $($Op.inf) failed ($($o.Code)): $($o.Output)" }
                $rec.backup = $exportDir
            } elseif ($script:Run.Backup) { throw "no driver package known for $($Op.componentId): refusing to remove it without a way back" }
            $o = Invoke-Native 'netcfg.exe' @('-u', [string]$Op.componentId)
            # 0x0004A020 = NETCFG_S_REBOOT.
            if ($o.Code -eq 0) { $rec.result = 'done' }
            elseif ($o.Code -eq 0x0004A020 -or $o.Output -match '(?i)reboot') { $rec.result = 'pending' }
            else { throw "netcfg -u $($Op.componentId) failed ($($o.Code)): $($o.Output)" }
        }
        'DriverPackageDelete' {
            if (-not (Test-Path -LiteralPath (Join-Path $env:SystemRoot "INF\$($Op.inf)"))) { $rec.result = 'skipped'; break }
            if ($script:Run.Backup) {
                $exportDir = Join-Path $script:Run.Root "drivers\$($Op.inf)"
                if (-not (Test-Path -LiteralPath $exportDir) -or -not @(Get-ChildItem -LiteralPath $exportDir -Recurse -Filter *.inf -ErrorAction SilentlyContinue).Count) {
                    [void](New-Item -ItemType Directory -Force -Path $exportDir)
                    $o = Invoke-Native 'pnputil.exe' @('/export-driver', [string]$Op.inf, $exportDir)
                    if ($o.Code -ne 0) { throw "pnputil /export-driver $($Op.inf) failed ($($o.Code)): $($o.Output)" }
                }
                $rec.backup = $exportDir
            }
            $o = Invoke-Native 'pnputil.exe' @('/delete-driver', [string]$Op.inf, '/uninstall')
            if ($o.Code -eq 0) { $rec.result = 'done' } elseif ($o.Code -eq 3010) { $rec.result = 'pending' } else { throw "pnputil /delete-driver $($Op.inf) failed ($($o.Code)): $($o.Output)" }
        }
        'TaskUnregister' {
            $t = Get-ScheduledTask -TaskPath $Op.taskPath -TaskName $Op.taskName -ErrorAction SilentlyContinue
            if (-not $t) { $rec.result = 'skipped'; break }
            if ($script:Run.Backup) { $f = Join-Path $script:Run.Root "tasks\$tag.xml"; Export-ScheduledTask -TaskPath $Op.taskPath -TaskName $Op.taskName | Set-Content -LiteralPath $f -Encoding Unicode; $rec.backup = $f }
            Unregister-ScheduledTask -TaskPath $Op.taskPath -TaskName $Op.taskName -Confirm:$false -ErrorAction Stop
            $rec.result = 'done'
        }
        'FirewallRuleDelete' {
            $r = Get-NetFirewallRule -Name $Op.id -ErrorAction SilentlyContinue
            if (-not $r) { $rec.result = 'skipped'; break }
            if ($script:Run.Backup) {
                $app = ($r | Get-NetFirewallApplicationFilter -ErrorAction SilentlyContinue); $port = ($r | Get-NetFirewallPortFilter -ErrorAction SilentlyContinue)
                $svc = ($r | Get-NetFirewallServiceFilter -ErrorAction SilentlyContinue)
                $b = [ordered]@{ Name = $r.Name; DisplayName = $r.DisplayName; Description = $r.Description; Group = $r.Group; Direction = [string]$r.Direction; Action = [string]$r.Action
                    Enabled = [string]$r.Enabled; Profile = [string]$r.Profile; Program = $(if ($app) { $app.Program } else { $null }); Service = $(if ($svc) { $svc.Service } else { $null })
                    Protocol = $(if ($port) { [string]$port.Protocol } else { $null }); LocalPort = $(if ($port) { @($port.LocalPort) } else { $null }); RemotePort = $(if ($port) { @($port.RemotePort) } else { $null }) }
                $f = Join-Path $bk "$tag.firewall.json"; ($b | ConvertTo-Json -Depth 4) | Set-Content -LiteralPath $f -Encoding UTF8; $rec.backup = $f
            }
            Remove-NetFirewallRule -Name $Op.id -ErrorAction Stop
            $rec.result = 'done'
        }
        'FileQuarantine' {
            # Never Kill It With Fire's own folders, whatever a plan says (a plan file is only JSON on disk).
            $own = Get-OwnFolderConflict ([string]$Op.path)
            if ($own) { throw "refusing to move $($Op.path): it is or holds Kill It With Fire's own folder $own" }
            if (-not (Test-Path -LiteralPath $Op.path)) { $rec.result = 'skipped'; break }
            if (-not $script:Run.Backup) {
                if (Test-Path -LiteralPath $Op.path -PathType Container) { Remove-TreeLongPath ([string]$Op.path) } else { Remove-Item -LiteralPath $Op.path -Force -ErrorAction Stop }
                if (Test-Path -LiteralPath $Op.path) { throw "could not delete $($Op.path) (something in it is in use)" }
                $rec.result = 'done'; $rec.note = 'deleted (no backup)'
                break
            }
            $vol = ([string]$Op.path).Substring(0, 2)
            $qroot = Get-QuarantineRoot $script:Run.RunId $vol
            if (-not (Test-Path -LiteralPath $qroot)) {
                [void](New-Item -ItemType Directory -Path $qroot -Force)
                $top = if ($vol -eq $env:SystemDrive) { $script:Run.Root } else { "$vol\.killitwithfire" }
                Protect-Folder $top
                if ($top -like '*\.killitwithfire') { try { (Get-Item -LiteralPath $top -Force).Attributes = 'Hidden, Directory' } catch { } }
            }
            $moves = New-Object System.Collections.Generic.List[object]
            try { Move-TreeToQuarantine ([string]$Op.path) $qroot @($Op.keep) $moves } finally { $rec.moves = $moves.ToArray() }
            $rec.result = if (@($moves | Where-Object { $_.state -in @('pending', 'emptied-pending') }).Count) { 'pending' } else { 'done' }
        }
        'ServiceRestart' {
            try { Restart-Service -Name $Op.name -Force -ErrorAction Stop; $rec.result = 'done' } catch { $rec.result = 'done'; $rec.note = "restart failed: $($_.Exception.Message)" }
        }
        'ProcessStop' {
            # Found again by image path: the PIDs from the scan are long gone by now.
            $ancestors = Get-ProcessAncestry
            $procs = @(Get-Process -ErrorAction SilentlyContinue | Where-Object { -not $ancestors.Contains($_.Id) } | Where-Object { $ip = $null; try { $ip = $_.Path } catch { }; $ip -and $ip.Equals([string]$Op.path, [StringComparison]::OrdinalIgnoreCase) })
            if (-not $procs.Count) { $rec.result = 'skipped'; $rec.note = 'not running'; break }
            $stopped = @(); $failedStop = @()
            foreach ($p in $procs) { try { Stop-Process -Id $p.Id -Force -ErrorAction Stop; $stopped += $p.Id } catch { $failedStop += "$($p.Id) ($($_.Exception.Message))" } }
            foreach ($p in $procs) { try { [void]$p.WaitForExit(10000) } catch { } }
            # One that can't be stopped doesn't stop the run: its files then move at the next boot instead.
            $rec.note = "stopped pid(s) $($stopped -join ', ')$(if ($failedStop.Count) { '; could not stop ' + ($failedStop -join ', ') })"
            $rec.result = 'done'
        }
        default { throw "unknown operation '$kind'" }
    }
    } catch {
        $rec.result = 'partial'
        $rec.note = $_.Exception.Message
        Add-JournalRecord $rec
        throw
    }
    if (-not $rec.result) { $rec.result = 'done' }
    if ($rec.result -eq 'skipped' -and -not $optional -and -not $rec.note) { $rec.note = 'already gone' }
    Add-JournalRecord $rec
    return $rec.result
}

# ---- Level 1: the app's own uninstaller -----------------------------------------------------------
# Which engine built an uninstaller, from structural markers in its first 4 MB. A PORT of the RFF agent's
# InstallerFingerprint.cs: the same markers, searched in the same order, and the same switches. Keep the
# two in step. The markers are what the build tools always emit, not marketing text.
$script:InstallerEngineMarkers = @(
    @('WixBurn', '.wixburn'), @('Nsis', 'NullsoftInst'), @('Nsis', 'Nullsoft Install System'),
    @('InnoSetup', 'Inno Setup Setup Data'), @('InnoSetup', 'JR.Inno.Setup'),
    @('InstallShield', 'InstallShield'), @('InstallAware', 'InstallAware'))
$script:EngineUninstallArgs = @{
    Nsis = '/S'; InstallShield = '-s'; InstallAware = '/s'
    InnoSetup = '/VERYSILENT /SUPPRESSMSGBOXES /NORESTART'; WixBurn = '/uninstall /quiet /norestart'
}
# Per-product rules, a PORT of the agent's SilentRules table (DeployOrchestrator.cs), each one measured on
# a real machine there. Checked before the engine markers, as the agent does, and only against an
# UninstallString: a vendor's own QuietUninstallString is trusted as written. Keep the two in step.
# (The agent's Visual Studio rule is left out: Microsoft software is refused before level 1 runs.)
$script:NamedUninstallRules = @(
    # Citrix: "bootstrapperhelper.exe /uninstall /cleanup" prompts; /silent first silences it.
    @{ Name = 'Citrix Workspace'; Inject = '/silent' },
    @{ Name = 'Citrix Receiver'; Inject = '/silent' },
    # AnyDesk: "AnyDesk.exe --uninstall" prompts; this replaces it.
    @{ Name = 'AnyDesk'; Override = '--silent --remove' },
    # Google Drive: a bare uninstall.exe exits 0 WITHOUT uninstalling while GoogleDriveFS.exe runs.
    @{ Name = 'Google Drive'; Override = '--silent --force_stop' },
    # NOT from the agent's table: Squirrel.Windows apps (Discord, Slack, GitHub Desktop) uninstall through
    # "Update.exe --uninstall", which prompts nothing but shows progress; -s is Squirrel's silent switch.
    @{ ExeName = 'Update.exe'; ArgsMatch = '(?i)--uninstall\b'; Append = '-s' }
)

function Get-InstallerEngine {
    # 'Nsis', 'InnoSetup', 'WixBurn', 'InstallShield', 'InstallAware' or 'Unknown'. Never throws: an
    # unreadable file is Unknown, which can only make level 1 skip, never act.
    param([string] $Path)
    try {
        if (-not $Path -or -not (Test-Path -LiteralPath $Path -PathType Leaf)) { return 'Unknown' }
        $fs = [System.IO.File]::Open($Path, 'Open', 'Read', 'ReadWrite, Delete')
        try {
            $len = [int][Math]::Min($fs.Length, 4MB)
            if ($len -lt 64) { return 'Unknown' }
            $buf = New-Object byte[] $len
            $read = 0
            while ($read -lt $len) { $n = $fs.Read($buf, $read, $len - $read); if ($n -le 0) { break }; $read += $n }
        } finally { $fs.Dispose() }
        # Latin-1 maps every byte to one char, so an ASCII marker is a plain ordinal IndexOf.
        $text = [System.Text.Encoding]::GetEncoding(28591).GetString($buf, 0, $read)
        foreach ($m in $script:InstallerEngineMarkers) { if ($text.IndexOf($m[1], [StringComparison]::Ordinal) -ge 0) { return $m[0] } }
        return 'Unknown'
    } catch { return 'Unknown' }
}

function New-UninstallCommand {
    # Every key, always: the script runs under Set-StrictMode, where reading a key a hashtable lacks
    # THROWS (PropertyNotFoundStrict). A result without Skip crashed the first unit test of a healthy app,
    # which is exactly the run that would have hit it next.
    param([string] $Exe, [string] $Arguments, [string] $How, [string] $Skip, [string] $Fail)
    return @{ Exe = $Exe; Args = $Arguments; How = $How; Skip = $Skip; Fail = $Fail }
}

function Get-UninstallCommand {
    # What level 1 runs, as @{ Exe; Args; How }, or @{ Skip = why } / @{ Fail = why }. Silent or nothing:
    # an uninstaller with no known silent switch would sit on a dialog nobody can click (as SYSTEM, for the
    # whole ten-minute timeout), so it is skipped and the scrub does the work.
    param($Target)
    $msiexec = Join-Path $env:SystemRoot 'System32\msiexec.exe'
    if ($Target.isMsi -and $Target.productCode) { return (New-UninstallCommand -Exe $msiexec -Arguments "/x $($Target.productCode) /qn /norestart" -How 'msiexec /x') }
    # A per-user entry's uninstaller acts on whoever runs it, so only that user runs it.
    # Fields added to the plan on 2026-10-03 go through Get-Prop: an older plan.json lacks them, and a direct
    # read throws under strict mode.
    $sid = Get-Prop $Target 'entrySid'; $loc = Get-Prop $Target 'installLocation'
    if ($sid) {
        $me = [Security.Principal.WindowsIdentity]::GetCurrent().User.Value
        if ($me -ne $sid) { return (New-UninstallCommand -Skip "a per-user install ($sid): its uninstaller would run as $([Environment]::UserName) and act on the wrong profile. The scrub removes it.") }
    }
    $from = $null; $line = $null
    if ($Target.quietUninstallString) { $from = 'QuietUninstallString'; $line = [string]$Target.quietUninstallString }
    elseif ($Target.uninstallString) { $from = 'UninstallString'; $line = [string]$Target.uninstallString }
    if (-not $line) { return (New-UninstallCommand -Skip 'no uninstaller is registered') }
    $parts = Split-CommandLine $line
    $exe = $parts[0]; $args0 = [string]$parts[1]
    # "MsiExec.exe /I{GUID}" on an entry not flagged WindowsInstaller: still an MSI, so remove it as one.
    if ((Split-Path $exe -Leaf) -match '^(?i)msiexec(\.exe)?$') {
        $g = [regex]::Match($args0, '\{[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}\}')
        if ($g.Success) { return (New-UninstallCommand -Exe $msiexec -Arguments "/x $($g.Value) /qn /norestart" -How "msiexec /x (from the $from)") }
        return (New-UninstallCommand -Skip "an msiexec $from with no ProductCode in it: $args0")
    }
    if (-not (Test-Path -LiteralPath $exe -PathType Leaf)) { return (New-UninstallCommand -Fail "$exe does not exist (the uninstaller is gone, so the scrub does the work)") }
    if ($from -eq 'UninstallString') {
        foreach ($r in $script:NamedUninstallRules) {
            if ($r.ContainsKey('Name') -and ([string]$Target.displayName).IndexOf($r.Name, [StringComparison]::OrdinalIgnoreCase) -lt 0) { continue }
            if ($r.ContainsKey('ExeName') -and -not (Split-Path $exe -Leaf).Equals($r.ExeName, [StringComparison]::OrdinalIgnoreCase)) { continue }
            if ($r.ContainsKey('ArgsMatch') -and $args0 -notmatch $r.ArgsMatch) { continue }
            $label = $(if ($r.ContainsKey('Name')) { $r.Name } else { $r.ExeName })
            if ($r.ContainsKey('Override')) { return (New-UninstallCommand -Exe $exe -Arguments $r.Override -How "named rule: $label") }
            if ($r.ContainsKey('Inject')) { return (New-UninstallCommand -Exe $exe -Arguments ("$($r.Inject) $args0").Trim() -How "named rule: $label") }
            if ($r.ContainsKey('Append')) {
                $a = $args0
                if ($a -notmatch ('(^|\s)' + [regex]::Escape($r.Append) + '(\s|$)')) { $a = ("$a $($r.Append)").Trim() }
                return (New-UninstallCommand -Exe $exe -Arguments $a -How "named rule: $label")
            }
        }
    }
    $engine = Get-InstallerEngine $exe
    if ($engine -eq 'Nsis') {
        # A bare NSIS uninstaller copies itself to %TEMP%, relaunches DETACHED and exits 0 at once, so the
        # scrub would race the real uninstall (the agent's "DBeaver phantom", 2026-07-01). _?=<dir> runs it
        # IN PLACE and synchronously. It must be LAST and unquoted: NSIS reads it to the end of the line.
        $tokens = @($args0 -split '\s+' | Where-Object { $_ })
        if (-not ($tokens -ccontains '/S')) { $args0 = ("$args0 /S").Trim() }   # case-sensitive: NSIS only knows /S
        if ($args0 -notmatch '(^|\s)_\?=') {
            $dir = Split-Path $exe -Parent
            if ($loc -and (Test-Path -LiteralPath $loc -PathType Container)) { $dir = ([string]$loc).TrimEnd('\') }
            $args0 = "$args0 _?=$dir"
        }
        return (New-UninstallCommand -Exe $exe -Arguments $args0 -How "NSIS, in place (from the $from)")
    }
    # Inno: /SILENT is not silent. TreeSize Free's QuietUninstallString is just "/SILENT", and it sat ten
    # minutes on an invisible "delete your settings too? Yes/No" (lab sweep, 2026-10-03); /SILENT plus
    # /SUPPRESSMSGBOXES STILL asked (measured in the lab). Only /VERYSILENT, the agent's Inno switch, ran it
    # through. /SUPPRESSMSGBOXES answers Inno's own boxes with its documented defaults, and /NORESTART must
    # come with it: one of those defaults is "Yes, restart now".
    $isInno = ($engine -eq 'InnoSetup') -or ((Split-Path $exe -Leaf) -match '^(?i)unins\d+\.exe$')
    if ($isInno -and $args0 -match '(?i)(^|\s)/(VERY)?SILENT\b') {
        $a = $args0
        if ($a -notmatch '(?i)(^|\s)/VERYSILENT\b') { $a = [regex]::Replace($a, '(?i)(^|\s)/SILENT\b', '$1/VERYSILENT') }
        if ($a -notmatch '(?i)(^|\s)/SUPPRESSMSGBOXES\b') { $a += ' /SUPPRESSMSGBOXES' }
        if ($a -notmatch '(?i)(^|\s)/NORESTART\b') { $a += ' /NORESTART' }
        if ($a -ne $args0) { return (New-UninstallCommand -Exe $exe -Arguments $a -How "the $from, made fully silent for Inno (its /SILENT still asks questions)") }
        return (New-UninstallCommand -Exe $exe -Arguments $args0 -How "the $from")
    }
    if ($from -eq 'QuietUninstallString') { return (New-UninstallCommand -Exe $exe -Arguments $args0 -How 'the QuietUninstallString') }
    # An UninstallString: add the engine's silent switch only when it carries none (the agent's rule: never
    # second-guess switches the vendor wrote), and complete WiX Burn's "/uninstall", which alone is interactive.
    if (-not $args0) {
        if ($script:EngineUninstallArgs.ContainsKey($engine)) { return (New-UninstallCommand -Exe $exe -Arguments $script:EngineUninstallArgs[$engine] -How "$engine silent switch") }
        # Inno's uninstaller is always unins000.exe, unins001.exe ... (the agent's name rule, for a stub the markers miss).
        if ((Split-Path $exe -Leaf) -match '^(?i)unins\d+\.exe$') { return (New-UninstallCommand -Exe $exe -Arguments $script:EngineUninstallArgs['InnoSetup'] -How 'InnoSetup silent switch (by file name)') }
    } elseif ($engine -eq 'WixBurn' -and $args0 -match '(?i)(^|\s)[/-]uninstall\b' -and $args0 -notmatch '(?i)(^|\s)[/-](quiet|silent|passive)\b') {
        return (New-UninstallCommand -Exe $exe -Arguments "$args0 /quiet /norestart" -How 'WixBurn silent switch')
    }
    $has = ''
    if ($args0) { $has = ", which already carries: $args0" }
    return (New-UninstallCommand -Skip "no silent switch is known for this uninstaller ($engine engine$has). Run as it is, it would wait for a click, so the scrub does the work.")
}

function Test-UninstallEntryPresent {
    param($Target)
    $hive = Get-Prop $Target 'entryHive'; $path = Get-Prop $Target 'entryKeyPath'
    if (-not $hive -or -not $path) { return $false }
    $k = Open-Key $hive $path
    if ($k) { Close-Key $k; return $true }
    return $false
}

function Get-ProcessTreeSince {
    # A process and everything it started, by parent id. A child outlives its parent and keeps the parent's
    # id as its ParentProcessId: that is how Inno's _unins.tmp and NSIS's Au_.exe are found once the
    # uninstaller that started them is gone. One created before the root is a reused id, never a child.
    param([int] $Root, [datetime] $Since)
    $all = @(Get-CimInstance Win32_Process -ErrorAction SilentlyContinue)
    $ids = New-Object 'System.Collections.Generic.HashSet[int]'
    [void]$ids.Add($Root)
    $grew = $true
    while ($grew) {
        $grew = $false
        foreach ($q in $all) {
            if ($ids.Contains([int]$q.ParentProcessId) -and $q.CreationDate -ge $Since -and $ids.Add([int]$q.ProcessId)) { $grew = $true }
        }
    }
    return @($all | Where-Object { $ids.Contains([int]$_.ProcessId) })
}

function Test-PromptUnseen {
    # Can anyone answer a prompt? Not one that is off screen, and not anything on session 0 (an RMM or
    # SYSTEM run), where no one sees anything. One a signed-in user can see is theirs to answer.
    param([bool] $Visible, [bool] $Interactive, [int] $Session)
    return (-not $Visible) -or (-not $Interactive) -or ($Session -eq 0)
}

function Stop-ProcessTreeSince {
    # The newest first, so nothing is left re-parented and running.
    param($Tree)
    foreach ($q in @($Tree | Sort-Object CreationDate -Descending)) { try { Stop-Process -Id ([int]$q.ProcessId) -Force -ErrorAction Stop } catch { } }
}

function Wait-Uninstaller {
    # Level 1's wait: the uninstaller, then (after a clean exit) what it left running and its own uninstall
    # entry, because Inno's second phase and NSIS's Au_.exe do the work in a copy and the scrub must not race
    # them. Gives up EARLY on a prompt nobody can answer: a dialog with a button besides Cancel, unseen
    # (Test-PromptUnseen), while the whole tree has used no CPU for IdleSec. Waiting longer cannot help, and
    # TreeSize Free's sat the full ten minutes on one (lab sweep, 2026-10-03).
    # Returns @{ Stopped = why it was stopped, or $null; Note = what the scrub should know, or $null }.
    param($Process, $Target, [int] $CeilingSec = 600, [int] $AfterSec = 90, [int] $IdleSec = 60, [int] $PollSec = 2,
        [scriptblock] $IsUnseen = { param($v) Test-PromptUnseen -Visible $v -Interactive ([Environment]::UserInteractive) -Session ((Get-Process -Id $PID).SessionId) })
    $since = try { $Process.StartTime.AddSeconds(-1) } catch { (Get-Date).AddSeconds(-5) }
    $start = Get-Date
    $cleanExit = $null
    $idleSince = $null; $lastCpu = -1.0
    while ($true) {
        $tree = @(Get-ProcessTreeSince $Process.Id $since)
        $exited = $Process.HasExited
        $running = @($tree | Where-Object { [int]$_.ProcessId -ne $Process.Id -or -not $exited })
        if ($exited -and -not $cleanExit) {
            if ($Process.ExitCode -notin @(0, 3010)) { return @{ Stopped = $null; Note = $null } }
            $cleanExit = Get-Date
        }
        if ($cleanExit) {
            # Its own uninstall entry going is the signal that the work is done (the full AfterSec). What it
            # left running only gets a short grace: an uninstaller may open a survey page in a browser.
            $entry = [bool]($Target -and (Test-UninstallEntryPresent $Target))
            $waited = ((Get-Date) - $cleanExit).TotalSeconds
            if (-not $entry -and (-not $running.Count -or $waited -ge 15)) { return @{ Stopped = $null; Note = $null } }
            if ($waited -ge $AfterSec) {
                $still = if ($running.Count) { " ($(@($running | ForEach-Object { $_.Name } | Select-Object -Unique) -join ', ') still running)" } else { '' }
                return @{ Stopped = $null; Note = "its uninstall entry is still there after $AfterSec s$still, so the scrub removes what is left" }
            }
        } elseif (((Get-Date) - $start).TotalSeconds -ge $CeilingSec) {
            $v = $false
            $pr = [KillItWithFire.Prompt]::FindPrompt([int[]]@($tree | ForEach-Object { [int]$_.ProcessId }), [ref]$v)
            Stop-ProcessTreeSince $tree
            $ceil = if ($CeilingSec % 60) { "$CeilingSec s" } else { "$([int]($CeilingSec / 60)) minutes" }
            return @{ Stopped = "timed out after $ceil$(if ($pr) { "; it was waiting on: $pr" })"; Note = $null }
        }
        $cpu = 0.0
        foreach ($q in $running) { $cpu += ([double]$q.KernelModeTime + [double]$q.UserModeTime) / 1e7 }
        if ($running.Count -and $lastCpu -ge 0 -and [Math]::Abs($cpu - $lastCpu) -lt 0.05) { if (-not $idleSince) { $idleSince = Get-Date } } else { $idleSince = $null }
        $lastCpu = $cpu
        if ($idleSince -and ((Get-Date) - $idleSince).TotalSeconds -ge $IdleSec) {
            $v = $false
            $pr = [KillItWithFire.Prompt]::FindPrompt([int[]]@($running | ForEach-Object { [int]$_.ProcessId }), [ref]$v)
            if ($pr -and (& $IsUnseen $v)) {
                Stop-ProcessTreeSince $tree
                return @{ Stopped = "stopped after $IdleSec s on a prompt nobody can answer: $pr"; Note = $null }
            }
        }
        Start-Sleep -Seconds $PollSec
    }
}

function Invoke-UninstallAttempt {
    # Level 1: the app's own uninstaller, once, silently (Get-UninstallCommand). A broken app is EXPECTED
    # to fail here; the scrub that follows does the rest either way.
    param($Plan)
    $t = $Plan.target
    $c = Get-UninstallCommand $t
    if ($c.Skip) { $res = "skipped: $($c.Skip)" }
    elseif ($c.Fail) { $res = "failed: $($c.Fail)" }
    else {
        Write-RunLog "  level 1 ($($c.How)): $($c.Exe) $($c.Args)"
        $sp = @{ FilePath = $c.Exe; PassThru = $true; WindowStyle = 'Hidden' }
        if ($c.Args) { $sp.ArgumentList = $c.Args }
        $p = Start-Process @sp
        $null = $p.Handle   # keep the handle, or ExitCode can come back empty once the process is gone
        $w = Wait-Uninstaller -Process $p -Target $t
        if ($w.Stopped) { $res = "failed: $($w.Stopped)" }
        else {
            $code = $p.ExitCode
            $res = "exit $code$(switch ($code) { 0 { ' (uninstalled)' } 3010 { ' (uninstalled, reboot needed)' } 1605 { ' (not installed as far as Windows Installer knows)' } 1612 { ' (the installation source is gone: broken, as expected)' } default { '' } })"
            if ($w.Note) { $res += "; $($w.Note)" }
        }
    }
    $cmdText = $null
    if ($c.Exe) { $cmdText = "$($c.Exe) $($c.Args)" }
    Add-JournalRecord @{ itemId = 0; category = 'Uninstall'; kind = 'UninstallAttempt'; op = @{ command = $cmdText; how = $c.How }; result = 'done'; note = $res }
    return $res
}

function Select-PlanItems {
    # The items a run acts on: at or below the level, in the chosen categories, opt-ins only when asked,
    # report-only items never.
    param($Plan, [int] $Level, [string[]] $IncludeGroups, [string[]] $ExcludeGroups, [bool] $UserData, [bool] $Review)
    $sel = @()
    foreach ($i in @($Plan.items)) {
        if ($i.level -gt $Level -or $Level -lt 2) { continue }
        if ($null -eq $i.op) { continue }
        if ($IncludeGroups -and $IncludeGroups.Count -and -not ($IncludeGroups -contains $i.group)) { continue }
        if ($ExcludeGroups -and ($ExcludeGroups -contains $i.group)) { continue }
        if ($i.group -eq 'UserData' -and -not $UserData -and -not ($IncludeGroups -contains 'UserData')) { continue }
        if ($i.review -and -not $Review) { continue }
        $sel += $i
    }
    return @($sel | Sort-Object order, id)
}

function Invoke-PlanExecution {
    param($Plan, [int] $Level, [string[]] $IncludeGroups, [string[]] $ExcludeGroups, [bool] $UserData, [bool] $Review, [bool] $Backup, [bool] $DoUninstall, [string] $LogFile, [int] $KeepDays)
    $runId = $Plan.runId
    $root = Join-Path (Get-RunsRoot) $runId
    foreach ($d in @($root, (Join-Path $root 'backups'), (Join-Path $root 'tasks'), (Join-Path $root 'drivers'))) { [void](New-Item -ItemType Directory -Force -Path $d) }
    Protect-Folder (Split-Path $root -Parent)
    $script:Run = [pscustomobject]@{ RunId = $runId; Root = $root; Backups = (Join-Path $root 'backups'); Journal = (Join-Path $root 'journal.jsonl'); Seq = 0; Backup = $Backup; LogFile = $LogFile }
    $selected = Select-PlanItems $Plan $Level $IncludeGroups $ExcludeGroups $UserData $Review
    $meta = [ordered]@{
        runId = $runId; tool = $script:ToolVersion; computer = $env:COMPUTERNAME; app = $Plan.target.displayName; productCode = $Plan.target.productCode
        level = $Level; backup = $Backup; started = (Get-Date).ToUniversalTime().ToString('o'); finished = $null; status = 'running'; items = @($selected).Count
        keepDays = $KeepDays; log = $LogFile
    }
    ($meta | ConvertTo-Json -Depth 4) | Set-Content -LiteralPath (Join-Path $root 'run.json') -Encoding UTF8
    Write-PlanFiles $Plan $root | Out-Null
    Remove-OldRuns $KeepDays
    Write-RunLog "Kill It With Fire $script:ToolVersion - level $Level run $runId for '$($Plan.target.displayName)' on $env:COMPUTERNAME ($(@($selected).Count) item(s); backup $(if ($Backup) { 'on' } else { 'OFF' }))"

    $status = @{}
    $result = [ordered]@{ level = $Level; done = 0; skipped = 0; pending = 0; failed = 0; notSelected = @($Plan.items).Count - @($selected).Count; stoppedAt = $null; error = $null; uninstall = $null; backup = $(if ($Backup) { $root } else { $null }); status = $status }
    if ($Level -ge 1 -and $DoUninstall) { $result.uninstall = Invoke-UninstallAttempt $Plan; Write-RunLog "  uninstall: $($result.uninstall)" }
    foreach ($item in $selected) {
        $ops = @($item.op)
        $itemResult = 'skipped'
        try {
            foreach ($op in $ops) {
                $r = Invoke-PrimitiveOp $item.id $op $item.category
                if ($r -eq 'pending') { $itemResult = 'pending' } elseif ($r -eq 'done' -and $itemResult -ne 'pending') { $itemResult = 'done' }
            }
        } catch {
            $status[[string]$item.id] = 'FAILED'
            $result.failed++
            $result.stoppedAt = $item.id; $result.error = "$($item.target): $($_.Exception.Message)"
            Add-JournalRecord @{ itemId = $item.id; category = $item.category; kind = 'Failure'; op = $null; result = 'failed'; note = $_.Exception.Message }
            Write-RunLog "  FAILED [$($item.category)] $($item.target): $($_.Exception.Message)"
            break
        }
        $status[[string]$item.id] = $itemResult
        switch ($itemResult) { 'done' { $result.done++ } 'pending' { $result.pending++ } default { $result.skipped++ } }
        Write-RunLog ("  {0,-8} [{1}] {2}" -f $itemResult, $item.category, $item.target)
    }
    $meta.finished = (Get-Date).ToUniversalTime().ToString('o')
    $meta.status = if ($result.failed) { 'stopped' } elseif ($result.pending) { 'pending-reboot' } else { 'done' }
    ($meta | ConvertTo-Json -Depth 4) | Set-Content -LiteralPath (Join-Path $root 'run.json') -Encoding UTF8
    ($result | ConvertTo-Json -Depth 5) | Set-Content -LiteralPath (Join-Path $root 'result.json') -Encoding UTF8
    Write-PlanFiles $Plan $root $result | Out-Null
    return $result
}

# =====================================================================================================
# Restore, resume, runs
# =====================================================================================================

function Get-RunList {
    $root = Get-RunsRoot
    if (-not (Test-Path -LiteralPath $root)) { return @() }
    return @(Get-ChildItem -LiteralPath $root -Directory -ErrorAction SilentlyContinue | ForEach-Object {
            $f = Join-Path $_.FullName 'run.json'
            if (Test-Path -LiteralPath $f) { try { Get-Content -LiteralPath $f -Raw -Encoding UTF8 | ConvertFrom-Json } catch { } }
        } | Where-Object { $_ } | Sort-Object started -Descending)
}

function Remove-TreeLongPath {
    # A quarantine keeps the original paths under runs\<id>\files\<drive>, so its deepest files can pass
    # 260 characters, which Remove-Item on Windows PowerShell 5.1 can't delete. rd with the \\?\ form can.
    param([string] $Path)
    if (-not (Test-Path -LiteralPath $Path)) { return }
    [void](Invoke-Native 'cmd.exe' @('/d', '/c', 'rd', '/s', '/q', ('\\?\' + $Path)))
    if (Test-Path -LiteralPath $Path) { Write-RunLog "  (could not fully remove $Path)" }
}

function Remove-OldRuns {
    # A run's backup is kept N days (policy or -QuarantineDays; 14 by default), never while it still
    # waits on a reboot. Purged runs are gone for good: say so in the log.
    param([int] $Days)
    if ($Days -le 0) { return }
    foreach ($r in Get-RunList) {
        if (-not $r.finished -or $r.status -in @('pending-reboot', 'running')) { continue }
        $age = (Get-Date).ToUniversalTime() - (ConvertTo-UtcDate $r.finished)
        if ($age.TotalDays -lt $Days) { continue }
        Remove-TreeLongPath (Join-Path (Get-RunsRoot) $r.runId)
        foreach ($d in [System.IO.DriveInfo]::GetDrives() | Where-Object { $_.DriveType -eq 'Fixed' -and $_.IsReady }) {
            $q = [System.IO.Path]::Combine($d.RootDirectory.FullName, '.killitwithfire', [string]$r.runId)
            if (Test-Path -LiteralPath $q) { Remove-TreeLongPath $q }
        }
        Write-RunLog "  purged run $($r.runId) ($($r.app), $([int]$age.TotalDays) days old)"
    }
}

function ConvertFrom-PendingRenameEntry {
    # "\??\C:\x" -> "C:\x". Windows 11 build 26100+ writes "*1\??\C:\x" (a number of its own), and a
    # destination can start with "!" (replace existing).
    param([string] $Entry)
    return [regex]::Replace($Entry, '^(\*\d+)?!?(\\\?\?\\)?', '')
}

function Clear-PendingMove {
    # Take our own entries back out of PendingFileRenameOperations (a restore before the reboot).
    param([string] $Source)
    $k = Open-Key 'HKLM64' 'SYSTEM\CurrentControlSet\Control\Session Manager' -Writable
    try {
        $raw = $k.GetValue('PendingFileRenameOperations', $null)
        if ($null -eq $raw) { return }
        $v = @($raw)
        $out = New-Object System.Collections.Generic.List[string]
        for ($i = 0; $i + 1 -lt $v.Count; $i += 2) {
            # Entries look like "\??\C:\x", and on Windows 11 build 26100+ like "*1\??\C:\x" (the number
            # is Windows' own; the destination may also carry "!" for replace-existing).
            $srcPath = ConvertFrom-PendingRenameEntry ([string]$v[$i])
            if ($srcPath.Equals($Source, [StringComparison]::OrdinalIgnoreCase)) { continue }
            $out.Add($v[$i]); $out.Add($v[$i + 1])
        }
        if ($out.Count) { $k.SetValue('PendingFileRenameOperations', [string[]]$out.ToArray(), [Microsoft.Win32.RegistryValueKind]::MultiString) } else { $k.DeleteValue('PendingFileRenameOperations', $false) }
    } finally { Close-Key $k }
}

function Invoke-RegImport {
    param([string] $File)
    $o = Invoke-Native 'reg.exe' @('import', $File)
    if ($o.Code -ne 0) { throw "reg import $File failed: $($o.Output)" }
}

function Invoke-KillItWithFireRestore {
    param([string] $RunId, [bool] $Confirmed)
    $root = Join-Path (Get-RunsRoot) $RunId
    $metaFile = Join-Path $root 'run.json'
    if (-not (Test-Path -LiteralPath $metaFile)) { Write-Host "No run $RunId under $(Get-RunsRoot). -ListRuns shows the runs that can be restored."; return 3 }
    $meta = Get-Content -LiteralPath $metaFile -Raw -Encoding UTF8 | ConvertFrom-Json
    if (-not $meta.backup) { Write-Host "Run $RunId was made with -NoBackup: there is nothing to restore it from."; return 2 }
    # Undo newest first. Records a previous (partial) restore already undid are skipped, so running
    # -Restore again after a reboot finishes the job instead of tripping over its own earlier work.
    $restoreJournal = Join-Path $root 'restore.jsonl'
    $undone = @{}
    foreach ($u in @(Get-JournalRecords $restoreJournal | Where-Object { $_.result -eq 'done' -and (Get-Prop $_ 'undoOf') })) { $undone[[string]$u.undoOf] = $true }
    $records = @(Get-JournalRecords (Join-Path $root 'journal.jsonl') | Where-Object { $_.result -in @('done', 'pending', 'partial') -and $_.kind -notin @('UninstallAttempt', 'Failure') -and $_.kind -notlike 'Resume-*' -and -not $undone.ContainsKey([string]$_.seq) })
    [array]::Reverse($records)
    if (-not $Confirmed) { Write-Host "Restore run $RunId ($($meta.app), level $($meta.level)): $($records.Count) change(s) to undo. Use -Force to confirm."; return 2 }
    $prior = @(Get-JournalRecords $restoreJournal)
    $script:Run = [pscustomobject]@{ RunId = $RunId; Root = $root; Backups = (Join-Path $root 'backups'); Journal = $restoreJournal; Seq = $(if ($prior.Count) { [int]($prior | Measure-Object -Property seq -Maximum).Maximum } else { 0 }); Backup = $false; LogFile = $(if ($meta.log) { $meta.log } else { $null }) }
    Write-RunLog "Restoring run $RunId ($($meta.app), level $($meta.level)): $($records.Count) change(s), newest first"
    $failed = 0; $reboot = $false; $restarts = @(); $deferred = 0; $held = 0; $chainBlocked = $false
    foreach ($r in $records) {
        # A change that failed before it backed anything up or moved anything changed nothing: there is
        # nothing to undo (counting it as a failed restore made a clean restore exit 1).
        if ($r.result -eq 'partial' -and -not (Get-Prop $r 'backup') -and -not @(Get-Prop $r 'moves' | Where-Object { $_ }).Count) {
            Add-JournalRecord @{ itemId = $r.itemId; category = $r.category; kind = "Undo-$($r.kind)"; undoOf = $r.seq; op = $null; result = 'done'; note = 'nothing had changed' }
            continue
        }
        # Logon hooks, device filters, services, network components and drivers (order 300-349) depend on
        # each other and on the app's files. Once anything they could rest on has failed, none of them goes
        # back: a filter or a driver service put back without its file kills a device class at boot.
        $order = [int]$script:Order[[string]$r.category]
        $isChain = $order -ge 300 -and $order -lt 350
        if ($isChain -and $chainBlocked) { $held++; continue }
        # A signed-in user's key is restored into their loaded hive. Once they have signed out it isn't
        # there to restore into: defer it (a rerun while they are signed in finishes it) rather than fail,
        # and never let it hold up the machine-wide changes (review 2026-09-29).
        $sid = if ((Get-Prop $r 'op') -and [string](Get-Prop $r.op 'hive') -eq 'HKU') { ([string]$r.op.path -split '\\')[0] } else { $null }
        if ($sid) {
            $hk = $null
            try { $hk = [Microsoft.Win32.RegistryKey]::OpenBaseKey([Microsoft.Win32.RegistryHive]::Users, [Microsoft.Win32.RegistryView]::Default).OpenSubKey($sid, $false) } catch { }
            if ($null -eq $hk) {
                $deferred++
                Add-JournalRecord @{ itemId = $r.itemId; category = $r.category; kind = "Undo-$($r.kind)"; undoOf = $r.seq; op = $null; result = 'deferred'; note = "user $sid is not signed in" }
                Write-RunLog ("  deferred [{0}] {1}: user {2} is not signed in; run -Restore {3} again while they are" -f $r.category, $r.kind, $sid, $RunId)
                continue
            }
            $hk.Close()
        }
        try {
            switch ($r.kind) {
                { $_ -in @('RegDeleteKey', 'RegDeleteValue', 'RegRemoveMultiSzEntry', 'RegRemoveListEntry', 'RegSetValue', 'MsiComponentClients') } {
                    if (-not $r.backup) { throw 'no backup recorded' }
                    Invoke-RegImport $r.backup
                    # A filter entry put back only joins the device stack when the stack is rebuilt: at boot.
                    # Reporting "complete" here left the filter inactive with no word of it (review 2026-09-29).
                    if ([string]$r.category -in @('DeviceClassFilter', 'DeviceInstanceFilter')) { $reboot = $true }
                    if ($r.kind -eq 'RegSetValue' -and (Get-Prop $r 'valueExisted') -eq $false) {
                        # The value did not exist before: the backup holds only its key, so take it out again.
                        $k = Open-Key $r.op.hive $r.op.path -Writable
                        try { if ($k) { $k.DeleteValue([string]$r.op.name, $false) } } finally { Close-Key $k }
                    }
                }
                'FileQuarantine' {
                    # Parents first: an emptied folder is re-created (with its own permissions) before its
                    # children move back into it.
                    foreach ($m in @(Get-Prop $r 'moves') | Where-Object { $_ } | Sort-Object { $_.src.Length }) {
                        if ($m.state -eq 'pending') {
                            if (Test-Path -LiteralPath $m.dst) { $m.state = 'moved' }
                            else { Clear-PendingMove $m.src; continue }
                        }
                        if ($m.state -eq 'emptied-pending') {
                            # Before the reboot the folder is still there: just cancel its removal.
                            if (Test-Path -LiteralPath $m.src) { Clear-PendingMove $m.src; continue }
                            $m.state = 'emptied'
                        }
                        if ($m.state -eq 'emptied') {
                            if (-not (Test-Path -LiteralPath $m.src)) {
                                [void](New-Item -ItemType Directory -Path $m.src -Force)
                                $sddl = Get-Prop $m 'sddl'
                                if ($sddl) { try { $acl = Get-Acl -LiteralPath $m.src; $acl.SetSecurityDescriptorSddlForm($sddl); Set-Acl -LiteralPath $m.src -AclObject $acl } catch { Write-RunLog "  (could not put back the permissions of $($m.src): $($_.Exception.Message))" } }
                            }
                            continue
                        }
                        if (-not (Test-Path -LiteralPath $m.dst)) {
                            if (Test-Path -LiteralPath $m.src) { continue }
                            throw "quarantined copy missing: $($m.dst)"
                        }
                        if (Test-Path -LiteralPath $m.src) { throw "something new already exists at $($m.src); not overwritten" }
                        $parent = Split-Path $m.src -Parent
                        if (-not (Test-Path -LiteralPath $parent)) { [void](New-Item -ItemType Directory -Path $parent -Force) }
                        if (Test-Path -LiteralPath $m.dst -PathType Container) { [System.IO.Directory]::Move($m.dst, $m.src) } else { [System.IO.File]::Move($m.dst, $m.src) }
                    }
                }
                'ServiceDelete' {
                    foreach ($m in @(Get-Prop $r 'moves') | Where-Object { $_ }) {
                        if ((Test-Path -LiteralPath $m.dst) -and -not (Test-Path -LiteralPath $m.src)) { [System.IO.File]::Move($m.dst, $m.src) }
                        elseif ($m.state -eq 'pending') { Clear-PendingMove $m.src }
                    }
                    # The run only moved the file (something else had already removed the service): the
                    # file is back, and whatever removed the service puts it back (netcfg -l, restored below).
                    if (Get-Prop $r 'serviceAbsent') { break }
                    $name = [string]$r.op.name
                    if ((Invoke-ScExe @('query', $name)).Code -eq 1060) {
                        $deps = @(Get-Prop $r 'dependOnService' | Where-Object { $_ })
                        $account = [string](Get-Prop $r 'objectName')
                        $isDrv = ([int](Get-Prop $r 'typeOriginal') -band 0xB) -ne 0
                        $code = [KillItWithFire.Native]::CreateServiceRaw($name, $(if (Get-Prop $r 'displayName') { [string]$r.displayName } else { $name }),
                            [uint32](Get-Prop $r 'typeOriginal'), [uint32](Get-Prop $r 'startOriginal'), [uint32](Get-Prop $r 'errorControl'), [string](Get-Prop $r 'imageRaw'),
                            $(if (Get-Prop $r 'group') { [string]$r.group } else { [NullString]::Value }),
                            $(if ($deps.Count) { ($deps -join [char]0) + [char]0 } else { [NullString]::Value }),
                            $(if ($account -and -not $isDrv) { $account } else { [NullString]::Value }))
                        if ($code -ne 0) { throw "could not re-create service $name (Windows error $code)" }
                        if ($account -and -not $isDrv -and $account -notmatch '^(?i)(LocalSystem|NT AUTHORITY\\|NT SERVICE\\|\.\\LocalSystem)') {
                            Write-RunLog "  service $name runs as $account again, but its password was not kept: set it before starting the service"
                        }
                    } else {
                        # Still there: either it was never deleted (a partial run), or it is marked for
                        # deletion and only a reboot finishes that.
                        $sk = Open-Key 'HKLM64' "SYSTEM\CurrentControlSet\Services\$name"
                        $marked = ((Get-ValueSafe $sk 'DeleteFlag') -eq 1)
                        Close-Key $sk
                        if ($marked) { $reboot = $true; throw "service $name is marked for deletion until the next reboot: reboot, then run -Restore $RunId again" }
                    }
                    if ($r.backup) { Invoke-RegImport $r.backup }
                    # The service manager ignores registry edits until the next boot: set the start type
                    # through it too (a partial run had already set this service to disabled).
                    $startWord = switch ([int](Get-Prop $r 'startOriginal')) { 0 { 'boot' } 1 { 'system' } 2 { 'auto' } 4 { 'disabled' } default { 'demand' } }
                    [void](Invoke-ScExe @('config', $name, 'start=', $startWord))
                    $started = $false
                    if (Get-Prop $r 'wasRunning') {
                        $st = Invoke-ScExe @('start', $name)
                        $started = $st.Code -in @(0, 1056)
                        if (-not $started) { Write-RunLog "  service $name is back but did not start (sc start: $($st.Code)); start it once whatever it needs is back" }
                    }
                    # A driver that is back but not running (boot/system start, or a filter that only loads
                    # into a stack at boot) needs the reboot to be in effect.
                    if ($r.op.isDriver -and -not $started) { $reboot = $true }
                }
                'NetcfgUninstall' {
                    $inf = @(Get-ChildItem -LiteralPath $r.backup -Recurse -Filter *.inf -ErrorAction Stop | Select-Object -First 1)
                    if (-not $inf.Count) { throw "no exported driver package in $($r.backup)" }
                    [void](Invoke-Native 'pnputil.exe' @('/add-driver', $inf[0].FullName, '/install'))
                    $o = Invoke-Native 'netcfg.exe' @('-l', $inf[0].FullName, '-c', [string]$r.op.netClass, '-i', [string]$r.op.componentId)
                    if ($o.Code -ne 0 -and $o.Code -ne 0x0004A020) { throw "netcfg -l failed ($($o.Code)): $($o.Output)" }
                    if ($o.Code -eq 0x0004A020) { $reboot = $true }
                }
                'DriverPackageDelete' {
                    $inf = @(Get-ChildItem -LiteralPath $r.backup -Recurse -Filter *.inf -ErrorAction Stop | Select-Object -First 1)
                    if (-not $inf.Count) { throw "no exported driver package in $($r.backup)" }
                    $o = Invoke-Native 'pnputil.exe' @('/add-driver', $inf[0].FullName, '/install')
                    # 259 = ERROR_NO_MORE_ITEMS: added, no matching device present to install it on.
                    if ($o.Code -notin @(0, 259, 3010)) { throw "pnputil /add-driver failed ($($o.Code)): $($o.Output)" }
                    if ($o.Code -eq 3010) { $reboot = $true }
                }
                'TaskUnregister' {
                    $xml = Get-Content -LiteralPath $r.backup -Raw -Encoding Unicode
                    Register-ScheduledTask -Xml $xml -TaskName $r.op.taskName -TaskPath $r.op.taskPath -Force -ErrorAction Stop | Out-Null
                }
                'FirewallRuleDelete' {
                    $b = Get-Content -LiteralPath $r.backup -Raw -Encoding UTF8 | ConvertFrom-Json
                    $p = @{ Name = $b.Name; DisplayName = $b.DisplayName; Direction = $b.Direction; Action = $b.Action; Enabled = $b.Enabled; Profile = $b.Profile }
                    if ($b.Description) { $p.Description = $b.Description }; if ($b.Group) { $p.Group = $b.Group }
                    if ($b.Program -and $b.Program -ne 'Any') { $p.Program = $b.Program }; if ($b.Service -and $b.Service -ne 'Any') { $p.Service = $b.Service }
                    if ($b.Protocol -and $b.Protocol -ne 'Any') { $p.Protocol = $b.Protocol; if ($b.LocalPort -and @($b.LocalPort)[0] -ne 'Any') { $p.LocalPort = @($b.LocalPort) }; if ($b.RemotePort -and @($b.RemotePort)[0] -ne 'Any') { $p.RemotePort = @($b.RemotePort) } }
                    New-NetFirewallRule @p -ErrorAction Stop | Out-Null
                }
                'ServiceRestart' { $restarts += $r.op.name }
                'ProcessStop' { Write-RunLog "  (not restarted: $($r.op.path))" }
            }
            Add-JournalRecord @{ itemId = $r.itemId; category = $r.category; kind = "Undo-$($r.kind)"; undoOf = $r.seq; op = $null; result = 'done' }
            Write-RunLog ("  restored [{0}] {1}" -f $r.category, $r.kind)
        } catch {
            # Newest-first IS the dependency order inside the chain: carrying on past a failed chain change
            # would put back older ones that rest on it, such as a device filter for a driver that isn't back
            # (every device in the class dead at the next boot), or a credential provider while the password
            # sign-in is off again (review 2026-09-26). So a chain failure stops the restore.
            # Outside the chain it does NOT (review 2026-09-29): one missing quarantined file used to stop
            # every older change from coming back, on every rerun, forever. Those carry on; only a failure
            # the chain could rest on (the app's files) holds the chain back. Undone records are skipped
            # next time, so a rerun picks up whatever is left.
            $failed++
            Add-JournalRecord @{ itemId = $r.itemId; category = $r.category; kind = "Undo-$($r.kind)"; undoOf = $r.seq; op = $null; result = 'failed'; note = $_.Exception.Message }
            Write-RunLog ("  FAILED to restore [{0}] {1}: {2}" -f $r.category, $r.kind, $_.Exception.Message)
            if ($isChain) {
                Write-RunLog "  Restore stopped here: nothing older was put back, because it may depend on this. Fix the cause$(if ($reboot) { ' (reboot first)' }), then run -Restore $RunId again."
                break
            }
            if ((Get-CategoryGroup ([string]$r.category)) -eq 'Files') { $chainBlocked = $true }
        }
    }
    if ($held) { Write-RunLog "  $held logon hook, driver or service change(s) held back: they may depend on what failed above. Fix it, then run -Restore $RunId again." }
    foreach ($s in $restarts | Select-Object -Unique) { try { Restart-Service -Name $s -Force -ErrorAction Stop } catch { } }
    $incomplete = $failed -or $deferred -or $held
    $meta.status = if ($incomplete) { 'restore-partial' } else { 'restored' }
    ($meta | ConvertTo-Json -Depth 4) | Set-Content -LiteralPath $metaFile -Encoding UTF8
    Write-RunLog "Restore of $RunId $(if ($incomplete) { 'is not finished' } else { 'complete' })$(if ($reboot) { '; reboot to finish' })."
    # An unfinished restore is exit 1 even when it also needs a reboot. It used to return 3010, which an
    # RMM reads as success and the window read as "reboot, then Resume", and -Resume refuses a restored
    # run: the rest never came back (review 2026-09-29). The way on is always -Restore again.
    if ($incomplete) {
        Write-RunLog "  To finish: $(if ($reboot) { 'reboot, then ' })run -Restore $RunId again."
        return 1
    }
    if ($reboot) { return 3010 }
    return 0
}

function Test-NetComponentPresent {
    # Is a network service/protocol/client with this ComponentId still installed?
    param([string] $ComponentId)
    foreach ($g in @('{4D36E974-E325-11CE-BFC1-08002BE10318}', '{4D36E975-E325-11CE-BFC1-08002BE10318}', '{4D36E973-E325-11CE-BFC1-08002BE10318}')) {
        $nk = Open-Key 'HKLM64' "SYSTEM\CurrentControlSet\Control\Network\$g"
        try {
            foreach ($inst in (Get-SubKeyNamesSafe $nk 'network components')) {
                $ik = $null; try { $ik = $nk.OpenSubKey($inst, $false) } catch { continue }
                if ($null -eq $ik) { continue }
                $cid = [string](Get-ValueSafe $ik 'ComponentId'); Close-Key $ik
                if ($cid -and $cid -ieq $ComponentId) { return $true }
            }
        } finally { Close-Key $nk }
    }
    return $false
}

function Invoke-KillItWithFireResume {
    # After the reboot a run asked for: check that every pending change happened.
    param([string] $RunId)
    $root = Join-Path (Get-RunsRoot) $RunId
    $metaFile = Join-Path $root 'run.json'
    if (-not (Test-Path -LiteralPath $metaFile)) { Write-Host "No run $RunId."; return 3 }
    $meta = Get-Content -LiteralPath $metaFile -Raw -Encoding UTF8 | ConvertFrom-Json
    if ([string]$meta.status -in @('restored', 'restore-partial')) { Write-Host "Run $RunId was restored (or partly): there is nothing to resume. -ListRuns shows its state."; return 2 }
    $journal = @(Get-JournalRecords (Join-Path $root 'journal.jsonl'))
    $maxSeq = if ($journal.Count) { [int]($journal | Measure-Object -Property seq -Maximum).Maximum } else { 0 }
    $script:Run = [pscustomobject]@{ RunId = $RunId; Root = $root; Backups = (Join-Path $root 'backups'); Journal = (Join-Path $root 'journal.jsonl'); Seq = $maxSeq; Backup = [bool]$meta.backup; LogFile = $(if ($meta.log) { $meta.log } else { $null }) }
    $still = 0; $leftInPlace = 0
    $resumed = @{}
    foreach ($x in @($journal | Where-Object { $_.kind -like 'Resume-*' -and $_.result -eq 'done' })) { $resumed[[string](Get-Prop $x 'resumeOf')] = $true }
    foreach ($u in @(Get-JournalRecords (Join-Path $root 'restore.jsonl') | Where-Object { $_.result -eq 'done' -and (Get-Prop $_ 'undoOf') })) { $resumed[[string]$u.undoOf] = $true }
    # "Still waiting" only while Windows still has the change queued for the next boot. Once a boot has
    # passed and nothing is queued, another reboot can't help: report it as left in place (exit 1)
    # instead of asking for reboots forever (review 2026-09-26).
    $queued = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
    $smk = Open-Key 'HKLM64' 'SYSTEM\CurrentControlSet\Control\Session Manager'
    $pfro = @(Get-ValueSafe $smk 'PendingFileRenameOperations' | Where-Object { $_ })
    Close-Key $smk
    for ($i = 0; $i -lt $pfro.Count; $i += 2) { [void]$queued.Add((ConvertFrom-PendingRenameEntry ([string]$pfro[$i]))) }
    $bootedSince = $false
    try { $bootedSince = ($meta.finished -and ((Get-CimInstance Win32_OperatingSystem -ErrorAction Stop).LastBootUpTime.ToUniversalTime() -gt (ConvertTo-UtcDate $meta.finished))) } catch { }
    foreach ($r in @($journal | Where-Object { $_.result -eq 'pending' -and -not $resumed.ContainsKey([string]$_.seq) })) {
        $ok = $true; $lost = @()
        foreach ($m in @(Get-Prop $r 'moves') | Where-Object { $_ }) {
            if ($m.state -notin @('pending', 'emptied-pending') -or -not (Test-Path -LiteralPath $m.src)) { continue }
            $ok = $false
            if ($bootedSince -and -not $queued.Contains([string]$m.src)) { $lost += [string]$m.src }
        }
        if ($r.kind -eq 'ServiceDelete' -and (Invoke-ScExe @('query', [string]$r.op.name)).Code -ne 1060) {
            $ok = $false
            if ($bootedSince) { $lost += "service $($r.op.name)" }
        }
        # Network components and driver packages have nothing in the move list to check, so they used to be
        # marked done unchecked, even by a -Resume with no reboot at all (review 2026-09-29). Check the
        # thing itself: the component gone from the network class, the INF gone from %SystemRoot%\INF.
        if ($r.kind -eq 'NetcfgUninstall' -and (Test-NetComponentPresent ([string]$r.op.componentId))) {
            $ok = $false
            if ($bootedSince) { $lost += "network component $($r.op.componentId)" }
        }
        if ($r.kind -eq 'DriverPackageDelete' -and (Test-Path -LiteralPath (Join-Path $env:SystemRoot "INF\$($r.op.inf)"))) {
            $ok = $false
            if ($bootedSince) { $lost += "driver package $($r.op.inf)" }
        }
        # Anything else with no check of its own: only a boot since the run can have finished it.
        if ($ok -and -not $bootedSince -and $r.kind -notin @('ServiceDelete', 'NetcfgUninstall', 'DriverPackageDelete') -and -not @(Get-Prop $r 'moves' | Where-Object { $_ }).Count) { $ok = $false }
        if (-not $ok -and $lost.Count) {
            $leftInPlace++
            foreach ($x in $lost) { Write-RunLog "  left in place: $x (a boot has passed and the change is no longer queued; it did not happen)" }
            continue
        }
        if ($ok) {
            Add-JournalRecord @{ itemId = $r.itemId; category = $r.category; kind = "Resume-$($r.kind)"; resumeOf = $r.seq; op = $null; result = 'done' }
            # The busy file that held its folder in place has moved at boot: the folder is empty now.
            # Remove it the same way a live run would, as a normal (restorable) FileQuarantine record.
            $folder = if ($r.kind -eq 'FileQuarantine') { [string]$r.op.path } else { $null }
            if ($folder -and (Test-Path -LiteralPath $folder -PathType Container) -and -not @(Get-ChildItem -LiteralPath $folder -Force -ErrorAction SilentlyContinue).Count) {
                $sddl = $null
                try { $sddl = (Get-Acl -LiteralPath $folder).Sddl } catch { }
                try { [System.IO.Directory]::Delete($folder, $false) } catch { }
                if (-not (Test-Path -LiteralPath $folder)) {
                    $dst = [System.IO.Path]::Combine((Get-QuarantineRoot $RunId $folder.Substring(0, 2)), $folder.Substring(3))
                    Add-JournalRecord @{ itemId = $r.itemId; category = $r.category; kind = 'FileQuarantine'; op = $r.op; backup = $null; result = 'done'; note = 'removed the folder emptied by the reboot'
                        moves = @([pscustomobject]@{ src = $folder; dst = $dst; state = 'emptied'; sddl = $sddl }) }
                    Write-RunLog "  removed the now-empty $folder"
                }
            }
        }
        else { $still++; Write-RunLog "  still pending: [$($r.category)] $($r.kind)" }
    }
    $meta.status = if ($leftInPlace) { 'resume-incomplete' } elseif ($still) { 'pending-reboot' } else { 'done' }
    ($meta | ConvertTo-Json -Depth 4) | Set-Content -LiteralPath $metaFile -Encoding UTF8
    Write-RunLog "Resume of ${RunId}: $(if ($leftInPlace) { "$leftInPlace change(s) did not happen at boot (listed above; -Restore $RunId puts the rest back)" } elseif ($still) { "$still change(s) still wait on a reboot" } else { 'everything completed' })."
    if ($leftInPlace) { return 1 }
    if ($still) { return 3010 }
    return 0
}

# =====================================================================================================
# The window (Disk Cleanup style). It never acts on its own: every change runs the same script as a
# child process with the switches it shows, so the window can do nothing the command line can't.
# =====================================================================================================

$script:LevelDescriptions = @(
    'Scan only: lists what would be removed and why. Changes nothing.',
    "Uninstall: runs the app's own uninstaller once, silently. For a broken app this usually fails; that is expected.",
    'Registration cleanup: the uninstaller, then removes the uninstall entry and the Windows Installer registration so the app can install again. Files stay.',
    'Full scrub: everything above, then unhooks the app from Windows and moves its files to a quarantine on the same drive. May need a reboot.'
)
$script:GroupDescriptions = @{
    Registration = 'The uninstall entry and the Windows Installer registration (product, features, upgrade code, component clients, patches, cached package). Removing them lets the app install again. Files are not touched.'
    LogonHooks   = 'Credential providers, network providers, LSA packages, Winlogon, AppInit and IFEO entries that load the app into sign-in or into every process. These go first, and the built-in password sign-in is turned back on if the app turned it off.'
    Drivers      = 'Device filters, network components, driver packages and drivers. A filter is always removed before its driver, so the devices keep working after the reboot.'
    Services     = "Windows services the app installed (stopped, disabled and deleted), and the app's own programs still running from its folder (stopped: unsaved work in them is lost, and a restore does not restart them)."
    Startup      = 'Scheduled tasks, Run keys and Active Setup entries that start the app.'
    ComShell     = 'COM classes, type libraries, shell extensions, context-menu verbs and file associations that point at the app. A Windows file type the app took over is reported, never deleted.'
    Other        = 'Shortcuts, firewall rules and print monitors.'
    Files        = "The app's folders and files. Moved to a quarantine on the same drive, not deleted, so a restore can put them back."
    Registry     = 'Registry keys and values named for the app or written by its installer.'
}

function Get-GuiGroups {
    # The checklist rows for a plan at a level. User data has its own checkbox, and items that need
    # review are counted separately: they only run with "Include items that need review".
    param($PlanObject, [int] $Level)
    $rows = @()
    if ($null -eq $PlanObject -or $Level -lt 2) { return $rows }
    foreach ($g in $script:Categories.Keys) {
        if ($g -eq 'UserData') { continue }
        $items = @($PlanObject.items | Where-Object { $_.group -eq $g -and $_.level -le $Level -and $null -ne $_.op })
        if (-not $items.Count) { continue }
        $normal = @($items | Where-Object { -not $_.review })
        $review = $items.Count - $normal.Count
        $bytes = [long]0
        foreach ($i in $normal) { if ($null -ne $i.bytes) { $bytes += [long]$i.bytes } }
        $crit = @($normal | Where-Object { $_.risk -eq 'critical' }).Count
        $label = "$g  -  $($script:CategoryLabels[$g]): $($normal.Count) item(s)"
        if ($bytes) { $label += ', {0:N1} MB' -f ($bytes / 1MB) }
        if ($crit) { $label += ", $crit critical" }
        if ($review) { $label += " (+$review uncertain)" }
        $rows += [pscustomobject]@{ Group = $g; Label = $label; Count = $normal.Count; Review = $review }
    }
    return $rows
}

$script:WindowIcon = $null   # set once, by the first window (strict mode: read before it is set throws)
function New-FlameIcon {
    # The window's icon: a flame drawn here at run time, so there is no image file to ship and nothing is
    # fetched from anywhere (2026-10-04).
    param([int] $Size = 32)
    Add-Type -AssemblyName System.Drawing
    $bmp = New-Object System.Drawing.Bitmap($Size, $Size)
    $g = [System.Drawing.Graphics]::FromImage($bmp)
    try {
        $g.SmoothingMode = [System.Drawing.Drawing2D.SmoothingMode]::AntiAlias
        $k = $Size / 32.0
        $pt = { param($x, $y) New-Object System.Drawing.PointF(([single]($x * $k)), ([single]($y * $k))) }
        $outer = [System.Drawing.PointF[]]@((& $pt 16 1), (& $pt 20 7), (& $pt 25 12), (& $pt 27.5 19), (& $pt 25 26), (& $pt 19.5 30.5), (& $pt 12.5 30.5),
            (& $pt 7 26), (& $pt 4.5 19), (& $pt 7.5 12), (& $pt 10.5 15.5), (& $pt 11.5 8.5))
        $inner = [System.Drawing.PointF[]]@((& $pt 16.5 12), (& $pt 20 18), (& $pt 21.5 23.5), (& $pt 19 28), (& $pt 16 29.5), (& $pt 13 28), (& $pt 10.5 23.5), (& $pt 12.5 18))
        $red = New-Object System.Drawing.Drawing2D.LinearGradientBrush((& $pt 16 1), (& $pt 16 31), [System.Drawing.Color]::FromArgb(255, 200, 30, 20), [System.Drawing.Color]::FromArgb(255, 255, 110, 20))
        $yellow = New-Object System.Drawing.Drawing2D.LinearGradientBrush((& $pt 16 12), (& $pt 16 30), [System.Drawing.Color]::FromArgb(255, 255, 190, 30), [System.Drawing.Color]::FromArgb(255, 255, 240, 150))
        $g.FillClosedCurve($red, $outer, [System.Drawing.Drawing2D.FillMode]::Winding, [single]0.4)
        $g.FillClosedCurve($yellow, $inner, [System.Drawing.Drawing2D.FillMode]::Winding, [single]0.4)
        $red.Dispose(); $yellow.Dispose()
    } finally { $g.Dispose() }
    return [System.Drawing.Icon]::FromHandle($bmp.GetHicon())
}

function New-KillItWithFireForm {
    # Builds the window and wires everything that only changes the window itself (levels, options,
    # checklist, command line). Actions that run the engine are wired by Show-KillItWithFireGui.
    param($Policy, [string] $PlanFile)
    Add-Type -AssemblyName System.Windows.Forms, System.Drawing
    [System.Windows.Forms.Application]::EnableVisualStyles()
    # An error in a handler is logged and shown plainly, not as .NET's "unhandled exception" dialog (whose
    # Continue button left the window half-updated on the lab VM, 2026-09-26).
    try { [System.Windows.Forms.Application]::SetUnhandledExceptionMode([System.Windows.Forms.UnhandledExceptionMode]::CatchException) } catch { }
    [System.Windows.Forms.Application]::add_ThreadException({
            param($s, $e)
            $log = Join-Path ([System.IO.Path]::GetTempPath()) 'killitwithfire-window-error.log'
            $pos = ''
            try { $pos = [string]$e.Exception.ErrorRecord.InvocationInfo.PositionMessage } catch { }
            try { Add-Content -LiteralPath $log -Value ("{0}  {1}`r`n{2}`r`n{3}`r`n" -f (Get-Date -Format s), $e.Exception.Message, $pos, $e.Exception.StackTrace) } catch { }
            [void][System.Windows.Forms.MessageBox]::Show("Something went wrong in the window: $($e.Exception.Message)`n`nDetails: $log", 'Kill It With Fire', 'OK', 'Error')
        })
    $ui = @{ Plan = $null; PlanFile = $null; App = $null; Unchecked = @{}; Loading = $false; Policy = $Policy }
    $bold = New-Object System.Drawing.Font('Segoe UI', 9, [System.Drawing.FontStyle]::Bold)
    $f = New-Object System.Windows.Forms.Form
    $f.Text = 'Kill It With Fire - remove an app completely'
    if (-not $script:WindowIcon) { try { $script:WindowIcon = New-FlameIcon } catch { } }
    if ($script:WindowIcon) { $f.Icon = $script:WindowIcon }
    # Fits a 1024x768 screen: the buttons live in a bar docked at the bottom and the rest scrolls, so
    # Clean up / Restore / Close are never off-screen (they were, on the lab VM).
    $wa = [System.Windows.Forms.Screen]::PrimaryScreen.WorkingArea
    $f.ClientSize = New-Object System.Drawing.Size(844, [Math]::Max(420, [Math]::Min(796, $wa.Height - 40)))
    $f.StartPosition = 'CenterScreen'
    $f.Font = New-Object System.Drawing.Font('Segoe UI', 9)
    $f.MinimumSize = New-Object System.Drawing.Size(760, 460)
    $main = New-Object System.Windows.Forms.Panel; $main.Dock = 'Fill'; $main.AutoScroll = $true
    $bar = New-Object System.Windows.Forms.Panel; $bar.Dock = 'Bottom'; $bar.Height = 46
    # Docked into the form BEFORE any control goes in: an anchor is measured against the parent's size
    # at the moment the control is added, and an unsized panel sent every right-anchored button off-screen.
    $f.Controls.Add($main); $f.Controls.Add($bar)
    $main.BringToFront()   # docked last, so it fills what the bottom bar leaves
    $tip = New-Object System.Windows.Forms.ToolTip
    $ui.Form = $f; $ui.Tip = $tip

    # 1. The app
    $lblApp = New-Object System.Windows.Forms.Label; $lblApp.Text = '1. Pick the app'; $lblApp.Location = '12,10'; $lblApp.AutoSize = $true; $lblApp.Font = $bold
    $search = New-Object System.Windows.Forms.TextBox; $search.Location = '12,32'; $search.Size = '620,24'; $search.Anchor = 'Top,Left,Right'
    $tip.SetToolTip($search, 'Type to filter the list')
    $btnScan = New-Object System.Windows.Forms.Button; $btnScan.Text = '&Scan'; $btnScan.Location = '640,30'; $btnScan.Size = '92,27'; $btnScan.Anchor = 'Top,Right'
    $tip.SetToolTip($btnScan, 'Build the plan for the selected app. Scanning changes nothing.')
    $apps = New-Object System.Windows.Forms.ListView; $apps.Location = '12,62'; $apps.Size = '820,150'; $apps.View = 'Details'; $apps.FullRowSelect = $true; $apps.HideSelection = $false; $apps.MultiSelect = $false; $apps.Anchor = 'Top,Left,Right'
    $apps.ShowItemToolTips = $true
    # Click a header to sort by it, again to reverse (Show-KillItWithFireGui). Installed and Size added 2026-10-04.
    foreach ($c in @(@('Name', 250, 'Left'), @('Version', 95, 'Left'), @('Publisher', 160, 'Left'), @('Type', 45, 'Left'), @('Scope', 110, 'Left'), @('Installed', 78, 'Left'), @('Size', 62, 'Right'))) {
        [void]$apps.Columns.Add([string]$c[0], [int]$c[1], [System.Windows.Forms.HorizontalAlignment]$c[2])
    }
    $ui.AppColumns = @('Name', 'Version', 'Publisher', 'Type', 'Scope', 'Installed', 'Size'); $ui.SortColumn = 0; $ui.SortDesc = $false
    $ui.Search = $search; $ui.Apps = $apps; $ui.Scan = $btnScan

    # 2. How far
    $grpLevel = New-Object System.Windows.Forms.GroupBox; $grpLevel.Text = '2. How far'; $grpLevel.Location = '12,220'; $grpLevel.Size = '820,88'; $grpLevel.Anchor = 'Top,Left,Right'
    $levels = @()
    $labels = @('Scan &only', '&Uninstall', 'Re&gistration cleanup', '&Full scrub')
    for ($i = 0; $i -le 3; $i++) {
        $rb = New-Object System.Windows.Forms.RadioButton; $rb.Text = $labels[$i]; $rb.Location = New-Object System.Drawing.Point((14 + $i * 196), 20); $rb.AutoSize = $true; $rb.Tag = $i
        $tip.SetToolTip($rb, $script:LevelDescriptions[$i])
        $grpLevel.Controls.Add($rb); $levels += $rb
    }
    $levels[0].Checked = $true
    $lblLevel = New-Object System.Windows.Forms.Label; $lblLevel.Location = '14,46'; $lblLevel.Size = '796,36'; $lblLevel.Anchor = 'Top,Left,Right'; $lblLevel.ForeColor = [System.Drawing.SystemColors]::GrayText
    $lblLevel.Text = $script:LevelDescriptions[0]
    $grpLevel.Controls.Add($lblLevel)
    $ui.Levels = $levels; $ui.LevelGroup = $grpLevel; $ui.LevelText = $lblLevel

    # 3. What to clean (the Disk Cleanup part: a checklist with sizes, a description, View items)
    $grpCats = New-Object System.Windows.Forms.GroupBox; $grpCats.Text = '3. What to clean'; $grpCats.Location = '12,314'; $grpCats.Size = '820,226'; $grpCats.Anchor = 'Top,Left,Right'
    $cats = New-Object System.Windows.Forms.CheckedListBox; $cats.Location = '10,20'; $cats.Size = '680,130'; $cats.CheckOnClick = $true; $cats.Anchor = 'Top,Left,Right'; $cats.IntegralHeight = $false
    $btnView = New-Object System.Windows.Forms.Button; $btnView.Text = '&View items...'; $btnView.Location = '698,20'; $btnView.Size = '112,27'; $btnView.Anchor = 'Top,Right'; $btnView.Enabled = $false
    $lblDescHead = New-Object System.Windows.Forms.Label; $lblDescHead.Text = 'Description'; $lblDescHead.Location = '10,156'; $lblDescHead.AutoSize = $true; $lblDescHead.Font = $bold
    $lblDesc = New-Object System.Windows.Forms.Label; $lblDesc.Location = '10,176'; $lblDesc.Size = '800,44'; $lblDesc.Anchor = 'Top,Left,Right'
    $lblDesc.Text = 'Scan an app, then choose Registration cleanup or Full scrub to pick what goes.'
    foreach ($c in @($cats, $btnView, $lblDescHead, $lblDesc)) { $grpCats.Controls.Add($c) }
    $ui.Categories = $cats; $ui.View = $btnView; $ui.Description = $lblDesc

    # 4. Options
    $grpOpt = New-Object System.Windows.Forms.GroupBox; $grpOpt.Text = '4. Options'; $grpOpt.Location = '12,546'; $grpOpt.Size = '820,122'; $grpOpt.Anchor = 'Top,Left,Right'
    $chkBackup = New-Object System.Windows.Forms.CheckBox; $chkBackup.Text = 'Keep a &backup (Restore can undo the run)'; $chkBackup.Location = '12,22'; $chkBackup.AutoSize = $true; $chkBackup.Checked = $true
    $chkLog = New-Object System.Windows.Forms.CheckBox; $chkLog.Text = 'Write a &log:'; $chkLog.Location = '330,22'; $chkLog.AutoSize = $true; $chkLog.Checked = $true
    $txtLog = New-Object System.Windows.Forms.TextBox; $txtLog.Location = '430,20'; $txtLog.Size = '378,24'; $txtLog.Anchor = 'Top,Left,Right'
    $tip.SetToolTip($txtLog, 'A file or a folder. Empty = log.txt in the run folder.')
    $chkUser = New-Object System.Windows.Forms.CheckBox; $chkUser.Text = 'Include user &data (AppData)'; $chkUser.Location = '12,52'; $chkUser.AutoSize = $true
    # "Include items that need review" read as "important, look at these", so as something to tick (first
    # outside try of the window, 2026-10-04). These are the WEAK matches, off on purpose: the tooltip says why.
    $chkReview = New-Object System.Windows.Forms.CheckBox; $chkReview.Text = 'Also remove uncer&tain matches'; $chkReview.Location = '330,52'; $chkReview.AutoSize = $true
    $tip.SetToolTip($chkReview, "Items tied to the app only by a name, its vendor or signer, or one MSI's claim on a Windows file. They may belong to another app or to Windows, so they stay unless you tick this. View items... lists each one and why it is uncertain.")
    # KILL IT (2026-10-03): the hard way as its own, unmissable choice. Off (the default) is the proper way:
    # the app's own uninstaller runs first. On is -KillIt: no uninstaller, the level jumps to Full scrub, and
    # the Clean up button says "Kill it" so nobody does it by accident.
    $chkUninst = New-Object System.Windows.Forms.CheckBox; $chkUninst.Text = "&KILL IT: skip the app's own uninstaller and scrub it out"; $chkUninst.Location = '12,78'; $chkUninst.AutoSize = $true; $chkUninst.Checked = $false
    $chkUninst.Font = $bold; $chkUninst.ForeColor = [System.Drawing.Color]::DarkRed
    $tip.SetToolTip($chkUninst, "Off = the proper way: the app's own uninstaller runs first, then the cleanup. On = -KillIt: no uninstaller, straight to the full scrub. It still backs everything up, so Restore can undo it.")
    $lblPolicy = New-Object System.Windows.Forms.Label; $lblPolicy.Location = '12,100'; $lblPolicy.Size = '796,18'; $lblPolicy.ForeColor = [System.Drawing.Color]::DarkRed; $lblPolicy.Anchor = 'Top,Left,Right'
    foreach ($c in @($chkBackup, $chkLog, $txtLog, $chkUser, $chkReview, $chkUninst, $lblPolicy)) { $grpOpt.Controls.Add($c) }
    $ui.Backup = $chkBackup; $ui.LogCheck = $chkLog; $ui.LogPath = $txtLog; $ui.UserData = $chkUser; $ui.Review = $chkReview; $ui.KillIt = $chkUninst; $ui.PolicyLabel = $lblPolicy

    # The same run as a command line
    $lblCmd = New-Object System.Windows.Forms.Label; $lblCmd.Text = 'The same run from a command line (RMM, PDQ, Intune):'; $lblCmd.Location = '12,676'; $lblCmd.AutoSize = $true
    $txtCmd = New-Object System.Windows.Forms.TextBox; $txtCmd.Location = '12,696'; $txtCmd.Size = '728,24'; $txtCmd.ReadOnly = $true; $txtCmd.Anchor = 'Top,Left,Right'
    $btnCopy = New-Object System.Windows.Forms.Button; $btnCopy.Text = 'Cop&y'; $btnCopy.Location = '746,694'; $btnCopy.Size = '86,27'; $btnCopy.Anchor = 'Top,Right'
    $ui.Command = $txtCmd; $ui.Copy = $btnCopy

    $status = New-Object System.Windows.Forms.Label; $status.Location = '12,14'; $status.Size = '496,20'; $status.Anchor = 'Top,Left,Right'; $status.Text = 'Pick an app and press Scan. Scanning changes nothing.'
    $btnClean = New-Object System.Windows.Forms.Button; $btnClean.Text = '&Clean up'; $btnClean.Location = '520,8'; $btnClean.Size = '100,30'; $btnClean.Anchor = 'Top,Right'; $btnClean.Enabled = $false
    $btnRestore = New-Object System.Windows.Forms.Button; $btnRestore.Text = '&Restore...'; $btnRestore.Location = '626,8'; $btnRestore.Size = '100,30'; $btnRestore.Anchor = 'Top,Right'
    $tip.SetToolTip($btnRestore, 'Put back everything an earlier run changed')
    $btnClose = New-Object System.Windows.Forms.Button; $btnClose.Text = 'Close'; $btnClose.Location = '732,8'; $btnClose.Size = '100,30'; $btnClose.Anchor = 'Top,Right'
    $ui.Clean = $btnClean; $ui.Restore = $btnRestore; $ui.Close = $btnClose; $ui.Status = $status
    foreach ($c in @($lblApp, $search, $btnScan, $apps, $grpLevel, $grpCats, $grpOpt, $lblCmd, $txtCmd, $btnCopy)) { $main.Controls.Add($c) }
    foreach ($c in @($status, $btnClean, $btnRestore, $btnClose)) { $bar.Controls.Add($c) }
    $ui.Main = $main
    $f.CancelButton = $btnClose
    # Come to the front when shown: started from a scheduled task or an RMM, the hidden console would
    # otherwise keep the focus and the first keystrokes go nowhere.
    $f.Add_Shown({ $this.Activate() })

    # Administrator locks: greyed out and labelled. The engine enforces them whatever the window shows.
    $locks = @()
    if ($null -ne $Policy.MaxLevel) {
        for ($i = 0; $i -le 3; $i++) { if ($i -gt [int]$Policy.MaxLevel) { $levels[$i].Enabled = $false; $tip.SetToolTip($levels[$i], 'Set by your administrator') } }
        $locks += "highest level $($Policy.MaxLevel)"
        # KILL IT selects Full scrub, and .Checked on a DISABLED radio still works from code: without this
        # the box would walk straight past the lock (the engine would still refuse the run, but the window
        # must not offer what the administrator took away).
        if ([int]$Policy.MaxLevel -lt 3) { $chkUninst.Enabled = $false; $tip.SetToolTip($chkUninst, 'Set by your administrator (KILL IT is a full scrub)') }
    }
    if ($Policy.RequireBackup) { $chkBackup.Checked = $true; $chkBackup.Enabled = $false; $tip.SetToolTip($chkBackup, 'Set by your administrator'); $locks += 'backup required' }
    if ($Policy.RequireLog) { $chkLog.Checked = $true; $chkLog.Enabled = $false; $tip.SetToolTip($chkLog, 'Set by your administrator'); $locks += 'log required' }
    if ($Policy.LogPath) { $txtLog.Text = $Policy.LogPath; $txtLog.Enabled = $false; $tip.SetToolTip($txtLog, 'Set by your administrator'); $locks += 'log location' }
    if ($Policy.AllowUserData -eq $false) { $chkUser.Checked = $false; $chkUser.Enabled = $false; $tip.SetToolTip($chkUser, 'Set by your administrator'); $locks += 'no user data' }
    if ($null -ne $Policy.QuarantineDays) { $locks += "backups kept $($Policy.QuarantineDays) days" }
    $lblPolicy.Text = if ($locks.Count) { 'Set by your administrator: ' + ($locks -join ', ') } else { '' }
    $ui.Locks = $locks

    $ui.GetLevel = { [int](($ui.Levels | Where-Object { $_.Checked } | Select-Object -First 1).Tag) }
    $ui.UpdateCommand = {
        $lvl = & $ui.GetLevel
        $present = @(Get-GuiGroups $ui.Plan $lvl | ForEach-Object { $_.Group })
        $exclude = @($present | Where-Object { $ui.Unchecked.ContainsKey($_) })
        $appName = if ($ui.App) { $ui.App.DisplayName } elseif ($ui.Plan) { $ui.Plan.target.displayName } else { '<app>' }
        $pcode = if ($ui.App -and $ui.App.ProductCode -and $ui.App.IsMsi) { $ui.App.ProductCode } elseif (-not $ui.App -and $ui.Plan -and $ui.Plan.target.productCode -and (Get-Prop $ui.Plan.target 'isMsi')) { $ui.Plan.target.productCode } else { $null }
        $ui.Command.Text = Format-CommandLine -AppName $appName -ProductCode $pcode -Level $lvl -Exclude $exclude -IncludeUserData $ui.UserData.Checked -IncludeReview $ui.Review.Checked `
            -NoBackup (-not $ui.Backup.Checked) -NoLog (-not $ui.LogCheck.Checked) -LogPath $ui.LogPath.Text -SkipUninstall $ui.KillIt.Checked
        $ui.Clean.Text = $(if ($ui.KillIt.Checked) { '&Kill it' } else { '&Clean up' })
        $ui.LogPath.Enabled = $ui.LogCheck.Checked -and -not $ui.Policy.LogPath
        $ui.Clean.Enabled = [bool]($ui.Plan -and $lvl -ge 1)
    }
    $ui.Rebuild = {
        # The checklist for the current plan and level; the user's unticks survive a level change.
        $lvl = & $ui.GetLevel
        $ui.LevelText.Text = $script:LevelDescriptions[$lvl]
        $ui.Loading = $true
        $ui.Categories.BeginUpdate(); $ui.Categories.Items.Clear()
        foreach ($row in @(Get-GuiGroups $ui.Plan $lvl)) {
            $idx = $ui.Categories.Items.Add($row.Label)
            $ui.Categories.SetItemChecked($idx, -not $ui.Unchecked.ContainsKey($row.Group))
        }
        $ui.Categories.EndUpdate()
        $ui.Loading = $false
        $ui.Categories.Enabled = ($lvl -ge 2 -and $ui.Categories.Items.Count -gt 0)
        $ui.View.Enabled = [bool]$ui.Plan
        if (-not $ui.Plan) { $ui.Description.Text = 'Scan an app, then choose Registration cleanup or Full scrub to pick what goes.' }
        elseif ($lvl -lt 2) { $ui.Description.Text = "Pick Registration cleanup or Full scrub to choose what goes. The scan found $(@($ui.Plan.items).Count) item(s)." }
        elseif (-not $ui.Categories.Items.Count) { $ui.Description.Text = 'Nothing to clean at this level.' }
        else { $ui.Description.Text = "Everything ticked goes when you press Clean up (it asks first). Untick a category to keep it, select one to see what it is, or View items for each item and the scan's notes." }
        # Strict mode: a property of $null throws, so no plan means no items, not $ui.Plan.items.
        $planItems = if ($ui.Plan) { @($ui.Plan.items) } else { @() }
        $ud = @($planItems | Where-Object { $_.group -eq 'UserData' -and $_.level -le $lvl })
        $udBytes = [long]0; foreach ($i in $ud) { if ($null -ne $i.bytes) { $udBytes += [long]$i.bytes } }
        $ui.UserData.Text = if ($ud.Count) { 'Include user &data (AppData): {0} item(s), {1:N1} MB' -f $ud.Count, ($udBytes / 1MB) } else { 'Include user &data (AppData)' }
        $rv = @($planItems | Where-Object { $_.review -and $null -ne $_.op -and $_.level -le $lvl })
        $ui.Review.Text = if ($rv.Count) { "Also remove uncer&tain matches: $($rv.Count)" } else { 'Also remove uncer&tain matches' }
        & $ui.UpdateCommand
    }
    $ui.LoadPlan = {
        param($PlanObject)
        $ui.Plan = $PlanObject
        $ui.Unchecked = @{}
        # A scan moves the level to the furthest the policy allows, so "3. What to clean" fills at once with what
        # the scan found. Left at Scan only, the list stayed EMPTY after a scan and the window read as broken
        # (first outside try, 2026-10-04). Nothing runs until Clean up, which asks first.
        $max = if ($null -ne $ui.Policy.MaxLevel) { [Math]::Min(3, [int]$ui.Policy.MaxLevel) } else { 3 }
        if ($max -ge 2 -and -not (Get-Prop $PlanObject 'refused')) { $ui.Levels[$max].Checked = $true }
        & $ui.Rebuild
        $notes = @(Get-Prop $PlanObject 'warnings' | Where-Object { $_ }).Count
        $ui.Status.Text = "Scanned '$($PlanObject.target.displayName)': $(@($PlanObject.items).Count) item(s)$(if ($notes) { ", $notes note(s)" }). Nothing changed yet."
    }

    foreach ($rb in $levels) {
        $rb.Add_CheckedChanged({
                if (-not $this.Checked) { return }
                # Below registration cleanup there is nothing to kill: KILL IT only means something at 2 and 3.
                if ([int]$this.Tag -lt 2 -and $ui.KillIt.Checked) { $ui.KillIt.Checked = $false }
                & $ui.Rebuild
            })
    }
    foreach ($c in @($chkBackup, $chkLog, $chkUser, $chkReview)) { $c.Add_CheckedChanged({ & $ui.UpdateCommand }) }
    $chkUninst.Add_CheckedChanged({
            # KILL IT goes all the way: tick it and the level moves to Full scrub (the level handler rebuilds).
            if ($ui.KillIt.Checked -and (& $ui.GetLevel) -lt 3) { $ui.Levels[3].Checked = $true } else { & $ui.UpdateCommand }
        })
    $txtLog.Add_TextChanged({ & $ui.UpdateCommand })
    $cats.Add_ItemCheck({
            if ($ui.Loading) { return }
            $g = ([string]$ui.Categories.Items[$_.Index] -split ' ')[0]
            if ($_.NewValue -eq [System.Windows.Forms.CheckState]::Checked) { $ui.Unchecked.Remove($g) } else { $ui.Unchecked[$g] = $true }
            & $ui.UpdateCommand
        })
    $cats.Add_SelectedIndexChanged({
            if ($ui.Categories.SelectedIndex -lt 0) { return }
            $g = ([string]$ui.Categories.SelectedItem -split ' ')[0]
            $ui.Description.Text = $script:GroupDescriptions[$g]
        })
    $btnCopy.Add_Click({ if ($ui.Command.Text) { [System.Windows.Forms.Clipboard]::SetText($ui.Command.Text) } })

    if ($PlanFile -and (Test-Path -LiteralPath $PlanFile)) { $ui.PlanFile = $PlanFile; & $ui.LoadPlan (Get-Content -LiteralPath $PlanFile -Raw -Encoding UTF8 | ConvertFrom-Json) }
    & $ui.Rebuild
    return $ui
}

function Show-TextDialog {
    param([string] $Title, [string] $Text, $Owner)
    $d = New-Object System.Windows.Forms.Form
    $d.Text = $Title; $d.ClientSize = New-Object System.Drawing.Size(860, 520); $d.StartPosition = 'CenterParent'; $d.Font = New-Object System.Drawing.Font('Segoe UI', 9)
    if ($script:WindowIcon) { $d.Icon = $script:WindowIcon }
    $tb = New-Object System.Windows.Forms.TextBox; $tb.Multiline = $true; $tb.ReadOnly = $true; $tb.ScrollBars = 'Both'; $tb.WordWrap = $false
    $tb.Font = New-Object System.Drawing.Font('Consolas', 9); $tb.Location = '10,10'; $tb.Size = '840,462'; $tb.Anchor = 'Top,Bottom,Left,Right'
    $tb.Text = ($Text -replace "(?<!`r)`n", "`r`n")
    $ok = New-Object System.Windows.Forms.Button; $ok.Text = 'OK'; $ok.Location = '760,480'; $ok.Size = '90,28'; $ok.Anchor = 'Bottom,Right'; $ok.DialogResult = 'OK'
    $d.Controls.Add($tb); $d.Controls.Add($ok); $d.AcceptButton = $ok
    # Focus starts on OK: a TextBox that gets focus first selects all its text, and the output opened
    # fully highlighted.
    $d.ActiveControl = $ok; $tb.SelectionStart = 0; $tb.SelectionLength = 0
    [void]$d.ShowDialog($Owner)
    $d.Dispose()
}

function Start-KillItWithFireChild {
    # The window's work runs as a child process of this same script: same engine, same switches. No
    # console at all (CreateNoWindow): on Windows 11 a hidden-window child still opened in Windows
    # Terminal, on top of the form, and took the keystrokes (lab 2026-09-26). Output comes back through
    # the redirected streams, read without blocking by the window's timer.
    param([string[]] $Arguments)
    $all = @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', $script:ScriptPath) + $Arguments
    $psi = New-Object System.Diagnostics.ProcessStartInfo
    $psi.FileName = Get-PowerShellExe
    $psi.Arguments = (@($all | ForEach-Object { ConvertTo-ArgvString $_ })) -join ' '
    $psi.UseShellExecute = $false
    $psi.CreateNoWindow = $true
    $psi.RedirectStandardOutput = $true
    $psi.RedirectStandardError = $true
    return [System.Diagnostics.Process]::Start($psi)
}

function Update-AppList {
    # The window's app list, rebuilt on every filter keystroke and every header click. The selected app stays
    # selected (and keeps its scan): $Ui.Filling mutes the selection handler while the rows are swapped.
    param($Ui, $All)
    $Ui.Filling = $true
    $keep = $null
    $Ui.Apps.BeginUpdate(); $Ui.Apps.Items.Clear()
    foreach ($e in (Select-AppListRows -Entries $All -Filter $Ui.Search.Text -Column $Ui.SortColumn -Descending $Ui.SortDesc)) {
        $li = New-Object System.Windows.Forms.ListViewItem([string]$e.DisplayName)
        $li.UseItemStyleForSubItems = $false
        [void]$li.SubItems.Add([string]$e.DisplayVersion); [void]$li.SubItems.Add([string]$e.Publisher)
        [void]$li.SubItems.Add($(if ($e.IsMsi) { 'MSI' } else { 'EXE' })); [void]$li.SubItems.Add((Get-EntryScopeLabel $e))
        $date = Get-Prop $e 'InstallDate'
        $d = $li.SubItems.Add($(if ($date) { $date.ToString('yyyy-MM-dd') } else { '' }))
        if (Get-Prop $e 'InstallDateFromKey') {
            $d.ForeColor = [System.Drawing.SystemColors]::GrayText
            $li.ToolTipText = 'Grey date: the app recorded no install date, so this is when its uninstall entry last changed (what Programs and Features shows too).'
        }
        [void]$li.SubItems.Add((Format-AppSize (Get-Prop $e 'SizeKB')))
        $li.Tag = $e
        [void]$Ui.Apps.Items.Add($li)
        if ($Ui.App -and $e.KeyPath -eq $Ui.App.KeyPath -and $e.Hive -eq $Ui.App.Hive) { $li.Selected = $true; $keep = $li }
    }
    for ($i = 0; $i -lt $Ui.Apps.Columns.Count; $i++) {
        $arrow = if ($i -ne $Ui.SortColumn) { '' } elseif ($Ui.SortDesc) { ' ' + [char]0x25BC } else { ' ' + [char]0x25B2 }
        $Ui.Apps.Columns[$i].Text = $Ui.AppColumns[$i] + $arrow
    }
    $Ui.Apps.EndUpdate()
    $Ui.Filling = $false
    if ($keep) { $keep.EnsureVisible() }
    # One app left after filtering: select it, so typing its name and pressing Alt+S scans it.
    elseif ($Ui.Apps.Items.Count -eq 1) { $Ui.Apps.Items[0].Selected = $true }
}

function Show-KillItWithFireGui {
    param($Policy)
    $ui = New-KillItWithFireForm -Policy $Policy
    # The window's scans live in the admin-only folder, not %TEMP%: the plan a scan writes is what Clean up
    # then executes elevated, and the user's own non-elevated programs can write to %TEMP% (review 2026-09-26).
    $guiRoot = Join-Path (Split-Path (Get-RunsRoot) -Parent) 'gui'
    [void](New-Item -ItemType Directory -Force -Path $guiRoot)
    Protect-Folder $guiRoot
    $work = Join-Path $guiRoot ([guid]::NewGuid().ToString('N').Substring(0, 8))
    [void](New-Item -ItemType Directory -Force -Path $work)
    $all = @((Get-UninstallEntries (Get-LoadedUserSids)) | Where-Object { $_.DisplayName -and -not $_.SystemComponent } | Sort-Object DisplayName)
    $fill = { Update-AppList $ui $all }
    & $fill
    $ui.Search.Add_TextChanged({ & $fill })
    $ui.Apps.Add_ColumnClick({
            param($s, $e)
            # The same header again reverses it. Installed and Size start newest and biggest first.
            if ($ui.SortColumn -eq $e.Column) { $ui.SortDesc = -not $ui.SortDesc } else { $ui.SortColumn = $e.Column; $ui.SortDesc = ($e.Column -ge 5) }
            & $fill
        })
    $ui.Apps.Add_SelectedIndexChanged({
            if ($ui.Filling -or -not $ui.Apps.SelectedItems.Count) { return }
            $picked = $ui.Apps.SelectedItems[0].Tag
            if ($ui.App -and $picked.KeyPath -eq $ui.App.KeyPath -and $picked.Hive -eq $ui.App.Hive) { return }
            $ui.App = $picked
            $ui.Plan = $null; $ui.PlanFile = $null
            & $ui.Rebuild
            $ui.Status.Text = "Selected '$($ui.App.DisplayName)'. Press Scan."
        })
    $ui.Apps.Add_DoubleClick({ $ui.Scan.PerformClick() })
    $ui.Close.Add_Click({ $ui.Form.Close() })

    $timer = New-Object System.Windows.Forms.Timer; $timer.Interval = 700
    $state = @{ Proc = $null; Kind = $null; Dir = $null; Started = $null; Lines = $null; Read = $null; Err = $null; Last = '' }
    $finish = {
        $timer.Stop()
        foreach ($b in @($ui.Scan, $ui.Restore)) { $b.Enabled = $true }
        $code = $state.Proc.ExitCode
        $output = $state.Lines.ToString()
        if ($state.Err -and $state.Err.IsCompleted -and $state.Err.Result) { $output += "`r`n" + $state.Err.Result }
        if ($state.Kind -eq 'Scan') {
            $pf = Join-Path $state.Dir 'plan.json'
            if ($code -eq 0 -and (Test-Path -LiteralPath $pf)) { $ui.PlanFile = $pf; & $ui.LoadPlan (Get-Content -LiteralPath $pf -Raw -Encoding UTF8 | ConvertFrom-Json) }
            else { $ui.Status.Text = "Scan stopped (exit $code)."; Show-TextDialog 'Kill It With Fire: scan' $output $ui.Form }
        } else {
            # By kind: a restore's 3010 means "reboot and it's in effect" and its 1 means "not finished, run
            # Restore again"; only a cleanup's 3010 goes on to Resume (review 2026-09-29).
            $meaning = if ($state.Kind -eq 'Restore') {
                switch ($code) { 0 { 'done' } 3010 { 'done; reboot to finish' } 1 { 'not finished; see why, then Restore again' } 2 { 'refused' } default { 'stopped on an error' } }
            } else {
                switch ($code) { 0 { 'done' } 3010 { 'done; reboot, then Resume' } 1 { 'stopped part way; the run can be restored' } 2 { 'refused' } default { 'stopped on an error' } }
            }
            $ui.Status.Text = "$($state.Kind) finished: exit $code ($meaning)."
            Show-TextDialog "Kill It With Fire: $($state.Kind) (exit $code, $meaning)" $output $ui.Form
            if ($state.Kind -ne 'Restore') { $ui.Plan = $null; $ui.PlanFile = $null; & $ui.Rebuild }
        }
    }
    $timer.Add_Tick({
            if (-not $state.Proc) { return }
            # Drain whatever output lines are ready, never waiting on the child.
            while ($state.Read -and $state.Read.IsCompleted) {
                $line = $state.Read.Result
                if ($null -eq $line) { $state.Read = $null; break }
                [void]$state.Lines.AppendLine($line)
                if ($line.Trim()) { $state.Last = $line.Trim() }
                $state.Read = $state.Proc.StandardOutput.ReadLineAsync()
            }
            $secs = [int]((Get-Date) - $state.Started).TotalSeconds
            $ui.Status.Text = ("{0}: {1} s  {2}" -f $state.Kind, $secs, [string]$state.Last)
            if ($state.Proc.HasExited -and -not $state.Read) { & $finish }
        })
    # Not while a run is going: closing would leave it working with nobody watching, its result unseen
    # (review 2026-09-26).
    $ui.Form.Add_FormClosing({
            if ($state.Proc -and -not $state.Proc.HasExited) {
                # A scan changes nothing, so it may be stopped (an Epic Games Launcher scan ran past seven minutes
                # and the window would not close, 2026-10-04). A cleanup or restore may not: it would stop part way.
                if ($state.Kind -eq 'Scan') {
                    $a = [System.Windows.Forms.MessageBox]::Show('The scan is still running. Stop it and close? A scan changes nothing, so stopping it is safe.', 'Kill It With Fire', 'YesNo', 'Question')
                    if ($a -eq [System.Windows.Forms.DialogResult]::Yes) {
                        $timer.Stop()
                        try { Stop-ProcessTreeSince @(Get-ProcessTreeSince $state.Proc.Id ($state.Started.AddSeconds(-2))) } catch { }
                        return
                    }
                    $_.Cancel = $true
                    return
                }
                $_.Cancel = $true
                [void][System.Windows.Forms.MessageBox]::Show("The $($state.Kind.ToLowerInvariant()) is still running. Wait for it to finish: closing now would leave it running with nobody watching.", 'Kill It With Fire', 'OK', 'Warning')
            }
        })
    $launch = {
        param([string] $Kind, [string[]] $ArgList)
        $state.Kind = $Kind; $state.Dir = Join-Path $work ([guid]::NewGuid().ToString('N').Substring(0, 8)); [void](New-Item -ItemType Directory -Force -Path $state.Dir)
        $state.Started = Get-Date; $state.Last = ''
        foreach ($b in @($ui.Scan, $ui.Restore, $ui.Clean)) { $b.Enabled = $false }
        $state.Proc = Start-KillItWithFireChild -Arguments ($ArgList + @('-OutDir', $state.Dir))
        $state.Lines = New-Object System.Text.StringBuilder
        $state.Read = $state.Proc.StandardOutput.ReadLineAsync()
        $state.Err = $state.Proc.StandardError.ReadToEndAsync()
        $timer.Start()
    }
    $ui.Scan.Add_Click({
            if (-not $ui.App) { [void][System.Windows.Forms.MessageBox]::Show('Pick an app first.', 'Kill It With Fire'); return }
            $a = if ($ui.App.ProductCode -and $ui.App.IsMsi) { @('-ProductCode', $ui.App.ProductCode) } else { @('-Name', $ui.App.DisplayName) }
            & $launch 'Scan' ($a + @('-Level', '0'))
        })
    $ui.View.Add_Click({
            if (-not $ui.Plan) { return }
            $g = if ($ui.Categories.SelectedIndex -ge 0) { ([string]$ui.Categories.SelectedItem -split ' ')[0] } else { $null }
            $dlg = New-Object System.Windows.Forms.Form; $dlg.Text = $(if ($g) { "Items: $g" } else { 'All items' }); $dlg.ClientSize = New-Object System.Drawing.Size(1000, 520); $dlg.StartPosition = 'CenterParent'; $dlg.Font = $ui.Form.Font; $dlg.Icon = $ui.Form.Icon
            $lv = New-Object System.Windows.Forms.ListView; $lv.Dock = 'Fill'; $lv.View = 'Details'; $lv.FullRowSelect = $true
            foreach ($c in @(@('Level', 44), @('Risk', 110), @('Target', 390), @('Action', 220), @('Why', 300))) { [void]$lv.Columns.Add($c[0], $c[1]) }
            # The scan's notes first: the window showed none of them until 2026-10-04 (only the command line's
            # report did), including "this folder also holds other programs".
            foreach ($w in @(Get-Prop $ui.Plan 'warnings' | Where-Object { $_ })) {
                $li = New-Object System.Windows.Forms.ListViewItem('!')
                [void]$li.SubItems.Add('note'); [void]$li.SubItems.Add([string]$w); [void]$li.SubItems.Add(''); [void]$li.SubItems.Add('')
                $li.ToolTipText = [string]$w
                [void]$lv.Items.Add($li)
            }
            $lv.ShowItemToolTips = $true
            foreach ($i in @($ui.Plan.items | Where-Object { -not $g -or $_.group -eq $g })) {
                $li = New-Object System.Windows.Forms.ListViewItem([string]$i.level)
                [void]$li.SubItems.Add("$($i.risk)$(if ($i.review) { ', review' })$(if ($null -eq $i.op) { ', report only' })")
                [void]$li.SubItems.Add([string]$i.target); [void]$li.SubItems.Add([string]$i.action); [void]$li.SubItems.Add([string]$i.evidence)
                [void]$lv.Items.Add($li)
            }
            $dlg.Controls.Add($lv); [void]$dlg.ShowDialog($ui.Form); $dlg.Dispose()
        })
    $ui.Clean.Add_Click({
            $lvl = & $ui.GetLevel
            $present = @(Get-GuiGroups $ui.Plan $lvl | ForEach-Object { $_.Group })
            $exclude = @($present | Where-Object { $ui.Unchecked.ContainsKey($_) })
            $keep = @($present | Where-Object { -not $ui.Unchecked.ContainsKey($_) })
            $msg = "Level $lvl ($(@('scan only', 'uninstall', 'registration cleanup', 'full scrub')[$lvl])) on '$($ui.Plan.target.displayName)'.`n`n"
            if ($lvl -ge 2) { $msg += "Categories: $(if ($keep.Count) { $keep -join ', ' } else { '(none)' })`n" }
            $msg += "The app's own uninstaller: $(if ($ui.KillIt.Checked) { 'SKIPPED - KILL IT scrubs the app out without it' } else { 'runs first' })`n"
            $msg += "Backup: $(if ($ui.Backup.Checked) { 'yes, a restore can undo it' } else { 'NO - this run cannot be restored' })`n"
            # The scan's notes, at the last moment before a full scrub (a folder holding other programs, say).
            $notes = @(Get-Prop $ui.Plan 'warnings' | Where-Object { $_ })
            if ($lvl -ge 3 -and $notes.Count) {
                $msg += "`nThe scan noted:`n" + ((@($notes | Select-Object -First 4) | ForEach-Object { "- $_" }) -join "`n") + "`n"
                if ($notes.Count -gt 4) { $msg += "...and $($notes.Count - 4) more in View items.`n" }
            }
            $msg += "`nContinue?"
            if ([System.Windows.Forms.MessageBox]::Show($msg, 'Kill It With Fire', 'YesNo', 'Warning') -ne 'Yes') { return }
            $a = @('-Plan', $ui.PlanFile, '-Level', [string]$lvl, '-Force')
            if ($lvl -ge 2 -and $exclude.Count) { $a += @('-Exclude', ($exclude -join ',')) }
            if ($ui.UserData.Checked) { $a += '-IncludeUserData' }; if ($ui.Review.Checked) { $a += '-IncludeReview' }
            if ($ui.KillIt.Checked) { $a += '-SkipUninstall' }
            if (-not $ui.Backup.Checked) { $a += '-NoBackup' }
            if (-not $ui.LogCheck.Checked) { $a += '-NoLog' } elseif ($ui.LogPath.Text -and -not $ui.Policy.LogPath) { $a += @('-Log', $ui.LogPath.Text) }
            & $launch 'Clean up' $a
        })
    $ui.Restore.Add_Click({
            $runs = @(Get-RunList | Where-Object { $_.backup -and $_.status -ne 'restored' })
            $dlg = New-Object System.Windows.Forms.Form; $dlg.Text = 'Restore a run'; $dlg.ClientSize = New-Object System.Drawing.Size(780, 330); $dlg.StartPosition = 'CenterParent'; $dlg.Font = $ui.Form.Font; $dlg.Icon = $ui.Form.Icon
            $lv = New-Object System.Windows.Forms.ListView; $lv.Location = '10,10'; $lv.Size = '760,262'; $lv.View = 'Details'; $lv.FullRowSelect = $true; $lv.MultiSelect = $false; $lv.Anchor = 'Top,Bottom,Left,Right'
            foreach ($c in @(@('Run', 170), @('App', 250), @('Level', 50), @('Items', 50), @('Status', 110), @('Finished (UTC)', 120))) { [void]$lv.Columns.Add($c[0], $c[1]) }
            foreach ($r in $runs) {
                $li = New-Object System.Windows.Forms.ListViewItem([string]$r.runId)
                foreach ($v in @($r.app, $r.level, $r.items, $r.status, $(if ($r.finished) { (ConvertTo-UtcDate $r.finished).ToString('yyyy-MM-dd HH:mm') } else { '' }))) { [void]$li.SubItems.Add([string]$v) }
                $li.Tag = $r; [void]$lv.Items.Add($li)
            }
            # The newest run starts selected. With nothing selected, the first Down key only focuses row 1
            # visually and the second row gets picked: the lab drive restored the wrong run exactly that way.
            $lv.HideSelection = $false
            if ($lv.Items.Count) { $lv.Items[0].Selected = $true; $lv.Items[0].Focused = $true }
            $note = New-Object System.Windows.Forms.Label; $note.Location = '10,284'; $note.Size = '560,36'; $note.Anchor = 'Bottom,Left'
            $note.Text = if ($runs.Count) { 'Restore puts back everything the run changed, newest change first. Runs made without a backup are not listed.' } else { 'No runs to restore. Runs made without a backup are not listed.' }
            $go = New-Object System.Windows.Forms.Button; $go.Text = 'Restore'; $go.Location = '680,286'; $go.Size = '90,28'; $go.DialogResult = 'OK'; $go.Anchor = 'Bottom,Right'
            $dlg.Controls.Add($lv); $dlg.Controls.Add($note); $dlg.Controls.Add($go); $dlg.AcceptButton = $go
            if ($dlg.ShowDialog($ui.Form) -eq 'OK' -and $lv.SelectedItems.Count) {
                $r = $lv.SelectedItems[0].Tag
                if ([System.Windows.Forms.MessageBox]::Show("Put back everything run $($r.runId) changed ($($r.app))?", 'Kill It With Fire', 'YesNo', 'Question') -eq 'Yes') { & $launch 'Restore' @('-Restore', [string]$r.runId, '-Force') }
            }
            $dlg.Dispose()
        })
    [void]$ui.Form.ShowDialog()
    $timer.Dispose()
    $ui.Form.Dispose()
    Remove-TreeLongPath $work
    return 0
}

function Invoke-GuiSelfTest {
    # Builds the window without showing it, renders it to a PNG and prints the control states as JSON:
    # how the tests prove the administrator locks, the checklist and the command line without a person
    # at the screen. -Plan loads a plan; the highest level the policy allows is selected.
    param($Policy, [string] $PngPath, [string] $PlanFile)
    $ui = New-KillItWithFireForm -Policy $Policy -PlanFile $PlanFile
    # Shown off-screen: a form that was never shown has no child windows, and DrawToBitmap then renders
    # an empty frame (the first self-test PNG was exactly that).
    $ui.Form.StartPosition = 'Manual'
    $ui.Form.Location = New-Object System.Drawing.Point(-20000, -20000)
    $ui.Form.ShowInTaskbar = $false
    $ui.Form.Show()
    [System.Windows.Forms.Application]::DoEvents()
    $max = if ($null -ne $Policy.MaxLevel) { [Math]::Min(3, [int]$Policy.MaxLevel) } else { 3 }
    $levelAfterScan = & $ui.GetLevel   # what loading a scan selected by itself, before this test touches it
    if ($ui.Plan) { $ui.Levels[$max].Checked = $true }
    if ($ui.Categories.Items.Count) { $ui.Categories.SelectedIndex = 0 }
    [System.Windows.Forms.Application]::DoEvents()
    $w = $ui.Form.Width; $h = $ui.Form.Height
    $bmp = New-Object System.Drawing.Bitmap($w, $h)
    $ui.Form.DrawToBitmap($bmp, (New-Object System.Drawing.Rectangle(0, 0, $w, $h)))
    $bmp.Save($PngPath, [System.Drawing.Imaging.ImageFormat]::Png)
    $bmp.Dispose()
    $stateOut = [ordered]@{
        level = (& $ui.GetLevel); levelsEnabled = @($ui.Levels | ForEach-Object { $_.Enabled }); levelText = $ui.LevelText.Text
        backupChecked = $ui.Backup.Checked; backupEnabled = $ui.Backup.Enabled
        logChecked = $ui.LogCheck.Checked; logEnabled = $ui.LogCheck.Enabled; logPath = $ui.LogPath.Text; logPathEnabled = $ui.LogPath.Enabled
        killItChecked = $ui.KillIt.Checked; cleanText = $ui.Clean.Text; userDataEnabled = $ui.UserData.Enabled; userDataText = $ui.UserData.Text; reviewText = $ui.Review.Text; policyLabel = $ui.PolicyLabel.Text
        categories = @($ui.Categories.Items | ForEach-Object { [string]$_ }); categoriesEnabled = $ui.Categories.Enabled; description = $ui.Description.Text
        command = $ui.Command.Text; cleanEnabled = $ui.Clean.Enabled; killItEnabled = $ui.KillIt.Enabled; killIt = $null
        levelAfterScan = $levelAfterScan; title = $ui.Form.Text; hasIcon = ($null -ne $script:WindowIcon -and [object]::ReferenceEquals($ui.Form.Icon, $script:WindowIcon)); appColumns = @($ui.Apps.Columns | ForEach-Object { $_.Text })
    }
    # The KILL IT wiring: from Scan only, ticking it must jump to Full scrub, say -KillIt, and relabel the
    # button; dropping back to level 1 must untick it (there is nothing to kill there).
    if ($ui.Plan -and $ui.KillIt.Enabled) {
        $ui.Levels[0].Checked = $true
        $ui.KillIt.Checked = $true
        [System.Windows.Forms.Application]::DoEvents()
        $k = [ordered]@{ level = (& $ui.GetLevel); command = $ui.Command.Text; cleanText = $ui.Clean.Text }
        $ui.Levels[1].Checked = $true
        [System.Windows.Forms.Application]::DoEvents()
        $k.checkedAfterLevel1 = $ui.KillIt.Checked
        $k.cleanTextAfterLevel1 = $ui.Clean.Text
        $stateOut.killIt = $k
    }
    $ui.Form.Close()
    $ui.Form.Dispose()
    Write-Host ($stateOut | ConvertTo-Json -Depth 4)
    return 0
}

# =====================================================================================================
# Main
# =====================================================================================================

function Test-Elevated {
    try {
        $id = [Security.Principal.WindowsIdentity]::GetCurrent()
        return ((New-Object Security.Principal.WindowsPrincipal $id).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator) -or $id.IsSystem)
    } catch { return $false }
}

function Invoke-Main {
    param([string] $Mode)
    $ErrorActionPreference = 'Stop'
    if ($PolicyFile -and $Mode -ne 'GuiSelfTest') { Write-Host '-PolicyFile is for the window self-test only. Policy comes from HKLM\SOFTWARE\Policies\KillItWithFire.'; return 3 }
    $policy = Get-KillItWithFirePolicy -Json $(if ($PolicyFile) { Get-Content -LiteralPath $PolicyFile -Raw } else { $null })
    $say = { param($m) if (-not $Quiet) { Write-Host $m } }
    $keepDays = if ($null -ne $policy.QuarantineDays) { [int]$policy.QuarantineDays } elseif ($QuarantineDays -gt 0) { $QuarantineDays } else { 14 }

    if ($Mode -eq 'GuiSelfTest') { return (Invoke-GuiSelfTest -Policy $policy -PngPath $GuiSelfTest -PlanFile $Plan) }
    if (-not (Test-Elevated)) {
        Write-Host 'Kill It With Fire must run elevated (admin or SYSTEM). A non-elevated scan misses services, tasks and other users, and a partial report would read like a complete one.'
        return 3
    }
    Initialize-RegistryBase
    if ($Mode -eq 'Gui') { return (Show-KillItWithFireGui -Policy $policy) }
    if ($Mode -eq 'List') {
        $entries = Get-UninstallEntries (Get-LoadedUserSids)
        $rows = $entries | Where-Object { $_.DisplayName } | Sort-Object DisplayName, DisplayVersion |
            Select-Object @{ n = 'Name'; e = { if ($_.DisplayName.Length -gt 60) { $_.DisplayName.Substring(0, 57) + '...' } else { $_.DisplayName } } }, @{ n = 'Version'; e = { $_.DisplayVersion } },
            @{ n = 'Publisher'; e = { if ($_.Publisher.Length -gt 30) { $_.Publisher.Substring(0, 27) + '...' } else { $_.Publisher } } }, @{ n = 'Type'; e = { if ($_.IsMsi) { 'MSI' } else { 'EXE' } } },
            @{ n = 'Scope'; e = { Get-EntryScopeLabel $_ } }, @{ n = 'Installed'; e = { if ($_.InstallDate) { $_.InstallDate.ToString('yyyy-MM-dd') } } },
            @{ n = 'Size'; e = { Format-AppSize $_.SizeKB } }, @{ n = 'ProductCode'; e = { $_.ProductCode } }
        $rows | Format-Table -AutoSize | Out-String -Width 400 | Write-Host
        return 0
    }
    if ($Mode -eq 'ListRuns') {
        $runs = Get-RunList
        if (-not @($runs).Count) { Write-Host 'No runs yet.'; return 0 }
        $runs | Select-Object runId, app, level, items, status, backup, started | Format-Table -AutoSize | Out-String -Width 300 | Write-Host
        return 0
    }
    if ($Mode -eq 'Restore') { return (Invoke-KillItWithFireRestore -RunId $Restore -Confirmed ([bool]$Force)) }
    if ($Mode -eq 'Resume') { return (Invoke-KillItWithFireResume -RunId $Resume) }

    # ---------------------------------------------------------------- Run: scan, then (level 1+) execute
    # -KillIt is the hard way on purpose: no uninstaller, straight to the level 3 scrub. It is ONLY a
    # shorthand: the protected list, the refusals, the policy's MaxLevel and the backup all apply exactly
    # as they do to "-Level 3 -SkipUninstall", so it can never reach anything that pair could not.
    $resolved = Resolve-RunLevel -Level $Level -KillIt ([bool]$KillIt) -SkipUninstall ([bool]$SkipUninstall)
    if ($resolved.Error) { Write-Host $resolved.Error; return 3 }
    $Level = $resolved.Level
    $SkipUninstall = $resolved.SkipUninstall
    $inc = @($Include | ForEach-Object { $_ -split ',' } | ForEach-Object { $_.Trim() } | Where-Object { $_ })
    $exc = @($Exclude | ForEach-Object { $_ -split ',' } | ForEach-Object { $_.Trim() } | Where-Object { $_ })
    foreach ($g in $inc + $exc) { if (-not $script:Categories.Contains($g)) { Write-Host "Unknown category '$g'. Categories: $($script:Categories.Keys -join ', ')"; return 3 } }
    $logFile = $null
    $violations = @(Get-PolicyViolations -Policy $policy -Level $Level -NoBackup ([bool]$NoBackup) -NoLog ([bool]$NoLog) -LogPath $Log -IncludeUserData ([bool]$IncludeUserData -or $inc -contains 'UserData') -QuarantineDays $QuarantineDays)
    if ($violations.Count) { Write-Host 'Refused by policy (HKLM\SOFTWARE\Policies\KillItWithFire):'; foreach ($v in $violations) { Write-Host "  - $v" }; return 2 }

    $planObj = $null
    if ($Plan) {
        if (-not (Test-Path -LiteralPath $Plan)) { Write-Host "No plan at $Plan"; return 3 }
        $planObj = Get-Content -LiteralPath $Plan -Raw -Encoding UTF8 | ConvertFrom-Json
        if ($planObj.computer -ne $env:COMPUTERNAME) { Write-Host "That plan was made on $($planObj.computer), not $env:COMPUTERNAME. A plan only ever runs where it was made."; return 2 }
        if ($planObj.refused) { Write-Host "That plan was refused: $($planObj.refused)"; return 2 }
        $age = (Get-Date).ToUniversalTime() - (ConvertTo-UtcDate $planObj.generatedUtc)
        if ($age.TotalHours -gt 24) { Write-Host "That plan is $([int]$age.TotalHours) hours old; scan again."; return 2 }
        # Every execution is its own run with its own journal, even when two start from the same plan.
        $planObj | Add-Member -NotePropertyName scanRunId -NotePropertyValue $planObj.runId -Force
        $planObj.runId = (Get-Date -Format 'yyyyMMdd-HHmmss') + '-' + ([guid]::NewGuid().ToString('N').Substring(0, 6))
    } else {
        $given = @($Name, $ProductCode, $UpgradeCode | Where-Object { $_ }).Count
        if ($given -ne 1) { Write-Host 'Name the app with exactly one of -Name, -ProductCode, -UpgradeCode (or -Plan). -List shows names.'; return 3 }
        # (A relaunched copy receives a list as one comma-joined argument.)
        try { $appProfiles = @(Import-AppProfile -Extra @($ProfilePath | ForEach-Object { $_ -split ',' } | Where-Object { $_ })) } catch { Write-Host "Profile error: $($_.Exception.Message)"; return 3 }
        $built = New-KillItWithFirePlan -AppName $Name -AppProductCode $ProductCode -AppUpgradeCode $UpgradeCode -AppKeyword $Keyword -Say $say -AppProfiles $appProfiles
        if ($built.Code -ne 0) {
            Write-Host $built.Message
            if ($built.ContainsKey('Near') -and $built.Near) { Write-Host 'Close matches:'; foreach ($n in $built.Near) { Write-Host "  $n" } }
            if ($built.ContainsKey('Candidates')) { foreach ($c in $built.Candidates) { Write-Host "  $c" } }
            if ($built.ContainsKey('Plan') -and $built.Plan -and $OutDir) { Write-PlanFiles $built.Plan $OutDir | Out-Null }
            return $built.Code
        }
        $planObj = $built.Plan
    }

    if ($Level -eq 0) {
        $dir = if ($OutDir) { $OutDir } else { Join-Path (Get-RunsRoot) "$($planObj.runId)-scan" }
        $files = Write-PlanFiles $planObj $dir
        if (-not $Quiet) { Write-Host ''; Write-Host (Get-Content -LiteralPath $files.Report -Raw); Write-Host "Plan: $($files.Json)" }
        return 0
    }

    $logFile = if ($NoLog) { $null } elseif ($policy.LogPath) { $policy.LogPath } elseif ($Log) { $Log } else { Join-Path (Join-Path (Get-RunsRoot) $planObj.runId) 'log.txt' }
    if ($logFile -and ((Test-Path -LiteralPath $logFile -PathType Container) -or $logFile.EndsWith('\'))) { $logFile = Join-Path $logFile "killitwithfire-$($planObj.runId)-$env:COMPUTERNAME.log" }
    if ($logFile) { $ld = Split-Path $logFile -Parent; if ($ld -and -not (Test-Path -LiteralPath $ld)) { [void](New-Item -ItemType Directory -Force -Path $ld) } }
    $selected = Select-PlanItems $planObj $Level $inc $exc ([bool]$IncludeUserData) ([bool]$IncludeReview)
    if (-not $Force) {
        Write-Host (Format-Report $planObj)
        Write-Host "About to run level $Level on $($env:COMPUTERNAME): $(@($selected).Count) change(s)$(if ($Level -ge 1 -and -not $SkipUninstall) { ' after one uninstall attempt' }). Backup: $(if ($NoBackup) { 'NONE' } else { 'yes' })."
        if (-not [Environment]::UserInteractive) { Write-Host 'Not interactive: add -Force to confirm.'; return 2 }
        $answer = Read-Host 'Type YES to continue'
        if ($answer -cne 'YES') { Write-Host 'Nothing changed.'; return 2 }
    }
    $result = Invoke-PlanExecution -Plan $planObj -Level $Level -IncludeGroups $inc -ExcludeGroups $exc -UserData ([bool]$IncludeUserData) -Review ([bool]$IncludeReview) `
        -Backup (-not $NoBackup) -DoUninstall ($Level -ge 1 -and -not $SkipUninstall) -LogFile $logFile -KeepDays $keepDays
    if ($OutDir) { Write-PlanFiles $planObj $OutDir $result | Out-Null }
    $runDir = Join-Path (Get-RunsRoot) $planObj.runId
    if (-not $Quiet) { Write-Host ''; Write-Host (Get-Content -LiteralPath (Join-Path $runDir 'report.txt') -Raw) }
    if ($result.failed) { return 1 }
    if ($result.pending) { Write-Host "A reboot is needed. After it, run: .\KillItWithFire.ps1 -Resume $($planObj.runId)"; return 3010 }
    return 0
}

if (-not $LibraryOnly) {
    $mode = $PSCmdlet.ParameterSetName
    # .NET calls resolve relative paths against the process directory, not PowerShell's location, and a
    # relaunched copy starts wherever .NET thinks it is: make every path absolute FIRST.
    foreach ($pv in @('OutDir', 'Log', 'Plan', 'GuiSelfTest', 'PolicyFile')) {
        $val = Get-Variable -Name $pv -ValueOnly
        if ($val -and -not [System.IO.Path]::IsPathRooted($val)) {
            $abs = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($val)
            Set-Variable -Name $pv -Value $abs
            if ($PSBoundParameters.ContainsKey($pv)) { $PSBoundParameters[$pv] = $abs }
        }
    }
    if ($ProfilePath) { $PSBoundParameters['ProfilePath'] = @($ProfilePath | ForEach-Object { if ([System.IO.Path]::IsPathRooted($_)) { $_ } else { $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($_) } }) }
    $relaunchArgs = ConvertTo-ArgumentList $PSBoundParameters
    # 64-bit Windows in a 32-bit host (Intune runs scripts 32-bit by default): System32 is redirected and
    # Program Files means Program Files (x86). Relaunch in the native host (review 2026-09-26).
    if ([Environment]::Is64BitOperatingSystem -and -not [Environment]::Is64BitProcess) {
        $native = Join-Path $env:SystemRoot 'Sysnative\WindowsPowerShell\v1.0\powershell.exe'
        if (Test-Path -LiteralPath $native) {
            exit (Invoke-SelfRelaunch -Exe $native -HostArgs @('-NoProfile', '-ExecutionPolicy', 'Bypass') -ScriptArgs $relaunchArgs)
        }
        Write-Host 'Kill It With Fire must run in 64-bit PowerShell on 64-bit Windows.'
        exit 3
    }
    if ($mode -eq 'Gui') {
        # No window where nobody can see it: an RMM job that runs the script with no arguments as SYSTEM
        # would otherwise hang forever on an invisible dialog.
        $me = [Security.Principal.WindowsIdentity]::GetCurrent()
        if (-not [Environment]::UserInteractive -or $me.IsSystem) {
            Write-Host 'No arguments: nothing to do in a non-interactive session. Name the app (-Name, -ProductCode, -UpgradeCode), or -List. Get-Help .\KillItWithFire.ps1 -Full shows every switch.'
            exit 3
        }
        if (-not (Test-Elevated)) {
            # Double-clicked by an admin without elevation: ask for it (UAC) instead of failing.
            try { Start-Process -FilePath (Get-PowerShellExe) -Verb RunAs -ArgumentList ((@('-NoProfile', '-STA', '-ExecutionPolicy', 'Bypass', '-File', $PSCommandPath) | ForEach-Object { ConvertTo-ArgvString $_ }) -join ' ') | Out-Null; exit 0 }
            catch { Write-Host 'Kill It With Fire needs to run as an administrator.'; exit 3 }
        }
        # The window needs a single-threaded apartment (message loop, dialogs).
        if ([System.Threading.Thread]::CurrentThread.GetApartmentState() -ne 'STA') {
            exit (Invoke-SelfRelaunch -Exe (Get-PowerShellExe) -HostArgs @('-NoProfile', '-STA', '-ExecutionPolicy', 'Bypass') -ScriptArgs $relaunchArgs)
        }
    }
    try {
        $code = Invoke-Main -Mode $mode
    } catch {
        Write-Host "Kill It With Fire stopped on an unexpected error: $($_.Exception.Message) (line $($_.InvocationInfo.ScriptLineNumber))"
        if ($script:Run) { Write-Host "Changes made before the error are in the journal: -Restore $($script:Run.RunId)" }
        $code = 4
    }
    exit $code
}
