#Requires -Version 5.1
<#
.SYNOPSIS
    Destructive end-to-end validation of Kill It With Fire. THROWAWAY MACHINES ONLY (a lab VM or a CI runner).

.DESCRIPTION
    Installs real apps, breaks them the way broken uninstalls really look, runs Kill It With Fire at every level,
    and checks every change AND every restore on the machine itself. It edits HKLM, creates services
    and a device class filter, and turns the password sign-in off and on. Never run it on a machine
    you care about: it refuses to start without -ConfirmThrowaway.

    Scenarios (each prints PASS/FAIL lines and writes <StateDir>\<scenario>-<phase>.json):
      putty      L2 on an MSI whose cached package and source are gone; reinstall works; restore round trip
      profile    profiles\PuTTY.psd1 adds the user's saved sessions (user data, opt-in); restore round trip
      notepadpp  L3 on an app whose uninstaller is gone; restore round trip; the app runs again
      hooks      one synthetic app hooked in a dozen ways (IFEO, AppInit, Userinit, Active Setup, verbs, file
                 types, shortcut, task, Run, firewall, service): all found, removed, restored exactly
      restorestop  a restore that can't undo one change stops there; a rerun finishes once the cause is gone
      plan       the window's path: -Plan <file> -Exclude ...; plan guards (other computer, stale plan)
      policy     HKLM\SOFTWARE\Policies\KillItWithFire locks enforced by the engine (and shown by the window)
      refusal    the RFF agent, a Microsoft MSI by ProductCode, a security vendor, a Windows keyword
      bitness    a 32-bit PowerShell host relaunches 64-bit and finds the same plan
      pending    a locked file: exit 3010, then restore BEFORE the reboot (CI-safe)
      resume     a locked file: exit 3010; phase 'after' (after a reboot): -Resume, then restore
      filter     a keyboard class filter + its driver; phases setup, broken, cleaned, restored, final
                 (the host reboots between phases and checks the keyboard device each time)
      credprov   a credential provider + the built-in password sign-in turned off; phases setup,
                 broken, cleaned, restored, final (the host reboots and tries a real sign-in)
      npcap      a real NDIS network component (Npcap: netcfg -u, pnputil /delete-driver, the driver);
                 phases setup, broken, cleaned, restored, final (the host installs Npcap through its
                 wizard and reboots between phases; the network must work after every boot)
      everything an app with a Windows service (voidtools Everything), uninstaller gone; restore round trip
      sevenzip   an MSI with shell extensions (7-Zip), cached package gone (1612); other handlers untouched
      zoom       a per-user install (Zoom, %APPDATA%, HKCU); profiles\Zoom.psd1 adds HKCU\Software\ZoomUMX

    Phases that follow a reboot read what the earlier phase saved in <StateDir>.

.PARAMETER ConfirmThrowaway
    Required: says this machine may be broken by the test.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidateSet('putty', 'profile', 'notepadpp', 'hooks', 'restorestop', 'plan', 'policy', 'refusal', 'bitness', 'pending', 'resume', 'filter', 'credprov', 'npcap', 'everything', 'sevenzip', 'zoom')]
    [string] $Scenario,
    [string] $Phase = 'run',
    [string] $Engine,
    [string] $Media,
    [string] $StateDir = (Join-Path $env:ProgramData 'KillItWithFireLab'),
    [string] $HostExe = (Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'),
    [switch] $ConfirmThrowaway
)
Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'
# Not parameter defaults: Windows PowerShell 5.1 leaves $PSScriptRoot empty while defaults are evaluated.
if (-not $Engine) { $Engine = Join-Path $PSScriptRoot '..\KillItWithFire.ps1' }
if (-not $Media) { $Media = Join-Path $PSScriptRoot '..\lab-media' }
if (-not $ConfirmThrowaway) {
    Write-Host 'Refusing: this validation installs, breaks and removes software, edits HKLM, adds a device filter and turns the password sign-in off. Run it only on a throwaway lab VM or CI runner, with -ConfirmThrowaway.'
    exit 2
}
$Engine = (Resolve-Path -LiteralPath $Engine).Path
New-Item -ItemType Directory -Force -Path $StateDir | Out-Null
$script:Checks = New-Object System.Collections.Generic.List[object]
$script:RunsRoot = Join-Path $env:ProgramData 'KillItWithFire\runs'

# ------------------------------------------------------------------------------------------ helpers

function Check {
    param([string] $Name, [bool] $Ok, [string] $Detail = '')
    $script:Checks.Add([pscustomobject][ordered]@{ name = $Name; pass = $Ok; detail = $Detail })
    Write-Host ("{0}  {1}{2}" -f $(if ($Ok) { 'PASS' } else { 'FAIL' }), $Name, $(if ($Detail) { "  ($Detail)" } else { '' }))
}

function Invoke-Engine {
    # Runs Kill It With Fire in its own process (the way an RMM would) and returns the exit code and output.
    param([string[]] $Arguments, [string] $Exe = $HostExe)
    $out = Join-Path $StateDir ('engine-' + [guid]::NewGuid().ToString('N').Substring(0, 8) + '.txt')
    $argLine = @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', $Engine) + $Arguments
    # CommandLineToArgvW rules: backslashes doubled before a quote (a trailing '\' ate the closing quote).
    $quoted = @($argLine | ForEach-Object {
            if ($_ -and $_ -notmatch '[\s"]') { $_ } else {
                $s = [regex]::Replace($_, '(\\*)"', { param($m) ($m.Groups[1].Value * 2) + '\"' })
                '"' + [regex]::Replace($s, '(\\+)$', { param($m) $m.Groups[1].Value * 2 }) + '"'
            } })
    $p = Start-Process -FilePath $Exe -ArgumentList $quoted -PassThru -Wait -NoNewWindow -RedirectStandardOutput $out
    $text = if (Test-Path -LiteralPath $out) { Get-Content -LiteralPath $out -Raw } else { '' }
    Remove-Item -LiteralPath $out -Force -ErrorAction SilentlyContinue
    return [pscustomobject]@{ Code = $p.ExitCode; Output = [string]$text }
}

function Get-NewestRun {
    param([datetime] $Since)
    if (-not (Test-Path -LiteralPath $script:RunsRoot)) { return $null }
    $runs = @(Get-ChildItem -LiteralPath $script:RunsRoot -Directory | Where-Object { $_.Name -notlike '*-scan' -and (Test-Path (Join-Path $_.FullName 'run.json')) -and $_.CreationTime -ge $Since } | Sort-Object CreationTime -Descending)
    if (-not $runs.Count) { return $null }
    return (Get-Content -LiteralPath (Join-Path $runs[0].FullName 'run.json') -Raw | ConvertFrom-Json)
}

function Get-Plan {
    param([string] $Dir)
    return (Get-Content -LiteralPath (Join-Path $Dir 'plan.json') -Raw | ConvertFrom-Json)
}

function Get-Journal {
    param([string] $RunId, [string] $Name = 'journal.jsonl')
    $f = Join-Path $script:RunsRoot "$RunId\$Name"
    if (-not (Test-Path -LiteralPath $f)) { return @() }
    return @(Get-Content -LiteralPath $f | Where-Object { $_.Trim() } | ForEach-Object { $_ | ConvertFrom-Json })
}

if (-not ('KillItWithFireLab.Native' -as [type])) {
    Add-Type -Namespace KillItWithFireLab -Name Native -MemberDefinition @"
[DllImport("ntdll.dll")]
private static extern int NtQueryKey(IntPtr keyHandle, int keyInformationClass, IntPtr keyInformation, int length, out int resultLength);
public static string GetKeyName(IntPtr keyHandle) {
    int len;
    NtQueryKey(keyHandle, 3, IntPtr.Zero, 0, out len);
    if (len <= 4) { return null; }
    IntPtr buf = Marshal.AllocHGlobal(len);
    try {
        if (NtQueryKey(keyHandle, 3, buf, len, out len) != 0) { return null; }
        return Marshal.PtrToStringUni(new IntPtr(buf.ToInt64() + 4), Marshal.ReadInt32(buf) / 2);
    } finally { Marshal.FreeHGlobal(buf); }
}
"@
}

function Get-RegPhysical {
    # Where the key really is (most of SOFTWARE\Classes is shared between the 32- and 64-bit views).
    param([string] $Hive, [string] $Path)
    $k = Open-RegKey $Hive $Path
    if ($k) {
        try { $n = [KillItWithFireLab.Native]::GetKeyName($k.Handle.DangerousGetHandle()) } finally { $k.Close() }
        if ($n -match '^(?i)\\REGISTRY\\MACHINE\\(.+)$') { return 'HKEY_LOCAL_MACHINE\' + $matches[1] }
        if ($n -match '^(?i)\\REGISTRY\\USER\\(.+)$') { return 'HKEY_USERS\' + $matches[1] }
    }
    switch ($Hive) {
        'HKLM64' { return "HKEY_LOCAL_MACHINE\$Path" }
        'HKLM32' { if ($Path -match '^(?i)SOFTWARE\\(.*)$') { return "HKEY_LOCAL_MACHINE\SOFTWARE\WOW6432Node\$($matches[1])" } return "HKEY_LOCAL_MACHINE\$Path" }
        'HKU' { return "HKEY_USERS\$Path" }
    }
    return $Path
}

function Open-RegKey {
    param([string] $Hive, [string] $Path)
    $h = if ($Hive -eq 'HKU') { [Microsoft.Win32.RegistryHive]::Users } else { [Microsoft.Win32.RegistryHive]::LocalMachine }
    $v = if ($Hive -eq 'HKLM32') { [Microsoft.Win32.RegistryView]::Registry32 } else { [Microsoft.Win32.RegistryView]::Registry64 }
    return [Microsoft.Win32.RegistryKey]::OpenBaseKey($h, $v).OpenSubKey($Path)
}

function Get-Hash {
    param([string] $Text)
    $sha = [System.Security.Cryptography.SHA256]::Create()
    return ([BitConverter]::ToString($sha.ComputeHash([System.Text.Encoding]::UTF8.GetBytes($Text))) -replace '-', '').Substring(0, 16)
}

function Get-KeyFingerprint {
    param([string] $Hive, [string] $Path)
    $k = Open-RegKey $Hive $Path
    if (-not $k) { return 'absent' }
    $k.Close()
    $tmp = Join-Path $StateDir 'fp.reg'
    & reg.exe export (Get-RegPhysical $Hive $Path) $tmp /y *> $null
    $text = [System.IO.File]::ReadAllText($tmp)
    Remove-Item -LiteralPath $tmp -Force
    return 'key:' + (Get-Hash $text)
}

function Get-ValueFingerprint {
    param([string] $Hive, [string] $Path, [string] $Name)
    $k = Open-RegKey $Hive $Path
    if (-not $k) { return 'absent' }
    try {
        if (-not ($k.GetValueNames() -contains $Name)) { return 'absent' }
        $d = $k.GetValue($Name, $null, [Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames)
        return "$($k.GetValueKind($Name)):" + (@($d) -join '|')
    } finally { $k.Close() }
}

function Get-PathFingerprint {
    param([string] $Path)
    if (-not (Test-Path -LiteralPath $Path)) { return 'absent' }
    if (Test-Path -LiteralPath $Path -PathType Leaf) { return 'file:' + (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.Substring(0, 16) }
    $lines = @(Get-ChildItem -LiteralPath $Path -Recurse -Force -File -ErrorAction Stop | Sort-Object FullName | ForEach-Object {
            $_.FullName.Substring($Path.Length) + '|' + $_.Length + '|' + (Get-FileHash -LiteralPath $_.FullName -Algorithm SHA256).Hash.Substring(0, 16) })
    $dirs = @(Get-ChildItem -LiteralPath $Path -Recurse -Force -Directory -ErrorAction Stop | Sort-Object FullName | ForEach-Object { $_.FullName.Substring($Path.Length) })
    return 'dir:' + (Get-Hash (($lines + $dirs) -join "`n")) + ":$($lines.Count)f"
}

function Get-OpFingerprint {
    # What the thing an operation changes looks like right now. Equal before a run and after its
    # restore = the restore really put it back.
    param($Op)
    $kind = [string]$Op.kind
    switch ($kind) {
        'RegDeleteKey' { return (Get-KeyFingerprint $Op.hive $Op.path) }
        { $_ -in @('RegDeleteValue', 'RegRemoveMultiSzEntry', 'RegRemoveListEntry', 'RegSetValue') } { return (Get-ValueFingerprint $Op.hive $Op.path ([string]$Op.name)) }
        'MsiComponentClients' {
            $parts = @(foreach ($e in @($Op.entries)) { Get-ValueFingerprint 'HKLM64' "SOFTWARE\Microsoft\Windows\CurrentVersion\Installer\UserData\$($e.sid)\Components\$($e.component)" ([string]$Op.packedPc) })
            if (-not @($parts | Where-Object { $_ -ne 'absent' }).Count) { return 'absent' }
            return 'comp:' + (Get-Hash ($parts -join "`n"))
        }
        'ServiceDelete' {
            $fk = Get-KeyFingerprint 'HKLM64' "SYSTEM\CurrentControlSet\Services\$($Op.name)"
            $fi = if ($Op.image) { Get-PathFingerprint ([string]$Op.image) } else { 'absent' }
            if ($fk -eq 'absent' -and $fi -eq 'absent') { return 'absent' }
            return "$fk|$fi"
        }
        'FileQuarantine' { return (Get-PathFingerprint ([string]$Op.path)) }
        'TaskUnregister' {
            $t = Get-ScheduledTask -TaskPath $Op.taskPath -TaskName $Op.taskName -ErrorAction SilentlyContinue
            if (-not $t) { return 'absent' }
            return 'task:' + (Get-Hash (Export-ScheduledTask -TaskPath $Op.taskPath -TaskName $Op.taskName))
        }
        'FirewallRuleDelete' { $r = Get-NetFirewallRule -Name $Op.id -ErrorAction SilentlyContinue; if ($r) { return "rule:$($r.DisplayName)" } return 'absent' }
        'DriverPackageDelete' { if (Test-Path (Join-Path $env:SystemRoot "INF\$($Op.inf)")) { return 'inf:present' } return 'absent' }
        'NetcfgUninstall' { if (Test-NetComponent ([string]$Op.componentId)) { return 'component:present' } return 'absent' }
        default { return "n/a:$kind" }
    }
}

function Get-PlanState {
    # Fingerprint of every operation of the given items, keyed "<item id>.<op index>".
    param([object[]] $Items)
    $state = [ordered]@{}
    foreach ($i in $Items) {
        $n = 0
        foreach ($op in @($i.op)) { $state["$($i.id).$n"] = Get-OpFingerprint $op; $n++ }
    }
    return $state
}

function Compare-State {
    param($Before, $After, [string] $What)
    $diff = @()
    foreach ($k in $Before.Keys) { if ($Before[$k] -ne $After[$k]) { $diff += "$k [$($Before[$k]) -> $($After[$k])]" } }
    Check $What ($diff.Count -eq 0) $(if ($diff.Count) { ($diff | Select-Object -First 6) -join '; ' } else { "$($Before.Count) item states identical" })
}

function Get-SelectedItems {
    # The items a run at this level acts on by default (mirror of the engine's rules, kept independent
    # on purpose: the test must not trust the code it tests).
    param($Plan, [int] $Level, [string[]] $ExcludeGroups = @(), [switch] $UserData, [switch] $Review)
    return @($Plan.items | Where-Object { $_.level -le $Level -and $null -ne $_.op -and ($ExcludeGroups -notcontains $_.group) -and ($UserData -or $_.group -ne 'UserData') -and ($Review -or -not $_.review) })
}

function Get-MsiProductState {
    param([string] $ProductCode)
    $i = New-Object -ComObject WindowsInstaller.Installer
    return [int]$i.GetType().InvokeMember('ProductState', [System.Reflection.BindingFlags]::GetProperty, $null, $i, @($ProductCode))
}

function Get-Uninstall {
    # -Msi: only a Windows Installer entry (a GitHub runner already has 7-Zip from its EXE installer).
    param([string] $DisplayNameLike, [switch] $Msi)
    foreach ($root in @('HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall', 'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall')) {
        foreach ($k in @(Get-ChildItem -LiteralPath $root -ErrorAction SilentlyContinue)) {
            $p = Get-ItemProperty -LiteralPath $k.PSPath -ErrorAction SilentlyContinue
            if (-not $p -or -not ($p.PSObject.Properties.Name -contains 'DisplayName') -or $p.DisplayName -notlike $DisplayNameLike) { continue }
            if ($Msi -and -not (($p.PSObject.Properties.Name -contains 'WindowsInstaller') -and $p.WindowsInstaller -eq 1)) { continue }
            return $p
        }
    }
    return $null
}

function Test-NetComponent {
    # Independent of the engine: what netcfg itself lists.
    param([string] $ComponentId)
    return [bool](@(& netcfg.exe -s n) | Where-Object { $_ -match ('^\s*' + [regex]::Escape($ComponentId) + '\s') })
}

function Test-Network {
    # The machine is still on the network: every adapter that was up is up, and a name resolves.
    param([int] $UpBefore)
    $up = @(Get-NetAdapter -ErrorAction SilentlyContinue | Where-Object { $_.Status -eq 'Up' }).Count
    $dns = [bool](Resolve-DnsName www.microsoft.com -ErrorAction SilentlyContinue)
    return [pscustomobject]@{ Ok = ($up -ge $UpBefore -and $dns); Detail = "$up adapter(s) up (was $UpBefore), DNS $(if ($dns) { 'resolves' } else { 'FAILS' })" }
}

function Get-DeviceErrors {
    return @(Get-PnpDevice -PresentOnly -ErrorAction SilentlyContinue | Where-Object { $_.Status -eq 'Error' } | ForEach-Object { $_.FriendlyName })
}

function Get-UserUninstall {
    # A per-user uninstall entry in any loaded user hive.
    param([string] $DisplayNameLike)
    foreach ($h in @(Get-ChildItem Registry::HKEY_USERS | Where-Object { $_.PSChildName -match '^S-1-5-21-[\d-]+$' })) {
        foreach ($k in @(Get-ChildItem -LiteralPath "Registry::$($h.Name)\Software\Microsoft\Windows\CurrentVersion\Uninstall" -ErrorAction SilentlyContinue)) {
            $p = Get-ItemProperty -LiteralPath $k.PSPath -ErrorAction SilentlyContinue
            if ($p -and ($p.PSObject.Properties.Name -contains 'DisplayName') -and $p.DisplayName -like $DisplayNameLike) { return $p }
        }
    }
    return $null
}

function Get-PendingRenames {
    # The boot-time move list, or none: once the last entry is gone Windows removes the value itself.
    $k = Open-RegKey 'HKLM64' 'SYSTEM\CurrentControlSet\Control\Session Manager'
    try { $v = $k.GetValue('PendingFileRenameOperations', $null) } finally { $k.Close() }
    if ($null -eq $v) { return @() }
    return @($v)
}

function Save-State { param([string] $Name, $Value) ($Value | ConvertTo-Json -Depth 8) | Set-Content -LiteralPath (Join-Path $StateDir "$Name.json") -Encoding UTF8 }
function Read-State { param([string] $Name) return (Get-Content -LiteralPath (Join-Path $StateDir "$Name.json") -Raw | ConvertFrom-Json) }

function ConvertTo-Ordered {
    # A saved state (JSON object) back to the ordered map Compare-State takes.
    param($Object)
    $h = [ordered]@{}
    foreach ($p in $Object.PSObject.Properties) { $h[$p.Name] = [string]$p.Value }
    return $h
}

function Invoke-Msiexec {
    param([string] $Arguments)
    $p = Start-Process -FilePath (Join-Path $env:SystemRoot 'System32\msiexec.exe') -ArgumentList $Arguments -Wait -PassThru
    return $p.ExitCode
}

function New-TestApp {
    # A small synthetic app: a folder with files, an uninstall entry whose uninstaller is missing.
    param([string] $Key, [string] $DisplayName, [string] $Folder, [string[]] $Files, [string] $Publisher = 'KillItWithFire Lab')
    New-Item -ItemType Directory -Force -Path $Folder | Out-Null
    foreach ($f in $Files) { Set-Content -LiteralPath (Join-Path $Folder $f) -Value "KillItWithFire lab file $f $(Get-Date -Format o)" -Encoding ASCII }
    $u = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\$Key"
    New-Item -Path $u -Force | Out-Null
    New-ItemProperty -Path $u -Name DisplayName -Value $DisplayName -Force | Out-Null
    New-ItemProperty -Path $u -Name Publisher -Value $Publisher -Force | Out-Null
    New-ItemProperty -Path $u -Name DisplayVersion -Value '1.0.0' -Force | Out-Null
    New-ItemProperty -Path $u -Name InstallLocation -Value $Folder -Force | Out-Null
    New-ItemProperty -Path $u -Name UninstallString -Value "`"$Folder\uninstall.exe`"" -Force | Out-Null
}

function Remove-TestApp {
    param([string] $Key, [string] $Folder)
    Remove-Item -LiteralPath "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\$Key" -Recurse -Force -ErrorAction SilentlyContinue
    if ($Folder) { Remove-Item -LiteralPath $Folder -Recurse -Force -ErrorAction SilentlyContinue }
}

function Finish {
    $file = Join-Path $StateDir "$Scenario-$Phase.json"
    ($script:Checks | ConvertTo-Json -Depth 4) | Set-Content -LiteralPath $file -Encoding UTF8
    $failed = @($script:Checks | Where-Object { -not $_.pass }).Count
    Write-Host ("{0} {1}: {2} passed, {3} failed" -f $Scenario, $Phase, ($script:Checks.Count - $failed), $failed)
    exit ([int]($failed -gt 0))
}

# ------------------------------------------------------------------------------------------ scenarios

$started = Get-Date
switch ($Scenario) {

    'putty' {
        # PuTTY 0.81 MSI, broken for real: cached package AND install source deleted, so msiexec /x = 1612.
        $pc = '{DDC95F26-92B1-4546-9678-5DC68DF76BA0}'
        $msi = Join-Path $Media 'putty-64bit-0.81-installer.msi'
        $src = Join-Path $StateDir 'putty-source.msi'
        function Set-BrokenPutty {
            if ((Get-MsiProductState $pc) -ne 5) {
                Copy-Item -LiteralPath $msi -Destination $src -Force
                $c = Invoke-Msiexec "/i `"$src`" /qn /norestart"
                if ($c -ne 0) { throw "PuTTY install failed: $c" }
            }
            foreach ($k in @(Get-ChildItem 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Installer\UserData\S-1-5-18\Products' -ErrorAction SilentlyContinue)) {
                $ip = Get-ItemProperty -LiteralPath (Join-Path $k.PSPath 'InstallProperties') -ErrorAction SilentlyContinue
                if ($ip -and ($ip.PSObject.Properties.Name -contains 'DisplayName') -and $ip.DisplayName -like 'PuTTY release 0.81*' -and $ip.LocalPackage -and (Test-Path -LiteralPath $ip.LocalPackage)) {
                    Remove-Item -LiteralPath $ip.LocalPackage -Force
                }
            }
            if (Test-Path -LiteralPath $src) { Remove-Item -LiteralPath $src -Force }
        }
        Set-BrokenPutty
        Check 'precondition: PuTTY is broken (msiexec /x = 1612)' ((Invoke-Msiexec "/x $pc /qn /norestart") -eq 1612)

        $scan = Join-Path $StateDir 'putty-scan'
        $r = Invoke-Engine @('-ProductCode', $pc, '-Level', '0', '-OutDir', $scan, '-Quiet')
        Check 'scan exit 0' ($r.Code -eq 0) "exit $($r.Code)"
        $plan = Get-Plan $scan
        $cats = @($plan.items | ForEach-Object { $_.category } | Select-Object -Unique)
        foreach ($c in @('UninstallEntry', 'MsiProduct', 'MsiUpgradeCode', 'MsiComponentClient')) { Check "plan has $c" ($cats -contains $c) }
        Check 'plan: files are level 3 only' (@($plan.items | Where-Object { $_.group -eq 'Files' -and $_.level -lt 3 }).Count -eq 0)
        $sel = Get-SelectedItems $plan 2
        $s0 = Get-PlanState $sel

        $r = Invoke-Engine @('-ProductCode', $pc, '-Level', '2', '-Force', '-Quiet')
        Check 'L2 exit 0' ($r.Code -eq 0) "exit $($r.Code)"
        $run = Get-NewestRun $started
        Check 'L2 made a run with a backup' ($null -ne $run -and $run.backup -and $run.status -eq 'done') "$($run.runId) $($run.status)"
        $s1 = Get-PlanState $sel
        $notGone = @($s1.Keys | Where-Object { $s1[$_] -ne 'absent' -and $s1[$_] -notlike 'n/a:*' })
        Check 'L2: every registration item is gone' ($notGone.Count -eq 0) ($notGone -join ', ')
        Check 'L2: Windows Installer no longer knows the product' ((Get-MsiProductState $pc) -eq -1)
        Check 'L2: files untouched' (Test-Path 'C:\Program Files\PuTTY\putty.exe')
        $journal = Get-Journal $run.runId
        Check 'L2: the uninstall attempt ran first and failed as expected (1612)' ((@($journal | Where-Object { $_.kind -eq 'UninstallAttempt' })[0].note) -like 'exit 1612*')

        $r = Invoke-Engine @('-Restore', $run.runId, '-Force', '-Quiet')
        Check 'restore exit 0' ($r.Code -eq 0) "exit $($r.Code)"
        Compare-State $s0 (Get-PlanState $sel) 'restore: every item back exactly as it was'
        Check 'restore: Windows Installer knows the product again' ((Get-MsiProductState $pc) -eq 5)
        Check 'restore: it is broken again, exactly as before (msiexec /x = 1612)' ((Invoke-Msiexec "/x $pc /qn /norestart") -eq 1612)
        $again = Invoke-Engine @('-Restore', $run.runId, '-Force')
        Check 'a second restore has nothing left to do' ($again.Code -eq 0 -and $again.Output -match ': 0 change\(s\)') "exit $($again.Code)"

        $r = Invoke-Engine @('-ProductCode', $pc, '-Level', '2', '-Force', '-Quiet')
        Check 'L2 again exit 0' ($r.Code -eq 0) "exit $($r.Code)"
        Copy-Item -LiteralPath $msi -Destination $src -Force
        Check 'THE POINT: a reinstall works after L2' ((Invoke-Msiexec "/i `"$src`" /qn /norestart") -eq 0)
        Check 'reinstalled product is registered' ((Get-MsiProductState $pc) -eq 5)
        Check 'and it uninstalls cleanly the normal way' ((Invoke-Msiexec "/x $pc /qn /norestart") -eq 0)
        Check 'normal uninstall removed the files' (-not (Test-Path 'C:\Program Files\PuTTY\putty.exe'))
        Set-BrokenPutty
        Check 'left broken again for the next run' ((Invoke-Msiexec "/x $pc /qn /norestart") -eq 1612)
    }

    'notepadpp' {
        $name = 'Notepad++ (64-bit x64)'
        $root = 'C:\Program Files\Notepad++'
        if (-not (Get-Uninstall $name)) {
            $p = Start-Process -FilePath (Join-Path $Media 'npp.8.6.4.Installer.x64.exe') -ArgumentList '/S' -Wait -PassThru
            if ($p.ExitCode -ne 0) { throw "Notepad++ install failed: $($p.ExitCode)" }
            Start-Sleep -Seconds 3
        }
        if (Test-Path "$root\uninstall.exe") { Remove-Item "$root\uninstall.exe" -Force }
        Check 'precondition: Notepad++ installed, its uninstaller gone' ((Get-Uninstall $name) -and -not (Test-Path "$root\uninstall.exe"))

        # Notepad++ running (it starts its updater, gup.exe, from the same folder): a real app is often
        # still running when it gets cleaned up, and a running updater once held this folder in place.
        $running = { @(Get-Process -ErrorAction SilentlyContinue | Where-Object { $ip = $null; try { $ip = $_.Path } catch { }; $ip -and $ip -like "$root\*" }) }
        [void](Start-Process "$root\notepad++.exe" -ArgumentList '-multiInst', '-nosession' -PassThru)
        Start-Sleep -Seconds 6
        Check 'precondition: Notepad++ is running from its folder' (@(& $running).Count -ge 1) ((@(& $running) | ForEach-Object { $_.ProcessName }) -join ', ')

        $scan = Join-Path $StateDir 'npp-scan'
        $r = Invoke-Engine @('-Name', $name, '-Level', '0', '-OutDir', $scan, '-Quiet')
        Check 'scan exit 0' ($r.Code -eq 0) "exit $($r.Code)"
        $plan = Get-Plan $scan
        Check 'plan has the uninstall entry and the install folder' ((@($plan.items | Where-Object { $_.category -eq 'UninstallEntry' }).Count -ge 1) -and (@($plan.items | Where-Object { $_.category -eq 'InstallRoot' -and $_.target -eq $root }).Count -eq 1))
        Check 'plan: stop the running notepad++.exe (high risk: unsaved work)' (@($plan.items | Where-Object { $_.category -eq 'RunningProcess' -and $_.target -like '*\notepad++.exe' -and $_.risk -eq 'high' }).Count -eq 1)
        Check 'plan keyword is Notepad++, whole-word (not "Notepad")' ($plan.keyword.value -eq 'Notepad++')
        Check 'no plan item touches Windows Notepad' (@($plan.items | Where-Object { $_.target -match '(?i)\\notepad\.exe|txtfile' -and $_.op }).Count -eq 0)
        $sel = Get-SelectedItems $plan 3
        $s0 = Get-PlanState $sel

        $r = Invoke-Engine @('-Name', $name, '-Level', '3', '-Force', '-Quiet')
        Check 'L3 exit 0' ($r.Code -eq 0) "exit $($r.Code)"
        $run = Get-NewestRun $started
        $s1 = Get-PlanState $sel
        $notGone = @($s1.Keys | Where-Object { $s1[$_] -ne 'absent' -and $s1[$_] -notlike 'n/a:*' })
        Check 'L3: nothing runs from the folder any more' (@(& $running).Count -eq 0)
        Check 'L3: every selected item is gone' ($notGone.Count -eq 0) ($notGone -join ', ')
        Check 'L3: the folder is gone' (-not (Test-Path $root))
        Check 'L3: the folder is in the quarantine' (Test-Path (Join-Path $script:RunsRoot "$($run.runId)\files\C\Program Files\Notepad++\notepad++.exe"))
        Check 'L3: the uninstall entry is gone' (-not (Get-Uninstall $name))
        Check 'L3: Windows Notepad still there' (Test-Path (Join-Path $env:SystemRoot 'System32\notepad.exe'))
        $acl = (Get-Acl -LiteralPath (Join-Path $script:RunsRoot $run.runId)).Access | ForEach-Object { $_.IdentityReference.Value }
        Check 'quarantine readable by SYSTEM and Administrators only' (-not ($acl | Where-Object { $_ -match '(?i)Users|Everyone|Authenticated' })) ($acl -join ', ')

        $r = Invoke-Engine @('-Restore', $run.runId, '-Force', '-Quiet')
        Check 'restore exit 0' ($r.Code -eq 0) "exit $($r.Code)"
        Compare-State $s0 (Get-PlanState $sel) 'restore: every item back exactly as it was (files hashed)'
        $v = (Get-Item "$root\notepad++.exe").VersionInfo.ProductVersion
        Check 'restore: notepad++.exe is back' ($v -like '8.6.4*') $v
        $p = Start-Process "$root\notepad++.exe" -ArgumentList '-multiInst', '-nosession', '-notabbar' -PassThru
        Start-Sleep -Seconds 4
        $alive = -not $p.HasExited
        Check 'restore: Notepad++ starts and runs' $alive
        # Leave nothing running from the folder (its updater included) for the scenarios after this one.
        & $running | Stop-Process -Force -ErrorAction SilentlyContinue
    }

    'plan' {
        # The window's path: scan to a file, then -Plan <file> with categories left out.
        # Any 7-Zip MSI (a healthy one: this scenario checks the partial run and its restore, not breakage).
        $z = Get-Uninstall '7-Zip*' -Msi
        if (-not $z) {
            $zmsi = @(Get-ChildItem -LiteralPath $Media -Filter '7z*.msi' -ErrorAction SilentlyContinue | Select-Object -First 1)
            if (-not $zmsi.Count) { Check 'precondition: a 7-Zip MSI is installed (or 7z*.msi is in the media folder)' $false; Finish }
            [void](Invoke-Msiexec "/i `"$($zmsi[0].FullName)`" /qn /norestart")
            $z = Get-Uninstall '7-Zip*' -Msi
        }
        if (-not $z) { Check 'precondition: the 7-Zip MSI installed' $false; Finish }
        $pc = $z.PSChildName
        if ((Get-MsiProductState $pc) -ne 5) { Check "precondition: 7-Zip MSI $pc installed" $false; Finish }
        $scan = Join-Path $StateDir 'plan-scan'
        $r = Invoke-Engine @('-ProductCode', $pc, '-Level', '0', '-OutDir', $scan, '-Quiet')
        Check 'scan exit 0' ($r.Code -eq 0) "exit $($r.Code)"
        $plan = Get-Plan $scan
        $exclude = @('Registration', 'Files', 'Registry')
        $sel = Get-SelectedItems $plan 3 -ExcludeGroups $exclude
        Check 'the plan has something outside the excluded groups' ($sel.Count -gt 0) "$($sel.Count) item(s)"
        $keepSel = @(Get-SelectedItems $plan 3 | Where-Object { $exclude -contains $_.group })
        $s0 = Get-PlanState $sel
        $k0 = Get-PlanState $keepSel

        $bad = Get-Content -LiteralPath (Join-Path $scan 'plan.json') -Raw | ConvertFrom-Json
        $bad.computer = 'SOME-OTHER-PC'
        ($bad | ConvertTo-Json -Depth 10) | Set-Content -LiteralPath (Join-Path $StateDir 'plan-other.json') -Encoding UTF8
        $r = Invoke-Engine @('-Plan', (Join-Path $StateDir 'plan-other.json'), '-Level', '3', '-Force', '-Quiet')
        Check 'a plan from another computer is refused (exit 2)' ($r.Code -eq 2) "exit $($r.Code)"
        $bad.computer = $env:COMPUTERNAME
        $bad.generatedUtc = (Get-Date).ToUniversalTime().AddDays(-2).ToString('o')
        ($bad | ConvertTo-Json -Depth 10) | Set-Content -LiteralPath (Join-Path $StateDir 'plan-old.json') -Encoding UTF8
        $r = Invoke-Engine @('-Plan', (Join-Path $StateDir 'plan-old.json'), '-Level', '3', '-Force', '-Quiet')
        Check 'a two-day-old plan is refused (exit 2)' ($r.Code -eq 2) "exit $($r.Code)"

        # -SkipUninstall: 7-Zip is healthy here, and its own uninstaller would really remove it.
        $r = Invoke-Engine @('-Plan', (Join-Path $scan 'plan.json'), '-Level', '3', '-Force', '-SkipUninstall', '-Exclude', ($exclude -join ','), '-Quiet')
        Check '-Plan run exit 0' ($r.Code -eq 0) "exit $($r.Code)"
        $run = Get-NewestRun $started
        Check 'the run got its own id (not the scan''s)' ($run.runId -ne $plan.runId) $run.runId
        $s1 = Get-PlanState $sel
        Check '-Plan run: every selected item is gone' (@($s1.Keys | Where-Object { $s1[$_] -ne 'absent' -and $s1[$_] -notlike 'n/a:*' }).Count -eq 0)
        Compare-State $k0 (Get-PlanState $keepSel) '-Exclude: the excluded groups were not touched'
        Check '7-Zip is still installed' ((Get-MsiProductState $pc) -eq 5)
        $r = Invoke-Engine @('-Restore', $run.runId, '-Force', '-Quiet')
        Check 'restore exit 0' ($r.Code -eq 0) "exit $($r.Code)"
        Compare-State $s0 (Get-PlanState $sel) 'restore: every item back exactly as it was'
        $list = Invoke-Engine @('-ListRuns')
        Check '-ListRuns shows the run as restored' ($list.Output -match [regex]::Escape($run.runId) -and $list.Output -match 'restored')
    }

    'profile' {
        # profiles\PuTTY.psd1 adds what identity can't see: the user's saved sessions and random seed.
        $pc = '{DDC95F26-92B1-4546-9678-5DC68DF76BA0}'
        if ((Get-MsiProductState $pc) -ne 5) { Check 'precondition: PuTTY 0.81 registered (run the putty scenario first)' $false; Finish }
        $sessKey = 'HKCU:\Software\SimonTatham\PuTTY\Sessions\KillItWithFireTest'
        $rnd = Join-Path $env:APPDATA 'putty.rnd'
        New-Item -Path $sessKey -Force | Out-Null
        New-ItemProperty -Path $sessKey -Name HostName -Value 'lab.example' -Force | Out-Null
        Set-Content -LiteralPath $rnd -Value 'seed' -Encoding ASCII
        try {
            $scan = Join-Path $StateDir 'profile-scan'
            $r = Invoke-Engine @('-ProductCode', $pc, '-Level', '0', '-OutDir', $scan, '-Quiet')
            Check 'scan exit 0' ($r.Code -eq 0) "exit $($r.Code)"
            $plan = Get-Plan $scan
            Check 'the PuTTY profile was applied' ((@($plan.identity.profiles) -join ',') -like 'PuTTY (PuTTY.psd1)*')
            $sid = ([Security.Principal.WindowsIdentity]::GetCurrent()).User.Value
            $key = @($plan.items | Where-Object { $_.target -eq "HKU\$sid\Software\SimonTatham\PuTTY" })
            $file = @($plan.items | Where-Object { $_.target -eq $rnd })
            Check 'profile item: the saved-sessions key, as user data' ($key.Count -eq 1 -and $key[0].group -eq 'UserData' -and $key[0].evidence -like 'profile PuTTY:*')
            Check 'profile item: the random seed file, as user data' ($file.Count -eq 1 -and $file[0].group -eq 'UserData')
            Check 'user data is NOT in a default level 3 run' (@(Get-SelectedItems $plan 3 | Where-Object { $_.group -eq 'UserData' }).Count -eq 0)
            $sel = @($plan.items | Where-Object { $_.group -eq 'UserData' -and $null -ne $_.op })
            $s0 = Get-PlanState $sel
            $r = Invoke-Engine @('-ProductCode', $pc, '-Level', '3', '-Include', 'UserData', '-SkipUninstall', '-Force', '-Quiet')
            Check '-Include UserData run exit 0' ($r.Code -eq 0) "exit $($r.Code)"
            $run = Get-NewestRun $started
            Check 'only the user data went' (-not (Test-Path $sessKey) -and -not (Test-Path $rnd) -and ((Get-MsiProductState $pc) -eq 5))
            $r = Invoke-Engine @('-Restore', $run.runId, '-Force', '-Quiet')
            Check 'restore exit 0' ($r.Code -eq 0) "exit $($r.Code)"
            Compare-State $s0 (Get-PlanState $sel) 'restore: sessions key and seed file back exactly'
        } finally {
            Remove-Item -LiteralPath 'HKCU:\Software\SimonTatham' -Recurse -Force -ErrorAction SilentlyContinue
            Remove-Item -LiteralPath $rnd -Force -ErrorAction SilentlyContinue
        }
    }

    'hooks' {
        # One synthetic app hooked into Windows every way that needs no reboot to prove: each hook must
        # be found by its path, removed by L3, and put back EXACTLY by the restore.
        $name = 'KillItWithFire Hooks Test'
        $folder = 'C:\Program Files\KillItWithFireHooksTest'
        $exe = "$folder\hook.exe"
        $wl = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon'
        $userinitBefore = (Get-ItemProperty -LiteralPath $wl).Userinit
        $appinitBefore = (Get-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows').AppInit_DLLs
        New-TestApp 'KillItWithFireHooksTest' $name $folder @('hook.exe', 'hook.dll', 'readme.txt')
        try {
            # IFEO debugger on a made-up exe name (never a real one).
            New-Item -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\killitwithfirelabtarget.exe' -Force | Out-Null
            Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\killitwithfirelabtarget.exe' -Name Debugger -Value "`"$exe`""
            # AppInit list entry (LoadAppInit_DLLs stays as it is: the list is only data here). The list is
            # space-separated, so real apps write the 8.3 path; that also proves short-path matching.
            $short = (New-Object -ComObject Scripting.FileSystemObject).GetFile("$folder\hook.dll").ShortPath
            $testAppInit = ($short -notmatch '\s')
            if ($testAppInit) {
                $ai = if ($appinitBefore) { "$appinitBefore $short" } else { $short }
                Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows' -Name AppInit_DLLs -Value $ai
            } else { Write-Host 'skip: 8.3 names are off on this volume, so no AppInit entry is possible' }
            # Userinit: OUR entry appended; Windows' own entry must survive.
            Set-ItemProperty -Path $wl -Name Userinit -Value ($userinitBefore.TrimEnd(',') + ",$exe,")
            # Active Setup, a folder context-menu verb, a file association, a Public Desktop shortcut.
            New-Item -Path 'HKLM:\SOFTWARE\Microsoft\Active Setup\Installed Components\{7E1F2A3B-LEFT-OVER-LAB0-000000000001}' -Force | Out-Null
            Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Active Setup\Installed Components\{7E1F2A3B-LEFT-OVER-LAB0-000000000001}' -Name StubPath -Value "`"$exe`" /peruser"
            New-Item -Path 'HKLM:\SOFTWARE\Classes\Directory\shell\KillItWithFireLabVerb\command' -Force | Out-Null
            Set-ItemProperty -Path 'HKLM:\SOFTWARE\Classes\Directory\shell\KillItWithFireLabVerb\command' -Name '(default)' -Value "`"$exe`" `"%1`""
            New-Item -Path 'HKLM:\SOFTWARE\Classes\.killitwithfirelab' -Force | Out-Null
            Set-ItemProperty -Path 'HKLM:\SOFTWARE\Classes\.killitwithfirelab' -Name '(default)' -Value 'KillItWithFireLab.File'
            New-Item -Path 'HKLM:\SOFTWARE\Classes\KillItWithFireLab.File\shell\open\command' -Force | Out-Null
            Set-ItemProperty -Path 'HKLM:\SOFTWARE\Classes\KillItWithFireLab.File\shell\open\command' -Name '(default)' -Value "`"$exe`" `"%1`""
            $sh = New-Object -ComObject WScript.Shell
            $lnk = $sh.CreateShortcut((Join-Path $env:PUBLIC 'Desktop\KillItWithFire Hooks Test.lnk')); $lnk.TargetPath = $exe; $lnk.Save()
            # A scheduled task, a Run value (+ its StartupApproved twin), a firewall rule, a service.
            Register-ScheduledTask -TaskName 'KillItWithFireLabHooksTask' -Action (New-ScheduledTaskAction -Execute $exe -Argument '/tick') -Trigger (New-ScheduledTaskTrigger -Daily -At 3am) -User 'SYSTEM' -Force | Out-Null
            Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run' -Name 'KillItWithFireLabHooks' -Value "`"$exe`" /tray"
            New-Item -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run' -Force -ErrorAction SilentlyContinue | Out-Null
            New-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run' -Name 'KillItWithFireLabHooks' -Value ([byte[]](2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0)) -PropertyType Binary -Force | Out-Null
            New-NetFirewallRule -Name 'KillItWithFireLabHooksRule' -DisplayName 'KillItWithFire Hooks Test' -Direction Inbound -Action Allow -Program $exe -Profile Any | Out-Null
            New-Service -Name 'KillItWithFireLabHooksSvc' -BinaryPathName "`"$exe`" -service" -StartupType Manual -DisplayName 'KillItWithFire Hooks Test' | Out-Null
            # Two top-level keys named for the keyword: one whose contents point at the app, one that
            # only shares the name (it must be review-only, never removed by default).
            New-Item -Path 'HKLM:\SOFTWARE\KillItWithFire Lab\App' -Force | Out-Null
            Set-ItemProperty -Path 'HKLM:\SOFTWARE\KillItWithFire Lab\App' -Name InstallPath -Value $folder
            New-Item -Path 'HKLM:\SOFTWARE\KillItWithFire Unrelated' -Force | Out-Null
            Set-ItemProperty -Path 'HKLM:\SOFTWARE\KillItWithFire Unrelated' -Name Setting -Value 'blue'
            # Another product's sloppy uninstall entry that names Program Files itself as its folder. It made
            # every app's folder "inside another product's" and the plan kept nearly everything (GitHub runner,
            # 2026-10-13). Program Files is nobody's folder.
            $sloppy = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\KillItWithFireLabSloppyEntry'
            New-Item -Path $sloppy -Force | Out-Null
            Set-ItemProperty -Path $sloppy -Name DisplayName -Value 'Sloppy Entry Lab Product'
            Set-ItemProperty -Path $sloppy -Name InstallLocation -Value "$env:ProgramFiles\"
            Set-ItemProperty -Path $sloppy -Name UninstallString -Value "`"$env:ProgramFiles\sloppy-uninstall.exe`""

            $scan = Join-Path $StateDir 'hooks-scan'
            $r = Invoke-Engine @('-Name', $name, '-Level', '0', '-OutDir', $scan, '-Quiet')
            Check 'scan exit 0' ($r.Code -eq 0) "exit $($r.Code)"
            $plan = Get-Plan $scan
            $cats = @($plan.items | ForEach-Object { $_.category } | Select-Object -Unique)
            foreach ($c in @('IfeoDebugger', 'Winlogon', 'ActiveSetup', 'ShellVerb', 'FileAssociation', 'Shortcut', 'ScheduledTask', 'RunValue', 'FirewallRule', 'Service', 'InstallRoot', 'UninstallEntry')) {
                Check "plan has $c" ($cats -contains $c)
            }
            if ($testAppInit) { Check 'plan has AppInitDll (matched through the 8.3 path)' ($cats -contains 'AppInitDll') }
            Check 'plan: the .killitwithfirelab extension stops naming our file type' (@($plan.items | Where-Object { $_.target -like '*\.killitwithfirelab : (default)' }).Count -eq 1)
            $w = @($plan.items | Where-Object { $_.category -eq 'Winlogon' })
            Check 'Userinit: remove OUR entry only, keep the rest' ($w.Count -eq 1 -and $w[0].action -like '*keep every other entry*')
            if ($plan.keyword.used -and $plan.keyword.value -eq 'KillItWithFire') {
                $vk = @($plan.items | Where-Object { $_.target -like '*\SOFTWARE\KillItWithFire Lab' })
                $uk = @($plan.items | Where-Object { $_.target -like '*\SOFTWARE\KillItWithFire Unrelated' })
                Check 'keyword key whose contents point at the app: planned normally' ($vk.Count -eq 1 -and -not $vk[0].review) $(if ($vk.Count) { $vk[0].evidence })
                Check 'keyword key that only shares the name: review-only' ($uk.Count -eq 1 -and $uk[0].review)
            } else { Write-Host "skip: keyword is '$($plan.keyword.value)' ($($plan.keyword.reason))" }
            $sel = Get-SelectedItems $plan 3
            $s0 = Get-PlanState $sel
            $r = Invoke-Engine @('-Name', $name, '-Level', '3', '-Force', '-Quiet')
            Check 'L3 exit 0' ($r.Code -eq 0) "exit $($r.Code)"
            $run = Get-NewestRun $started
            $s1 = Get-PlanState $sel
            $left = @($sel | Where-Object { $_.category -notin @('Winlogon', 'AppInitDll') } | ForEach-Object { $i = $_; @(0..(@($i.op).Count - 1) | ForEach-Object { "$($i.id).$_" }) } | Where-Object { $s1[$_] -ne 'absent' -and $s1[$_] -notlike 'n/a:*' })
            Check 'L3: every hook and file is gone' ($left.Count -eq 0) ($left -join ', ')
            Check 'L3: Userinit is exactly what it was before the app' ((Get-ItemProperty -LiteralPath $wl).Userinit -eq $userinitBefore) (Get-ItemProperty -LiteralPath $wl).Userinit
            Check 'L3: AppInit_DLLs is exactly what it was before the app' ([string](Get-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows').AppInit_DLLs -eq [string]$appinitBefore)
            Check 'L3: the StartupApproved twin went with the Run value' ((Get-ValueFingerprint 'HKLM64' 'SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run' 'KillItWithFireLabHooks') -eq 'absent')
            $r = Invoke-Engine @('-Restore', $run.runId, '-Force', '-Quiet')
            Check 'restore exit 0' ($r.Code -eq 0) "exit $($r.Code)"
            Compare-State $s0 (Get-PlanState $sel) 'restore: every hook back exactly (task XML, firewall rule, service, lists, keys, files)'
            Check 'the unrelated key that only shares the name was never touched' ((Get-ValueFingerprint 'HKLM64' 'SOFTWARE\KillItWithFire Unrelated' 'Setting') -eq 'String:blue')

            # The app as the ONLY Userinit entry (kiosk and lockdown software do this): removing it must
            # put Windows' default back, never leave Userinit empty (no shell at sign-in).
            Set-ItemProperty -Path $wl -Name Userinit -Value "$exe,"
            $scan2 = Join-Path $StateDir 'hooks-scan2'
            [void](Invoke-Engine @('-Name', $name, '-Level', '0', '-OutDir', $scan2, '-Quiet'))
            $w2 = @((Get-Plan $scan2).items | Where-Object { $_.category -eq 'Winlogon' })
            Check 'sole Userinit entry: the plan sets Windows'' default back' ($w2.Count -eq 1 -and $w2[0].action -like "*default*userinit.exe*") $(if ($w2.Count) { $w2[0].action })
            $r = Invoke-Engine @('-Name', $name, '-Level', '3', '-Include', 'LogonHooks', '-SkipUninstall', '-Force', '-Quiet')
            $ui = (Get-ItemProperty -LiteralPath $wl).Userinit
            Check 'sole Userinit entry: after L3 Userinit is Windows'' default' ($r.Code -eq 0 -and $ui -match '(?i)\\system32\\userinit\.exe,$') $ui
            $run2 = Get-NewestRun $started
            $r = Invoke-Engine @('-Restore', $run2.runId, '-Force', '-Quiet')
            Check 'sole Userinit entry: restore puts the app''s entry back' ($r.Code -eq 0 -and (Get-ItemProperty -LiteralPath $wl).Userinit -eq "$exe,")

            # The app replaced userinit.exe AND another product hooked in after it: Windows' entry goes
            # back in front, the other product's entry stays (review 2026-09-26).
            $other = 'C:\Program Files\OtherVendor\agent.exe'
            Set-ItemProperty -Path $wl -Name Userinit -Value "$exe,$other,"
            $r = Invoke-Engine @('-Name', $name, '-Level', '3', '-Include', 'LogonHooks', '-SkipUninstall', '-Force', '-Quiet')
            $ui = (Get-ItemProperty -LiteralPath $wl).Userinit
            Check 'Userinit: Windows'' entry back in front, the other product''s entry kept' ($r.Code -eq 0 -and $ui -eq "$env:SystemRoot\system32\userinit.exe,$other,") $ui
            $run3 = Get-NewestRun $started
            $r = Invoke-Engine @('-Restore', $run3.runId, '-Force', '-Quiet')
            Check 'Userinit: restore puts the exact old value back' ($r.Code -eq 0 -and (Get-ItemProperty -LiteralPath $wl).Userinit -eq "$exe,$other,")
        } finally {
            # Leave the machine as it was, whatever happened above.
            Set-ItemProperty -Path $wl -Name Userinit -Value $userinitBefore
            Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows' -Name AppInit_DLLs -Value ([string]$appinitBefore)
            Remove-Item -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\killitwithfirelabtarget.exe' -Recurse -Force -ErrorAction SilentlyContinue
            Remove-Item -Path 'HKLM:\SOFTWARE\Microsoft\Active Setup\Installed Components\{7E1F2A3B-LEFT-OVER-LAB0-000000000001}' -Recurse -Force -ErrorAction SilentlyContinue
            Remove-Item -Path 'HKLM:\SOFTWARE\Classes\Directory\shell\KillItWithFireLabVerb', 'HKLM:\SOFTWARE\Classes\.killitwithfirelab', 'HKLM:\SOFTWARE\Classes\KillItWithFireLab.File' -Recurse -Force -ErrorAction SilentlyContinue
            Remove-Item -Path 'HKLM:\SOFTWARE\KillItWithFire Lab', 'HKLM:\SOFTWARE\KillItWithFire Unrelated', 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\KillItWithFireLabSloppyEntry' -Recurse -Force -ErrorAction SilentlyContinue
            Remove-Item -LiteralPath (Join-Path $env:PUBLIC 'Desktop\KillItWithFire Hooks Test.lnk') -Force -ErrorAction SilentlyContinue
            Unregister-ScheduledTask -TaskName 'KillItWithFireLabHooksTask' -Confirm:$false -ErrorAction SilentlyContinue
            Remove-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run' -Name 'KillItWithFireLabHooks' -ErrorAction SilentlyContinue
            Remove-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run' -Name 'KillItWithFireLabHooks' -ErrorAction SilentlyContinue
            Remove-NetFirewallRule -Name 'KillItWithFireLabHooksRule' -ErrorAction SilentlyContinue
            & sc.exe delete KillItWithFireLabHooksSvc 2>&1 | Out-Null
            Remove-TestApp 'KillItWithFireHooksTest' $folder
        }
    }

    'restorestop' {
        # A restore that can't undo one change: changes that can't depend on it still come back, the
        # services, drivers and logon hooks that could (their program is in the blocked folder) are held
        # back, the blocker is never overwritten, and a rerun once the cause is gone finishes the job.
        # (Until 2026-09-29 the first failure stopped everything older, on every rerun.)
        $name = 'KillItWithFire Restore Test'
        $folder = 'C:\Program Files\KillItWithFireRestoreTest'
        $svc = 'LtRestoreSvc'
        New-TestApp 'KillItWithFireRestoreTest' $name $folder @('a.txt', 'b.txt', 'svc.exe')
        & sc.exe create $svc type= own start= demand binPath= "`"$folder\svc.exe`"" DisplayName= 'KillItWithFire Restore Test' | Out-Null
        try {
            $r = Invoke-Engine @('-Name', $name, '-Level', '3', '-Force', '-Quiet')
            Check 'L3 exit 0' ($r.Code -eq 0) "exit $($r.Code)"
            $run = Get-NewestRun $started
            Check 'L3: folder, entry and service gone' (-not (Test-Path $folder) -and -not (Get-Uninstall $name) -and -not (Get-Service $svc -ErrorAction SilentlyContinue))
            # Something new appears where the folder was: the restore must not overwrite it.
            New-Item -ItemType Directory -Force -Path $folder | Out-Null
            Set-Content -LiteralPath (Join-Path $folder 'new.txt') -Value 'someone else' -Encoding ASCII
            $r = Invoke-Engine @('-Restore', $run.runId, '-Force', '-Quiet')
            Check 'restore with a blocker: exit 1 (not finished)' ($r.Code -eq 1) "exit $($r.Code)"
            Check 'the blocker was not overwritten' ((Get-Content -LiteralPath (Join-Path $folder 'new.txt')) -eq 'someone else')
            Check 'an independent change (the uninstall entry) still came back' ([bool](Get-Uninstall $name))
            Check 'the service, whose program is in the blocked folder, was held back' (-not (Get-Service $svc -ErrorAction SilentlyContinue))
            [System.IO.Directory]::Delete($folder, $true)
            $r = Invoke-Engine @('-Restore', $run.runId, '-Force', '-Quiet')
            Check 'rerun after the cause is gone: exit 0' ($r.Code -eq 0) "exit $($r.Code)"
            Check 'rerun: folder, entry and service back' ((Test-Path (Join-Path $folder 'a.txt')) -and [bool](Get-Uninstall $name) -and [bool](Get-Service $svc -ErrorAction SilentlyContinue))
        } finally {
            & sc.exe delete $svc | Out-Null
            Remove-TestApp 'KillItWithFireRestoreTest' $folder
        }
    }

    'policy' {
        $pol = 'HKLM:\SOFTWARE\Policies\KillItWithFire'
        $name = 'KillItWithFire Policy Test'
        $folder = 'C:\Program Files\KillItWithFirePolicyTest'
        New-TestApp 'KillItWithFirePolicyTest' $name $folder @('app.exe.txt')
        try {
            New-Item -Path $pol -Force | Out-Null
            New-ItemProperty -Path $pol -Name MaxLevel -Value 2 -PropertyType DWord -Force | Out-Null
            New-ItemProperty -Path $pol -Name RequireBackup -Value 1 -PropertyType DWord -Force | Out-Null
            New-ItemProperty -Path $pol -Name RequireLog -Value 1 -PropertyType DWord -Force | Out-Null
            New-ItemProperty -Path $pol -Name AllowUserData -Value 0 -PropertyType DWord -Force | Out-Null
            foreach ($t in @(
                    @{ a = @('-Level', '3', '-Force'); why = 'level above MaxLevel' },
                    @{ a = @('-Level', '2', '-NoBackup', '-Force'); why = '-NoBackup when a backup is required' },
                    @{ a = @('-Level', '2', '-NoLog', '-Force'); why = '-NoLog when a log is required' },
                    @{ a = @('-Level', '2', '-IncludeUserData', '-Force'); why = '-IncludeUserData when not allowed' },
                    @{ a = @('-Level', '2', '-Include', 'UserData', '-Force'); why = '-Include UserData when not allowed' })) {
                $r = Invoke-Engine (@('-Name', $name) + $t.a + @('-Quiet'))
                Check "policy refuses $($t.why) (exit 2)" ($r.Code -eq 2 -and $r.Output -match 'Refused by policy') "exit $($r.Code)"
            }
            Check 'nothing was changed by the refused runs' ([bool](Get-Uninstall $name) -and (Test-Path $folder))
            $r = Invoke-Engine @('-Name', $name, '-Level', '0', '-OutDir', (Join-Path $StateDir 'policy-scan'), '-Quiet')
            Check 'a scan is still allowed' ($r.Code -eq 0) "exit $($r.Code)"
            $png = Join-Path $StateDir 'policy-window.png'
            $r = Invoke-Engine @('-GuiSelfTest', $png, '-Plan', (Join-Path $StateDir 'policy-scan\plan.json'))
            $json = $r.Output.Substring([Math]::Max(0, $r.Output.IndexOf('{'))) | ConvertFrom-Json
            Check 'the window reads the REAL policy key: Full scrub and KILL IT WITH FIRE greyed out' ((@($json.actionsEnabled) -join ',') -eq 'True,True,False,False') (@($json.actionsEnabled) -join ',')
            Check 'the window: backup and log locked on' ($json.backupChecked -and -not $json.backupEnabled -and $json.logChecked -and -not $json.logEnabled)
            Check 'the window: user data locked off' (-not $json.userDataEnabled)
            $r = Invoke-Engine @('-Name', $name, '-Level', '2', '-Force', '-Quiet')
            Check 'a run inside the policy works' ($r.Code -eq 0) "exit $($r.Code)"
            $run = Get-NewestRun $started
            Check '... and it kept a backup and a log (the policy)' ($run.backup -and (Test-Path -LiteralPath $run.log)) $run.log
            $r = Invoke-Engine @('-Restore', $run.runId, '-Force', '-Quiet')
            Check 'restore exit 0' ($r.Code -eq 0) "exit $($r.Code)"
            Check 'restore: the uninstall entry is back' ([bool](Get-Uninstall $name))
        } finally {
            Remove-Item -LiteralPath $pol -Recurse -Force -ErrorAction SilentlyContinue
            Remove-TestApp 'KillItWithFirePolicyTest' $folder
        }
    }

    'refusal' {
        $agent = Get-Uninstall 'RFF Agent'
        if ($agent) {
            $r = Invoke-Engine @('-Name', 'RFF Agent', '-Level', '3', '-Force', '-Quiet')
            Check 'the RFF agent is refused (exit 2)' ($r.Code -eq 2 -and $r.Output -match 'REFUSED') "exit $($r.Code)"
            Check 'the agent service is untouched' ([bool](Get-Service RFFAgent -ErrorAction SilentlyContinue))
        } else { Write-Host 'skip: no RFF agent on this machine' }
        # A Microsoft MSI by ProductCode (the runtimes hide as SystemComponent entries).
        $ms = $null
        foreach ($root in @('HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall', 'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall')) {
            foreach ($k in @(Get-ChildItem -LiteralPath $root -ErrorAction SilentlyContinue)) {
                $p = Get-ItemProperty -LiteralPath $k.PSPath -ErrorAction SilentlyContinue
                if ($p -and ($p.PSObject.Properties.Name -contains 'Publisher') -and $p.Publisher -like 'Microsoft*' -and
                    ($p.PSObject.Properties.Name -contains 'WindowsInstaller') -and $p.WindowsInstaller -eq 1 -and $k.PSChildName -match '^\{[0-9A-Fa-f-]{36}\}$') { $ms = $k.PSChildName; break }
            }
            if ($ms) { break }
        }
        if ($ms) {
            $r = Invoke-Engine @('-ProductCode', $ms, '-Level', '3', '-Force', '-Quiet')
            Check "a Microsoft MSI by ProductCode is refused ($ms)" ($r.Code -eq 2 -and $r.Output -match 'REFUSED') "exit $($r.Code)"
        } else { Write-Host 'skip: no Microsoft MSI product found' }
        New-TestApp 'KillItWithFireSecurityTest' 'CrowdStrike Windows Sensor' 'C:\Program Files\KillItWithFireSecurityTest' @('csagent.txt') -Publisher 'CrowdStrike, Inc.'
        try {
            $r = Invoke-Engine @('-Name', 'CrowdStrike Windows Sensor', '-Level', '3', '-Force', '-Quiet')
            Check 'a security product is refused, and names the vendor tool' ($r.Code -eq 2 -and $r.Output -match 'CsUninstallTool') "exit $($r.Code)"
        } finally { Remove-TestApp 'KillItWithFireSecurityTest' 'C:\Program Files\KillItWithFireSecurityTest' }
        New-TestApp 'KillItWithFireKeywordTest' 'KillItWithFire Keyword Test' 'C:\Program Files\KillItWithFireKeywordTest' @('a.txt')
        try {
            $r = Invoke-Engine @('-Name', 'KillItWithFire Keyword Test', '-Keyword', 'Microsoft', '-Level', '0', '-OutDir', (Join-Path $StateDir 'kw-scan'), '-Quiet')
            $plan = Get-Plan (Join-Path $StateDir 'kw-scan')
            Check '-Keyword Microsoft is refused (the scan still runs)' ($r.Code -eq 0 -and -not $plan.keyword.used -and $plan.keyword.reason -like 'REFUSED*') $plan.keyword.reason
            $r = Invoke-Engine @('-Name', 'KillItWithFire Keyword Test', '-Keyword', 'Intune', '-Level', '0', '-OutDir', (Join-Path $StateDir 'kw-scan2'), '-Quiet')
            $plan = Get-Plan (Join-Path $StateDir 'kw-scan2')
            Check '-Keyword Intune is refused' (-not $plan.keyword.used) $plan.keyword.reason
        } finally { Remove-TestApp 'KillItWithFireKeywordTest' 'C:\Program Files\KillItWithFireKeywordTest' }
        $r = Invoke-Engine @('-Name', 'No Such App 12345', '-Level', '0', '-Quiet')
        Check 'an unknown name is exit 3' ($r.Code -eq 3) "exit $($r.Code)"
    }

    'bitness' {
        $name = 'KillItWithFire Bitness Test'
        $folder = 'C:\Program Files\KillItWithFireBitnessTest'
        New-TestApp 'KillItWithFireBitnessTest' $name $folder @('a.txt', 'b.txt')
        try {
            $r64 = Invoke-Engine @('-Name', $name, '-Level', '0', '-OutDir', (Join-Path $StateDir 'bit64'), '-Quiet')
            $wow = Join-Path $env:SystemRoot 'SysWOW64\WindowsPowerShell\v1.0\powershell.exe'
            $r32 = Invoke-Engine @('-Name', $name, '-Level', '0', '-OutDir', (Join-Path $StateDir 'bit32'), '-Quiet') -Exe $wow
            Check '64-bit host: exit 0' ($r64.Code -eq 0) "exit $($r64.Code)"
            Check '32-bit host: exit 0 after relaunching 64-bit' ($r32.Code -eq 0) "exit $($r32.Code)"
            $p64 = Get-Plan (Join-Path $StateDir 'bit64'); $p32 = Get-Plan (Join-Path $StateDir 'bit32')
            $t64 = (@($p64.items | ForEach-Object { "$($_.category)|$($_.target)" }) | Sort-Object) -join "`n"
            $t32 = (@($p32.items | ForEach-Object { "$($_.category)|$($_.target)" }) | Sort-Object) -join "`n"
            Check '32-bit host finds exactly the 64-bit plan' ($t64 -eq $t32 -and $t64) "$(@($p64.items).Count) vs $(@($p32.items).Count) items"
            Check 'the install folder is C:\Program Files, not (x86)' (@($p32.items | Where-Object { $_.category -eq 'InstallRoot' -and $_.target -eq $folder }).Count -eq 1)
        } finally { Remove-TestApp 'KillItWithFireBitnessTest' $folder }
    }

    { $_ -in @('pending', 'resume') } {
        # A file held open with no sharing can't move now: it is scheduled for the next boot (exit 3010).
        $name = 'KillItWithFire Locked Test'
        $folder = 'C:\Program Files\KillItWithFireLockedTest'
        $locked = Join-Path $folder 'locked.bin'
        if ($Phase -eq 'run') {
            New-TestApp 'KillItWithFireLockedTest' $name $folder @('a.txt', 'locked.bin')
            $holder = Start-Process -FilePath $HostExe -ArgumentList '-NoProfile', '-Command', "`$f = [System.IO.File]::Open('$locked', 'Open', 'Read', 'None'); Start-Sleep -Seconds 1800" -PassThru -WindowStyle Hidden
            Start-Sleep -Seconds 3
            $r = Invoke-Engine @('-Name', $name, '-Level', '3', '-Force', '-Quiet')
            Check 'a locked file makes the run exit 3010' ($r.Code -eq 3010) "exit $($r.Code)"
            $run = Get-NewestRun $started
            Check 'the run is marked pending-reboot' ($run.status -eq 'pending-reboot') $run.status
            Check 'the other file moved now' (-not (Test-Path (Join-Path $folder 'a.txt')))
            Check 'the locked file is still in place' (Test-Path $locked)
            $pfro = Get-PendingRenames
            Check 'the locked file is scheduled to move at boot' (@($pfro | Where-Object { $_ -like "*$locked" }).Count -eq 1)
            Save-State 'resume' @{ runId = $run.runId; holder = $holder.Id }
            if ($Scenario -eq 'pending') {
                Stop-Process -Id $holder.Id -Force -ErrorAction SilentlyContinue
                $r = Invoke-Engine @('-Restore', $run.runId, '-Force', '-Quiet')
                Check 'restore before the reboot: exit 0' ($r.Code -eq 0) "exit $($r.Code)"
                $pfro = Get-PendingRenames
                Check 'restore took the boot-time move back out' (@($pfro | Where-Object { $_ -like "*$locked" }).Count -eq 0)
                Check 'restore: both files and the entry are back' ((Test-Path $locked) -and (Test-Path (Join-Path $folder 'a.txt')) -and [bool](Get-Uninstall $name))
                $r = Invoke-Engine @('-Resume', $run.runId, '-Quiet')
                Check 'a restored run refuses -Resume (no reboot loop)' ($r.Code -eq 2) "exit $($r.Code)"
                Remove-TestApp 'KillItWithFireLockedTest' $folder
            }
        } elseif ($Phase -eq 'after') {
            $st = Read-State 'resume'
            Check 'after the reboot: the locked file moved' (-not (Test-Path $locked))
            Check 'after the reboot: it is in the quarantine' (Test-Path (Join-Path $script:RunsRoot "$($st.runId)\files\C\Program Files\KillItWithFireLockedTest\locked.bin"))
            $r = Invoke-Engine @('-Resume', $st.runId, '-Quiet')
            Check '-Resume exit 0' ($r.Code -eq 0) "exit $($r.Code)"
            $meta = Get-Content -LiteralPath (Join-Path $script:RunsRoot "$($st.runId)\run.json") -Raw | ConvertFrom-Json
            Check 'the run is now done' ($meta.status -eq 'done') $meta.status
            Check '-Resume removed the folder the reboot emptied' (-not (Test-Path $folder))
            $r = Invoke-Engine @('-Restore', $st.runId, '-Force', '-Quiet')
            Check 'restore after the reboot: exit 0' ($r.Code -eq 0) "exit $($r.Code)"
            Check 'restore: both files and the entry are back' ((Test-Path $locked) -and (Test-Path (Join-Path $folder 'a.txt')) -and [bool](Get-Uninstall $name))
            Remove-TestApp 'KillItWithFireLockedTest' $folder
        }
    }

    'filter' {
        # A fake "driver" registered as an UPPER FILTER of the keyboard class. The file is not a real
        # driver, so while it is listed the keyboard fails to start at boot: exactly what happens when a
        # tool deletes a filter driver but leaves it listed. Kill It With Fire must remove the class entry first.
        $name = 'KillItWithFire Filter Test'
        $folder = 'C:\Program Files\KillItWithFireFilterTest'
        $svc = 'LtFilter'
        $classKey = 'HKLM:\SYSTEM\CurrentControlSet\Control\Class\{4D36E96B-E325-11CE-BFC1-08002BE10318}'
        $kbd = { @(Get-PnpDevice -PresentOnly -Class Keyboard -ErrorAction SilentlyContinue | Where-Object { $_.InstanceId -like 'VMBUS*' -or $_.InstanceId -like 'ACPI*' -or $_.InstanceId -like 'HID*' }) }
        $uppers = { @((Get-ItemProperty -LiteralPath $classKey -Name UpperFilters).UpperFilters) -join ',' }
        switch ($Phase) {
            'setup' {
                Check 'precondition: the keyboard works' (@(& $kbd | Where-Object { $_.Status -eq 'OK' }).Count -ge 1)
                New-TestApp 'KillItWithFireFilterTest' $name $folder @('readme.txt')
                Set-Content -LiteralPath "$folder\ltfilter.sys" -Value 'not a driver' -Encoding ASCII
                & sc.exe create $svc type= kernel start= demand binPath= "$folder\ltfilter.sys" DisplayName= 'KillItWithFire Filter Test' | Out-Null
                $u = @((Get-ItemProperty -LiteralPath $classKey -Name UpperFilters).UpperFilters) + $svc
                Set-ItemProperty -LiteralPath $classKey -Name UpperFilters -Value ([string[]]$u) -Type MultiString
                Check 'setup: keyboard class loads kbdclass,LtFilter' ((& $uppers) -eq 'kbdclass,LtFilter') (& $uppers)
            }
            'broken' {
                $k = & $kbd
                Check 'PROBE: with the filter listed, the keyboard fails to start after a reboot' (@($k | Where-Object { $_.Status -ne 'OK' }).Count -ge 1) (@($k | ForEach-Object { "$($_.FriendlyName)=$($_.Status)" }) -join ', ')
                $scan = Join-Path $StateDir 'filter-scan'
                $r = Invoke-Engine @('-Name', $name, '-Level', '0', '-OutDir', $scan, '-Quiet')
                $plan = Get-Plan $scan
                $f = @($plan.items | Where-Object { $_.category -eq 'DeviceClassFilter' })
                $d = @($plan.items | Where-Object { $_.category -eq 'Driver' })
                Check 'plan: the class filter entry, critical' ($f.Count -eq 1 -and $f[0].risk -eq 'critical' -and -not $f[0].review) $(if ($f.Count) { $f[0].target })
                Check 'plan: the driver (tied by its path, not a guess)' ($d.Count -eq 1 -and -not $d[0].review)
                Check 'plan: the filter entry goes BEFORE the driver' ($f.Count -and $d.Count -and $f[0].order -lt $d[0].order)
                $sel = Get-SelectedItems $plan 3
                Save-State 'filter-s0' (Get-PlanState $sel)
                Copy-Item -LiteralPath (Join-Path $scan 'plan.json') -Destination (Join-Path $StateDir 'filter-plan.json') -Force
                $r = Invoke-Engine @('-Name', $name, '-Level', '3', '-Force', '-Quiet')
                Check 'L3 exit 0' ($r.Code -eq 0) "exit $($r.Code)"
                $run = Get-NewestRun $started
                Save-State 'filter-run' @{ runId = $run.runId }
                Check 'L3: the class lists kbdclass only' ((& $uppers) -eq 'kbdclass') (& $uppers)
                Check 'L3: the driver service is gone' (-not (Get-Service $svc -ErrorAction SilentlyContinue))
            }
            'cleaned' {
                $k = & $kbd
                Check 'after the reboot: the keyboard works again' (@($k | Where-Object { $_.Status -eq 'OK' }).Count -ge 1 -and @($k | Where-Object { $_.Status -ne 'OK' }).Count -eq 0) (@($k | ForEach-Object { "$($_.FriendlyName)=$($_.Status)" }) -join ', ')
                $bad = @(Get-PnpDevice -PresentOnly -ErrorAction SilentlyContinue | Where-Object { $_.Status -eq 'Error' })
                Check 'no device in an error state' ($bad.Count -eq 0) (@($bad | ForEach-Object { $_.FriendlyName }) -join ', ')
                $run = Read-State 'filter-run'
                $r = Invoke-Engine @('-Restore', $run.runId, '-Force', '-Quiet')
                Check 'restore exit 3010 (a filter only joins the device stack at boot)' ($r.Code -eq 3010) "exit $($r.Code)"
                $plan = Get-Content -LiteralPath (Join-Path $StateDir 'filter-plan.json') -Raw | ConvertFrom-Json
                Compare-State (ConvertTo-Ordered (Read-State 'filter-s0')) (Get-PlanState (Get-SelectedItems $plan 3)) 'restore: filter entry, driver service, files and entry back exactly'
            }
            'restored' {
                $k = & $kbd
                Check 'restore was faithful: the keyboard fails again after the reboot' (@($k | Where-Object { $_.Status -ne 'OK' }).Count -ge 1) (@($k | ForEach-Object { "$($_.FriendlyName)=$($_.Status)" }) -join ', ')
                $r = Invoke-Engine @('-Name', $name, '-Level', '3', '-Force', '-Quiet')
                Check 'L3 again exit 0' ($r.Code -eq 0) "exit $($r.Code)"
            }
            'final' {
                $k = & $kbd
                Check 'final: the keyboard works' (@($k | Where-Object { $_.Status -eq 'OK' }).Count -ge 1 -and @($k | Where-Object { $_.Status -ne 'OK' }).Count -eq 0)
                Check 'final: the class lists kbdclass only' ((& $uppers) -eq 'kbdclass') (& $uppers)
                Check 'final: nothing of the test app is left' (-not (Test-Path $folder) -and -not (Get-Uninstall $name) -and -not (Get-Service $svc -ErrorAction SilentlyContinue))
            }
        }
    }

    'npcap' {
        # A REAL network component: Npcap 1.86 (NDIS lightweight filter INSECURE_NPCAP, driver package
        # oemNN.inf, kernel driver npcap.sys), installed through its wizard by the host, uninstaller
        # deleted. Removing it in the wrong order, or the wrong way (deleting the service under a bound
        # filter), leaves a machine with no network. The host reboots between phases.
        $name = 'Npcap'
        $root = 'C:\Program Files\Npcap'
        $cid = 'INSECURE_NPCAP'
        $inf = { @(Get-ChildItem (Join-Path $env:SystemRoot 'INF\oem*.inf') | Where-Object { Select-String -LiteralPath $_.FullName -Pattern $cid -SimpleMatch -Quiet } | ForEach-Object Name) }
        $svcState = { $q = (& sc.exe query npcap) -join ' '; if ($LASTEXITCODE -eq 1060) { 'absent' } elseif ($q -match 'RUNNING') { 'running' } else { 'stopped' } }
        $resumeIfNeeded = {
            $run = Read-State 'npcap-run'
            if ([int]$run.code -eq 3010) {
                $r = Invoke-Engine @('-Resume', $run.runId)
                Check 'after the reboot, -Resume confirms every pending change happened: exit 0' ($r.Code -eq 0) "exit $($r.Code)"
            }
        }
        switch ($Phase) {
            'setup' {
                Check 'precondition: Npcap is installed (component, driver package, running driver)' ((Test-NetComponent $cid) -and @(& $inf).Count -ge 1 -and (& $svcState) -eq 'running') "inf $((& $inf) -join ','), driver $(& $svcState)"
                Check 'precondition: Npcap is bound to the adapters' (@(Get-NetAdapterBinding -ComponentID $cid -ErrorAction SilentlyContinue | Where-Object Enabled).Count -ge 1)
                $up = @(Get-NetAdapter | Where-Object { $_.Status -eq 'Up' }).Count
                $n = Test-Network $up
                Check 'precondition: the network works' $n.Ok $n.Detail
                Save-State 'npcap-net' @{ up = $up }
                if (Test-Path "$root\uninstall.exe") { Remove-Item "$root\uninstall.exe" -Force }
                Check 'broken: the uninstaller is gone, the entry still points at it' ((Get-Uninstall $name) -and -not (Test-Path "$root\uninstall.exe"))
            }
            'broken' {
                $scan = Join-Path $StateDir 'npcap-scan'
                $r = Invoke-Engine @('-Name', $name, '-Level', '0', '-OutDir', $scan, '-Quiet')
                Check 'scan exit 0' ($r.Code -eq 0) "exit $($r.Code)"
                $plan = Get-Plan $scan
                $nc = @($plan.items | Where-Object { $_.category -eq 'NetworkComponent' })
                $pk = @($plan.items | Where-Object { $_.category -eq 'DriverPackage' -and $_.op })
                $dv = @($plan.items | Where-Object { $_.category -eq 'Driver' })
                $infNow = @(& $inf)
                Check 'plan: the network component, removed with netcfg -u' ($nc.Count -eq 1 -and $nc[0].op.kind -eq 'NetcfgUninstall' -and $nc[0].op.componentId -eq $cid)
                Check 'plan: the component keeps the INF Windows recorded for it' ($nc.Count -eq 1 -and $infNow -contains $nc[0].op.inf) "$($nc[0].op.inf) of $($infNow -join ',')"
                Check 'plan: the driver package' ($pk.Count -ge 1 -and $infNow -contains $pk[0].op.inf)
                Check 'plan: the kernel driver' ($dv.Count -eq 1 -and $dv[0].op.name -eq 'npcap')
                Check 'plan: component BEFORE package BEFORE driver' ($nc.Count -and $pk.Count -and $dv.Count -and $nc[0].order -lt $pk[0].order -and $pk[0].order -lt $dv[0].order)
                Check 'plan: nothing Microsoft in the network stack is touched' (@($plan.items | Where-Object { $_.op -and ($_.target -match '(?i)\bms_|ndiscap|tcpip|wfplwf') }).Count -eq 0)
                $sel = Get-SelectedItems $plan 3 -Review
                Save-State 'npcap-s0' (Get-PlanState $sel)
                Copy-Item -LiteralPath (Join-Path $scan 'plan.json') -Destination (Join-Path $StateDir 'npcap-plan.json') -Force
                $r = Invoke-Engine @('-Name', $name, '-Level', '3', '-IncludeReview', '-Force', '-Quiet')
                Check 'L3 (with the reviewed driver items) exit 0 or 3010' ($r.Code -in @(0, 3010)) "exit $($r.Code)"
                $run = Get-NewestRun $started
                Save-State 'npcap-run' @{ runId = $run.runId; code = $r.Code }
                $j = @(Get-Journal $run.runId | Where-Object { $_.kind -in @('NetcfgUninstall', 'DriverPackageDelete', 'ServiceDelete') -and $_.category -in @('NetworkComponent', 'DriverPackage', 'Driver') })
                Check 'journal: netcfg -u ran first, then the package, then the driver' ((($j | ForEach-Object { $_.kind }) -join ',') -eq 'NetcfgUninstall,DriverPackageDelete,ServiceDelete') (($j | ForEach-Object { "$($_.kind)=$($_.result)" }) -join ', ')
                Check 'L3: npcap.sys is out of System32\drivers (netcfg -u leaves it; the run quarantines it)' (-not (Test-Path (Join-Path $env:SystemRoot 'System32\drivers\npcap.sys')))
                Check 'L3: netcfg no longer lists the component' (-not (Test-NetComponent $cid))
                Check 'L3: the driver package is gone' (@(& $inf).Count -eq 0) ((& $inf) -join ',')
                $n = Test-Network ([int](Read-State 'npcap-net').up)
                Check 'L3: the network still works, before any reboot' $n.Ok $n.Detail
            }
            'cleaned' {
                & $resumeIfNeeded
                $n = Test-Network ([int](Read-State 'npcap-net').up)
                Check 'after the reboot: the network works' $n.Ok $n.Detail
                $bad = @(Get-DeviceErrors)
                Check 'after the reboot: no device in an error state' ($bad.Count -eq 0) ($bad -join ', ')
                Check 'after the reboot: component, package and driver are all gone' (-not (Test-NetComponent $cid) -and @(& $inf).Count -eq 0 -and (& $svcState) -eq 'absent' -and -not (Test-Path (Join-Path $env:SystemRoot 'System32\drivers\npcap.sys'))) "driver $(& $svcState)"
                Check 'after the reboot: folder and entry gone' (-not (Test-Path $root) -and -not (Get-Uninstall $name))
                $run = Read-State 'npcap-run'
                $r = Invoke-Engine @('-Restore', $run.runId, '-Force', '-Quiet')
                Check 'restore exit 0 or 3010' ($r.Code -in @(0, 3010)) "exit $($r.Code)"
                $plan = Get-Content -LiteralPath (Join-Path $StateDir 'npcap-plan.json') -Raw | ConvertFrom-Json
                # The driver SERVICE is the one item not compared byte for byte: netcfg -u deletes it itself,
                # so the run never exported it, and on restore netcfg -l re-creates it from the INF (same
                # service, install-time values rewritten). It is checked by what matters instead: present,
                # the same npcap.sys (hash), and loaded and bound after the next boot (phase 'restored').
                $drvIds = @($plan.items | Where-Object { $_.category -eq 'Driver' } | ForEach-Object { "$($_.id).0" })
                $before = ConvertTo-Ordered (Read-State 'npcap-s0'); $after = Get-PlanState (Get-SelectedItems $plan 3 -Review)
                foreach ($d in $drvIds) {
                    $fileSame = ([string]$before[$d]).Split('|')[-1] -eq ([string]$after[$d]).Split('|')[-1]
                    Check 'restore: the driver service is back, with the identical npcap.sys' ((& $svcState) -ne 'absent' -and $fileSame) "$($before[$d]) -> $($after[$d])"
                    $before.Remove($d); $after.Remove($d)
                }
                Compare-State $before $after 'restore: component, package, task, files and entry all back exactly'
                $n = Test-Network ([int](Read-State 'npcap-net').up)
                Check 'restore: the network still works' $n.Ok $n.Detail
            }
            'restored' {
                $n = Test-Network ([int](Read-State 'npcap-net').up)
                Check 'after the reboot: the network works with Npcap back' $n.Ok $n.Detail
                $bad = @(Get-DeviceErrors)
                Check 'after the reboot: no device in an error state' ($bad.Count -eq 0) ($bad -join ', ')
                Check 'restore was faithful: Npcap is loaded and bound again' ((Test-NetComponent $cid) -and (& $svcState) -eq 'running' -and @(Get-NetAdapterBinding -ComponentID $cid -ErrorAction SilentlyContinue | Where-Object Enabled).Count -ge 1) "driver $(& $svcState)"
                Check 'restore was faithful: still broken the same way (entry, no uninstaller)' ((Get-Uninstall $name) -and (Test-Path $root) -and -not (Test-Path "$root\uninstall.exe"))
                $r = Invoke-Engine @('-Name', $name, '-Level', '3', '-IncludeReview', '-Force', '-Quiet')
                Check 'L3 again exit 0 or 3010' ($r.Code -in @(0, 3010)) "exit $($r.Code)"
                $run = Get-NewestRun $started
                Save-State 'npcap-run' @{ runId = $run.runId; code = $r.Code }
            }
            'final' {
                & $resumeIfNeeded
                $n = Test-Network ([int](Read-State 'npcap-net').up)
                Check 'final: the network works' $n.Ok $n.Detail
                $bad = @(Get-DeviceErrors)
                Check 'final: no device in an error state' ($bad.Count -eq 0) ($bad -join ', ')
                Check 'final: nothing of Npcap is left' (-not (Test-NetComponent $cid) -and @(& $inf).Count -eq 0 -and (& $svcState) -eq 'absent' -and -not (Test-Path $root) -and -not (Get-Uninstall $name) -and -not (Get-ScheduledTask -TaskName npcapwatchdog -ErrorAction SilentlyContinue))
            }
        }
    }

    'everything' {
        # An app with a Windows service: voidtools Everything 1.4 (NSIS, service "Everything" running from
        # the install folder), uninstaller deleted.
        $name = 'Everything 1.4*'
        $root = 'C:\Program Files\Everything'
        if (-not (Get-Uninstall $name)) {
            $p = Start-Process -FilePath (Join-Path $Media 'Everything-x64-Setup.exe') -ArgumentList '/S' -Wait -PassThru
            if ($p.ExitCode -ne 0) { throw "Everything install failed: $($p.ExitCode)" }
            Start-Sleep -Seconds 3
        }
        if (Test-Path "$root\Uninstall.exe") { Remove-Item "$root\Uninstall.exe" -Force }
        $full = (Get-Uninstall $name).DisplayName
        Check 'precondition: Everything installed, its service running, its uninstaller gone' ((Get-Service Everything -ErrorAction SilentlyContinue).Status -eq 'Running' -and -not (Test-Path "$root\Uninstall.exe"))
        $scan = Join-Path $StateDir 'everything-scan'
        $r = Invoke-Engine @('-Name', $full, '-Level', '0', '-OutDir', $scan, '-Quiet')
        Check 'scan exit 0' ($r.Code -eq 0) "exit $($r.Code)"
        $plan = Get-Plan $scan
        $sv = @($plan.items | Where-Object { $_.category -eq 'Service' })
        Check 'plan: the Everything service, tied by its program path (not review)' ($sv.Count -eq 1 -and $sv[0].op.name -eq 'Everything' -and -not $sv[0].review)
        Check 'plan: no per-user folder outside the UserData opt-in' (@($plan.items | Where-Object { $_.category -eq 'AppDataFolder' -and $_.group -ne 'UserData' }).Count -eq 0)
        $sel = Get-SelectedItems $plan 3
        $s0 = Get-PlanState $sel
        $r = Invoke-Engine @('-Name', $full, '-Level', '3', '-Force', '-Quiet')
        Check 'L3 exit 0' ($r.Code -eq 0) "exit $($r.Code)"
        $run = Get-NewestRun $started
        Check 'L3: the service is gone, and nothing runs from the folder' (-not (Get-Service Everything -ErrorAction SilentlyContinue) -and -not @(Get-Process Everything -ErrorAction SilentlyContinue).Count)
        Check 'L3: folder, entry and Run value gone' (-not (Test-Path $root) -and -not (Get-Uninstall $name) -and -not ((Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run' -ErrorAction SilentlyContinue).PSObject.Properties.Name -contains 'Everything'))
        $r = Invoke-Engine @('-Restore', $run.runId, '-Force', '-Quiet')
        Check 'restore exit 0' ($r.Code -eq 0) "exit $($r.Code)"
        Compare-State $s0 (Get-PlanState $sel) 'restore: every item back exactly as it was (files hashed)'
        Start-Sleep -Seconds 3
        Check 'restore: the service is back and running again' ((Get-Service Everything -ErrorAction SilentlyContinue).Status -eq 'Running')
        Check 'restore: still broken the same way (no uninstaller)' ((Get-Uninstall $name) -and -not (Test-Path "$root\Uninstall.exe"))
    }

    'sevenzip' {
        # An MSI with shell extensions: 7-Zip (context menu and drag-drop handlers under *, Directory,
        # Folder and Drive, a COM class in both views, the Approved list). Broken the PuTTY way: cached
        # package deleted, msiexec /x = 1612. The cached package is kept aside and put back at the end.
        # Only ever break a 7-Zip THIS scenario installed from a throwaway copy (the marker file). Any other
        # 7-Zip may have its install source still reachable, and then msiexec /x re-caches from it and REALLY
        # uninstalls: that happened twice on 2026-09-29. A foreign 7-Zip gets a normal uninstall first.
        $marker = Join-Path $StateDir '7zip-ours.txt'
        $z = Get-Uninstall '7-Zip*'
        if ($z -and -not (Test-Path -LiteralPath $marker)) {
            if (($z.PSObject.Properties.Name -contains 'WindowsInstaller') -and $z.WindowsInstaller -eq 1) { [void](Invoke-Msiexec "/x $($z.PSChildName) /qn /norestart") }
            elseif ($z.PSObject.Properties.Name -contains 'UninstallString') { [void](Start-Process -FilePath ($z.UninstallString.Trim('"')) -ArgumentList '/S' -Wait -PassThru) }
            $z = Get-Uninstall '7-Zip*'
        }
        if (-not $z) {
            # From a throwaway copy that is deleted below, like PuTTY: with the original source still on
            # disk, msiexec /x re-caches from it and REALLY uninstalls (it did, 2026-09-29).
            $src7 = Join-Path $StateDir '7zip-source.msi'
            Copy-Item -LiteralPath (Join-Path $Media '7z2409-x64.msi') -Destination $src7 -Force
            Check 'precondition: a 7-Zip MSI is installed' ((Invoke-Msiexec "/i `"$src7`" /qn /norestart") -eq 0)
            Remove-Item -LiteralPath $src7 -Force
            Set-Content -LiteralPath $marker -Value 'installed by the sevenzip scenario from a deleted throwaway copy' -Encoding ASCII
            $z = Get-Uninstall '7-Zip*'
        }
        $pc = $z.PSChildName
        $clsid = '{23170F69-40C1-278A-1000-000100020000}'
        $handlers = @('*\shellex\ContextMenuHandlers\7-Zip', 'Directory\shellex\ContextMenuHandlers\7-Zip', 'Folder\ShellEx\ContextMenuHandlers\7-Zip', 'Directory\shellex\DragDropHandlers\7-Zip', 'Drive\shellex\DragDropHandlers\7-Zip')
        $present = { @($handlers | Where-Object { Test-Path -LiteralPath "HKLM:\SOFTWARE\Classes\$_" }).Count }
        $others = { @(Get-ChildItem -LiteralPath 'HKLM:\SOFTWARE\Classes\*\shellex\ContextMenuHandlers' | Where-Object { $_.PSChildName -ne '7-Zip' } | ForEach-Object PSChildName) -join ',' }
        $approved = { @((Get-Item 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Shell Extensions\Approved').GetValueNames() | Where-Object { $_ -ne $clsid }).Count }
        # Ask Windows Installer where the cached package is. A registry walk for it came back empty on
        # 2026-09-29, and the 1612 check below then ran msiexec /x against a HEALTHY 7-Zip and really
        # uninstalled it. The break is now confirmed before msiexec /x is ever run.
        $wi = New-Object -ComObject WindowsInstaller.Installer
        $local = [string]$wi.GetType().InvokeMember('ProductInfo', [System.Reflection.BindingFlags]::GetProperty, $null, $wi, @($pc, 'LocalPackage'))
        $aside = Join-Path $StateDir '7zip-cached.msi'
        if ($local -and (Test-Path -LiteralPath $local)) { Copy-Item -LiteralPath $local -Destination $aside -Force; Remove-Item -LiteralPath $local -Force }
        if (-not $local -or (Test-Path -LiteralPath $local)) { throw "could not break 7-Zip: cached package '$local' not found or still there; refusing to run msiexec /x on a healthy install" }
        Check 'precondition: 7-Zip is broken (msiexec /x = 1612) and its shell extension registered' ((Invoke-Msiexec "/x $pc /qn /norestart") -eq 1612 -and (& $present) -eq $handlers.Count)
        $othersBefore = & $others; $approvedBefore = & $approved
        try {
            $scan = Join-Path $StateDir '7zip-scan'
            $r = Invoke-Engine @('-ProductCode', $pc, '-Level', '0', '-OutDir', $scan, '-Quiet')
            Check 'scan exit 0' ($r.Code -eq 0) "exit $($r.Code)"
            $plan = Get-Plan $scan
            Check 'plan: every 7-Zip shell handler, the Approved entry and the COM class' (@($plan.items | Where-Object { $_.category -eq 'ShellExtension' }).Count -ge ($handlers.Count + 1) -and @($plan.items | Where-Object { $_.category -eq 'ComClass' -and $_.target -like "*$clsid" }).Count -ge 1)
            $sel = Get-SelectedItems $plan 3
            $s0 = Get-PlanState $sel
            $r = Invoke-Engine @('-ProductCode', $pc, '-Level', '3', '-Force', '-Quiet')
            Check 'L3 exit 0' ($r.Code -eq 0) "exit $($r.Code)"
            $run = Get-NewestRun $started
            Check 'L3: Windows Installer no longer knows it' ((Get-MsiProductState $pc) -eq -1)
            Check 'L3: every 7-Zip shell handler and the COM class are gone' ((& $present) -eq 0 -and -not (Test-Path -LiteralPath "HKLM:\SOFTWARE\Classes\CLSID\$clsid"))
            Check 'L3: every OTHER context menu handler untouched' ((& $others) -eq $othersBefore) (& $others)
            Check 'L3: every other Approved shell extension untouched' ((& $approved) -eq $approvedBefore) "$(& $approved) (was $approvedBefore)"
            Check 'L3: the folder is gone' (-not (Test-Path 'C:\Program Files\7-Zip'))
            $r = Invoke-Engine @('-Restore', $run.runId, '-Force', '-Quiet')
            Check 'restore exit 0' ($r.Code -eq 0) "exit $($r.Code)"
            Compare-State $s0 (Get-PlanState $sel) 'restore: every item back exactly as it was (files hashed)'
            Check 'restore: the shell extension is registered again' ((& $present) -eq $handlers.Count -and (Test-Path -LiteralPath "HKLM:\SOFTWARE\Classes\CLSID\$clsid"))
            $t = Start-Process 'C:\Program Files\7-Zip\7z.exe' -ArgumentList 'i' -Wait -PassThru -WindowStyle Hidden
            Check 'restore: 7z.exe runs' ($t.ExitCode -eq 0) "exit $($t.ExitCode)"
            Check 'restore: broken exactly as before (msiexec /x = 1612)' ((Invoke-Msiexec "/x $pc /qn /norestart") -eq 1612)
        } finally {
            # Leave it healthy for the scenarios that want a working 7-Zip MSI.
            if ((Test-Path -LiteralPath $aside) -and $local -and -not (Test-Path -LiteralPath $local)) { Copy-Item -LiteralPath $aside -Destination $local -Force }
        }
    }

    'zoom' {
        # A per-user install: Zoom Workplace via ZoomInstaller.exe (the host installs it as this user).
        # %APPDATA%\Zoom\bin and \uninstall, an HKCU uninstall entry, HKCU protocol handlers, a per-user
        # scheduled task, and HKCU\Software\ZoomUMX, which only profiles\Zoom.psd1 knows about. The user
        # is signed in (this session), so the hive is loaded. Uninstaller deleted.
        $name = 'Zoom Workplace'
        $zroot = Join-Path $env:APPDATA 'Zoom'
        $sid = ([System.Security.Principal.WindowsIdentity]::GetCurrent()).User.Value
        $umx = "Registry::HKEY_USERS\$sid\Software\ZoomUMX"
        $task = { @(Get-ScheduledTask -ErrorAction SilentlyContinue | Where-Object { $_.TaskName -like "ZoomUpdateTaskUser-$sid" }).Count }
        if (Test-Path "$zroot\uninstall\Installer.exe") { Remove-Item "$zroot\uninstall\Installer.exe" -Force }
        Check 'precondition: Zoom installed per user, its uninstaller gone' ((Get-UserUninstall $name) -and (Test-Path "$zroot\bin\Zoom.exe") -and -not (Test-Path "$zroot\uninstall\Installer.exe") -and (Test-Path $umx))
        $scan = Join-Path $StateDir 'zoom-scan'
        $r = Invoke-Engine @('-Name', $name, '-Level', '0', '-OutDir', $scan, '-Quiet')
        Check 'scan exit 0' ($r.Code -eq 0) "exit $($r.Code)"
        $plan = Get-Plan $scan
        Check 'plan: the per-user uninstall entry' (@($plan.items | Where-Object { $_.category -eq 'UninstallEntry' -and $_.target -like "HKU\$sid\*" }).Count -eq 1)
        Check 'plan: the profile adds HKCU\Software\ZoomUMX' (@($plan.items | Where-Object { $_.target -like '*\Software\ZoomUMX' -and $_.op }).Count -eq 1)
        Check 'plan: the zoommtg protocol handler and the per-user task' (@($plan.items | Where-Object { $_.target -like '*_Classes\zoommtg' }).Count -eq 1 -and @($plan.items | Where-Object { $_.category -eq 'ScheduledTask' }).Count -eq 1)
        $sel = Get-SelectedItems $plan 3
        $s0 = Get-PlanState $sel
        $r = Invoke-Engine @('-Name', $name, '-Level', '3', '-Force', '-Quiet')
        Check 'L3 exit 0' ($r.Code -eq 0) "exit $($r.Code)"
        $run = Get-NewestRun $started
        Check 'L3: entry, program folders, ZoomUMX, protocol handler and task all gone' (-not (Get-UserUninstall $name) -and -not (Test-Path "$zroot\bin") -and -not (Test-Path $umx) -and -not (Test-Path "Registry::HKEY_USERS\$($sid)_Classes\zoommtg") -and (& $task) -eq 0)
        Check 'L3: the rest of %APPDATA%\Zoom (user data) left alone without -IncludeUserData' (Test-Path $zroot)
        $r = Invoke-Engine @('-Restore', $run.runId, '-Force', '-Quiet')
        Check 'restore exit 0' ($r.Code -eq 0) "exit $($r.Code)"
        Compare-State $s0 (Get-PlanState $sel) 'restore: every item back exactly as it was (files hashed)'
        Check 'restore: Zoom is back for this user, still without its uninstaller' ((Get-UserUninstall $name) -and (Test-Path "$zroot\bin\Zoom.exe") -and (Test-Path $umx) -and (& $task) -eq 1 -and -not (Test-Path "$zroot\uninstall\Installer.exe"))
    }

    'credprov' {
        # A credential provider whose DLL can't load, with the built-in password sign-in turned OFF: the
        # machine nobody can sign in to. Kill It With Fire must turn the password sign-in back on BEFORE it removes
        # the provider. The host tries a real sign-in (keyboard over Hyper-V) after each reboot.
        $name = 'KillItWithFire Credential Test'
        $folder = 'C:\Program Files\KillItWithFireCredTest'
        $clsid = '{6A1E5D3C-7B2F-4E8A-9C0D-1F2E3D4C5B6A}'
        $pw = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\Credential Providers\{60b78e88-EAD8-445C-9CFD-0B87F74EA6CD}'
        $cp = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\Credential Providers\$clsid"
        $pwOff = { $v = Get-ItemProperty -LiteralPath $pw -ErrorAction SilentlyContinue; [bool]($v -and ($v.PSObject.Properties.Name -contains 'Disabled') -and $v.Disabled -eq 1) }
        switch ($Phase) {
            'setup' {
                New-TestApp 'KillItWithFireCredTest' $name $folder @('readme.txt')
                Set-Content -LiteralPath "$folder\ltcred.dll" -Value 'not a dll' -Encoding ASCII
                New-Item -Path "HKLM:\SOFTWARE\Classes\CLSID\$clsid\InprocServer32" -Force | Out-Null
                Set-ItemProperty -Path "HKLM:\SOFTWARE\Classes\CLSID\$clsid" -Name '(default)' -Value 'KillItWithFire Credential Test'
                Set-ItemProperty -Path "HKLM:\SOFTWARE\Classes\CLSID\$clsid\InprocServer32" -Name '(default)' -Value "$folder\ltcred.dll"
                Set-ItemProperty -Path "HKLM:\SOFTWARE\Classes\CLSID\$clsid\InprocServer32" -Name 'ThreadingModel' -Value 'Apartment'
                New-Item -Path $cp -Force | Out-Null
                Set-ItemProperty -Path $cp -Name '(default)' -Value 'KillItWithFire Credential Test'
                New-ItemProperty -Path $pw -Name Disabled -Value 1 -PropertyType DWord -Force | Out-Null
                Check 'setup: password sign-in is OFF, our provider registered' ((& $pwOff) -and (Test-Path $cp))
            }
            'broken' {
                $scan = Join-Path $StateDir 'cred-scan'
                $r = Invoke-Engine @('-Name', $name, '-Level', '0', '-OutDir', $scan, '-Quiet')
                $plan = Get-Plan $scan
                $p = @($plan.items | Where-Object { $_.category -eq 'PasswordProviderRestore' })
                $c = @($plan.items | Where-Object { $_.category -eq 'CredentialProvider' })
                Check 'plan: turn the password sign-in back on (critical)' ($p.Count -eq 1 -and $p[0].risk -eq 'critical')
                Check 'plan: our credential provider (tied by its COM server path)' ($c.Count -eq 1 -and -not $c[0].review)
                Check 'plan: password sign-in back on BEFORE the provider goes' ($p.Count -and $c.Count -and $p[0].order -lt $c[0].order)
                $sel = Get-SelectedItems $plan 3
                Save-State 'cred-s0' (Get-PlanState $sel)
                Copy-Item -LiteralPath (Join-Path $scan 'plan.json') -Destination (Join-Path $StateDir 'cred-plan.json') -Force
                $r = Invoke-Engine @('-Name', $name, '-Level', '3', '-Force', '-Quiet')
                Check 'L3 exit 0' ($r.Code -eq 0) "exit $($r.Code)"
                $run = Get-NewestRun $started
                Save-State 'cred-run' @{ runId = $run.runId }
                Check 'L3: password sign-in is ON' (-not (& $pwOff))
                Check 'L3: our provider and its COM class are gone' (-not (Test-Path $cp) -and -not (Test-Path "HKLM:\SOFTWARE\Classes\CLSID\$clsid"))
            }
            'cleaned' {
                $run = Read-State 'cred-run'
                $r = Invoke-Engine @('-Restore', $run.runId, '-Force', '-Quiet')
                Check 'restore exit 0' ($r.Code -eq 0) "exit $($r.Code)"
                $plan = Get-Content -LiteralPath (Join-Path $StateDir 'cred-plan.json') -Raw | ConvertFrom-Json
                Compare-State (ConvertTo-Ordered (Read-State 'cred-s0')) (Get-PlanState (Get-SelectedItems $plan 3)) 'restore: provider, COM class, password switch, files and entry back exactly'
                Check 'restore: password sign-in is OFF again' (& $pwOff)
            }
            'restored' {
                $r = Invoke-Engine @('-Name', $name, '-Level', '3', '-Force', '-Quiet')
                Check 'L3 again exit 0' ($r.Code -eq 0) "exit $($r.Code)"
                Check 'password sign-in is ON' (-not (& $pwOff))
            }
            'final' {
                Check 'final: nothing of the test app is left' (-not (Test-Path $folder) -and -not (Get-Uninstall $name) -and -not (Test-Path $cp))
                Check 'final: password sign-in is ON' (-not (& $pwOff))
            }
        }
    }
}
Finish
