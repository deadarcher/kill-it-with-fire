#Requires -Version 5.1
<#
.SYNOPSIS
    Destructive end-to-end validation of Leftovers. THROWAWAY MACHINES ONLY (a lab VM or a CI runner).

.DESCRIPTION
    Installs real apps, breaks them the way broken uninstalls really look, runs Leftovers at every level,
    and checks every change AND every restore on the machine itself. It edits HKLM, creates services
    and a device class filter, and turns the password sign-in off and on. Never run it on a machine
    you care about: it refuses to start without -ConfirmThrowaway.

    Scenarios (each prints PASS/FAIL lines and writes <StateDir>\<scenario>-<phase>.json):
      putty      L2 on an MSI whose cached package and source are gone; reinstall works; restore round trip
      profile    profiles\PuTTY.psd1 adds the user's saved sessions (user data, opt-in); restore round trip
      notepadpp  L3 on an app whose uninstaller is gone; restore round trip; the app runs again
      hooks      one synthetic app hooked in a dozen ways (IFEO, AppInit, Userinit, Active Setup, verbs, file
                 types, shortcut, task, Run, firewall, service): all found, removed, restored exactly
      plan       the window's path: -Plan <file> -Exclude ...; plan guards (other computer, stale plan)
      policy     HKLM\SOFTWARE\Policies\Leftovers locks enforced by the engine (and shown by the window)
      refusal    the RFF agent, a Microsoft MSI by ProductCode, a security vendor, a Windows keyword
      bitness    a 32-bit PowerShell host relaunches 64-bit and finds the same plan
      pending    a locked file: exit 3010, then restore BEFORE the reboot (CI-safe)
      resume     a locked file: exit 3010; phase 'after' (after a reboot): -Resume, then restore
      filter     a keyboard class filter + its driver; phases setup, broken, cleaned, restored, final
                 (the host reboots between phases and checks the keyboard device each time)
      credprov   a credential provider + the built-in password sign-in turned off; phases setup,
                 broken, cleaned, restored, final (the host reboots and tries a real sign-in)

    Phases that follow a reboot read what the earlier phase saved in <StateDir>.

.PARAMETER ConfirmThrowaway
    Required: says this machine may be broken by the test.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidateSet('putty', 'profile', 'notepadpp', 'hooks', 'plan', 'policy', 'refusal', 'bitness', 'pending', 'resume', 'filter', 'credprov')]
    [string] $Scenario,
    [string] $Phase = 'run',
    [string] $Engine,
    [string] $Media,
    [string] $StateDir = (Join-Path $env:ProgramData 'LeftoversLab'),
    [string] $HostExe = (Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'),
    [switch] $ConfirmThrowaway
)
Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'
# Not parameter defaults: Windows PowerShell 5.1 leaves $PSScriptRoot empty while defaults are evaluated.
if (-not $Engine) { $Engine = Join-Path $PSScriptRoot '..\Leftovers.ps1' }
if (-not $Media) { $Media = Join-Path $PSScriptRoot '..\lab-media' }
if (-not $ConfirmThrowaway) {
    Write-Host 'Refusing: this validation installs, breaks and removes software, edits HKLM, adds a device filter and turns the password sign-in off. Run it only on a throwaway lab VM or CI runner, with -ConfirmThrowaway.'
    exit 2
}
$Engine = (Resolve-Path -LiteralPath $Engine).Path
New-Item -ItemType Directory -Force -Path $StateDir | Out-Null
$script:Checks = New-Object System.Collections.Generic.List[object]
$script:RunsRoot = Join-Path $env:ProgramData 'Leftovers\runs'

# ------------------------------------------------------------------------------------------ helpers

function Check {
    param([string] $Name, [bool] $Ok, [string] $Detail = '')
    $script:Checks.Add([pscustomobject][ordered]@{ name = $Name; pass = $Ok; detail = $Detail })
    Write-Host ("{0}  {1}{2}" -f $(if ($Ok) { 'PASS' } else { 'FAIL' }), $Name, $(if ($Detail) { "  ($Detail)" } else { '' }))
}

function Invoke-Engine {
    # Runs Leftovers in its own process (the way an RMM would) and returns the exit code and output.
    param([string[]] $Arguments, [string] $Exe = $HostExe)
    $out = Join-Path $StateDir ('engine-' + [guid]::NewGuid().ToString('N').Substring(0, 8) + '.txt')
    $argLine = @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', $Engine) + $Arguments
    $quoted = @($argLine | ForEach-Object { if ($_ -match '[\s"]' -or $_ -eq '') { '"' + ($_ -replace '"', '\"') + '"' } else { $_ } })
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

if (-not ('LeftoversLab.Native' -as [type])) {
    Add-Type -Namespace LeftoversLab -Name Native -MemberDefinition @"
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
        try { $n = [LeftoversLab.Native]::GetKeyName($k.Handle.DangerousGetHandle()) } finally { $k.Close() }
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
    param([string] $DisplayNameLike)
    foreach ($root in @('HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall', 'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall')) {
        foreach ($k in @(Get-ChildItem -LiteralPath $root -ErrorAction SilentlyContinue)) {
            $p = Get-ItemProperty -LiteralPath $k.PSPath -ErrorAction SilentlyContinue
            if ($p -and ($p.PSObject.Properties.Name -contains 'DisplayName') -and $p.DisplayName -like $DisplayNameLike) { return $p }
        }
    }
    return $null
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
    param([string] $Key, [string] $DisplayName, [string] $Folder, [string[]] $Files, [string] $Publisher = 'Leftovers Lab')
    New-Item -ItemType Directory -Force -Path $Folder | Out-Null
    foreach ($f in $Files) { Set-Content -LiteralPath (Join-Path $Folder $f) -Value "Leftovers lab file $f $(Get-Date -Format o)" -Encoding ASCII }
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
        $z = Get-Uninstall '7-Zip*'
        if (-not $z -or -not ($z.PSObject.Properties.Name -contains 'WindowsInstaller') -or $z.WindowsInstaller -ne 1) {
            $zmsi = @(Get-ChildItem -LiteralPath $Media -Filter '7z*.msi' -ErrorAction SilentlyContinue | Select-Object -First 1)
            if (-not $zmsi.Count) { Check 'precondition: a 7-Zip MSI is installed (or 7z*.msi is in the media folder)' $false; Finish }
            [void](Invoke-Msiexec "/i `"$($zmsi[0].FullName)`" /qn /norestart")
            $z = Get-Uninstall '7-Zip*'
        }
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
        $sessKey = 'HKCU:\Software\SimonTatham\PuTTY\Sessions\LeftoversTest'
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
        $name = 'Leftovers Hooks Test'
        $folder = 'C:\Program Files\LeftoversHooksTest'
        $exe = "$folder\hook.exe"
        $wl = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon'
        $userinitBefore = (Get-ItemProperty -LiteralPath $wl).Userinit
        $appinitBefore = (Get-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows').AppInit_DLLs
        New-TestApp 'LeftoversHooksTest' $name $folder @('hook.exe', 'hook.dll', 'readme.txt')
        try {
            # IFEO debugger on a made-up exe name (never a real one).
            New-Item -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\leftoverslabtarget.exe' -Force | Out-Null
            Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\leftoverslabtarget.exe' -Name Debugger -Value "`"$exe`""
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
            New-Item -Path 'HKLM:\SOFTWARE\Classes\Directory\shell\LeftoversLabVerb\command' -Force | Out-Null
            Set-ItemProperty -Path 'HKLM:\SOFTWARE\Classes\Directory\shell\LeftoversLabVerb\command' -Name '(default)' -Value "`"$exe`" `"%1`""
            New-Item -Path 'HKLM:\SOFTWARE\Classes\.leftoverslab' -Force | Out-Null
            Set-ItemProperty -Path 'HKLM:\SOFTWARE\Classes\.leftoverslab' -Name '(default)' -Value 'LeftoversLab.File'
            New-Item -Path 'HKLM:\SOFTWARE\Classes\LeftoversLab.File\shell\open\command' -Force | Out-Null
            Set-ItemProperty -Path 'HKLM:\SOFTWARE\Classes\LeftoversLab.File\shell\open\command' -Name '(default)' -Value "`"$exe`" `"%1`""
            $sh = New-Object -ComObject WScript.Shell
            $lnk = $sh.CreateShortcut((Join-Path $env:PUBLIC 'Desktop\Leftovers Hooks Test.lnk')); $lnk.TargetPath = $exe; $lnk.Save()
            # A scheduled task, a Run value (+ its StartupApproved twin), a firewall rule, a service.
            Register-ScheduledTask -TaskName 'LeftoversLabHooksTask' -Action (New-ScheduledTaskAction -Execute $exe -Argument '/tick') -Trigger (New-ScheduledTaskTrigger -Daily -At 3am) -User 'SYSTEM' -Force | Out-Null
            Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run' -Name 'LeftoversLabHooks' -Value "`"$exe`" /tray"
            New-Item -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run' -Force -ErrorAction SilentlyContinue | Out-Null
            New-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run' -Name 'LeftoversLabHooks' -Value ([byte[]](2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0)) -PropertyType Binary -Force | Out-Null
            New-NetFirewallRule -Name 'LeftoversLabHooksRule' -DisplayName 'Leftovers Hooks Test' -Direction Inbound -Action Allow -Program $exe -Profile Any | Out-Null
            New-Service -Name 'LeftoversLabHooksSvc' -BinaryPathName "`"$exe`" -service" -StartupType Manual -DisplayName 'Leftovers Hooks Test' | Out-Null
            # Two top-level keys named for the keyword: one whose contents point at the app, one that
            # only shares the name (it must be review-only, never removed by default).
            New-Item -Path 'HKLM:\SOFTWARE\Leftovers Lab\App' -Force | Out-Null
            Set-ItemProperty -Path 'HKLM:\SOFTWARE\Leftovers Lab\App' -Name InstallPath -Value $folder
            New-Item -Path 'HKLM:\SOFTWARE\Leftovers Unrelated' -Force | Out-Null
            Set-ItemProperty -Path 'HKLM:\SOFTWARE\Leftovers Unrelated' -Name Setting -Value 'blue'

            $scan = Join-Path $StateDir 'hooks-scan'
            $r = Invoke-Engine @('-Name', $name, '-Level', '0', '-OutDir', $scan, '-Quiet')
            Check 'scan exit 0' ($r.Code -eq 0) "exit $($r.Code)"
            $plan = Get-Plan $scan
            $cats = @($plan.items | ForEach-Object { $_.category } | Select-Object -Unique)
            foreach ($c in @('IfeoDebugger', 'Winlogon', 'ActiveSetup', 'ShellVerb', 'FileAssociation', 'Shortcut', 'ScheduledTask', 'RunValue', 'FirewallRule', 'Service', 'InstallRoot', 'UninstallEntry')) {
                Check "plan has $c" ($cats -contains $c)
            }
            if ($testAppInit) { Check 'plan has AppInitDll (matched through the 8.3 path)' ($cats -contains 'AppInitDll') }
            Check 'plan: the .leftoverslab extension stops naming our file type' (@($plan.items | Where-Object { $_.target -like '*\.leftoverslab : (default)' }).Count -eq 1)
            $w = @($plan.items | Where-Object { $_.category -eq 'Winlogon' })
            Check 'Userinit: remove OUR entry only, keep the rest' ($w.Count -eq 1 -and $w[0].action -like '*keep every other entry*')
            if ($plan.keyword.used -and $plan.keyword.value -eq 'Leftovers') {
                $vk = @($plan.items | Where-Object { $_.target -like '*\SOFTWARE\Leftovers Lab' })
                $uk = @($plan.items | Where-Object { $_.target -like '*\SOFTWARE\Leftovers Unrelated' })
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
            Check 'L3: the StartupApproved twin went with the Run value' ((Get-ValueFingerprint 'HKLM64' 'SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run' 'LeftoversLabHooks') -eq 'absent')
            $r = Invoke-Engine @('-Restore', $run.runId, '-Force', '-Quiet')
            Check 'restore exit 0' ($r.Code -eq 0) "exit $($r.Code)"
            Compare-State $s0 (Get-PlanState $sel) 'restore: every hook back exactly (task XML, firewall rule, service, lists, keys, files)'
            Check 'the unrelated key that only shares the name was never touched' ((Get-ValueFingerprint 'HKLM64' 'SOFTWARE\Leftovers Unrelated' 'Setting') -eq 'String:blue')

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
        } finally {
            # Leave the machine as it was, whatever happened above.
            Set-ItemProperty -Path $wl -Name Userinit -Value $userinitBefore
            Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows' -Name AppInit_DLLs -Value ([string]$appinitBefore)
            Remove-Item -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\leftoverslabtarget.exe' -Recurse -Force -ErrorAction SilentlyContinue
            Remove-Item -Path 'HKLM:\SOFTWARE\Microsoft\Active Setup\Installed Components\{7E1F2A3B-LEFT-OVER-LAB0-000000000001}' -Recurse -Force -ErrorAction SilentlyContinue
            Remove-Item -Path 'HKLM:\SOFTWARE\Classes\Directory\shell\LeftoversLabVerb', 'HKLM:\SOFTWARE\Classes\.leftoverslab', 'HKLM:\SOFTWARE\Classes\LeftoversLab.File' -Recurse -Force -ErrorAction SilentlyContinue
            Remove-Item -Path 'HKLM:\SOFTWARE\Leftovers Lab', 'HKLM:\SOFTWARE\Leftovers Unrelated' -Recurse -Force -ErrorAction SilentlyContinue
            Remove-Item -LiteralPath (Join-Path $env:PUBLIC 'Desktop\Leftovers Hooks Test.lnk') -Force -ErrorAction SilentlyContinue
            Unregister-ScheduledTask -TaskName 'LeftoversLabHooksTask' -Confirm:$false -ErrorAction SilentlyContinue
            Remove-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run' -Name 'LeftoversLabHooks' -ErrorAction SilentlyContinue
            Remove-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run' -Name 'LeftoversLabHooks' -ErrorAction SilentlyContinue
            Remove-NetFirewallRule -Name 'LeftoversLabHooksRule' -ErrorAction SilentlyContinue
            & sc.exe delete LeftoversLabHooksSvc 2>&1 | Out-Null
            Remove-TestApp 'LeftoversHooksTest' $folder
        }
    }

    'policy' {
        $pol = 'HKLM:\SOFTWARE\Policies\Leftovers'
        $name = 'Leftovers Policy Test'
        $folder = 'C:\Program Files\LeftoversPolicyTest'
        New-TestApp 'LeftoversPolicyTest' $name $folder @('app.exe.txt')
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
            Check 'the window reads the REAL policy key: Full scrub greyed out' ((@($json.levelsEnabled) -join ',') -eq 'True,True,True,False')
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
            Remove-TestApp 'LeftoversPolicyTest' $folder
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
        New-TestApp 'LeftoversSecurityTest' 'CrowdStrike Windows Sensor' 'C:\Program Files\LeftoversSecurityTest' @('csagent.txt') -Publisher 'CrowdStrike, Inc.'
        try {
            $r = Invoke-Engine @('-Name', 'CrowdStrike Windows Sensor', '-Level', '3', '-Force', '-Quiet')
            Check 'a security product is refused, and names the vendor tool' ($r.Code -eq 2 -and $r.Output -match 'CsUninstallTool') "exit $($r.Code)"
        } finally { Remove-TestApp 'LeftoversSecurityTest' 'C:\Program Files\LeftoversSecurityTest' }
        New-TestApp 'LeftoversKeywordTest' 'Leftovers Keyword Test' 'C:\Program Files\LeftoversKeywordTest' @('a.txt')
        try {
            $r = Invoke-Engine @('-Name', 'Leftovers Keyword Test', '-Keyword', 'Microsoft', '-Level', '0', '-OutDir', (Join-Path $StateDir 'kw-scan'), '-Quiet')
            $plan = Get-Plan (Join-Path $StateDir 'kw-scan')
            Check '-Keyword Microsoft is refused (the scan still runs)' ($r.Code -eq 0 -and -not $plan.keyword.used -and $plan.keyword.reason -like 'REFUSED*') $plan.keyword.reason
            $r = Invoke-Engine @('-Name', 'Leftovers Keyword Test', '-Keyword', 'Intune', '-Level', '0', '-OutDir', (Join-Path $StateDir 'kw-scan2'), '-Quiet')
            $plan = Get-Plan (Join-Path $StateDir 'kw-scan2')
            Check '-Keyword Intune is refused' (-not $plan.keyword.used) $plan.keyword.reason
        } finally { Remove-TestApp 'LeftoversKeywordTest' 'C:\Program Files\LeftoversKeywordTest' }
        $r = Invoke-Engine @('-Name', 'No Such App 12345', '-Level', '0', '-Quiet')
        Check 'an unknown name is exit 3' ($r.Code -eq 3) "exit $($r.Code)"
    }

    'bitness' {
        $name = 'Leftovers Bitness Test'
        $folder = 'C:\Program Files\LeftoversBitnessTest'
        New-TestApp 'LeftoversBitnessTest' $name $folder @('a.txt', 'b.txt')
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
        } finally { Remove-TestApp 'LeftoversBitnessTest' $folder }
    }

    { $_ -in @('pending', 'resume') } {
        # A file held open with no sharing can't move now: it is scheduled for the next boot (exit 3010).
        $name = 'Leftovers Locked Test'
        $folder = 'C:\Program Files\LeftoversLockedTest'
        $locked = Join-Path $folder 'locked.bin'
        if ($Phase -eq 'run') {
            New-TestApp 'LeftoversLockedTest' $name $folder @('a.txt', 'locked.bin')
            $holder = Start-Process -FilePath $HostExe -ArgumentList '-NoProfile', '-Command', "`$f = [System.IO.File]::Open('$locked', 'Open', 'Read', 'None'); Start-Sleep -Seconds 1800" -PassThru -WindowStyle Hidden
            Start-Sleep -Seconds 3
            $r = Invoke-Engine @('-Name', $name, '-Level', '3', '-Force', '-Quiet')
            Check 'a locked file makes the run exit 3010' ($r.Code -eq 3010) "exit $($r.Code)"
            $run = Get-NewestRun $started
            Check 'the run is marked pending-reboot' ($run.status -eq 'pending-reboot') $run.status
            Check 'the other file moved now' (-not (Test-Path (Join-Path $folder 'a.txt')))
            Check 'the locked file is still in place' (Test-Path $locked)
            $pfro = @((Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager' -Name PendingFileRenameOperations -ErrorAction SilentlyContinue).PendingFileRenameOperations)
            Check 'the locked file is scheduled to move at boot' (@($pfro | Where-Object { $_ -like "*$locked" }).Count -eq 1)
            Save-State 'resume' @{ runId = $run.runId; holder = $holder.Id }
            if ($Scenario -eq 'pending') {
                Stop-Process -Id $holder.Id -Force -ErrorAction SilentlyContinue
                $r = Invoke-Engine @('-Restore', $run.runId, '-Force', '-Quiet')
                Check 'restore before the reboot: exit 0' ($r.Code -eq 0) "exit $($r.Code)"
                $pfro = @((Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager' -Name PendingFileRenameOperations -ErrorAction SilentlyContinue).PendingFileRenameOperations)
                Check 'restore took the boot-time move back out' (@($pfro | Where-Object { $_ -like "*$locked" }).Count -eq 0)
                Check 'restore: both files and the entry are back' ((Test-Path $locked) -and (Test-Path (Join-Path $folder 'a.txt')) -and [bool](Get-Uninstall $name))
                Remove-TestApp 'LeftoversLockedTest' $folder
            }
        } elseif ($Phase -eq 'after') {
            $st = Read-State 'resume'
            Check 'after the reboot: the locked file moved' (-not (Test-Path $locked))
            Check 'after the reboot: it is in the quarantine' (Test-Path (Join-Path $script:RunsRoot "$($st.runId)\files\C\Program Files\LeftoversLockedTest\locked.bin"))
            $r = Invoke-Engine @('-Resume', $st.runId, '-Quiet')
            Check '-Resume exit 0' ($r.Code -eq 0) "exit $($r.Code)"
            $meta = Get-Content -LiteralPath (Join-Path $script:RunsRoot "$($st.runId)\run.json") -Raw | ConvertFrom-Json
            Check 'the run is now done' ($meta.status -eq 'done') $meta.status
            Check '-Resume removed the folder the reboot emptied' (-not (Test-Path $folder))
            $r = Invoke-Engine @('-Restore', $st.runId, '-Force', '-Quiet')
            Check 'restore after the reboot: exit 0' ($r.Code -eq 0) "exit $($r.Code)"
            Check 'restore: both files and the entry are back' ((Test-Path $locked) -and (Test-Path (Join-Path $folder 'a.txt')) -and [bool](Get-Uninstall $name))
            Remove-TestApp 'LeftoversLockedTest' $folder
        }
    }

    'filter' {
        # A fake "driver" registered as an UPPER FILTER of the keyboard class. The file is not a real
        # driver, so while it is listed the keyboard fails to start at boot: exactly what happens when a
        # tool deletes a filter driver but leaves it listed. Leftovers must remove the class entry first.
        $name = 'Leftovers Filter Test'
        $folder = 'C:\Program Files\LeftoversFilterTest'
        $svc = 'LtFilter'
        $classKey = 'HKLM:\SYSTEM\CurrentControlSet\Control\Class\{4D36E96B-E325-11CE-BFC1-08002BE10318}'
        $kbd = { @(Get-PnpDevice -PresentOnly -Class Keyboard -ErrorAction SilentlyContinue | Where-Object { $_.InstanceId -like 'VMBUS*' -or $_.InstanceId -like 'ACPI*' -or $_.InstanceId -like 'HID*' }) }
        $uppers = { @((Get-ItemProperty -LiteralPath $classKey -Name UpperFilters).UpperFilters) -join ',' }
        switch ($Phase) {
            'setup' {
                Check 'precondition: the keyboard works' (@(& $kbd | Where-Object { $_.Status -eq 'OK' }).Count -ge 1)
                New-TestApp 'LeftoversFilterTest' $name $folder @('readme.txt')
                Set-Content -LiteralPath "$folder\ltfilter.sys" -Value 'not a driver' -Encoding ASCII
                & sc.exe create $svc type= kernel start= demand binPath= "$folder\ltfilter.sys" DisplayName= 'Leftovers Filter Test' | Out-Null
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
                Check 'restore exit 0' ($r.Code -eq 0) "exit $($r.Code)"
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

    'credprov' {
        # A credential provider whose DLL can't load, with the built-in password sign-in turned OFF: the
        # machine nobody can sign in to. Leftovers must turn the password sign-in back on BEFORE it removes
        # the provider. The host tries a real sign-in (keyboard over Hyper-V) after each reboot.
        $name = 'Leftovers Credential Test'
        $folder = 'C:\Program Files\LeftoversCredTest'
        $clsid = '{6A1E5D3C-7B2F-4E8A-9C0D-1F2E3D4C5B6A}'
        $pw = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\Credential Providers\{60b78e88-EAD8-445C-9CFD-0B87F74EA6CD}'
        $cp = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\Credential Providers\$clsid"
        $pwOff = { $v = Get-ItemProperty -LiteralPath $pw -ErrorAction SilentlyContinue; [bool]($v -and ($v.PSObject.Properties.Name -contains 'Disabled') -and $v.Disabled -eq 1) }
        switch ($Phase) {
            'setup' {
                New-TestApp 'LeftoversCredTest' $name $folder @('readme.txt')
                Set-Content -LiteralPath "$folder\ltcred.dll" -Value 'not a dll' -Encoding ASCII
                New-Item -Path "HKLM:\SOFTWARE\Classes\CLSID\$clsid\InprocServer32" -Force | Out-Null
                Set-ItemProperty -Path "HKLM:\SOFTWARE\Classes\CLSID\$clsid" -Name '(default)' -Value 'Leftovers Credential Test'
                Set-ItemProperty -Path "HKLM:\SOFTWARE\Classes\CLSID\$clsid\InprocServer32" -Name '(default)' -Value "$folder\ltcred.dll"
                Set-ItemProperty -Path "HKLM:\SOFTWARE\Classes\CLSID\$clsid\InprocServer32" -Name 'ThreadingModel' -Value 'Apartment'
                New-Item -Path $cp -Force | Out-Null
                Set-ItemProperty -Path $cp -Name '(default)' -Value 'Leftovers Credential Test'
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
