# Unit tests for Kill It With Fire's pure helpers, plus one read-only check against the real registry.
# No Pester dependency (Windows ships Pester 3.4, CI can use anything): runs on Windows PowerShell 5.1
# and PowerShell 7. Exit code 0 = all passed.
#   powershell -NoProfile -File tests\Run-Tests.ps1
#   pwsh -NoProfile -File tests\Run-Tests.ps1
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot '..\KillItWithFire.ps1') -LibraryOnly

$script:pass = 0
$script:fail = 0
function Assert-Equal {
    param($Expected, $Actual, [string] $Name)
    $ok = if ($Expected -is [bool] -or $Actual -is [bool]) { ([bool]$Expected -eq [bool]$Actual) } else { ("$Expected" -ceq "$Actual") }
    if ($ok) { $script:pass++ } else { $script:fail++; Write-Host "FAIL  $Name`n      expected: [$Expected]`n      actual:   [$Actual]" }
}

# ---- packed GUIDs (Windows Installer registry key names)
Assert-Equal '96F071321C0420724290000010000000' (ConvertTo-PackedGuid '{23170F69-40C1-2702-2409-000001000000}') 'pack 7-Zip ProductCode'
Assert-Equal '{23170F69-40C1-2702-2409-000001000000}' (ConvertFrom-PackedGuid '96F071321C0420724290000010000000') 'unpack 7-Zip ProductCode'
foreach ($g in @('{00000000-0000-0000-0000-000000000000}', '{FFFFFFFF-1234-ABCD-EF01-23456789ABCD}', '{AC76BA86-7AD7-1033-7B44-AC0F074E4100}')) {
    Assert-Equal $g (ConvertFrom-PackedGuid (ConvertTo-PackedGuid $g)) "round trip $g"
}
Assert-Equal '{AC76BA86-7AD7-1033-7B44-AC0F074E4100}' (ConvertFrom-PackedGuid (ConvertTo-PackedGuid 'ac76ba86-7ad7-1033-7b44-ac0f074e4100')) 'lowercase, no braces'
Assert-Equal $null (ConvertFrom-PackedGuid 'not-a-guid') 'unpack garbage = null'

# ---- paths
Assert-Equal 'C:\Program Files\App' (Get-NormalizedPath 'C:\Program Files\App\') 'trailing slash dropped'
Assert-Equal 'C:\x\y.exe' (Get-NormalizedPath '"C:\x\y.exe"') 'quotes dropped'
Assert-Equal 'C:\drv\x.sys' (Get-NormalizedPath '\??\C:\drv\x.sys') 'NT \??\ prefix'
Assert-Equal "$env:SystemRoot\System32\drivers\x.sys" (Get-NormalizedPath '\SystemRoot\System32\drivers\x.sys') '\SystemRoot prefix'
Assert-Equal "$env:ProgramFiles\App" (Get-NormalizedPath '%ProgramFiles%\App') 'env var expanded'
Assert-Equal $null (Get-NormalizedPath 'relative\path') 'relative = null'
Assert-Equal $null (Get-NormalizedPath '') 'empty = null'
Assert-Equal 'C:\' (Get-NormalizedPath 'C:\') 'drive root kept'

Assert-Equal $true (Test-PathUnder 'C:\App\sub\x.dll' 'C:\App') 'under'
Assert-Equal $true (Test-PathUnder 'c:\app' 'C:\App\') 'equal, case and slash insensitive'
Assert-Equal $false (Test-PathUnder 'C:\App2\x.dll' 'C:\App') 'sibling with a longer name is NOT under'
Assert-Equal $false (Test-PathUnder 'C:\Apple' 'C:\App') 'prefix without a boundary is NOT under'
Assert-Equal $true (Test-PathUnder 'D:\x' 'D:\') 'drive root as root'
Assert-Equal $false (Test-PathUnder $null 'C:\App') 'null path'

$roots = @('C:\Program Files\App')
Assert-Equal $true (Test-TextReferencesPath '"C:\Program Files\App\app.exe" -x' $roots) 'quoted command'
Assert-Equal $true (Test-TextReferencesPath 'C:\Program Files\App\app.exe /s' $roots) 'unquoted command with spaces'
Assert-Equal $true (Test-TextReferencesPath 'rundll32.exe C:\Program Files\App\x.dll,Run' $roots) 'path in the arguments'
Assert-Equal $false (Test-TextReferencesPath 'C:\Program Files\App2\a.exe' $roots) 'longer sibling folder'
Assert-Equal $false (Test-TextReferencesPath 'C:\Program Files\Apple\a.exe' $roots) 'prefix without a boundary'
Assert-Equal $true (Test-TextReferencesPath 'C:\Program Files\App' $roots) 'the folder itself'
Assert-Equal $true (Test-TextReferencesPath '%ProgramFiles%\App\a.exe' @("$env:ProgramFiles\App")) 'env var in the text'
Assert-Equal $false (Test-TextReferencesPath 'D:\Other\C:\Program Files\App' $roots) 'embedded after a backslash does not count'
# A space does not end a path: Bonjour must not claim "Bonjour Print Services" (review 2026-09-26).
Assert-Equal $false (Test-TextReferencesPath 'C:\Program Files\Bonjour Print Services\x.exe' @('C:\Program Files\Bonjour')) 'Bonjour is not Bonjour Print Services'
Assert-Equal $true (Test-TextReferencesPath '"C:\Program Files\Bonjour" -x' @('C:\Program Files\Bonjour')) 'quoted folder then an argument'

Assert-Equal 'C:\Program Files\App\app.exe' (Get-CommandExePath '"C:\Program Files\App\app.exe" /uninstall') 'exe from quoted command'
Assert-Equal 'C:\Program Files\App\app.exe' (Get-CommandExePath 'C:\Program Files\App\app.exe /S') 'exe from unquoted command with spaces'
Assert-Equal $null (Get-CommandExePath 'MsiExec.exe /X{23170F69-40C1-2702-2409-000001000000}') 'bare msiexec = no folder'
Assert-Equal "$env:SystemRoot\System32\drivers\x.sys" (Resolve-ServiceImagePath '\SystemRoot\System32\drivers\x.sys' 'x' 1) 'driver \SystemRoot path'
Assert-Equal "$env:SystemRoot\system32\DRIVERS\y.sys" (Resolve-ServiceImagePath 'system32\DRIVERS\y.sys' 'y' 1) 'driver relative System32 path'
Assert-Equal "$env:SystemRoot\System32\drivers\z.sys" (Resolve-ServiceImagePath '' 'z' 1) 'driver with no ImagePath'
Assert-Equal 'C:\Program Files\App\svc.exe' (Resolve-ServiceImagePath '"C:\Program Files\App\svc.exe" -k' 'svc' 16) 'service with arguments'

# ---- MSI key paths
$k = ConvertFrom-MsiKeyPath '02:\SOFTWARE\Vendor\Product\Value'
Assert-Equal 'Registry|HKLM|False|SOFTWARE\Vendor\Product\Value' "$($k.Kind)|$($k.Hive)|$($k.Is64)|$($k.Path)" 'registry key path, 32-bit view'
$k = ConvertFrom-MsiKeyPath '22:\SOFTWARE\Vendor'
Assert-Equal 'Registry|HKLM|True' "$($k.Kind)|$($k.Hive)|$($k.Is64)" 'registry key path, 64-bit view'
$k = ConvertFrom-MsiKeyPath '01:\Software\Vendor'
Assert-Equal 'HKCU' $k.Hive 'HKCU key path'
$k = ConvertFrom-MsiKeyPath 'C:\Program Files\App\a.dll'
Assert-Equal 'File|C:\Program Files\App\a.dll|False' "$($k.Kind)|$($k.Path)|$($k.IsFolder)" 'file key path'
$k = ConvertFrom-MsiKeyPath 'C:\Program Files\App\'
Assert-Equal 'File|C:\Program Files\App|True' "$($k.Kind)|$($k.Path)|$($k.IsFolder)" 'folder key path'
$k = ConvertFrom-MsiKeyPath 'C?\Program Files\App\a.dll'
Assert-Equal 'C:\Program Files\App\a.dll' $k.Path 'run-from-source marker'
Assert-Equal $null (ConvertFrom-MsiKeyPath '') 'empty key path'

# ---- keywords
Assert-Equal $false (Test-WholeWord 'ZoomIt' 'Zoom') 'Zoom is not ZoomIt'
Assert-Equal $true (Test-WholeWord 'Zoom Workplace' 'Zoom') 'Zoom Workplace'
Assert-Equal $false (Test-WholeWord 'JavaScript' 'Java') 'Java is not JavaScript'
Assert-Equal $true (Test-WholeWord 'Oracle Java 8 Update 401' 'Java') 'Java in a name'
Assert-Equal $true (Test-WholeWord '7-Zip 24.09 (x64 edition)' '7-Zip') 'hyphenated name'
Assert-Equal $true (Test-WholeWord 'Notepad++ (64-bit x64)' 'Notepad++') 'plus signs'
Assert-Equal $true (Test-WholeWord 'IMPRIVATA onesign' 'Imprivata') 'case-insensitive'
Assert-Equal '7-Zip,Igor,Pavlov' ((Get-KeywordCandidates '7-Zip 24.09 (x64 edition)' 'Igor Pavlov') -join ',') 'candidates: version and arch dropped'
Assert-Equal 'Imprivata,OneSign' ((Get-KeywordCandidates 'Imprivata OneSign Agent' 'Imprivata, Inc.') -join ',') 'candidates: generic words dropped, deduped'
Assert-Equal 'Chrome' ((Get-KeywordCandidates 'Google Chrome' 'Google LLC') -join ',') 'candidates: a mega-vendor name is never a keyword'
Assert-Equal 'Imprivata,OneSign,Tatham' ((Get-KeywordCandidates 'Imprivata OneSign' 'Tatham Ltd') -join ',') 'candidates: name words first, then publisher'
foreach ($w in @('Intune', 'Microsoft', 'windows', 'Defender', 'OneDrive', 'Office', 'Adobe', 'Java', 'agent', '')) {
    Assert-Equal $true (Test-BlockedKeyword $w) "blocked keyword '$w'"
}
Assert-Equal $false (Test-BlockedKeyword 'Imprivata') 'Imprivata is a fine keyword'
Assert-Equal '' ((Get-KeywordCandidates 'App 2' 'Co') -join ',') 'nothing distinctive'
Assert-Equal 'Notepad++' ((Get-KeywordCandidates 'Notepad++ (64-bit x64)' '') -join ',') 'Notepad++ keeps its plus signs (not "Notepad")'
Assert-Equal $false (Test-WholeWord 'Notepad' 'Notepad++') 'keyword Notepad++ does not match Windows Notepad'

# ---- protected folders
$containers = @($env:ProgramFiles, ${env:ProgramFiles(x86)}, $env:ProgramData)
$trees = @($env:SystemRoot)
Assert-Equal $true ([bool](Get-ProtectedPathReason $env:ProgramFiles $containers $trees)) 'Program Files itself is protected'
Assert-Equal $true ([bool](Get-ProtectedPathReason "$env:SystemRoot\System32\x" $containers $trees)) 'anything under Windows'
Assert-Equal $true ([bool](Get-ProtectedPathReason 'C:\Tools' $containers $trees)) 'one folder deep is too shallow'
Assert-Equal $false ([bool](Get-ProtectedPathReason "$env:ProgramFiles\Vendor\App" $containers $trees)) 'a vendor app folder is fine'
Assert-Equal $true ([bool](Get-ProtectedPathReason "$env:ProgramFiles\Microsoft Office" $containers $trees)) 'Microsoft folder in Program Files'
if (${env:ProgramFiles(x86)}) {
    Assert-Equal $true ([bool](Get-ProtectedPathReason "${env:ProgramFiles(x86)}\Microsoft Intune Management Extension" $containers $trees)) 'Intune Management Extension'
}
Assert-Equal $true ([bool](Get-ProtectedPathReason '\\server\share\x\y' $containers $trees)) 'network path'
Assert-Equal $true ([bool](Get-ProtectedPathReason "$env:ProgramFiles\dotnet" $containers $trees)) 'dotnet'

# ---- signer subjects
Assert-Equal 'Vitko Software, LLC' (Get-SignerOrg 'CN="Vitko Software, LLC", O="Vitko Software, LLC", L=Chino, S=California, C=US') 'quoted O with a comma'
Assert-Equal 'Igor Pavlov' (Get-SignerOrg 'CN=Igor Pavlov, O=Igor Pavlov, L=Moscow, C=RU') 'plain O'
Assert-Equal 'Some Dev' (Get-SignerOrg 'CN=Some Dev') 'CN when there is no O'
Assert-Equal $true (Test-IsMicrosoftName 'Microsoft Corporation') 'Microsoft'
Assert-Equal $false (Test-IsMicrosoftName 'Microsofty Ltd') 'Microsofty is not Microsoft'

# ---- user-data tagging (temp fixture, removed afterwards)
$tmp = Join-Path ([System.IO.Path]::GetTempPath()) ('killitwithfire-test-' + [guid]::NewGuid().ToString('N'))
try {
    New-Item -ItemType Directory -Path (Join-Path $tmp 'cache') -Force | Out-Null
    Set-Content -LiteralPath (Join-Path $tmp 'cache\blob.bin') -Value 'x'
    $t = Get-UserDataTag $tmp
    Assert-Equal $false $t.HighRisk 'cache-only folder is not high risk'
    Set-Content -LiteralPath (Join-Path $tmp 'Quarterly numbers.xlsx') -Value 'x'
    $t = Get-UserDataTag $tmp
    Assert-Equal $true $t.HighRisk 'a spreadsheet makes it high risk'
    Assert-Equal 1 $t.DocLike 'one document-like file counted'
    $t = Get-UserDataTag $tmp -SizeThresholdBytes 1
    Assert-Equal $true ($t.Reason -like '*MB*') 'size threshold reported'
} finally {
    Remove-Item -LiteralPath $tmp -Recurse -Force -ErrorAction SilentlyContinue
}

# ---- protected folders added by the 2026-09-26 review
$trees2 = @($env:SystemRoot, $env:PUBLIC, 'C:\Users\u\OneDrive - Contoso', 'C:\Users\u\AppData\Roaming\Microsoft')
$containers2 = @($env:ProgramFiles, $env:ProgramData, (Join-Path $env:ProgramData 'Package Cache'), 'C:\Users\u')
Assert-Equal $true ([bool](Get-ProtectedPathReason "$env:PUBLIC\Documents\Vendor" $containers2 $trees2)) 'Public tree'
Assert-Equal $true ([bool](Get-ProtectedPathReason 'C:\Users\u\OneDrive - Contoso\Vendor' $containers2 $trees2)) 'OneDrive tree'
Assert-Equal $true ([bool](Get-ProtectedPathReason 'C:\Users\u\AppData\Roaming\Microsoft\Vendor' $containers2 $trees2)) 'AppData\Roaming\Microsoft tree'
Assert-Equal $true ([bool](Get-ProtectedPathReason "$env:ProgramFiles\Microsoft Office\root\Office16\Library" $containers2 $trees2)) 'Microsoft folder at ANY depth'
Assert-Equal $true ([bool](Get-ProtectedPathReason "$env:CommonProgramFiles\microsoft shared\ink" $containers2 $trees2)) 'Common Files\microsoft shared'
Assert-Equal $true ([bool](Get-ProtectedPathReason (Join-Path $env:ProgramData 'Package Cache') $containers2 $trees2)) 'Package Cache container itself'
Assert-Equal $false ([bool](Get-ProtectedPathReason (Join-Path $env:ProgramData 'Package Cache\{11111111-2222-3333-4444-555555555555}v1.0') $containers2 $trees2)) 'one product''s Package Cache folder is allowed'

# ---- refusals
Assert-Equal $true ([bool](Get-RefusalReason 'Microsoft Corporation' 'Microsoft Teams' $null)) 'Microsoft publisher'
Assert-Equal $true ([bool](Get-RefusalReason 'CrowdStrike, Inc.' 'CrowdStrike Windows Sensor' $null)) 'security vendor'
Assert-Equal $true ([bool](Get-RefusalReason '' '{DDC95F26-92B1-4546-9678-5DC68DF76BA0}' 'Sophos Limited')) 'security vendor by signer only (a -ProductCode run with no publisher)'
Assert-Equal $true ([bool](Get-RefusalReason 'Vitko Software, LLC' 'RFF Agent' $null)) 'the RFF agent'
Assert-Equal $true ([bool](Get-RefusalReason 'Contoso' 'Contoso Tool' 'Microsoft Corporation')) 'Microsoft-signed binaries'
Assert-Equal $false ([bool](Get-RefusalReason 'Simon Tatham' 'PuTTY release 0.81 (64-bit)' 'Simon Tatham')) 'PuTTY is fine'
Assert-Equal $true (Test-SameVendor 'Insecure.Com LLC' 'Insecure.Com, LLC') 'same vendor, punctuation differs'
Assert-Equal $true (Test-SameVendor 'Intel' 'Intel Corporation') 'same vendor, suffix dropped'
Assert-Equal $false (Test-SameVendor 'Contoso' 'Fabrikam') 'different vendors'

# ---- list and command-line helpers
Assert-Equal 'C:\Windows\system32\userinit.exe,' (Remove-ListEntry 'C:\Windows\system32\userinit.exe,C:\App\hook.exe,' 'C:\App\hook.exe' ',') 'Userinit: only our entry goes, the trailing comma stays'
Assert-Equal 'a,c' (Remove-ListEntry 'a,b,c' 'B' ',') 'list entry, case-insensitive'
Assert-Equal 'C:\Other\y.dll' (Remove-ListEntry 'C:\App\x.dll C:\Other\y.dll' 'c:\app\X.DLL' ' ') 'space-separated AppInit list'
Assert-Equal 'a,b' (Remove-ListEntry 'a,b' 'zzz' ',') 'entry not present: unchanged'
$sp = Split-CommandLine '"C:\Program Files\App\unins000.exe" /SILENT /NORESTART'
Assert-Equal 'C:\Program Files\App\unins000.exe|/SILENT /NORESTART' ($sp -join '|') 'split a quoted uninstall command'
$sp = Split-CommandLine 'C:\Program Files\App\uninstall.exe /S'
Assert-Equal 'C:\Program Files\App\uninstall.exe|/S' ($sp -join '|') 'split an unquoted uninstall command'
Assert-Equal ".\KillItWithFire.ps1 -ProductCode '{DDC95F26-92B1-4546-9678-5DC68DF76BA0}' -Level 3 -Exclude Drivers,Files -IncludeReview -Log '\\srv\logs\' -Force" `
    (Format-CommandLine -AppName 'x' -ProductCode '{DDC95F26-92B1-4546-9678-5DC68DF76BA0}' -Level 3 -Exclude @('Drivers', 'Files') -IncludeUserData $false -IncludeReview $true -NoBackup $false -NoLog $false -LogPath '\\srv\logs\') 'command line for the window'
Assert-Equal ".\KillItWithFire.ps1 -Name 'Bob''s App' -Level 0" (Format-CommandLine -AppName "Bob's App" -Level 0 -IncludeUserData $false -IncludeReview $false -NoBackup $false -NoLog $false) 'scan command, quote escaped, no -Force'
Assert-Equal ".\KillItWithFire.ps1 -Name 'x' -KillIt -Force" (Format-CommandLine -AppName 'x' -Level 3 -IncludeUserData $false -IncludeReview $false -NoBackup $false -NoLog $false -SkipUninstall $true) 'level 3 without the uninstaller reads as -KillIt'
Assert-Equal ".\KillItWithFire.ps1 -Name 'x' -Level 2 -SkipUninstall -Force" (Format-CommandLine -AppName 'x' -Level 2 -IncludeUserData $false -IncludeReview $false -NoBackup $false -NoLog $false -SkipUninstall $true) 'level 2 without the uninstaller stays -SkipUninstall'

# ---- -KillIt is exactly "-Level 3 -SkipUninstall", and contradicting levels are refused
$r = Resolve-RunLevel -Level 0 -KillIt $true -SkipUninstall $false
Assert-Equal '3|True' "$($r.Level)|$($r.SkipUninstall)" '-KillIt alone: level 3, no uninstaller'
$r = Resolve-RunLevel -Level 3 -KillIt $true -SkipUninstall $false
Assert-Equal '3|True' "$($r.Level)|$($r.SkipUninstall)" '-KillIt with -Level 3 is the same'
Assert-Equal $true ([bool](Resolve-RunLevel -Level 1 -KillIt $true -SkipUninstall $false).Error) '-KillIt with -Level 1 is refused'
Assert-Equal $true ([bool](Resolve-RunLevel -Level 2 -KillIt $true -SkipUninstall $false).Error) '-KillIt with -Level 2 is refused'
$r = Resolve-RunLevel -Level 2 -KillIt $false -SkipUninstall $true
Assert-Equal '2|True' "$($r.Level)|$($r.SkipUninstall)" 'without -KillIt the level and switch pass through'
# Every result carries every key: the script runs under Set-StrictMode, where reading a key a hashtable
# lacks THROWS. A success result without Error crashed every run in the first catalog pilot (2026-10-03),
# and New-UninstallCommand exists for the same reason. Checked on every shape each function returns.
foreach ($case in @(@(0, $false, $false), @(0, $true, $false), @(3, $true, $false), @(1, $true, $false))) {
    $r = Resolve-RunLevel -Level $case[0] -KillIt $case[1] -SkipUninstall $case[2]
    Assert-Equal 'Error,Level,SkipUninstall' ((@($r.Keys) | Sort-Object) -join ',') "Resolve-RunLevel $($case -join '/'): every key present"
}
Assert-Equal 'Args,Exe,Fail,How,Skip' ((@((New-UninstallCommand -Skip 'x').Keys) | Sort-Object) -join ',') 'New-UninstallCommand: every key present'

# ---- level 1: which engine built an uninstaller, and the silent command for it
$fp = Join-Path ([System.IO.Path]::GetTempPath()) ('killitwithfire-fp-' + [guid]::NewGuid().ToString('N').Substring(0, 8))
New-Item -ItemType Directory -Path $fp -Force | Out-Null
try {
    $stub = { param([string] $Name, [string] $Marker) $p = Join-Path $fp $Name; [System.IO.File]::WriteAllBytes($p, [System.Text.Encoding]::ASCII.GetBytes(('MZ' + ('.' * 200) + $Marker + ('.' * 200)))); $p }
    Assert-Equal 'Nsis' (Get-InstallerEngine (& $stub 'nsis.exe' 'NullsoftInst')) 'engine: NSIS by its overlay magic'
    Assert-Equal 'InnoSetup' (Get-InstallerEngine (& $stub 'inno.exe' 'Inno Setup Setup Data')) 'engine: Inno Setup'
    Assert-Equal 'WixBurn' (Get-InstallerEngine (& $stub 'burn.exe' '.wixburn')) 'engine: WiX Burn by its section'
    Assert-Equal 'WixBurn' (Get-InstallerEngine (& $stub 'both.exe' 'NullsoftInst.wixburn')) 'engine: markers are checked in the agent''s order (Burn first)'
    Assert-Equal 'Unknown' (Get-InstallerEngine (& $stub 'plain.exe' 'nothing to see')) 'engine: no marker is Unknown'
    [System.IO.File]::WriteAllBytes((Join-Path $fp 'tiny.exe'), [byte[]](1, 2, 3))
    Assert-Equal 'Unknown' (Get-InstallerEngine (Join-Path $fp 'tiny.exe')) 'engine: a file under 64 bytes is Unknown'
    Assert-Equal 'Unknown' (Get-InstallerEngine (Join-Path $fp 'missing.exe')) 'engine: a missing file is Unknown, not an error'

    $t = { param([hashtable] $h) $o = [ordered]@{ displayName = 'Some App'; isMsi = $false; productCode = $null; uninstallString = $null; quietUninstallString = $null; installLocation = $null; entrySid = $null }; foreach ($k in $h.Keys) { $o[$k] = $h[$k] }; [pscustomobject]$o }
    $c = Get-UninstallCommand (& $t @{ isMsi = $true; productCode = '{DDC95F26-92B1-4546-9678-5DC68DF76BA0}' })
    Assert-Equal '/x {DDC95F26-92B1-4546-9678-5DC68DF76BA0} /qn /norestart' $c.Args 'MSI: msiexec /x, quiet'
    $c = Get-UninstallCommand (& $t @{ uninstallString = 'MsiExec.exe /I{DDC95F26-92B1-4546-9678-5DC68DF76BA0}' })
    Assert-Equal '/x {DDC95F26-92B1-4546-9678-5DC68DF76BA0} /qn /norestart' $c.Args 'an msiexec /I uninstall string is removed as an MSI'
    $nsis = & $stub 'uninst.exe' 'NullsoftInst'
    $c = Get-UninstallCommand (& $t @{ uninstallString = "`"$nsis`"" })
    Assert-Equal "/S _?=$fp" $c.Args 'NSIS: /S, run in place from its own folder, _?= last and unquoted'
    $other = Join-Path $fp 'installdir'; New-Item -ItemType Directory -Path $other -Force | Out-Null
    $c = Get-UninstallCommand (& $t @{ uninstallString = "`"$nsis`""; installLocation = "$other\" })
    Assert-Equal "/S _?=$other" $c.Args 'NSIS: InstallLocation wins for _?= (trailing slash dropped)'
    $c = Get-UninstallCommand (& $t @{ quietUninstallString = "`"$nsis`" /S" })
    Assert-Equal "/S _?=$fp" $c.Args 'NSIS from the QuietUninstallString: /S kept once, _?= added'
    $c = Get-UninstallCommand (& $t @{ uninstallString = "`"$nsis`" /s" })
    Assert-Equal "/s /S _?=$fp" $c.Args 'NSIS: a lowercase /s is not NSIS''s switch, so /S is added'
    $innoByName = & $stub 'unins000.exe' 'nothing'
    $c = Get-UninstallCommand (& $t @{ uninstallString = "`"$innoByName`"" })
    Assert-Equal '/VERYSILENT /SUPPRESSMSGBOXES /NORESTART' $c.Args 'Inno: unins000.exe gets its silent switches by name'
    # TreeSize Free registers QuietUninstallString "unins000.exe /SILENT", which still asks Yes/No (even with
    # /SUPPRESSMSGBOXES): it sat ten minutes on an invisible prompt (lab sweep, 2026-10-03).
    $inno = & $stub 'unins001.exe' 'Inno Setup Setup Data'
    $c = Get-UninstallCommand (& $t @{ quietUninstallString = "`"$inno`" /SILENT"; uninstallString = "`"$inno`"" })
    Assert-Equal '/VERYSILENT /SUPPRESSMSGBOXES /NORESTART' $c.Args 'Inno quiet string of just /SILENT: made fully silent, and no surprise restart'
    $c = Get-UninstallCommand (& $t @{ quietUninstallString = "`"$inno`" /SILENT /SUPPRESSMSGBOXES /LOG" })
    Assert-Equal '/VERYSILENT /SUPPRESSMSGBOXES /LOG /NORESTART' $c.Args 'Inno: /SILENT upgraded in place, the vendor''s other switches kept'
    $c = Get-UninstallCommand (& $t @{ quietUninstallString = "`"$inno`" /VERYSILENT /SUPPRESSMSGBOXES" })
    Assert-Equal '/VERYSILENT /SUPPRESSMSGBOXES /NORESTART' $c.Args 'Inno: /NORESTART comes with suppressed message boxes (their restart default is Yes)'
    $c = Get-UninstallCommand (& $t @{ quietUninstallString = "`"$inno`" /VERYSILENT /SUPPRESSMSGBOXES /NORESTART" })
    Assert-Equal '/VERYSILENT /SUPPRESSMSGBOXES /NORESTART' $c.Args 'Inno: a complete quiet string runs as the vendor wrote it'
    $c = Get-UninstallCommand (& $t @{ uninstallString = "`"$inno`" /silent" })
    Assert-Equal '/VERYSILENT /SUPPRESSMSGBOXES /NORESTART' $c.Args 'Inno UninstallString carrying /silent: completed and run, not skipped'
    $innoAnyName = & $stub 'uninstall-app.exe' 'Inno Setup Setup Data'
    $c = Get-UninstallCommand (& $t @{ quietUninstallString = "`"$innoAnyName`" /SILENT" })
    Assert-Equal '/VERYSILENT /SUPPRESSMSGBOXES /NORESTART' $c.Args 'Inno by its marker, whatever the file is called'
    $burn = & $stub 'setup.exe' '.wixburn'
    $c = Get-UninstallCommand (& $t @{ uninstallString = "`"$burn`" /uninstall" })
    Assert-Equal '/uninstall /quiet /norestart' $c.Args 'Burn: a bare /uninstall is completed with /quiet'
    $c = Get-UninstallCommand (& $t @{ quietUninstallString = "`"$burn`" /uninstall /quiet"; uninstallString = "`"$burn`" /uninstall" })
    Assert-Equal '/uninstall /quiet' $c.Args 'a non-NSIS QuietUninstallString runs exactly as the vendor wrote it'
    $plain = & $stub 'remove.exe' 'nothing'
    $c = Get-UninstallCommand (& $t @{ uninstallString = "`"$plain`" /remove" })
    Assert-Equal $true ([bool]$c.Skip -and -not $c.Exe) 'unknown engine with switches: skipped, never run (it would wait for a click)'
    $c = Get-UninstallCommand (& $t @{ quietUninstallString = "`"$plain`" /SILENT" })
    Assert-Equal '/SILENT' $c.Args 'Inno''s switches are never added to an uninstaller that is not Inno'
    $c = Get-UninstallCommand (& $t @{ uninstallString = "`"$(Join-Path $fp 'gone.exe')`"" })
    Assert-Equal $true ([bool]$c.Fail -and -not $c.Exe) 'a deleted uninstaller fails without running anything'
    $c = Get-UninstallCommand (& $t @{ uninstallString = "`"$nsis`""; entrySid = 'S-1-5-21-1-2-3-9999' })
    Assert-Equal $true ([bool]$c.Skip -and $c.Skip -like '*per-user*') 'another user''s per-user entry: its uninstaller is not run as us'
    # The agent's per-product rules, checked before the engine markers, on an UninstallString only.
    $any = & $stub 'AnyDesk.exe' 'nothing'
    $c = Get-UninstallCommand (& $t @{ displayName = 'AnyDesk'; uninstallString = "`"$any`" --uninstall" })
    Assert-Equal '--silent --remove' $c.Args 'named rule: AnyDesk is replaced (its --uninstall prompts)'
    $ctx = & $stub 'bootstrapperhelper.exe' 'nothing'
    $c = Get-UninstallCommand (& $t @{ displayName = 'Citrix Workspace 2409'; uninstallString = "`"$ctx`" /uninstall /cleanup" })
    Assert-Equal '/silent /uninstall /cleanup' $c.Args 'named rule: Citrix gets /silent first'
    $gd = & $stub 'uninstall.exe' 'nothing'
    $c = Get-UninstallCommand (& $t @{ displayName = 'Google Drive'; uninstallString = "`"$gd`"" })
    Assert-Equal '--silent --force_stop' $c.Args 'named rule: Google Drive (a bare uninstall exits 0 while it runs)'
    $sq = & $stub 'Update.exe' 'nothing'
    $c = Get-UninstallCommand (& $t @{ displayName = 'Discord'; uninstallString = "`"$sq`" --uninstall" })
    Assert-Equal '--uninstall -s' $c.Args 'Squirrel: Update.exe --uninstall gets -s'
    $c = Get-UninstallCommand (& $t @{ displayName = 'AnyDesk'; quietUninstallString = "`"$any`" --remove --silent"; uninstallString = "`"$any`" --uninstall" })
    Assert-Equal '--remove --silent' $c.Args 'a vendor QuietUninstallString wins over a named rule'
    $me = [Security.Principal.WindowsIdentity]::GetCurrent().User.Value
    $c = Get-UninstallCommand (& $t @{ uninstallString = "`"$nsis`""; entrySid = $me })
    Assert-Equal "/S _?=$fp" $c.Args 'our own per-user entry: its uninstaller runs'
} finally { Remove-Item -LiteralPath $fp -Recurse -Force -ErrorAction SilentlyContinue }

# ---- level 1's wait: real processes. A prompt nobody can answer is found and stopped early; a clean exit
# returns at once; a child that outlives its parent is waited for; the ceiling stops the whole tree.
Assert-Equal $false (Test-PromptUnseen -Visible $true -Interactive $true -Session 1) 'prompt on screen in a signed-in session: someone can answer it'
Assert-Equal $true (Test-PromptUnseen -Visible $false -Interactive $true -Session 1) 'prompt off screen: nobody can answer it'
Assert-Equal $true (Test-PromptUnseen -Visible $true -Interactive $false -Session 1) 'not interactive: nobody can answer it'
Assert-Equal $true (Test-PromptUnseen -Visible $true -Interactive $true -Session 0) 'session 0 (RMM, SYSTEM): nobody can answer it'
$hostExe = Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'
$unseen = { param($v) $true }
# The prompt is a real dialog-class (#32770) window with Static text and Yes/No buttons, built WITHOUT
# WS_VISIBLE. NOT a MessageBox: one from a hidden-started process still shows on the desktop of whoever
# runs these tests (checked 2026-10-03, it popped up on the dev machine).
$box = @'
Add-Type -Namespace T -Name U -MemberDefinition '[DllImport("user32.dll", CharSet = CharSet.Unicode)] public static extern IntPtr CreateWindowExW(int ex, string cls, string name, int style, int x, int y, int w, int h, IntPtr parent, IntPtr menu, IntPtr inst, IntPtr param);'
$z = [IntPtr]::Zero
$d = [T.U]::CreateWindowExW(0, '#32770', 'Uninstall', 0x00C00000, 0, 0, 300, 200, $z, $z, $z, $z)
[void][T.U]::CreateWindowExW(0, 'Static', 'Would you like your application settings to be deleted too?', 0x40000000, 10, 10, 280, 20, $d, $z, $z, $z)
[void][T.U]::CreateWindowExW(0, 'Button', '&Yes', 0x40000000, 10, 40, 80, 24, $d, $z, $z, $z)
[void][T.U]::CreateWindowExW(0, 'Button', '&No', 0x40000000, 100, 40, 80, 24, $d, $z, $z, $z)
Start-Sleep -Seconds 120
'@
$p = Start-Process -FilePath $hostExe -ArgumentList @('-NoProfile', '-EncodedCommand', [Convert]::ToBase64String([System.Text.Encoding]::Unicode.GetBytes($box))) -PassThru -WindowStyle Hidden
$null = $p.Handle
$t0 = Get-Date
$w = Wait-Uninstaller -Process $p -Target $null -CeilingSec 90 -IdleSec 3 -PollSec 1 -IsUnseen $unseen
Assert-Equal $true ([string]$w.Stopped -like '*prompt nobody can answer: Uninstall: Would you like your application settings to be deleted too? `[Yes/No`]*') "level 1: an unanswerable Yes/No is found, with its text ($($w.Stopped))"
Assert-Equal $true (((Get-Date) - $t0).TotalSeconds -lt 60) 'level 1: ... and stopped well before the ceiling'
Assert-Equal $true ($p.WaitForExit(5000)) 'level 1: ... and the prompting process is gone'
$p = Start-Process -FilePath "$env:SystemRoot\System32\cmd.exe" -ArgumentList '/d /c exit 0' -PassThru -WindowStyle Hidden
$null = $p.Handle
$t0 = Get-Date
$w = Wait-Uninstaller -Process $p -Target $null -CeilingSec 60 -IdleSec 3 -PollSec 1 -IsUnseen $unseen
Assert-Equal $true ($null -eq $w.Stopped -and $null -eq $w.Note -and ((Get-Date) - $t0).TotalSeconds -lt 10) 'level 1: a clean exit with nothing left running returns at once'
$p = Start-Process -FilePath "$env:SystemRoot\System32\cmd.exe" -ArgumentList '/d /c exit 1603' -PassThru -WindowStyle Hidden
$null = $p.Handle
$w = Wait-Uninstaller -Process $p -Target $null -CeilingSec 60 -IdleSec 3 -PollSec 1 -IsUnseen $unseen
Assert-Equal $true ($null -eq $w.Stopped -and $p.ExitCode -eq 1603) 'level 1: a failed uninstaller returns its own code, not a stop'
# A copy that does the work after its parent exits (Inno's second phase, NSIS's Au_.exe).
$p = Start-Process -FilePath "$env:SystemRoot\System32\cmd.exe" -ArgumentList "/d /c start `"`" /b `"$hostExe`" -NoProfile -Command Start-Sleep 5" -PassThru -WindowStyle Hidden
$null = $p.Handle
$t0 = Get-Date
$w = Wait-Uninstaller -Process $p -Target $null -CeilingSec 60 -IdleSec 30 -PollSec 1 -IsUnseen $unseen
$took = ((Get-Date) - $t0).TotalSeconds
Assert-Equal $true ($null -eq $w.Stopped -and $took -ge 3.5 -and $took -lt 15) "level 1: a child that outlives the uninstaller is waited for ($([int]$took) s)"
$p = Start-Process -FilePath $hostExe -ArgumentList @('-NoProfile', '-Command', 'Start-Sleep 60') -PassThru -WindowStyle Hidden
$null = $p.Handle
$w = Wait-Uninstaller -Process $p -Target $null -CeilingSec 4 -IdleSec 30 -PollSec 1 -IsUnseen $unseen
Assert-Equal $true ([string]$w.Stopped -like 'timed out after 4 s*') "level 1: the ceiling stops it ($($w.Stopped))"
Assert-Equal $true ($p.WaitForExit(5000)) 'level 1: ... and the timed-out process is gone'

# ---- the window's app list (2026-10-04): install date, size, spelled-out scope, and sorting by any column
Assert-Equal '2026-02-12' ((ConvertFrom-InstallDate '20260212').ToString('yyyy-MM-dd')) 'install date: yyyyMMdd'
Assert-Equal '2025-07-04' ((ConvertFrom-InstallDate '7/4/2025').ToString('yyyy-MM-dd')) 'install date: M/d/yyyy'
Assert-Equal $null (ConvertFrom-InstallDate '19800101') 'install date: implausibly old is no date'
Assert-Equal $null (ConvertFrom-InstallDate 'yesterday') 'install date: unreadable is no date'
Assert-Equal '' (Format-AppSize $null) 'size: unknown is blank'
Assert-Equal '850 KB' (Format-AppSize 850) 'size: KB'
Assert-Equal ('{0:N1} MB' -f 1.5) (Format-AppSize 1536) 'size: small MB keeps a decimal'
Assert-Equal '188 MB' (Format-AppSize 192868) 'size: MB'
Assert-Equal ('{0:N1} GB' -f 2) (Format-AppSize (2 * 1024 * 1024)) 'size: GB'
Assert-Equal $true ((ConvertTo-VersionSortKey '10.2') -gt (ConvertTo-VersionSortKey '9.12')) 'version sort: 10.2 after 9.12 (numbers, not text)'
Assert-Equal 'Machine 32-bit' (Get-EntryScopeLabel ([pscustomobject]@{ Hive = 'HKLM32'; Sid = $null })) 'scope: 32-bit view'
Assert-Equal $(if ([Environment]::Is64BitOperatingSystem) { 'Machine 64-bit' } else { 'Machine' }) (Get-EntryScopeLabel ([pscustomobject]@{ Hive = 'HKLM64'; Sid = $null })) 'scope: 64-bit view is said, not just "machine"'
Assert-Equal $true ((Get-EntryScopeLabel ([pscustomobject]@{ Hive = 'HKU'; Sid = 'S-1-5-18' })) -like 'User (*)') 'scope: a user entry names its user'
$apps = @(
    [pscustomobject]@{ DisplayName = 'Bravo'; DisplayVersion = '9.12'; Publisher = 'B'; IsMsi = $true; Hive = 'HKLM64'; Sid = $null; InstallDate = [datetime]'2026-01-05'; SizeKB = 900 },
    [pscustomobject]@{ DisplayName = 'alpha'; DisplayVersion = '10.2'; Publisher = 'A'; IsMsi = $false; Hive = 'HKLM32'; Sid = $null; InstallDate = $null; SizeKB = 120000 },
    [pscustomobject]@{ DisplayName = 'Charlie'; DisplayVersion = ''; Publisher = 'C'; IsMsi = $false; Hive = 'HKLM64'; Sid = $null; InstallDate = [datetime]'2025-03-01'; SizeKB = $null })
Assert-Equal 'alpha,Bravo,Charlie' ((Select-AppListRows $apps '' 0 $false | ForEach-Object { $_.DisplayName }) -join ',') 'list: by name, case-insensitive'
Assert-Equal 'alpha,Bravo,Charlie' ((Select-AppListRows $apps '' 6 $true | ForEach-Object { $_.DisplayName }) -join ',') 'list: by size, biggest first, as numbers; no size goes last'
Assert-Equal 'Bravo,alpha,Charlie' ((Select-AppListRows $apps '' 6 $false | ForEach-Object { $_.DisplayName }) -join ',') 'list: by size, smallest first; no size STILL last'
Assert-Equal 'Bravo,Charlie,alpha' ((Select-AppListRows $apps '' 5 $true | ForEach-Object { $_.DisplayName }) -join ',') 'list: by date, newest first; no date last'
Assert-Equal 'Bravo,alpha,Charlie' ((Select-AppListRows $apps '' 1 $false | ForEach-Object { $_.DisplayName }) -join ',') 'list: by version, part by part; no version last'
Assert-Equal 'Charlie' ((Select-AppListRows $apps 'c' 0 $false | ForEach-Object { $_.DisplayName }) -join ',') 'list: the filter matches name or publisher'
# The list itself, filled into a real ListView that is never shown.
Add-Type -AssemblyName System.Windows.Forms, System.Drawing
$lv = New-Object System.Windows.Forms.ListView
foreach ($c in @('Name', 'Version', 'Publisher', 'Type', 'Scope', 'Installed', 'Size')) { [void]$lv.Columns.Add($c, 60) }
$fx = @($apps | ForEach-Object { $_ | Add-Member -NotePropertyName KeyPath -NotePropertyValue "k\$($_.DisplayName)" -PassThru | Add-Member -NotePropertyName InstallDateFromKey -NotePropertyValue ($_.DisplayName -eq 'Charlie') -PassThru })
$lui = @{ Apps = $lv; Search = (New-Object System.Windows.Forms.TextBox); SortColumn = 6; SortDesc = $true; AppColumns = @('Name', 'Version', 'Publisher', 'Type', 'Scope', 'Installed', 'Size'); App = $null; Filling = $false }
Update-AppList $lui $fx
Assert-Equal 'alpha,Bravo,Charlie' ((@($lv.Items) | ForEach-Object { $_.Text }) -join ',') 'window list: sorted by size, biggest first'
Assert-Equal ("{0}|{1}|" -f (Format-AppSize 120000), (Format-AppSize 900)) ((@($lv.Items) | ForEach-Object { $_.SubItems[6].Text }) -join '|') 'window list: the Size column'
Assert-Equal ('Size ' + [char]0x25BC) $lv.Columns[6].Text 'window list: the sorted column shows its direction'
Assert-Equal 'Name' $lv.Columns[0].Text 'window list: the other headers stay plain'
Assert-Equal '2025-03-01' $lv.Items[2].SubItems[5].Text 'window list: the Installed column'
Assert-Equal $true ($lv.Items[2].ToolTipText -like 'Grey date*') 'window list: a date from the key is marked as such'
$lui.App = $fx[1]   # alpha selected, then the list re-sorted by name
$lui.SortColumn = 0; $lui.SortDesc = $false
Update-AppList $lui $fx
# (Items' own Selected flag: SelectedItems stays empty on a ListView that never got a window handle.)
Assert-Equal 'alpha' ((@($lv.Items) | Where-Object { $_.Selected } | ForEach-Object { $_.Text }) -join ',') 'window list: re-sorting keeps the selected app selected'
Assert-Equal $false $lui.Filling 'window list: the selection handler is live again afterwards'
$lv.Dispose()
Assert-Equal 'C:\a' (Get-ParentPath 'C:\a\b') 'parent path'
Assert-Equal 'C:\' (Get-ParentPath 'C:\a') 'parent of a top folder is the drive'
Assert-Equal $null (Get-ParentPath 'C:\') 'the drive has no parent'
Assert-Equal 2 (Get-PathDepth 'C:\a\b') 'path depth'
Assert-Equal (Get-NormalizedPath '%ProgramFiles%\App\') (Get-NormalizedPath '%ProgramFiles%\App\') 'normalized path: the remembered answer is the same answer'
$hp = Join-Path ([System.IO.Path]::GetTempPath()) ('killitwithfire-hp-' + [guid]::NewGuid().ToString('N').Substring(0, 8))
try {
    New-Item -ItemType Directory -Path (Join-Path $hp 'data\logs'), (Join-Path $hp 'prog\bin') -Force | Out-Null
    Set-Content -LiteralPath (Join-Path $hp 'data\logs\today.log') -Value 'x'
    Set-Content -LiteralPath (Join-Path $hp 'prog\bin\engine.dll') -Value 'x'
    Assert-Equal $false (Test-HoldsProgramFiles (Join-Path $hp 'data')) 'a folder of logs holds no programs'
    Assert-Equal $true (Test-HoldsProgramFiles (Join-Path $hp 'prog')) 'a folder with a .dll deep inside holds programs'
    Assert-Equal $true (Test-HoldsProgramFiles (Join-Path $hp 'missing')) 'a folder that cannot be read counts as holding programs (doubt keeps)'
    # The EXE-install note: a vendor folder (programs only in subfolders) vs an app's own folder.
    New-Item -ItemType Directory -Path (Join-Path $hp 'vendor\Launcher'), (Join-Path $hp 'vendor\UE_5.7\bin') -Force | Out-Null
    Set-Content -LiteralPath (Join-Path $hp 'vendor\Launcher\launcher.exe') -Value 'x'
    Set-Content -LiteralPath (Join-Path $hp 'vendor\UE_5.7\bin\editor.dll') -Value 'x'
    Assert-Equal 'Launcher,UE_5.7' ((@(Get-ProgramContainerSubfolders (Join-Path $hp 'vendor')) | Sort-Object) -join ',') 'a vendor folder (programs only in subfolders) is noted'
    Set-Content -LiteralPath (Join-Path $hp 'vendor\app.exe') -Value 'x'
    Assert-Equal 0 @(Get-ProgramContainerSubfolders (Join-Path $hp 'vendor')).Count 'an app folder (its own program at the top) is not'
    Assert-Equal 0 @(Get-ProgramContainerSubfolders (Join-Path $hp 'prog')).Count 'one subfolder of programs is not a container'
} finally { Remove-Item -LiteralPath $hp -Recurse -Force -ErrorAction SilentlyContinue }

# ---- the compiled MSI reader against Windows Installer's own COM reader, on a real cached MSI (read-only)
$someMsi = Get-ChildItem -LiteralPath (Join-Path $env:SystemRoot 'Installer') -Filter *.msi -File -ErrorAction SilentlyContinue | Sort-Object Length | Select-Object -First 1
if ($someMsi) {
    $fast = [KillItWithFire.Fast]::MsiQuery($someMsi.FullName, 'SELECT `Property`, `Value` FROM `Property`', 2)
    $wi = New-Object -ComObject WindowsInstaller.Installer
    $db = Invoke-ComMember $wi 'OpenDatabase' 'InvokeMethod' @($someMsi.FullName, 0)
    $v = Invoke-ComMember $db 'OpenView' 'InvokeMethod' @('SELECT `Property`, `Value` FROM `Property`')
    [void](Invoke-ComMember $v 'Execute')
    $com = @()
    while ($null -ne ($rec = Invoke-ComMember $v 'Fetch')) { $com += ([string](Invoke-ComMember $rec 'StringData' 'GetProperty' @(1)) + '=' + [string](Invoke-ComMember $rec 'StringData' 'GetProperty' @(2))) }
    [void](Invoke-ComMember $v 'Close')
    Assert-Equal ($com -join '|') (($fast | ForEach-Object { $_[0] + '=' + $_[1] }) -join '|') "machine: compiled MSI reader = COM reader ($($someMsi.Name), $($com.Count) properties)"
    Assert-Equal 0 @([KillItWithFire.Fast]::MsiQuery($someMsi.FullName, 'SELECT `Name` FROM `KillItWithFireNoSuchTable`', 1)).Count 'machine: a table the package lacks is no rows, not an error'
} else { Write-Host 'note: no cached MSI on this machine; the MSI reader check was skipped' }

Assert-Equal '"C:\IT Logs\\"' (ConvertTo-ArgvString 'C:\IT Logs\') 'argv: a trailing backslash is doubled before the closing quote'
Assert-Equal '"a\"b"' (ConvertTo-ArgvString 'a"b') 'argv: an embedded quote is escaped'
Assert-Equal '"x\\\"y z"' (ConvertTo-ArgvString 'x\"y z') 'argv: backslashes before an embedded quote are doubled'
Assert-Equal 'plain' (ConvertTo-ArgvString 'plain') 'argv: nothing to quote'
Assert-Equal '""' (ConvertTo-ArgvString '') 'argv: empty argument'
Assert-Equal 'C:\a\b' (ConvertTo-ArgvString 'C:\a\b') 'argv: backslashes alone are left alone'
$anc = Get-ProcessAncestry
Assert-Equal $true ($anc.Contains($PID)) 'ancestry: this process'
Assert-Equal $true ($anc.Count -ge 2) 'ancestry: and its parent'
Assert-Equal $true ((Split-Path (Get-PowerShellExe) -Leaf) -in @('powershell.exe', 'pwsh.exe') -and (Test-Path (Get-PowerShellExe))) 'child host is a real PowerShell console exe'
$al = ConvertTo-ArgumentList ([ordered]@{ Name = 'Notepad++ (64-bit x64)'; Level = 3; Exclude = @('Drivers', 'Files'); Force = [System.Management.Automation.SwitchParameter]::new($true); Quiet = [System.Management.Automation.SwitchParameter]::new($false) })
Assert-Equal '-Name|Notepad++ (64-bit x64)|-Level|3|-Exclude|Drivers,Files|-Force' ($al -join '|') 'relaunch arguments'
Assert-Equal $null (Get-Prop ([pscustomobject]@{ a = 1 }) 'b') 'missing property is null, not a strict-mode error'
Assert-Equal 1 (Get-Prop ([ordered]@{ a = 1 }) 'a') 'dictionary property'
Assert-Equal '2026-09-26 01:30' ((ConvertTo-UtcDate '2026-09-26T01:30:00.0000000Z').ToString('yyyy-MM-dd HH:mm')) 'ISO text to UTC'
Assert-Equal '2026-09-26 01:30' ((ConvertTo-UtcDate ([datetime]::SpecifyKind([datetime]'2026-09-26 01:30', 'Utc'))).ToString('yyyy-MM-dd HH:mm')) 'DateTime (PowerShell 7 JSON) to UTC'

# ---- .reg serializer (golden text; the import round trip runs in the lab validation, never here)
$reg = ConvertTo-RegFileText @(@{ Path = 'HKEY_LOCAL_MACHINE\SOFTWARE\Test'; Values = @(
            @{ Name = ''; Kind = 'String'; Data = 'C:\a "b"' },
            @{ Name = 'D'; Kind = 'DWord'; Data = -1 },
            @{ Name = 'Q'; Kind = 'QWord'; Data = [int64]1 },
            @{ Name = 'E'; Kind = 'ExpandString'; Data = '%A%' },
            @{ Name = 'M'; Kind = 'MultiString'; Data = @('a', 'b') },
            @{ Name = 'B'; Kind = 'Binary'; Data = [byte[]]@(1, 255) },
            @{ Name = 'N'; Kind = 'String'; Data = "x`ny" }) })
$regLines = $reg -split "`r?`n"
Assert-Equal 'Windows Registry Editor Version 5.00' $regLines[0] '.reg header'
Assert-Equal '[HKEY_LOCAL_MACHINE\SOFTWARE\Test]' $regLines[2] '.reg key line'
Assert-Equal '@="C:\\a \"b\""' $regLines[3] '.reg default string, escaped'
Assert-Equal '"D"=dword:ffffffff' $regLines[4] '.reg dword -1'
Assert-Equal '"Q"=hex(b):01,00,00,00,00,00,00,00' $regLines[5] '.reg qword'
Assert-Equal '"E"=hex(2):25,00,41,00,25,00,00,00' $regLines[6] '.reg expand string'
Assert-Equal '"M"=hex(7):61,00,00,00,62,00,00,00,00,00' $regLines[7] '.reg multi string'
Assert-Equal '"B"=hex:01,ff' $regLines[8] '.reg binary'
Assert-Equal '"N"=hex(1):78,00,0a,00,79,00,00,00' $regLines[9] '.reg string with a line break goes hex(1)'

# ---- Kill It With Fire never touches its own folders (under the tool's first name, a lab app named
#      "Leftovers ... Test" made the derived keyword "Leftovers" match C:\ProgramData\Leftovers, and the
#      run moved its own backups; today's equivalent is KillItWithFire and C:\ProgramData\KillItWithFire)
Assert-Equal $true ([bool](Get-OwnFolderConflict (Join-Path $env:ProgramData 'KillItWithFire'))) 'own folder: the runs parent itself'
Assert-Equal $true ([bool](Get-OwnFolderConflict $env:ProgramData)) 'own folder: a parent that contains it'
Assert-Equal $true ([bool](Get-OwnFolderConflict (Join-Path $env:ProgramData 'KillItWithFire\runs\x\files'))) 'own folder: anything inside'
Assert-Equal $true ([bool](Get-OwnFolderConflict (Join-Path $env:SystemDrive '.killitwithfire\abc'))) 'own folder: a drive quarantine'
Assert-Equal $true ([bool](Get-OwnFolderConflict (Split-Path $PSScriptRoot -Parent))) 'own folder: the folder the script runs from'
Assert-Equal $false ([bool](Get-OwnFolderConflict (Join-Path $env:ProgramData 'KillItWithFireLab'))) 'own folder: a sibling with a longer name is not'
Assert-Equal $false ([bool](Get-OwnFolderConflict "$env:ProgramFiles\Notepad++")) 'own folder: an app folder is not'
Assert-Equal 'C:\Program Files\X\locked.bin' (ConvertFrom-PendingRenameEntry '*1\??\C:\Program Files\X\locked.bin') 'boot-time move entry, Windows 11 form'
Assert-Equal 'C:\X\a.dll' (ConvertFrom-PendingRenameEntry '\??\C:\X\a.dll') 'boot-time move entry, classic form'
Assert-Equal 'C:\X\b.dll' (ConvertFrom-PendingRenameEntry '*2!\??\C:\X\b.dll') 'boot-time move entry, replace-existing destination'

# ---- the run purge deletes trees deeper than 260 characters (scratch folder in %TEMP%; a review once
#      claimed rd rejects the \\?\ form, and this proves it doesn't)
$deep = Join-Path ([System.IO.Path]::GetTempPath()) ('killitwithfire-deep ' + [guid]::NewGuid().ToString('N').Substring(0, 6))
[void][System.IO.Directory]::CreateDirectory('\\?\' + $deep + '\' + (('d' * 50 + '\') * 6))
[System.IO.File]::WriteAllText('\\?\' + $deep + '\' + (('d' * 50 + '\') * 6) + 'deep.txt', 'x')
$script:Run = $null
Remove-TreeLongPath $deep
Assert-Equal $false (Test-Path -LiteralPath $deep) 'long-path purge removes a 360-character tree (path with a space)'

# ---- policy: the ENGINE refuses what an administrator locked
$noPolicy = Get-KillItWithFirePolicy -Json $null
if ($noPolicy.Source) { Write-Host "note: this machine has a real Kill It With Fire policy ($($noPolicy.Source)); the no-policy case is checked with an empty JSON policy" }
$empty = Get-KillItWithFirePolicy -Json '{}'
Assert-Equal 0 @(Get-PolicyViolations -Policy $empty -Level 3 -NoBackup $true -NoLog $true -LogPath 'C:\x.log' -IncludeUserData $true -QuarantineDays 30).Count 'no policy: nothing refused'
$locked = Get-KillItWithFirePolicy -Json '{"MaxLevel":2,"RequireBackup":1,"RequireLog":1,"LogPath":"\\\\srv\\logs\\","AllowUserData":0,"QuarantineDays":30}'
Assert-Equal '2|True|True|\\srv\logs\|False|30' "$($locked.MaxLevel)|$($locked.RequireBackup)|$($locked.RequireLog)|$($locked.LogPath)|$($locked.AllowUserData)|$($locked.QuarantineDays)" 'policy parsed like the registry values'
Assert-Equal 0 @(Get-PolicyViolations -Policy $locked -Level 2 -NoBackup $false -NoLog $false -LogPath '' -IncludeUserData $false -QuarantineDays 0).Count 'within the policy'
Assert-Equal 1 @(Get-PolicyViolations -Policy $locked -Level 3 -NoBackup $false -NoLog $false -LogPath '' -IncludeUserData $false -QuarantineDays 0).Count 'level above MaxLevel'
Assert-Equal 1 @(Get-PolicyViolations -Policy $locked -Level 2 -NoBackup $true -NoLog $false -LogPath '' -IncludeUserData $false -QuarantineDays 0).Count 'NoBackup when a backup is required'
Assert-Equal 1 @(Get-PolicyViolations -Policy $locked -Level 2 -NoBackup $false -NoLog $true -LogPath '' -IncludeUserData $false -QuarantineDays 0).Count 'NoLog when a log is required'
Assert-Equal 1 @(Get-PolicyViolations -Policy $locked -Level 2 -NoBackup $false -NoLog $false -LogPath 'C:\mine.log' -IncludeUserData $false -QuarantineDays 0).Count 'a different log path'
Assert-Equal 1 @(Get-PolicyViolations -Policy $locked -Level 2 -NoBackup $false -NoLog $false -LogPath '' -IncludeUserData $true -QuarantineDays 0).Count 'user data when not allowed'
Assert-Equal 1 @(Get-PolicyViolations -Policy $locked -Level 2 -NoBackup $false -NoLog $false -LogPath '' -IncludeUserData $false -QuarantineDays 7).Count 'a different quarantine period'

# ---- execution order: the rules the review made non-negotiable
$o = $script:Order
Assert-Equal $true ($o.PasswordProviderRestore -lt $o.CredentialProviderFilter -and $o.CredentialProviderFilter -lt $o.CredentialProvider) 'password sign-in back on BEFORE the filter, filter before the provider'
Assert-Equal $true ($o.DeviceClassFilter -lt $o.Driver -and $o.DeviceInstanceFilter -lt $o.Driver) 'device filters before their driver'
Assert-Equal $true ($o.NetworkComponent -lt $o.DriverPackage -and $o.DriverPackage -lt $o.Driver) 'netcfg -u, then the package, then the driver'
Assert-Equal $true ($o.Service -lt $o.Driver) 'user-mode services stop before drivers'
Assert-Equal $true ((@($o.Keys | Where-Object { (Get-CategoryGroup $_) -eq 'LogonHooks' } | ForEach-Object { $o[$_] }) | Measure-Object -Maximum).Maximum -lt $o.DeviceClassFilter) 'every logon hook before any driver work'
Assert-Equal $true ($o.CredentialProvider -lt $o.ComClass) 'provider registration goes before its COM class'
Assert-Equal $true ($o.InstallRoot -gt $o.ComClass -and $o.InstallRoot -gt $o.Driver -and $o.InstallRoot -gt $o.Service) 'files move only after everything that loads them is unhooked'
$allCats = @($script:Categories.Values | ForEach-Object { $_ })
Assert-Equal '' (@($o.Keys | Where-Object { $allCats -notcontains $_ }) -join ',') 'every ordered category has a group'
Assert-Equal '' (@($allCats | Where-Object { -not $o.ContainsKey($_) }) -join ',') 'every grouped category has an order'

# ---- which items a run acts on
function New-TestItem {
    param([int] $Id, [int] $Level, [string] $Category, [string] $Risk = 'low', [switch] $Review, $Bytes = $null, [switch] $NoOp)
    $g = Get-CategoryGroup $Category
    [pscustomobject]@{ id = $Id; level = $Level; order = $script:Order[$Category]; category = $Category; group = $g; scope = 'machine'; target = "item $Id ($Category)"
        action = 'delete'; evidence = 'test'; risk = $Risk; review = [bool]$Review; optIn = ([bool]$Review -or $g -eq 'UserData'); note = ''; bytes = $Bytes
        op = $(if ($NoOp) { $null } else { [pscustomobject]@{ kind = 'RegDeleteKey'; hive = 'HKLM64'; path = "SOFTWARE\KillItWithFireTest\$Id" } }) }
}
$testPlan = [pscustomobject]@{
    tool = 'KillItWithFire'; version = $script:ToolVersion; runId = 'test'; computer = $env:COMPUTERNAME; generatedUtc = (Get-Date).ToUniversalTime().ToString('o'); level = 0; refused = $null
    target = [pscustomobject]@{ displayName = 'Test App'; version = '1.0'; publisher = 'Test Co'; productCode = '{DDC95F26-92B1-4546-9678-5DC68DF76BA0}'; upgradeCode = $null; isMsi = $true
        uninstallEntries = @(); uninstallString = ''; quietUninstallString = ''; cachedMsi = $null; cachedMsiPresent = $false }
    items = @(
        (New-TestItem 1 2 'UninstallEntry'), (New-TestItem 2 2 'MsiProduct'), (New-TestItem 3 3 'CredentialProvider' -Risk critical), (New-TestItem 4 3 'Driver' -Risk high -Review),
        (New-TestItem 5 3 'Service'), (New-TestItem 6 3 'InstallRoot' -Bytes 52428800), (New-TestItem 7 3 'AppDataFolder' -Bytes 1048576),
        (New-TestItem 8 3 'FileAssociation' -Risk high -Review -NoOp), (New-TestItem 9 3 'VendorRegistryKey' -Risk high))
    kept = @(); offlineProfiles = @(); preflight = @(); warnings = @()
}
$ids = { param($sel) (@($sel | Where-Object { $_ }) | ForEach-Object { $_.id }) -join ',' }
Assert-Equal '' (& $ids (Select-PlanItems $testPlan 1 @() @() $false $false)) 'level 1 acts on no items (uninstaller only)'
Assert-Equal '1,2' (& $ids (Select-PlanItems $testPlan 2 @() @() $false $false)) 'level 2 = registration only'
Assert-Equal '1,2,3,5,6,9' (& $ids (Select-PlanItems $testPlan 3 @() @() $false $false)) 'level 3, in execution order, no opt-ins'
Assert-Equal '1,2,3,5,4,6,9' (& $ids (Select-PlanItems $testPlan 3 @() @() $false $true)) 'IncludeReview adds the vendor-only driver; a report-only item never runs'
Assert-Equal '1,2,3,5,6,9,7' (& $ids (Select-PlanItems $testPlan 3 @() @() $true $false)) 'IncludeUserData adds AppData (last: it runs after the vendor keys)'
Assert-Equal '1,2,3,5,9' (& $ids (Select-PlanItems $testPlan 3 @() @('Files') $false $false)) 'Exclude Files'
Assert-Equal '6' (& $ids (Select-PlanItems $testPlan 3 @('Files') @() $false $false)) 'Include Files only'
Assert-Equal '7' (& $ids (Select-PlanItems $testPlan 3 @('UserData') @() $false $false)) 'Include UserData counts as opting in'

# ---- profiles: the shipped ones load, a malformed one is refused, the registry fence holds
$profs = @(Import-AppProfile)
Assert-Equal 'Citrix Workspace,Notepad++,PuTTY,Zoom' ((@($profs | ForEach-Object { $_.Data.Name }) | Sort-Object) -join ',') 'shipped profiles load (the .example template does not)'
$badDir = Join-Path ([System.IO.Path]::GetTempPath()) ('killitwithfire-prof-' + [guid]::NewGuid().ToString('N').Substring(0, 8))
New-Item -ItemType Directory -Path $badDir -Force | Out-Null
try {
    "@{ Name = 'Bad'; Match = @{ DisplayName = 'x' }; Items = @( @{ Kind = 'DeleteEverything'; Path = 'C:\'; Why = 'no' } ) }" | Set-Content -LiteralPath (Join-Path $badDir 'bad.psd1')
    $threw = $false; try { [void](Import-AppProfile -Extra (Join-Path $badDir 'bad.psd1')) } catch { $threw = ($_.Exception.Message -like '*unknown item kind*') }
    Assert-Equal $true $threw 'a profile with an unknown item kind is refused'
    "@{ Name = 'NoMatch'; Match = @{}; Items = @() }" | Set-Content -LiteralPath (Join-Path $badDir 'nomatch.psd1')
    $threw = $false; try { [void](Import-AppProfile -Extra (Join-Path $badDir 'nomatch.psd1')) } catch { $threw = ($_.Exception.Message -like '*Match needs*') }
    Assert-Equal $true $threw 'a profile that matches everything is refused'
} finally { Remove-Item -LiteralPath $badDir -Recurse -Force -ErrorAction SilentlyContinue }
foreach ($p in @('SOFTWARE\Microsoft\Windows', 'SOFTWARE\Classes\CLSID\{x}', 'SOFTWARE\WOW6432Node\Vendor', 'SOFTWARE', 'SYSTEM\CurrentControlSet\Services\x', 'SOFTWARE\Policies\Vendor')) {
    Assert-Equal $true ($p -match $script:ProtectedRegistry) "profile registry fence blocks $p"
}
Assert-Equal $false ('SOFTWARE\SimonTatham\PuTTY' -match $script:ProtectedRegistry) 'profile registry fence allows a vendor key'
Assert-Equal $false ('SOFTWARE\Microsoftish Tools' -match $script:ProtectedRegistry) 'the fence is on whole names'

# ---- the window: built without showing it, rendered, control states checked (no elevation needed)
$hostExe = (Get-Process -Id $PID).Path
$guiDir = Join-Path ([System.IO.Path]::GetTempPath()) ('killitwithfire-gui-test-' + [guid]::NewGuid().ToString('N').Substring(0, 8))
New-Item -ItemType Directory -Path $guiDir -Force | Out-Null
try {
    $planFile = Join-Path $guiDir 'plan.json'
    ($testPlan | ConvertTo-Json -Depth 8) | Set-Content -LiteralPath $planFile -Encoding UTF8
    '{}' | Set-Content -LiteralPath (Join-Path $guiDir 'open.json') -Encoding ASCII
    '{"MaxLevel":2,"RequireBackup":1,"RequireLog":1,"LogPath":"\\\\srv\\logs\\","AllowUserData":0}' | Set-Content -LiteralPath (Join-Path $guiDir 'locked.json') -Encoding ASCII
    $runGui = {
        param([string] $Policy, [string] $Png)
        $ErrorActionPreference = 'Continue'
        $out = & $hostExe -NoProfile -ExecutionPolicy Bypass -File $engine -GuiSelfTest $Png -Plan $planFile -PolicyFile (Join-Path $guiDir $Policy) 2>&1 | Out-String
        $json = $out.Substring([Math]::Max(0, $out.IndexOf('{')))
        try { return ($json | ConvertFrom-Json) } catch { Write-Host "GUI self-test output was not JSON:`n$out"; return $null }
    }
    $engine = Join-Path $PSScriptRoot '..\KillItWithFire.ps1'
    $s = & $runGui 'open.json' (Join-Path $guiDir 'open.png')
    Assert-Equal $true ($null -ne $s) 'window self-test ran (no policy)'
    if ($s) {
        Assert-Equal 3 $s.level 'no policy: the highest level is selectable and selected'
        Assert-Equal 'True,True,True,True' (@($s.levelsEnabled) -join ',') 'no policy: every level enabled'
        Assert-Equal 'Registration,LogonHooks,Drivers,Services,Files,Registry' ((@($s.categories) | ForEach-Object { ($_ -split ' ')[0] }) -join ',') 'checklist rows (user data has its own box; report-only rows never show)'
        Assert-Equal $true ((@($s.categories) | Where-Object { $_ -like 'Files*' }) -like '*50.0 MB*') 'checklist shows sizes'
        Assert-Equal $true ((@($s.categories) | Where-Object { $_ -like 'Drivers*' }) -like '*+1 uncertain*') 'checklist counts uncertain (review) items apart'
        Assert-Equal 'Also remove uncer&tain matches: 1' $s.reviewText 'the review box says what it is and how many, and stays off by default'
        Assert-Equal 'Kill It With Fire - remove an app completely' $s.title 'window title'
        Assert-Equal $true ([bool]$s.hasIcon) 'the window has its flame icon'
        Assert-Equal 'Name|Version|Publisher|Type|Scope|Installed|Size' (@($s.appColumns) -join '|') 'app list columns: install date and size added'
        Assert-Equal ".\KillItWithFire.ps1 -ProductCode '{DDC95F26-92B1-4546-9678-5DC68DF76BA0}' -Level 3 -Force" $s.command 'equivalent command line'
        Assert-Equal $true ($s.userDataText -like '*1 item(s), 1.0 MB*') 'user data box shows what it would add'
        Assert-Equal $true ([bool]$s.cleanEnabled) 'Clean up enabled once a plan is loaded'
        Assert-Equal '' $s.policyLabel 'no policy label'
        Assert-Equal 'False|&Clean up|True' "$($s.killItChecked)|$($s.cleanText)|$($s.killItEnabled)" 'KILL IT starts unticked: the proper way is the default'
        Assert-Equal $true ($null -ne $s.killIt) 'the KILL IT wiring was exercised'
        if ($s.killIt) {
            Assert-Equal 3 $s.killIt.level 'ticking KILL IT from Scan only jumps to Full scrub'
            Assert-Equal ".\KillItWithFire.ps1 -ProductCode '{DDC95F26-92B1-4546-9678-5DC68DF76BA0}' -KillIt -Force" $s.killIt.command 'and the command line says -KillIt'
            Assert-Equal '&Kill it' $s.killIt.cleanText 'and the button says Kill it'
            Assert-Equal 'False|&Clean up' "$($s.killIt.checkedAfterLevel1)|$($s.killIt.cleanTextAfterLevel1)" 'dropping to level 1 unticks it (nothing to kill there)'
        }
        Assert-Equal $true ((Get-Item -LiteralPath (Join-Path $guiDir 'open.png')).Length -gt 10000) 'window rendered to a PNG'
    }
    $s = & $runGui 'locked.json' (Join-Path $guiDir 'locked.png')
    Assert-Equal $true ($null -ne $s) 'window self-test ran (locked policy)'
    if ($s) {
        Assert-Equal 'True,True,True,False' (@($s.levelsEnabled) -join ',') 'MaxLevel 2 greys out Full scrub'
        Assert-Equal $false ([bool]$s.killItEnabled) 'MaxLevel 2 greys out KILL IT too (it is a full scrub)'
        Assert-Equal 2 $s.level 'the highest allowed level is selected'
        Assert-Equal 'True|False|True|False|\\srv\logs\|False|False' "$($s.backupChecked)|$($s.backupEnabled)|$($s.logChecked)|$($s.logEnabled)|$($s.logPath)|$($s.logPathEnabled)|$($s.userDataEnabled)" 'locked options are set and greyed out'
        Assert-Equal $true ($s.policyLabel -like 'Set by your administrator:*highest level 2*') 'the lock is labelled'
        Assert-Equal 'Registration' ((@($s.categories) | ForEach-Object { ($_ -split ' ')[0] }) -join ',') 'level 2 shows registration only'
        Assert-Equal ".\KillItWithFire.ps1 -ProductCode '{DDC95F26-92B1-4546-9678-5DC68DF76BA0}' -Level 2 -Log '\\srv\logs\' -Force" $s.command 'command line carries the locked log path'
    }
    # -PolicyFile is refused outside the self-test: it can never stand in for an administrator's policy.
    & $hostExe -NoProfile -ExecutionPolicy Bypass -File $engine -Name 'x' -PolicyFile (Join-Path $guiDir 'open.json') *> $null
    Assert-Equal 3 $LASTEXITCODE '-PolicyFile refused for a real run'
} finally {
    Remove-Item -LiteralPath $guiDir -Recurse -Force -ErrorAction SilentlyContinue
}

# ---- static: the engine parses, and every command it calls exists. A search-and-replace once turned
# "Test-OurReference $val" into "Test-OurReference$val", which parses fine and only fails at run time.
$engine = Join-Path $PSScriptRoot '..\KillItWithFire.ps1'
$tokens = $null; $parseErrors = $null
[void][System.Management.Automation.Language.Parser]::ParseFile($engine, [ref]$tokens, [ref]$parseErrors)
Assert-Equal 0 @($parseErrors).Count 'engine parses'
$defined = @([regex]::Matches((Get-Content -LiteralPath $engine -Raw), '(?m)^function\s+([\w-]+)') | ForEach-Object { $_.Groups[1].Value })
$unresolved = @($tokens | Where-Object { $_.TokenFlags -band [System.Management.Automation.Language.TokenFlags]::CommandName } |
    ForEach-Object { $_.Text } | Select-Object -Unique | Where-Object { $defined -notcontains $_ -and -not (Get-Command $_ -ErrorAction SilentlyContinue) })
Assert-Equal '' ($unresolved -join ', ') 'every command the engine calls exists'
# A local named like an automatic variable parses fine and fails only at run time, and only on some
# hosts: "$isWindows = ..." is a read-only-variable error on PowerShell 7 alone (2026-09-26, it
# stopped every level-0 scan on 7.6 while 5.1 ran clean).
$automatic = @('args', 'input', 'error', 'host', 'home', 'pid', 'profile', 'pwd', 'this', 'isLinux', 'isMacOS', 'isWindows', 'isCoreCLR',
    'event', 'eventArgs', 'eventSubscriber', 'sender', 'ofs', 'foreach', 'switch', 'stackTrace', 'psItem', 'executionContext', 'myInvocation',
    'psCulture', 'psUICulture', 'shellId', 'psHome', 'psVersionTable', 'psScriptRoot', 'psCommandPath', 'psBoundParameters', 'nestedPromptLevel')
# ($null = x is the normal way to discard output, so null is deliberately not in this list.)
$ast = [System.Management.Automation.Language.Parser]::ParseFile($engine, [ref]$null, [ref]$null)
$badAssign = @($ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.AssignmentStatementAst] }, $true) |
    ForEach-Object { $_.Left } | Where-Object { $_ -is [System.Management.Automation.Language.VariableExpressionAst] -and ($automatic -contains $_.VariablePath.UserPath) } |
    ForEach-Object { "$($_.VariablePath.UserPath) (line $($_.Extent.StartLineNumber))" })
Assert-Equal '' ($badAssign -join ', ') 'no assignment to an automatic variable name'
# This file dot-sources the engine, so the engine's $script: variables ARE this file's variables: a test
# named "$base" once replaced the engine's registry roots with a single key (2026-09-26).
$engineScriptVars = @($ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.VariableExpressionAst] -and $n.VariablePath.IsScript }, $true) |
    ForEach-Object { ($_.VariablePath.UserPath -replace '^(?i)script:', '').ToLowerInvariant() } | Select-Object -Unique)
$selfAst = [System.Management.Automation.Language.Parser]::ParseFile($PSCommandPath, [ref]$null, [ref]$null)
$mine = @($selfAst.FindAll({ param($n) $n -is [System.Management.Automation.Language.AssignmentStatementAst] }, $true) | ForEach-Object { $_.Left } |
    Where-Object { $_ -is [System.Management.Automation.Language.VariableExpressionAst] -and -not $_.VariablePath.IsScript } | ForEach-Object { $_.VariablePath.UserPath.ToLowerInvariant() } | Select-Object -Unique)
Assert-Equal '' (@($mine | Where-Object { $engineScriptVars -contains $_ }) -join ', ') 'no test variable shadows an engine $script: variable'
# $PSScriptRoot / $PSCommandPath are EMPTY inside a script's parameter defaults on Windows PowerShell 5.1
# (2026-09-26: the lab script's -Engine default resolved to nothing on the VM and every scenario died).
$rootInDefault = @()
foreach ($f in @(Get-ChildItem -LiteralPath (Join-Path $PSScriptRoot '..') -Recurse -Filter *.ps1 -File | Where-Object { $_.FullName -notmatch '\\(lab|out)\\' })) {
    $fa = [System.Management.Automation.Language.Parser]::ParseFile($f.FullName, [ref]$null, [ref]$null)
    if (-not $fa.ParamBlock) { continue }
    foreach ($prm in $fa.ParamBlock.Parameters) {
        if ($prm.DefaultValue -and $prm.DefaultValue.FindAll({ param($n) $n -is [System.Management.Automation.Language.VariableExpressionAst] -and $n.VariablePath.UserPath -in @('PSScriptRoot', 'PSCommandPath') }, $true).Count) {
            $rootInDefault += "$($f.Name): $($prm.Name.VariablePath.UserPath)"
        }
    }
}
Assert-Equal '' ($rootInDefault -join ', ') 'no script parameter default uses $PSScriptRoot (empty on 5.1)'
$ascii = @([System.IO.File]::ReadAllBytes($engine) | Where-Object { $_ -gt 127 }).Count
Assert-Equal 0 $ascii 'engine is pure ASCII (Windows PowerShell 5.1 misreads UTF-8 without a BOM)'

# ---- read-only check against THIS machine: our packing must name real Installer\Products keys
# (Not "$base": the engine is dot-sourced into this scope, and its $script:Base is the same variable.)
$hklm64 = [Microsoft.Win32.RegistryKey]::OpenBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine, [Microsoft.Win32.RegistryView]::Registry64)
$products = $hklm64.OpenSubKey('SOFTWARE\Classes\Installer\Products')
$checked = 0
if ($products) {
    foreach ($packed in ($products.GetSubKeyNames() | Select-Object -First 25)) {
        $guid = ConvertFrom-PackedGuid $packed
        if (-not $guid) { continue }
        $arp = $hklm64.OpenSubKey("SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\$guid")
        if (-not $arp) { $arp = [Microsoft.Win32.RegistryKey]::OpenBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine, [Microsoft.Win32.RegistryView]::Registry32).OpenSubKey("SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\$guid") }
        if ($arp) {
            Assert-Equal $packed (ConvertTo-PackedGuid $guid) "machine: $guid packs back to its Installer\Products key"
            $arp.Close(); $checked++
        }
        if ($checked -ge 5) { break }
    }
    $products.Close()
}
if ($checked -eq 0) { Write-Host 'note: no MSI product with an uninstall entry on this machine; the machine check was skipped' }

# ---- read-only: real key locations under WOW64 (the 32-bit view is NOT simply WOW6432Node)
Initialize-RegistryBase
if ([Environment]::Is64BitOperatingSystem) {
    Assert-Equal $true ((Get-KeyNativePath 'HKLM32' 'SOFTWARE\Classes\CLSID') -match '(?i)WOW6432Node') 'machine: the 32-bit CLSID tree is redirected'
    Assert-Equal (Get-KeyNativePath 'HKLM64' 'SOFTWARE\Classes\.txt') (Get-KeyNativePath 'HKLM32' 'SOFTWARE\Classes\.txt') 'machine: file extensions are shared between the views'
    Assert-Equal 'HKLM\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall' (Format-RegPath 'HKLM32' 'SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall') 'machine: the 32-bit uninstall key is redirected'
    Assert-Equal $null (Get-KeyNativePath 'HKLM64' 'SOFTWARE\KillItWithFire-no-such-key-7f3a') 'machine: a missing key has no native path'
}

# ---- a ProgID's guard: delete it while it points at our class, or (once the app's own uninstaller cut
# that link) at nothing but what the scan saw pointing at the app. Foxit PDF Reader left four such keys
# (lab sweep, 2026-10-03). A scratch key in this user's own hive, removed again at the end.
$me = [Security.Principal.WindowsIdentity]::GetCurrent().User.Value
$tk = "$me\Software\KillItWithFire-Test-$([guid]::NewGuid().ToString('N').Substring(0, 8))"
$hkuBase = [Microsoft.Win32.RegistryKey]::OpenBaseKey([Microsoft.Win32.RegistryHive]::Users, [Microsoft.Win32.RegistryView]::Registry64)
try {
    $pk = "$tk\App.Document"
    $k = $hkuBase.CreateSubKey("$pk\CLSID"); $k.SetValue('', '{11111111-2222-3333-4444-555555555555}'); $k.Close()
    $k = $hkuBase.CreateSubKey("$pk\DefaultIcon"); $k.SetValue('', 'C:\App\app.exe,1'); $k.Close()
    $k = $hkuBase.CreateSubKey("$pk\shell\open\command"); $k.SetValue('', '"C:\App\app.exe" "%1"'); $k.Close()
    $refs = Get-ProgIdRefs 'HKU' $pk
    Assert-Equal 'DefaultIcon=C:\App\app.exe,1|shell\open\command="C:\App\app.exe" "%1"' ((@($refs.Keys) | Sort-Object | ForEach-Object { "$_=$($refs[$_])" }) -join '|') 'ProgID refs: its icon and every verb command'
    $exp = @{ sub = 'CLSID'; value = '{11111111-2222-3333-4444-555555555555}'; orphanRefs = $refs }
    $expJson = $exp | ConvertTo-Json -Depth 4 | ConvertFrom-Json
    $old = @{ sub = 'CLSID'; value = '{11111111-2222-3333-4444-555555555555}' }
    Assert-Equal $true (Test-KeyExpectation 'HKU' $pk $exp) 'ProgID: still points at our class'
    $hkuBase.DeleteSubKeyTree("$pk\CLSID")
    Assert-Equal $true (Test-KeyExpectation 'HKU' $pk $exp) 'ProgID: CLSID link cut by the uninstaller, the rest as the scan saw it: ours'
    Assert-Equal $true (Test-KeyExpectation 'HKU' $pk $expJson) '... the same from a plan.json read back'
    Assert-Equal $false (Test-KeyExpectation 'HKU' $pk $old) '... but never under an older plan without orphanRefs'
    $hkuBase.DeleteSubKeyTree("$pk\DefaultIcon")
    Assert-Equal $true (Test-KeyExpectation 'HKU' $pk $exp) 'ProgID: less of it left than the scan saw is still ours'
    $k = $hkuBase.CreateSubKey("$pk\shell\edit\command"); $k.SetValue('', '"C:\Other\editor.exe" "%1"'); $k.Close()
    Assert-Equal $false (Test-KeyExpectation 'HKU' $pk $exp) 'ProgID: a verb that was not there at the scan means someone else uses it: kept'
    $hkuBase.DeleteSubKeyTree("$pk\shell\edit")
    $k = $hkuBase.CreateSubKey("$pk\shell\open\command"); $k.SetValue('', '"C:\Other\viewer.exe" "%1"'); $k.Close()
    Assert-Equal $false (Test-KeyExpectation 'HKU' $pk $exp) 'ProgID: its open command now runs another program: kept'
    $k = $hkuBase.CreateSubKey("$pk\CLSID"); $k.SetValue('', '{99999999-2222-3333-4444-555555555555}'); $k.Close()
    Assert-Equal $false (Test-KeyExpectation 'HKU' $pk $exp) 'ProgID: re-pointed at another class: kept'
} finally {
    try { $hkuBase.DeleteSubKeyTree($tk, $false) } catch { }
    $hkuBase.Close()
}

Write-Host ("{0} passed, {1} failed ({2})" -f $script:pass, $script:fail, $PSVersionTable.PSVersion)
exit ([int]($script:fail -gt 0))
