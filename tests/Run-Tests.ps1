# Unit tests for Leftovers' pure helpers, plus one read-only check against the real registry.
# No Pester dependency (Windows ships Pester 3.4, CI can use anything): runs on Windows PowerShell 5.1
# and PowerShell 7. Exit code 0 = all passed.
#   powershell -NoProfile -File tests\Run-Tests.ps1
#   pwsh -NoProfile -File tests\Run-Tests.ps1
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot '..\Leftovers.ps1') -LibraryOnly

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
Assert-Equal 'Google,Chrome' ((Get-KeywordCandidates 'Google Chrome' 'Google LLC') -join ',') 'candidates: order kept'
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
$tmp = Join-Path ([System.IO.Path]::GetTempPath()) ('leftovers-test-' + [guid]::NewGuid().ToString('N'))
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

# ---- static: the engine parses, and every command it calls exists. A search-and-replace once turned
# "Test-OurReference $val" into "Test-OurReference$val", which parses fine and only fails at run time.
$engine = Join-Path $PSScriptRoot '..\Leftovers.ps1'
$tokens = $null; $parseErrors = $null
[void][System.Management.Automation.Language.Parser]::ParseFile($engine, [ref]$tokens, [ref]$parseErrors)
Assert-Equal 0 @($parseErrors).Count 'engine parses'
$defined = @([regex]::Matches((Get-Content -LiteralPath $engine -Raw), '(?m)^function\s+([\w-]+)') | ForEach-Object { $_.Groups[1].Value })
$unresolved = @($tokens | Where-Object { $_.TokenFlags -band [System.Management.Automation.Language.TokenFlags]::CommandName } |
    ForEach-Object { $_.Text } | Select-Object -Unique | Where-Object { $defined -notcontains $_ -and -not (Get-Command $_ -ErrorAction SilentlyContinue) })
Assert-Equal '' ($unresolved -join ', ') 'every command the engine calls exists'
$ascii = @([System.IO.File]::ReadAllBytes($engine) | Where-Object { $_ -gt 127 }).Count
Assert-Equal 0 $ascii 'engine is pure ASCII (Windows PowerShell 5.1 misreads UTF-8 without a BOM)'

# ---- read-only check against THIS machine: our packing must name real Installer\Products keys
$base = [Microsoft.Win32.RegistryKey]::OpenBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine, [Microsoft.Win32.RegistryView]::Registry64)
$products = $base.OpenSubKey('SOFTWARE\Classes\Installer\Products')
$checked = 0
if ($products) {
    foreach ($packed in ($products.GetSubKeyNames() | Select-Object -First 25)) {
        $guid = ConvertFrom-PackedGuid $packed
        if (-not $guid) { continue }
        $arp = $base.OpenSubKey("SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\$guid")
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

Write-Host ("{0} passed, {1} failed ({2})" -f $script:pass, $script:fail, $PSVersionTable.PSVersion)
exit ([int]($script:fail -gt 0))
