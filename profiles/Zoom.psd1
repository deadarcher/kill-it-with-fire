# What Zoom keeps where identity matching can't see it. Source: a lab capture of Zoom Workplace 6.6.11,
# installed per user with ZoomInstaller.exe (HYD-CLIENT3, 2026-09-29). The app itself lives in
# %APPDATA%\Zoom\bin and uninstall, with an HKCU uninstall entry named ZoomUMX, and those are found by
# identity already. The key below is not: "ZoomUMX" is not the whole word "Zoom", so the keyword never
# matches it. The rest of %APPDATA%\Zoom (chat history, recordings settings) is per-user data and is
# already an opt-in AppData item.
@{
    Name  = 'Zoom'
    Match = @{ DisplayName = '^Zoom( Workplace)?( \(64-bit\))?$'; Publisher = '^Zoom (Video )?Communications' }
    Notes = 'Per-user installs are cleaned for signed-in users only. Run it while each user who has Zoom is signed in.'
    Items = @(
        @{ Kind = 'UserRegistryKey'; Path = 'Software\ZoomUMX'; Why = 'per-user install state (PerInstall subkey), written by the per-user installer (lab capture 2026-09-29)' }
    )
}
