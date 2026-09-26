# What Notepad++ keeps outside its install folder. Source: the Notepad++ user manual, "Configuration
# Files" (settings, sessions and unsaved-file backups live in %APPDATA%\Notepad++ unless doLocalConf.xml
# keeps them next to the exe). Per-user data: it only goes with -IncludeUserData.
@{
    Name  = 'Notepad++'
    Match = @{ DisplayName = '^Notepad\+\+ \('; Publisher = '^Notepad\+\+ Team$' }
    Notes = 'The backup folder inside holds unsaved documents: treat it as user data.'
    Items = @(
        @{ Kind = 'UserPath'; Path = 'AppData\Roaming\Notepad++'; Why = 'settings, sessions and backups of unsaved files'; UserData = $true }
    )
}
