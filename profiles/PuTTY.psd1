# What PuTTY keeps outside its install folder. Source: the PuTTY manual, "Saving your settings" and
# "putty.rnd" (sessions and cached host keys live in HKCU\Software\SimonTatham\PuTTY; the random seed
# file lives in the roaming profile). Both are per-user data: they only go with -IncludeUserData.
@{
    Name  = 'PuTTY'
    Match = @{ DisplayName = '^PuTTY release \d'; Publisher = '^Simon Tatham$' }
    Notes = 'Saved sessions and cached SSH host keys are per-user settings; removing them is an opt-in.'
    Items = @(
        @{ Kind = 'UserRegistryKey'; Path = 'Software\SimonTatham\PuTTY'; Why = 'saved sessions and cached SSH host keys'; UserData = $true }
        @{ Kind = 'UserPath'; Path = 'AppData\Roaming\putty.rnd'; Why = 'random seed file'; UserData = $true }
    )
}
