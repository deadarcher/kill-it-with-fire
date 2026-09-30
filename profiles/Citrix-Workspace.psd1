# What Citrix Workspace app keeps where identity matching can't see it. Source: a capture of Citrix
# Workspace 2603 (26.3.11.10) on a working machine, read-only (2026-09-29): every key and folder below
# was present there. Not yet run past a real removal: validate with -Level 0 first.
#
# Deliberately NOT here, because other Citrix products own them and each has its own uninstall entry:
# SOFTWARE\Citrix\Install (shared by every Citrix installer), AppProtection (App Protection),
# Secure Access Endpoint Analysis, AuthManager (Authentication Manager), and Program Files\Citrix
# (Secure Access Client). The kept-path check would hold most of them back anyway; leaving them out
# means the dry run never even offers them.
@{
    Name  = 'Citrix Workspace'
    Match = @{ DisplayName = '^Citrix Workspace \d{4}'; Publisher = '^Citrix Systems' }
    Notes = 'A suite: the bundle entry (Citrix Workspace YYMM) plus several component MSIs. Clean the bundle entry; its components match by identity.'
    Items = @(
        @{ Kind = 'MachineRegistryKey'; Path = 'SOFTWARE\Citrix\ICA Client'; View = 32; Why = 'client engine settings (Workspace capture 2026-09-29)' }
        @{ Kind = 'MachineRegistryKey'; Path = 'SOFTWARE\Citrix\Dazzle'; View = 32; Why = 'self-service (store) settings' }
        @{ Kind = 'MachineRegistryKey'; Path = 'SOFTWARE\Citrix\Receiver'; View = 32; Why = 'Workspace app settings (32-bit view)' }
        @{ Kind = 'MachineRegistryKey'; Path = 'SOFTWARE\Citrix\Receiver'; View = 64; Why = 'Workspace app settings (64-bit view)' }
        @{ Kind = 'MachineRegistryKey'; Path = 'SOFTWARE\Citrix\ReceiverInside'; View = 32; Why = 'Workspace Inside component settings' }
        @{ Kind = 'MachineRegistryKey'; Path = 'SOFTWARE\Citrix\PluginPackages'; View = 32; Why = 'the XenAppSuite plug-in package list the bundle installer keeps' }
        @{ Kind = 'MachineRegistryKey'; Path = 'SOFTWARE\Citrix\Program Neighborhood Agent'; View = 32; Why = 'legacy PNAgent settings the client still writes' }
        @{ Kind = 'MachineRegistryKey'; Path = 'SOFTWARE\Citrix\InstallDetect'; View = 32; Why = 'installed-component detection the bundle installer reads' }
        @{ Kind = 'MachineRegistryKey'; Path = 'SOFTWARE\Citrix\CitrixCAB'; View = 32; Why = 'Citrix Enterprise Browser component settings' }
        @{ Kind = 'MachineRegistryKey'; Path = 'SOFTWARE\Citrix\XenDesktop'; View = 32; Why = 'desktop viewer settings' }
        @{ Kind = 'MachineFolder'; Path = '%ProgramData%\Citrix\Receiver'; Why = 'machine-wide Workspace app data' }
        @{ Kind = 'UserRegistryKey'; Path = 'Software\Citrix\ICA Client'; Why = 'per-user client settings'; UserData = $true }
        @{ Kind = 'UserRegistryKey'; Path = 'Software\Citrix\Receiver'; Why = 'per-user Workspace settings'; UserData = $true }
        @{ Kind = 'UserRegistryKey'; Path = 'Software\Citrix\Dazzle'; Why = 'per-user store and app subscriptions'; UserData = $true }
        @{ Kind = 'UserRegistryKey'; Path = 'Software\Citrix\XenDesktop'; Why = 'per-user desktop viewer settings'; UserData = $true }
        @{ Kind = 'UserRegistryKey'; Path = 'Software\Citrix\HdxRealTime'; Why = 'per-user HDX RealTime settings'; UserData = $true }
        @{ Kind = 'UserPath'; Path = 'AppData\Roaming\ICAClient'; Why = 'per-user connection settings (APPSRV.INI, WFCLIENT.INI) and cache' }
        @{ Kind = 'UserPath'; Path = 'AppData\Local\Citrix\Receiver'; Why = 'per-user Workspace app data' }
        @{ Kind = 'UserPath'; Path = 'AppData\Local\Citrix\SelfService'; Why = 'per-user store data' }
    )
}
