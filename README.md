# Leftovers

<!-- BRIAN: the opening warning goes here, in your words. The beat: this is for an app whose uninstall is
     ALREADY broken. If msiexec /x or the vendor's uninstaller still works, use that. Leftovers is the
     second attempt, not the first. -->

Cleans up what a broken Windows app left behind: registration, services, drivers, device filters,
network components, driver packages, scheduled tasks, startup entries, COM, shell extensions, file
associations, logon hooks, firewall rules, shortcuts, folders and per-user state. Every item comes with
the evidence that ties it to the app, everything it changes is backed up first, and a whole run can be
restored.

## Levels

| Level | What it does |
|---|---|
| 0 | **Scan only.** Writes `plan.json` and `report.txt`. Changes nothing. The default. |
| 1 | **Uninstall.** Runs the app's own uninstaller once, silently (`msiexec /x` or its QuietUninstallString). |
| 2 | **Registration cleanup.** Removes the uninstall entry and the Windows Installer registration so the app can install again. Files are not touched. |
| 3 | **Full scrub.** Unhooks the app from Windows, then moves its files to a quarantine on the same drive. |

Levels are cumulative. Level 3 unhooks in a fixed order, so a run that stops part way never leaves a
machine worse than it found it:

1. The built-in password sign-in is turned back on, if the app had turned it off. Then its credential
   provider filters, credential providers, Winlogon, LSA, network provider, AppInit and IFEO entries go.
2. Device class and per-device filter entries go before the driver they name (a filter that points at a
   deleted driver stops every device in that class at the next boot).
3. Services stop, then network components (`netcfg -u`), driver packages (`pnputil /delete-driver`), and
   drivers.
4. Tasks, startup entries, COM, shell extensions, file associations, shortcuts, firewall rules.
5. Files and registry keys last, once nothing loads them.

A file in use is moved at the next boot instead. The run then ends with exit code 3010; after the
reboot, `-Resume <runId>` confirms everything finished.

## Run it

Elevated (admin or SYSTEM), Windows PowerShell 5.1 or PowerShell 7, 64-bit (a 32-bit host relaunches
itself in 64-bit PowerShell).

```powershell
.\Leftovers.ps1                                         # the window (below)
.\Leftovers.ps1 -List                                   # installed apps, to pick a target
.\Leftovers.ps1 -Name "Notepad++ (64-bit x64)"          # scan: the plan and the evidence
.\Leftovers.ps1 -ProductCode "{DDC95F26-92B1-4546-9678-5DC68DF76BA0}" -Level 2 -Force
.\Leftovers.ps1 -Name "Notepad++ (64-bit x64)" -Level 3 -Exclude Drivers -Force
.\Leftovers.ps1 -ListRuns
.\Leftovers.ps1 -Restore 20260926-093000-1a2b3c -Force
.\Leftovers.ps1 -Resume 20260926-093000-1a2b3c
```

Without `-Force`, a run at level 1 or above prints the plan and asks you to type YES. `-Force` is for
unattended runs (RMM, PDQ, Intune).

| Switch | Meaning |
|---|---|
| `-Level 0..3` | How far to go (above). |
| `-Include` / `-Exclude` | Categories: `Registration`, `LogonHooks`, `Drivers`, `Services`, `Startup`, `ComShell`, `Other`, `Files`, `Registry`, `UserData`. |
| `-IncludeUserData` | Also move per-user AppData folders and settings. Off by default. |
| `-IncludeReview` | Also act on items tied only by vendor name, signer, or one MSI claim on a Windows file. Off by default. |
| `-SkipUninstall` | Go straight to the cleanup at level 1 and up. |
| `-NoBackup` | Change things without a backup (then the run can't be restored). |
| `-Log <file or folder>` / `-NoLog` | Where the log goes. Default: `log.txt` in the run folder. |
| `-Keyword <word>` | The app's own distinctive name, if the derived one is refused. |
| `-Plan <plan.json>` | Run a plan made earlier on this machine (within 24 hours). |
| `-ProfilePath <file.psd1>` | An extra per-app profile (below). |
| `-QuarantineDays <n>` | How long run backups are kept (default 14). |
| `-OutDir <folder>` | Where a scan writes `plan.json` and `report.txt`. |

Every run gets a folder under `%ProgramData%\Leftovers\runs\<runId>\`, readable by SYSTEM and
Administrators only: `run.json`, the plan and report, `journal.jsonl` (every change, in order),
`backups\` (`.reg` exports), `tasks\`, `drivers\` (exported driver packages) and `files\` (the
quarantine for drive C:; other drives keep theirs in `<drive>:\.leftovers\<runId>`).

| Exit code | Meaning |
|---|---|
| 0 | done (or plan written) |
| 3010 | done, but a reboot is needed to finish (then `-Resume`) |
| 1 | stopped part way: the item that failed is in the report; `-Restore` undoes the rest |
| 2 | refused: policy, a protected product, an ambiguous name, or no confirmation |
| 3 | bad input, app not found, or not elevated |
| 4 | stopped on an unexpected error |

## The window

`.\Leftovers.ps1` with no arguments opens a Disk Cleanup-style window: pick the app, Scan, choose how
far to go, untick categories (each shows its item count and size, and a description), choose the
options, Clean up. Restore lists earlier runs. The window shows the equivalent command line for every
choice, and it does nothing the command line can't: every action runs the same script as a child
process with those switches.

## Locking options (Group Policy, Intune)

Values under `HKLM\SOFTWARE\Policies\Leftovers`. The engine enforces them (a switch past the policy is
refused with exit code 2); the window shows them greyed out and labelled.

| Value | Type | Effect |
|---|---|---|
| `MaxLevel` | DWORD 0-3 | The highest level anyone can run. |
| `RequireBackup` | DWORD 1 | `-NoBackup` is refused. |
| `RequireLog` | DWORD 1 | `-NoLog` is refused. |
| `LogPath` | String | Every run logs here (a file, or a folder such as a share); `-Log` elsewhere is refused. |
| `AllowUserData` | DWORD 0/1 | 0: user data is never removed. |
| `QuarantineDays` | DWORD | How long run backups are kept. |

## How it decides what belongs to the app

Identity first, never name first:

- **The app's own registration:** its uninstall entry, its Windows Installer ProductCode, UpgradeCode
  and components, and the files and registry values its MSI says it owns.
- **Its folders**, from its own registration. A folder that another installed product also points into
  (or that sits inside another product's folder) is **shared**: inside it only the app's own files
  count, and the folder itself stays.
- **Things that point at those folders or files:** services, drivers, tasks, Run keys, Active Setup,
  COM classes, shell extensions, context-menu verbs, file associations, credential providers, network
  providers, print monitors, firewall rules, shortcuts.
- **Weak ties need review** and are left out unless `-IncludeReview`: a driver tied only by the vendor
  named in its version resource (never one that serves present hardware, never a boot driver, never
  when the vendor has other products installed), a logon DLL tied only by its signer, a file under
  `C:\Windows` that one MSI claims.
- **A keyword** (the app's own distinctive name) only ever narrows a match. It is refused when it names
  another installed product, matches much outside the app, or names Windows or its management stack
  ("Microsoft", "Intune", "Defender", ...).
- **Profiles** (`profiles\*.psd1`) add what an app keeps where identity can't see it, such as PuTTY's
  saved sessions. A profile only adds items, and they pass the same checks. See
  `profiles\TEMPLATE.psd1.example`.

Never touched:

- Microsoft software (by publisher, or by the signer of the app's own executables).
- Security products. Use the vendor's removal tool; the report names it.
- The RFF agent.
- Windows folders, the Public profile, OneDrive, users' Desktop/Documents/Pictures/Music/Videos/
  Downloads, and `AppData\*\Microsoft`.
- Signed-out users' registry hives: never loaded in this version. The report lists those profiles.
- `SharedDLLs` reference counts (a wrong decrement breaks a third product).
- Winsock providers and Windows file types an app took over: reported, never edited.

## Tests

```powershell
powershell -NoProfile -File tests\Run-Tests.ps1     # unit tests, no dependencies, changes nothing
pwsh -NoProfile -File tests\Run-Tests.ps1
```

`tests\Invoke-LabValidation.ps1` is the destructive end-to-end validation. It installs real apps,
breaks them, runs every level and restores, and checks each result on the machine. **Throwaway
machines only** (a lab VM or a CI runner): it refuses to start without `-ConfirmThrowaway`. The
scenarios that need a reboot (a boot-time file move, a keyboard class filter, a credential provider
with the password sign-in turned off) run on a lab VM, with a real sign-in attempt after each reboot.

## License

MIT. See [LICENSE](LICENSE).
