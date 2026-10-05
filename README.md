# Kill It With Fire

<!-- BRIAN: the opening warning goes here, in your words. The beats (2026-10-03): it removes ANY app, live
     or broken. The proper way is the default: the app's own uninstaller first, then whatever it left
     behind. KILL IT skips the uninstaller and scrubs the app out. Either way it scans first, backs
     everything up, and Restore puts it back; it never touches Microsoft software, security agents or
     Windows itself. -->

Removes a Windows app completely, the proper way or the hard way:

- **The proper way** (the default): the app's own uninstaller runs first, silently, and then whatever it
  left behind is cleaned up. For an MSI that is `msiexec /x`. For an EXE it is the app's registered quiet
  uninstall command, or the silent switch of the engine that built its uninstaller (NSIS, Inno Setup,
  WiX Burn, InstallShield, InstallAware), recognised from markers inside the uninstaller itself. An
  uninstaller with no known silent switch is skipped rather than left waiting for a click, and one that
  stops on a prompt nobody can see anyway (a "quiet" command that still asks Yes/No) is stopped after a
  minute of waiting on it, with the prompt's text in the log. The cleanup then does the rest.
- **KILL IT** (`-KillIt`, or KILL IT WITH FIRE in the window): skip the uninstaller and scrub the app out.
  For an uninstaller that is broken, hangs, or wants a click nobody is there to give.

What gets cleaned up: registration, services, drivers, device filters, network components, driver
packages, scheduled tasks, startup entries, COM, shell extensions, file associations, logon hooks,
firewall rules, shortcuts, folders and per-user state. Every item comes with the evidence that ties it
to the app, everything it changes is backed up first, and a whole run can be restored. (A restore puts
back what Kill It With Fire removed. After the proper way, the app's own uninstaller has already done
most of the work, so reinstall the app instead.)

## Levels

| Level | What it does |
|---|---|
| 0 | **Scan only.** Writes `plan.json` and `report.txt`. Changes nothing. The default. |
| 1 | **Uninstall.** Runs the app's own uninstaller once, silently (above). `-KillIt` skips it. |
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
reboot, `-Resume <runId>` confirms everything finished (exit 1, with the list, if a boot-time change
didn't happen: another reboot won't help then). Level 3 also stops the app's own programs still running
from its folder; a restore doesn't restart them.

`-Restore <runId>` undoes a run newest change first. If one change can't be undone (something new sits
where a file was, a service still waits on a reboot), the rest still comes back, except the logon
hooks, device filters, services, network components and drivers: those can depend on what failed, so
a failure among them stops the restore, and a failed file holds them back. A signed-in user's settings
are restored while that user is signed in; if they've signed out since, those wait. Either way the
restore exits 1 and says why. Fix the cause (or reboot, or have the user sign in), run `-Restore`
again, and it carries on with whatever is left.

## Run it

Elevated (admin or SYSTEM), Windows PowerShell 5.1 or PowerShell 7, 64-bit (a 32-bit host relaunches
itself in 64-bit PowerShell).

```powershell
.\KillItWithFire.ps1                                         # the window (below)
.\KillItWithFire.ps1 -List                                   # installed apps, to pick a target
.\KillItWithFire.ps1 -Name "Notepad++ (64-bit x64)"          # scan: the plan and the evidence
.\KillItWithFire.ps1 -ProductCode "{DDC95F26-92B1-4546-9678-5DC68DF76BA0}" -Level 2 -Force
.\KillItWithFire.ps1 -Name "Notepad++ (64-bit x64)" -Level 3 -Exclude Drivers -Force   # the proper way
.\KillItWithFire.ps1 -Name "Notepad++ (64-bit x64)" -KillIt -Force                      # the hard way
.\KillItWithFire.ps1 -ListRuns
.\KillItWithFire.ps1 -Restore 20260926-093000-1a2b3c -Force
.\KillItWithFire.ps1 -Resume 20260926-093000-1a2b3c
```

Without `-Force`, a run at level 1 or above prints the plan and asks you to type YES. `-Force` is for
unattended runs (RMM, PDQ, Intune).

| Switch | Meaning |
|---|---|
| `-Level 0..3` | How far to go (above). |
| `-Include` / `-Exclude` | Categories: `Registration`, `LogonHooks`, `Drivers`, `Services`, `Startup`, `ComShell`, `Other`, `Files`, `Registry`, `UserData`. |
| `-IncludeUserData` | Also move per-user AppData folders and settings. Off by default. |
| `-IncludeReview` | Also act on items tied only by vendor name, signer, or one MSI claim on a Windows file. Off by default. |
| `-KillIt` | The hard way: skip the app's own uninstaller and scrub it out (level 3). Still backed up and restorable. |
| `-SkipUninstall` | Go straight to the cleanup at level 2 (registration only) or 3. |
| `-NoBackup` | Change things without a backup (then the run can't be restored). |
| `-Log <file or folder>` / `-NoLog` | Where the log goes. Default: `log.txt` in the run folder. |
| `-Keyword <word>` | The app's own distinctive name, if the derived one is refused. |
| `-Plan <plan.json>` | Run a plan made earlier on this machine (within 24 hours). |
| `-ProfilePath <file.psd1>` | An extra per-app profile (below). |
| `-QuarantineDays <n>` | How long run backups are kept (default 14). |
| `-OutDir <folder>` | Where a scan writes `plan.json` and `report.txt`. |

Every run gets a folder under `%ProgramData%\KillItWithFire\runs\<runId>\`, readable by SYSTEM and
Administrators only: `run.json`, the plan and report, `journal.jsonl` (every change, in order),
`backups\` (`.reg` exports), `tasks\`, `drivers\` (exported driver packages) and `files\` (the
quarantine for drive C:; other drives keep theirs in `<drive>:\.killitwithfire\<runId>`).

| Exit code | Meaning |
|---|---|
| 0 | done (or plan written) |
| 3010 | done, but a reboot is needed to finish (after a run: then `-Resume`; after a restore: that's all) |
| 1 | stopped part way: the item that failed is in the report; `-Restore` undoes the rest. After a restore: not finished, run `-Restore` again |
| 2 | refused: policy, a protected product, an ambiguous name, or no confirmation |
| 3 | bad input, app not found, or not elevated |
| 4 | stopped on an unexpected error |

## The window

`.\KillItWithFire.ps1` with no arguments opens a Disk Cleanup-style window that runs in the order things
happen: 1, pick the app (search the list); 2, Scan it (nothing else is offered until it is scanned); 3,
choose how far to go (Uninstall, Registration cleanup, Full scrub or **KILL IT WITH FIRE**) and untick
categories (each shows its item count and size, and a description); 4, options; then Clean up. A scan
opens step 3 on Full scrub, the proper way: the app's own uninstaller still runs first. KILL IT WITH FIRE
skips the uninstaller and the button says "Kill it". Restore lists earlier runs. The window shows the
equivalent command line for every choice, and it does nothing the command line can't: every action runs
the same script as a child process with those switches.

## Locking options (Group Policy, Intune)

Values under `HKLM\SOFTWARE\Policies\KillItWithFire`. The engine enforces them (a switch past the policy is
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
- **A vendor folder holding another program.** An uninstall entry can name a whole vendor folder in which
  another program lives that never registered itself (Epic Games Launcher's names `C:\Program Files\Epic
  Games`, where Unreal Engine and the launcher's games are installed). For an app installed from an MSI,
  the scan knows the app's own folders and removes only those; the vendor folder stays.
  **For an app installed by an EXE it can't tell them apart: anything else inside that folder goes with
  it.** The scan notes a folder that looks like a container of programs (no program files of its own,
  programs in two or more subfolders), and the window shows the note in View items and again before a
  full scrub. Check the Files items before you clean up such an app.
- **Things that point at those folders or files:** services, drivers, tasks, Run keys, Active Setup,
  COM classes, shell extensions, context-menu verbs, file associations, credential providers, network
  providers, print monitors, firewall rules, shortcuts.
- **Weak ties are uncertain matches** and are left out unless `-IncludeReview` (in the window: "Also
  remove uncertain matches"): a driver tied only by the vendor
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
