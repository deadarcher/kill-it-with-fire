# Leftovers

<!-- BRIAN: the opening warning goes here, in your words. The beat: this is for an app whose uninstall is
     ALREADY broken. If msiexec /x or the vendor's uninstaller still works, use that. Leftovers is the
     second attempt, not the first. -->

Finds everything a broken Windows app left behind (registration, services, drivers, device filters,
network components, driver packages, scheduled tasks, startup entries, COM, shell extensions, file
associations, logon hooks, firewall rules, shortcuts, folders, per-user state) and writes a plan with
the evidence for every item.

**Version 0.1 is report-only (level 0).** Nothing on the machine is changed. The levels that act on the
plan are being built and validated in a lab first.

## Run it

Elevated (admin or SYSTEM), Windows PowerShell 5.1 or PowerShell 7:

```powershell
.\Leftovers.ps1 -List                                  # installed apps, to pick a target
.\Leftovers.ps1 -Name "Notepad++ (64-bit x64)"         # exact name from the list
.\Leftovers.ps1 -ProductCode "{DDC95F26-92B1-4546-9678-5DC68DF76BA0}"   # an MSI, even with no uninstall entry left
```

It writes `plan.json` (every item, machine-readable) and `report.txt` to
`%ProgramData%\Leftovers\reports\<runId>\`, or to `-OutDir`.

| Exit code | Meaning |
|---|---|
| 0 | plan written |
| 2 | refused: a protected product (Microsoft, a security product, the RFF agent) or an ambiguous name |
| 3 | bad input, app not found, or not elevated |
| 4 | stopped on an unexpected error; no plan was written |

## How it decides what belongs to the app

Identity first, never name first:

- **The app's own registration:** its uninstall entry, its Windows Installer ProductCode, UpgradeCode
  and components, and the files its MSI says it owns.
- **Its folders**, from its own registration. A folder that another installed product also points into
  is **shared**: inside it only the app's own files count, and the folder itself is never planned for
  removal.
- **Things that point at those folders or files:** services, drivers, tasks, Run keys, COM classes,
  shell extensions, file associations, credential providers, firewall rules, shortcuts.
- **Drivers outside the app's folders** (like `System32\drivers\npcap.sys`) are tied by the vendor named
  in the file's own version resource. That is weaker evidence, so it is labelled. It needs review when
  the vendor has other products installed.
- **A keyword** (the app's own distinctive name) only ever narrows a match. It is refused when it names
  another installed product or matches much outside the app. "Drive" is refused on a machine with a
  floppy driver; "Adobe" is refused when Acrobat and Creative Cloud are both installed.

Never touched:

- Microsoft software.
- Security products. Use the vendor's removal tool; the report names it.
- The RFF agent.
- Anything under `C:\Windows` except this product's own cached MSI and icon folder.
- Signed-out users' registry hives. They are never loaded in this version, and the report lists those
  profiles.

## Tests

```powershell
powershell -NoProfile -File tests\Run-Tests.ps1
pwsh -NoProfile -File tests\Run-Tests.ps1
```

No dependencies. They include a read-only check that the packed-GUID conversion names real
`Installer\Products` keys on the machine you run them on.

## License

MIT. See [LICENSE](LICENSE).
