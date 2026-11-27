# Architecture

How a browser gets from a vendor to a folder on disk.

```
settings dialog
      │  pick browser / channel / arch
      ▼
UPDATECHROME()                       src/MyBrowser.au3
      │
      ├─ GET_LATEST_CHROME_VER()  ── resolve version + download URL
      │     ├─ Chrome     → _CFT_GETLATEST()      Chrome for Testing JSON
      │     │              └ fallback: Google Omaha (tools.google.com), https mirrors only
      │     ├─ Chromium   → chromium-browser-snapshots/<arch>/LAST_CHANGE
      │     ├─ Brave      → _BRAVE_GITHUB_LATEST() → release ZIP
      │     │              └ fallback: Omaha (updates.bravesoftware.com)
      │     ├─ Firefox    → _MOZILLA_FIREFOX_VER() + download.mozilla.org
      │     ├─ Edge       → Microsoft CDP API
      │     └─ Cent/Vivaldi → a download page link, not a binary
      │
      ├─ DOWNLOAD_CHROME()  ── segmented download, 3 threads, resume, proxy aware
      │        writes App\~update\installer.exe
      │
      ├─ INSTALLCHROME()   ── unpack and normalise
      │     ├─ 7z t      integrity test (3.9.3+)
      │     ├─ 7z x      extract to App\~update\
      │     ├─ detect    Chrome for Testing: chrome-win64\ / chrome-win32\
      │     │            Chromium:          chrome-win\
      │     │            Brave ZIP:         brave.exe at archive root
      │     │            installers:        Chrome-bin\ , chrome.7z , MSEDGE.7z , core\
      │     ├─ normalise to App\~updated\
      │     └─ verify    App\~updated\<exe> exists before going further
      │
      └─ APPLYUPDATE()    ── copy App\~updated\ over the browser folder
            ├─ guard   refuse if the tree is incomplete
            ├─ copy
            ├─ inject  optional GreenChrome / Chrome++ (off by default)
            └─ clean   remove ~updated, ~update, 7z.exe, 7z.dll
```

## Why it looks like this

**Resolve, then download, then extract, then swap.** Each stage can fail on its own and
each failure has a different cause. Keeping them separate is what lets 3.9.x report
"the package is corrupt" instead of a generic extraction error.

**Chrome for Testing over the Omaha installer.** Google's update service still answers,
but it now returns a 536 MB *uncompressed* installer that has to be unpacked. Chrome for
Testing publishes a direct ZIP per channel, roughly 170 MB, and the ZIP contains the
browser in a single folder. That removed the step that kept breaking.

**Every source keeps a fallback.** Chrome falls back to Omaha, Brave to its own Omaha
endpoint. A vendor feed outage should degrade, not fail.

**The extract step is the fragile one.** Vendor packaging changes without notice: a ZIP
one release, a self-extracting 7z the next. The detection chain in `INSTALLCHROME()` is
deliberately a list of shapes rather than a single assumption, and `_ZIPBROWSERDIR()`
covers any archive that puts the executable in one subfolder.

## Threading

AutoIt has no real threads. `_STARTTHREAD()` relaunches the same executable with
`child_thread_by <hwnd> <function> <args>`, and the parent polls a shared variable
(`DLInfo`) that the child updates as it progresses. Long operations — version lookup,
download — run in those child processes so the GUI stays responsive. `ENDUPDATE()` and
`_KILLTHREAD()` terminate them by pid.

## Files on disk

| Path | Contents |
| --- | --- |
| `MyBrowser.exe` | the launcher, with `resources/` embedded by `FileInstall()` |
| `MyBrowser.ini` | all settings |
| `App\` | the browser, by default |
| `App\~update\` | transient: downloaded package and extraction scratch |
| `App\~updated\` | transient: the verified tree waiting to be copied into place |

Both transient folders are removed on success and on failure (3.9.2+).

## Build and release

`build/build.ps1` downloads the AutoIt3 SDK, copies `resources/` next to the source for
`FileInstall()`, runs `Au3Check`, compiles x64 and x86, packages both archives with
`MyBrowser.exe` at the archive root (the self-updater looks for that exact name) and
writes `SHA256SUMS.txt`.

`.github/workflows/build.yml` runs that on every push, then `build/smoke.ps1`, which
checks every download source and starts both binaries to prove they stay alive. A `v*`
tag attaches the archives and the checksums to a release.

## Known structural debt

- `src/MyBrowser.au3` is one 6,900-line file because the 3.8.50 binary was compiled from
  flattened source. The original upstream project kept UDFs in separate includes; see
  `ROADMAP.md` H1.
- The version string lives in the `.au3` and both language files. `build.ps1` fails the
  build if they disagree.
