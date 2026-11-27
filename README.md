# MyBrowser (MyChrome fork) — 3.9.0

Portable multi-browser launcher for Windows. Downloads a browser build, unpacks it
into its own folder, and runs it with its own profile — no installer, no registry,
no admin rights. Chrome, Chromium, Edge, Brave, Firefox, Vivaldi and Cent.

This fork keeps the app working with **current Chrome**. Chrome stable at the time of
this release is 158.0.8127.88.

- **Download:** [Releases](https://github.com/drsamonline/MyChrome/releases)
- **Landing page:** [drsamonline.github.io/MyChrome](https://drsamonline.github.io/MyChrome/)
- **Upstream project:** [xixiranran/MyChrome](https://github.com/xixiranran/MyChrome)

## What changed in 3.9.0

| Change | Why |
| --- | --- |
| Chrome now comes from the official **Chrome for Testing** feed (`last-known-good-versions-with-downloads.json`) | The old path asked Google's Omaha update service for an installer and then had to unpack it. Google now serves a 536 MB "uncompressed" installer there, and the unpack step is what kept breaking. Chrome for Testing gives a direct `chrome-win64.zip` / `chrome-win32.zip` per channel. |
| Direct ZIP install path | The archive is extracted straight into the browser folder — no nested `chrome.7z`, no `Chrome-bin` version guessing. Roughly 170 MB instead of 536 MB per update. |
| Omaha kept as fallback | If the Chrome for Testing feed is unreachable, the old installer path still runs. |
| Full source published | Upstream ships binaries only. `src/MyBrowser.au3` is the complete AutoIt source, so the app can be built and maintained from this repo. |
| Reproducible build | `build/build.ps1` plus a GitHub Actions workflow compile both architectures with AutoIt3 3.3.16.1 and package the `.7z` assets. |
| Update endpoints point here | `update.txt` and the in-app updater now resolve to this fork. |

Channels: Stable, Beta, Dev, Canary. Architectures: x64 and x86.

## Build

Windows with PowerShell 7, or let GitHub Actions do it (`Actions → build → Run workflow`).

```powershell
./build/build.ps1
```

The script downloads the AutoIt3 SDK, copies `resources/` next to the script for
`FileInstall()`, runs `Au3Check`, compiles x64 and x86, and writes the release
archives to `dist/`.

Pushing a `v*` tag attaches both archives to a GitHub release.

## Layout

```
src/MyBrowser.au3      application source (AutoIt3)
resources/             files embedded into the exe at compile time
build/build.ps1        build and packaging
docs/                  landing page published to gh-pages
update.txt             self-update manifest read by the app
```

## Notes

- Chrome for Testing builds have no Google Update, no crash-reporter service and no
  installer — which is exactly what a portable launcher wants.
- The optional GreenChrome / Chrome++ DLL injection still ships and is off unless you
  enable it. On very new Chrome builds, run without injection first if the browser
  refuses to start; the launcher works fine without it.
- Windows Defender sometimes flags unpacked portable browser launchers. The exe is
  unsigned, as before.

## Credits

Original MyChrome / MyBrowser by [xixiranran](https://github.com/xixiranran/MyChrome).
GreenChrome, 7-Zip, MozLz4 and MouseInc are bundled under their own licences.
