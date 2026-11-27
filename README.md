<div align="center">

# MyBrowser

**Portable browser launcher for Windows.** Downloads a browser, unpacks it beside the
executable and runs it with its own profile. No installer, no registry, no admin rights —
delete the folder to uninstall.

[![Release](https://img.shields.io/github/v/release/drsamonline/MyChrome?style=flat-square&label=release&color=e04b12)](https://github.com/drsamonline/MyChrome/releases)
[![Downloads](https://img.shields.io/github/downloads/drsamonline/MyChrome/total?style=flat-square&color=e04b12)](https://github.com/drsamonline/MyChrome/releases)
[![Build](https://img.shields.io/github/actions/workflow/status/drsamonline/MyChrome/build.yml?style=flat-square&label=build)](https://github.com/drsamonline/MyChrome/actions/workflows/build.yml)
[![License](https://img.shields.io/github/license/drsamonline/MyChrome?style=flat-square&color=e04b12)](LICENSE)
[![Platform](https://img.shields.io/badge/platform-Windows%2010%20%7C%2011-0078D6?style=flat-square)](#requirements)

[![Chrome](https://img.shields.io/badge/Chrome%20for%20Testing-158.0.8127.88-4285F4?style=flat-square)](https://googlechromelabs.github.io/chrome-for-testing/)
[![AutoIt](https://img.shields.io/badge/AutoIt-3.3.16.1-1B6B93?style=flat-square)](https://www.autoitscript.com/)
[![Landing page](https://img.shields.io/badge/landing%20page-drsamonline.github.io-e04b12?style=flat-square)](https://drsamonline.github.io/MyChrome/)

**[Download](https://github.com/drsamonline/MyChrome/releases/latest)** ·
[Landing page](https://drsamonline.github.io/MyChrome/) ·
[What changed](https://github.com/drsamonline/MyChrome/releases) ·
[Roadmap](ROADMAP.md) ·
[Architecture](docs/ARCHITECTURE.md)

</div>

---

## Download

| Build | File | Notes |
| --- | --- | --- |
| **x64** (recommended) | [`MyBrowser_v3.9.3_x64.7z`](https://github.com/drsamonline/MyChrome/releases/latest/download/MyBrowser_v3.9.3_x64.7z) | Windows 10 / 11, 64-bit |
| x86 | [`MyBrowser_v3.9.3.7z`](https://github.com/drsamonline/MyChrome/releases/latest/download/MyBrowser_v3.9.3.7z) | 32-bit systems |
| Source | `MyBrowser_v3.9.3_source.7z` | source, resources, build scripts |

Unzip, run `MyBrowser.exe`, pick a browser and channel. Each release publishes
`SHA256SUMS.txt`; verify with `certutil -hashfile <file> SHA256`.

The executable is unsigned, so Windows may warn on first run.

## What it does

```
resolve the current build  →  download it  →  extract it beside the exe  →  run it
```

It asks the vendor's own feed what the current build is, downloads it in segments with
resume, extracts it into `App\`, and starts it with a profile folder of your choosing.
Nothing touches the registry, and no elevation is needed.

## Browsers

| Browser | Source | Status |
| --- | --- | --- |
| **Chrome** | Chrome for Testing (Stable / Beta / Dev / Canary) | Verified |
| **Chromium** | Chromium snapshot `chrome-win.zip` | Verified |
| **Brave** | Official release ZIP (Release / Beta / Dev / Nightly) | Verified |
| **Firefox** | Mozilla release feed (Release / ESR / Beta / Dev / Nightly) | Verified |
| **Edge** | Microsoft CDP API | Legacy path, not verified here |
| **Vivaldi** | Download page link | Link only — no binary download |
| **Cent** | Download page link | Link only — no binary download |

"Verified" means the source was checked against the live feed during development and the
archive layout matches what the installer expects. It does not mean every Windows
configuration was tested; see [Known limits](#known-limits).

## Requirements

- Windows 10 or Windows 11 (x64 or x86)
- ~1.5 GB free disk space per browser while updating
- No runtime, no .NET, no Visual C++ redistributable — the executable is self-contained

## What's new in 3.9.3

- **Hardcoded Google API credentials removed.** The upstream build shipped a Google API
  key, OAuth client id and client secret as literals and wrote them into your environment
  with `setx`. This fork does not redistribute them.
- **`--no-sandbox` is no longer a default.** It disabled the renderer sandbox on every
  launch. Add it back in Settings → Params only if you must, and know what it costs.
- **Archive integrity is checked before extraction**, so a truncated download reports
  itself instead of failing inside the unpack step.
- **Command quoting fixed.** Folder paths with spaces or `&` no longer break the DLL
  injection step or inject a second command into `cmd.exe`.
- **DPI awareness** — the UI is no longer blurry at 125% scaling.
- **`SHA256SUMS.txt`** published with every release.

Full history: [releases](https://github.com/drsamonline/MyChrome/releases).

## Build

Requires Windows with PowerShell 7, or use the CI workflow
(`Actions → build → Run workflow`).

```powershell
git clone https://github.com/drsamonline/MyChrome
cd MyChrome
./build/build.ps1     # downloads the AutoIt3 SDK, checks syntax, compiles x64 + x86, packages
./build/smoke.ps1     # checks every download source and starts both binaries
```

Output lands in `dist/`: two `.7z` archives and `SHA256SUMS.txt`. Pushing a `v*` tag
attaches them to a GitHub release.

## Project layout

```
src/MyBrowser.au3        application source (AutoIt3, single file — see ROADMAP H1)
resources/               files embedded into the exe at compile time
build/build.ps1          build and packaging
build/smoke.ps1          source and binary smoke test
docs/                    landing page (published to gh-pages) and ARCHITECTURE.md
licenses/                licence texts for bundled third-party binaries
update.txt               self-update manifest read by the app
```

## Documentation

| Document | What is in it |
| --- | --- |
| [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) | how the resolve → download → extract → swap pipeline works |
| [`ROADMAP.md`](ROADMAP.md) | 80-item enhancement list with priority, effort and risk |
| [`SECURITY.md`](SECURITY.md) | how to report a vulnerability, scope, accepted risks |
| [`PRIVACY.md`](PRIVACY.md) | exactly what is sent where — and how to check it |
| [`licenses/`](licenses/) | terms for the bundled 7-Zip, MozLz4 and other binaries |

## Known limits

- **Edge, Vivaldi and Cent are not verified end to end.** Edge uses a Microsoft endpoint
  that could not be reached from the build environment; Vivaldi and Cent have no binary
  source in the code at all — those menu entries open a download page.
- **GreenChrome / Chrome++ injection is untested on current Chrome.** It is off by
  default and the launcher works without it.
- **The executable is not Authenticode-signed** yet ([ROADMAP](ROADMAP.md) C1).
- The UI has been compiled and structurally verified on Windows CI, but not exercised
  by hand on a desktop.

## Contributing

Bug reports are welcome — please include the version from the settings dialog, your
Windows build, the browser and channel, and the exact error text. Security issues go
through [`SECURITY.md`](SECURITY.md), not the public issue tracker.

Before opening a pull request, run `./build/build.ps1` and `./build/smoke.ps1`; CI runs
both.

## Licence

GPL-3.0 — see [`LICENSE`](LICENSE) and [`NOTICE`](NOTICE).

This is a derivative of [cnjackchen/my-chrome](https://github.com/cnjackchen/my-chrome)
(GPL-3.0). The 3.8.x line was published as MyBrowser by
[xixiranran](https://github.com/xixiranran/MyChrome), from whose 3.8.50 release the
source in `src/` was recovered. Bundled third-party components keep their own terms —
see [`licenses/`](licenses/).

Chrome, Chromium, Edge, Brave, Firefox, Vivaldi and Cent are downloaded from their
vendors at runtime and are not redistributed here.
