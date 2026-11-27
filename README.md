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
| **x64** (recommended) | [`MyBrowser_v3.9.5_x64.7z`](https://github.com/drsamonline/MyChrome/releases/latest/download/MyBrowser_v3.9.3_x64.7z) | Windows 10 / 11, 64-bit |
| x86 | [`MyBrowser_v3.9.5.7z`](https://github.com/drsamonline/MyChrome/releases/latest/download/MyBrowser_v3.9.3.7z) | 32-bit systems |
| Source | `MyBrowser_v3.9.5_source.7z` | source, resources, build scripts |

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

Fourteen browsers, in three honest tiers. "Wired" means the launcher resolves a version
from the vendor's own feed and installs the build itself.

| Browser | Engine | Status | Source used |
| --- | --- | --- | --- |
| **Chrome** | Chromium | ✅ Wired — verified | Chrome for Testing (Stable / Beta / Dev / Canary) |
| **Chromium** | Chromium | ✅ Wired — verified | `chromium-browser-snapshots` (`chrome-win.zip`) |
| **Brave** | Chromium | ✅ Wired — verified | Official release ZIP, GitHub |
| **Firefox** | Gecko | ✅ Wired — verified | Mozilla release feed (Release / ESR / Beta / Dev / Nightly) |
| **Vivaldi** | Chromium | ✅ Wired — verified (3.9.5) | Sparkle appcast, x64 and x86 |
| **Edge** | Chromium | ⚠️ Wired — unverified | Microsoft CDP API |
| **Cent Browser** | Chromium | ⚠️ Wired — unverified | Vendor download page |
| **ungoogled-chromium** | Chromium | 🔜 Not wired — archive inspected | GitHub release ZIP, `chrome.exe` in one folder |
| **Supermium** | Chromium (Win 7+) | 🔜 Not wired — archive inspected | GitHub release ZIP, flat `chrome.exe` |
| **Thorium** | Chromium | 🔜 Not wired | GitHub releases, Windows ZIP |
| **LibreWolf** | Gecko | 🔜 Not wired | Installer only |
| **Floorp** | Gecko | 🔜 Not wired | Installer only |
| **Waterfox** | Gecko | 🔜 Not wired | Installer only |
| **Opera / Opera GX** | Chromium | ❌ No portable build | Installer only, no portable ZIP published |
| **Yandex Browser** | Chromium | ❌ No portable build | Installer only |
| **Naver Whale** | Chromium | ❌ No portable build | Installer only |
| **Pale Moon / Basilisk** | Goanna | ❌ Not supported | Own packaging, not Chromium or Firefox shaped |

Legend: ✅ wired and checked against the live feed · ⚠️ wired, source could not be verified
from the build environment · 🔜 archive layout confirmed, wiring is open work
([ROADMAP](ROADMAP.md) G2) · ❌ no portable artifact to download.

Adding a browser is not just a URL: each one needs a source function, an archive-shape
branch in `INSTALLCHROME()` and a settings branch. The roadmap tracks the ones whose
archives are already confirmed.

## Requirements

- Windows 10 or Windows 11 (x64 or x86)
- ~1.5 GB free disk space per browser while updating
- No runtime, no .NET, no Visual C++ redistributable — the executable is self-contained

## What's new in 3.9.5

- **Vivaldi actually downloads now.** It used to point at a link hub page, which is not a
  download — the version resolved empty and the update aborted. It now reads Vivaldi's
  Sparkle appcast for x64 and x86 and installs the real build.
- **Browser matrix** in the README and on the landing page, with three honest tiers
  instead of one flat list.
- **Support block** added, matching the rest of the fleet.
- Repo docs rewritten to describe this as a standalone project with an explicit lineage
  section, rather than as a fork of a repository that contained no code.

Earlier: **3.9.4** fixed "No" disabling update checks permanently and added
`MyBrowser.log`. **3.9.3** removed hardcoded Google API credentials, dropped
`--no-sandbox` from the defaults, fixed command injection in the injection path, added
the archive integrity test and `SHA256SUMS.txt`.

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
| [`PRIVACY.md`](PRIVACY.md) | exactly what is sent where, what the log holds, and how to check it |
| [`licenses/`](licenses/) | terms for the bundled 7-Zip, MozLz4 and other binaries |

## Known limits

- **Edge, Vivaldi and Cent are not verified end to end.** Edge uses a Microsoft endpoint
  that could not be reached from the build environment; Vivaldi and Cent have no binary
  source in the code at all — those menu entries open a download page.
- **GreenChrome / Chrome++ injection is untested on current Chrome.** It is off by
  default and the launcher works without it.
- **The executable is not Authenticode-signed** — the hook is in CI, it needs a
  certificate secret to activate ([ROADMAP](ROADMAP.md) C1).
- The UI has been compiled and structurally verified on Windows CI, but not exercised
  by hand on a desktop.

## Contributing

Bug reports are welcome — please include the version from the settings dialog, your
Windows build, the browser and channel, and the exact error text. Security issues go
through [`SECURITY.md`](SECURITY.md), not the public issue tracker.

Before opening a pull request, run `./build/build.ps1` and `./build/smoke.ps1`; CI runs
both.

<!-- support:sweep -->
## Support

| | |
|---|---|
| UPI (India) | `drsohilboi@ybl` — payee Dr Sohil Momin, open amount |
| GitHub Sponsors | [github.com/sponsors/drsamonline](https://github.com/sponsors/drsamonline) |
| Ko-fi | [ko-fi.com/matneo](https://ko-fi.com/matneo) |
| PayPal | [paypal.me/drsohilmomin](https://paypal.me/drsohilmomin?locale.x=en_GB&country.x=IN) |
| My books | [Amazon author store](https://www.amazon.com/stores/author/B08ZT331LY/allbooks?ccs_id=aed72b9f-71d9-41dc-adee-e9368a317acc) |
| More apps | [drsamonline.github.io](https://drsamonline.github.io/) |
| Email | [sohilmomin2000@gmail.com](mailto:sohilmomin2000@gmail.com) |

Nothing is gated behind it: no accounts, no telemetry, no tracking, no "pro" build.

## Licence

GPL-3.0 — see [`LICENSE`](LICENSE) and [`NOTICE`](NOTICE). The complete corresponding
source for every release is in this repository and attached to each release as
`MyBrowser_v3.9.5_source.7z`.

## Lineage

This project stands on its own: the source, the build, the CI, the landing page and the
release pipeline are all here, and nothing is fetched from another repository at build
time. Where the code came from matters, so:

| | |
| --- | --- |
| **Original code** | [cnjackchen/my-chrome](https://github.com/cnjackchen/my-chrome) — GPL-3.0, the AutoIt launcher this is derived from |
| **Binary lineage** | [xixiranran/MyChrome](https://github.com/xixiranran/MyChrome) — published the 3.8.x line as MyBrowser; the source in `src/` was recovered from its 3.8.50 release, which shipped binaries only |
| **This fork** | maintained here since 3.9.0: Chrome for Testing migration, repaired Firefox / Chromium / Brave / Vivaldi sources, security fixes, build and release automation |

Because the upstream is GPL-3.0, this derivative stays GPL-3.0. The full attribution
chain, including the bundled third-party binaries, is in [`NOTICE`](NOTICE).

Chrome, Chromium, Edge, Brave, Firefox, Vivaldi and every other browser named above are
downloaded from their vendors at runtime and are not redistributed here. No vendor logo
or trademark is used to imply endorsement.
