# Roadmap and enhancement list

Everything below was derived from reading `src/MyBrowser.au3` (the recovered 3.8.50
source, now maintained here) and from testing the live vendor feeds. Items marked
**verified** were confirmed against a live endpoint during this work; items marked
**code finding** come from reading the source and were not exercised at runtime.

How to read the columns:

- **P** — priority. P0 = correctness/security, P1 = user-visible quality, P2 = polish, P3 = optional.
- **Eff** — effort. S = under a day, M = a few days, L = a week or more.
- **Risk** — chance of breaking something that works today.

---

## Shipped so far

| Item | Shipped in |
| --- | --- |
| A1 — archive integrity test before extraction | 3.9.3 |
| A5 — https-only mirrors on the fallback path | 3.9.2 |
| B1 — pre-flight check before applying (partial) | 3.9.2 |
| B5 — temp cleanup on failure and success (partial) | 3.9.2 |
| C2 — `SHA256SUMS.txt` per release | 3.9.3 |
| C3 — `--no-sandbox` removed from the defaults | 3.9.3 |
| C5 — injection off by default and labelled | 3.9.x |
| E2 — DPI awareness | 3.9.3 |
| H2 — build fails if the version drifts (partial) | 3.9.3 |
| H3 — `docs/ARCHITECTURE.md` | 3.9.3 |
| I1 — smoke test in CI (partial: sources + launch) | 3.9.3 |
| K1 — GPL-3.0 `LICENSE` and `NOTICE` | 3.9.1 |
| K2 — `licenses/` with third-party terms | 3.9.3 |

Plus two findings that were not on the original list:

- **Hardcoded Google API credentials** — an API key, an OAuth client id and a client
  secret were compiled into the binary and written into the user's environment with
  `setx`. Removed in 3.9.3.
- **Unquoted `cd <dir>&cmd`** in the DLL-injection path: a folder name containing a space
  or `&` broke it, and `&` injected a second command into `cmd.exe`. Quoted in 3.9.3.

## A. Download integrity and correctness

| # | Item | Why | P | Eff | Risk |
| --- | --- | --- | --- | --- | --- |
| A1 | Verify archive integrity (`7z t`) before extraction | A truncated 170 MB ZIP currently fails deep inside extraction with a generic message | P0 | S | Low |
| A2 | Compare `Content-Length` against bytes received before unpacking | Catches silent truncation the segmented downloader can mask | P0 | S | Low |
| A3 | Confirm extracted `chrome.exe` FileVersion equals the requested version | Detects a vendor feed serving a stale or wrong package | P1 | S | Low |
| A4 | Keep a last-known-good version string in the ini | If every source is down, the UI can still show "latest known" instead of an error | P1 | S | Low |
| A5 | Reject plain-http mirrors | **Done in 3.9.2** — the Omaha manifest lists `http://edgedl…` first and it was being tried first | P0 | S | Low |
| A6 | Cache the Brave version for 24 h | The GitHub API allows 60 unauthenticated requests per hour per IP; a shared NAT can exhaust it | P1 | S | Low |
| A7 | Retry 5xx with exponential backoff | Today it retries three times immediately, which usually hits the same failure | P1 | S | Low |
| A8 | Handle HTTP 416 (range not satisfiable) on resume | A stale `.part` file can wedge the resume loop | P2 | S | Low |
| A9 | Verify vendor hashes where published | Omaha packages carry `hash_sha256`; Chrome for Testing publishes none, so this only helps the fallback path | P2 | M | Low |

## B. Update engine

| # | Item | Why | P | Eff | Risk |
| --- | --- | --- | --- | --- | --- |
| B1 | Atomic swap: extract to `App.new`, rename `App`→`App.old`, swap, delete old | Today `APPLYUPDATE` copies over the live folder; a mid-copy failure leaves a broken browser. **Partially mitigated in 3.9.2** (pre-flight check only) | P0 | M | Medium |
| B2 | Roll back automatically if the new build fails to start | Pairs with B1: keep `App.old` until the browser has run once | P1 | M | Medium |
| B3 | Verify the profile folder is never inside the replaced directory | A profile inside `App\` would be deleted by B1 | P1 | S | Low |
| B4 | "Skip this version" instead of only "don't prompt again" | The current opt-out is permanent; users want to skip one bad release | P1 | S | Low |
| B5 | Clean stale `~update` / `~updated` on startup | **Partly done in 3.9.2**; a crash can still leave several hundred MB behind | P1 | S | Low |
| B6 | Deterministic cancel | Cancel sets a flag; the child download process is killed by pid and can race | P1 | M | Medium |
| B7 | Show speed and ETA, not just a percentage | The status bar shows percent only | P2 | S | Low |
| B8 | Background check with a notification | Every check today is a modal dialog | P2 | M | Low |
| B9 | Update history log (what was installed, when) | Useful for support and for B2 | P2 | S | Low |
| B10 | Concurrent-instance lock | `CHROMEISUPDATING` exists but is file-based and race-prone | P2 | S | Low |

## C. Security and trust

| # | Item | Why | P | Eff | Risk |
| --- | --- | --- | --- | --- | --- |
| C1 | Authenticode-sign the executable | Unsigned portable browser launchers get flagged by Defender and SmartScreen. Biggest trust win available | P0 | M | Low |
| C2 | Publish `SHA256SUMS` per release | Lets users verify what they downloaded | P1 | S | Low |
| C3 | Stop passing `--no-sandbox` by default | **Code finding:** the default params disable the renderer sandbox. That is a real security downgrade for a browser; make it opt-in with a warning | P0 | S | Low |
| C4 | Reconsider `--test-type` | It suppresses the "unsupported flag" infobar, which also hides the fact that flags are in use | P2 | S | Low |
| C5 | Treat GreenChrome/Chrome++ injection as advanced | It patches `chrome.exe` imports; on current Chrome this is the least predictable part of the app. Keep it off by default (it is) and label it | P1 | S | Low |
| C6 | Build provenance attestation (`actions/attest-build-provenance`) | Ties the published binary to the commit that produced it | P2 | S | Low |
| C7 | Optional VirusTotal link in release notes | Users ask; a scan link is cheap | P3 | S | Low |
| C8 | Document that no telemetry is sent | The app talks only to vendor endpoints; say so explicitly | P2 | S | Low |

## D. Performance and footprint

| # | Item | Why | P | Eff | Risk |
| --- | --- | --- | --- | --- | --- |
| D1 | Strip unreferenced UDFs | The recovered source inlines every UDF the original compiler pulled in; `Au3Check -v 3` lists them. The exe is 4.4 MB | P2 | M | Medium |
| D2 | Split the 6,900-line file into includes | See H1 | P2 | M | Medium |
| D3 | Adaptive segment count | Fixed at 3 threads; a slow link does better with more, a fast one with fewer | P3 | M | Low |
| D4 | Keep the previous build for instant rollback | Costs disk, saves a 170 MB re-download after a bad update | P3 | M | Low |

## E. User experience

| # | Item | Why | P | Eff | Risk |
| --- | --- | --- | --- | --- | --- |
| E1 | First-run wizard | The settings dialog assumes you already know what "GC injection" and "channel" mean | P1 | M | Low |
| E2 | DPI awareness | **Code finding:** no DPI manifest, so the UI is blurry on scaled displays | P1 | S | Low |
| E3 | Move hardcoded Chinese strings into the language files | Many `LANG(...)` defaults are inline Chinese; translators can only reach the ini | P1 | M | Low |
| E4 | More languages (ja, ko, es, pt-BR, ru) | Currently zh-TW and en-US | P2 | M | Low |
| E5 | Error dialogs with "copy details" | Users cannot report what failed | P1 | S | Low |
| E6 | Installed vs latest version side by side, with an Update button | Today it is split across a label and a menu item | P1 | S | Low |
| E7 | Remember window position and size | | P2 | S | Low |
| E8 | Multiple profiles per browser | The portable case often wants work/personal split | P2 | M | Low |
| E9 | Keyboard navigation and accessible names | AutoIt dialogs are usually mouse-only | P2 | M | Low |
| E10 | Progress in the taskbar button | More visible than a tray balloon | P3 | S | Low |

## F. Portability and automation

| # | Item | Why | P | Eff | Risk |
| --- | --- | --- | --- | --- | --- |
| F1 | CLI mode: `/update chrome /channel stable /arch x64 /silent` | Lets people script updates; also makes CI smoke tests possible (see I2) | P1 | M | Low |
| F2 | Scoop manifest | The natural distribution channel for portable Windows tools | P2 | S | Low |
| F3 | winget manifest | | P2 | S | Low |
| F4 | ARM64 build | Chrome for Testing ships `win-arm64`; the launcher does not | P2 | M | Low |
| F5 | Fully portable settings (no `%APPDATA%` writes) | Audit and document every write outside the app folder | P2 | S | Low |

## G. Browser coverage

| # | Item | Why | P | Eff | Risk |
| --- | --- | --- | --- | --- | --- |
| G1 | Real source for Edge | **Code finding:** the Edge path uses `MSXML2.XMLHTTP`, which ignores the app's own proxy setting. It is also the one path not verified here (TLS failure from the build sandbox) | P0 | M | Medium |
| G2 | Real source for Vivaldi | Today it opens a link hub, not a download. Vivaldi publishes `download.vivaldi.com/stable/Vivaldi.<ver>.Stable.x64.exe`; the version comes from their appcast XML | P1 | M | Low |
| G3 | Real source for Cent | Same as G2 — currently a link only | P2 | M | Low |
| G4 | Chrome Extended Stable channel | Chrome for Testing exposes it; the app does not | P2 | S | Low |
| G5 | A "Chrome 109 for Windows 7/8" option | Last Chrome that runs there; a portable launcher is the natural way to keep it | P3 | M | Low |
| G6 | Warn if win32 Chrome is retired | Chrome for Testing still publishes `win32`; if that stops, the x86 option must fail loudly rather than silently | P2 | S | Low |
| G7 | Firefox ESR/Dev channel naming check | The app maps `Dev` to the devel feed; verify it matches Mozilla's naming over time | P3 | S | Low |

## H. Maintainability and build

| # | Item | Why | P | Eff | Risk |
| --- | --- | --- | --- | --- | --- |
| H1 | Restore the include-based structure | `cnjackchen/my-chrome` ships `WinHttp.au3`, `WinHttpConstants.au3`, `SimpleMultiThreading.au3` separately. The recovered 3.8.50 source has them inlined, which is why one file is 6,900 lines | P1 | M | Medium |
| H2 | Single source of truth for the version | It lives in `src/MyBrowser.au3`, two `.ini` files and `update.txt` | P1 | S | Low |
| H3 | `docs/ARCHITECTURE.md` | The update pipeline (resolve → download → extract → swap) is only discoverable by reading code | P1 | S | Low |
| H4 | Fail CI on Au3Check warnings | Today only errors fail the build | P2 | S | Low |
| H5 | Changelog generated from commits | Release notes are written by hand | P2 | S | Low |
| H6 | Pin the AutoIt SDK version and cache it | Every run re-downloads 12 MB; pinning also makes builds reproducible | P2 | S | Low |
| H7 | `.editorconfig` and a formatting pass | Mixed tabs/spacing in places | P3 | S | Low |

## I. Testing and QA

| # | Item | Why | P | Eff | Risk |
| --- | --- | --- | --- | --- | --- |
| I1 | Smoke test in CI on a Windows runner | Download one channel, launch it headless with `--version`, assert the version string. This is the single highest-value test | P0 | M | Medium |
| I2 | `--selftest` flag that probes every source and prints pass/fail | Turns "is it broken?" into one command | P1 | S | Low |
| I3 | Fault injection: proxy that drops mid-download | The resume path is the least tested code in the app | P2 | M | Low |
| I4 | Matrix: Win10/Win11 × x64/x86 × each browser | Only Chrome and Chromium are verified end to end today | P2 | L | Low |
| I5 | Upgrade test from 3.8.50 → current | Proves the in-app updater still works across the fork boundary | P1 | S | Low |

## J. Distribution

| # | Item | Why | P | Eff | Risk |
| --- | --- | --- | --- | --- | --- |
| J1 | Enable GitHub Pages | The landing page is committed to `gh-pages` but Pages is not switched on; it needs one click in Settings | P0 | S | Low |
| J2 | Mirror releases for mainland China | GitHub asset downloads are slow or blocked there, which is a large part of this app's audience | P1 | M | Low |
| J3 | Issue templates and a support doc | "Chrome download failed" reports need the version, channel and log | P2 | S | Low |
| J4 | Release notes in Chinese as well as English | The audience is bilingual; the app already ships both languages | P2 | S | Low |

## K. Licensing

| # | Item | Why | P | Eff | Risk |
| --- | --- | --- | --- | --- | --- |
| K1 | GPL-3.0 `LICENSE` and `NOTICE` | **Done in 3.9.1** — upstream is GPL-3.0 and this is a derivative | P0 | S | Low |
| K2 | `licenses/` folder for bundled binaries | 7-Zip is LGPL (binary redistribution requires the licence text); GreenChrome, MozLz4, MouseInc and TabPlus each have their own terms | P1 | S | Low |
| K3 | Confirm source availability for every binary release | GPL requires the corresponding source to accompany the binary; the source archive is attached to each release, keep that up | P1 | S | Low |

## L. Long-term

| # | Item | Why | P | Eff | Risk |
| --- | --- | --- | --- | --- | --- |
| L1 | Rewrite the launcher in Go or Rust | Cross-compiles from Linux, unit-testable, signable, no AutoIt runtime quirks. The download/extract/swap logic is ~500 lines of real logic wrapped in 6,000 lines of UDFs | P2 | L | High |
| L2 | Keep AutoIt as the maintenance branch | Freeze feature work, ship only feed fixes | P2 | S | Low |
| L3 | Or a small .NET single-file tray app | Same benefit, easier Windows integration, larger runtime | P3 | L | High |

---

## Do these ten next

1. **C3** — stop disabling the renderer sandbox by default. One line, real security impact.
2. **C1** — sign the executable. Nothing else improves trust as much.
3. **I1** — a CI smoke test that actually launches the browser. Everything else is guesswork without it.
4. **B1 + B2** — atomic swap with rollback. This is what turns "usually works" into "cannot brick my browser".
5. **G1** — a verified Edge source. It is the only major browser whose path is neither verified nor proxy-aware.
6. **J1** — switch Pages on. The landing page is already written and pushed.
7. **A1 + A2** — integrity checks before extraction; cheap and they convert confusing failures into clear ones.
8. **E1 + E2** — first-run wizard and DPI awareness; the two things every new user hits immediately.
9. **F1** — CLI mode; it is the prerequisite for I1, I3 and I5.
10. **H2** — one place for the version number; it currently drifts across four files.

## Known limits, stated plainly

- Edge, Vivaldi and Cent download paths are **not verified end to end**. Edge's endpoint could not be reached from the build environment; Vivaldi and Cent have no real download source in the code at all.
- GreenChrome / Chrome++ injection on Chrome 158 is **untested**. It is off by default and the launcher works without it.
- Everything was compiled and structurally verified on Windows CI, but the UI flow has not been exercised on a real desktop.
