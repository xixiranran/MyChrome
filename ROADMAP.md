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

## Status board

**Progress: 23 of 75 done (31%), 5 partial, 47 open.** Updated for 3.9.6.

| | Category | Done | Partial | Open | Total |
|---|---|---|---|---|---|
| A | Download integrity | 4 | 0 | 5 | 9 |
| B | Update engine | 2 | 2 | 6 | 10 |
| C | Security and trust | 4 | 1 | 3 | 8 |
| D | Performance | 0 | 0 | 4 | 4 |
| E | User experience | 1 | 0 | 9 | 10 |
| F | Portability | 0 | 0 | 5 | 5 |
| G | Browser coverage | 1 | 0 | 6 | 7 |
| H | Maintainability | 2 | 1 | 4 | 7 |
| I | Testing | 0 | 1 | 4 | 5 |
| J | Distribution | 1 | 0 | 3 | 4 |
| K | Licensing | 3 | 0 | 0 | 3 |
| L | Long term | 0 | 0 | 3 | 3 |
| | **Total** | **18** | **5** | **52** | **75** |

| ID | Item | P | Status | In |
|---|---|---|---|---|
| A1 | Verify archive integrity before extraction | P0 | ✅ done | 3.9.3 |
| A2 | Compare Content-Length with bytes received | P0 | ✅ done | pre-existing |
| A3 | Assert unpacked version equals requested | P1 | ✅ done | 3.9.4 |
| A4 | Keep last-known-good version | P1 | ✅ done | 3.9.4 |
| A5 | Reject plain-http mirrors | P0 | ✅ done | 3.9.2 |
| A6 | Cache Brave version 24 h (rate limits) | P1 | ⬜ open | — |
| A7 | Retry 5xx with backoff | P1 | ⬜ open | — |
| A8 | Handle HTTP 416 on resume | P2 | ⬜ open | — |
| A9 | Verify vendor hashes where published | P2 | ⬜ open | — |
| B1 | Atomic swap of the browser folder | P0 | ✅ done | 3.9.6 |
| B2 | Auto rollback if new build fails | P1 | ✅ done | 3.9.6 |
| B3 | Profile folder never inside replaced dir | P1 | ✅ done | 3.9.6 |
| B4 | Skip one version, not all checks | P1 | ✅ done | 3.9.4 |
| B5 | Clean stale temp dirs on startup | P1 | 🟡 partial | 3.9.2 |
| B6 | Deterministic cancel | P1 | ⬜ open | — |
| B7 | Speed and ETA in progress | P2 | ⬜ open | — |
| B8 | Background check with notification | P2 | ⬜ open | — |
| B9 | Update log | P2 | ✅ done | 3.9.4 |
| B10 | Concurrent-instance lock | P2 | ⬜ open | — |
| C1 | Authenticode signing | P0 | 🟡 partial | 3.9.4 |
| C2 | SHA256SUMS per release | P1 | ✅ done | 3.9.3 |
| C3 | No --no-sandbox default | P0 | ✅ done | 3.9.3 |
| C4 | Reconsider --test-type | P2 | ⬜ open | — |
| C5 | Injection off by default and labelled | P1 | ✅ done | 3.9.x |
| C6 | Build provenance attestation | P2 | ⬜ open | — |
| C7 | VirusTotal link in release notes | P3 | ⬜ open | — |
| C8 | Document no telemetry | P2 | ✅ done | 3.9.3 |
| D1 | Strip unreferenced UDFs | P2 | ⬜ open | — |
| D2 | Split 6,900-line file into includes | P2 | ⬜ open | — |
| D3 | Adaptive segment count | P3 | ⬜ open | — |
| D4 | Keep previous build for rollback | P3 | ⬜ open | — |
| E1 | First-run wizard | P1 | ⬜ open | — |
| E2 | DPI awareness | P1 | ✅ done | 3.9.3 |
| E3 | Strings out of code into language files | P1 | ⬜ open | — |
| E4 | More languages | P2 | ⬜ open | — |
| E5 | Error dialogs with copy details | P1 | ⬜ open | — |
| E6 | Installed vs latest side by side | P1 | ⬜ open | — |
| E7 | Remember window position | P2 | ⬜ open | — |
| E8 | Multiple profiles per browser | P2 | ⬜ open | — |
| E9 | Keyboard nav and accessible names | P2 | ⬜ open | — |
| E10 | Progress in taskbar button | P3 | ⬜ open | — |
| F1 | CLI mode | P1 | 🟡 partial | 3.9.6 |
| F2 | Scoop manifest | P2 | ⬜ open | — |
| F3 | winget manifest | P2 | ⬜ open | — |
| F4 | ARM64 build | P2 | ⬜ open | — |
| F5 | Fully portable settings | P2 | ⬜ open | — |
| G1 | Real, verified source for Edge | P0 | ⬜ open | — |
| G2 | Real source for Vivaldi | P1 | ✅ done | 3.9.5 |
| G3 | Real source for Cent | P2 | ⬜ open | — |
| G4 | Chrome Extended Stable | P2 | ⬜ open | — |
| G5 | Chrome 109 for Windows 7/8 | P3 | ⬜ open | — |
| G6 | Warn if win32 Chrome retired | P2 | ⬜ open | — |
| G7 | Firefox channel naming check | P3 | ⬜ open | — |
| H1 | Restore include-based structure | P1 | ⬜ open | — |
| H2 | Single source of truth for version | P1 | 🟡 partial | 3.9.3 |
| H3 | docs/ARCHITECTURE.md | P1 | ✅ done | 3.9.3 |
| H4 | CI fails on warnings | P2 | ✅ done | 3.9.4 |
| H5 | Changelog from commits | P2 | ⬜ open | — |
| H6 | Pin and cache AutoIt SDK | P2 | ⬜ open | — |
| H7 | .editorconfig + format pass | P3 | ⬜ open | — |
| I1 | Smoke test in CI | P0 | ✅ done | 3.9.6 |
| I2 | --selftest flag | P1 | ⬜ open | — |
| I3 | Fault injection on download | P2 | ⬜ open | — |
| I4 | OS x arch x browser matrix | P2 | ⬜ open | — |
| I5 | Upgrade test 3.8.50 to current | P1 | ⬜ open | — |
| J1 | Enable GitHub Pages | P0 | ✅ done | 3.9.4 |
| J2 | Mirror releases for mainland China | P1 | ⬜ open | — |
| J3 | Issue templates and support doc | P2 | ⬜ open | — |
| J4 | Release notes in Chinese | P2 | ⬜ open | — |
| K1 | GPL-3.0 LICENSE and NOTICE | P0 | ✅ done | 3.9.1 |
| K2 | licenses/ for bundled binaries | P1 | ✅ done | 3.9.3 |
| K3 | Source archive on every release | P1 | ✅ done | 3.9.1 |
| L1 | Rewrite in Go or Rust | P2 | ⬜ open | — |
| L2 | Freeze AutoIt as maintenance branch | P2 | ⬜ open | — |
| L3 | Or a .NET single-file tray app | P3 | ⬜ open | — |

### Shipped but not on the original list

| Finding | Fixed in |
|---|---|
| Hardcoded Google API key, OAuth client id and client secret in the binary, written to the user environment | 3.9.3 |
| Command injection: unquoted `cd <dir>&cmd` in the DLL-injection path (9 call sites) | 3.9.3 |
| "No" wrote `UpdateInterval=-1`, disabling update checks permanently | 3.9.4 |
| CI smoke test went red on a GitHub API rate limit (unauthenticated) | 3.9.4 |

### Next, in order

| Order | ID | Item | Why now |
|---|---|---|---|
| 1 | G1 | Verified Edge source over the proxy-aware WinHTTP path | Only major browser neither verified nor proxy-aware |
| 2 | C1 | Finish signing (needs a certificate secret) | Hook is in CI; nothing else improves trust as much |
| 3 | B1+B2 | Atomic swap with rollback | Turns "usually works" into "cannot brick my browser" |
| 4 | I1 | Smoke test that downloads a real browser | Everything else stays guesswork without it |
| 5 | F1 | CLI mode | Prerequisite for I2, I3, I5 |
| 6 | A2 | Content-Length check before unpack | Cheap; converts confusing failures into clear ones |
| 7 | E1+E3 | First-run wizard; strings out of code | First things a new user and a translator hit |
| 8 | H2+H1 | One version source; includes instead of one 6,900-line file | Slows every other change |
| 9 | J2 | Mirror releases for mainland China | Large part of the audience |
| 10 | A6 | Cache Brave version | Confirmed real: CI hit the GitHub rate limit |

### Release log

| Version | Date | Shipped |
|---|---|---|
| 3.9.0 | 2026-11-27 | Rebuilt from recovered source; Chrome via Chrome for Testing; source, build and CI published |
| 3.9.1 | 2026-11-27 | Firefox, Chromium and Brave sources repaired; GPL-3.0 LICENSE and NOTICE |
| 3.9.2 | 2026-11-27 | Disk-space guard, temp cleanup, apply pre-flight, portable flags, modern UA, HTTPS-only mirrors |
| 3.9.3 | 2026-11-27 | Google credentials removed; `--no-sandbox` dropped; command injection fixed; archive integrity test; SHA256SUMS; README rebuilt; SECURITY, PRIVACY, licenses, ARCHITECTURE |
| 3.9.4 | 2026-11-27 | Skip one version not all; `MyBrowser.log`; version assertion; last-known version; signing hook; CI fails on warnings |
| 3.9.5 | 2026-11-27 | Vivaldi real appcast; 17-browser matrix; support block; standalone framing; TERMS.md |

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
| G2 | ~~Real source for Vivaldi~~ — **done in 3.9.5** via `update.vivaldi.com/update/1.0/public/appcast.{x64,}.xml` | The old path opened a link hub page, so the version resolved empty and the update aborted | P1 | M | Low |
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
