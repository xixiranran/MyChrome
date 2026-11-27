# Privacy

MyBrowser 3.9.4 · effective 27 November 2026

MyBrowser is a portable launcher. It has no account system, no telemetry, no analytics
and no crash reporting. Nothing about you is sent anywhere by this program.

This document describes exactly what the code does, and how to check it.

## What is stored on your computer

| What | Where | Why |
| --- | --- | --- |
| Settings | `MyBrowser.ini` next to the executable | browser choice, channel, paths, window options |
| Browser profile | the profile folder you choose (default: inside the app folder) | history, cookies, passwords — managed by the browser itself, not by this program |
| Downloaded update package | `App\~update\` during an update | extracted, then deleted when the update finishes or fails (3.9.2 and later) |
| Update log | `MyBrowser.log` next to the executable | browser, channel, version numbers and file names for each update step, so a bug report can be diagnosed. No browsing data, no personal data. Delete it any time; it is recreated on the next update check |

There is no database and no cache of personal data. The update log described above is the only file the program writes that is not a setting.

To erase everything, delete the folder. Nothing is left behind outside it, except what
you explicitly point the browser's profile path at.

## What leaves your computer

MyBrowser contacts only the servers needed to download a browser or check for an app
update. Each request carries no user identifier, no device identifier, no account, no
file names and no browsing data. Requests are ordinary HTTP(S) GET or POST.

| Server | When | What is sent |
| --- | --- | --- |
| `googlechromelabs.github.io` | Chrome update check | nothing beyond the request |
| `storage.googleapis.com` | Chrome / Chromium download | nothing beyond the request |
| `tools.google.com` | Chrome fallback check | a fixed update-check XML: OS platform and version, CPU architecture, language. The session and request IDs in it are **hardcoded constants**, identical for every user |
| `dl.google.com`, `edgedl.me.gvt1.com` | Chrome fallback download | nothing beyond the request |
| `api.github.com` | Brave update check | nothing beyond the request |
| `updates.bravesoftware.com` | Brave fallback check | a fixed update-check XML, same shape as the Google one |
| `msedge.api.cdp.microsoft.com` | Edge update check | a fixed JSON body: OS platform, version, architecture |
| `product-details.mozilla.org` | Firefox version check | nothing beyond the request |
| `download.mozilla.org` | Firefox download | nothing beyond the request |
| `raw.githubusercontent.com` | app self-update check | nothing beyond the request |
| `github.com` | app self-update download | nothing beyond the request |
| `xixiranran.github.io` | only when you click a "download page" link for Vivaldi or Cent | nothing — the launcher opens the page in your default browser, it does not fetch it |

Any server sees your IP address and the time of the request, as with any download.
That is inherent to fetching a file, not something this program adds.

**Not present in the code:** no analytics SDK, no crash reporter, no advertising ID, no
machine GUID, no username, no hardware fingerprint, no "phone home" on launch. The app
does not contact anything unless you start an update or it checks for one on the
schedule you set.

## Cookies and accounts

None. The launcher has no web view and sets no cookies.

## Children

The program collects nothing, so there is nothing specific to say about children's data.

## Changes

This file is versioned with the code. If a future release changes any of the above, the
change appears here in the same commit.

## How to verify this yourself

Everything above is checkable in the repository:

```bash
# every domain the source can reach
grep -oiE '[a-z0-9.-]+\.(com|org|io|net)' src/MyBrowser.au3 | sort -u

# the identifiers sent to Google are constants, not per-machine values
grep -n 'sessionid=' src/MyBrowser.au3

# everything the program writes is an ini file next to itself
grep -n 'IniWrite' src/MyBrowser.au3 | head
```

If you find a discrepancy between this document and the code, that is a security
report — see `SECURITY.md`.
