# Security policy

## Supported versions

Only the latest release receives fixes. The app updates itself, so staying current is
one click in the settings dialog.

| Version | Supported |
| --- | --- |
| 3.9.x | Yes |
| 3.8.x and earlier | No |

## Reporting a vulnerability

Please **do not open a public issue** for a security problem.

Use GitHub's private reporting: **Security → Advisories → Report a vulnerability** on
<https://github.com/drsamonline/MyChrome>. If that is unavailable, open a normal issue
that says only "security report, please contact me" and no details, and you will be
given a private channel.

Please include:

- the version from the settings dialog, and your Windows version;
- which browser and channel you were updating;
- what you expected, what happened, and the exact error text;
- a proof of concept if you have one.

You can expect an acknowledgement within a few days. There is no bounty.

## What is in scope

- The launcher itself: `src/MyBrowser.au3` and anything built from it.
- The download and extract path, including the handling of URLs, archives and file
  names taken from a vendor response.
- The update mechanism (`update.txt` → `.7z` → executable replacement).
- The build and release pipeline in this repository.

## What is out of scope

- **The browsers themselves.** Chrome, Chromium, Edge, Brave, Firefox, Vivaldi and
  Cent are downloaded from their vendors, unmodified. Report bugs in them to the vendor.
- **The bundled third-party DLLs and tools** (`licenses/README.md`). Report those to
  their own projects.
- **The optional GreenChrome / Chrome++ injection.** It patches the browser executable
  and is off by default. Running it is at your own risk; see the note below.
- **An unsigned executable being flagged by antivirus or SmartScreen.** That is
  expected for an unsigned portable launcher. Releases are built from this repository
  by GitHub Actions, and `SHA256SUMS.txt` is published with every release so you can
  verify what you downloaded.

## Known accepted risks

- The executable is **not Authenticode-signed** yet (tracked in `ROADMAP.md` as C1).
- **DLL injection** into the browser (`GreenChrome`, `Chrome++`) is off by default and
  unsupported on current Chrome builds. Turning it on modifies `chrome.exe` on disk.
- The renderer sandbox is **not** disabled by default any more (3.9.3 removed
  `--no-sandbox` from the shipped parameters). If you add it back by hand to work
  around a startup problem, you are weakening the browser's isolation — prefer fixing
  the underlying cause.
