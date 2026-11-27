# Bundled third-party components

`resources/` is embedded into `MyBrowser.exe` at compile time by `FileInstall()`.
These files are not written by this project and stay under their own terms.

| File | Component | Licence |
| --- | --- | --- |
| `7z.exe`, `7z.dll` | 7-Zip | GNU LGPL, with the unRAR restriction — full text in `LGPL-2.1.txt`; restriction at <https://www.7-zip.org/license.txt> |
| `mozlz4-win32.exe`, `mozlz4-win64.exe` | MozLz4 | Mozilla Public License 2.0 — full text in `MPL-2.0.txt` |
| `GreenChrome.dll`, `GreenChrome64.dll`, `GreenChrome.ini` | GreenChrome | Distributed by its own project; terms are set there |
| `setdll.exe`, `setdll64.exe` | Microsoft `setdll` | Distributed with the Windows SDK; Microsoft licence terms |
| `MouseInc.exe`, `MouseInc.json`, `MouseInc.Settings.zip`, `hook.dll`, `hook64.dll` | MouseInc | Distributed by its own project; terms are set there |
| `TabPlus.exe`, `TabPlus.ini` | TabPlus | Distributed by its own project; terms are set there |

## What is not bundled

Chrome, Chromium, Edge, Brave, Firefox, Vivaldi and Cent are downloaded at runtime
from their vendors. No browser binary is redistributed here, and no vendor logo or
trademark is used to imply endorsement.

## GPL position

The launcher itself is GPL-3.0 (`../LICENSE`). Bundling LGPL and MPL components inside
a GPL work is permitted: the LGPL text above is included as required, and the
components are used unmodified. If you rebuild from source you get the same bundle.
