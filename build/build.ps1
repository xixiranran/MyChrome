# Builds MyBrowser from source with AutoIt3.
# Runs on Windows (GitHub Actions windows-latest or a local Windows box).
$ErrorActionPreference = 'Stop'

$root = Split-Path -Parent $PSScriptRoot
$src  = Join-Path $root 'src'
$res  = Join-Path $root 'resources'
$dist = Join-Path $root 'dist'
$tool = Join-Path $root '.build'

$Version = (Select-String -Path (Join-Path $src 'MyBrowser.au3') -Pattern 'Global Const \$APPVERSION = "([^"]+)"').Matches[0].Groups[1].Value
if (-not $Version) { throw 'Could not read $APPVERSION from src/MyBrowser.au3' }
Write-Host "Building MyBrowser $Version"

New-Item -ItemType Directory -Force -Path $dist, $tool | Out-Null

# ---------------------------------------------------------------- AutoIt3 SDK
$au = Join-Path $tool 'autoit'
if (-not (Test-Path (Join-Path $au 'ok.marker'))) {
    $zip = Join-Path $tool 'autoit.zip'
    $url = 'https://www.autoitscript.com/autoit3/files/archive/autoit/autoit-v3.3.16.1.zip'
    Write-Host "Downloading $url"
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
    Invoke-WebRequest -Uri $url -OutFile $zip -UseBasicParsing
    if (Test-Path $au) { Remove-Item $au -Recurse -Force }
    Expand-Archive -Path $zip -DestinationPath $au -Force
    New-Item -ItemType File -Force -Path (Join-Path $au 'ok.marker') | Out-Null
}

$au3check = (Get-ChildItem -Path $au -Filter 'Au3Check.exe' -Recurse | Select-Object -First 1).FullName
$aut2exe  = (Get-ChildItem -Path $au -Filter 'Aut2Exe.exe' -Recurse | Select-Object -First 1).FullName
$aut2exe64 = (Get-ChildItem -Path $au -Filter 'Aut2Exe_x64.exe' -Recurse | Select-Object -First 1).FullName
if (-not $au3check -or -not $aut2exe) { throw 'AutoIt SDK not found after extraction' }

# ------------------------------------------------- resources next to the script
# FileInstall() resolves paths relative to the .au3 file at compile time.
Get-ChildItem -Path $res -File | ForEach-Object {
    Copy-Item $_.FullName (Join-Path $src $_.Name) -Force
}

# ---------------------------------------------------------------- syntax check
Write-Host 'Au3Check:'
& $au3check /q /d (Join-Path $src 'MyBrowser.au3')
$checkExit = $LASTEXITCODE
if ($checkExit -ne 0) { throw "Au3Check failed with exit code $checkExit" }

# ---------------------------------------------------------------- compile
$au3 = Join-Path $src 'MyBrowser.au3'

Write-Host 'Compiling x64 ...'
& $aut2exe64 /in $au3 /out (Join-Path $dist 'MyBrowser.exe') /x64 /comp 4
if (-not (Test-Path (Join-Path $dist 'MyBrowser.exe'))) { throw 'x64 compile produced no output' }

Write-Host 'Compiling x86 ...'
& $aut2exe /in $au3 /out (Join-Path $dist 'MyBrowser_x86.exe') /x86 /comp 4
if (-not (Test-Path (Join-Path $dist 'MyBrowser_x86.exe'))) { throw 'x86 compile produced no output' }

# ---------------------------------------------------------------- package
$sevenZip = Join-Path $res '7z.exe'
$x64Archive = Join-Path $dist "MyBrowser_v$Version`_x64.7z"
$x86Archive = Join-Path $dist "MyBrowser_v$Version.7z"

Remove-Item $x64Archive, $x86Archive -Force -ErrorAction SilentlyContinue
& $sevenZip a -t7z -mx=9 $x64Archive (Join-Path $dist 'MyBrowser.exe') | Out-Null
& $sevenZip a -t7z -mx=9 $x86Archive (Join-Path $dist 'MyBrowser_x86.exe') | Out-Null
if ($LASTEXITCODE -ne 0) { throw '7z packaging failed' }

Get-ChildItem $dist | Format-Table Name, Length
Write-Host "Done: MyBrowser $Version"
