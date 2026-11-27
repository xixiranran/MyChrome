# Smoke test: proves the things that can be proved without a desktop.
#  1. every download source the app knows about answers with a usable URL
#  2. the built executable starts and stays alive
# Runs on Windows (GitHub Actions) or locally with PowerShell 7.
$ErrorActionPreference = 'Stop'

$root = Split-Path -Parent $PSScriptRoot
$dist = Join-Path $root 'dist'
$fail = @()

function Check([string]$Name, [scriptblock]$Body) {
    try {
        $result = & $Body
        if (-not $result) { throw 'empty result' }
        Write-Host ("PASS  {0}  {1}" -f $Name, $result)
    } catch {
        Write-Host ("FAIL  {0}  {1}" -f $Name, $_.Exception.Message)
        $script:fail += $Name
    }
}

# ---------------------------------------------------------------- sources
Check 'Chrome for Testing (stable win64)' {
    $j = Invoke-RestMethod 'https://googlechromelabs.github.io/chrome-for-testing/last-known-good-versions-with-downloads.json'
    $u = ($j.channels.Stable.downloads.chrome | Where-Object platform -eq 'win64').url
    if (-not $u) { throw 'no win64 asset' }
    $null = Invoke-WebRequest $u -Method Head -UseBasicParsing
    "$($j.channels.Stable.version) $u"
}

Check 'Chromium snapshot (win64)' {
    $rev = (Invoke-WebRequest 'https://storage.googleapis.com/chromium-browser-snapshots/Win_x64/LAST_CHANGE' -UseBasicParsing).Content.Trim()
    $u = "https://storage.googleapis.com/chromium-browser-snapshots/Win_x64/$rev/chrome-win.zip"
    $null = Invoke-WebRequest $u -Method Head -UseBasicParsing
    "rev $rev"
}

Check 'Brave release ZIP' {
    $r = Invoke-RestMethod 'https://api.github.com/repos/brave/brave-browser/releases/latest'
    $a = $r.assets | Where-Object { $_.name -match '^brave-v[\d.]+-win32-x64\.zip$' } | Select-Object -First 1
    if (-not $a) { throw 'no win32-x64 asset' }
    "$($r.tag_name) $($a.name)"
}

Check 'Firefox version feed' {
    $j = Invoke-RestMethod 'https://product-details.mozilla.org/1.0/firefox_versions.json'
    if (-not $j.LATEST_FIREFOX_VERSION) { throw 'no LATEST_FIREFOX_VERSION' }
    $null = Invoke-WebRequest 'https://download.mozilla.org/?product=firefox-latest&os=Win64&lang=zh-CN' -Method Head -UseBasicParsing
    "release $($j.LATEST_FIREFOX_VERSION), esr $($j.FIREFOX_ESR)"
}

Check 'Update manifest is reachable' {
    $t = (Invoke-WebRequest 'https://raw.githubusercontent.com/drsamonline/MyChrome/master/update.txt' -UseBasicParsing).Content
    if ($t -notmatch 'latest=([\d.]+)') { throw 'no latest= line' }
    "latest=$($Matches[1])"
}

# ---------------------------------------------------------------- binaries
Check 'x64 executable starts' {
    $exe = Join-Path $dist 'MyBrowser.exe'
    if (-not (Test-Path $exe)) { throw 'dist/MyBrowser.exe missing' }
    $p = Start-Process $exe -PassThru
    Start-Sleep -Seconds 6
    if ($p.HasExited) { throw "exited with code $($p.ExitCode)" }
    Stop-Process -Id $p.Id -Force
    'stayed alive for 6s'
}

Check 'x86 executable starts' {
    $exe = Join-Path $dist 'MyBrowser_x86.exe'
    if (-not (Test-Path $exe)) { throw 'dist/MyBrowser_x86.exe missing' }
    $p = Start-Process $exe -PassThru
    Start-Sleep -Seconds 6
    if ($p.HasExited) { throw "exited with code $($p.ExitCode)" }
    Stop-Process -Id $p.Id -Force
    'stayed alive for 6s'
}

# ---------------------------------------------------------------- verdict
if ($fail.Count -gt 0) {
    throw ("Smoke test failed: " + ($fail -join ', '))
}
Write-Host 'All smoke checks passed.'
