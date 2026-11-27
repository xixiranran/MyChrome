# Rebuilds the gh-pages branch from docs/ and pushes it.
# The branch is a build artefact: docs/ on master is the single source of truth.
$ErrorActionPreference = 'Stop'

$root = Split-Path -Parent $PSScriptRoot
Push-Location $root
try {
    $stage = Join-Path $env:TEMP ('mychrome-pages-' + [guid]::NewGuid().ToString('N'))
    New-Item -ItemType Directory -Force -Path $stage | Out-Null
    Copy-Item (Join-Path $root 'docs\*') $stage -Recurse -Force
    Copy-Item (Join-Path $root 'update.txt') $stage -Force
    New-Item -ItemType File -Force -Path (Join-Path $stage '.nojekyll') | Out-Null

    git checkout --orphan gh-pages 2>$null
    git rm -rf . 2>$null | Out-Null
    Copy-Item (Join-Path $stage '*') $root -Recurse -Force
    git add -A
    git commit -m 'landing page' | Out-Null
    git push -f origin gh-pages
    Write-Host 'gh-pages published from docs/.'
} finally {
    Pop-Location
}
