[CmdletBinding()]
param(
    [Parameter(Mandatory)] [string] $Message,
    [string] $Tag
)
$ErrorActionPreference = 'Stop'

# Always operate on the repo this script lives in, regardless of cwd.
$RepoPath = Split-Path -Parent $PSCommandPath
Push-Location $RepoPath
try {
    # Make sure local tag list reflects what's on origin so we don't bump
    # off a stale local view.
    git fetch --tags --quiet

    if (-not $Tag) {
        # Find the highest existing vMAJOR.MINOR.PATCH tag and bump patch.
        # `git tag --sort=-v:refname` orders semver tags newest-first.
        $latest = git tag --list 'v[0-9]*.[0-9]*.[0-9]*' --sort=-v:refname |
                  Where-Object { $_ -match '^v\d+\.\d+\.\d+$' } |
                  Select-Object -First 1

        if (-not $latest) {
            $Tag = 'v0.1.0'
            Write-Host "[Publish-BTCT] no existing version tags; starting at $Tag" -ForegroundColor Cyan
        } else {
            if ($latest -notmatch '^v(\d+)\.(\d+)\.(\d+)$') {
                throw "Could not parse latest tag '$latest' as vMAJOR.MINOR.PATCH."
            }
            $major = [int]$Matches[1]
            $minor = [int]$Matches[2]
            $patch = [int]$Matches[3]
            $Tag = "v$major.$minor.$($patch + 1)"
            Write-Host "[Publish-BTCT] bumping $latest -> $Tag" -ForegroundColor Cyan
        }
    } else {
        if ($Tag -notmatch '^v\d+\.\d+\.\d+$') {
            throw "Tag must look like vMAJOR.MINOR.PATCH (got '$Tag')."
        }
        Write-Host "[Publish-BTCT] using explicit tag $Tag" -ForegroundColor Cyan
    }

    git add -A
    if (git diff --cached --name-only) {
        git commit -m $Message
    } else {
        Write-Host "[Publish-BTCT] no staged changes; skipping commit"
    }
    git push origin main
    git tag -fa $Tag -m $Message
    git push origin $Tag --force
    Write-Host "[Publish-BTCT] released $Tag"                 -ForegroundColor Green
    Write-Host "[Publish-BTCT] on Linux run:  update-btct $Tag" -ForegroundColor Cyan
} finally {
    Pop-Location
}
