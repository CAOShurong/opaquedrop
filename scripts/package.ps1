param(
    [Parameter(Mandatory = $true)]
    [string]$Version
)

$ErrorActionPreference = 'Stop'
$repoRoot = Split-Path -Parent $PSScriptRoot
$distRoot = Join-Path $repoRoot 'dist'
$resolvedRepo = [System.IO.Path]::GetFullPath($repoRoot)
$resolvedDist = [System.IO.Path]::GetFullPath($distRoot)
if (-not $resolvedDist.StartsWith($resolvedRepo + [System.IO.Path]::DirectorySeparatorChar, [System.StringComparison]::OrdinalIgnoreCase)) {
    throw "Refusing to clean unexpected dist path: $resolvedDist"
}
if (Test-Path -LiteralPath $resolvedDist) {
    Remove-Item -LiteralPath $resolvedDist -Recurse -Force
}
New-Item -ItemType Directory -Path $resolvedDist | Out-Null

$cleanVersion = $Version.TrimStart('v')
$targets = @(
    @{ OS = 'windows'; Arch = 'amd64'; Archive = 'zip' },
    @{ OS = 'windows'; Arch = 'arm64'; Archive = 'zip' },
    @{ OS = 'linux'; Arch = 'amd64'; Archive = 'tar.gz' },
    @{ OS = 'linux'; Arch = 'arm64'; Archive = 'tar.gz' },
    @{ OS = 'darwin'; Arch = 'amd64'; Archive = 'tar.gz' },
    @{ OS = 'darwin'; Arch = 'arm64'; Archive = 'tar.gz' }
)

Push-Location $repoRoot
try {
    foreach ($target in $targets) {
        $env:GOOS = $target.OS
        $env:GOARCH = $target.Arch
        $env:CGO_ENABLED = '0'
        $name = "opaquedrop_${cleanVersion}_$($target.OS)_$($target.Arch)"
        $stage = Join-Path $resolvedDist $name
        New-Item -ItemType Directory -Path $stage | Out-Null
        $binary = 'opaquedrop'
        if ($target.OS -eq 'windows') { $binary += '.exe' }
        go build -trimpath -buildvcs=true -ldflags "-s -w -X main.version=$Version" -o (Join-Path $stage $binary) ./cmd/opaquedrop
        Copy-Item -LiteralPath 'README.md','LICENSE','SECURITY.md','CHANGELOG.md' -Destination $stage
        New-Item -ItemType Directory -Path (Join-Path $stage 'docs') | Out-Null
        Copy-Item -LiteralPath 'docs/THREAT_MODEL.md','docs/PROTOCOL.md','docs/DEPLOYMENT.md' -Destination (Join-Path $stage 'docs')
        if ($target.Archive -eq 'zip') {
            Compress-Archive -LiteralPath $stage -DestinationPath (Join-Path $resolvedDist ($name + '.zip')) -CompressionLevel Optimal
        } else {
            tar -czf (Join-Path $resolvedDist ($name + '.tar.gz')) -C $resolvedDist $name
        }
        Remove-Item -LiteralPath $stage -Recurse -Force
    }
} finally {
    Pop-Location
    Remove-Item Env:GOOS -ErrorAction SilentlyContinue
    Remove-Item Env:GOARCH -ErrorAction SilentlyContinue
    Remove-Item Env:CGO_ENABLED -ErrorAction SilentlyContinue
}

$lines = Get-ChildItem -LiteralPath $resolvedDist -File | Sort-Object Name | ForEach-Object {
    $hash = (Get-FileHash -Algorithm SHA256 -LiteralPath $_.FullName).Hash.ToLowerInvariant()
    "$hash  $($_.Name)"
}
$utf8NoBom = New-Object System.Text.UTF8Encoding($false)
[System.IO.File]::WriteAllLines((Join-Path $resolvedDist 'SHA256SUMS'), [string[]]$lines, $utf8NoBom)
Get-ChildItem -LiteralPath $resolvedDist -File | Sort-Object Name | Select-Object Name,Length
