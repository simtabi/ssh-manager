<#
.SYNOPSIS
  sshmgr installer for Windows.

.EXAMPLE
  irm https://opensource.simtabi.com/install/ssh-manager.ps1 | iex

.EXAMPLE
  # Pin a version / custom dir (env vars are prefixed with the uppercased binary name)
  $env:SSHMGR_VERSION = 'v0.1.0'; irm https://.../install.ps1 | iex
#>
#Requires -Version 5
[CmdletBinding()]
param(
  [string]$Version,
  [string]$InstallDir
)

$ErrorActionPreference = 'Stop'
$owner   = 'simtabi'
$repo    = 'ssh-manager'
$binBase = 'sshmgr'
$binary  = 'sshmgr.exe'

# Per-project env-var prefix, derived so it stays a valid identifier for any
# project name (uppercase, non-alnum -> '_'). Keyed off the binary name so it
# matches the POSIX installer (e.g. sshmgr -> SSHMGR).
$prefix = ($binBase.ToUpper() -replace '[^A-Z0-9]', '_')
if (-not $Version)    { $Version    = [Environment]::GetEnvironmentVariable("${prefix}_VERSION") }
if (-not $InstallDir) { $InstallDir = [Environment]::GetEnvironmentVariable("${prefix}_INSTALL_DIR") }

# Go-style GOARCH, matching the release artifact names.
switch ($env:PROCESSOR_ARCHITECTURE) {
  'AMD64' { $arch = 'amd64' }
  'ARM64' { $arch = 'arm64' }
  'x86'   { $arch = '386' }
  default { throw "unsupported architecture: $($env:PROCESSOR_ARCHITECTURE)" }
}

if (-not $InstallDir) { $InstallDir = Join-Path $env:LOCALAPPDATA "Programs\$repo" }

if (-not $Version) {
  $rel = Invoke-RestMethod -Headers @{ 'Accept' = 'application/vnd.github+json' } `
    "https://api.github.com/repos/$owner/$repo/releases/latest"
  $Version = $rel.tag_name
}
if ($Version -notlike 'v*') { $Version = "v$Version" }

# Bare, ready-to-run executable: sshmgr_windows_<arch>.exe.
$asset = "${binBase}_windows_${arch}.exe"
$base  = "https://github.com/$owner/$repo/releases/download/$Version"
$tmp   = Join-Path ([IO.Path]::GetTempPath()) ([Guid]::NewGuid())
New-Item -ItemType Directory -Path $tmp | Out-Null

try {
  Write-Host "Downloading $asset ($Version) ..."
  $exe = Join-Path $tmp $asset
  Invoke-WebRequest "$base/$asset" -OutFile $exe

  $sums = Join-Path $tmp 'checksums.txt'
  $haveSums = $true
  try { Invoke-WebRequest "$base/checksums.txt" -OutFile $sums } catch { $haveSums = $false; Write-Warning 'checksums.txt not found; skipping verification.' }
  if ($haveSums) {
    $line = Select-String -Path $sums -Pattern ([regex]::Escape($asset)) | Select-Object -First 1
    if (-not $line) { throw "no checksum entry for $asset" }
    $want = (($line.Line -split '\s+')[0]).ToLower()
    $got  = (Get-FileHash $exe -Algorithm SHA256).Hash.ToLower()
    if ($got -ne $want) { throw "checksum mismatch for $asset" }
  }

  New-Item -ItemType Directory -Path $InstallDir -Force | Out-Null
  Copy-Item $exe (Join-Path $InstallDir $binary) -Force
}
finally {
  Remove-Item -Recurse -Force $tmp -ErrorAction SilentlyContinue
}

# Add the install dir to the user PATH if it isn't already there.
$userPath = [Environment]::GetEnvironmentVariable('Path', 'User')
if (($userPath -split ';') -notcontains $InstallDir) {
  [Environment]::SetEnvironmentVariable('Path', "$userPath;$InstallDir", 'User')
  Write-Host "Added $InstallDir to your user PATH (restart your shell to pick it up)."
}
$env:Path += ";$InstallDir"

& (Join-Path $InstallDir $binary) version
Write-Host "Installed $binBase to $InstallDir\$binary"
