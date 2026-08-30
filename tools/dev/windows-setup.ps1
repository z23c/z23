# Copyright 2026 Rhett Creighton - Apache License 2.0
#
# windows-setup.ps1 — one-command Windows bootstrap for the Z23 C23 build.
#
# Purpose: get from a fresh Windows machine to a built build/bin/z23.exe with
# almost no operator friction. The script is deliberately a courier, not a
# build system: it ensures MSYS2 UCRT64 exists, installs the exact packages the
# Makefile's `make doctor` probes for, then runs `make setup` and `make z23`.
#
# Usage (from an elevated or normal PowerShell):
#   .\tools\dev\windows-setup.ps1
#   .\tools\dev\windows-setup.ps1 -SkipBuild       # prepare only, do not compile
#   .\tools\dev\windows-setup.ps1 -Msys2Root D:\msys64
#
# The script refuses rather than guess when it cannot find or install MSYS2.

[CmdletBinding()]
param(
    [string]$CheckoutRoot = "",
    [string]$Msys2Root = "C:\msys64",
    [switch]$SkipBuild,
    [int]$BuildJobs = 4
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Write-Refusal {
    param([string]$Message)
    [Console]::Error::WriteLine("z23-setup: REFUSE: $Message")
}

function Write-Note {
    param([string]$Message)
    [Console]::Error::WriteLine("z23-setup: $Message")
}

# Resolve checkout root from $PSScriptRoot when not supplied.
if ([string]::IsNullOrEmpty($CheckoutRoot)) {
    if ([string]::IsNullOrEmpty($PSScriptRoot)) {
        Write-Refusal "cannot derive checkout root; pass -CheckoutRoot explicitly"
        exit 1
    }
    # $PSScriptRoot is tools/dev; go up two levels.
    $CheckoutRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
}
$CheckoutRoot = Resolve-Path -LiteralPath $CheckoutRoot | Select-Object -ExpandProperty Path

$Bash = Join-Path $Msys2Root 'usr\bin\bash.exe'
$Pacman = Join-Path $Msys2Root 'usr\bin\pacman.exe'

# ---------------------------------------------------------------------------
# MSYS2 presence and architecture checks
# ---------------------------------------------------------------------------
$arch = $env:PROCESSOR_ARCHITECTURE
if ($arch -ne 'AMD64') {
    Write-Refusal "this script is verified only for x86_64 Windows (got $arch)"
    exit 1
}

if (-not (Test-Path -LiteralPath $Bash)) {
    Write-Refusal "MSYS2 bash not found at $Bash`n" +
                  "Install MSYS2 from https://www.msys2.org to $Msys2Root, " +
                  "or pass -Msys2Root to an existing installation."
    exit 1
}

if (-not (Test-Path -LiteralPath $Pacman)) {
    Write-Refusal "MSYS2 pacman not found at $Pacman; installation is incomplete"
    exit 1
}

# ---------------------------------------------------------------------------
# Package manifest: every tool the Makefile probes, mapped to a UCRT64 package.
# Keep this in sync with tools/scripts/vendor_prereqs.tsv.
# ---------------------------------------------------------------------------
$RequiredPackages = @(
    'mingw-w64-ucrt-x86_64-gcc',      # cc, c++
    'mingw-w64-ucrt-x86_64-gcc-libs',
    'mingw-w64-ucrt-x86_64-binutils', # ar, nm
    'make',
    'git',
    'coreutils',                      # sha256sum
    'tar',
    'perl',
    'patch',
    'unzip',
    'curl',
    'wget',
    'diffutils',
    'autoconf',
    'automake',
    'libtool',
    'pkgconf',
    'mingw-w64-ucrt-x86_64-cmake'     # optional but preferred for LevelDB
)

# Use MSYSTEM=UCRT64 and CHERE_INVOKING so pacman runs in the right environment
# without launching an interactive shell.
$env:MSYSTEM = 'UCRT64'
$env:CHERE_INVOKING = '1'

Write-Note "updating MSYS2 package database..."
& $Bash '-lc' "pacman -Syy --noconfirm"
if ($LASTEXITCODE -ne 0) {
    Write-Refusal "pacman -Syy failed (exit $LASTEXITCODE)"
    exit 1
}

Write-Note "installing required packages..."
$pkgList = $RequiredPackages -join ' '
& $Bash '-lc' "pacman -S --needed --noconfirm $pkgList"
if ($LASTEXITCODE -ne 0) {
    Write-Refusal "pacman install failed (exit $LASTEXITCODE)"
    exit 1
}

# ---------------------------------------------------------------------------
# Build phase inside the UCRT64 environment.
# The PATH order is critical: UCRT64 toolchain first, then MSYS2 utilities.
# ---------------------------------------------------------------------------
$repoRoot = $CheckoutRoot -replace '\\', '/'
$repoRoot = $repoRoot -replace '^([A-Za-z]):', '/$1'

Write-Note "running make setup..."
& $Bash '-lc' "cd '$repoRoot' && export PATH='/c/msys64/ucrt64/bin:/c/msys64/usr/bin:`$PATH' && make setup"
if ($LASTEXITCODE -ne 0) {
    Write-Refusal "make setup failed (exit $LASTEXITCODE)"
    exit 1
}

if ($SkipBuild) {
    Write-Note "setup complete; build skipped by -SkipBuild"
    Write-Output (Join-Path $CheckoutRoot 'build\bin\z23.exe')
    exit 0
}

Write-Note "building z23 with -j$BuildJobs..."
& $Bash '-lc' "cd '$repoRoot' && export PATH='/c/msys64/ucrt64/bin:/c/msys64/usr/bin:`$PATH' && make -j$BuildJobs z23"
if ($LASTEXITCODE -ne 0) {
    Write-Refusal "make z23 failed (exit $LASTEXITCODE)"
    exit 1
}

$exe = Join-Path $CheckoutRoot 'build\bin\z23.exe'
if (-not (Test-Path -LiteralPath $exe)) {
    Write-Refusal "built binary missing: $exe"
    exit 1
}

Write-Note "build complete: $exe"
Write-Output $exe
