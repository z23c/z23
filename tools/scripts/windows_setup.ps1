# Copyright 2026 Rhett Creighton - Apache License 2.0
#
# windows_setup.ps1 — bootstrap a fresh Windows machine for the Z23 C23
# developer journey. Hides MSYS2, UCRT64, package installation, compiler
# discovery, and the vendor build behind one command.
#
# This script is idempotent: running it again repairs/upgrades missing pieces
# without reinstalling from scratch.
#
# Usage (from the checkout root):
#   powershell -ExecutionPolicy Bypass -File tools\scripts\windows_setup.ps1
#   or: z23 setup

[CmdletBinding()]
param(
    [string]$CheckoutRoot = (Split-Path -Parent (Split-Path -Parent $PSScriptRoot)),
    [string]$Msys2Root = "C:\msys64",
    [string]$Msys2InstallerUrl = "https://github.com/msys2/msys2-installer/releases/download/2024-07-27/msys2-x86_64-20240727.exe",
    [switch]$SkipMsys2Install,
    [switch]$SkipVendor
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Write-Refusal {
    param([string]$Message)
    [Console]::Error.WriteLine("z23-setup: REFUSE: $Message")
}

function Write-Note {
    param([string]$Message)
    [Console]::Error.WriteLine("z23-setup: $Message")
}

$CheckoutRoot = Resolve-Path -LiteralPath $CheckoutRoot | Select-Object -ExpandProperty Path
$Bash = Join-Path $Msys2Root 'usr\bin\bash.exe'
$Pacman = Join-Path $Msys2Root 'usr\bin\pacman.exe'

# ── MSYS2 presence ─────────────────────────────────────────────────────────
if (-not (Test-Path -LiteralPath $Bash)) {
    if ($SkipMsys2Install) {
        Write-Refusal "MSYS2 not found at $Msys2Root and -SkipMsys2Install is set"
        exit 1
    }
    Write-Note "MSYS2 not found at $Msys2Root; downloading installer..."
    $installer = Join-Path $env:TEMP (Split-Path -Leaf $Msys2InstallerUrl)
    try {
        Invoke-WebRequest -Uri $Msys2InstallerUrl -OutFile $installer -UseBasicParsing -TimeoutSec 300
    } catch {
        Write-Refusal "could not download MSYS2 installer: $_"
        exit 1
    }
    Write-Note "installing MSYS2 to $Msys2Root (this takes a minute)..."
    & $installer 'in' '--confirm-command' '--accept-messages' "--root=$Msys2Root"
    if ($LASTEXITCODE -ne 0) {
        Write-Refusal "MSYS2 installer exited $LASTEXITCODE"
        exit 1
    }
    if (-not (Test-Path -LiteralPath $Bash)) {
        Write-Refusal "MSYS2 installer finished but bash is missing at $Bash"
        exit 1
    }
}

# ── UCRT64 toolchain and dependencies ──────────────────────────────────────
$packages = @(
    'base-devel',
    'git',
    'mingw-w64-ucrt-x86_64-toolchain',
    'mingw-w64-ucrt-x86_64-clang',
    'mingw-w64-ucrt-x86_64-clang-tools-extra',
    'mingw-w64-ucrt-x86_64-lld',
    'mingw-w64-ucrt-x86_64-cmake',
    'mingw-w64-ucrt-x86_64-ninja',
    'mingw-w64-ucrt-x86_64-libsystre'
)

Write-Note "updating MSYS2 package database..."
& $Pacman '-Syu' '--noconfirm'
# pacman -Syu may exit 1 when it closes the shell for a runtime update; continue.

Write-Note "installing UCRT64 toolchain and dependencies..."
& $Pacman '-S' '--needed' '--noconfirm' @packages
if ($LASTEXITCODE -ne 0) {
    Write-Refusal "pacman failed to install required packages (exit $LASTEXITCODE)"
    exit 1
}

# ── Repository setup ───────────────────────────────────────────────────────
$repoRoot = $CheckoutRoot -replace '\\', '/'
$repoRoot = $repoRoot -replace '^([A-Za-z]):', '/$1'

function Invoke-InUcrt64 {
    param([string]$Command)
    $env:MSYSTEM = 'UCRT64'
    $env:CHERE_INVOKING = '1'
    & $Bash '-lc' $Command
    return $LASTEXITCODE
}

Write-Note "running make setup in UCRT64..."
$rc = Invoke-InUcrt64 "cd '$repoRoot' && make setup"
if ($rc -ne 0) {
    Write-Refusal "make setup failed (exit $rc)"
    exit 1
}

if (-not $SkipVendor) {
    Write-Note "running make vendor in UCRT64 (one-time vendored archive build)..."
    $rc = Invoke-InUcrt64 "cd '$repoRoot' && make vendor"
    if ($rc -ne 0) {
        Write-Refusal "make vendor failed (exit $rc)"
        exit 1
    }
}

Write-Note "running make z23 in UCRT64..."
$rc = Invoke-InUcrt64 "cd '$repoRoot' && make -j`$(nproc) z23"
if ($rc -ne 0) {
    Write-Refusal "make z23 failed (exit $rc)"
    exit 1
}

Write-Note "setup complete. Next: z23 new ball; z23 dev"
