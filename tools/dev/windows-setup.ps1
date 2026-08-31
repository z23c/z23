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
#   .\tools\dev\windows-setup.ps1 -Msys2Root D:\msys64 -DryRun
#
# The script refuses rather than guess when it cannot find or install MSYS2.

[CmdletBinding()]
param(
    [string]$CheckoutRoot = "",
    [string]$Msys2Root = "C:\msys64",
    [switch]$SkipBuild,
    [switch]$DryRun,
    [int]$BuildJobs = 4
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'windows-path.ps1')
Assert-Z23MsysPathContract

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
try {
    $Msys2Root = Resolve-Z23Msys2Root -Path $Msys2Root
} catch {
    Write-Refusal $_.Exception.Message
    exit 1
}

$LogicalProcessors = [Environment]::ProcessorCount
if ($BuildJobs -lt 1 -or $BuildJobs -gt [Math]::Min(32, $LogicalProcessors)) {
    Write-Refusal "BuildJobs must be between 1 and $([Math]::Min(32, $LogicalProcessors)) on this host (got $BuildJobs)"
    exit 1
}

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
    'base-devel',
    'gcc',
    'git',
    'curl',
    'wget',
    'unzip',
    'mingw-w64-ucrt-x86_64-toolchain',
    'mingw-w64-ucrt-x86_64-clang',
    'mingw-w64-ucrt-x86_64-clang-tools-extra',
    'mingw-w64-ucrt-x86_64-lld',
    'mingw-w64-ucrt-x86_64-cmake',
    'mingw-w64-ucrt-x86_64-ninja',
    'mingw-w64-ucrt-x86_64-libsystre'
)

# Use MSYSTEM=UCRT64 and CHERE_INVOKING so pacman runs in the right environment
# without launching an interactive shell.
$env:MSYSTEM = 'UCRT64'
$env:CHERE_INVOKING = '1'
$NativeUcrtBin = Join-Path $Msys2Root 'ucrt64\bin'
$NativeUsrBin = Join-Path $Msys2Root 'usr\bin'
# Native compiler children resolve their DLLs with Windows PATH semantics;
# MSYS spellings added inside Bash are not sufficient for the PE loader.
$env:Path = "$NativeUcrtBin;$NativeUsrBin;$env:Path"
$repoRoot = ConvertTo-Z23MsysPath -Path $CheckoutRoot
$msys2RootMsys = ConvertTo-Z23MsysPath -Path $Msys2Root
$env:Z23_CHECKOUT_ROOT_MSYS = $repoRoot
$env:Z23_MSYS2_ROOT_MSYS = $msys2RootMsys
$MakeWrapper = Join-Path $PSScriptRoot 'windows-make.ps1'

$pkgList = $RequiredPackages -join ' '

if ($DryRun) {
    Write-Output "Z23_CHECKOUT_ROOT_MSYS=$repoRoot"
    Write-Output "Z23_MSYS2_ROOT_MSYS=$msys2RootMsys"
    Write-Output "NATIVE_PATH_PREFIX=$NativeUcrtBin;$NativeUsrBin"
    Write-Output "pacman -Syu --noconfirm (pass 1)"
    Write-Output "pacman -Syu --noconfirm (pass 2)"
    Write-Output "pacman -S --needed --noconfirm $pkgList"
    Write-Output 'compiler-smoke: gcc and clang -std=c23 compile and execute'
    & $MakeWrapper '-CheckoutRoot' $CheckoutRoot '-Msys2Root' $Msys2Root `
        '-DryRun' 'setup'
    if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
    if (-not $SkipBuild) {
        & $MakeWrapper '-CheckoutRoot' $CheckoutRoot '-Msys2Root' $Msys2Root `
            '-DryRun' "-j$BuildJobs" 'z23'
        if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
    }
    exit 0
}

# Setup necessarily runs package-manager and compiler bootstrap processes
# before the repository's native Job-Object runner exists. Make those tools
# inherit fail-fast, headless Windows error handling so a damaged compiler or
# DLL reports failure instead of opening a blocking WER/critical-error popup.
Enable-Z23NativeErrorMode

Write-Note "fully upgrading MSYS2 (rolling releases do not support partial upgrades)..."
for ($UpgradePass = 1; $UpgradePass -le 2; $UpgradePass++) {
    & $Bash '-lc' 'exec pacman -Syu --noconfirm'
    if ($LASTEXITCODE -ne 0) {
        Write-Refusal "pacman -Syu pass $UpgradePass failed (exit $LASTEXITCODE); reopen MSYS2, complete pacman -Syu, then rerun this script"
        exit 1
    }
}

Write-Note "installing required packages..."
& $Bash '-lc' 'exec pacman -S --needed --noconfirm "$@"' `
    'z23-windows-setup' @RequiredPackages
if ($LASTEXITCODE -ne 0) {
    Write-Refusal "pacman install failed (exit $LASTEXITCODE)"
    exit 1
}

Write-Note "running GCC and Clang C23 compile/execute smoke probes..."
$SmokeProgram = @'
set -euo pipefail
export PATH="$1/ucrt64/bin:$1/usr/bin:$PATH"
d=$(mktemp -d)
trap 'rm -rf "$d"' EXIT
printf 'int main(void){return 0;}\n' >"$d/probe.c"
for cc in gcc clang; do
    "$cc" -std=c23 -Wall -Wextra -Werror -pedantic \
        "$d/probe.c" -o "$d/probe.exe"
    "$d/probe.exe"
done
'@
& $Bash '-lc' $SmokeProgram 'z23-windows-setup' $msys2RootMsys
if ($LASTEXITCODE -ne 0) {
    Write-Refusal "C23 compiler smoke probe failed (exit $LASTEXITCODE); repair the MSYS2 UCRT64 installation before building"
    exit 1
}

Write-Note "running hosted zcc bootstrap and native-child smoke probe..."
$ZccSmokeProgram = @'
set -euo pipefail
repo=$1
msys_root=$2
export PATH="$msys_root/ucrt64/bin:$msys_root/usr/bin:$PATH"
d=$(mktemp -d)
trap 'rm -rf "$d"' EXIT
printf 'int main(void){return 0;}\n' >"$d/probe.c"
zcc=$(ZCL_BIN_DIR="$d/bin" ZCC_DIR="$d/cache" \
    "$repo/tools/dev/zcc_bootstrap.sh")
[ -x "$zcc" ]
ZCC_DIR="$d/cache" "$zcc" gcc -std=c23 -Wall -Wextra -Werror \
    -pedantic "$d/probe.c" -o "$d/probe.exe"
"$d/probe.exe"
'@
& $Bash '-lc' $ZccSmokeProgram 'z23-windows-zcc-smoke' $repoRoot $msys2RootMsys
if ($LASTEXITCODE -ne 0) {
    Write-Refusal "hosted zcc bootstrap/native-child smoke failed (exit $LASTEXITCODE); verify the MSYS gcc and UCRT64 toolchains"
    exit 1
}

# ---------------------------------------------------------------------------
# Build phase inside the UCRT64 environment.
# The PATH order is critical: UCRT64 toolchain first, then MSYS2 utilities.
# ---------------------------------------------------------------------------
Write-Note "running make setup..."
& $MakeWrapper '-CheckoutRoot' $CheckoutRoot '-Msys2Root' $Msys2Root 'setup'
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
& $MakeWrapper '-CheckoutRoot' $CheckoutRoot '-Msys2Root' $Msys2Root `
    "-j$BuildJobs" 'z23'
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
