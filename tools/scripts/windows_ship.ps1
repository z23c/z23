# Copyright 2026 Rhett Creighton - Apache License 2.0
#
# windows_ship.ps1 — package a built Windows GUI app into an audited,
# self-contained release directory.
#
# The Z23 Windows build links vendored dependencies statically and admits only
# declared Windows system DLLs, so the release root is the single .exe plus a
# manifest that binds source identity, compiler, and output hash.

[CmdletBinding()]
param(
    [string]$CheckoutRoot = "",
    [Parameter(Mandatory=$true)][string]$AppName,
    [string]$Msys2Root = "C:\msys64",
    [string]$OutDir = ""
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Write-Refusal {
    param([string]$Message)
    [Console]::Error.WriteLine("z23-ship: REFUSE: $Message")
}

function Write-Note {
    param([string]$Message)
    [Console]::Error.WriteLine("z23-ship: $Message")
}

# $PSScriptRoot is empty inside param() default expressions on Windows PowerShell
# 5.1, so resolve any path that depends on it after the param block.
if ([string]::IsNullOrEmpty($CheckoutRoot)) {
    if ([string]::IsNullOrEmpty($PSScriptRoot)) {
        Write-Refusal "cannot derive checkout root; pass -CheckoutRoot explicitly"
        exit 1
    }
    $CheckoutRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
}

$CheckoutRoot = Resolve-Path -LiteralPath $CheckoutRoot | Select-Object -ExpandProperty Path
$Bash = Join-Path $Msys2Root 'usr\bin\bash.exe'
if (-not (Test-Path -LiteralPath $Bash)) {
    Write-Refusal "MSYS2 bash not found at $Bash; run 'z23 setup' first"
    exit 1
}

$repoRoot = $CheckoutRoot -replace '\\', '/'
$repoRoot = $repoRoot -replace '^([A-Za-z]):', '/$1'

$env:MSYSTEM = 'UCRT64'
$env:CHERE_INVOKING = '1'

# Ensure the binary is current. Build the file target, not the phony run target,
# so a GUI app is not launched during packaging.
Write-Note "building $AppName..."
& $Bash '-lc' "cd '$repoRoot' && make build/bin/$AppName"
if ($LASTEXITCODE -ne 0) {
    Write-Refusal "make build/bin/$AppName failed (exit $LASTEXITCODE)"
    exit 1
}

$srcExe = Join-Path $CheckoutRoot "build\bin\$AppName.exe"
if (-not (Test-Path -LiteralPath $srcExe)) {
    Write-Refusal "built binary missing: $srcExe"
    exit 1
}

$shipRoot = if ($OutDir) { $OutDir } else { Join-Path $CheckoutRoot "build\ship\$AppName" }
$null = New-Item -ItemType Directory -Path $shipRoot -Force
$dstExe = Join-Path $shipRoot "$AppName.exe"
Copy-Item -LiteralPath $srcExe -Destination $dstExe -Force

# SHA-256 of the shipped executable (System.Security.Cryptography works on
# Windows PowerShell 5.1 and PowerShell 7, where Get-FileHash may not load).
$sha = [System.Security.Cryptography.SHA256]::Create()
$fs = [System.IO.File]::OpenRead($dstExe)
try {
    $bytes = $sha.ComputeHash($fs)
} finally {
    $fs.Close()
    $sha.Dispose()
}
$exeHash = ([BitConverter]::ToString($bytes)).Replace('-', '').ToLowerInvariant()

# Source identity from git. Use the commit author date as shipped_at so two
# identical checkouts produce identical manifests.
$sourceId = ''
$gitCommit = ''
$shippedAt = ''
try {
    $gitCommit = (& git -C $CheckoutRoot rev-parse HEAD 2>$null)
    $sourceId = $gitCommit
    $shippedAt = (& git -C $CheckoutRoot show -s --format='%cI' HEAD 2>$null)
} catch { }

$compiler = ''
try {
    $compiler = (& $Bash '-lc' 'gcc --version | head -1' 2>$null) -join " "
} catch { }

$manifest = @{
    app = $AppName
    platform = 'windows-x86_64'
    shipped_at = $shippedAt
    source_commit = $gitCommit
    source_identity = $sourceId
    compiler = $compiler
    exe = "$AppName.exe"
    exe_sha256 = $exeHash
} | ConvertTo-Json -Depth 2

$manifestPath = Join-Path $shipRoot 'manifest.json'
$manifest | Set-Content -LiteralPath $manifestPath -Encoding UTF8

$sumLine = "$exeHash *$AppName.exe"
$sumsPath = Join-Path $shipRoot 'SHA256SUMS'
$sumLine | Set-Content -LiteralPath $sumsPath -Encoding UTF8

Write-Note "shipped $AppName to $shipRoot"
Write-Note "exe sha256: $exeHash"
Write-Output (Resolve-Path -LiteralPath $shipRoot).Path
