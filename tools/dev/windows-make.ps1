# Copyright 2026 Rhett Creighton - Apache License 2.0
#
# windows-make.ps1 — run `make` inside the MSYS2 UCRT64 environment from Windows.
#
# Usage:
#   .\tools\dev\windows-make.ps1 z23
#   .\tools\dev\windows-make.ps1 -j4 t-fast ONLY=mesh_route
#   .\tools\dev\windows-make.ps1 windows-acceptance
#
# This is a thin courier: it ensures the UCRT64 toolchain is on PATH, then
# invokes the real make with the same arguments. It is the normal way for a
# Windows agent or developer to run the repository's Makefile without
# remembering the MSYS2 bash quoting.

[CmdletBinding()]
param(
    [string]$CheckoutRoot = "",
    [string]$Msys2Root = "C:\msys64",
    [Parameter(ValueFromRemainingArguments=$true)]$MakeArgs
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

if ([string]::IsNullOrEmpty($CheckoutRoot)) {
    if ([string]::IsNullOrEmpty($PSScriptRoot)) {
        [Console]::Error::WriteLine("z23-make: REFUSE: cannot derive checkout root; pass -CheckoutRoot explicitly")
        exit 1
    }
    $CheckoutRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
}
$CheckoutRoot = Resolve-Path -LiteralPath $CheckoutRoot | Select-Object -ExpandProperty Path

$Bash = Join-Path $Msys2Root 'usr\bin\bash.exe'
if (-not (Test-Path -LiteralPath $Bash)) {
    [Console]::Error::WriteLine("z23-make: REFUSE: MSYS2 bash not found at $Bash; run tools\dev\windows-setup.ps1 first")
    exit 1
}

$repoRoot = $CheckoutRoot -replace '\\', '/'
$repoRoot = $repoRoot -replace '^([A-Za-z]):', '/$1'

$env:MSYSTEM = 'UCRT64'
$env:CHERE_INVOKING = '1'

$argString = if ($MakeArgs) { $MakeArgs -join ' ' } else { '' }
& $Bash '-lc' "cd '$repoRoot' && export PATH='/c/msys64/ucrt64/bin:/c/msys64/usr/bin:`$PATH' && make $argString"
exit $LASTEXITCODE
