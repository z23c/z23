# Copyright 2026 Rhett Creighton - Apache License 2.0
#
# windows-make.ps1 — run `make` inside the MSYS2 UCRT64 environment from Windows.
#
# Usage:
#   .\tools\dev\windows-make.ps1 z23
#   .\tools\dev\windows-make.ps1 -j4 t-fast ONLY=mesh_route
#   .\tools\dev\windows-make.ps1 windows-acceptance
#   .\tools\dev\windows-make.ps1 -Msys2Root D:\msys64 -DryRun z23
#
# This is a thin courier: it ensures the UCRT64 toolchain is on PATH, then
# invokes the real make with the same arguments. It is the normal way for a
# Windows agent or developer to run the repository's Makefile without
# remembering the MSYS2 bash quoting.

[CmdletBinding()]
param(
    [string]$CheckoutRoot = "",
    [string]$Msys2Root = "C:\msys64",
    [switch]$DryRun,
    [Parameter(ValueFromRemainingArguments=$true)]$MakeArgs
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'windows-path.ps1')
Assert-Z23MsysPathContract

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

$repoRoot = ConvertTo-Z23MsysPath -Path $CheckoutRoot
$msys2RootMsys = ConvertTo-Z23MsysPath -Path $Msys2Root

$env:MSYSTEM = 'UCRT64'
$env:CHERE_INVOKING = '1'
$env:Z23_CHECKOUT_ROOT_MSYS = $repoRoot
$env:Z23_MSYS2_ROOT_MSYS = $msys2RootMsys

$argString = if ($MakeArgs) { $MakeArgs -join ' ' } else { '' }
$command = 'cd "$Z23_CHECKOUT_ROOT_MSYS" && export PATH="$Z23_MSYS2_ROOT_MSYS/ucrt64/bin:$Z23_MSYS2_ROOT_MSYS/usr/bin:$PATH" && make'
if (-not [string]::IsNullOrEmpty($argString)) {
    $command += " $argString"
}
if ($DryRun) {
    Write-Output "Z23_CHECKOUT_ROOT_MSYS=$repoRoot"
    Write-Output "Z23_MSYS2_ROOT_MSYS=$msys2RootMsys"
    Write-Output $command
    exit 0
}
& $Bash '-lc' $command
exit $LASTEXITCODE
