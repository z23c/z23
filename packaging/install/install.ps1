# Copyright 2026 Rhett Creighton - Apache License 2.0
#
# install.ps1 - the Windows front door served at the project domain.
#
# Same four steps as packaging/install/install.sh, and nothing else: name this
# machine, fetch the one C23 bootstrap binary published for it, check its
# SHA-256 against the digest baked in below, and run it with every argument
# forwarded. It used to be 322 lines that re-derived the release-pin channels,
# the agreement rule, the platform refusal, the installer verification and the
# handoff a SECOND time, by hand, in a second language. Two implementations of
# one security judgement drift, and the drift is invisible until the day they
# answer differently about whether to install something. There is now one, in
# C23, inside the binary this fetches - and it runs only after a digest check,
# where this file runs before one.
#
# TODAY THERE IS NO WINDOWS BOOTSTRAP. packaging/release/build_release.sh is
# x86_64-linux only, so $BootPins below has no Windows row and this refuses
# cleanly, having downloaded nothing and changed nothing.
[CmdletBinding()]
param([Parameter(ValueFromRemainingArguments = $true)][string[]]$Forward)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
# platform -> SHA-256 of its published bootstrap. The all-zero digest is the
# SENTINEL: nothing is published for that platform yet.
$BootZero = '0' * 64
$BootPins = @{}
$Origin = if ($env:Z23_INSTALL_TEST_ORIGIN) { $env:Z23_INSTALL_TEST_ORIGIN } else { 'https://z23.sh' }
$arch = switch ($env:PROCESSOR_ARCHITECTURE) { 'AMD64' { 'x86_64' } 'ARM64' { 'aarch64' } $null { 'unknown' } default { "$($env:PROCESSOR_ARCHITECTURE)".ToLowerInvariant() } }
$platform = "windows-$arch"
$touched = $false
$work = Join-Path ([System.IO.Path]::GetTempPath()) ("z23-install-" + [guid]::NewGuid().ToString('N'))
try {
    if (-not $BootPins.ContainsKey($platform)) { throw "no Z23 bootstrap is published for $platform; published: none for Windows, linux-x86_64 on Linux" }
    if ($BootPins[$platform] -ceq $BootZero) { throw "no Z23 bootstrap is pinned into this script yet - nothing was downloaded" }
    New-Item -ItemType Directory -Path $work -Force | Out-Null
    $touched = $true
    $boot = Join-Path $work 'z23-bootstrap.exe'
    Invoke-WebRequest -Uri "$Origin/bootstrap/$platform/z23-bootstrap.exe" -OutFile $boot -UseBasicParsing -MaximumRedirection 2 -TimeoutSec 120 -ErrorAction Stop | Out-Null
    if ((Get-Item -LiteralPath $boot).Length -gt 33554432) { throw "the served bootstrap is larger than this front door will hash" }
    if ((Get-FileHash -LiteralPath $boot -Algorithm SHA256).Hash.ToLowerInvariant() -cne $BootPins[$platform]) { throw "bootstrap digest mismatch - $Origin served bytes this front door does not name" }
    & $boot @Forward
    $code = Get-Variable -Name LASTEXITCODE -ValueOnly -ErrorAction SilentlyContinue
    exit $(if ($null -eq $code) { 0 } else { $code })
} catch {
    [Console]::Error.WriteLine("z23-install: REFUSE: $($_.Exception.Message)")
    if (-not $touched) { [Console]::Error.WriteLine("z23-install: nothing was downloaded and nothing on this machine was changed.") }
    exit 1
} finally {
    if (Test-Path -LiteralPath $work) { Remove-Item -LiteralPath $work -Recurse -Force }
}
