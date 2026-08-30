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
# THERE IS NO WINDOWS BOOTSTRAP, so $BootPins below has no Windows row and
# this file refuses cleanly, having downloaded nothing and changed nothing.
# It is worth being exact about what is and is not missing, because a runtime
# now EXISTS and it would be easy to mistake that for a release:
#   1. packaging/release/build_release.sh does package windows-x86_64 — a real
#      x86-64 PE built from the whole node source, cross-linked on Linux with
#      clang and the mingw-w64 sysroot, importing only Windows system DLLs,
#      with its own exact closed SHA-256 manifest.
#   2. tools/install/z23_bootstrap.c, the program this file exists to fetch,
#      is POSIX: uname(2), a UDP socket, fork/exec. It has no Windows build,
#      so there is no z23-bootstrap.exe to publish or to pin here.
#   3. there is no second stage on Windows either. A Windows bootstrap would
#      fetch install_z23.ps1, which does not exist.
#   4. the packaged PE has never been EXECUTED — the host that cross-links it
#      has no Windows machine and no Wine — and no Windows service lifecycle,
#      fresh-host install, restart persistence, running-image qualification or
#      rollback proof has been accepted.
# A platform-index authority is still needed as well: the current
# single-manifest pin cannot describe different per-platform releases.
# Adding a row below is therefore not a sufficient release action, and
# tools/lint/check_published_platforms.sh refuses a row the release cutter
# cannot actually produce a bootstrap for.
#
# These checks run only after this file is already executing. An irm-to-iex
# user trusts the z23.sh TLS origin for these first-stage bytes. A verified
# bootstrap must authenticate this file against an anchor obtained outside
# z23.sh before executing it.
#
# No prompt and no terminal is required: this runs under a coding agent as
# often as under a person, and every refusal names the thing it protects,
# never the shape of the caller.
[CmdletBinding()]
param([Parameter(ValueFromRemainingArguments = $true)][string[]]$Forward)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
# platform -> SHA-256 of the bootstrap published for it. The all-zero digest
# is the SENTINEL: something is named but nothing is published for it yet, and
# an empty table means no Windows platform is claimed at all. The release
# cutter (packaging/release/build_release.sh --front-door) writes the real
# rows into the copy it publishes; the checked-in copy stays a refusal.
$BootZero = '0' * 64
$BootPins = @{}
$Origin = if ($env:Z23_INSTALL_TEST_ORIGIN) { $env:Z23_INSTALL_TEST_ORIGIN } else { 'https://z23.sh' }
# Same rule as install.sh and lib/install/src/front_door_platform.c: fold only
# the AMD64/x86_64 alias. ARM64 lowercases to arm64 through the default arm,
# because arm64 is what the machine and the release cutter both call it.
$arch = switch ($env:PROCESSOR_ARCHITECTURE) { 'AMD64' { 'x86_64' } $null { 'unknown' } default { "$($env:PROCESSOR_ARCHITECTURE)".ToLowerInvariant() } }
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
