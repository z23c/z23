# Copyright 2026 Rhett Creighton - Apache License 2.0
#
# install.ps1 - the Windows front door served at the project domain.
#
# Same job and same discipline as packaging/install/install.sh:
#   1. decide whether a runtime is published for THIS machine, and name the
#      ones that are if it is not;
#   2. learn the release pin from THREE independent systems - a value baked
#      in below, a DNS TXT record on the domain, and the source repository -
#      and refuse unless they agree;
#   3. verify the real installer's bytes against that agreed pin BEFORE one
#      line of it runs;
#   4. hand off, passing every attestation through so the installer judges
#      the same evidence again for itself.
#
# TODAY THERE IS NO WINDOWS RUNTIME. packaging/release/build_release.sh is
# x86_64-linux only, so $PublishedPlatforms below is empty for Windows and
# this script refuses cleanly, having downloaded nothing and changed nothing.
# It is written so the day that release lands is a one-line change to that
# table plus a pin - not a rewrite: the pin agreement, the digest check and
# the handoff are all here and all exercised by -SelfTest, which runs the
# judgement in both directions without touching the network.
#
# No prompt and no terminal is required: this runs under a coding agent as
# often as under a person, and every refusal names the thing it protects,
# never the shape of the caller.
[CmdletBinding()]
param(
    [switch]$SelfTest,
    [switch]$PrintPin
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# What we publish. Windows is absent on purpose - see the header. Adding
# 'windows-x86_64' here is what turns this script on.
$PublishedPlatforms = @()
$LinuxPublished = 'linux-x86_64'

$Origin = if ($env:Z23_INSTALL_TEST_ORIGIN) { $env:Z23_INSTALL_TEST_ORIGIN } else { 'https://z23.sh' }
$PinDnsName = if ($env:Z23_INSTALL_TEST_PIN_DNS) { $env:Z23_INSTALL_TEST_PIN_DNS } else { '_z23-pin.z23.sh' }
$PinRepoUrl = if ($env:Z23_INSTALL_TEST_PIN_REPO_URL) { $env:Z23_INSTALL_TEST_PIN_REPO_URL } else { 'https://raw.githubusercontent.com/ZclassiC23/zclassic/main/packaging/install/RELEASE_PIN' }

# Source 1 of 3: the pin baked into these bytes, rewritten by the release
# cutter. The all-zero sentinel means NO RELEASE IS PINNED YET.
$PinZero = '0' * 64
$PinBaked = "z23-pin-v1:${PinZero}:${PinZero}"
if ($env:Z23_INSTALL_TEST_BAKED_PIN) { $PinBaked = $env:Z23_INSTALL_TEST_BAKED_PIN }

function Write-Refusal {
    param([string]$Message)
    [Console]::Error.WriteLine("z23-install: REFUSE: $Message")
}

function Write-Note {
    param([string]$Message)
    [Console]::Error.WriteLine("z23-install: $Message")
}

function Test-Sha256Hex {
    param([string]$Value)
    if ($null -eq $Value) { return $false }
    return $Value -cmatch '^[0-9a-f]{64}$'
}

# z23-pin-v1:<64 hex manifest>:<64 hex installer>. Returns $null when the
# text is not a pin at all, which the callers translate into UNREACHABLE,
# never into a dissenting opinion.
function Read-Pin {
    param([string]$Text)
    if ([string]::IsNullOrWhiteSpace($Text)) { return $null }
    # The unset sentinel declares that nothing is pinned; it is not a pin.
    if ($Text.Trim() -ceq "z23-pin-v1:${PinZero}:${PinZero}") { return $null }
    $parts = $Text.Trim() -split ':'
    if ($parts.Count -ne 3) { return $null }
    if ($parts[0] -cne 'z23-pin-v1') { return $null }
    if (-not (Test-Sha256Hex $parts[1])) { return $null }
    if (-not (Test-Sha256Hex $parts[2])) { return $null }
    return [pscustomobject]@{
        Pin       = $Text.Trim()
        Manifest  = $parts[1]
        Installer = $parts[2]
    }
}

function New-Attestation {
    param([string]$OriginName, [string]$Pin, [string]$Reason)
    return [pscustomobject]@{ Origin = $OriginName; Pin = $Pin; Reason = $Reason }
}

# The judgement, identical in policy to install.sh and install_z23.sh:
#   * any two answered pins that differ -> refuse, never a majority vote;
#   * fewer than two answered sources  -> refuse, no silent degradation;
#   * exactly two agreeing             -> proceed, and say what was missing.
# Unreachable is never rendered as disagreement.
function Resolve-Pin {
    param([object[]]$Attestations)
    $answered = @($Attestations | Where-Object { $_.Pin })
    $unreachable = @($Attestations | Where-Object { -not $_.Pin } |
        ForEach-Object { "$($_.Origin)=$($_.Reason)" })
    $missing = if ($unreachable.Count -gt 0) { $unreachable -join ', ' } else { 'none' }
    foreach ($a in $answered) {
        if ($a.Pin -cne $answered[0].Pin) {
            Write-Note "attested pin $($answered[0].Origin)=$($answered[0].Pin)"
            Write-Note "attested pin $($a.Origin)=$($a.Pin)"
            throw "release pin disagreement between $($answered[0].Origin) and $($a.Origin) - refusing to install either"
        }
    }
    if ($answered.Count -lt 2) {
        throw "release pin quorum: $($answered.Count) of 3 sources answered, two independent sources are required (unreachable: $missing)"
    }
    if ($answered.Count -lt 3) {
        Write-Note "release pin agreed by $($answered.Count) of 3 sources (unreachable: $missing)"
    }
    return $answered[0].Pin
}

function Get-BakedAttestation {
    if ($PinBaked -ceq "z23-pin-v1:${PinZero}:${PinZero}") {
        return New-Attestation 'baked' $null 'no-release-pinned'
    }
    $parsed = Read-Pin $PinBaked
    if ($null -eq $parsed) { return New-Attestation 'baked' $null 'malformed-answer' }
    return New-Attestation 'baked' $parsed.Pin $null
}

# Source 2 of 3. Resolve-DnsName ships with Windows; nslookup is the fallback
# on a stripped image. We deliberately do NOT fall back to DNS-over-HTTPS:
# buying this source back by trusting an unnamed third-party resolver is a
# worse dependency than the one it replaces.
function Get-DnsAttestation {
    $answers = @()
    try {
        if (Get-Command Resolve-DnsName -ErrorAction SilentlyContinue) {
            $answers = @(Resolve-DnsName -Name $PinDnsName -Type TXT -ErrorAction Stop |
                ForEach-Object { $_.Strings } | Where-Object { $_ })
        } elseif (Get-Command nslookup -ErrorAction SilentlyContinue) {
            $answers = @(& nslookup -type=TXT $PinDnsName 2>$null)
        } else {
            return New-Attestation 'dns' $null 'no-dns-tool'
        }
    } catch {
        return New-Attestation 'dns' $null 'lookup-failed'
    }
    if ($answers.Count -eq 0) { return New-Attestation 'dns' $null 'no-answer' }
    foreach ($line in $answers) {
        foreach ($token in ([string]$line -split '["\s]+')) {
            $parsed = Read-Pin $token
            if ($null -ne $parsed) { return New-Attestation 'dns' $parsed.Pin $null }
        }
    }
    # A captive portal or a hijacked resolver answers with something that is
    # not a pin. That is unreachable, not a disagreement.
    return New-Attestation 'dns' $null 'malformed-answer'
}

# Invoke-WebRequest has no streaming size cap, so the ceiling is enforced on
# the file after transfer and the file is destroyed if it is over. That is
# weaker than curl --max-filesize on the sh side and is stated here rather
# than hidden: it bounds what is ever hashed, parsed or run, not what is
# briefly written to a temporary directory.
function Get-BoundedFile {
    param([string]$Url, [string]$Destination, [int]$MaxBytes, [int]$TimeoutSeconds)
    try {
        Invoke-WebRequest -Uri $Url -OutFile $Destination -UseBasicParsing `
            -MaximumRedirection 2 -TimeoutSec $TimeoutSeconds -ErrorAction Stop | Out-Null
    } catch {
        if (Test-Path -LiteralPath $Destination) { Remove-Item -LiteralPath $Destination -Force }
        return $false
    }
    if (-not (Test-Path -LiteralPath $Destination)) { return $false }
    if ((Get-Item -LiteralPath $Destination).Length -gt $MaxBytes) {
        Remove-Item -LiteralPath $Destination -Force
        return $false
    }
    return $true
}

function Get-RepoAttestation {
    param([string]$WorkDir)
    $file = Join-Path $WorkDir 'repo.pin'
    if (-not (Get-BoundedFile $PinRepoUrl $file 512 20)) {
        return New-Attestation 'repo' $null 'fetch-failed'
    }
    foreach ($line in (Get-Content -LiteralPath $file)) {
        $parsed = Read-Pin $line
        if ($null -ne $parsed) { return New-Attestation 'repo' $parsed.Pin $null }
    }
    return New-Attestation 'repo' $null 'malformed-answer'
}

function Get-Platform {
    $arch = $env:PROCESSOR_ARCHITECTURE
    if ([string]::IsNullOrEmpty($arch)) { return "windows-unknown" }
    switch ($arch) {
        'AMD64' { return 'windows-x86_64' }
        'ARM64' { return 'windows-aarch64' }
        'x86'   { return 'windows-x86' }
        default { return "windows-$($arch.ToLowerInvariant())" }
    }
}

# ── The mutation tests ─────────────────────────────────────────────────────
# The pipeline above cannot be run end to end until a Windows release exists,
# but the judgement can, and it is the part that decides whether anything
# gets installed. Both directions, in-process, no network.
function Invoke-SelfTest {
    $a = 'a' * 64
    $b = 'b' * 64
    $pin1 = "z23-pin-v1:${a}:${a}"
    $pin2 = "z23-pin-v1:${b}:${b}"
    $failures = @()

    $got = Resolve-Pin @(
        (New-Attestation 'baked' $pin1 $null),
        (New-Attestation 'dns' $pin1 $null),
        (New-Attestation 'repo' $pin1 $null))
    if ($got -cne $pin1) { $failures += 'three agreeing sources must resolve to the pin' }

    $got = Resolve-Pin @(
        (New-Attestation 'baked' $pin1 $null),
        (New-Attestation 'dns' $null 'no-dns-tool'),
        (New-Attestation 'repo' $pin1 $null))
    if ($got -cne $pin1) { $failures += 'two agreeing sources must resolve to the pin' }

    $refused = $false
    try {
        Resolve-Pin @(
            (New-Attestation 'baked' $pin1 $null),
            (New-Attestation 'dns' $pin1 $null),
            (New-Attestation 'repo' $pin2 $null)) | Out-Null
    } catch { $refused = $_.Exception.Message -like '*disagreement*' }
    if (-not $refused) { $failures += 'a dissenting source must refuse, never be outvoted' }

    $refused = $false
    try {
        Resolve-Pin @(
            (New-Attestation 'baked' $pin1 $null),
            (New-Attestation 'dns' $null 'no-dns-tool'),
            (New-Attestation 'repo' $null 'fetch-failed')) | Out-Null
    } catch { $refused = $_.Exception.Message -like '*quorum*' }
    if (-not $refused) { $failures += 'one answering source must refuse' }

    $refused = $false
    try {
        Resolve-Pin @(
            (New-Attestation 'baked' $null 'no-release-pinned'),
            (New-Attestation 'dns' $null 'malformed-answer'),
            (New-Attestation 'repo' $null 'fetch-failed')) | Out-Null
    } catch { $refused = $_.Exception.Message -like '*quorum*' }
    if (-not $refused) { $failures += 'no answering source must refuse' }

    if ($null -ne (Read-Pin 'z23-pin-v1:short:short')) { $failures += 'a short pin must not parse' }
    if ($null -ne (Read-Pin "z23-pin-v2:${a}:${a}")) { $failures += 'a foreign pin version must not parse' }
    if ($null -ne (Read-Pin 'this-domain-is-parked')) { $failures += 'a portal answer must not parse' }
    if ($null -eq (Read-Pin $pin1)) { $failures += 'a valid pin must parse' }
    if ((Get-BakedAttestation).Pin) { $failures += 'the all-zero sentinel must not count as a pin' }

    if ($failures.Count -gt 0) {
        foreach ($f in $failures) { Write-Refusal "selftest: $f" }
        exit 1
    }
    Write-Note 'install.ps1 selftest PASS'
    exit 0
}

if ($SelfTest) { Invoke-SelfTest }

$platform = Get-Platform
if ($PublishedPlatforms -notcontains $platform) {
    Write-Refusal "no Z23 runtime is published for $platform; published: $LinuxPublished"
    Write-Note "nothing was downloaded and nothing on this machine was changed."
    Write-Note "the Linux runtime is published and installs from a Linux shell; docs/work/BOOTSTRAP_PLAN.md carries the line."
    exit 1
}

$work = Join-Path ([System.IO.Path]::GetTempPath()) ("z23-install-" + [guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $work -Force | Out-Null
try {
    $attestations = @(
        (Get-BakedAttestation),
        (Get-DnsAttestation),
        (Get-RepoAttestation $work))
    $agreed = Resolve-Pin $attestations
    $pin = Read-Pin $agreed
    if ($null -eq $pin) { throw 'agreed pin is not a z23-pin-v1 record' }
    if ($PrintPin) { Write-Output $agreed; exit 0 }

    $installer = Join-Path $work 'install_z23.ps1'
    if (-not (Get-BoundedFile "$Origin/install_z23.ps1" $installer 262144 60)) {
        throw "could not fetch $Origin/install_z23.ps1"
    }
    $got = (Get-FileHash -LiteralPath $installer -Algorithm SHA256).Hash.ToLowerInvariant()
    if ($got -cne $pin.Installer) {
        throw "installer digest mismatch - $Origin served bytes the agreed release pin does not name"
    }

    $source = if ($env:Z23_RELEASE_SOURCE) { $env:Z23_RELEASE_SOURCE } else { "$Origin/release/$platform" }
    $argv = @("--source=$source", "--manifest-sha256=$($pin.Manifest)")
    foreach ($a in $attestations) {
        if ($a.Pin) { $argv += "--attest=$($a.Origin)=$($a.Pin)" }
        else { $argv += "--attest-unreachable=$($a.Origin)=$($a.Reason)" }
    }
    & $installer @argv
    $code = Get-Variable -Name LASTEXITCODE -ValueOnly -ErrorAction SilentlyContinue
    if ($null -eq $code) { $code = 0 }
    exit $code
} catch {
    Write-Refusal $_.Exception.Message
    exit 1
} finally {
    if (Test-Path -LiteralPath $work) { Remove-Item -LiteralPath $work -Recurse -Force }
}
