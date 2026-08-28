# Copyright 2026 Rhett Creighton. Licensed under Apache-2.0.

<#[
.SYNOPSIS
Black-box acceptance for the native Windows developer journey.

.DESCRIPTION
Run this on a clean Windows 10 22H2 or Windows 11 x64 machine from the stock
Windows PowerShell host.  The test deliberately invokes no bash, MSYS2, WSL,
compiler, SDK, CMake, Ninja, Make, Git, or package manager directly.  Those
details are private implementation details of the devkit.

The controller contract exercised here is:

  z23-dev bootstrap
  z23-dev create hello
  z23-dev develop <directory> --once
  z23-dev ship <directory>

Every command must be non-interactive when stdout is redirected.  The created
application must be a native graphical PE executable.
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidateScript({ Test-Path -LiteralPath $_ -PathType Leaf })]
    [string]$DevkitZip,

    [int]$GuiReadySeconds = 15,

    [string]$ResultsPath
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Invoke-MeasuredCommand {
    param(
        [Parameter(Mandatory = $true)][string]$Name,
        [Parameter(Mandatory = $true)][string]$FilePath,
        [Parameter(Mandatory = $true)][string[]]$Arguments,
        [Parameter(Mandatory = $true)][string]$WorkingDirectory
    )

    $stdout = [System.IO.Path]::GetTempFileName()
    $stderr = [System.IO.Path]::GetTempFileName()
    $watch = [System.Diagnostics.Stopwatch]::StartNew()
    try {
        # Windows PowerShell flattens ArgumentList. Quote every argument so a
        # stock host preserves the deliberately spaced/non-ASCII project path.
        $quotedArguments = @($Arguments | ForEach-Object {
            '"' + $_.Replace('"', '\"') + '"'
        })
        $process = Start-Process -FilePath $FilePath -ArgumentList $quotedArguments `
            -Wait -PassThru -NoNewWindow -RedirectStandardOutput $stdout `
            -RedirectStandardError $stderr -WorkingDirectory $WorkingDirectory
        $watch.Stop()
        if ($process.ExitCode -ne 0) {
            throw "$Name failed with exit code $($process.ExitCode).`nstdout:`n$([IO.File]::ReadAllText($stdout))`nstderr:`n$([IO.File]::ReadAllText($stderr))"
        }
        [pscustomobject]@{
            name = $Name
            milliseconds = $watch.ElapsedMilliseconds
            stdout = [IO.File]::ReadAllText($stdout).Trim()
            stderr = [IO.File]::ReadAllText($stderr).Trim()
        }
    }
    finally {
        Remove-Item -LiteralPath $stdout, $stderr -Force -ErrorAction SilentlyContinue
    }
}

function Assert-NativeGraphicalExecutable {
    param([Parameter(Mandatory = $true)][string]$Path)

    $bytes = [IO.File]::ReadAllBytes($Path)
    if ($bytes.Length -lt 256 -or $bytes[0] -ne 0x4d -or $bytes[1] -ne 0x5a) {
        throw "ship did not produce a PE executable: $Path"
    }
    $peOffset = [BitConverter]::ToInt32($bytes, 0x3c)
    if ($peOffset -lt 0 -or ($peOffset + 96) -ge $bytes.Length -or
        $bytes[$peOffset] -ne 0x50 -or $bytes[$peOffset + 1] -ne 0x45) {
        throw "ship produced an invalid PE executable: $Path"
    }
    $optionalHeader = $peOffset + 24
    $subsystemOffset = $optionalHeader + 68
    $subsystem = [BitConverter]::ToUInt16($bytes, $subsystemOffset)
    if ($subsystem -ne 2) {
        throw "application is not a Windows graphical executable (PE subsystem=$subsystem): $Path"
    }

    $process = Start-Process -FilePath $Path -PassThru
    try {
        $deadline = [DateTime]::UtcNow.AddSeconds($GuiReadySeconds)
        do {
            if ($process.HasExited) {
                throw "graphical application exited before presenting a window (exit=$($process.ExitCode))"
            }
            $process.Refresh()
            if ($process.MainWindowHandle -ne [IntPtr]::Zero) { return }
            Start-Sleep -Milliseconds 100
        } while ([DateTime]::UtcNow -lt $deadline)
        throw "graphical application presented no top-level window within $GuiReadySeconds seconds"
    }
    finally {
        if (-not $process.HasExited) { $process.Kill() }
        $process.Dispose()
    }
}

$root = Join-Path ([IO.Path]::GetTempPath()) ("z23 Windows journey ü " + [Guid]::NewGuid().ToString('N'))
$kit = Join-Path $root 'kit'
$project = Join-Path $root 'hello'
$dist = Join-Path $project 'dist'
$pathBefore = [Environment]::GetEnvironmentVariable('PATH', 'Process')
$userPathBefore = [Environment]::GetEnvironmentVariable('PATH', 'User')
$machinePathBefore = [Environment]::GetEnvironmentVariable('PATH', 'Machine')
$measurements = [System.Collections.Generic.List[object]]::new()

try {
    [IO.Directory]::CreateDirectory($kit) | Out-Null
    $extractWatch = [Diagnostics.Stopwatch]::StartNew()
    Expand-Archive -LiteralPath (Resolve-Path -LiteralPath $DevkitZip) -DestinationPath $kit
    $extractWatch.Stop()
    $measurements.Add([pscustomobject]@{ name = 'extract'; milliseconds = $extractWatch.ElapsedMilliseconds })

    $controllers = @(Get-ChildItem -LiteralPath $kit -Filter 'z23-dev.exe' -File -Recurse)
    if ($controllers.Count -ne 1) {
        throw "devkit must contain exactly one z23-dev.exe; found $($controllers.Count)"
    }
    $controller = $controllers[0].FullName

    $measurements.Add((Invoke-MeasuredCommand 'bootstrap' $controller @('bootstrap') $root))
    $measurements.Add((Invoke-MeasuredCommand 'create' $controller @('create', 'hello') $root))
    $measurements.Add((Invoke-MeasuredCommand 'develop-first' $controller @('develop', $project, '--once') $root))
    $measurements.Add((Invoke-MeasuredCommand 'develop-noop' $controller @('develop', $project, '--once') $root))
    $measurements.Add((Invoke-MeasuredCommand 'ship' $controller @('ship', $project) $root))

    if ([Environment]::GetEnvironmentVariable('PATH', 'Process') -cne $pathBefore) {
        throw 'developer journey changed the caller process PATH'
    }
    if ([Environment]::GetEnvironmentVariable('PATH', 'User') -cne $userPathBefore -or
        [Environment]::GetEnvironmentVariable('PATH', 'Machine') -cne $machinePathBefore) {
        throw 'developer journey changed persistent Windows PATH state'
    }

    if (-not (Test-Path -LiteralPath $dist -PathType Container)) {
        throw "ship did not create the documented project dist directory: $dist"
    }
    $applications = @(Get-ChildItem -LiteralPath $dist -Filter '*.exe' -File -Recurse |
        Where-Object { $_.Name -cne 'z23-dev.exe' })
    if ($applications.Count -ne 1) {
        throw "ship must produce exactly one application executable; found $($applications.Count)"
    }

    $guiWatch = [Diagnostics.Stopwatch]::StartNew()
    Assert-NativeGraphicalExecutable -Path $applications[0].FullName
    $guiWatch.Stop()
    $measurements.Add([pscustomobject]@{ name = 'gui-ready'; milliseconds = $guiWatch.ElapsedMilliseconds })

    $slowest = $measurements | Sort-Object milliseconds -Descending | Select-Object -First 1
    $result = [ordered]@{
        schema = 'z23.windows.devkit-journey.v1'
        verdict = 'PASS'
        windows = [Environment]::OSVersion.VersionString
        architecture = [Runtime.InteropServices.RuntimeInformation]::OSArchitecture.ToString()
        devkit_sha256 = (Get-FileHash -LiteralPath $DevkitZip -Algorithm SHA256).Hash.ToLowerInvariant()
        measurements = @($measurements)
        slowest_step = $slowest.name
        slowest_milliseconds = $slowest.milliseconds
    }
    $json = $result | ConvertTo-Json -Depth 5
    if ($ResultsPath) { [IO.File]::WriteAllText($ResultsPath, $json + [Environment]::NewLine) }
    $json
}
finally {
    if (Test-Path -LiteralPath $root) { Remove-Item -LiteralPath $root -Recurse -Force }
}
