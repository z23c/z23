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

param(
    [Parameter(Position=0, ValueFromRemainingArguments=$true)]
    [string[]]$Arguments
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'windows-path.ps1')
Assert-Z23MsysPathContract

$CheckoutRoot = ""
$Msys2Root = "C:\msys64"
$DryRun = $false
$MakeArgs = [System.Collections.Generic.List[string]]::new()
# Parse wrapper options exactly. PowerShell's normal prefix matching would
# otherwise consume make's -C as -CheckoutRoot and -m as -Msys2Root.
$rawArguments = @($Arguments)
for ($index = 0; $index -lt $rawArguments.Count; $index++) {
    $argument = $rawArguments[$index]
    if ($argument -ieq '-DryRun') {
        $DryRun = $true
        continue
    }
    if (($argument -ieq '-CheckoutRoot') -or ($argument -ieq '-Msys2Root')) {
        if (($index + 1) -ge $rawArguments.Count) {
            Write-Error -Message "z23-make: REFUSE: $argument requires a path value" -ErrorAction Continue
            exit 1
        }
        $index++
        if ($argument -ieq '-CheckoutRoot') {
            $CheckoutRoot = $rawArguments[$index]
        } else {
            $Msys2Root = $rawArguments[$index]
        }
        continue
    }
    $MakeArgs.Add($argument)
}

if ([string]::IsNullOrEmpty($CheckoutRoot)) {
    if ([string]::IsNullOrEmpty($PSScriptRoot)) {
        Write-Error -Message "z23-make: REFUSE: cannot derive checkout root; pass -CheckoutRoot explicitly" -ErrorAction Continue
        exit 1
    }
    $CheckoutRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
}
$CheckoutRoot = Resolve-Path -LiteralPath $CheckoutRoot | Select-Object -ExpandProperty Path
try {
    $Msys2Root = Resolve-Z23Msys2Root -Path $Msys2Root
} catch {
    Write-Error -Message "z23-make: REFUSE: $($_.Exception.Message)" -ErrorAction Continue
    exit 1
}

$Bash = Join-Path $Msys2Root 'usr\bin\bash.exe'
if (-not (Test-Path -LiteralPath $Bash)) {
    Write-Error -Message "z23-make: REFUSE: MSYS2 bash not found at $Bash; run tools\dev\windows-setup.ps1 first" -ErrorAction Continue
    exit 1
}
$SelectedMake = Join-Path $Msys2Root 'usr\bin\make.exe'
$SelectedGcc = Join-Path $Msys2Root 'ucrt64\bin\gcc.exe'
foreach ($RequiredTool in @($SelectedMake, $SelectedGcc)) {
    if (-not (Test-Path -LiteralPath $RequiredTool -PathType Leaf)) {
        Write-Error -Message "z23-make: REFUSE: selected MSYS2 root is missing $RequiredTool; run tools\dev\windows-setup.ps1 -Msys2Root $Msys2Root" -ErrorAction Continue
        exit 1
    }
}
$SelectedCc1 = @(Get-ChildItem -LiteralPath (Join-Path $Msys2Root 'ucrt64\lib\gcc\x86_64-w64-mingw32') -Filter 'cc1.exe' -File -Recurse -ErrorAction SilentlyContinue)
if ($SelectedCc1.Count -lt 1) {
    Write-Error -Message "z23-make: REFUSE: selected MSYS2 root has no root-owned UCRT64 cc1.exe; run tools\dev\windows-setup.ps1 -Msys2Root $Msys2Root" -ErrorAction Continue
    exit 1
}

$repoRoot = ConvertTo-Z23MsysPath -Path $CheckoutRoot
$msysRoot = ConvertTo-Z23MsysPath -Path $Msys2Root

$env:MSYSTEM = 'UCRT64'
$env:CHERE_INVOKING = '1'
# Bash understands /c/msys64/... but the native Windows loader resolving
# cc1.exe's runtime DLLs does not. Give the entire contained process tree the
# equivalent native spellings as well; this is process-local and does not
# mutate the user's or machine's persistent PATH.
$NativeUcrtBin = Join-Path $Msys2Root 'ucrt64\bin'
$NativeUsrBin = Join-Path $Msys2Root 'usr\bin'
$env:Path = "$NativeUcrtBin;$NativeUsrBin;$env:Path"
$env:Z23_CHECKOUT_ROOT_MSYS = $repoRoot
$env:Z23_MSYS2_ROOT_MSYS = $msysRoot

# Keep make's arguments as argv entries. Joining them into shell source loses
# spaces and lets shell metacharacters in a variable assignment or path run as
# commands. The fixed Bash program consumes only the two wrapper-owned values.
$bashCommand = 'repo_root=$1; msys_root=$2; shift 2; cd -- "$repo_root" && export PATH="$msys_root/ucrt64/bin:$msys_root/usr/bin:$PATH" && exec make "$@"'
$bashArgs = @('-lc', $bashCommand, 'z23-windows-make', $repoRoot, $msysRoot) + $MakeArgs.ToArray()

if ($DryRun) {
    Write-Output "Z23_CHECKOUT_ROOT_MSYS=$repoRoot"
    Write-Output "Z23_MSYS2_ROOT_MSYS=$msysRoot"
    Write-Output "NATIVE_PATH_PREFIX=$NativeUcrtBin;$NativeUsrBin"
    Write-Output 'BASH_ARGV:'
    foreach ($BashArgument in $bashArgs) {
        Write-Output "  $BashArgument"
    }
    exit 0
}

# Keep every ordinary build/test process at below-normal CPU priority in the
# native kill-on-close Job Object and error-dialog suppression boundary. This
# lets browsers and interactive work preempt vibe-coding builds while builds
# still use otherwise-idle CPU. A fresh checkout bootstraps
# the tiny C23 launcher directly once; subsequent invocations rebuild it only
# when one of its two sources is newer. This prevents Ctrl-C or a backend
# crash from leaving orphaned make/cc1 processes and WER popups behind.
$Runner = Join-Path $CheckoutRoot 'build\bin\z23-headless-run.exe'
$RunnerSources = @(
    (Join-Path $CheckoutRoot 'tools\dev\windows_headless_run.c'),
    (Join-Path $CheckoutRoot 'platform\modules\base\src\safe_alloc.c')
)
$NeedsBootstrap = -not (Test-Path -LiteralPath $Runner)
if (-not $NeedsBootstrap) {
    $RunnerStamp = (Get-Item -LiteralPath $Runner).LastWriteTimeUtc
    foreach ($Source in $RunnerSources) {
        if ((Get-Item -LiteralPath $Source).LastWriteTimeUtc -gt $RunnerStamp) {
            $NeedsBootstrap = $true
            break
        }
    }
}
if ($NeedsBootstrap) {
    # The runner does not exist yet, so this one compiler invocation cannot
    # already be placed inside it. Suppress inherited Windows Error Reporting
    # and critical-error UI before spawning Bash: a broken cc1 must return an
    # exit status, never block an unattended setup behind a desktop popup.
    Enable-Z23NativeErrorMode
    $BootstrapArgs = @('-lc', $bashCommand, 'z23-windows-make', $repoRoot,
                       $msysRoot, 'build/bin/z23-headless-run.exe')
    & $Bash @BootstrapArgs
    if ($LASTEXITCODE -ne 0 -or -not (Test-Path -LiteralPath $Runner)) {
        Write-Error -Message 'z23-make: REFUSE: failed to build the native process-tree launcher' -ErrorAction Continue
        exit 1
    }
}

$LogDirectory = Join-Path $CheckoutRoot '.cache\windows-make'
[void](New-Item -ItemType Directory -Force -Path $LogDirectory)
$Log = Join-Path $LogDirectory ("make-{0}-{1}.log" -f $PID,
                                [DateTime]::UtcNow.Ticks)
$RunnerCopy = Join-Path $LogDirectory ("runner-{0}-{1}.exe" -f $PID,
                                      [DateTime]::UtcNow.Ticks)
Copy-Item -LiteralPath $Runner -Destination $RunnerCopy
Write-Host "z23-make: contained process tree; captured output: $Log"
try {
    # Execute a private copy so `make clean` or a forced rebuild can replace
    # the canonical runner while this invocation is still using it.
    & $RunnerCopy --cwd $CheckoutRoot --log $Log -- $Bash @bashArgs
    $MakeExit = $LASTEXITCODE
    if (Test-Path -LiteralPath $Log) {
        Get-Content -LiteralPath $Log
    }
} finally {
    Remove-Item -LiteralPath $RunnerCopy -Force -ErrorAction SilentlyContinue
}
exit $MakeExit
