# Copyright 2026 Rhett Creighton - Apache License 2.0
# Shared Windows-path conversion for the native MSYS2 UCRT64 couriers.

function ConvertTo-Z23MsysPath {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [string]$Path
    )

    $full = [System.IO.Path]::GetFullPath($Path)
    if ($full -match '^([A-Za-z]):[\\/]*(.*)$') {
        $drive = $Matches[1].ToLowerInvariant()
        $tail = ($Matches[2] -replace '\\', '/').Trim('/')
        if ([string]::IsNullOrEmpty($tail)) {
            return "/$drive"
        }
        return "/$drive/$tail"
    }
    if ($full -match '^[\\]{2}') {
        return ($full -replace '\\', '/')
    }
    throw "z23-windows-path: REFUSE: expected an absolute drive or UNC path, got '$full'"
}

function Resolve-Z23Msys2Root {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [string]$Path
    )

    if (-not [System.IO.Path]::IsPathFullyQualified($Path)) {
        throw "z23-windows-path: REFUSE: MSYS2 root must be an absolute path, got '$Path'"
    }
    if ($Path.StartsWith('\\?\') -or $Path.StartsWith('\\.\')) {
        throw "z23-windows-path: REFUSE: device-path MSYS2 roots are not qualified"
    }
    if ($Path.StartsWith('\\')) {
        throw "z23-windows-path: REFUSE: UNC MSYS2 roots are not qualified"
    }
    if ($Path.Contains(';')) {
        throw "z23-windows-path: REFUSE: MSYS2 root cannot contain the Windows PATH separator ';'"
    }
    return (Resolve-Path -LiteralPath $Path | Select-Object -ExpandProperty Path)
}

function Assert-Z23MsysPathContract {
    $cases = @(
        @{ Input = 'D:\msys64'; Expected = '/d/msys64' },
        @{ Input = 'C:\Program Files\MSYS2'; Expected = '/c/Program Files/MSYS2' },
        @{ Input = '\\server\share\msys64'; Expected = '//server/share/msys64' }
    )
    foreach ($case in $cases) {
        $actual = ConvertTo-Z23MsysPath -Path $case.Input
        if ($actual -cne $case.Expected) {
            throw "z23-windows-path: SELFTEST FAIL: '$($case.Input)' became '$actual', expected '$($case.Expected)'"
        }
    }
}
