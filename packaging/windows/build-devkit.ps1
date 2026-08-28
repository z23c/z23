# Copyright 2026 Rhett Creighton. Licensed under Apache-2.0.

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$LlvmMingwRoot,
    [Parameter(Mandatory = $true)][string]$CMakeRoot,
    [Parameter(Mandatory = $true)][string]$NinjaExe,
    [Parameter(Mandatory = $true)][string]$OutputDirectory,
    [string]$Version = 'dev',
    [string]$SignTool,
    [string]$CertificateThumbprint
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Require-Path([string]$Path, [string]$Kind) {
    if ($Kind -eq 'Container' -and -not (Test-Path -LiteralPath $Path -PathType Container)) {
        throw "required directory is missing: $Path"
    }
    if ($Kind -eq 'Leaf' -and -not (Test-Path -LiteralPath $Path -PathType Leaf)) {
        throw "required file is missing: $Path"
    }
}

$repo = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path
$llvm = (Resolve-Path -LiteralPath $LlvmMingwRoot).Path
$cmake = (Resolve-Path -LiteralPath $CMakeRoot).Path
$ninja = (Resolve-Path -LiteralPath $NinjaExe).Path
Require-Path (Join-Path $llvm 'bin\clang.exe') Leaf
Require-Path (Join-Path $cmake 'bin\cmake.exe') Leaf
Require-Path $ninja Leaf

$output = [IO.Path]::GetFullPath($OutputDirectory)
$stageParent = Join-Path $output ('.z23-devkit-stage-' + [Guid]::NewGuid().ToString('N'))
$kit = Join-Path $stageParent 'z23-windows-devkit-x64'
$toolchain = Join-Path $kit 'toolchain'
[IO.Directory]::CreateDirectory($toolchain) | Out-Null

# LLVM-MinGW is copied as one relocatable sysroot. This is the Windows SDK and
# compiler runtime contract; Clang never searches a machine installation.
Copy-Item -Path (Join-Path $llvm '*') -Destination $toolchain `
    -Recurse -Force
Copy-Item -Path (Join-Path $cmake 'bin\*') `
    -Destination (Join-Path $toolchain 'bin') -Recurse -Force
foreach ($directory in @('share', 'doc')) {
    $source = Join-Path $cmake $directory
    if (Test-Path -LiteralPath $source -PathType Container) {
        Copy-Item -LiteralPath $source -Destination $toolchain -Recurse -Force
    }
}
Copy-Item -LiteralPath $ninja -Destination (Join-Path $toolchain 'bin\ninja.exe') -Force

$clang = Join-Path $toolchain 'bin\clang.exe'
$controller = Join-Path $kit 'z23-dev.exe'
$sources = @(
    (Join-Path $repo 'tools\windows\z23_dev_main.c'),
    (Join-Path $repo 'tools\windows\z23_dev_journey.c')
)
foreach ($source in $sources) { Require-Path $source Leaf }
& $clang '-std=c23' '-O2' '-Wall' '-Wextra' '-Wpedantic' '-Werror' `
    '-D_WIN32_WINNT=0x0A00' '-DWIN32_LEAN_AND_MEAN' '-static' `
    '-municode' `
    ('-I' + (Join-Path $repo 'tools\windows')) @sources `
    '-ladvapi32' '-lshell32' '-o' $controller
if ($LASTEXITCODE -ne 0) { throw "controller build failed: $LASTEXITCODE" }

# Fail the devkit build before packaging if the controller accidentally gains
# a dependency on an emulation layer or compiler runtime DLL.
$readobj = Join-Path $toolchain 'bin\llvm-readobj.exe'
Require-Path $readobj Leaf
$imports = (& $readobj '--coff-imports' $controller | Select-String 'Name: .*\.dll' |
    ForEach-Object { $_.Matches[0].Value.Substring(6).ToLowerInvariant() })
if ($LASTEXITCODE -ne 0) { throw "controller PE import audit failed: $LASTEXITCODE" }
$forbiddenImports = @($imports | Where-Object {
    $_ -match '^(msys-|cygwin|libgcc|libstdc\+\+|libwinpthread|clang_rt|api-ms-win-crt-private)'
})
if ($forbiddenImports.Count -ne 0) {
    throw "controller requires forbidden DLLs: $($forbiddenImports -join ', ')"
}

$signed = $false
if ($SignTool -and $CertificateThumbprint) {
    Require-Path $SignTool Leaf
    & $SignTool sign /sha1 $CertificateThumbprint /fd SHA256 /tr `
        'http://timestamp.digicert.com' /td SHA256 $controller
    if ($LASTEXITCODE -ne 0) { throw "controller signing failed: $LASTEXITCODE" }
    $signed = $true
}

$payload = Get-ChildItem -LiteralPath $kit -File -Recurse |
    Sort-Object { $_.FullName.Substring($kit.Length + 1) } |
    ForEach-Object {
        [ordered]@{
            path = $_.FullName.Substring($kit.Length + 1).Replace('\', '/')
            bytes = $_.Length
            sha256 = (Get-FileHash -LiteralPath $_.FullName -Algorithm SHA256).Hash.ToLowerInvariant()
        }
    }
$manifest = [ordered]@{
    schema = 'z23.windows.devkit.v1'
    version = $Version
    architecture = 'x86_64'
    controller = 'z23-dev.exe'
    compiler = 'portable-llvm-mingw'
    signed = $signed
    signature_status = if ($signed) { 'signed' } else { 'unsigned-development-snapshot' }
    controller_imports = @($imports)
    files = @($payload)
}
$manifestPath = Join-Path $kit 'devkit-manifest.json'
[IO.File]::WriteAllText($manifestPath,
    (($manifest | ConvertTo-Json -Depth 6) + [Environment]::NewLine),
    [Text.UTF8Encoding]::new($false))

[IO.Directory]::CreateDirectory($output) | Out-Null
$archive = Join-Path $output 'z23-windows-devkit-x64.zip'
if (Test-Path -LiteralPath $archive) { Remove-Item -LiteralPath $archive -Force }
Compress-Archive -LiteralPath $kit -DestinationPath $archive -CompressionLevel Optimal
Remove-Item -LiteralPath $stageParent -Recurse -Force
$archiveHash = (Get-FileHash -LiteralPath $archive -Algorithm SHA256).Hash.ToLowerInvariant()
[IO.File]::WriteAllText(($archive + '.sha256'),
    "$archiveHash  z23-windows-devkit-x64.zip$([Environment]::NewLine)",
    [Text.UTF8Encoding]::new($false))
[pscustomobject]@{
    archive = $archive
    sha256 = $archiveHash
    signed = $signed
    payload_files = $payload.Count
} | ConvertTo-Json
