<!-- Copyright 2026 Rhett Creighton. Licensed under Apache-2.0. -->

# Native Windows developer journey contract

This is the acceptance contract for the supported Windows 10/11 x64 product,
not documentation for assembling its toolchain. A new user downloads one
signed ZIP, extracts it, and runs one executable. MSYS2, WSL, Git, Visual
Studio, an SDK, CMake, Ninja, Make, compiler selection, environment variables,
and DLL placement are not user decisions.

The checked-in controller currently implements the relocatable tool selection,
native GUI scaffold, isolated builds, resident incremental watch/restart loop,
timing output, and unsigned development packaging portions of this contract.
Manifest installation, release signing, and clean-machine certification remain
release gates; this document does not claim they are complete.

## The entire interface

```powershell
.\z23-dev.exe bootstrap
.\z23-dev.exe create hello
.\z23-dev.exe develop hello
.\z23-dev.exe ship hello
```

`bootstrap` verifies the devkit manifest and signature, installs its immutable
version under `%LOCALAPPDATA%\z23\toolchains`, and reports the next command. It
must not require administrator rights, mutate the machine or user `PATH`, use
an unpinned download, or discover a compiler or SDK elsewhere on the machine.

`create` makes a minimal native graphical C23 application from a bundled,
versioned template. `develop` builds it and opens the real application; while
it remains active it watches source files, performs incremental rebuilds, and
restarts the application after a successful build. A failed edit leaves the
last successful application running and prints the diagnostic. `ship` performs
the strict clean release build and writes one application executable and a
redistributable ZIP under `<project>\dist`, with its manifest, hashes, licenses,
and signature status.

Each command accepts `--help`. Each command is non-interactive when output is
redirected, returns a meaningful process exit code, and prints its only obvious
next action. The controller resolves paths relative to the explicit project or
its own location, so it behaves identically from PowerShell, Command Prompt,
Windows Terminal, Explorer, and an agent process.

## What is measured

Release acceptance runs
[`tests/windows/devkit_journey_acceptance.ps1`](../tests/windows/devkit_journey_acceptance.ps1)
on clean Windows 10 22H2 and Windows 11 x64 virtual machines. It records these
independent wall-clock stages:

1. ZIP extraction
2. bootstrap
3. project creation
4. first development build
5. unchanged incremental build
6. release packaging
7. application window readiness

The result is machine-readable JSON and names the slowest stage. Performance
work starts with that stage; aggregate time must not hide it. CI retains the
devkit SHA-256, OS build, architecture, and all raw durations so regressions
are comparable. The initial baseline is evidence, not a target invented before
the native journey runs. After three clean-machine samples per supported OS,
the median becomes the baseline and a 20 percent regression in any stage is a
release failure unless the release notes name and justify it.

Run the acceptance from stock Windows PowerShell:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File `
  .\tests\windows\devkit_journey_acceptance.ps1 `
  -DevkitZip .\z23-windows-devkit-x64.zip `
  -ResultsPath .\windows-journey.json
```

The acceptance never calls a shell, build system, compiler, SDK, Git, WSL, or
package manager. It checks that the shipped program is a native Windows GUI PE,
actually presents a top-level window, and that the caller's `PATH` is unchanged.

## Release gates beyond the happy path

The runtime ZIP must pass a PE import audit: no MSYS2, Cygwin, compiler-runtime,
or undeclared DLL may be required. A second test launches the application from
a directory containing spaces and non-ASCII characters. Offline bootstrap must
succeed using only ZIP contents. Corrupt manifests, hashes, and signatures must
fail before execution. Running `bootstrap`, `create`, and `ship` twice must be
safe and deterministic; concurrent `develop` invocations must report ownership
rather than corrupting outputs.

The graphical sample is intentionally custody-free and network-free. Node,
wallet, service, sync, and transaction acceptance remain separate isolated
lanes and cannot borrow a green result from this developer journey.
