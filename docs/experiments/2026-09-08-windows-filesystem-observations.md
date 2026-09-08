<!-- Copyright 2026 Rhett Creighton. Licensed under Apache-2.0. -->

# Preserve filesystem observation boundaries on Windows

The Windows syntax check at `16b524458` rejected two existing production
calls: `readlink` in `native_dev_agents_scan.c` and `lstat` in the Tor archive
shortcut in `native_dev_land.c`.

The process collector retains its non-Windows `/proc` scan. Windows has no
process-cwd backend here. The running-workspace JSON now reports
`process_observation: "unavailable"` when that backend cannot be opened, and
`"partial"` when it reads an observable subset. Text output repeats this
qualification. Workspace and Git observations remain available; zero matched
processes does not establish that no agent is running. A collector-only
process-root option allows the existing local fixture to reproduce an
unavailable backend without a new command or process authority.

The landing archive shortcut uses the existing `platform_file_metadata_read`
seam. It requires a regular file without following a final symlink or reparse
point. The remaining landing admission and dependency checks are unchanged.

## Verification

MinGW GCC 16.1.0, using the existing Windows syntax gate's derived production
flags and include paths, rejected both unmodified `16b524458` source copies
at the reported calls. It accepted the modified scan, landing, and text-render
translation units with implicit function declarations treated as errors.
This is cross-compilation evidence, not native Windows execution evidence.

The registered Linux command
`make -j4 t-fast-exact ONLY=fleet_agents,dev_land T_FAST_EXACT_ARGS=--no-cache`
ran at reduced scheduling priority and passed both groups with zero cache
hits, zero failures, and zero skips in 45.4 seconds. The new unavailable-backend
fixture preserved workspace observations and reported the distinct process
status. Existing landing fixtures passed. Complexity, flag-registry, and diff
checks passed; only seven affected existing source pointers were adjusted.

Recorded at `2026-09-08T04:26:26-04:00` /
`2026-09-08T08:26:26+00:00`. Full composed publication proof remains required.
