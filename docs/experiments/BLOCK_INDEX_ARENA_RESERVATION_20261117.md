<!-- Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0 -->

# Block-index arena reservation errors

The file-backed block-index load arena previously ignored the return from
`posix_fallocate`. A hard reservation failure could therefore be followed by
an mmap and a later SIGBUS when a page was written. The loader now removes the
scratch file and uses its existing anonymous allocation fallback after a hard
reservation error. Unsupported reservation results retain the existing
unreserved mapping behavior; macOS remains unchanged. Those paths retain their
existing disk-exhaustion risk.

An isolated loader fixture injects reservation return values in test builds
and checks the fallback, file cleanup and chain identity. It also checks that
unsupported results retain the file-backed path. It does not fill a disk or
access a canonical datadir. The repair and native proof remain pending verification.
<!-- claim: symbol-present bil_arena_file_map engine/services/src/block_index_loader.c # file-backed block-index load arena -->

On source `4adfb4213f36cc19beb4fc59db968c5026d88a73`, five focused cold
loader-related groups passed in 7.9 seconds with no failures or skips. All six
injected error cases executed. The same run failed the complexity gate in the
test fixture; the fixture was split afterward. The repaired source requires
verification. Native proof remains pending.
