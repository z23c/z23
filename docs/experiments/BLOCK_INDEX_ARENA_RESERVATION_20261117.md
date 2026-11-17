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
access a canonical datadir. Focused and native proof: not yet run.
