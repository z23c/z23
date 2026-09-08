<!-- Copyright 2026 Rhett Creighton. Licensed under Apache-2.0. -->

# Canonical hex decoding for compile locks

The composed proof's hex-codec gate rejected `tools/zcc.c`: its new compile
lock offset calculation duplicated hexadecimal nibble arithmetic. A direct
gate invocation identified that file as the sole new private codec.

The offset calculation now uses the existing `zcl_hex_nibble` helper. Generated
content keys are canonical lowercase hexadecimal. Cached manifests currently
check key length without proving its alphabet, so an invalid prefix digit
explicitly declines coordination and follows the existing uncached compile
path. Valid keys retain their exact byte-range offsets. Cache acceptance and
the hex-codec baseline are unchanged.

Validation uses a strict C23 build of `tools/zcc.c`, the expanded
`tools/lint/check_zcc_cache.sh` concurrency fixtures, and the existing native
hex-codec gate and selftest. The cache fixtures cover shared compilation,
independent keys and audits, changed inputs, failed owners, depfile rewriting,
and diagnostic replay. Gate results are recorded with the commit.
