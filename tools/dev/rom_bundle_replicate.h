/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: Copy a verified ROM bundle and prove the copy by SHA3-256. */

#ifndef ZCL_ROM_BUNDLE_REPLICATE_H
#define ZCL_ROM_BUNDLE_REPLICATE_H

/* repo supplies the default producing binary and rom_bundle_sha3 when those
 * options are omitted. argv is the option vector, without argv0.
 * Returns 0 after the PASS lines, 1 on a digest mismatch, 2 on usage. */
int zcl_rom_bundle_replicate(const char *repo, int argc, char **argv);

#endif
