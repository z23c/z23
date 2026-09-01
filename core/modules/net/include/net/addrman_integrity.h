/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Addrman Integrity — load-time verification of peers.dat.
 *
 * Background
 * ----------
 * `peers.dat` is written by `connman_save_addrman()` using an
 * open-write-rename pattern (already atomic) but with no checksum.
 * On partial disk failure, bit-flip, or an attacker tampering with
 * the file offline, a corrupt `peers.dat` can steer a restarting
 * node into connecting to attacker-chosen peers. `addrman_deserialize`
 * will happily accept any wire-format-valid bytes, including bytes
 * whose bucket layout points at adversary addresses.
 *
 * Sidecar format
 * --------------
 * Stored next to peers.dat as `peers.dat.sha3`. 48 bytes, same
 * layout as `block_index_integrity` for consistency:
 *
 *     struct aii_sidecar_header {
 *         uint8_t  magic[4];         // "ADIX"
 *         uint32_t version;          // 1
 *         uint64_t body_size;        // file size at write time
 *         uint8_t  body_sha3[32];    // SHA3-256 of peers.dat
 *     };
 *
 * Write semantics
 * ---------------
 * `aii_write_sidecar()` is called AFTER `connman_save_addrman()`
 * finishes renaming peers.dat. It streams the full body through
 * SHA3-256, stat()s the file for size, and writes the 48-byte
 * sidecar atomically (fwrite to `.tmp`, fsync, rename).
 *
 * Verify semantics
 * ----------------
 * `aii_verify()` reads the sidecar and re-hashes the body. On any
 * non-OK verdict the caller should NOT deserialize — it should
 * call `aii_quarantine_corrupt()` to move the evidence out of the
 * way and start fresh. peers.dat is always reconstructible by
 * relearning from the network, so we can afford to throw it away
 * on mismatch — the cost of acting on a corrupt file is higher
 * than the cost of a few more DNS-seed hops on next boot.
 *
 * First-run / upgrade
 * -------------------
 * `AII_SIDECAR_MISSING` is returned when the body exists but the
 * sidecar does not. This is the expected state during the first
 * boot after this module ships — the caller should accept the
 * body in that case (a subsequent save will generate the sidecar).
 */

#ifndef ZCL_NET_ADDRMAN_INTEGRITY_H
#define ZCL_NET_ADDRMAN_INTEGRITY_H

#include "util/result.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define AII_MAGIC "ADIX"
#define AII_SIDECAR_VERSION 1u
#define AII_SIDECAR_BYTES   48u

enum aii_verdict {
    AII_OK = 0,
    AII_SIDECAR_MISSING,      /* no .sha3 next to peers.dat — accept body */
    AII_SIDECAR_STALE,        /* sidecar body_size differs from actual */
    AII_HASH_MISMATCH,        /* sha3 of body does not match sidecar */
    AII_BODY_MISSING,         /* peers.dat itself is missing */
    AII_BODY_UNREADABLE,      /* open/read/stat failed on peers.dat */
    AII_SIDECAR_BAD_MAGIC,    /* wrong magic in the sidecar header */
    AII_SIDECAR_UNSUPPORTED,  /* sidecar version we don't understand */
    AII_NUM_VERDICTS          /* sentinel */
};

const char *aii_verdict_name(enum aii_verdict v);

/* Verify peers.dat against its sidecar in `datadir`. Writes a
 * diagnostic string into `err_out` (capacity `err_cap`) on any
 * non-OK verdict. Both output parameters are optional. */
enum aii_verdict aii_verify(const char *datadir,
                             char *err_out, size_t err_cap);

/* Write the SHA3 sidecar for the current peers.dat. Call AFTER
 * the body has been renamed into place. Returns a non-ok zcl_result
 * on any I/O error. The caller is free to ignore the return value —
 * a later `aii_verify` will just return AII_SIDECAR_MISSING. */
struct zcl_result aii_write_sidecar(const char *datadir);

/* Rename `peers.dat` and `peers.dat.sha3` aside as
 * `<name>.corrupt.<unix_ts>`. Does NOT delete — operators need
 * the bytes for forensic analysis. Missing files are silently
 * ignored. Emits `EV_ADDRMAN_CORRUPT`. */
void aii_quarantine_corrupt(const char *datadir, enum aii_verdict v);

#endif /* ZCL_NET_ADDRMAN_INTEGRITY_H */
