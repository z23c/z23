/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Addrman Integrity — see addrman_integrity.h for rationale.
 *
 * The body+sidecar hashing, atomic write, header parse, and
 * quarantine logic are shared with block_index_sidecar_integrity.c
 * via storage/sha3_sidecar_io.h so the two sidecars behave
 * identically. The aii_* functions below are thin wrappers that pass
 * the addrman-specific constants (magic "ADIX", filenames peers.dat,
 * EV_ADDRMAN_CORRUPT) into that shared module and translate its
 * generic verdict back to enum aii_verdict.
 *
 * Unlike block_index, peers.dat has no SQLite cross-check (there is
 * no on-chain "tip" for the peer file).
 */

#include "net/addrman_integrity.h"
#include "storage/sha3_sidecar_io.h"

#include "encoding/utilstrencodings.h"
#include "event/event.h"

#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>

/* ── Layout check ───────────────────────────────────────────── */

_Static_assert(AII_SIDECAR_BYTES == 48u,
               "AII_SIDECAR_BYTES must match sidecar header layout");

/* ── Sidecar spec ───────────────────────────────────────────── */

static const struct ssio_spec aii_spec = {
    .body_name     = "peers.dat",
    .sidecar_name  = "peers.dat.sha3",
    .magic         = AII_MAGIC,
    .version       = AII_SIDECAR_VERSION,
    .domain        = "aii",
    .malloc_label  = "integrity_hash_buf",
    .corrupt_event = EV_ADDRMAN_CORRUPT,
};

/* ── Verdict names ──────────────────────────────────────────── */

const char *aii_verdict_name(enum aii_verdict v)
{
    switch (v) {
    case AII_OK:                  return "ok";
    case AII_SIDECAR_MISSING:     return "sidecar_missing";
    case AII_SIDECAR_STALE:       return "sidecar_stale";
    case AII_HASH_MISMATCH:       return "hash_mismatch";
    case AII_BODY_MISSING:        return "body_missing";
    case AII_BODY_UNREADABLE:     return "body_unreadable";
    case AII_SIDECAR_BAD_MAGIC:   return "sidecar_bad_magic";
    case AII_SIDECAR_UNSUPPORTED: return "sidecar_unsupported";
    default:                      return "unknown";
    }
}

/* ── Sidecar writer ─────────────────────────────────────────── */

struct zcl_result aii_write_sidecar(const char *datadir)
{
    return ssio_write_sidecar(datadir, &aii_spec);
}

/* ── Sidecar reader (thin wrapper) ──────────────────────────── */

static enum aii_verdict aii_read_sidecar(const char *datadir,
                                          struct ssio_sidecar_header *out)
{
    switch (ssio_read_sidecar(datadir, &aii_spec, out)) {
    case SSIO_READ_OK:          return AII_OK;
    case SSIO_READ_MISSING:     return AII_SIDECAR_MISSING;
    case SSIO_READ_UNREADABLE:  return AII_BODY_UNREADABLE;
    case SSIO_READ_STALE:       return AII_SIDECAR_STALE;
    case SSIO_READ_BAD_MAGIC:   return AII_SIDECAR_BAD_MAGIC;
    case SSIO_READ_UNSUPPORTED: return AII_SIDECAR_UNSUPPORTED;
    }
    return AII_BODY_UNREADABLE;
}

/* ── Verification entry point ───────────────────────────────── */

enum aii_verdict aii_verify(const char *datadir,
                             char *err_out, size_t err_cap)
{
    if (err_out && err_cap) err_out[0] = '\0';
    if (!datadir) {
        if (err_out) snprintf(err_out, err_cap, "null datadir");
        return AII_BODY_UNREADABLE;
    }

    char body_path[1024];
    char side_path[1024];
    snprintf(body_path, sizeof(body_path), "%s/%s", datadir, aii_spec.body_name);
    snprintf(side_path, sizeof(side_path), "%s/%s", datadir, aii_spec.sidecar_name);

    struct stat body_st;
    if (stat(body_path, &body_st) != 0) {
        if (err_out) snprintf(err_out, err_cap,
                "peers.dat: %s", strerror(errno));
        return errno == ENOENT ? AII_BODY_MISSING : AII_BODY_UNREADABLE;
    }

    struct ssio_sidecar_header hdr;
    enum aii_verdict rv = aii_read_sidecar(datadir, &hdr);
    if (rv == AII_SIDECAR_MISSING) {
        if (err_out) snprintf(err_out, err_cap,
                "no sidecar at %s (first run after upgrade?)", side_path);
        return AII_SIDECAR_MISSING;
    }
    if (rv != AII_OK) {
        if (err_out) snprintf(err_out, err_cap,
                "sidecar read: %s", aii_verdict_name(rv));
        return rv;
    }

    if (hdr.body_size != (uint64_t)body_st.st_size) {
        if (err_out) snprintf(err_out, err_cap,
                "size drift: sidecar=%llu actual=%lld",
                (unsigned long long)hdr.body_size,
                (long long)body_st.st_size);
        return AII_SIDECAR_STALE;
    }

    uint8_t actual_hash[32];
    uint64_t hashed_size = 0;
    if (!ssio_hash_body(datadir, &aii_spec, actual_hash, &hashed_size)) {
        if (err_out) snprintf(err_out, err_cap,
                "failed to hash %s: %s", body_path, strerror(errno));
        return AII_BODY_UNREADABLE;
    }
    if (hashed_size != hdr.body_size) {
        if (err_out) snprintf(err_out, err_cap,
                "size drift mid-hash: sidecar=%llu hashed=%llu",
                (unsigned long long)hdr.body_size,
                (unsigned long long)hashed_size);
        return AII_SIDECAR_STALE;
    }
    if (memcmp(actual_hash, hdr.body_sha3, 32) != 0) {
        if (err_out) {
            char exp[65], got[65];
            HexStr(hdr.body_sha3, 32, false, exp, sizeof(exp));
            HexStr(actual_hash, 32, false, got, sizeof(got));
            snprintf(err_out, err_cap,
                    "body sha3 mismatch expected=%s actual=%s",
                    exp, got);
        }
        return AII_HASH_MISMATCH;
    }

    return AII_OK;
}

/* ── Quarantine ─────────────────────────────────────────────── */

void aii_quarantine_corrupt(const char *datadir, enum aii_verdict v)
{
    ssio_quarantine(datadir, &aii_spec, aii_verdict_name(v));
}
