/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Block Index Sidecar Integrity — hash sidecar verification for
 * block_index.bin. Split from block_index_integrity.c so the sidecar
 * verifier and structural repair paths stay separately readable. */

#include "services/block_index_integrity.h"
#include "storage/sha3_sidecar_io.h"

#include "adapters/outbound/persistence/block_index_sidecar_sqlite.h"
#include "encoding/utilstrencodings.h"
#include "event/event.h"
#include "ports/block_index_sidecar_port.h"
#include "platform/file_metadata.h"
#include "util/result.h"

#include <errno.h>
#include <stdio.h>
#include <string.h>

_Static_assert(BII_SIDECAR_BYTES == 48u,
               "BII_SIDECAR_BYTES must match sidecar header layout");

/* ── Sidecar spec ───────────────────────────────────────────── */

static const struct ssio_spec bii_spec = {
    .body_name     = "block_index.bin",
    .sidecar_name  = "block_index.bin.sha3",
    .magic         = BII_MAGIC,
    .version       = BII_SIDECAR_VERSION,
    .domain        = "bii",
    .malloc_label  = "integrity_hash_buf",
    .corrupt_event = EV_BLOCK_INDEX_CORRUPT,
};

/* Embedded single-file spec (task #32): same body file, but the
 * integrity header is the file's own first 48 bytes (magic "BIIE",
 * version 2). The sidecar_name is unused on the embedded path but kept
 * for ssio_quarantine, which moves any leftover legacy sidecar aside. */
_Static_assert(BII_EMBEDDED_HEADER_BYTES == SSIO_EMBEDDED_HEADER_BYTES,
               "bii embedded header must match the shared 48-byte layout");

static const struct ssio_spec bii_embedded_spec = {
    .body_name     = "block_index.bin",
    .sidecar_name  = "block_index.bin.sha3",
    .magic         = BII_EMBEDDED_MAGIC,
    .version       = BII_EMBEDDED_VERSION,
    .domain        = "bii",
    .malloc_label  = "integrity_hash_buf",
    .corrupt_event = EV_BLOCK_INDEX_CORRUPT,
};

struct zcl_result bii_write_sidecar(const char *datadir)
{
    return ssio_write_sidecar(datadir, &bii_spec);
}

struct zcl_result bii_write_sidecar_raw(const char *datadir,
                                        uint64_t body_size,
                                        const uint8_t body_sha3[32])
{
    return ssio_write_sidecar_raw(datadir, &bii_spec, body_size, body_sha3);
}

struct zcl_result bii_write_embedded(
    const char *datadir,
    bool (*emit_payload)(FILE *f, void *ctx,
                         uint64_t *out_payload_size,
                         uint8_t out_payload_sha3[32]),
    void *ctx)
{
    return ssio_write_embedded(datadir, &bii_embedded_spec, emit_payload, ctx);
}

int bii_verify_embedded(const char *datadir,
                        struct ssio_sidecar_header *out,
                        uint64_t *out_payload_off)
{
    return (int)ssio_verify_embedded(datadir, &bii_embedded_spec, out,
                                     out_payload_off);
}

static enum bii_verdict bii_read_sidecar(const char *datadir,
                                          struct ssio_sidecar_header *out)
{
    switch (ssio_read_sidecar(datadir, &bii_spec, out)) {
    case SSIO_READ_OK:          return BII_OK;
    case SSIO_READ_MISSING:     return BII_SIDECAR_MISSING;
    case SSIO_READ_UNREADABLE:  return BII_BODY_UNREADABLE;
    case SSIO_READ_STALE:       return BII_SIDECAR_STALE;
    case SSIO_READ_BAD_MAGIC:   return BII_SIDECAR_BAD_MAGIC;
    case SSIO_READ_UNSUPPORTED: return BII_SIDECAR_UNSUPPORTED;
    }
    return BII_BODY_UNREADABLE;
}

/* Cross-check the loader's declared tip against the SQLite `blocks`
 * table. The single SELECT lives behind
 * block_index_sidecar_port; we bind the default sqlite adapter to the
 * node DB connection and translate the port's three-way lookup result
 * to the EXACT verdict:
 *
 *   FOUND + height matches    -> BII_OK
 *   FOUND + height differs     -> BII_TIP_HEIGHT_MISMATCH
 *   NOT_FOUND                  -> BII_TIP_MISSING_IN_SQL
 *   UNAVAILABLE (skip)         -> BII_OK   (defer to CSR)
 */
static enum bii_verdict bii_check_tip_in_sql(struct node_db *db,
                                               const struct block_index *tip)
{
    if (!db || !db->open || !db->db || !tip || !tip->phashBlock)
        return BII_OK;  /* nothing to cross-check */

    struct block_index_sidecar_sqlite_ctx ctx;
    struct block_index_sidecar_port port = {0};
    if (!block_index_sidecar_sqlite_bind(&ctx, db->db, &port))
        return BII_OK;  /* bind only fails on NULL args — skip cross-check */

    int64_t sql_h = 0;
    enum bii_height_lookup got =
        port.lookup_block_height(port.self, tip->phashBlock->data, &sql_h);

    switch (got) {
    case BII_HEIGHT_FOUND:
        return sql_h != (int64_t)tip->nHeight
                   ? BII_TIP_HEIGHT_MISMATCH
                   : BII_OK;
    case BII_HEIGHT_NOT_FOUND:
        return BII_TIP_MISSING_IN_SQL;
    case BII_HEIGHT_UNAVAILABLE:
    default:
        return BII_OK;  /* schema may not be ready — defer to CSR */
    }
}

enum bii_verdict bii_verify(const char *datadir,
                             struct node_db *db,
                             const struct block_index *declared_tip,
                             char *err_out, size_t err_cap)
{
    if (err_out && err_cap) err_out[0] = '\0';
    if (!datadir) {
        if (err_out) snprintf(err_out, err_cap, "null datadir");
        return BII_BODY_UNREADABLE;
    }

    char body_path[1024];
    char side_path[1024];
    snprintf(body_path, sizeof(body_path), "%s/%s", datadir, bii_spec.body_name);
    snprintf(side_path, sizeof(side_path), "%s/%s", datadir, bii_spec.sidecar_name);

    /* Body presence. */
    struct platform_file_metadata body_metadata;
    enum platform_file_metadata_result metadata_result =
        platform_file_metadata_read(body_path, &body_metadata);
    if (metadata_result != PLATFORM_FILE_METADATA_OK) {
        if (err_out) snprintf(err_out, err_cap,
                "block_index.bin: %s",
                metadata_result == PLATFORM_FILE_METADATA_MISSING
                    ? "missing" : "unreadable or not a regular file");
        return metadata_result == PLATFORM_FILE_METADATA_MISSING
            ? BII_BODY_MISSING : BII_BODY_UNREADABLE;
    }

    /* Embedded single-file format FIRST (task #32): the integrity header
     * is the body's own first 48 bytes, so a re-hash of the payload
     * verifies the whole file with no sidecar. BAD_MAGIC here just means
     * "this is the legacy two-file body" — fall through to the sidecar
     * path below. Any other non-OK verdict is a hard integrity failure. */
    {
        struct ssio_sidecar_header ehdr;
        enum ssio_read_verdict ev =
            ssio_verify_embedded(datadir, &bii_embedded_spec, &ehdr, NULL);
        if (ev == SSIO_READ_OK) {
            /* Body integrity proven by the embedded header; only the
             * SQLite tip cross-check remains. */
            enum bii_verdict sql = bii_check_tip_in_sql(db, declared_tip);
            if (sql != BII_OK) {
                if (err_out && declared_tip) snprintf(err_out, err_cap,
                        "tip h=%d: %s", declared_tip->nHeight,
                        bii_verdict_name(sql));
                return sql;
            }
            return BII_OK;
        }
        if (ev != SSIO_READ_BAD_MAGIC) {
            /* Embedded magic/version matched but the payload hash, size,
             * or a read failed — refuse loudly with the specific reason. */
            if (err_out) snprintf(err_out, err_cap,
                    "embedded integrity: %s",
                    ev == SSIO_READ_STALE      ? "payload hash/size mismatch" :
                    ev == SSIO_READ_UNSUPPORTED ? "unsupported embedded version" :
                    ev == SSIO_READ_MISSING    ? "block_index.bin vanished" :
                                                 "block_index.bin unreadable");
            return ev == SSIO_READ_MISSING ? BII_BODY_MISSING
                                           : (ev == SSIO_READ_UNSUPPORTED
                                                  ? BII_SIDECAR_UNSUPPORTED
                                                  : BII_HASH_MISMATCH);
        }
        /* SSIO_READ_BAD_MAGIC → legacy two-file body; continue. */
    }

    /* Sidecar read. */
    struct ssio_sidecar_header hdr;
    enum bii_verdict rv = bii_read_sidecar(datadir, &hdr);
    if (rv == BII_SIDECAR_MISSING) {
        if (err_out) snprintf(err_out, err_cap,
                "no sidecar at %s (first run after upgrade?)", side_path);
        /* Even without a sidecar the SQLite cross-check is still
         * useful — a stale block_index.bin tip trips the tip check
         * regardless. */
        enum bii_verdict sql = bii_check_tip_in_sql(db, declared_tip);
        if (sql != BII_OK) {
            if (err_out) {
                char tmp[256];
                snprintf(tmp, sizeof(tmp),
                         "sidecar missing; SQLite cross-check: %s",
                         bii_verdict_name(sql));
                snprintf(err_out, err_cap, "%s", tmp);
            }
            return sql;
        }
        return BII_SIDECAR_MISSING;
    }
    if (rv != BII_OK) {
        if (err_out) snprintf(err_out, err_cap,
                "sidecar read: %s", bii_verdict_name(rv));
        return rv;
    }

    /* Size check before expensive hash. */
    if (hdr.body_size != body_metadata.size) {
        if (err_out) snprintf(err_out, err_cap,
                "size drift: sidecar=%llu actual=%llu",
                (unsigned long long)hdr.body_size,
                (unsigned long long)body_metadata.size);
        return BII_SIDECAR_STALE;
    }

    /* Full hash. */
    uint8_t actual_hash[32];
    uint64_t hashed_size = 0;
    if (!ssio_hash_body(datadir, &bii_spec, actual_hash, &hashed_size)) {
        if (err_out) snprintf(err_out, err_cap,
                "failed to hash %s: %s", body_path, strerror(errno));
        return BII_BODY_UNREADABLE;
    }
    if (hashed_size != hdr.body_size) {
        if (err_out) snprintf(err_out, err_cap,
                "size drift mid-hash: sidecar=%llu hashed=%llu",
                (unsigned long long)hdr.body_size,
                (unsigned long long)hashed_size);
        return BII_SIDECAR_STALE;
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
        return BII_HASH_MISMATCH;
    }

    /* SQLite cross-check. */
    enum bii_verdict sql = bii_check_tip_in_sql(db, declared_tip);
    if (sql != BII_OK) {
        if (err_out && declared_tip) snprintf(err_out, err_cap,
                "tip h=%d: %s", declared_tip->nHeight,
                bii_verdict_name(sql));
        return sql;
    }

    return BII_OK;
}

void bii_quarantine_corrupt(const char *datadir, enum bii_verdict v)
{
    ssio_quarantine(datadir, &bii_spec, bii_verdict_name(v));
}
