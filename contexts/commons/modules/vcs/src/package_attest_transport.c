/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * package_attest_transport — implementation. See
 * vcs/package_attest_transport.h for the contract and the reasons.
 *
 * Everything here is a thin, hostile-input-checked adapter over
 * primitives that already exist: package_attest for the grammar and the
 * embedded signature, blob_store for the content-addressed carriage, and
 * the store's own durable-write helpers (store_mkdir_p /
 * store_atomic_write, package_store_io.c) for filing. No new wire
 * message, no new bound, and — deliberately — no second copy of the
 * tmp+fsync+rename discipline.
 *
 * No sockets, no threads, no wall clock: scheduling a transfer is the
 * swarm engine's job and the caller drives it. */

#include "vcs/package_attest_transport.h"

#include "vcs/blob_store.h"
#include "vcs/package_attest.h"

#include "package_store_priv.h" /* store_mkdir_p / store_atomic_write */

#include "base/hex.h"
#include "base/log_macros.h"
#include "base/safe_alloc.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

#define ATT_LOG "vcs.attest.transport"

/* Room for the whole canonical wire plus one byte, so a read that fills
 * the bound can still be told apart from a file that overflows it. */
#define ATT_READ_CAP (VCS_PACKAGE_ATTEST_MAX_WIRE_BYTES + 1u)

#define ATT_ID_HEX_BYTES (2u * VCS_PACKAGE_ATTEST_ID_BYTES + 1u)

const char *vcs_package_attest_transport_result_string(
    enum vcs_package_attest_transport_result result)
{
    switch (result) {
    case VCS_PACKAGE_ATTEST_TRANSPORT_OK:           return "ok";
    case VCS_PACKAGE_ATTEST_TRANSPORT_ERR_NULL:     return "null-argument";
    case VCS_PACKAGE_ATTEST_TRANSPORT_ERR_ALLOC:    return "allocation-failed";
    case VCS_PACKAGE_ATTEST_TRANSPORT_ERR_PATH:     return "path-too-long";
    case VCS_PACKAGE_ATTEST_TRANSPORT_ERR_ABSENT:   return "attestation-absent";
    case VCS_PACKAGE_ATTEST_TRANSPORT_ERR_BLOB:     return "blob-refused";
    case VCS_PACKAGE_ATTEST_TRANSPORT_ERR_ATTEST:   return "not-an-attestation";
    case VCS_PACKAGE_ATTEST_TRANSPORT_ERR_ID:       return "attestation-id-mismatch";
    case VCS_PACKAGE_ATTEST_TRANSPORT_ERR_BINDING:  return "package-root-binding";
    case VCS_PACKAGE_ATTEST_TRANSPORT_ERR_STORE:    return "store-refused";
    case VCS_PACKAGE_ATTEST_TRANSPORT_ERR_CONFLICT: return "attestation-id-conflict";
    }
    return "unknown";
}

/* ── small shared helpers ───────────────────────────────────────────── */

/* Stamp the outcome's verdict field and hand the same value back, so
 * every exit of a public entry point reports exactly one result. */
static enum vcs_package_attest_transport_result att_done(
    struct vcs_package_attest_transport_outcome *out,
    enum vcs_package_attest_transport_result result)
{
    out->result = result;
    return result;
}

/* Read one bounded file whole. False when missing, unreadable, empty, or
 * larger than `cap` — trailing bytes mean these are not the exact object.
 * `buf` must hold cap + 1 bytes: the extra byte is what makes "exactly
 * cap bytes" distinguishable from "cap bytes and more to come". */
static bool att_read_bounded(const char *path, uint8_t *buf, size_t cap,
                             size_t *out_len)
{
    *out_len = 0;
    FILE *f = fopen(path, "rb");
    if (!f)
        return false;
    size_t len = fread(buf, 1, cap + 1u, f);
    bool ok = !ferror(f) && len > 0 && len <= cap;
    fclose(f);
    if (!ok)
        return false;
    *out_len = len;
    return true;
}

/* The authentication half of every path: the ZCLATT grammar, then the
 * embedded secp256k1 signature over the recomputed attestation id. This
 * proves authorship of these exact bytes ONLY — whether the signer COUNTS
 * is the policy layer's rule, applied later by `zcode package verify`. */
static enum vcs_package_attest_transport_result att_authenticate(
    const uint8_t *wire, size_t wire_len,
    struct vcs_package_attest_transport_outcome *out)
{
    enum vcs_package_attest_error aerr =
        vcs_package_attest_parse(wire, wire_len, &out->attestation);
    if (aerr != VCS_PACKAGE_ATTEST_OK) {
        out->attest_error = aerr;
        LOG_RETURN(VCS_PACKAGE_ATTEST_TRANSPORT_ERR_ATTEST, ATT_LOG,
                   "%zu bytes are not a canonical attestation: %s", wire_len,
                   vcs_package_attest_error_string(aerr));
    }
    aerr = vcs_package_attest_verify(&out->attestation);
    if (aerr != VCS_PACKAGE_ATTEST_OK) {
        out->attest_error = aerr;
        LOG_RETURN(VCS_PACKAGE_ATTEST_TRANSPORT_ERR_ATTEST, ATT_LOG,
                   "the embedded verifier signature does not verify: %s",
                   vcs_package_attest_error_string(aerr));
    }
    aerr = vcs_package_attest_id(&out->attestation, out->attestation_id);
    if (aerr != VCS_PACKAGE_ATTEST_OK) {
        out->attest_error = aerr;
        LOG_RETURN(VCS_PACKAGE_ATTEST_TRANSPORT_ERR_ATTEST, ATT_LOG,
                   "a verified attestation has no id: %s",
                   vcs_package_attest_error_string(aerr));
    }
    return VCS_PACKAGE_ATTEST_TRANSPORT_OK;
}

/* ── pure: the transport root of these exact bytes ──────────────────── */

static enum vcs_package_attest_transport_result att_root_inner(
    const uint8_t *wire, size_t wire_len,
    struct vcs_package_attest_transport_outcome *out)
{
    if (!wire)
        LOG_RETURN(VCS_PACKAGE_ATTEST_TRANSPORT_ERR_NULL, ATT_LOG,
                   "wire is NULL");

    /* Parse and verify FIRST. A node never advertises a transport root
     * for bytes it has not proven are a genuine attestation. */
    enum vcs_package_attest_transport_result r =
        att_authenticate(wire, wire_len, out);
    if (r != VCS_PACKAGE_ATTEST_TRANSPORT_OK)
        return r;

    enum vcs_blob_result br =
        vcs_blob_root_of(wire, wire_len, out->transport_root);
    if (br != VCS_BLOB_OK) {
        out->blob_error = br;
        memset(out->transport_root, 0, sizeof(out->transport_root));
        LOG_RETURN(VCS_PACKAGE_ATTEST_TRANSPORT_ERR_BLOB, ATT_LOG,
                   "blob root of a verified attestation refused: %s",
                   vcs_blob_result_string(br));
    }
    return VCS_PACKAGE_ATTEST_TRANSPORT_OK;
}

enum vcs_package_attest_transport_result vcs_package_attest_transport_root(
    const uint8_t *wire, size_t wire_len,
    struct vcs_package_attest_transport_outcome *out)
{
    if (!out)
        LOG_RETURN(VCS_PACKAGE_ATTEST_TRANSPORT_ERR_NULL, ATT_LOG,
                   "outcome is NULL");
    memset(out, 0, sizeof(*out));
    return att_done(out, att_root_inner(wire, wire_len, out));
}

/* ── local filing (the one implementation) ──────────────────────────── */

enum vcs_package_attest_transport_result vcs_package_attest_transport_file(
    const char *zcode_dir, const uint8_t *wire, size_t wire_len,
    const uint8_t id[VCS_PACKAGE_ATTEST_ID_BYTES], bool *out_filed,
    bool *out_already_present)
{
    if (out_filed)
        *out_filed = false;
    if (out_already_present)
        *out_already_present = false;
    if (!zcode_dir || !wire || !id)
        LOG_RETURN(VCS_PACKAGE_ATTEST_TRANSPORT_ERR_NULL, ATT_LOG,
                   "zcode_dir, wire, or id is NULL");
    if (wire_len == 0 || wire_len > VCS_PACKAGE_ATTEST_MAX_WIRE_BYTES)
        LOG_RETURN(VCS_PACKAGE_ATTEST_TRANSPORT_ERR_ATTEST, ATT_LOG,
                   "%zu bytes cannot be a canonical attestation", wire_len);

    /* Both paths are bounded before anything is created, so a datadir
     * that cannot hold the final name never leaves a new directory
     * behind. */
    char dir[STORE_PATH_MAX];
    int n = snprintf(dir, sizeof(dir), "%s/attestations", zcode_dir);
    if (n <= 0 || (size_t)n >= sizeof(dir))
        LOG_RETURN(VCS_PACKAGE_ATTEST_TRANSPORT_ERR_PATH, ATT_LOG,
                   "attestations directory path too long under %s",
                   zcode_dir);
    char id_hex[ATT_ID_HEX_BYTES];
    zcl_hex_encode(id, VCS_PACKAGE_ATTEST_ID_BYTES, id_hex);
    char dest[STORE_PATH_MAX];
    n = snprintf(dest, sizeof(dest), "%s/%s", dir, id_hex);
    if (n <= 0 || (size_t)n >= sizeof(dest))
        LOG_RETURN(VCS_PACKAGE_ATTEST_TRANSPORT_ERR_PATH, ATT_LOG,
                   "attestation path too long under %s", dir);

    if (!store_mkdir_p(dir))
        LOG_RETURN(VCS_PACKAGE_ATTEST_TRANSPORT_ERR_STORE, ATT_LOG,
                   "cannot create %s: %s", dir, strerror(errno));

    /* Idempotent: the id IS the content hash, so a same-name file holding
     * identical bytes is a no-op success. A same-name file that does not
     * read back identical is store corruption — never overwritten. */
    struct stat st;
    if (stat(dest, &st) == 0) {
        uint8_t *have = zcl_malloc(ATT_READ_CAP, "attest-transport-readback");
        if (!have)
            LOG_RETURN(VCS_PACKAGE_ATTEST_TRANSPORT_ERR_ALLOC, ATT_LOG,
                       "readback buffer for %s", dest);
        size_t have_len = 0;
        bool same = att_read_bounded(dest, have,
                                     VCS_PACKAGE_ATTEST_MAX_WIRE_BYTES,
                                     &have_len) &&
                    have_len == wire_len &&
                    memcmp(have, wire, wire_len) == 0;
        free(have);
        if (!same)
            LOG_RETURN(VCS_PACKAGE_ATTEST_TRANSPORT_ERR_CONFLICT, ATT_LOG,
                       "a different or unreadable object already occupies "
                       "%s", dest);
        if (out_already_present)
            *out_already_present = true;
        return VCS_PACKAGE_ATTEST_TRANSPORT_OK;
    }

    if (!store_atomic_write(dest, wire, wire_len))
        LOG_RETURN(VCS_PACKAGE_ATTEST_TRANSPORT_ERR_STORE, ATT_LOG,
                   "the attestation could not be filed at %s", dest);
    if (out_filed)
        *out_filed = true;
    return VCS_PACKAGE_ATTEST_TRANSPORT_OK;
}

/* ── publish side: make a local attestation reachable ───────────────── */

static enum vcs_package_attest_transport_result att_offer_inner(
    struct vcs_package_store *store, const char *zcode_dir,
    const uint8_t id[VCS_PACKAGE_ATTEST_ID_BYTES],
    struct vcs_package_attest_transport_outcome *out)
{
    if (!store || !zcode_dir || !id)
        LOG_RETURN(VCS_PACKAGE_ATTEST_TRANSPORT_ERR_NULL, ATT_LOG,
                   "store, zcode_dir, or id is NULL");
    memcpy(out->attestation_id, id, VCS_PACKAGE_ATTEST_ID_BYTES);

    char id_hex[ATT_ID_HEX_BYTES];
    zcl_hex_encode(id, VCS_PACKAGE_ATTEST_ID_BYTES, id_hex);
    char path[STORE_PATH_MAX];
    int n = snprintf(path, sizeof(path), "%s/attestations/%s", zcode_dir,
                     id_hex);
    if (n <= 0 || (size_t)n >= sizeof(path))
        LOG_RETURN(VCS_PACKAGE_ATTEST_TRANSPORT_ERR_PATH, ATT_LOG,
                   "attestation path too long under %s", zcode_dir);

    uint8_t *wire = zcl_malloc(ATT_READ_CAP, "attest-transport-offer");
    if (!wire)
        LOG_RETURN(VCS_PACKAGE_ATTEST_TRANSPORT_ERR_ALLOC, ATT_LOG,
                   "wire buffer for %s", path);
    size_t wire_len = 0;
    if (!att_read_bounded(path, wire, VCS_PACKAGE_ATTEST_MAX_WIRE_BYTES,
                          &wire_len)) {
        free(wire);
        LOG_RETURN(VCS_PACKAGE_ATTEST_TRANSPORT_ERR_ABSENT, ATT_LOG,
                   "no readable attestation at %s", path);
    }

    /* Re-parse, re-verify, re-derive: a stored object is input too. */
    enum vcs_package_attest_transport_result r =
        att_authenticate(wire, wire_len, out);
    if (r != VCS_PACKAGE_ATTEST_TRANSPORT_OK) {
        free(wire);
        return r;
    }
    if (memcmp(out->attestation_id, id, VCS_PACKAGE_ATTEST_ID_BYTES) != 0) {
        free(wire);
        LOG_RETURN(VCS_PACKAGE_ATTEST_TRANSPORT_ERR_ID, ATT_LOG,
                   "the object filed at %s does not recompute to that id",
                   path);
    }

    enum vcs_blob_result br =
        vcs_blob_put_to(store, wire, wire_len, out->transport_root);
    free(wire);
    if (br != VCS_BLOB_OK) {
        out->blob_error = br;
        memset(out->transport_root, 0, sizeof(out->transport_root));
        LOG_RETURN(VCS_PACKAGE_ATTEST_TRANSPORT_ERR_BLOB, ATT_LOG,
                   "the blob layer refused attestation %s: %s", id_hex,
                   vcs_blob_result_string(br));
    }
    return VCS_PACKAGE_ATTEST_TRANSPORT_OK;
}

enum vcs_package_attest_transport_result vcs_package_attest_transport_offer(
    struct vcs_package_store *store, const char *zcode_dir,
    const uint8_t id[VCS_PACKAGE_ATTEST_ID_BYTES],
    struct vcs_package_attest_transport_outcome *out)
{
    if (!out)
        LOG_RETURN(VCS_PACKAGE_ATTEST_TRANSPORT_ERR_NULL, ATT_LOG,
                   "outcome is NULL");
    memset(out, 0, sizeof(*out));
    return att_done(out, att_offer_inner(store, zcode_dir, id, out));
}

/* ── receive side: admit what the swarm delivered ───────────────────── */

static enum vcs_package_attest_transport_result att_admit_inner(
    struct vcs_package_store *store, const char *zcode_dir,
    const uint8_t transport_root[32], const uint8_t *expect_package_root,
    struct vcs_package_attest_transport_outcome *out)
{
    if (!store || !zcode_dir || !transport_root)
        LOG_RETURN(VCS_PACKAGE_ATTEST_TRANSPORT_ERR_NULL, ATT_LOG,
                   "store, zcode_dir, or transport_root is NULL");
    memcpy(out->transport_root, transport_root, sizeof(out->transport_root));

    uint8_t *wire = zcl_malloc(ATT_READ_CAP, "attest-transport-admit");
    if (!wire)
        LOG_RETURN(VCS_PACKAGE_ATTEST_TRANSPORT_ERR_ALLOC, ATT_LOG,
                   "wire buffer for an admitted blob");
    size_t wire_len = 0;
    /* The blob layer re-verifies the manifest, the root, and the chunk
     * hash; a blob larger than the canonical wire bound cannot be an
     * attestation and is refused by capacity before it is trusted. */
    enum vcs_blob_result br =
        vcs_blob_get_from(store, transport_root, wire,
                          VCS_PACKAGE_ATTEST_MAX_WIRE_BYTES, &wire_len);
    if (br != VCS_BLOB_OK) {
        free(wire);
        out->blob_error = br;
        LOG_RETURN(VCS_PACKAGE_ATTEST_TRANSPORT_ERR_BLOB, ATT_LOG,
                   "the blob layer refused the delivered bytes: %s",
                   vcs_blob_result_string(br));
    }

    enum vcs_package_attest_transport_result r =
        att_authenticate(wire, wire_len, out);
    if (r != VCS_PACKAGE_ATTEST_TRANSPORT_OK) {
        free(wire);
        return r;
    }

    /* The binding check, and the whole reason a hostile pointer cannot
     * poison a package's evidence. Refused BEFORE filing: nothing is
     * written for an attestation about a different package. */
    if (expect_package_root &&
        memcmp(out->attestation.package_root, expect_package_root, 32) != 0) {
        free(wire);
        LOG_RETURN(VCS_PACKAGE_ATTEST_TRANSPORT_ERR_BINDING, ATT_LOG,
                   "the delivered attestation names a different package "
                   "root than the one asked about");
    }

    /* Admitting is NOT accepting: an unapproved signer, a failure result
     * class, and a package this node does not hold all file here. The
     * approved-verifier quorum is applied later, by evaluation. */
    bool filed = false;
    bool already_present = false;
    r = vcs_package_attest_transport_file(zcode_dir, wire, wire_len,
                                          out->attestation_id, &filed,
                                          &already_present);
    free(wire);
    if (r != VCS_PACKAGE_ATTEST_TRANSPORT_OK)
        return r; /* the filer already named the rule */
    out->filed = filed;
    out->already_present = already_present;
    return VCS_PACKAGE_ATTEST_TRANSPORT_OK;
}

enum vcs_package_attest_transport_result vcs_package_attest_transport_admit(
    struct vcs_package_store *store, const char *zcode_dir,
    const uint8_t transport_root[32], const uint8_t *expect_package_root,
    struct vcs_package_attest_transport_outcome *out)
{
    if (!out)
        LOG_RETURN(VCS_PACKAGE_ATTEST_TRANSPORT_ERR_NULL, ATT_LOG,
                   "outcome is NULL");
    memset(out, 0, sizeof(*out));
    return att_done(out, att_admit_inner(store, zcode_dir, transport_root,
                                         expect_package_root, out));
}
