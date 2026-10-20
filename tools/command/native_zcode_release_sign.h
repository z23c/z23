/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * purpose: the one release-signing core shared by zcode.release.sign and
 *          ops.release.sign. It reads the seed files (0600/0400, exact hex
 *          length), signs a v1 doc, or a ZRS1 v2 hybrid doc when a PQ seed
 *          file is named, and wipes every seed buffer on every path. It never
 *          logs or returns seed bytes. */
#ifndef ZCL_NATIVE_ZCODE_RELEASE_SIGN_H
#define ZCL_NATIVE_ZCODE_RELEASE_SIGN_H

#include "kernel/command_registry.h"
#include "zid/zid.h"
#include "zid/zid_hybrid.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/* Outcome of signing one release: the wire bytes plus the keys. `pq` is true
 * for a v2 (hybrid) doc. */
struct zcode_release_signed {
    uint8_t wire[ZID_DOC_V2_MAX];
    size_t wire_len;
    uint8_t master_pubkey[32];
    uint8_t pq_pk[ZRS1_PQ_PK_SIZE];
    bool pq;
};

/* v1 when pq_seed_file is NULL or empty, v2 hybrid otherwise. On failure the
 * reply is failed with a typed code (BAD_SEED_FILE, BAD_PQ_SEED_FILE,
 * SIGN_FAILED, ENCODE_FAILED) and false is returned; nothing is written. */
bool zcl_zcode_release_sign_doc(struct zcl_command_reply *reply,
                                const struct zid_release *rel, uint64_t seq,
                                uint64_t expiry, const char *seed_file,
                                const char *pq_seed_file,
                                struct zcode_release_signed *out);

#endif
