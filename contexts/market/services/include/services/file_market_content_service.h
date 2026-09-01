/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: register and re-verify private seller content for paid delivery. */

#ifndef ZCL_SERVICE_FILE_MARKET_CONTENT_H
#define ZCL_SERVICE_FILE_MARKET_CONTENT_H

#include "base/result.h"
#include "models/market_content.h"
#include "net/file_market_delivery.h"

#include <stdint.h>

#define MARKET_CONTENT_REGISTRATION_STATE_MAX 80u

struct zcl_result file_market_content_register(
    struct node_db *ndb, const uint8_t offer_id[32], const char *content_path,
    int64_t now_unix, struct market_content_public_record *out);

/* Mint and atomically consume a registration plan. The token commits the
 * canonical signed-offer wire, complete durable registration-row identity,
 * and exact target path. */
struct zcl_result file_market_content_registration_plan(
    struct node_db *ndb, const uint8_t offer_id[32], const char *content_path,
    uint8_t token_out[32],
    char state_out[MARKET_CONTENT_REGISTRATION_STATE_MAX]);
struct zcl_result file_market_content_register_planned(
    struct node_db *ndb, const uint8_t offer_id[32], const char *content_path,
    const uint8_t plan_token[32], int64_t now_unix,
    struct market_content_public_record *out);

#ifdef ZCL_TESTING
typedef void (*file_market_content_precommit_test_hook_fn)(void *ctx);
void file_market_content_set_precommit_test_hook(
    file_market_content_precommit_test_hook_fn hook, void *ctx);
#endif

/* Canonicalize a private content reference and derive its complete manifest
 * (per-chunk digests and their root) from the bytes on disk, with symlink,
 * type, size-limit, and mid-hash mutation refusal. When hashes_out is
 * non-NULL it receives the zcl_malloc-owned num_chunks*32 digest array the
 * caller must free; the offer service passes NULL when it needs only the
 * root. Shares the exact refusal codes with file_market_content_register. */
struct zcl_result file_market_content_manifest_build(
    const char *content_path, char canonical_out[MARKET_CONTENT_PATH_MAX],
    uint8_t **hashes_out, uint64_t *size_out, uint32_t *chunks_out,
    uint8_t root_out[32]);

/* Reopens the private regular file, reads exactly one registered chunk, and
 * verifies its digest. On success out->data is zcl_malloc-owned. */
struct zcl_result file_market_content_load_chunk(
    struct node_db *ndb, const uint8_t offer_id[32], uint32_t chunk_index,
    struct file_market_delivery_chunk *out);

#endif
