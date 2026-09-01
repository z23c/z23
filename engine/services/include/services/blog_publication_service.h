/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Blog publication service: deterministic payload/anchor codecs, wallet-bound
 * signed-event creation, ZNAM owner verification, ActiveRecord persistence,
 * and reorg-aware observation of the full-node projections. */

#ifndef ZCL_SERVICES_BLOG_PUBLICATION_SERVICE_H
#define ZCL_SERVICES_BLOG_PUBLICATION_SERVICE_H

#include "framework/app_platform.h"
#include "models/blog_post.h"
#include "services/wallet_money_service.h"
#include "util/result.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define BLOG_APP_ID "blog"
#define BLOG_EVENT_TOPIC "blog.posts.v1"
#define BLOG_EVENT_KIND_PUBLISH 1u
#define BLOG_EVENT_MAX_BYTES 20000u
#define BLOG_ANCHOR_SCRIPT_MAX 128u
#define BLOG_MAX_FUTURE_SKEW_SECONDS 300u

struct wallet;

struct blog_publish_request {
    const char *blog_name;
    const char *slug;
    const char *title;
    const char *body;
    uint64_t sequence;
    uint64_t created_at;
    uint8_t previous_event_id[32];
};

struct blog_publish_result {
    struct db_blog_post post;
    uint8_t anchor_script[BLOG_ANCHOR_SCRIPT_MAX];
    size_t anchor_script_len;
};

/* Durable custody-bound plan/commit contract for one already stored signed
 * event. Wallet selection/signing and publication stay behind narrow ports so
 * the workflow never handles a key. The prepared raw transaction is public
 * transaction material, persisted by the existing vault-intent lifecycle. */
#define BLOG_ANCHOR_APPLICATION "blog_anchor"
#define BLOG_ANCHOR_IDEMPOTENCY_MAX 64

typedef struct zcl_result (*blog_anchor_money_fn)(
    void *ctx, const char *wallet_scope, struct wallet_money_snapshot *out);
typedef struct zcl_result (*blog_anchor_prepare_fn)(
    void *ctx, const uint8_t *anchor_script, size_t anchor_script_len,
    int64_t maximum_fee_zat, uint8_t *raw_tx, size_t raw_capacity,
    size_t *raw_tx_len, uint8_t txid_out[32], int64_t *actual_fee_zat);
typedef struct zcl_result (*blog_anchor_publish_fn)(
    void *ctx, const uint8_t *raw_tx, size_t raw_tx_len,
    const uint8_t expected_txid[32]);

struct blog_anchor_runtime {
    struct node_db *node_db;
    blog_anchor_money_fn read_money;
    void *money_ctx;
    blog_anchor_prepare_fn prepare;
    void *prepare_ctx;
    blog_anchor_publish_fn publish;
    void *publish_ctx;
    int32_t tip_height;
    uint8_t tip_hash[32];
    int64_t maximum_fee_zat;
    int64_t now_unix;
};

struct blog_anchor_request {
    char wallet_scope[5];
    char blog_name[BLOG_NAME_MAX + 1];
    uint8_t event_id[32];
    char idempotency_key[BLOG_ANCHOR_IDEMPOTENCY_MAX + 1];
};

struct blog_anchor_transaction_result {
    uint8_t plan_id[32];
    char wallet_scope[5];
    char blog_name[BLOG_NAME_MAX + 1];
    uint8_t event_id[32];
    uint8_t anchor_script[BLOG_ANCHOR_SCRIPT_MAX];
    size_t anchor_script_len;
    bool event_verified;
    bool broadcast;
    bool idempotent_replay;
    bool has_txid;
    uint8_t txid[32];
    int64_t actual_fee_zat;
    int64_t maximum_fee_zat;
    int64_t reserved_zat;
    int64_t expires_at;
    char state[24];
};

struct blog_projection_observation {
    bool observed;
    bool projection_only;
    bool served_frontier_proven;
    struct db_blog_publication_receipt receipt;
};

/* Derive inbound verification policy from the selected chain's genesis hash.
 * This is policy, not signing authority. */
struct zcl_result blog_publication_scope(struct zcl_app_event_scope_v1 *out);

/* Strong pre-sign validation. Checks canonical fields, sequence shape,
 * timestamp policy, database readiness, and that the ZNAM identity exists.
 * Exact signer↔owner matching is rechecked after the opaque Core signer emits
 * the public author key; the future broker will expose a preflight predicate. */
struct zcl_result blog_publication_validate_request(
    struct node_db *ndb, const struct blog_publish_request *request);

/* Core-only create path. `binding` is opaque and must come from the future
 * active-generation/local-grant broker. Production currently has no public
 * constructor; tests use the explicit test-only constructor. */
struct zcl_result blog_publication_create(
    struct node_db *ndb, struct wallet *wallet,
    const struct zcl_app_event_signing_binding_v1 *binding,
    const struct blog_publish_request *request,
    struct blog_publish_result *out);

/* Import from any relay: cryptographically verify, parse, bind the signer to
 * the current on-chain ZNAM projection, and persist through ActiveRecord. */
struct zcl_result blog_publication_import_event(
    struct node_db *ndb, const struct zcl_app_signed_event_v1 *event,
    struct db_blog_post *out);

/* Rebuild the canonical signed event from an ActiveRecord row. `payload` is
 * caller-owned storage retained by the returned borrowed event view. */
struct zcl_result blog_publication_export_event(
    const struct db_blog_post *post,
    uint8_t *payload, size_t payload_capacity,
    struct zcl_app_signed_event_v1 *out_event);

/* Index projection that admits only rows whose canonical event and signature
 * still verify. This keeps corrupt/directly-written rows out of public HTML. */
int blog_publication_recent_verified_summaries(
    struct node_db *ndb, const char *blog_name_or_null,
    struct db_blog_post_summary *out, size_t max);

/* ZBLG chain commitment: OP_RETURN <"ZBLG"> <v1> <znam> <event-id>.
 * Parsing is strict and rejects trailing fields. */
struct zcl_result blog_anchor_script_build(
    const char *blog_name, const uint8_t event_id[32],
    uint8_t *out, size_t out_capacity, size_t *out_len);
struct zcl_result blog_anchor_script_parse(
    const uint8_t *script, size_t script_len,
    char blog_name[BLOG_NAME_MAX + 1], uint8_t event_id[32]);

struct zcl_result blog_publication_anchor_plan(
    const struct blog_anchor_runtime *runtime,
    const struct blog_anchor_request *request,
    struct blog_anchor_transaction_result *out);
struct zcl_result blog_publication_anchor_commit(
    const struct blog_anchor_runtime *runtime, const char *wallet_scope,
    const uint8_t plan_id[32],
    struct blog_anchor_transaction_result *out);
struct zcl_result blog_publication_anchor_status(
    const struct blog_anchor_runtime *runtime, const uint8_t plan_id[32],
    struct blog_anchor_transaction_result *out);

/* Observe the lossy SQLite projections only. A true result is explicitly not
 * a served-frontier/H* proof; missing rows remain unresolved, never "absent". */
struct zcl_result blog_publication_observe_projection(
    struct node_db *ndb, const uint8_t event_id[32],
    struct blog_projection_observation *out);

#endif /* ZCL_SERVICES_BLOG_PUBLICATION_SERVICE_H */
