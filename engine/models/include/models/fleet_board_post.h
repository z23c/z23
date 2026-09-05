/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Fleet board / wiki persistence: the node's local append-only ledger of
 * signed board posts (schema v80). One row per post, keyed by the post id,
 * which is the hash of the signed bytes — so a save is idempotent and a
 * different body can never take an id that is already bound.
 *
 * The ledger is LOCAL evidence of arrival, not an authority over anybody. It
 * records what this node has seen and in what order; the board's meaning
 * comes from the signatures on the posts, and what is true comes from the
 * gates. Nothing here is consulted by consensus. */

#ifndef ZCL_DB_MODEL_FLEET_BOARD_POST_H
#define ZCL_DB_MODEL_FLEET_BOARD_POST_H

#include "models/activerecord.h"
#include "models/database.h"
#include "session/fleet_board_proto.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/* Storage ceilings. A node carries the whole board, so the board must be
 * small enough that carrying it is never a reason not to run a node. */
enum {
    FLEET_BOARD_STORE_MAX_POSTS = 10000,
    FLEET_BOARD_STORE_MAX_BYTES = 16 * 1024 * 1024,
    /* One list/inventory page. */
    FLEET_BOARD_LIST_MAX = 256,
};

struct db_fleet_board_post {
    struct fleet_board_post post;
    int64_t seq;            /* local arrival order, 1-based */
    int64_t expires_at;     /* created_at + ttl, materialized for the reaper */
    /* Canonical encoded size. Stored so the ledger can report and cap its
     * own footprint with one SQL aggregate instead of re-encoding every
     * row; validated on write against the encoding itself. */
    int64_t body_bytes;
    int64_t received_at;
    uint8_t chain_prev[32];
    uint8_t chain_hash[32];
};

/* Filters for db_fleet_board_list. A zero/empty field does not filter. */
struct fleet_board_filter {
    uint8_t kind;                       /* 0 = any kind */
    uint8_t host_pubkey[32];            /* all-zero = any host */
    bool host_set;
    int64_t since;                      /* created_at strictly greater */
    /* Open questions only: problem/need posts that no claim or result
     * references yet. An answered question drops out of --open the moment a
     * result naming it arrives, which is the whole point of the filter. */
    bool open_only;
    char slug[FLEET_BOARD_SLUG_MAX + 1];/* empty = any slug */
};

struct fleet_board_status {
    int64_t posts;
    int64_t bytes;
    int64_t oldest_created_at;
    int64_t newest_created_at;
    int64_t open_questions;
    int64_t wiki_pages;
    uint8_t head_chain[32];
    bool head_chain_set;
};

struct ar_callbacks *db_fleet_board_post_callbacks(void);

bool db_fleet_board_post_validate(const struct db_fleet_board_post *record,
                                  struct ar_errors *errors);

/* Verify, chain, and append one post. `now` is Unix seconds and decides the
 * expiry/future checks. Returns:
 *   FLEET_BOARD_OK        stored (or already stored with the same bytes)
 *   FLEET_BOARD_ERR_*     refused, with the exact reason
 * A post that fails signature, shape, or time checks is never stored, and a
 * refusal never partially mutates the ledger. `stored_out` (optional)
 * distinguishes a fresh append from an idempotent duplicate. */
enum fleet_board_result db_fleet_board_post_ingest(
    struct node_db *ndb, const struct fleet_board_post *post, int64_t now,
    bool *stored_out);

/* Exact-id lookup. Returns false when the id is unknown. */
bool db_fleet_board_post_find(struct node_db *ndb, const uint8_t id[32],
                              struct db_fleet_board_post *out);

/* Newest-first listing under `filter`. Returns the number written, at most
 * `max` (capped at FLEET_BOARD_LIST_MAX). Expired discussions are excluded;
 * durable wiki revisions remain discoverable. */
int db_fleet_board_list(struct node_db *ndb,
                        const struct fleet_board_filter *filter, int64_t now,
                        struct db_fleet_board_post *out, size_t max);

/* Latest valid revision of one wiki slug: the newest created_at among that
 * slug's stored revisions, ties broken by the larger id, so every node that
 * holds the same revisions resolves the same page. */
bool db_fleet_board_wiki_read(struct node_db *ndb, const char *slug,
                              struct db_fleet_board_post *out);

/* One row per slug: the latest revision of every page. */
int db_fleet_board_wiki_list(struct node_db *ndb,
                             struct db_fleet_board_post *out, size_t max);

/* Every revision of one slug, newest first. */
int db_fleet_board_wiki_history(struct node_db *ndb, const char *slug,
                                struct db_fleet_board_post *out, size_t max);

bool db_fleet_board_status(struct node_db *ndb, int64_t now,
                           struct fleet_board_status *out);

/* The ids this node holds, newest first, for a gossip inventory. */
int db_fleet_board_recent_ids(struct node_db *ndb, int64_t now,
                              uint8_t (*ids)[32], size_t max);

/* One verified, unexpired inventory page in descending local arrival order.
 * before_seq=0 starts at the head; otherwise only seq<before_seq is eligible.
 * last_seq_out is reset to zero and receives the last returned sequence, which
 * lets a caller advance to the next page. Returns -1 on query or verification
 * failure, 0 only at a verified end, and otherwise the number of ids. */
int db_fleet_board_ids_before(struct node_db *ndb, int64_t now,
                              int64_t before_seq, uint8_t (*ids)[32],
                              size_t max, int64_t *last_seq_out);

bool db_fleet_board_have(struct node_db *ndb, const uint8_t id[32]);

/* Re-walk the stored chain in seq order and confirm every chain_hash is the
 * step its predecessor implies. Local integrity only. */
bool db_fleet_board_chain_verify(struct node_db *ndb, int64_t *checked_out);

struct json_value;
bool fleet_board_dump_state_json(struct json_value *out, const char *key);

#ifdef ZCL_TESTING
/* Narrow capacity seam for adversarial store tests. Production always uses
 * FLEET_BOARD_STORE_MAX_{POSTS,BYTES}; zero restores those defaults. */
void db_fleet_board_test_set_store_limits(int64_t max_posts,
                                          int64_t max_bytes);
#endif

#endif /* ZCL_DB_MODEL_FLEET_BOARD_POST_H */
