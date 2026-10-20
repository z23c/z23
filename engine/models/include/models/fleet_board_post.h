/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Fleet board / wiki persistence: the node's local append-only ledger of
 * signed board posts (schema v81). One row per post, keyed by the post id,
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
    /* Distinct public rooms on one index page. */
    FLEET_BOARD_ROOM_LIST_MAX = 64,
    /* Distinct signing keys one host scan reports. A fleet is the owner's
     * own machines, so this is generous, not a limit anybody meets. */
    FLEET_BOARD_HOST_LIST_MAX = 64,

    /* PUBLIC-scope quota: a stranger key needs no grant to post to a public
     * room, so this is the only thing standing between one key and a flood.
     * Two independent ceilings, both per signing key, asking two different
     * questions:
     *   WINDOW    is this key bursting? Counts every arrival in the window,
     *             expired or not, because a burst is a burst even when
     *             every post in it expires a minute later.
     *   RESIDENT  how much of this node's finite, forever-carried store is
     *             this key holding? Counts every row this node is STORING
     *             for the key, live or expired: an expired row still on
     *             disk is still bytes this node carries, until
     *             db_fleet_board_reclaim_expired takes it back. That
     *             reclaim is what hands the slot back — the ceiling itself
     *             never depends on the reclaim having run, because a node
     *             can opt out of boot maintenance
     *             (ZCL_DISABLE_BOOT_DB_MAINT) and a ceiling counted over
     *             live rows alone would then let one key grow into the
     *             whole shared store cap above and wedge the board for
     *             every key.
     * Either one being spent refuses the post. A FLEET-scope post meets the
     * same two ceilings after its role check, counted over that key's
     * fleet-scope rows alone: a granted key, or a paired peer carrying its
     * posts, can no more fill the shared store than a stranger can. A
     * legacy post is admitted by its role alone, as before. Neither touches
     * the global store cap above. */
    FLEET_BOARD_PUBLIC_QUOTA_WINDOW_SECONDS = 600,   /* 10 minutes */
    FLEET_BOARD_PUBLIC_QUOTA_WINDOW_MAX = 60,        /* posts / key / window */
    FLEET_BOARD_PUBLIC_QUOTA_STORED_MAX = 1000,      /* stored posts / key */

    /* WIKI budget: wiki revisions are counted against their own per-key
     * ceilings and ordinary posts against the two above, which count every
     * kind except wiki. Chatter can therefore never block knowledge, and
     * wiki writes can never crowd out messages. Wiki revisions are durable
     * history that expiry reclaim never takes back. A key at its stored
     * ceiling replaces its own oldest superseded revision (one with a later
     * revision of the same slug by the same key in the same scope). Failing
     * that it replaces its oldest plain revision whose ttl has elapsed (never
     * a review row); a future pin flag will exempt pinned pages. It is
     * refused when neither exists.
     * Wiki rows together may use at most half of FLEET_BOARD_STORE_MAX_BYTES. */
    FLEET_BOARD_WIKI_QUOTA_WINDOW_MAX = 20,          /* revisions / key / window */
    FLEET_BOARD_WIKI_QUOTA_STORED_MAX = 200,         /* stored revisions / key */
    /* Node-wide cap on wiki replacements, across all keys, counted on the
     * ingest clock: a replacement relinks the rows after the victim. */
    FLEET_BOARD_WIKI_EVICT_MAX = 6,
    FLEET_BOARD_WIKI_EVICT_SECONDS = 60,
};

struct db_fleet_board_post {
    struct fleet_board_post post;
    int64_t seq;            /* local arrival order, 1-based */
    int64_t expires_at;     /* created_at + ttl, the reclaim's own predicate */
    /* Canonical encoded size. Stored so the ledger can report and cap its
     * own footprint with one SQL aggregate instead of re-encoding every
     * row; validated on write against the encoding itself. */
    int64_t body_bytes;
    int64_t received_at;
    uint8_t chain_prev[32];
    uint8_t chain_hash[32];
    /* This store's own arrival number (schema v84): assigned once at
     * ingest, strictly above every number this process has handed out and
     * every number already stored, and never rewritten — a reclaim
     * renumbers seq, not this. The paired fleet pull pages on it. */
    int64_t arrival;
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
    char agent[FLEET_BOARD_AGENT_MAX + 1];/* empty = any agent (exact match) */
    /* Scope filtering. scope_set=false means "every scope this caller may
     * see" — the caller decides visibility; the store only matches. A room
     * filter matches the room a post READS as: asking for the default room
     * also returns legacy posts, whose empty signed room is that room. */
    bool scope_set;
    uint8_t scope;                      /* enum fleet_board_scope */
    char room[FLEET_BOARD_ROOM_MAX + 1];/* empty = any room */
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
 * distinguishes a fresh append from an idempotent duplicate.
 *
 * The signing host key must also hold a ROLE granting `fleet.board.post`
 * for this post's kind on this node, asked through util/fleet_role_check.h.
 * A key with no such grant refuses as FLEET_BOARD_ERR_ROLE, and so does a
 * process with no role checker installed: a good signature says who wrote
 * the post, never that this box agreed to keep it. */
enum fleet_board_result db_fleet_board_post_ingest(
    struct node_db *ndb, const struct fleet_board_post *post, int64_t now,
    bool *stored_out);

enum fleet_board_wiki_write_status {
    FLEET_WIKI_WRITE_OK, FLEET_WIKI_WRITE_REPLAY,
    FLEET_WIKI_WRITE_ARGS, FLEET_WIKI_WRITE_CONFLICT,
    FLEET_WIKI_WRITE_CORRUPT, FLEET_WIKI_WRITE_COLLISION,
    FLEET_WIKI_WRITE_CLOCK, FLEET_WIKI_WRITE_BUSY,
    FLEET_WIKI_WRITE_STORAGE, FLEET_WIKI_WRITE_REFUSED,
};
/* Atomically compare this receiver's strict newest retained slug revision
 * across local authors, then append through the canonical AR writer. NULL
 * expected means absent; otherwise it names the exact parent. Receipt is a
 * caller-bound request marker. A retained exact-payload replay returns its
 * signed object even after supersession; eviction ends this bounded replay
 * claim. Corrupt/ambiguous retained rows refuse, never fall back to an older
 * head. Caller admission and signing remain composition responsibilities. */
enum fleet_board_wiki_write_status db_fleet_board_wiki_write(
    struct node_db *ndb, const struct fleet_board_post *post,
    const uint8_t *expected, int64_t now, struct db_fleet_board_post *out,
    enum fleet_board_result *refusal);

/* What one reclaim pass did. DEFERRED is not a failure: the pass owns the
 * whole transaction it needs, so finding somebody else's already open means
 * "not this tick" — an ordinary race with the node's own writers, and the
 * next tick finds the work still there. A caller that counts DEFERRED as a
 * failure reports a node as permanently unhealthy for doing the right
 * thing. */
enum fleet_board_reclaim {
    FLEET_BOARD_RECLAIM_DONE = 0,      /* ran; `removed_out` says how many */
    FLEET_BOARD_RECLAIM_DEFERRED = 1,  /* a transaction was open; try later */
    FLEET_BOARD_RECLAIM_FAILED = 2,    /* a leg failed; nothing changed */
};

/* Maintenance reclaim: physically remove every reclaimable row and
 * re-seq/re-chain the survivors, in ONE transaction under the board write
 * lock. `removed_out` (optional) receives the number of rows taken back.
 * A row is reclaimable when its TTL has run out, it is not durable wiki
 * history, and it arrived longer ago than
 * FLEET_BOARD_PUBLIC_QUOTA_WINDOW_SECONDS — the window leg counts arrivals
 * regardless of TTL, so taking a row back while its own window is still
 * open would hand the key that slot twice and lift the burst ceiling.
 * Nothing changes unless the pass returns DONE.
 *
 * This is the separately bounded maintenance path the store reserves, and
 * it is the physical half of the per-key quota above: the resident ceiling
 * counts STORED rows, and this is what hands a key its slots back once the
 * posts holding them are dead. Peer ingress never reaches this expiry
 * reclaim: its only caller is the local db_maintenance scheduler, as the op
 * "board-reclaim". Ingress can cause exactly one other deletion: an accepted
 * wiki revision from a key at its stored wiki ceiling removes that same
 * key's own oldest superseded revision and relinks only the rows stored
 * after it (bounded by the per-key wiki window and by
 * FLEET_BOARD_WIKI_EVICT_MAX replacements per FLEET_BOARD_WIKI_EVICT_SECONDS
 * node-wide). Survivors keep their arrival order: seq becomes 1..n in
 * that order and the chain is rebuilt from genesis over them, which is
 * exactly what db_fleet_board_chain_verify walks, unchanged. */
enum fleet_board_reclaim db_fleet_board_reclaim_expired(
    struct node_db *ndb, int64_t now, int64_t *removed_out);

/* Exact-id lookup. Returns false when the id is unknown. */
bool db_fleet_board_post_find(struct node_db *ndb, const uint8_t id[32],
                              struct db_fleet_board_post *out);

/* Newest-first listing under `filter`. Returns the number written, at most
 * `max` (capped at FLEET_BOARD_LIST_MAX). Expired discussions are excluded;
 * durable wiki revisions remain discoverable.
 *
 * `*complete` (optional) is true only when the query was prepared, every
 * row it matched was read and the cursor ended cleanly: a table that cannot
 * be read, a step that fails part-way and a stored row that no longer
 * decodes all leave it false, so a caller that must not mistake "I could
 * not look" for "nothing there" can tell. The rows written are still those
 * that did read. */
int db_fleet_board_list_checked(struct node_db *ndb,
                                const struct fleet_board_filter *filter,
                                int64_t now, struct db_fleet_board_post *out,
                                size_t max, bool *complete);

/* The listing for a caller that has no use for the difference. */
static inline int db_fleet_board_list(
    struct node_db *ndb, const struct fleet_board_filter *filter, int64_t now,
    struct db_fleet_board_post *out, size_t max)
{
    return db_fleet_board_list_checked(ndb, filter, now, out, max, NULL);
}

/* Latest valid revision of one wiki slug: the newest created_at among that
 * slug's stored revisions, ties broken by the larger id, so every node that
 * holds the same revisions resolves the same page. */
bool db_fleet_board_wiki_read(struct node_db *ndb, const char *slug,
                              struct db_fleet_board_post *out);


/* db_fleet_board_wiki_read with the same newest-verifying rule, bounded to
 * FLEET_BOARD_LIST_MAX revision verifications. *newer_unverified is set when
 * a newer stored revision of the slug failed verification and an older one
 * is returned instead. */
bool db_fleet_board_wiki_read_checked(struct node_db *ndb, const char *slug,
                                      struct db_fleet_board_post *out,
                                      bool *newer_unverified);

enum fleet_wiki_query_status {
    FLEET_WIKI_QUERY_DONE, FLEET_WIKI_QUERY_PAGE,
    FLEET_WIKI_QUERY_VERIFY_BUDGET, FLEET_WIKI_QUERY_STORAGE,
    FLEET_WIKI_QUERY_VISITOR_FAILED
};
struct fleet_wiki_query_progress {
    enum fleet_wiki_query_status status;
    unsigned scanned, verified;
    char after_slug[FLEET_BOARD_SLUG_MAX + 1];
    char blocked_slug[FLEET_BOARD_SLUG_MAX + 1];
};
enum fleet_wiki_visit_result { FLEET_WIKI_VISIT_CONTINUE,
    FLEET_WIKI_VISIT_PAGE, FLEET_WIKI_VISIT_FAILED };
typedef enum fleet_wiki_visit_result (*fleet_wiki_visit_fn)(void *,
    const struct db_fleet_board_post *);

/* PAGE stops before an unaccepted slug. after_slug is the last fully examined
 * slug (exclusive); scanned counts completed slugs, verified counts attempted
 * revision checks including corrupt rows. VERIFY_BUDGET leaves blocked_slug
 * unresolved and must not skip it or claim absence. Repeating unchanged input
 * need not progress; the separate exact slug read has its existing contract.
 * Observations are latest-held, not a snapshot or global completeness proof. */
bool db_fleet_board_wiki_query(struct node_db *, const char *after_slug,
    fleet_wiki_visit_fn, void *, struct fleet_wiki_query_progress *);


/* One row per slug: the latest revision of the first max pages. Pages past
 * max are reached with db_fleet_board_wiki_list_after. */
int db_fleet_board_wiki_list(struct node_db *ndb,
                             struct db_fleet_board_post *out, size_t max);

/* Up to max pages whose slug sorts after `after` (exclusive; empty starts at
 * the first), in slug order. *last_scanned is the last slug examined, even
 * when its revisions all failed verification and it wrote no row; resume
 * from it. *more is set when a later slug exists. Returns rows written, or
 * -1 when the store could not be read (never a short list). */
int db_fleet_board_wiki_list_after(struct node_db *ndb, const char *after,
    struct db_fleet_board_post *out, size_t max,
    char last_scanned[FLEET_BOARD_SLUG_MAX + 1], bool *more);

/* Every revision of one slug, newest first. */
int db_fleet_board_wiki_history(struct node_db *ndb, const char *slug,
                                struct db_fleet_board_post *out, size_t max);

bool db_fleet_board_status(struct node_db *ndb, int64_t now,
                           struct fleet_board_status *out);

/* The ids this node holds, newest first. public_only excludes fleet-scoped
 * rows; a PUBLIC gossip inventory is built with public_only=true so a
 * fleet-private post's id never leaves the node on the public path. */
int db_fleet_board_recent_ids(struct node_db *ndb, int64_t now,
                              bool public_only, uint8_t (*ids)[32],
                              size_t max);

/* One verified, unexpired inventory page in descending local arrival order.
 * before_seq=0 starts at the head; otherwise only seq<before_seq is eligible.
 * public_only excludes fleet-scoped rows: the public gossip inventory must
 * never reveal that a fleet-private post exists, so the announce path always
 * pages with public_only=true. last_seq_out is reset to zero and receives the
 * last returned sequence, which lets a caller advance to the next page.
 * Returns -1 on query or verification failure, 0 only at a verified end, and
 * otherwise the number of ids. */
int db_fleet_board_ids_before(struct node_db *ndb, int64_t now,
                              int64_t before_seq, bool public_only,
                              uint8_t (*ids)[32], size_t max,
                              int64_t *last_seq_out);

bool db_fleet_board_have(struct node_db *ndb, const uint8_t id[32]);

/* One row handed to a page visitor. Return false to stop the page there;
 * that row is then NOT counted as visited. The row is borrowed for the
 * call only. */
typedef bool (*db_fleet_board_row_visit)(const struct db_fleet_board_post *row,
                                         void *ctx);

/* The FLEET-scope page the paired pull service serves: at most `limit`
 * still-discoverable fleet-scoped rows with arrival > after_arrival, in
 * ascending arrival order, read through the arrival index — so one page
 * costs at most `limit` row reads and signature checks however large the
 * store is. Start from 0. Public and legacy rows never appear.
 *
 * `*scanned_out` is the arrival of the last row this page consumed, or
 * after_arrival when it consumed none: every row at or below it was either
 * handed to the visitor or failed read verification (logged, never handed
 * on, and never going to verify later). A row the visitor refused is not
 * consumed, so the page stops there and the next one starts at it.
 * Returns the number of rows the visitor accepted, or -1 when the store
 * could not be read. */
int db_fleet_board_fleet_after(struct node_db *ndb, int64_t now,
                               int64_t after_arrival, unsigned limit,
                               db_fleet_board_row_visit visit, void *ctx,
                               int64_t *scanned_out);

/* Every distinct key that signed a post this node is storing, newest post
 * first, capped at FLEET_BOARD_HOST_LIST_MAX. A key appears only when at
 * least one of its stored posts still verifies here, so a tampered row
 * cannot put a key on the list. Returns the count written, or -1 when the
 * store could not be read. This is what the role bootstrap asks: these are
 * the keys this node has ALREADY been accepting posts from.
 * `truncated` (optional) is set when a distinct key past `max` exists:
 * the list is then a PREFIX, and the caller must say so rather than
 * act as though it saw every key.
 * Expiry is not applied — the question is who was trusted, not what is
 * still worth reading. */
int db_fleet_board_distinct_hosts(struct node_db *ndb, uint8_t (*out)[32],
                                  size_t max, bool *truncated);

/* The distinct rooms a public reader can reach, for the read-only /board
 * pages: every room named by a non-fleet post, with legacy rows' empty
 * signed room reported as the default room. Fleet-scoped posts never
 * appear — even a room index must not reveal that they exist. Returns the
 * number of rooms written, at most `max` (capped at 64). */
int db_fleet_board_room_list(struct node_db *ndb,
                             char (*rooms)[FLEET_BOARD_ROOM_MAX + 1],
                             size_t max);

/* Re-walk the stored chain in seq order and confirm every chain_hash is the
 * step its predecessor implies. Local integrity only. */
bool db_fleet_board_chain_verify(struct node_db *ndb, int64_t *checked_out);

struct json_value;

#ifdef ZCL_TESTING
/* Narrow capacity seam for adversarial store tests. Production always uses
 * FLEET_BOARD_STORE_MAX_{POSTS,BYTES}; zero restores those defaults. */
void db_fleet_board_test_set_store_limits(int64_t max_posts,
                                          int64_t max_bytes);
/* Wiki ceilings for tests that need a small stored bound; zero restores the
 * FLEET_BOARD_WIKI_QUOTA_* defaults. */
void db_fleet_board_test_set_wiki_limits(int64_t window_max,
                                         int64_t stored_max);
/* Forgets the node-wide replacement history. */
void db_fleet_board_test_reset_wiki_evictions(void);
/* Empties the permanent-refusal quarantine so one group's poisoned post does
 * not follow the process into the next group. */
void db_fleet_board_test_clear_quarantine(void);
#endif

/* Review admission and reads use the existing signed WIKI ledger. Local check
 * runs inside the caller's write transaction; peer ingest permits unresolved
 * targets but never inconsistent signed body/ref bindings. */
bool fleet_board_review_shape(const struct fleet_board_post *);
enum fleet_board_result db_fleet_board_review_local_check(
    struct node_db *, const struct fleet_board_post *);
bool db_fleet_board_wiki_reviews(struct node_db *, const uint8_t target[32],
    const uint8_t after[32], struct db_fleet_board_post *, size_t,
    size_t *, uint8_t next[32], bool *);
struct fleet_wiki_review_state {
    unsigned graph_verified;
    bool resolved, lineage_valid, current, fork, complete;
};
bool db_fleet_board_review_state(struct node_db *,
    const struct fleet_board_post *, struct fleet_wiki_review_state *);

#endif /* ZCL_DB_MODEL_FLEET_BOARD_POST_H */
