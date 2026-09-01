/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * zendp_swarm — implementation. See vcs/zendp_swarm.h for the shape,
 * the chain-binding contract, the hint discipline, and the per-record
 * freshness rule.
 *
 * Everything here is an adapter over primitives that already exist:
 * zid/zendp.h for the codec and the signature, vcs/blob_store.h for
 * content-addressed transport, and a registered port for the on-chain
 * identity lookup. No new wire message, no new bound. */

#include "vcs/zendp_swarm.h"

#include "vcs/blob_store.h"

#include "base/log_macros.h"

#include <pthread.h>
#include <string.h>

#define ZEP_LOG "vcs.zendp"

const char *zendp_anchor_state_string(enum zendp_anchor_state s)
{
    switch (s) {
    case ZENDP_ANCHOR_UNKNOWN: return "unknown";
    case ZENDP_ANCHOR_ABSENT:  return "absent";
    case ZENDP_ANCHOR_ACTIVE:  return "active";
    case ZENDP_ANCHOR_ROTATED: return "rotated";
    case ZENDP_ANCHOR_REVOKED: return "revoked";
    }
    return "unknown";
}

const char *zendp_result_string(enum zendp_result r)
{
    switch (r) {
    case ZENDP_OK:                    return "ok";
    case ZENDP_ERR_NULL:              return "null-argument";
    case ZENDP_ERR_SHAPE:             return "record-shape-refused";
    case ZENDP_ERR_ENCODE:            return "encode-failed";
    case ZENDP_ERR_SIGN:              return "sign-refused";
    case ZENDP_ERR_WINDOW_TOO_LONG:   return "window-exceeds-maximum";
    case ZENDP_ERR_BLOB:              return "blob-refused";
    case ZENDP_ERR_ABSENT:            return "no-local-witness";
    case ZENDP_ERR_DECODE:            return "doc-decode-failed";
    case ZENDP_ERR_VERIFY:            return "verify-failed";
    case ZENDP_ERR_BODY:              return "not-a-zide-body";
    case ZENDP_ERR_KEY_MISMATCH:      return "signed-by-another-identity";
    case ZENDP_ERR_STALE:             return "seq-does-not-supersede";
    case ZENDP_ERR_FULL:              return "directory-full";
    case ZENDP_ERR_FETCH:             return "swarm-refused";
    case ZENDP_ERR_NO_ANCHOR_LOOKUP:  return "no-chain-lookup-registered";
    case ZENDP_ERR_ANCHOR_UNAVAILABLE:return "chain-lookup-unavailable";
    case ZENDP_ERR_NOT_ANCHORED:      return "key-not-anchored-on-chain";
    case ZENDP_ERR_ROTATED:           return "key-rotated-away";
    case ZENDP_ERR_REVOKED:           return "key-revoked";
    }
    return "unknown";
}

/* One lock for every directory this module touches, plus the port.
 * Directories are plain caller-owned structs (tests own theirs), but
 * the global one is read from the discovery path and written from
 * command handlers, so the lock is unconditional. */
static pthread_mutex_t g_lock = PTHREAD_MUTEX_INITIALIZER;

static struct zendp_directory g_dir;
static bool g_dir_ready;

static zendp_anchor_lookup_fn g_anchor_fn;
static void *g_anchor_ctx;

/* ── the chain-binding port ────────────────────────────────────────── */

void zendp_set_anchor_lookup(zendp_anchor_lookup_fn fn, void *ctx)
{
    pthread_mutex_lock(&g_lock);
    g_anchor_fn = fn;
    g_anchor_ctx = ctx;
    pthread_mutex_unlock(&g_lock);
}

bool zendp_anchor_lookup_registered(void)
{
    pthread_mutex_lock(&g_lock);
    bool have = g_anchor_fn != NULL;
    pthread_mutex_unlock(&g_lock);
    return have;
}

enum zendp_result zendp_anchor_check(const uint8_t master_pubkey[32],
                                     struct zendp_anchor *out)
{
    if (!master_pubkey)
        LOG_RETURN(ZENDP_ERR_NULL, ZEP_LOG, "anchor_check: NULL pubkey");

    pthread_mutex_lock(&g_lock);
    zendp_anchor_lookup_fn fn = g_anchor_fn;
    void *ctx = g_anchor_ctx;
    pthread_mutex_unlock(&g_lock);

    struct zendp_anchor a;
    memset(&a, 0, sizeof(a));

    if (!fn) {
        if (out)
            *out = a;
        /* FAIL CLOSED. "I could not ask the chain" must never be
         * reported as, or silently behave like, "the chain said yes". */
        LOG_RETURN(ZENDP_ERR_NO_ANCHOR_LOOKUP, ZEP_LOG,
                   "anchor_check: no on-chain identity lookup is registered "
                   "— refusing to treat an unchecked key as anchored");
    }
    if (!fn(ctx, master_pubkey, &a)) {
        memset(&a, 0, sizeof(a));
        if (out)
            *out = a;
        LOG_RETURN(ZENDP_ERR_ANCHOR_UNAVAILABLE, ZEP_LOG,
                   "anchor_check: the identity lookup could not run (node.db "
                   "unavailable or read failed)");
    }
    if (out)
        *out = a;

    switch (a.state) {
    case ZENDP_ANCHOR_ACTIVE:
        return ZENDP_OK;
    case ZENDP_ANCHOR_ROTATED:
        LOG_RETURN(ZENDP_ERR_ROTATED, ZEP_LOG,
                   "anchor_check: signing key was rotated away at height %d "
                   "(anchored at %d)", a.updated_height, a.anchor_height);
    case ZENDP_ANCHOR_REVOKED:
        LOG_RETURN(ZENDP_ERR_REVOKED, ZEP_LOG,
                   "anchor_check: signing key was revoked at height %d "
                   "(anchored at %d)", a.updated_height, a.anchor_height);
    case ZENDP_ANCHOR_ABSENT:
    case ZENDP_ANCHOR_UNKNOWN:
        break;
    }
    LOG_RETURN(ZENDP_ERR_NOT_ANCHORED, ZEP_LOG,
               "anchor_check: signing key has no on-chain anchor — a record "
               "signed by an unanchored key is not a peer hint");
}

/* ── directory internals (caller holds g_lock) ─────────────────────── */

static void dir_init_locked(struct zendp_directory *dir)
{
    memset(dir, 0, sizeof(*dir));
}

static const struct zendp_entry *dir_by_key_locked(
    const struct zendp_directory *dir, const uint8_t record_key[32])
{
    for (size_t i = 0; i < ZENDP_DIR_MAX; i++) {
        if (dir->e[i].used &&
            memcmp(dir->e[i].record_key, record_key, 32) == 0)
            return &dir->e[i];
    }
    return NULL;
}

static struct zendp_entry *dir_by_pubkey_locked(struct zendp_directory *dir,
                                                const uint8_t pk[32])
{
    for (size_t i = 0; i < ZENDP_DIR_MAX; i++) {
        if (dir->e[i].used && memcmp(dir->e[i].master_pubkey, pk, 32) == 0)
            return &dir->e[i];
    }
    return NULL;
}

static size_t dir_records_locked(const struct zendp_directory *dir,
                                 uint64_t now_unix,
                                 struct zendp_record_view *out, size_t max)
{
    size_t n = 0;
    for (size_t i = 0; i < ZENDP_DIR_MAX && n < max; i++) {
        const struct zendp_entry *e = &dir->e[i];
        if (!e->used)
            continue;
        /* Freshness is the record's OWN signed window — there is no
         * refresh heartbeat anywhere in this design. */
        if (now_unix < e->ep.not_before || now_unix >= e->doc.expiry)
            continue;
        /* And that window must be one this node would accept TODAY.
         * Re-checked on the read path, not just at acceptance: the
         * directory is a projection, so an entry installed by an older
         * build (or before this rule existed) must not outlive the rule
         * simply because it is already resident. No allocation, no I/O
         * — this runs on the shared supervisor tick runner. */
        if (zendp_window_check(e->ep.not_before, e->doc.expiry) !=
            ZENDP_WINDOW_OK)
            continue;
        /* And the chain's verdict, recorded at acceptance. Anything
         * short of ACTIVE is not projected to discovery. */
        if (e->anchor.state != ZENDP_ANCHOR_ACTIVE)
            continue;
        memcpy(out[n].master_pubkey, e->master_pubkey, 32);
        out[n].seq = e->doc.seq;
        out[n].expiry = e->doc.expiry;
        out[n].anchor_height = e->anchor.anchor_height;
        out[n].ep = e->ep;
        n++;
    }
    return n;
}

static enum zendp_result dir_install_locked(struct zendp_directory *dir,
                                            const uint8_t pk[32],
                                            const uint8_t record_key[32],
                                            uint64_t period,
                                            const uint8_t root[32],
                                            const struct zid_doc *doc,
                                            const struct zendp *ep,
                                            const struct zendp_anchor *anchor)
{
    struct zendp_entry *e = dir_by_pubkey_locked(dir, pk);
    if (!e) {
        for (size_t i = 0; i < ZENDP_DIR_MAX; i++) {
            if (!dir->e[i].used) {
                e = &dir->e[i];
                break;
            }
        }
        if (!e)
            LOG_RETURN(ZENDP_ERR_FULL, ZEP_LOG,
                       "endpoint directory is full (%d identities)",
                       ZENDP_DIR_MAX);
        dir->count++;
    }
    e->used = true;
    memcpy(e->record_key, record_key, 32);
    e->period = period;
    memcpy(e->master_pubkey, pk, 32);
    memcpy(e->root, root, 32);
    e->doc = *doc;
    e->ep = *ep;
    e->anchor = *anchor;
    return ZENDP_OK;
}

/* ── the verify pipeline (the ONE place a record is judged) ─────────
 *
 * Decode the wire, verify the signature and the validity window, decode
 * the ZIDE body, then ask the CHAIN about the key the doc carries. No
 * caller hands a key in: that is the difference between this file and
 * zdesc_swarm.c, and it is the whole point of the slice. */
static enum zendp_result zendp_check_wire(const uint8_t *wire,
                                          size_t wire_len,
                                          uint64_t now_unix,
                                          struct zid_doc *doc_out,
                                          struct zendp *ep_out,
                                          struct zendp_anchor *anchor_out)
{
    struct zid_doc doc;
    if (!zid_doc_decode(&doc, wire, wire_len))
        LOG_RETURN(ZENDP_ERR_DECODE, ZEP_LOG,
                   "record bytes are not a well-formed zid doc (%zu bytes)",
                   wire_len);

    struct zendp ep;
    if (!zendp_verify(&doc, &ep, now_unix)) {
        /* Separate "the signature/window failed" from "the signature
         * held but the body is not an endpoint record" — a verifier
         * that conflates them cannot tell tampering from a wrong doc
         * type. */
        if (!zid_doc_verify(&doc, now_unix))
            LOG_RETURN(ZENDP_ERR_VERIFY, ZEP_LOG,
                       "record signature or validity window failed at "
                       "now=%llu", (unsigned long long)now_unix);
        /* A third case, and it must not read as either of the two
         * above: the signature is GOOD and the body is a real ZIDE, but
         * the window it signed is longer than this node will honour.
         * The publisher can fix that; nobody can fix a bad signature. */
        struct zendp probe;
        if (zendp_decode_body(&probe, doc.body, doc.body_len) &&
            zendp_window_check(probe.not_before, doc.expiry) ==
                ZENDP_WINDOW_TOO_LONG)
            LOG_RETURN(ZENDP_ERR_WINDOW_TOO_LONG, ZEP_LOG,
                       "record refused — the signed window is %llu seconds "
                       "and the maximum is %llu (%llu days). The publisher "
                       "must re-sign with a nearer expiry: a longer promise "
                       "would keep advertising this key on a node that never "
                       "sees it revoked",
                       (unsigned long long)(doc.expiry - probe.not_before),
                       (unsigned long long)ZENDP_MAX_WINDOW_SECONDS,
                       (unsigned long long)(ZENDP_MAX_WINDOW_SECONDS / 86400u));
        LOG_RETURN(ZENDP_ERR_BODY, ZEP_LOG,
                   "doc verified but its body is not a ZIDE endpoint record "
                   "(or the window has not opened)");
    }

    /* ── CHAIN BINDING — CLOSED ────────────────────────────────────
     * The key is not supplied, it is resolved. Unanchored, rotated and
     * revoked each get their own named refusal so an operator can tell
     * "never registered" from "key retired" from "chain unreachable". */
    struct zendp_anchor anchor;
    enum zendp_result ar = zendp_anchor_check(doc.master_pubkey, &anchor);
    if (ar != ZENDP_OK)
        return ar;

    if (doc_out)
        *doc_out = doc;
    if (ep_out)
        *ep_out = ep;
    if (anchor_out)
        *anchor_out = anchor;
    return ZENDP_OK;
}

/* ── public directory accessors ────────────────────────────────────── */

void zendp_directory_init(struct zendp_directory *dir)
{
    if (!dir) {
        LOG_ERROR(ZEP_LOG, "directory_init: NULL directory");
        return;
    }
    pthread_mutex_lock(&g_lock);
    dir_init_locked(dir);
    pthread_mutex_unlock(&g_lock);
}

bool zendp_directory_lookup(const struct zendp_directory *dir,
                            const uint8_t record_key[32],
                            const struct zendp_entry **out)
{
    if (!dir || !record_key)
        LOG_FAIL(ZEP_LOG, "directory_lookup: NULL argument");
    pthread_mutex_lock(&g_lock);
    const struct zendp_entry *e = dir_by_key_locked(dir, record_key);
    if (e && out)
        *out = e;
    pthread_mutex_unlock(&g_lock);
    return e != NULL;
}

bool zendp_directory_find(const struct zendp_directory *dir,
                          const uint8_t master_pubkey[32],
                          const struct zendp_entry **out)
{
    if (!dir || !master_pubkey)
        LOG_FAIL(ZEP_LOG, "directory_find: NULL argument");
    pthread_mutex_lock(&g_lock);
    struct zendp_entry *e =
        dir_by_pubkey_locked((struct zendp_directory *)dir, master_pubkey);
    if (e && out)
        *out = e;
    pthread_mutex_unlock(&g_lock);
    return e != NULL;
}

size_t zendp_directory_records(const struct zendp_directory *dir,
                               uint64_t now_unix,
                               struct zendp_record_view *out, size_t max)
{
    if (!dir || !out || max == 0)
        LOG_RETURN(0, ZEP_LOG,
                   "directory_records: NULL argument or zero capacity");
    pthread_mutex_lock(&g_lock);
    size_t n = dir_records_locked(dir, now_unix, out, max);
    pthread_mutex_unlock(&g_lock);
    return n;
}

struct zendp_directory *zendp_directory_global(void)
{
    pthread_mutex_lock(&g_lock);
    if (!g_dir_ready) {
        dir_init_locked(&g_dir);
        g_dir_ready = true;
    }
    pthread_mutex_unlock(&g_lock);
    return &g_dir;
}

size_t zendp_global_records(uint64_t now_unix, struct zendp_record_view *out,
                            size_t max)
{
    if (!out || max == 0)
        LOG_RETURN(0, ZEP_LOG, "global_records: NULL out or zero capacity");
    pthread_mutex_lock(&g_lock);
    size_t n = g_dir_ready ? dir_records_locked(&g_dir, now_unix, out, max) : 0;
    pthread_mutex_unlock(&g_lock);
    return n;
}

/* ── revalidation ──────────────────────────────────────────────────── */

enum zendp_result zendp_directory_revalidate(struct zendp_directory *dir,
                                             struct zendp_revalidation *out)
{
    struct zendp_revalidation tally;
    memset(&tally, 0, sizeof(tally));
    if (out)
        *out = tally;
    if (!dir)
        LOG_RETURN(ZENDP_ERR_NULL, ZEP_LOG, "revalidate: NULL directory");

    /* Snapshot the held identities under the lock, then RELEASE it before
     * asking the chain about a single one of them.
     *
     * Two reasons, both fatal if ignored. First, zendp_anchor_check takes
     * g_lock itself to read the port, so holding it here is an immediate
     * self-deadlock on a non-recursive mutex. Second, and the one that
     * matters operationally: the lookup behind that port reads node.db and
     * can park for as long as the fold holds its write batch — 120-330 s at
     * tip on this chain. Holding g_lock across it would stall
     * zendp_global_records(), which IS the discovery projection and DOES run
     * on the shared supervisor tick runner. That is the exact shape that has
     * had this node SIGABRT'd by its own watchdog. */
    uint8_t keys[ZENDP_DIR_MAX][32];
    size_t n = 0;
    pthread_mutex_lock(&g_lock);
    for (size_t i = 0; i < ZENDP_DIR_MAX; i++) {
        if (dir->e[i].used)
            memcpy(keys[n++], dir->e[i].master_pubkey, 32);
    }
    pthread_mutex_unlock(&g_lock);

    enum zendp_result unanswered = ZENDP_OK;
    for (size_t i = 0; i < n; i++) {
        struct zendp_anchor a;
        /* NO LOCK HELD. This is the call that can block. */
        enum zendp_result r = zendp_anchor_check(keys[i], &a);
        if (r == ZENDP_ERR_NO_ANCHOR_LOOKUP ||
            r == ZENDP_ERR_ANCHOR_UNAVAILABLE) {
            tally.unavailable++;
            unanswered = r;
            continue;
        }
        tally.checked++;

        pthread_mutex_lock(&g_lock);
        /* Re-find rather than reuse an index: an accept may have landed
         * while the lock was down. */
        struct zendp_entry *e = dir_by_pubkey_locked(dir, keys[i]);
        if (e) {
            if (a.state == ZENDP_ANCHOR_ACTIVE) {
                e->anchor = a;
            } else {
                memset(e, 0, sizeof(*e));   /* used = false: no residue */
                if (dir->count > 0)
                    dir->count--;
                tally.dropped++;
            }
        }
        pthread_mutex_unlock(&g_lock);
    }

    if (tally.dropped > 0)
        LOG_INFO(ZEP_LOG,
                 "revalidate: dropped %d endpoint record(s) whose signing key "
                 "the chain no longer calls active — they stop being offered "
                 "to peer discovery immediately, without a restart "
                 "(%d checked, %d unavailable)",
                 tally.dropped, tally.checked, tally.unavailable);
    if (out)
        *out = tally;
    if (unanswered != ZENDP_OK)
        LOG_RETURN(unanswered, ZEP_LOG,
                   "revalidate: %d of %zu held identities could not be "
                   "resolved against the chain (%s) — those entries were left "
                   "untouched rather than dropped on a non-answer",
                   tally.unavailable, n, zendp_result_string(unanswered));
    return ZENDP_OK;
}

enum zendp_result zendp_global_revalidate(struct zendp_revalidation *out)
{
    return zendp_directory_revalidate(zendp_directory_global(), out);
}

/* ── publish ───────────────────────────────────────────────────────── */

enum zendp_result zendp_publish_to(struct vcs_package_store *store,
                                   struct zendp_directory *dir,
                                   const struct zendp *ep, uint64_t seq,
                                   uint64_t expiry, const uint8_t seed[32],
                                   uint64_t now_unix, uint8_t out_root[32],
                                   uint8_t out_pubkey[32])
{
    if (!store || !dir || !ep || !seed)
        LOG_RETURN(ZENDP_ERR_NULL, ZEP_LOG,
                   "publish: NULL argument (store=%p dir=%p ep=%p seed=%p)",
                   (void *)store, (void *)dir, (const void *)ep,
                   (const void *)seed);
    if (!zendp_valid(ep))
        LOG_RETURN(ZENDP_ERR_SHAPE, ZEP_LOG,
                   "publish: the record names no reachable endpoint or "
                   "carries a field its flags do not claim");

    /* Ask the window rule ITSELF (never a second copy of it) so the
     * refusal an operator sees names the actual cause. zendp_sign would
     * refuse this too — this is here only to keep "your window is too
     * long", which is fixable by re-signing, from arriving as the same
     * generic sign-refused as "your seed is unusable". */
    enum zendp_window w = zendp_window_check(ep->not_before, expiry);
    if (w == ZENDP_WINDOW_TOO_LONG)
        LOG_RETURN(ZENDP_ERR_WINDOW_TOO_LONG, ZEP_LOG,
                   "publish: refused — the signed window is %llu seconds and "
                   "the maximum is %llu (%llu days); re-sign with a nearer "
                   "expiry",
                   (unsigned long long)(expiry - ep->not_before),
                   (unsigned long long)ZENDP_MAX_WINDOW_SECONDS,
                   (unsigned long long)(ZENDP_MAX_WINDOW_SECONDS / 86400u));

    struct zid_doc doc;
    if (!zendp_sign(&doc, ep, seq, expiry, seed))
        LOG_RETURN(ZENDP_ERR_SIGN, ZEP_LOG,
                   "publish: sign refused (bad validity window or bad seed)");

    uint8_t wire[ZID_DOC_MAX];
    size_t wire_len = zid_doc_encode(wire, sizeof(wire), &doc);
    if (wire_len == 0)
        LOG_RETURN(ZENDP_ERR_ENCODE, ZEP_LOG, "publish: doc encode failed");

    uint64_t period = zdesc_period_at(now_unix);
    uint8_t record_key[32];
    zendp_record_key(record_key, doc.master_pubkey, period);

    /* Monotonic FIRST, so a stale republish never reaches the store. */
    pthread_mutex_lock(&g_lock);
    const struct zendp_entry *cur =
        dir_by_pubkey_locked(dir, doc.master_pubkey);
    bool stale = cur && !zid_doc_supersedes(&doc, &cur->doc);
    uint64_t cur_seq = cur ? cur->doc.seq : 0;
    pthread_mutex_unlock(&g_lock);
    if (stale)
        LOG_RETURN(ZENDP_ERR_STALE, ZEP_LOG,
                   "publish: seq %llu does not supersede the held seq %llu — "
                   "rotation requires a strictly higher seq",
                   (unsigned long long)doc.seq, (unsigned long long)cur_seq);

    /* The publisher's own key may not be anchored YET (the anchor
     * transaction can still be unconfirmed), so this is recorded, not
     * enforced. Only ACTIVE entries are ever projected to discovery, so
     * an unanchored self-publish is stored and addressable but never
     * offered to anyone as a peer hint. */
    struct zendp_anchor anchor;
    enum zendp_result ar = zendp_anchor_check(doc.master_pubkey, &anchor);
    if (ar != ZENDP_OK)
        LOG_WARN(ZEP_LOG,
                 "publish: signing key is not chain-active (%s) — the record "
                 "is stored but will not be projected to peer discovery",
                 zendp_result_string(ar));

    uint8_t root[32];
    enum vcs_blob_result br = vcs_blob_put_to(store, wire, wire_len, root);
    if (br != VCS_BLOB_OK)
        LOG_RETURN(ZENDP_ERR_BLOB, ZEP_LOG, "publish: blob put refused: %s",
                   vcs_blob_result_string(br));

    pthread_mutex_lock(&g_lock);
    enum zendp_result r = dir_install_locked(dir, doc.master_pubkey,
                                             record_key, period, root, &doc,
                                             ep, &anchor);
    pthread_mutex_unlock(&g_lock);
    if (r != ZENDP_OK)
        return r;

    if (out_root)
        memcpy(out_root, root, 32);
    if (out_pubkey)
        memcpy(out_pubkey, doc.master_pubkey, 32);
    return ZENDP_OK;
}

/* ── accept ────────────────────────────────────────────────────────── */

enum zendp_result zendp_accept(struct zendp_directory *dir,
                               const uint8_t *wire, size_t wire_len,
                               uint64_t now_unix, struct zendp *ep_out,
                               uint8_t pubkey_out[32])
{
    if (!dir || !wire)
        LOG_RETURN(ZENDP_ERR_NULL, ZEP_LOG,
                   "accept: NULL argument (dir=%p wire=%p)", (void *)dir,
                   (const void *)wire);

    struct zid_doc doc;
    struct zendp ep;
    struct zendp_anchor anchor;
    enum zendp_result r = zendp_check_wire(wire, wire_len, now_unix, &doc, &ep,
                                           &anchor);
    if (r != ZENDP_OK)
        return r;

    /* The root is the CONTENT's, never a claim: derive it from the same
     * bytes that just verified. */
    uint8_t root[32];
    enum vcs_blob_result br = vcs_blob_root_of(wire, wire_len, root);
    if (br != VCS_BLOB_OK)
        LOG_RETURN(ZENDP_ERR_BLOB, ZEP_LOG, "accept: blob root refused: %s",
                   vcs_blob_result_string(br));

    uint64_t period = zdesc_period_at(now_unix);
    uint8_t record_key[32];
    zendp_record_key(record_key, doc.master_pubkey, period);

    pthread_mutex_lock(&g_lock);
    const struct zendp_entry *cur =
        dir_by_pubkey_locked(dir, doc.master_pubkey);
    if (cur && !zid_doc_supersedes(&doc, &cur->doc)) {
        uint64_t cur_seq = cur->doc.seq;
        pthread_mutex_unlock(&g_lock);
        LOG_RETURN(ZENDP_ERR_STALE, ZEP_LOG,
                   "accept: replayed record seq %llu does not supersede the "
                   "held seq %llu — directory unchanged",
                   (unsigned long long)doc.seq, (unsigned long long)cur_seq);
    }
    r = dir_install_locked(dir, doc.master_pubkey, record_key, period, root,
                           &doc, &ep, &anchor);
    pthread_mutex_unlock(&g_lock);
    if (r != ZENDP_OK)
        return r;

    if (ep_out)
        *ep_out = ep;
    if (pubkey_out)
        memcpy(pubkey_out, doc.master_pubkey, 32);
    return ZENDP_OK;
}

/* ── fetch ─────────────────────────────────────────────────────────── */

/* Resolve the entry addressable at now_unix: the current period first,
 * then the previous one. THE BOUNDARY RULE — a publisher a few seconds
 * the other side of midnight must still be findable, so this fallback
 * lives here and is never left to callers. Copies the entry out under
 * the lock so the caller never holds a pointer into the directory. */
static bool zendp_resolve_locked(const struct zendp_directory *dir,
                                 const uint8_t master_pubkey[32],
                                 uint64_t now_unix, struct zendp_entry *out)
{
    uint64_t period = zdesc_period_at(now_unix);
    uint8_t key[32];
    zendp_record_key(key, master_pubkey, period);
    const struct zendp_entry *e = dir_by_key_locked(dir, key);
    if (!e) {
        zendp_record_key(key, master_pubkey, zdesc_period_prev(period));
        e = dir_by_key_locked(dir, key);
    }
    if (!e)
        return false;
    *out = *e;
    return true;
}

enum zendp_result zendp_fetch_from(struct vcs_package_store *store,
                                   const struct zendp_directory *dir,
                                   const uint8_t master_pubkey[32],
                                   uint64_t now_unix, struct zendp *ep_out)
{
    if (!store || !dir || !master_pubkey)
        LOG_RETURN(ZENDP_ERR_NULL, ZEP_LOG,
                   "fetch: NULL argument (store=%p dir=%p pk=%p)",
                   (void *)store, (const void *)dir,
                   (const void *)master_pubkey);

    struct zendp_entry entry;
    pthread_mutex_lock(&g_lock);
    bool found = zendp_resolve_locked(dir, master_pubkey, now_unix, &entry);
    pthread_mutex_unlock(&g_lock);
    if (!found)
        LOG_RETURN(ZENDP_ERR_ABSENT, ZEP_LOG,
                   "fetch: no record addressable at period %llu or its "
                   "predecessor — the publisher must republish each period",
                   (unsigned long long)zdesc_period_at(now_unix));

    /* Re-read the bytes and re-run the WHOLE pipeline on what came off
     * disk. The directory is a projection; it is never the authority
     * for what a record says. */
    uint8_t wire[ZID_DOC_MAX];
    size_t wire_len = 0;
    enum vcs_blob_result br =
        vcs_blob_get_from(store, entry.root, wire, sizeof(wire), &wire_len);
    if (br != VCS_BLOB_OK)
        LOG_RETURN(ZENDP_ERR_BLOB, ZEP_LOG, "fetch: blob get refused: %s",
                   vcs_blob_result_string(br));

    struct zid_doc doc;
    struct zendp ep;
    enum zendp_result r = zendp_check_wire(wire, wire_len, now_unix, &doc, &ep,
                                           NULL);
    if (r != ZENDP_OK)
        return r;

    /* The address we resolved and the key that signed the bytes must be
     * the same identity: a store that hands back another identity's
     * record at this address is a corrupt witness, not a resolution. */
    if (memcmp(doc.master_pubkey, master_pubkey, 32) != 0)
        LOG_RETURN(ZENDP_ERR_KEY_MISMATCH, ZEP_LOG,
                   "fetch: the record stored at this identity's address is "
                   "signed by a different identity");

    if (ep_out)
        *ep_out = ep;
    return ZENDP_OK;
}

enum zendp_result zendp_swarm_fetch(struct vcs_swarm_engine *engine,
                                    const struct zendp_directory *dir,
                                    const uint8_t master_pubkey[32],
                                    int64_t day, uint64_t now_unix)
{
    if (!engine || !dir || !master_pubkey)
        LOG_RETURN(ZENDP_ERR_NULL, ZEP_LOG,
                   "swarm_fetch: NULL argument (engine=%p dir=%p pk=%p)",
                   (void *)engine, (const void *)dir,
                   (const void *)master_pubkey);

    struct zendp_entry entry;
    pthread_mutex_lock(&g_lock);
    bool found = zendp_resolve_locked(dir, master_pubkey, now_unix, &entry);
    pthread_mutex_unlock(&g_lock);
    if (!found)
        LOG_RETURN(ZENDP_ERR_ABSENT, ZEP_LOG,
                   "swarm_fetch: no local witness maps this record key to a "
                   "blob root — the record_key->root mapping has no "
                   "distribution mechanism yet");

    enum vcs_blob_result br =
        vcs_blob_fetch_via(engine, entry.root, day, now_unix);
    if (br != VCS_BLOB_OK)
        LOG_RETURN(ZENDP_ERR_FETCH, ZEP_LOG, "swarm_fetch: refused: %s",
                   vcs_blob_result_string(br));
    return ZENDP_OK;
}
