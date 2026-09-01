/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * zdesc_swarm — implementation. See vcs/zdesc_swarm.h for the shape,
 * the period-addressing consequence, the open edge, and the
 * verification status.
 *
 * Everything here is an adapter over primitives that already exist:
 * zid/zdesc.h for the codec and the signature, vcs/blob_store.h for
 * content-addressed transport. No new wire message, no new bound. */

#include "vcs/zdesc_swarm.h"

#include "vcs/blob_store.h"

#include "base/log_macros.h"

#include <pthread.h>
#include <string.h>

#define ZDS_LOG "vcs.zdesc"

const char *zdesc_result_string(enum zdesc_result r)
{
    switch (r) {
    case ZDESC_OK:               return "ok";
    case ZDESC_ERR_NULL:         return "null-argument";
    case ZDESC_ERR_ONION:        return "not-a-v3-onion";
    case ZDESC_ERR_ENCODE:       return "body-encode-failed";
    case ZDESC_ERR_SIGN:         return "sign-refused";
    case ZDESC_ERR_BLOB:         return "blob-refused";
    case ZDESC_ERR_ABSENT:       return "no-local-witness";
    case ZDESC_ERR_DECODE:       return "doc-decode-failed";
    case ZDESC_ERR_VERIFY:       return "verify-failed";
    case ZDESC_ERR_BODY:         return "not-a-zidd-body";
    case ZDESC_ERR_KEY_MISMATCH: return "signed-by-another-identity";
    case ZDESC_ERR_STALE:        return "seq-does-not-supersede";
    case ZDESC_ERR_FULL:         return "directory-full";
    case ZDESC_ERR_FETCH:        return "swarm-refused";
    }
    return "unknown";
}

/* One lock for every directory this module touches. Directories are
 * plain caller-owned structs (tests own theirs), but the global one is
 * read from the net discovery path and written from command handlers,
 * so the lock is unconditional and the internals below are the
 * already-locked bodies. */
static pthread_mutex_t g_dir_lock = PTHREAD_MUTEX_INITIALIZER;

static struct zdesc_directory g_dir;
static bool g_dir_ready;

/* ── directory internals (caller holds g_dir_lock) ─────────────────── */

static void dir_init_locked(struct zdesc_directory *dir)
{
    memset(dir, 0, sizeof(*dir));
}

static const struct zdesc_entry *dir_by_key_locked(
    const struct zdesc_directory *dir, const uint8_t record_key[32])
{
    for (size_t i = 0; i < ZDESC_DIR_MAX; i++) {
        if (dir->e[i].used &&
            memcmp(dir->e[i].record_key, record_key, 32) == 0)
            return &dir->e[i];
    }
    return NULL;
}

static struct zdesc_entry *dir_by_pubkey_locked(struct zdesc_directory *dir,
                                                const uint8_t pk[32])
{
    for (size_t i = 0; i < ZDESC_DIR_MAX; i++) {
        if (dir->e[i].used && memcmp(dir->e[i].master_pubkey, pk, 32) == 0)
            return &dir->e[i];
    }
    return NULL;
}

static size_t dir_onions_locked(const struct zdesc_directory *dir,
                                uint64_t now_unix,
                                char out[][ZDESC_ONION_LEN + 1], size_t max)
{
    size_t n = 0;
    for (size_t i = 0; i < ZDESC_DIR_MAX && n < max; i++) {
        const struct zdesc_entry *e = &dir->e[i];
        if (!e->used)
            continue;
        /* The doc's own signed window decides, not the period: an entry
         * whose window has closed is not a peer. */
        if (now_unix < e->desc.not_before || now_unix >= e->doc.expiry)
            continue;
        memcpy(out[n], e->desc.onion, ZDESC_ONION_LEN + 1);
        n++;
    }
    return n;
}

/* Install a verified doc as the identity's current descriptor. Assumes
 * the seq rule has already been checked against the existing entry. */
static enum zdesc_result dir_install_locked(struct zdesc_directory *dir,
                                            const uint8_t pk[32],
                                            const uint8_t record_key[32],
                                            uint64_t period,
                                            const uint8_t root[32],
                                            const struct zid_doc *doc,
                                            const struct zdesc *desc)
{
    struct zdesc_entry *e = dir_by_pubkey_locked(dir, pk);
    if (!e) {
        for (size_t i = 0; i < ZDESC_DIR_MAX; i++) {
            if (!dir->e[i].used) {
                e = &dir->e[i];
                break;
            }
        }
        if (!e)
            LOG_RETURN(ZDESC_ERR_FULL, ZDS_LOG,
                       "descriptor directory is full (%d identities)",
                       ZDESC_DIR_MAX);
        dir->count++;
    }
    e->used = true;
    memcpy(e->record_key, record_key, 32);
    e->period = period;
    memcpy(e->master_pubkey, pk, 32);
    memcpy(e->root, root, 32);
    e->doc = *doc;
    e->desc = *desc;
    return ZDESC_OK;
}

/* ── the verify pipeline (the ONE place a key is decided) ───────────
 *
 * Decode the wire, check whose key signed it, verify signature +
 * validity window, and decode the ZIDD body. Every entry point in this
 * file funnels through here, so there is exactly one call site that
 * decides which key a descriptor is checked against. */
static enum zdesc_result zdesc_check_wire(const uint8_t *wire,
                                          size_t wire_len,
                                          const uint8_t master_pubkey[32],
                                          uint64_t now_unix,
                                          struct zid_doc *doc_out,
                                          struct zdesc *desc_out)
{
    struct zid_doc doc;
    if (!zid_doc_decode(&doc, wire, wire_len))
        LOG_RETURN(ZDESC_ERR_DECODE, ZDS_LOG,
                   "descriptor bytes are not a well-formed zid doc (%zu bytes)",
                   wire_len);

    /* ── CHAIN-BINDING SEAM — OPEN ─────────────────────────────────
     * master_pubkey is CALLER-SUPPLIED. Nothing in this file consults
     * the chain, so a descriptor accepted here is "signed by the key
     * you handed me", NOT "signed by a chain-anchored key".
     *
     * The single call site that closes this is the check immediately
     * below: replace the caller-supplied key with the result of
     *     db_zid_identity_find(master_pubkey) -> {anchored, height,
     *                                             status}
     * and refuse unless anchored is true and status is active. That
     * lookup is being built in another worktree, does not exist in
     * this tree, and is deliberately NOT stubbed, faked, or hardcoded
     * here. Until it lands, every user-visible surface built on this
     * file must say "verified against the supplied master key — not
     * chain-anchored". */
    if (memcmp(doc.master_pubkey, master_pubkey, 32) != 0)
        LOG_RETURN(ZDESC_ERR_KEY_MISMATCH, ZDS_LOG,
                   "descriptor is signed by a different identity than the "
                   "key supplied");

    struct zdesc desc;
    if (!zdesc_verify(&doc, &desc, now_unix)) {
        /* Separate "the signature/window failed" from "the signature
         * held but the body is not a descriptor" — a verifier that
         * conflates them cannot tell tampering from a wrong doc type. */
        if (!zid_doc_verify(&doc, now_unix))
            LOG_RETURN(ZDESC_ERR_VERIFY, ZDS_LOG,
                       "descriptor signature or validity window failed at "
                       "now=%llu", (unsigned long long)now_unix);
        LOG_RETURN(ZDESC_ERR_BODY, ZDS_LOG,
                   "doc verified but its body is not a ZIDD descriptor "
                   "(or the window has not opened)");
    }

    if (doc_out)
        *doc_out = doc;
    if (desc_out)
        *desc_out = desc;
    return ZDESC_OK;
}

/* ── public directory accessors ────────────────────────────────────── */

void zdesc_directory_init(struct zdesc_directory *dir)
{
    if (!dir) {
        LOG_ERROR(ZDS_LOG, "directory_init: NULL directory");
        return;
    }
    pthread_mutex_lock(&g_dir_lock);
    dir_init_locked(dir);
    pthread_mutex_unlock(&g_dir_lock);
}

bool zdesc_directory_lookup(const struct zdesc_directory *dir,
                            const uint8_t record_key[32],
                            const struct zdesc_entry **out)
{
    if (!dir || !record_key)
        LOG_FAIL(ZDS_LOG, "directory_lookup: NULL argument");
    pthread_mutex_lock(&g_dir_lock);
    const struct zdesc_entry *e = dir_by_key_locked(dir, record_key);
    if (e && out)
        *out = e;
    pthread_mutex_unlock(&g_dir_lock);
    return e != NULL;
}

bool zdesc_directory_find(const struct zdesc_directory *dir,
                          const uint8_t master_pubkey[32],
                          const struct zdesc_entry **out)
{
    if (!dir || !master_pubkey)
        LOG_FAIL(ZDS_LOG, "directory_find: NULL argument");
    pthread_mutex_lock(&g_dir_lock);
    struct zdesc_entry *e =
        dir_by_pubkey_locked((struct zdesc_directory *)dir, master_pubkey);
    if (e && out)
        *out = e;
    pthread_mutex_unlock(&g_dir_lock);
    return e != NULL;
}

size_t zdesc_directory_onions(const struct zdesc_directory *dir,
                              uint64_t now_unix,
                              char out[][ZDESC_ONION_LEN + 1], size_t max)
{
    if (!dir || !out || max == 0)
        LOG_RETURN(0, ZDS_LOG,
                   "directory_onions: NULL argument or zero capacity");
    pthread_mutex_lock(&g_dir_lock);
    size_t n = dir_onions_locked(dir, now_unix, out, max);
    pthread_mutex_unlock(&g_dir_lock);
    return n;
}

struct zdesc_directory *zdesc_directory_global(void)
{
    pthread_mutex_lock(&g_dir_lock);
    if (!g_dir_ready) {
        dir_init_locked(&g_dir);
        g_dir_ready = true;
    }
    pthread_mutex_unlock(&g_dir_lock);
    return &g_dir;
}

size_t zdesc_global_onions(uint64_t now_unix,
                           char out[][ZDESC_ONION_LEN + 1], size_t max)
{
    if (!out || max == 0)
        LOG_RETURN(0, ZDS_LOG, "global_onions: NULL out or zero capacity");
    pthread_mutex_lock(&g_dir_lock);
    size_t n = g_dir_ready ? dir_onions_locked(&g_dir, now_unix, out, max) : 0;
    pthread_mutex_unlock(&g_dir_lock);
    return n;
}

/* ── publish ───────────────────────────────────────────────────────── */

enum zdesc_result zdesc_publish_to(struct vcs_package_store *store,
                                   struct zdesc_directory *dir,
                                   const struct zdesc *desc, uint64_t seq,
                                   uint64_t expiry, const uint8_t seed[32],
                                   uint64_t now_unix, uint8_t out_root[32],
                                   uint8_t out_pubkey[32])
{
    if (!store || !dir || !desc || !seed)
        LOG_RETURN(ZDESC_ERR_NULL, ZDS_LOG,
                   "publish: NULL argument (store=%p dir=%p desc=%p seed=%p)",
                   (void *)store, (void *)dir, (const void *)desc,
                   (const void *)seed);
    if (!zdesc_onion_valid(desc->onion))
        LOG_RETURN(ZDESC_ERR_ONION, ZDS_LOG,
                   "publish: service hostname is not a v3 onion");

    struct zid_doc doc;
    if (!zdesc_sign(&doc, desc, seq, expiry, seed))
        LOG_RETURN(ZDESC_ERR_SIGN, ZDS_LOG,
                   "publish: sign refused (bad validity window, bad "
                   "introduction point, or bad seed)");

    uint8_t wire[ZID_DOC_MAX];
    size_t wire_len = zid_doc_encode(wire, sizeof(wire), &doc);
    if (wire_len == 0)
        LOG_RETURN(ZDESC_ERR_ENCODE, ZDS_LOG, "publish: doc encode failed");

    uint64_t period = zdesc_period_at(now_unix);
    uint8_t record_key[32];
    zdesc_record_key(record_key, doc.master_pubkey, period);

    /* Monotonic FIRST, so a stale republish never reaches the store.
     * The seq rule is the whole replay defence; enforcing it after the
     * write would leave a superseded doc addressable. */
    pthread_mutex_lock(&g_dir_lock);
    const struct zdesc_entry *cur =
        dir_by_pubkey_locked(dir, doc.master_pubkey);
    bool stale = cur && !zid_doc_supersedes(&doc, &cur->doc);
    uint64_t cur_seq = cur ? cur->doc.seq : 0;
    pthread_mutex_unlock(&g_dir_lock);
    if (stale)
        LOG_RETURN(ZDESC_ERR_STALE, ZDS_LOG,
                   "publish: seq %llu does not supersede the held seq %llu "
                   "— rotation requires a strictly higher seq",
                   (unsigned long long)doc.seq, (unsigned long long)cur_seq);

    uint8_t root[32];
    enum vcs_blob_result br = vcs_blob_put_to(store, wire, wire_len, root);
    if (br != VCS_BLOB_OK)
        LOG_RETURN(ZDESC_ERR_BLOB, ZDS_LOG, "publish: blob put refused: %s",
                   vcs_blob_result_string(br));

    pthread_mutex_lock(&g_dir_lock);
    enum zdesc_result r = dir_install_locked(dir, doc.master_pubkey,
                                             record_key, period, root, &doc,
                                             desc);
    pthread_mutex_unlock(&g_dir_lock);
    if (r != ZDESC_OK)
        return r;

    if (out_root)
        memcpy(out_root, root, 32);
    if (out_pubkey)
        memcpy(out_pubkey, doc.master_pubkey, 32);
    return ZDESC_OK;
}

/* ── accept ────────────────────────────────────────────────────────── */

enum zdesc_result zdesc_accept(struct zdesc_directory *dir,
                               const uint8_t master_pubkey[32],
                               const uint8_t *wire, size_t wire_len,
                               uint64_t now_unix, struct zdesc *desc_out)
{
    if (!dir || !master_pubkey || !wire)
        LOG_RETURN(ZDESC_ERR_NULL, ZDS_LOG,
                   "accept: NULL argument (dir=%p pk=%p wire=%p)",
                   (void *)dir, (const void *)master_pubkey,
                   (const void *)wire);

    struct zid_doc doc;
    struct zdesc desc;
    enum zdesc_result r = zdesc_check_wire(wire, wire_len, master_pubkey,
                                           now_unix, &doc, &desc);
    if (r != ZDESC_OK)
        return r;

    /* The root is the CONTENT's, never a claim: derive it from the same
     * bytes that just verified. */
    uint8_t root[32];
    enum vcs_blob_result br = vcs_blob_root_of(wire, wire_len, root);
    if (br != VCS_BLOB_OK)
        LOG_RETURN(ZDESC_ERR_BLOB, ZDS_LOG, "accept: blob root refused: %s",
                   vcs_blob_result_string(br));

    uint64_t period = zdesc_period_at(now_unix);
    uint8_t record_key[32];
    zdesc_record_key(record_key, doc.master_pubkey, period);

    pthread_mutex_lock(&g_dir_lock);
    const struct zdesc_entry *cur =
        dir_by_pubkey_locked(dir, doc.master_pubkey);
    if (cur && !zid_doc_supersedes(&doc, &cur->doc)) {
        uint64_t cur_seq = cur->doc.seq;
        pthread_mutex_unlock(&g_dir_lock);
        LOG_RETURN(ZDESC_ERR_STALE, ZDS_LOG,
                   "accept: replayed descriptor seq %llu does not supersede "
                   "the held seq %llu — directory unchanged",
                   (unsigned long long)doc.seq, (unsigned long long)cur_seq);
    }
    r = dir_install_locked(dir, doc.master_pubkey, record_key, period, root,
                           &doc, &desc);
    pthread_mutex_unlock(&g_dir_lock);
    if (r != ZDESC_OK)
        return r;

    if (desc_out)
        *desc_out = desc;
    return ZDESC_OK;
}

/* ── fetch ─────────────────────────────────────────────────────────── */

/* Resolve the entry addressable at now_unix: the current period first,
 * then the previous one. THE BOUNDARY RULE — a publisher a few seconds
 * the other side of midnight must still be findable, so this fallback
 * lives here and is never left to callers. Copies the entry out under
 * the lock so the caller never holds a pointer into the directory. */
static bool zdesc_resolve_locked(const struct zdesc_directory *dir,
                                 const uint8_t master_pubkey[32],
                                 uint64_t now_unix, struct zdesc_entry *out)
{
    uint64_t period = zdesc_period_at(now_unix);
    uint8_t key[32];
    zdesc_record_key(key, master_pubkey, period);
    const struct zdesc_entry *e = dir_by_key_locked(dir, key);
    if (!e) {
        zdesc_record_key(key, master_pubkey, zdesc_period_prev(period));
        e = dir_by_key_locked(dir, key);
    }
    if (!e)
        return false;
    *out = *e;
    return true;
}

enum zdesc_result zdesc_fetch_from(struct vcs_package_store *store,
                                   const struct zdesc_directory *dir,
                                   const uint8_t master_pubkey[32],
                                   uint64_t now_unix, struct zdesc *desc_out)
{
    if (!store || !dir || !master_pubkey)
        LOG_RETURN(ZDESC_ERR_NULL, ZDS_LOG,
                   "fetch: NULL argument (store=%p dir=%p pk=%p)",
                   (void *)store, (const void *)dir,
                   (const void *)master_pubkey);

    struct zdesc_entry entry;
    pthread_mutex_lock(&g_dir_lock);
    bool found = zdesc_resolve_locked(dir, master_pubkey, now_unix, &entry);
    pthread_mutex_unlock(&g_dir_lock);
    if (!found)
        LOG_RETURN(ZDESC_ERR_ABSENT, ZDS_LOG,
                   "fetch: no record addressable at period %llu or its "
                   "predecessor — the publisher must republish each period",
                   (unsigned long long)zdesc_period_at(now_unix));

    /* Re-read the bytes and re-run the WHOLE pipeline on what came off
     * disk. The directory is a projection; it is never the authority
     * for what a descriptor says. */
    uint8_t wire[ZID_DOC_MAX];
    size_t wire_len = 0;
    enum vcs_blob_result br =
        vcs_blob_get_from(store, entry.root, wire, sizeof(wire), &wire_len);
    if (br != VCS_BLOB_OK)
        LOG_RETURN(ZDESC_ERR_BLOB, ZDS_LOG, "fetch: blob get refused: %s",
                   vcs_blob_result_string(br));

    struct zdesc desc;
    enum zdesc_result r = zdesc_check_wire(wire, wire_len, master_pubkey,
                                           now_unix, NULL, &desc);
    if (r != ZDESC_OK)
        return r;
    if (desc_out)
        *desc_out = desc;
    return ZDESC_OK;
}

enum zdesc_result zdesc_swarm_fetch(struct vcs_swarm_engine *engine,
                                    const struct zdesc_directory *dir,
                                    const uint8_t master_pubkey[32],
                                    int64_t day, uint64_t now_unix)
{
    if (!engine || !dir || !master_pubkey)
        LOG_RETURN(ZDESC_ERR_NULL, ZDS_LOG,
                   "swarm_fetch: NULL argument (engine=%p dir=%p pk=%p)",
                   (void *)engine, (const void *)dir,
                   (const void *)master_pubkey);

    struct zdesc_entry entry;
    pthread_mutex_lock(&g_dir_lock);
    bool found = zdesc_resolve_locked(dir, master_pubkey, now_unix, &entry);
    pthread_mutex_unlock(&g_dir_lock);
    if (!found)
        /* THE OPEN EDGE, by name: we can derive the record key but have
         * no witness mapping it to a blob root. Distribution of that
         * mapping is not built in this slice. */
        LOG_RETURN(ZDESC_ERR_ABSENT, ZDS_LOG,
                   "swarm_fetch: no local witness maps this record key to a "
                   "blob root — the record_key->root mapping has no "
                   "distribution mechanism yet");

    enum vcs_blob_result br =
        vcs_blob_fetch_via(engine, entry.root, day, now_unix);
    if (br != VCS_BLOB_OK)
        LOG_RETURN(ZDESC_ERR_FETCH, ZDS_LOG, "swarm_fetch: refused: %s",
                   vcs_blob_result_string(br));
    return ZDESC_OK;
}
