/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Private broadcast of this wallet's own sends. See
 * services/wallet_private_relay.h for the contract and its limits. */

#include "services/wallet_private_relay.h"

#include "chain/chainparams.h"
#include "coins/coins_view.h"
#include "core/serialize.h"
#include "crypto/random_secret.h"
#include "net/connman.h"
#include "net/net.h"
#include "net/netaddr.h"
#include "net/tor_integration.h"
#include "platform/clock.h"
#include "util/authority_receipt.h"
#include "platform/file_stream.h"
#include "primitives/transaction.h"
#include "util/log_macros.h"
#include "validation/accept_to_mempool.h"
#include "validation/contextual_check_tx.h"
#include "validation/main_state.h"
#include "wallet/wallet.h"

#include <pthread.h>
#include <stdio.h>
#include <string.h>

#define WPR_PENDING_FILE "wallet_private_relay.pending"
#define WPR_PENDING_HEADER "# wallet_private_relay v1\n"

enum wpr_push_result {
    WPR_PUSH_OK,
    WPR_PUSH_NO_ROUTE,
    WPR_PUSH_NO_TX,
    WPR_PUSH_QUEUE_FAILED,
};

static int64_t wpr_default_now_ms(void)
{
    return clock_now_monotonic_ns() / 1000000;
}

static bool wpr_default_random(uint8_t *out, size_t n)
{
    return zcl_random_secret_bytes(out, n, "wallet_private_relay");
}

const char *wpr_state_name(enum wpr_state state)
{
    switch (state) {
    case WPR_WAITING_FOR_ROUTE: return "waiting_for_route";
    case WPR_EXPIRED: return "expired";
    case WPR_PREPARED:          return "preparing";
    case WPR_SCHEDULED:         return "scheduled";
    case WPR_SENT:              return "sent";
    case WPR_SEEN:              return "seen";
    }
    return "unknown";
}

const char *wpr_mode_name(enum wpr_mode mode)
{
    return mode == WPR_MODE_PRIVATE ? "private" : "public";
}

void wpr_init(struct wpr *r)
{
    memset(r, 0, sizeof(*r));
    zcl_mutex_init(&r->lock);
    tx_mempool_init(&r->pool, 0);
    r->mode = WPR_MODE_PUBLIC;
    r->now_ms = wpr_default_now_ms;
    r->random_bytes = wpr_default_random;
}

void wpr_free(struct wpr *r)
{
    tx_mempool_free(&r->pool);
}

static struct wpr g_wpr;
static pthread_once_t g_wpr_once = PTHREAD_ONCE_INIT;

static void wpr_global_init(void)
{
    wpr_init(&g_wpr);
}

struct wpr *wpr_global(void)
{
    pthread_once(&g_wpr_once, wpr_global_init);
    return &g_wpr;
}

void wpr_configure(struct wpr *r, enum wpr_mode mode,
                   const struct wpr_env *env)
{
    zcl_mutex_lock(&r->lock);
    r->mode = mode;
    if (env) {
        r->env = *env;
        r->datadir[0] = '\0';
        if (env->datadir)
            (void)snprintf(r->datadir, sizeof(r->datadir), "%s", env->datadir);
        r->env.datadir = r->datadir;
        r->pool.min_relay_fee = env->min_relay_fee;
    }
    zcl_mutex_unlock(&r->lock);
}

enum wpr_mode wpr_get_mode(struct wpr *r)
{
    zcl_mutex_lock(&r->lock);
    enum wpr_mode m = r->mode;
    zcl_mutex_unlock(&r->lock);
    return m;
}

struct tx_mempool *wpr_pool(struct wpr *r)
{
    return &r->pool;
}

/* ── peers ──────────────────────────────────────────────────────────── */

bool wpr_peer_eligible(const struct p2p_node *n)
{
    return !tor_integration_service_violated() && !n->inbound &&
           net_addr_is_tor(&n->addr.svc.addr) &&
           n->state >= PEER_HANDSHAKE_COMPLETE && !n->disconnect &&
           n->relay_txes;
}

size_t wpr_count_eligible_peers(struct connman *cm)
{
    if (!cm)
        return 0;
    size_t count = 0;
    zcl_mutex_lock(&cm->manager.cs_nodes);
    for (size_t i = 0; i < cm->manager.num_nodes; i++)
        if (wpr_peer_eligible(cm->manager.nodes[i]))
            count++;
    zcl_mutex_unlock(&cm->manager.cs_nodes);
    return count;
}

/* ── persistence ────────────────────────────────────────────────────── */

static bool wpr_pending_path(const struct wpr *r, char *out, size_t cap)
{
    if (!r->datadir[0])
        return false;
    int n = snprintf(out, cap, "%s/%s", r->datadir, WPR_PENDING_FILE);
    return n > 0 && (size_t)n < cap;
}

/* Caller holds r->lock. Records every transaction not yet seen back. */
static bool wpr_persist_locked(const struct wpr *r)
{
    char path[1100];
    if (!wpr_pending_path(r, path, sizeof(path)))
        return true;
    char buf[sizeof(WPR_PENDING_HEADER) + WPR_MAX_ENTRIES * 66];
    size_t len = 0;
    memcpy(buf, WPR_PENDING_HEADER, sizeof(WPR_PENDING_HEADER) - 1);
    len = sizeof(WPR_PENDING_HEADER) - 1;
    for (size_t i = 0; i < WPR_MAX_ENTRIES; i++) {
        const struct wpr_entry *e = &r->entries[i];
        if (!e->used || e->state == WPR_SEEN)
            continue;
        if (e->state == WPR_EXPIRED)
            buf[len++] = 'x';
        else if (e->handed)
            buf[len++] = 'a';
        uint256_get_hex(&e->txid, buf + len);
        len += 64;
        buf[len++] = '\n';
    }
    if (!authority_receipt_write_atomic(r->datadir, WPR_PENDING_FILE,
                                        (const uint8_t *)buf, len, NULL, 0)) {
        LOG_WARN("wallet_private_relay", "pending set write failed");
        return false;
    }
    return true;
}

static bool wpr_hex_line_valid(const char *s)
{
    for (size_t i = 0; i < 64; i++) {
        char c = s[i];
        bool hex = (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f');
        if (!hex)
            return false;
    }
    return s[64] == '\n' || s[64] == '\0';
}

static size_t wpr_read_pending(const struct wpr *r, struct uint256 *out,
                               bool *expired, bool *handed, size_t cap)
{
    char path[1100];
    if (!wpr_pending_path(r, path, sizeof(path)))
        return 0;
    FILE *fp = platform_file_stream_open_read(path);
    if (!fp)
        return 0;
    char buf[sizeof(WPR_PENDING_HEADER) + WPR_MAX_ENTRIES * 66 + 1];
    size_t len = fread(buf, 1, sizeof(buf) - 1, fp);
    fclose(fp);
    buf[len] = '\0';
    size_t n = 0;
    for (char *line = buf; *line && n < cap;) {
        char *end = strchr(line, '\n');
        size_t line_len = end ? (size_t)(end - line) : strlen(line);
        bool x = line_len == 65 && line[0] == 'x';
        bool a = line_len == 65 && line[0] == 'a';
        const char *id = (x || a) ? line + 1 : line;
        if ((line_len == 64 || x || a) && wpr_hex_line_valid(id)) {
            char hex[65];
            memcpy(hex, id, 64);
            hex[64] = '\0';
            expired[n] = x;
            handed[n] = a;
            uint256_set_hex(&out[n++], hex);
        }
        if (!end)
            break;
        line = end + 1;
    }
    return n;
}

/* ── scheduling ─────────────────────────────────────────────────────── */

static bool wpr_draw_delay_ms(struct wpr *r, int64_t *out)
{
    uint8_t raw[8];
    if (!r->random_bytes(raw, sizeof(raw)))
        return false;
    uint64_t v = 0;
    for (size_t i = 0; i < sizeof(raw); i++)
        v = (v << 8) | raw[i];
    const uint64_t span = (uint64_t)(WPR_DELAY_MAX_MS - WPR_DELAY_MIN_MS) + 1u;
    *out = WPR_DELAY_MIN_MS + (int64_t)(v % span);
    return true;
}

static struct wpr_entry *wpr_find_locked(struct wpr *r,
                                         const struct uint256 *txid)
{
    for (size_t i = 0; i < WPR_MAX_ENTRIES; i++)
        if (r->entries[i].used &&
            memcmp(r->entries[i].txid.data, txid->data, 32) == 0)
            return &r->entries[i];
    return NULL;
}

/* A free slot, reclaiming the oldest seen-back record when full, then the
 * oldest expired record. */
static struct wpr_entry *wpr_alloc_locked(struct wpr *r)
{
    struct wpr_entry *oldest_seen = NULL;
    for (size_t i = 0; i < WPR_MAX_ENTRIES; i++) {
        struct wpr_entry *e = &r->entries[i];
        if (!e->used)
            return e;
        bool terminal = e->state == WPR_SEEN || e->state == WPR_EXPIRED;
        if (terminal && (!oldest_seen ||
            (e->state == WPR_SEEN && oldest_seen->state == WPR_EXPIRED) ||
            (e->state == oldest_seen->state &&
             e->seen_ms < oldest_seen->seen_ms)))
            oldest_seen = e;
    }
    if (oldest_seen)
        memset(oldest_seen, 0, sizeof(*oldest_seen));
    return oldest_seen;
}

static void wpr_fill_entry(struct wpr_entry *e, const struct uint256 *txid,
                           const struct transaction *tx, int64_t due_ms,
                           bool in_pool)
{
    memset(e, 0, sizeof(*e));
    e->used = true;
    e->in_pool = in_pool;
    e->txid = *txid;
    e->has_expiry = tx->overwintered && tx->expiry_height > 0;
    e->expiry_height = tx->expiry_height;
    e->last_attempt_ms = -1;
    e->state = in_pool ? WPR_SCHEDULED : WPR_WAITING_FOR_ROUTE;
    e->due_ms = due_ms;
}

struct zcl_result wpr_prepare(struct wpr *r, const struct uint256 *txid)
{
    if (!r || !txid)
        return ZCL_ERR(-1, "private relay: NULL relay or transaction id");
    zcl_mutex_lock(&r->lock);
    if (wpr_find_locked(r, txid)) {
        zcl_mutex_unlock(&r->lock);
        return ZCL_OK;
    }
    struct wpr_entry *e = wpr_alloc_locked(r);
    if (!e) {
        zcl_mutex_unlock(&r->lock);
        return ZCL_ERR(-2, "private relay: pending queue is full");
    }
    memset(e, 0, sizeof(*e));
    e->used = true;
    e->txid = *txid;
    e->state = WPR_PREPARED;
    e->last_attempt_ms = -1;
    e->seen_ms = r->now_ms();
    if (!wpr_persist_locked(r)) {
        memset(e, 0, sizeof(*e));
        zcl_mutex_unlock(&r->lock);
        return ZCL_ERR(-4, "private relay: cannot record the pending set");
    }
    zcl_mutex_unlock(&r->lock);
    return ZCL_OK;
}

void wpr_mark_held(struct wpr *r, const struct uint256 *txid, bool held)
{
    if (!r || !txid)
        return;
    zcl_mutex_lock(&r->lock);
    struct wpr_entry *e = wpr_find_locked(r, txid);
    if (e)
        e->held = held;
    zcl_mutex_unlock(&r->lock);
}

void wpr_set_disk_retry(struct wpr *r, const struct uint256 *txid, bool on)
{
    if (!r || !txid)
        return;
    zcl_mutex_lock(&r->lock);
    struct wpr_entry *e = wpr_find_locked(r, txid);
    if (e)
        e->disk_retry = on;
    zcl_mutex_unlock(&r->lock);
}

bool wpr_disk_retry(struct wpr *r, const struct uint256 *txid)
{
    bool on = false;
    if (!r || !txid)
        return false;
    zcl_mutex_lock(&r->lock);
    struct wpr_entry *e = wpr_find_locked(r, txid);
    on = e && e->disk_retry;
    zcl_mutex_unlock(&r->lock);
    return on;
}

struct zcl_result wpr_enqueue(struct wpr *r, const struct transaction *tx)
{
    if (!r || !tx)
        return ZCL_ERR(-1, "private relay: NULL relay or transaction");
    zcl_mutex_lock(&r->lock);
    int64_t delay = 0;
    struct wpr_entry *e = wpr_find_locked(r, &tx->hash);
    if (e && e->state != WPR_PREPARED) {
        zcl_mutex_unlock(&r->lock);
        return ZCL_OK;
    }
    bool existed = e != NULL;
    struct wpr_entry saved;
    memset(&saved, 0, sizeof(saved));
    if (existed)
        saved = *e;
    if (!e)
        e = wpr_alloc_locked(r);
    if (!e) {
        zcl_mutex_unlock(&r->lock);
        return ZCL_ERR(-2, "private relay: pending queue is full");
    }
    if (!wpr_draw_delay_ms(r, &delay)) {
        zcl_mutex_unlock(&r->lock);
        return ZCL_ERR(-3, "private relay: random delay unavailable");
    }
    wpr_fill_entry(e, &tx->hash, tx, r->now_ms() + delay, true);
    if (!wpr_persist_locked(r)) {
        /* A recorded send stays recorded: the wallet may still hold it. */
        if (existed)
            *e = saved;
        else
            memset(e, 0, sizeof(*e));
        zcl_mutex_unlock(&r->lock);
        return ZCL_ERR(-4, "private relay: cannot record the pending set");
    }
    zcl_mutex_unlock(&r->lock);
    return ZCL_OK;
}

static void wpr_clear_locked(struct wpr *r, struct wpr_entry *e)
{
    tx_mempool_remove(&r->pool, &e->txid);
    memset(e, 0, sizeof(*e));
}

void wpr_note_seen(struct wpr *r, const struct uint256 *txid)
{
    if (!r || !txid)
        return;
    zcl_mutex_lock(&r->lock);
    struct wpr_entry *e = wpr_find_locked(r, txid);
    if (e && e->state != WPR_SEEN) {
        e->state = WPR_SEEN;
        e->seen_ms = r->now_ms();
        e->in_pool = false;
        e->mined = false;
        tx_mempool_remove(&r->pool, txid);
        (void)wpr_persist_locked(r);
    }
    zcl_mutex_unlock(&r->lock);
}

void wpr_mark_expired(struct wpr *r, const struct uint256 *txid)
{
    if (!r || !txid)
        return;
    zcl_mutex_lock(&r->lock);
    struct wpr_entry *e = wpr_find_locked(r, txid);
    if (e) {
        tx_mempool_remove(&r->pool, txid);
        e->state = WPR_EXPIRED;
        e->in_pool = false;
        e->expired = false;
        e->held = false;
        e->disk_retry = false;
        e->seen_ms = r->now_ms();
        (void)wpr_persist_locked(r);
    }
    zcl_mutex_unlock(&r->lock);
}

void wpr_forget(struct wpr *r, const struct uint256 *txid)
{
    if (!r || !txid)
        return;
    zcl_mutex_lock(&r->lock);
    struct wpr_entry *e = wpr_find_locked(r, txid);
    if (e) {
        wpr_clear_locked(r, e);
        (void)wpr_persist_locked(r);
    }
    zcl_mutex_unlock(&r->lock);
}

/* ── validation into the private pool ───────────────────────────────── */

static bool wpr_admit(struct wpr *r, struct transaction *tx)
{
    char detail[128];
    enum mempool_accept_result ar = accept_to_mempool_detailed(
        &r->pool, r->env.coins_tip, r->env.main_state, r->env.params, tx,
        detail, sizeof(detail));
    return ar == MEMPOOL_ACCEPT_OK || ar == MEMPOOL_ACCEPT_DUPLICATE;
}

/* An expired record from before the restart: kept for the status only. */
static void wpr_restore_expired(struct wpr *r, const struct uint256 *txid)
{
    zcl_mutex_lock(&r->lock);
    struct wpr_entry *e = wpr_find_locked(r, txid);
    if (!e)
        e = wpr_alloc_locked(r);
    if (e) {
        memset(e, 0, sizeof(*e));
        e->used = true;
        e->txid = *txid;
        e->state = WPR_EXPIRED;
        e->last_attempt_ms = -1;
        e->seen_ms = r->now_ms();
    }
    zcl_mutex_unlock(&r->lock);
}

/* Bring one recorded send back: the wallet's copy is revalidated into the
 * private pool and scheduled with a fresh delay. A send the wallet does not
 * hold is dropped from the record. Returns true when the wallet holds it. */
static bool wpr_resume_one(struct wpr *r, const struct uint256 *txid,
                            bool handed)
{
    struct wallet_tx wtx;
    memset(&wtx, 0, sizeof(wtx));
    if (!r->env.wallet || !wallet_get_tx_copy(r->env.wallet, txid, &wtx)) {
        wpr_forget(r, txid);  /* the wallet never admitted it, or lost it */
        return false;
    }
    if (r->env.reserve)
        r->env.reserve(&r->env, &wtx.tx);
    bool done = wtx.confirms > 0;
    bool in_pool = !done && wpr_admit(r, &wtx.tx);
    int64_t delay = 0;
    bool drew = in_pool && wpr_draw_delay_ms(r, &delay);
    if (!done) {
        zcl_mutex_lock(&r->lock);
        struct wpr_entry *e = wpr_find_locked(r, txid);
        if (!e)
            e = wpr_alloc_locked(r);
        int64_t now = r->now_ms();
        if (e) {
            wpr_fill_entry(e, txid, &wtx.tx, now + (drew ? delay : 0),
                           in_pool && drew);
            e->retry_ms = now + (int64_t)WPR_RETRY_S * 1000;
            e->handed = handed;
        }
        zcl_mutex_unlock(&r->lock);
    }
    transaction_free(&wtx.tx);
    return true;
}

struct zcl_result wpr_resume(struct wpr *r)
{
    if (!r)
        return ZCL_ERR(-1, "private relay resume: NULL relay");
    struct uint256 ids[WPR_MAX_ENTRIES];
    bool was_expired[WPR_MAX_ENTRIES];
    bool was_handed[WPR_MAX_ENTRIES];
    zcl_mutex_lock(&r->lock);
    size_t n = wpr_read_pending(r, ids, was_expired, was_handed,
                                WPR_MAX_ENTRIES);
    zcl_mutex_unlock(&r->lock);

    for (size_t i = 0; i < n; i++) {
        if (was_expired[i]) {
            wpr_restore_expired(r, &ids[i]);
            continue;
        }
        wpr_resume_one(r, &ids[i], was_handed[i]);
    }
    zcl_mutex_lock(&r->lock);
    bool ok = wpr_persist_locked(r);
    zcl_mutex_unlock(&r->lock);
    return ok ? ZCL_OK
              : ZCL_ERR(-2, "private relay resume: cannot record pending set");
}

/* ── push ───────────────────────────────────────────────────────────── */

static bool wpr_tried_contains(const struct wpr_entry *e, uint32_t id)
{
    for (size_t i = 0; i < e->num_tried; i++)
        if (e->tried[i] == id)
            return true;
    return false;
}

/* The single place that decides which peer may receive an attempt. Returns
 * -1 when the peer must not be used, otherwise a rank where lower is
 * preferred. Rules: the peer must be eligible; the peer that received the
 * previous attempt is never reused; a peer not yet tried beats one tried
 * earlier. */
static int wpr_peer_rank(const struct wpr_entry *e, const struct p2p_node *n)
{
    if (!wpr_peer_eligible(n))
        return -1;
    uint32_t id = (uint32_t)n->id;
    if (e->num_tried) {
        uint32_t last =
            e->tried[(e->tried_next + WPR_MAX_TRIED - 1) % WPR_MAX_TRIED];
        if (id == last)
            return -1;
    }
    return wpr_tried_contains(e, id) ? 1 : 0;
}

/* Caller holds cs_nodes. Chooses uniformly among the best-ranked peers. */
static struct p2p_node *wpr_choose_peer(struct wpr *r, struct connman *cm,
                                        const struct wpr_entry *e)
{
    struct p2p_node *best[256];
    size_t count = 0;
    int best_rank = -1;
    for (size_t i = 0; i < cm->manager.num_nodes; i++) {
        struct p2p_node *n = cm->manager.nodes[i];
        int rank = wpr_peer_rank(e, n);
        if (rank < 0)
            continue;
        if (best_rank < 0 || rank < best_rank) {
            best_rank = rank;
            count = 0;
        }
        if (rank == best_rank && count < 256)
            best[count++] = n;
    }
    if (count == 0)
        return NULL;
    uint8_t raw[8];
    if (!r->random_bytes(raw, sizeof(raw)))
        return NULL;
    uint64_t v = 0;
    for (size_t i = 0; i < sizeof(raw); i++)
        v = (v << 8) | raw[i];
    return best[v % count];
}

static enum wpr_push_result wpr_push(struct wpr *r, const struct wpr_entry *e,
                                     uint32_t *peer_out)
{
    struct connman *cm = r->env.connman;
    if (!cm || !r->env.params || wpr_get_mode(r) != WPR_MODE_PRIVATE)
        return WPR_PUSH_NO_ROUTE;
    struct transaction tx;
    transaction_init(&tx);
    if (!tx_mempool_lookup(&r->pool, &e->txid, &tx)) {
        transaction_free(&tx);
        return WPR_PUSH_NO_TX;
    }
    struct byte_stream bs;
    stream_init(&bs, 512);
    bool ok = transaction_serialize(&tx, &bs);
    transaction_free(&tx);

    enum wpr_push_result res = WPR_PUSH_NO_ROUTE;
    if (ok) {
        zcl_mutex_lock(&cm->manager.cs_nodes);
        struct p2p_node *peer = wpr_choose_peer(r, cm, e);
        if (peer) {
            p2p_node_begin_message(peer, "tx", r->env.params->pchMessageStart);
            p2p_node_write_message_data(peer, bs.data, bs.size);
            /* A refused queue (cap reached, transport failure) is not an
             * attempt. */
            res = p2p_node_end_message(peer) ? WPR_PUSH_OK
                                             : WPR_PUSH_QUEUE_FAILED;
            *peer_out = (uint32_t)peer->id;
        }
        zcl_mutex_unlock(&cm->manager.cs_nodes);
    }
    stream_free(&bs);
    return res;
}

/* ── tick ───────────────────────────────────────────────────────────── */

static bool wpr_wallet_confirmed(struct wpr *r, const struct uint256 *txid)
{
    if (!r->env.wallet)
        return false;
    struct wallet_tx wtx;
    memset(&wtx, 0, sizeof(wtx));
    if (!wallet_get_tx_copy(r->env.wallet, txid, &wtx))
        return false;  // raw-return-ok:an unknown transaction is not confirmed
    bool confirmed = wtx.confirms > 0;
    transaction_free(&wtx.tx);
    return confirmed;
}

/* The expiry test of the consensus predicate, on the exact bytes. */
static bool wpr_entry_expired(struct wpr *r, const struct wpr_entry *e,
                              int wallet_height)
{
    if (!e->has_expiry || wallet_height < 0 ||
        (int64_t)wallet_height <=
            (int64_t)e->expiry_height + WPR_EXPIRY_MARGIN_BLOCKS)
        return false;
    struct wallet_tx wtx;
    memset(&wtx, 0, sizeof(wtx));
    if (!r->env.wallet || !wallet_get_tx_copy(r->env.wallet, &e->txid, &wtx))
        return true;
    bool expired = is_expired_tx(&wtx.tx, wallet_height + 1);
    transaction_free(&wtx.tx);
    return expired;
}

static void wpr_schedule_locked(struct wpr *r, struct wpr_entry *e,
                                int64_t now)
{
    int64_t delay = 0;
    if (!wpr_draw_delay_ms(r, &delay)) {
        e->state = WPR_WAITING_FOR_ROUTE;
        return;
    }
    e->state = WPR_SCHEDULED;
    e->due_ms = now + delay;
}

static void wpr_revalidate(struct wpr *r, const struct wpr_entry *snap,
                           int64_t now)
{
    struct wallet_tx wtx;
    memset(&wtx, 0, sizeof(wtx));
    bool have = r->env.wallet &&
                wallet_get_tx_copy(r->env.wallet, &snap->txid, &wtx);
    bool admitted = have && wpr_admit(r, &wtx.tx);
    if (have)
        transaction_free(&wtx.tx);
    zcl_mutex_lock(&r->lock);
    struct wpr_entry *e = wpr_find_locked(r, &snap->txid);
    if (e && !have) {
        wpr_clear_locked(r, e);
        (void)wpr_persist_locked(r);
    } else if (e && admitted) {
        e->in_pool = true;
        wpr_schedule_locked(r, e, now);
    } else if (e) {
        e->retry_ms = now + (int64_t)WPR_RETRY_S * 1000;
    }
    zcl_mutex_unlock(&r->lock);
}

/* Record, durably, that a push is about to happen. False leaves the entry
 * unchanged: nothing may be pushed that the record cannot say was pushed. */
static bool wpr_record_handed_intent(struct wpr *r, const struct uint256 *txid,
                                     int64_t now)
{
    zcl_mutex_lock(&r->lock);
    struct wpr_entry *e = wpr_find_locked(r, txid);
    bool ok = e != NULL;
    if (e && !e->handed) {
        e->handed = true;
        ok = wpr_persist_locked(r);
        if (!ok) {
            e->handed = false;
            e->due_ms = now + (int64_t)WPR_RETRY_S * 1000;
        }
    }
    zcl_mutex_unlock(&r->lock);
    return ok;
}

static void wpr_attempt_push(struct wpr *r, const struct wpr_entry *snap,
                             int64_t now, struct wpr_tick_result *out)
{
    uint32_t peer = 0;
    if (!wpr_record_handed_intent(r, &snap->txid, now))
        return;
    enum wpr_push_result res = wpr_push(r, snap, &peer);
    zcl_mutex_lock(&r->lock);
    struct wpr_entry *e = wpr_find_locked(r, &snap->txid);
    if (e && res != WPR_PUSH_OK && !snap->handed) {
        /* Nothing was queued: undo the intent (best effort; a failed write
         * leaves the conservative fact on disk). */
        e->handed = false;
        (void)wpr_persist_locked(r);
    }
    if (e && res == WPR_PUSH_OK) {
        e->attempts++;
        e->last_attempt_ms = now;
        e->tried[e->tried_next] = peer;
        e->tried_next = (uint8_t)((e->tried_next + 1) % WPR_MAX_TRIED);
        if (e->num_tried < WPR_MAX_TRIED)
            e->num_tried++;
        e->state = WPR_SENT;
        e->due_ms = now + (int64_t)WPR_RESEND_AFTER_S * 1000;
        out->pushed++;
    } else if (e && res == WPR_PUSH_NO_TX) {
        e->in_pool = false;
        e->state = WPR_WAITING_FOR_ROUTE;
        e->retry_ms = now;
    } else if (e) {
        e->state = WPR_WAITING_FOR_ROUTE;
    }
    zcl_mutex_unlock(&r->lock);
}

static void wpr_tick_live(struct wpr *r, const struct wpr_entry *snap,
                          int64_t now, struct wpr_tick_result *out)
{
    if (!snap->in_pool) {
        if (now >= snap->retry_ms)
            wpr_revalidate(r, snap, now);
        return;
    }
    if (snap->state == WPR_WAITING_FOR_ROUTE) {
        out->held++;
        if (wpr_get_mode(r) == WPR_MODE_PRIVATE &&
            wpr_count_eligible_peers(r->env.connman) > 0) {
            zcl_mutex_lock(&r->lock);
            struct wpr_entry *e = wpr_find_locked(r, &snap->txid);
            if (e)
                wpr_schedule_locked(r, e, now);
            zcl_mutex_unlock(&r->lock);
        }
    } else if (snap->state == WPR_SENT) {
        if (now >= snap->due_ms) {
            zcl_mutex_lock(&r->lock);
            struct wpr_entry *e = wpr_find_locked(r, &snap->txid);
            if (e)
                wpr_schedule_locked(r, e, now);
            zcl_mutex_unlock(&r->lock);
        }
    } else if (snap->state == WPR_SCHEDULED && now >= snap->due_ms) {
        if (wpr_get_mode(r) != WPR_MODE_PRIVATE)
            out->held++;
        else
            wpr_attempt_push(r, snap, now, out);
    }
}

/* Drop a finished entry once its retention has passed. */
static void wpr_prune_terminal(struct wpr *r, const struct wpr_entry *snap,
                               int64_t now)
{
    int64_t keep_s = snap->state == WPR_SEEN ? WPR_SEEN_RETAIN_S
                                             : WPR_EXPIRED_RETAIN_S;
    if (now - snap->seen_ms <= keep_s * 1000)
        return;
    zcl_mutex_lock(&r->lock);
    struct wpr_entry *e = wpr_find_locked(r, &snap->txid);
    if (e && e->state == snap->state) {
        memset(e, 0, sizeof(*e));
        (void)wpr_persist_locked(r);
    }
    zcl_mutex_unlock(&r->lock);
}

/* Entries that need no push: a finished one is pruned after its retention; a
 * recorded send that was never queued is adopted once the grace has passed
 * when the wallet holds it, and dropped when the wallet never admitted it.
 * Returns true when the entry was one of these. */
static bool wpr_tick_settled(struct wpr *r, const struct wpr_entry *snap,
                             int64_t now)
{
    if (snap->state == WPR_PREPARED) {
        if (now - snap->seen_ms > (int64_t)WPR_PREPARE_GRACE_S * 1000)
            (void)wpr_resume_one(r, &snap->txid, snap->handed);
        return true;
    }
    if (snap->state != WPR_SEEN && snap->state != WPR_EXPIRED)
        return false;
    if (snap->state == WPR_SEEN && !snap->mined) {
        /* Seen back but not yet in a block: the record stays, with a status,
         * until the wallet shows it mined. A send that is dropped and then
         * passes its expiry is not settled: it falls through to the expiry
         * check so its coins are released. */
        if (!wpr_wallet_confirmed(r, &snap->txid))
            return false;
        zcl_mutex_lock(&r->lock);
        struct wpr_entry *e = wpr_find_locked(r, &snap->txid);
        if (e && e->state == WPR_SEEN) {
            e->mined = true;
            e->seen_ms = now;
        }
        zcl_mutex_unlock(&r->lock);
        return true;
    }
    wpr_prune_terminal(r, snap, now);
    return true;
}

static void wpr_tick_entry(struct wpr *r, size_t slot, int wallet_height,
                           int64_t now, struct wpr_tick_result *out)
{
    zcl_mutex_lock(&r->lock);
    struct wpr_entry snap = r->entries[slot];
    zcl_mutex_unlock(&r->lock);
    if (!snap.used)
        return;

    if (wpr_tick_settled(r, &snap, now))
        return;
    if (wpr_wallet_confirmed(r, &snap.txid)) {
        wpr_note_seen(r, &snap.txid);
        return;
    }
    if (snap.expired) {
        if (now >= snap.retry_ms && out->num_expired < WPR_MAX_ENTRIES) {
            out->expired[out->num_expired++] = snap.txid;
            zcl_mutex_lock(&r->lock);
            struct wpr_entry *e = wpr_find_locked(r, &snap.txid);
            if (e)
                e->retry_ms = now + (int64_t)WPR_RETRY_S * 1000;
            zcl_mutex_unlock(&r->lock);
        }
        return;
    }
    if (wpr_entry_expired(r, &snap, wallet_height)) {
        zcl_mutex_lock(&r->lock);
        struct wpr_entry *e = wpr_find_locked(r, &snap.txid);
        if (e) {
            e->expired = true;
            e->retry_ms = 0;
        }
        zcl_mutex_unlock(&r->lock);
        if (out->num_expired < WPR_MAX_ENTRIES)
            out->expired[out->num_expired++] = snap.txid;
        return;
    }
    if (snap.state == WPR_SEEN)
        return;  /* seen back: nothing to push, only the expiry above */
    wpr_tick_live(r, &snap, now, out);
}

void wpr_tick(struct wpr *r, int wallet_height, struct wpr_tick_result *out)
{
    memset(out, 0, sizeof(*out));
    if (!r)
        return;
    int64_t now = r->now_ms();
    for (size_t i = 0; i < WPR_MAX_ENTRIES; i++)
        wpr_tick_entry(r, i, wallet_height, now, out);
}

/* ── status ─────────────────────────────────────────────────────────── */

bool wpr_entry_state(struct wpr *r, const struct uint256 *txid,
                     enum wpr_state *state, bool *handed)
{
    if (!r || !txid)
        return false;
    zcl_mutex_lock(&r->lock);
    const struct wpr_entry *e = wpr_find_locked(r, txid);
    if (e) {
        if (state)
            *state = e->state;
        if (handed)
            *handed = e->handed;
    }
    zcl_mutex_unlock(&r->lock);
    return e != NULL;
}

void wpr_status_snapshot(struct wpr *r, struct wpr_status *out)
{
    memset(out, 0, sizeof(*out));
    out->eligible_peers = wpr_count_eligible_peers(r->env.connman);
    zcl_mutex_lock(&r->lock);
    int64_t now = r->now_ms();
    out->mode = r->mode;
    for (size_t i = 0; i < WPR_MAX_ENTRIES; i++) {
        const struct wpr_entry *e = &r->entries[i];
        if (!e->used)
            continue;
        struct wpr_status_entry *s = &out->entries[out->num_entries++];
        s->txid = e->txid;
        s->state = e->state;
        s->attempts = e->attempts;
        s->seconds_since_attempt =
            e->last_attempt_ms < 0 ? -1 : (now - e->last_attempt_ms) / 1000;
        s->held = e->held;
        s->disk_retry = e->disk_retry;
        s->handed = e->handed;
        s->mined = e->mined;
        if (e->state == WPR_EXPIRED)
            out->expired++;
        else if (e->state != WPR_SEEN)
            out->pending++;
    }
    zcl_mutex_unlock(&r->lock);
}
