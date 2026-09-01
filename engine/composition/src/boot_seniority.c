/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * boot_seniority.c — the advisory peer-selection weight feed, its on-chain
 * address binding, and the epoch-driven rebuild that keeps the per-client
 * favourite set rotating. See config/boot_seniority.h for the contract and
 * for why the on-chain node directory is deliberately NOT an input.
 *
 * Extracted from boot_node_utilities.c, which now only calls
 * boot_seniority_start(). Two opinions arrive about the same address —
 * banked bandwidth reputation (peers_projection) and on-chain seniority
 * (zid_seniority) — and they are merged into ONE bounded value by
 * zid_seniority_combine() and issued as ONE call per address. Two calls
 * would be two influence paths in everything but name, with the later one
 * silently clobbering the earlier. */

#include "config/boot_seniority.h"

#include "config/boot_internal.h"

#include "jobs/reducer_frontier.h"
#include "models/zid_identity.h"
#include "net/addrman.h"
#include "net/zdir_selection.h"
#include "platform/time_compat.h"
#include "supervisors/domains.h"
#include "validation/chainstate.h"

#include "base/serialize_le.h"
#include "crypto/sha3.h"
#include "util/log_macros.h"
#include "util/safe_alloc.h"
#include "util/supervisor.h"
#include "util/thread_registry.h"

#include <stdatomic.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#define BSEN_LOG "boot_seniority"

/* How often the worker asks whether the ranking epoch has rolled. Epochs are
 * ZID_SENIORITY_EPOCH_BLOCKS * 150 s ~ 6 h, so this is cheap by three orders
 * of magnitude; it is short only so a stuck rebuild is retried promptly. */
#define BSEN_POLL_SECS 30

/* Heartbeat deadline. Comfortably above the 120-330 s fold commits observed
 * on this chain: the rebuild takes cs_main and node.db, so a slow tick is a
 * busy node, not a wedged worker, and a false TIME_DEADLINE stall would be
 * exactly the kind of alarm an operator learns to ignore. */
#define BSEN_DEADLINE_SECS 600

/* NO_PROGRESS quiet window. Between epochs the worker reports itself idle
 * every poll, which refreshes this clock without moving the marker — so
 * quiet only accumulates while a rebuild is PENDING AND FAILING. Fifteen
 * minutes of that is a defect worth a named blocker. */
#define BSEN_MAX_QUIET_US (15 * 60 * 1000000LL)

static _Atomic int32_t  g_applied_epoch = INT32_MIN;
static _Atomic uint64_t g_rebuilds;
static _Atomic bool     g_running;
static _Atomic supervisor_child_id g_sup_id = SUPERVISOR_INVALID_ID;
static struct liveness_contract g_contract;
static struct addr_man *g_am;   /* owned by connman; outlives the worker */

int32_t boot_seniority_applied_epoch(void)
{
    return atomic_load(&g_applied_epoch);
}

uint64_t boot_seniority_rebuild_count(void)
{
    return atomic_load(&g_rebuilds);
}

/* ── The address binding ───────────────────────────────────────────── */

static bool bsen_bytes_zero(const uint8_t *p, size_t n)
{
    for (size_t i = 0; i < n; i++)
        if (p[i])
            return false;
    return true;
}

static int bsen_binding_cmp(const void *va, const void *vb)
{
    const struct boot_relay_binding *a = va, *b = vb;
    int c = memcmp(a->ip, b->ip, 16);
    if (c != 0)
        return c;
    if (a->port != b->port)
        return a->port < b->port ? -1 : 1;
    return memcmp(a->relay_id, b->relay_id, 32);
}

static void bsen_push_binding(struct boot_relay_binding *out, size_t cap,
                              size_t *n, const uint8_t ip[16], uint16_t port,
                              const uint8_t relay_id[32])
{
    if (*n >= cap)
        return;
    struct boot_relay_binding *e = &out[*n];
    memset(e, 0, sizeof(*e));
    memcpy(e->ip, ip, 16);
    e->port = port;
    memcpy(e->relay_id, relay_id, 32);
    (*n)++;
}

size_t boot_relay_bindings_build(const struct zendp_record_view *views,
                                 size_t n_views,
                                 struct boot_relay_binding *out, size_t cap)
{
    if (!out || cap == 0)
        LOG_RETURN(0, BSEN_LOG, "bindings_build: NULL out or zero capacity");
    if (n_views > 0 && !views)
        LOG_RETURN(0, BSEN_LOG, "bindings_build: NULL views with n=%zu",
                   n_views);

    size_t n = 0;
    for (size_t i = 0; i < n_views && n < cap; i++) {
        const struct zendp *ep = &views[i].ep;
        /* 0.0.0.0 and :: reach nobody. zendp_valid() already refuses them at
         * decode; refused again here because this table is what a weight is
         * keyed on, and an all-zero key would collide every unrouted entry
         * into one identity. */
        if ((ep->flags & ZENDP_HAS_IPV4) && !bsen_bytes_zero(ep->ipv4, 4)) {
            /* IPv4-mapped, the same 16-byte form addrman and the peers
             * projection key on (pchIPv4Prefix + the four bytes). */
            uint8_t ip[16];
            memset(ip, 0, 10);
            ip[10] = 0xff;
            ip[11] = 0xff;
            memcpy(ip + 12, ep->ipv4, 4);
            bsen_push_binding(out, cap, &n, ip, ep->ipv4_port,
                              views[i].master_pubkey);
        }
        if ((ep->flags & ZENDP_HAS_IPV6) && n < cap &&
            !bsen_bytes_zero(ep->ipv6, 16))
            bsen_push_binding(out, cap, &n, ep->ipv6, ep->ipv6_port,
                              views[i].master_pubkey);
        /* ZENDP_HAS_ONION is carried and verified and produces no row —
         * see boot_seniority.h. Stated, not hidden. */
    }

    if (n > 1)
        qsort(out, n, sizeof(*out), bsen_binding_cmp);
    return n;
}

/* Index of the first row whose ip is >= `ip`, or `n`. */
static size_t bsen_lower_bound(const struct boot_relay_binding *t, size_t n,
                               const uint8_t ip[16])
{
    size_t lo = 0, hi = n;
    while (lo < hi) {
        size_t mid = lo + (hi - lo) / 2;
        if (memcmp(t[mid].ip, ip, 16) < 0)
            lo = mid + 1;
        else
            hi = mid;
    }
    return lo;
}

/* True when a record advertising `have` may answer for a peer seen on
 * `want`. Either side naming no port is not a disagreement; two different
 * declared ports are, and a disagreement costs the boost, never the peer. */
static bool bsen_port_ok(uint16_t have, uint16_t want)
{
    return have == 0 || want == 0 || have == want;
}

bool boot_relay_binding_find(const struct boot_relay_binding *table, size_t n,
                             const uint8_t ip[16], uint16_t port,
                             uint8_t relay_id_out[32])
{
    if (!table || n == 0 || !ip || !relay_id_out)
        return false;   /* a legitimate negative answer, not an error */

    for (size_t i = bsen_lower_bound(table, n, ip); i < n; i++) {
        if (memcmp(table[i].ip, ip, 16) != 0)
            break;
        if (bsen_port_ok(table[i].port, port)) {
            memcpy(relay_id_out, table[i].relay_id, 32);
            return true;
        }
    }
    return false;
}

/* ── The single weighting pass ─────────────────────────────────────── */

/* Index of the binding that answered for this address, or SIZE_MAX. Used
 * only to mark `seen`, so the directory sweep cannot double-issue. */
static size_t bsen_binding_index(const struct boot_seniority_pass *pass,
                                 const uint8_t ip[16], uint16_t port)
{
    const struct boot_relay_binding *t = pass->bindings;
    size_t n = pass->bindings_n;
    for (size_t i = bsen_lower_bound(t, n, ip); i < n; i++) {
        if (memcmp(t[i].ip, ip, 16) != 0)
            break;
        if (bsen_port_ok(t[i].port, port))
            return i;
    }
    return SIZE_MAX;
}

void boot_seniority_weigh_address(struct boot_seniority_pass *pass,
                                  const uint8_t ip[16], uint16_t port,
                                  const struct peer_reputation *rep)
{
    if (!pass || !ip)
        return;

    /* NET-2: bandwidth_score 0..255 -> bounded [1, MAX] multiplier. */
    double bandwidth_mult = 1.0;
    if (rep && rep->bandwidth_score > 0) {
        double frac = (double)rep->bandwidth_score / 255.0;
        if (frac > 1.0) frac = 1.0;
        bandwidth_mult = 1.0 + (ADDRMAN_REPUTATION_MAX_MULT - 1.0) * frac;
    }

    /* T5.2: on-chain seniority, per-client, owner-capped, epoch-keyed. */
    double seniority_mult = 1.0;
    size_t bidx = SIZE_MAX;
    if (pass->table_n && pass->bindings_n) {
        bidx = bsen_binding_index(pass, ip, port);
        if (bidx != SIZE_MAX) {
            const struct zid_seniority_weight *w = zid_seniority_find(
                pass->table, pass->table_n, pass->bindings[bidx].relay_id);
            if (w)
                seniority_mult = w->multiplier;
        }
    }
    if (bidx != SIZE_MAX && bidx < BOOT_RELAY_BINDINGS_MAX)
        pass->seen[bidx] = true;

    double weight = zid_seniority_combine(bandwidth_mult, seniority_mult);
    if (weight <= 1.0)
        return;   /* no opinion — emit NO row, which reads exactly 1.0 */

    if (!pass->rows || pass->rows_n >= pass->rows_cap) {
        if (pass->rows)
            pass->dropped++;
        return;
    }

    struct addrman_weight_row *row = &pass->rows[pass->rows_n++];
    memcpy(row->ip, ip, 16);
    row->multiplier = weight;

    pass->applied++;
    if (seniority_mult > 1.0)
        pass->boosted++;
}

size_t boot_seniority_weigh_unseen_bindings(struct boot_seniority_pass *pass)
{
    if (!pass || !pass->bindings)
        return 0;

    size_t before = pass->applied;
    for (size_t i = 0; i < pass->bindings_n && i < BOOT_RELAY_BINDINGS_MAX;
         i++) {
        if (pass->seen[i])
            continue;
        pass->seen[i] = true;
        struct peer_reputation rep;
        memset(&rep, 0, sizeof(rep));
        bool have = peers_projection_get_reputation_global(
            pass->bindings[i].ip, pass->bindings[i].port, &rep);
        boot_seniority_weigh_address(pass, pass->bindings[i].ip,
                                     pass->bindings[i].port,
                                     have ? &rep : NULL);
    }
    return pass->applied - before;
}

/* ── Per-client derivation, plugged into zid_seniority's draw seam ─── */

struct bsen_draw_ctx {
    uint8_t seed[32];
};

/* The per-client selection derivation is net/zdir_selection.h's and is NOT
 * reimplemented here — this is the adapter that plugs it into the seniority
 * weighting's zid_seniority_draw_fn seam. contexts/wallet/modules/zid sits below core/modules/net in the
 * module order and cannot call into it, so the composition root is where the
 * two meet.
 *
 * zdir_candidate_score is SHA3-256(0x02 || "ZDIR" || seed || candidate_id)
 * with the seed already bound to this node's client key and the epoch's block
 * hash; the low 8 bytes are a uniform draw. */
static bool bsen_client_draw(void *vctx, const uint8_t relay_id[32],
                             uint64_t *draw_out)
{
    const struct bsen_draw_ctx *ctx = vctx;
    if (!ctx || !relay_id || !draw_out)
        LOG_FAIL(BSEN_LOG, "draw: NULL ctx/relay/out");

    uint8_t score[32];
    if (!zdir_candidate_score(score, ctx->seed, relay_id))
        LOG_FAIL(BSEN_LOG, "draw: zdir_candidate_score failed");

    *draw_out = zcl_read_u64_le(score);
    return true;
}

/* Build the per-client, per-epoch seed the draw above is keyed on, entirely
 * through zdir_selection's primitives: client_key from this node's addrman
 * salt (durable across restarts, never on the wire), epoch seed from that key
 * plus the block hash at the RANKING EPOCH height rather than at the tip —
 * that is the update rate limit, so the favourite set rotates about every six
 * hours instead of every block, and an attacker gets one grinding attempt per
 * epoch instead of one per 150 seconds.
 *
 * When the epoch height is outside the in-memory active chain window (early
 * boot, or a node still folding) the block hash stays all-zero. The seed is
 * still per-client, because client_key alone already makes it so; the only
 * thing missing is chain-binding of the rotation. Never an error, never a
 * fallback to a shared ranking. */
static bool bsen_epoch_seed(const struct addr_man *am, int32_t epoch_height,
                            uint8_t seed[32])
{
    if (!am || !seed)
        LOG_FAIL(BSEN_LOG, "epoch seed: NULL addrman/out");

    uint8_t client_key[32];
    if (!zdir_client_key(client_key, am->nKey.data))
        LOG_FAIL(BSEN_LOG, "epoch seed: client key derivation failed");

    uint8_t block_hash[32];
    memset(block_hash, 0, sizeof(block_hash));

    struct boot_svc_ctx *svc = boot_active_svc();
    if (svc && svc->state && epoch_height > 0) {
        zcl_mutex_lock(&svc->state->cs_main);
        struct block_index *bi =
            active_chain_at(&svc->state->chain_active, epoch_height);
        if (bi)
            memcpy(block_hash, bi->hashBlock.data, 32);
        zcl_mutex_unlock(&svc->state->cs_main);
    }

    if (!zdir_epoch_seed(seed, block_hash, client_key))
        LOG_FAIL(BSEN_LOG, "epoch seed: zdir_epoch_seed failed");
    return true;
}

/* ── Table build ───────────────────────────────────────────────────── */

/* Build this node's seniority table from the on-chain identity projection.
 *
 * Reads anchor_height (how long the identity has been anchored) and
 * owner_address (the P2PKH signer that anchored it, the same owner convention
 * ZNAM uses) out of zid_identities, hashes the owner address into an opaque
 * grouping key, and hands the set to zid_seniority_rank() — which applies the
 * anti-Sybil age floor, the per-owner influence cap, and this node's own draw
 * for `epoch_height`.
 *
 * Returns the entry count and sets *out_table to a heap table the caller
 * frees, or 0 with *out_table NULL (no rows, no db, or allocation failure —
 * all of which degrade to bandwidth-only weighting, never to an error). */
static size_t bsen_build_table(struct zid_seniority_weight **out_table,
                               const struct addr_man *am, int32_t epoch_height)
{
    if (!out_table)
        return 0;
    *out_table = NULL;

    struct boot_svc_ctx *svc = boot_active_svc();
    if (!svc || !svc->node_db || !svc->node_db->open)
        return 0;

    int64_t total = db_zid_identity_count(svc->node_db);
    if (total <= 0)
        return 0;   /* no anchored identities: nothing to weigh */
    if (total > ZID_SENIORITY_MAX_RELAYS)
        total = ZID_SENIORITY_MAX_RELAYS;   /* projection quota */

    size_t n = (size_t)total;
    struct zid_relay_registration *regs =
        zcl_malloc(n * sizeof(*regs), "seniority_registrations");
    struct zid_seniority_weight *tbl =
        zcl_malloc(n * sizeof(*tbl), "seniority_weights");
    if (!regs || !tbl) {
        free(regs);
        free(tbl);
        return 0;
    }

    /* Page the projection in bounded chunks — the row struct is large and
     * this runs on the refresh worker's stack. */
    struct zid_identity page[32];
    size_t filled = 0;
    int offset = 0;
    while (filled < n) {
        int got = db_zid_identity_list(svc->node_db, page,
                                       (int)(sizeof(page) / sizeof(page[0])),
                                       offset);
        if (got <= 0)
            break;
        for (int i = 0; i < got && filled < n; i++) {
            memset(&regs[filled], 0, sizeof(regs[filled]));
            memcpy(regs[filled].relay_id, page[i].master_pubkey, 32);
            regs[filled].registration_height = page[i].anchor_height;
            /* owner_id is an opaque grouping key; an empty owner_address
             * stays all-zero, which zid_seniority treats as "unknown owner"
             * and pointedly does NOT pool with other unknowns. */
            if (page[i].owner_address[0])
                sha3_256((const unsigned char *)page[i].owner_address,
                         strlen(page[i].owner_address), regs[filled].owner_id);
            filled++;
        }
        offset += got;
    }

    size_t count = 0;
    if (filled > 0) {
        struct bsen_draw_ctx dctx;
        memset(&dctx, 0, sizeof(dctx));
        if (bsen_epoch_seed(am, epoch_height, dctx.seed)) {
            /* The tip the AGE score is measured against is the live tip; the
             * epoch height only keys the per-client draw. Conflating them
             * would freeze every relay's age at the epoch boundary. */
            int32_t tip = reducer_frontier_provable_tip_cached();
            int ranked = zid_seniority_rank(regs, filled, tip,
                                            bsen_client_draw, &dctx, tbl, n);
            if (ranked > 0)
                count = (size_t)ranked;
        }
    }

    free(regs);
    if (count == 0) {
        free(tbl);
        return 0;
    }
    *out_table = tbl;
    return count;
}

/* ── The rebuild ───────────────────────────────────────────────────── */

static void bsen_reputation_cb(const uint8_t ip[16], uint16_t port,
                               const struct peer_reputation *rep, void *ctx)
{
    boot_seniority_weigh_address(ctx, ip, port, rep);
}

bool boot_seniority_refresh_once(struct addr_man *am, int32_t epoch_height)
{
    if (!am)
        LOG_FAIL(BSEN_LOG, "refresh: no addrman — cannot weigh anything");

    struct boot_svc_ctx *svc = boot_active_svc();
    if (!svc || !svc->node_db || !svc->node_db->open)
        LOG_FAIL(BSEN_LOG,
                 "refresh: node.db is not open — the chain cannot be asked, "
                 "so no address may be given a seniority boost");

    /* The table is derived per-client (through zdir_client_key over this
     * node's durable addrman salt), never globally: a single deterministic
     * ranking every client shares would be an anonymity monoculture, one
     * ranking with one top relay for everyone to attack. */
    struct zid_seniority_weight *table = NULL;
    size_t table_n = bsen_build_table(&table, am, epoch_height);

    struct boot_seniority_pass *pass =
        zcl_malloc(sizeof(*pass), "seniority_pass");
    struct addrman_weight_row *rows = zcl_malloc(
        BOOT_SENIORITY_ROWS_MAX * sizeof(*rows), "seniority_rows");
    if (!pass || !rows) {
        free(pass);
        free(rows);
        free(table);
        LOG_FAIL(BSEN_LOG, "refresh: pass allocation failed");
    }
    memset(pass, 0, sizeof(*pass));
    pass->am = am;
    pass->table = table;
    pass->table_n = table_n;
    pass->rows = rows;
    pass->rows_cap = BOOT_SENIORITY_ROWS_MAX;

    struct zendp_record_view views[ZENDP_DIR_MAX];
    struct boot_relay_binding bindings[BOOT_RELAY_BINDINGS_MAX];
    size_t n_views = zendp_global_records(
        (uint64_t)platform_time_wall_unix(), views, ZENDP_DIR_MAX);
    pass->bindings = bindings;
    pass->bindings_n = boot_relay_bindings_build(views, n_views, bindings,
                                                 BOOT_RELAY_BINDINGS_MAX);

    /* Both feeds are re-read in full every epoch. Neither carries forward:
     * the table this builds is the ENTIRE opinion this node holds about
     * dial preference, so an address that appears in neither feed this time
     * is back at 1.0 by not being in it. */
    (void)peers_projection_for_each_reputation_global(4096, bsen_reputation_cb,
                                                      pass);
    (void)boot_seniority_weigh_unseen_bindings(pass);

    bool published = addrman_publish_reputation_weights(am, pass->rows,
                                                        pass->rows_n,
                                                        epoch_height);

    LOG_INFO(BSEN_LOG,
             "epoch %d: ranked %zu anchored relay identities, %zu signed "
             "address bindings; %zu addresses weighted, %zu of them carrying "
             "a seniority boost; table %s",
             epoch_height, table_n, pass->bindings_n, pass->applied,
             pass->boosted,
             published ? "published" : "WITHHELD (degraded mode) — the "
                                       "previous epoch's table still stands");
    if (pass->dropped > 0)
        LOG_WARN(BSEN_LOG,
                 "epoch %d: %zu weighted address(es) exceeded the %u-row table "
                 "capacity and were left on the baseline",
                 epoch_height, pass->dropped, BOOT_SENIORITY_ROWS_MAX);

    free(rows);
    free(pass);
    free(table);
    return true;
}

/* ── Rotation ──────────────────────────────────────────────────────── */

enum boot_seniority_action boot_seniority_next_action(int32_t tip_height,
                                                      int32_t applied_epoch,
                                                      int32_t *epoch_out)
{
    int32_t epoch = zid_seniority_epoch_height(tip_height);
    if (epoch_out)
        *epoch_out = epoch;
    return epoch == applied_epoch ? BOOT_SENIORITY_IDLE
                                  : BOOT_SENIORITY_REBUILD;
}

/* ── The supervised refresh worker ─────────────────────────────────── */

static void *bsen_worker_main(void *arg)
{
    (void)arg;
    supervisor_child_id id = atomic_load(&g_sup_id);

    while (atomic_load(&g_running) && !thread_registry_shutdown_requested()) {
        int32_t epoch = 0;
        enum boot_seniority_action action = boot_seniority_next_action(
            reducer_frontier_provable_tip_cached(),
            atomic_load(&g_applied_epoch), &epoch);

        if (action == BOOT_SENIORITY_IDLE) {
            /* POSITIVELY established there is no work: the ranking epoch has
             * not rolled, so the favourite set this node already published is
             * the correct one for this epoch. Refreshes the quiet clock
             * without moving the marker. */
            supervisor_progress_idle(id);
        } else if (boot_seniority_refresh_once(g_am, epoch)) {
            atomic_store(&g_applied_epoch, epoch);
            uint64_t done = atomic_fetch_add(&g_rebuilds, 1) + 1;
            supervisor_progress(id, (int64_t)done);
        }
        /* else: report NEITHER progress NOR idle. A rebuild that could not
         * run is exactly the state NO_PROGRESS exists to catch, and calling
         * it idle would re-create the silent stall. */
        supervisor_tick(id);

        for (int i = 0; i < BSEN_POLL_SECS && atomic_load(&g_running) &&
                        !thread_registry_shutdown_requested(); i++) {
            struct timespec ts = { .tv_sec = 1, .tv_nsec = 0 };
            nanosleep(&ts, NULL);
        }
    }
    return NULL;
}

void boot_seniority_start(struct addr_man *am)
{
    if (!am || atomic_load(&g_running))
        return;
    g_am = am;

    /* The first build happens inline so a node that never reaches the worker
     * still boots with a weighted addrman. */
    int32_t epoch = 0;
    (void)boot_seniority_next_action(reducer_frontier_provable_tip_cached(),
                                     atomic_load(&g_applied_epoch), &epoch);
    if (boot_seniority_refresh_once(am, epoch)) {
        atomic_store(&g_applied_epoch, epoch);
        atomic_fetch_add(&g_rebuilds, 1);
    }

    liveness_contract_init(&g_contract, "net.seniority_refresh");
    /* period_secs 0: the worker heartbeats itself. The rebuild reads node.db
     * and takes cs_main, and a blocking read on the shared tick runner parks
     * every other child behind it — see boot_seniority.h. */
    atomic_store(&g_contract.period_secs, (int64_t)0);
    atomic_store(&g_contract.deadline_secs, (int64_t)BSEN_DEADLINE_SECS);
    g_contract.on_tick = NULL;
    g_contract.on_stall = NULL;
    supervisor_domains_init();
    supervisor_child_id id = supervisor_register_in_domain(g_net_sup,
                                                           &g_contract);
    atomic_store(&g_sup_id, id);
    if (id == SUPERVISOR_INVALID_ID) {
        LOG_WARN(BSEN_LOG, "supervisor register failed; refresh not started");
        return;
    }
    supervisor_tick(id);
    /* Count RESULTS: one applied ranking epoch. Between epochs the worker
     * reports idle, so a frozen marker means a rebuild is pending and
     * failing, never merely "nothing to do". Armed AFTER register so the
     * child id is valid. */
    supervisor_set_progress_max_quiet(id, BSEN_MAX_QUIET_US);
    supervisor_progress(id, (int64_t)atomic_load(&g_rebuilds));

    atomic_store(&g_running, true);
    /* supervised:net.seniority_refresh */
    int rc = thread_registry_spawn("zcl_seniority", bsen_worker_main, NULL,
                                   NULL);
    if (rc != 0) {
        atomic_store(&g_running, false);
        supervisor_child_complete(id);
        LOG_WARN(BSEN_LOG, "worker spawn failed (%d); rotation is frozen at "
                 "epoch %d until restart", rc, epoch);
    }
}
