/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Dandelion++ routing, epoch, embargo and lock-balance checks aimed at the
 * mutants the 1105 sweep left alive in core/modules/net/src/dandelion.c.
 * Run from test_dandelion(), so the `dandelion` test group covers them.
 *
 * Seams used (all process-wide, always restored before a group returns):
 *   - the injectable wall clock (clock_set_default), so epoch and embargo
 *     boundaries are exact seconds, never a sleep;
 *   - the injectable RNG iface (rng_set_default), fed a scripted stream of
 *     little-endian 64-bit words. An all-zero word, or a drained script,
 *     makes zcl_random_secret_bytes refuse, which is the RNG-failure path
 *     (the fake fill itself always returns true: a false would abort).
 *     Threads other than the installing one fall through to the real RNG.
 * Lock discipline is checked without timing: zcl_mutex_t is recursive, so a
 * test holds the mutex once, runs the call, and asks another thread to
 * trylock. A call that lost its lock or its unlock changes the answer. */

#include "platform/clock.h"
#include "platform/rng.h"
#include "test/test_core.h"
#include "net/dandelion.h"
#include "core/uint256.h"
#include <pthread.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

bool dandelion_test_shuffle(node_id_t *inout, int n);
bool dandelion_test_should_stem_coin(bool *out_stem);

#define NO_PEER DANDELION_NODE_ID_NONE

static void mchk(int *failures, bool ok, const char *what)
{
    if (!ok) {
        printf("\n  FAIL %s", what);
        (*failures)++;
    }
}

/* ── fake wall clock ───────────────────────────────────────────── */

static _Atomic int64_t g_now_s;
static const clock_iface_t *g_real_clock;

static int64_t fk_wall_ms(void *self)
{
    (void)self;
    return atomic_load(&g_now_s) * 1000;
}

static int64_t fk_mono_ns(void *self)
{
    (void)self;
    return g_real_clock->now_monotonic_ns(g_real_clock->self);
}

static const clock_iface_t g_fake_clock = { fk_mono_ns, fk_wall_ms, NULL };

static void clock_begin(int64_t now_s)
{
    if (clock_default() != &g_fake_clock)
        g_real_clock = clock_default();
    atomic_store(&g_now_s, now_s);
    clock_set_default(&g_fake_clock);
}

static void clock_end(void)
{
    clock_reset_default();
}

/* ── scripted RNG ──────────────────────────────────────────────── */

static uint8_t g_rb[8 * 16];
static size_t g_rb_bytes;
static size_t g_rb_pos;
static size_t g_rb_max_len;
static pthread_t g_rb_owner;
static const rng_iface_t *g_rb_real;

static bool fk_fill(void *self, uint8_t *out, size_t len)
{
    (void)self;
    if (!pthread_equal(pthread_self(), g_rb_owner))
        return g_rb_real->fill(g_rb_real->self, out, len);
    if (len > g_rb_max_len)
        g_rb_max_len = len;
    for (size_t i = 0; i < len; i++) {
        out[i] = g_rb_pos < g_rb_bytes ? g_rb[g_rb_pos] : 0;
        g_rb_pos++;
    }
    return true;
}

static const rng_iface_t g_fake_rng = { fk_fill, NULL };

static void rng_begin(const uint64_t *words, size_t n)
{
    memset(g_rb, 0, sizeof g_rb);
    for (size_t w = 0; w < n; w++)
        for (size_t b = 0; b < 8; b++)
            g_rb[w * 8 + b] = (uint8_t)(words[w] >> (8 * b));
    g_rb_bytes = n * 8;
    g_rb_pos = 0;
    g_rb_max_len = 0;
    g_rb_owner = pthread_self();
    if (rng_default() != &g_fake_rng)
        g_rb_real = rng_default();
    rng_set_default(&g_fake_rng);
}

static void rng_end(void)
{
    rng_reset_default();
}

/* ── lock probe ────────────────────────────────────────────────── */

static void *trylock_thread(void *arg)
{
    zcl_mutex_t *m = arg;
    if (!zcl_mutex_trylock(m))
        return (void *)(intptr_t)0;
    zcl_mutex_unlock(m);
    return (void *)(intptr_t)1;
}

/* 1 when another thread could take the mutex, 0 when it is held, -1 when
 * the probe thread could not be started. */
static int probe_other(zcl_mutex_t *m)
{
    pthread_t t;
    void *res = NULL;
    if (pthread_create(&t, NULL, trylock_thread, m) != 0)
        return -1;
    pthread_join(t, &res);
    return (int)(intptr_t)res;
}

/* The caller took `m` once before the call under test. A balanced call
 * leaves that one hold: a deleted lock frees it, a deleted unlock keeps it
 * held past our own unlock. */
static void bal(int *f, zcl_mutex_t *m, const char *what)
{
    mchk(f, probe_other(m) == 0, what);
    zcl_mutex_unlock(m);
    mchk(f, probe_other(m) == 1, what);
}

/* ── fixtures ──────────────────────────────────────────────────── */

static struct net_manager g_nm;
static struct p2p_node g_peers[16];
static struct p2p_node *g_nodes[16];

static void nm_reset(void)
{
    memset(&g_nm, 0, sizeof g_nm);
    memset(g_peers, 0, sizeof g_peers);
    memset(g_nodes, 0, sizeof g_nodes);
    zcl_mutex_init(&g_nm.cs_nodes);
    g_nm.nodes = g_nodes;
    g_nm.nodes_cap = 16;
}

static void nm_add(node_id_t id, bool inbound, enum peer_state st,
                   bool disconnect, bool relay)
{
    struct p2p_node *p = &g_peers[g_nm.num_nodes];
    p->id = id;
    p->inbound = inbound;
    atomic_store(&p->state, st);
    atomic_store(&p->disconnect, disconnect);
    p->relay_txes = relay;
    g_nodes[g_nm.num_nodes++] = p;
}

/* Eligible peer parked just past num_nodes: a loop that reads one slot too
 * far picks it up. */
static void nm_decoy(node_id_t id)
{
    nm_add(id, false, PEER_ACTIVE, false, true);
    g_nm.num_nodes--;
}

static void nm_done(void)
{
    zcl_mutex_destroy(&g_nm.cs_nodes);
}

/* Six peers of which exactly ids 11 (at the handshake boundary) and 12 are
 * eligible; inbound, pre-handshake, disconnecting and no-relay peers are
 * not; a decoy sits at nodes[num_nodes]. */
static void nm_filter_fixture(void)
{
    nm_reset();
    nm_add(11, false, PEER_HANDSHAKE_COMPLETE, false, true);
    nm_add(21, true, PEER_ACTIVE, false, true);
    nm_add(22, false, PEER_VERSION_RECEIVED, false, true);
    nm_add(12, false, PEER_ACTIVE, false, true);
    nm_add(23, false, PEER_ACTIVE, true, true);
    nm_add(24, false, PEER_ACTIVE, false, false);
    nm_decoy(77);
}

static void ds_stale(struct dandelion_state *ds)
{
    dandelion_init(ds);
    ds->num_stem_peers = 2;
    ds->stem_peers[0] = 99;
    ds->stem_peers[1] = 98;
    ds->stem_rr_index = 1;
}

static struct uint256 hash_of(int i)
{
    struct uint256 h;
    memset(h.data, 0, sizeof h.data);
    memcpy(h.data, &i, sizeof i);
    return h;
}

static void expect_stem(int *f, const struct dandelion_state *ds, int n,
                        node_id_t a, node_id_t b, const char *what)
{
    mchk(f, ds->num_stem_peers == n, what);
    mchk(f, ds->stem_peers[0] == a, what);
    mchk(f, ds->stem_peers[1] == b, what);
}

/* ── lifecycle ─────────────────────────────────────────────────── */

static int check_lifecycle(void)
{
    int f = 0;
    struct dandelion_state ds;
    memset(&ds, 0xA5, sizeof ds);
    dandelion_init(&ds);
    mchk(&f, ds.epoch_start == 0, "init epoch_start 0");
    mchk(&f, ds.num_stem_peers == 0, "init num_stem_peers 0");
    mchk(&f, ds.stempool_count == 0, "init stempool_count 0");
    mchk(&f, ds.stem_rr_index == 0, "init stem_rr_index 0");
    mchk(&f, ds.enabled, "init enabled");
    mchk(&f, ds.stem_peers[0] == NO_PEER, "init stem slot 0 NO_PEER");
    mchk(&f, ds.stem_peers[1] == NO_PEER, "init stem slot 1 NO_PEER");
    mchk(&f, !ds.stempool[0].active, "init stempool slot 0 inactive");
    mchk(&f, ds.stat_embargo_fluff == 0, "init stats zero");

    /* The mutex is recursive: lock twice, one probe, unlock twice. */
    zcl_mutex_lock(&ds.cs);
    mchk(&f, zcl_mutex_trylock(&ds.cs), "init mutex recursive");
    zcl_mutex_unlock(&ds.cs);
    zcl_mutex_unlock(&ds.cs);

    ds.num_stem_peers = 2;
    ds.stempool_count = 3;
    ds.stem_rr_index = 1;
    ds.stem_peers[1] = 7;
    ds.stempool[0].active = true;
    dandelion_free(&ds);
    const unsigned char *raw = (const unsigned char *)&ds;
    bool zeroed = true;
    for (size_t i = 0; i < sizeof ds; i++)
        if (raw[i] != 0)
            zeroed = false;
    mchk(&f, zeroed, "free zeroes the whole state");
    return f;
}

/* ── routing decisions ─────────────────────────────────────────── */

static int check_get_stem_peer_routing(void)
{
    int f = 0;
    struct dandelion_state ds;
    dandelion_init(&ds);
    mchk(&f, dandelion_get_stem_peer(NULL, 5) == NO_PEER, "NULL ds -> NO_PEER");
    mchk(&f, dandelion_get_stem_peer(&ds, 5) == NO_PEER, "no peers -> NO_PEER");

    ds.num_stem_peers = 1;
    ds.stem_peers[0] = 10;
    mchk(&f, dandelion_get_stem_peer(&ds, 99) == 10, "single peer chosen");
    mchk(&f, dandelion_get_stem_peer(&ds, 10) == NO_PEER, "single peer = sender");

    dandelion_free(&ds);
    dandelion_init(&ds);
    ds.num_stem_peers = 2;
    ds.stem_peers[0] = 10;
    ds.stem_peers[1] = 20;
    /* rr index straight from init: first pick is slot 0. */
    mchk(&f, dandelion_get_stem_peer(&ds, NO_PEER) == 10, "rr first = 10");
    mchk(&f, ds.stem_rr_index == 1, "rr advances to 1");
    mchk(&f, dandelion_get_stem_peer(&ds, NO_PEER) == 20, "rr second = 20");
    mchk(&f, ds.stem_rr_index == 0, "rr wraps to 0");
    mchk(&f, dandelion_get_stem_peer(&ds, 10) == 20, "skip sender 10");
    mchk(&f, ds.stem_rr_index == 0, "rr after skip wraps");
    mchk(&f, dandelion_get_stem_peer(&ds, 10) == 20, "skip sender again");
    dandelion_free(&ds);
    return f;
}

static int coin_pos;
static int coin_len;

/* -1 RNG refused, 0 fluff, 1 stem. */
static int coin_probe(bool use_hook, uint64_t r)
{
    struct dandelion_state ds;
    dandelion_init(&ds);
    ds.num_stem_peers = 1;
    ds.stem_peers[0] = 5;
    int res;
    rng_begin(&r, 1);
    if (use_hook) {
        bool stem = false;
        bool ok = dandelion_test_should_stem_coin(&stem);
        res = ok ? (stem ? 1 : 0) : -1;
    } else {
        res = dandelion_should_stem(&ds, NO_PEER) ? 1 : 0;
    }
    coin_pos = (int)g_rb_pos;
    coin_len = (int)g_rb_max_len;
    rng_end();
    dandelion_free(&ds);
    return res;
}

struct coin_case {
    uint64_t r;
    int want;
};

/* Fluff when r % 100 < 10. The three large words differ, in outcome, from
 * what a decode that drops the top byte, or shifts bytes by 7 or 9 bits,
 * would produce. */
static const struct coin_case k_coin[] = {
    { 0, -1 },
    { 9, 0 }, { 10, 1 }, { 99, 1 }, { 100, 0 }, { 109, 0 }, { 110, 1 },
    { 0x3e3e1651ad19c67cULL, 1 },
    { 0x6672141411cb8201ULL, 1 },
    { 0x78ad33f54a21016aULL, 1 },
};

static int check_coin_table(bool use_hook)
{
    int f = 0;
    for (size_t i = 0; i < sizeof k_coin / sizeof k_coin[0]; i++) {
        int want = k_coin[i].want;
        int got = coin_probe(use_hook, k_coin[i].r);
        if (!use_hook && want < 0)
            want = 0;
        char what[64];
        snprintf(what, sizeof what, "coin %s case %zu",
                 use_hook ? "hook" : "should_stem", i);
        mchk(&f, got == want, what);
        mchk(&f, coin_pos == 8, "coin draws exactly 8 bytes");
        mchk(&f, coin_len == 8, "coin asks for an 8-byte word");
    }
    return f;
}

static int check_coin_hook(void)
{
    int f = check_coin_table(true);
    mchk(&f, !dandelion_test_should_stem_coin(NULL), "coin hook NULL out");
    return f;
}

static int check_should_stem_decision(void)
{
    int f = check_coin_table(false);
    struct dandelion_state ds;
    dandelion_init(&ds);
    mchk(&f, !dandelion_should_stem(NULL, 5), "NULL ds never stems");
    ds.enabled = false;
    ds.num_stem_peers = 1;
    ds.stem_peers[0] = 5;
    mchk(&f, !dandelion_should_stem(&ds, 5), "disabled never stems");
    ds.enabled = true;
    ds.num_stem_peers = 0;
    mchk(&f, !dandelion_should_stem(&ds, 5), "no peers never stems");
    /* RNG refusal must fluff every time, whatever is on the stack. */
    ds.num_stem_peers = 1;
    rng_begin(NULL, 0);
    bool any = false;
    for (int i = 0; i < 16; i++)
        if (dandelion_should_stem(&ds, 5))
            any = true;
    rng_end();
    mchk(&f, !any, "RNG refusal fluffs");
    dandelion_free(&ds);
    return f;
}

/* ── shuffle ───────────────────────────────────────────────────── */

static int check_hook_shuffle(void)
{
    int f = 0;
    node_id_t a[5] = { 1, 2, 3, 4, 0x5555 };
    const uint64_t s3[] = { 1, 3, 2 };
    rng_begin(s3, 3);
    bool ok = dandelion_test_shuffle(a, 4);
    size_t pos = g_rb_pos;
    rng_end();
    mchk(&f, ok, "shuffle ok");
    mchk(&f, a[0] == 4 && a[1] == 3, "shuffle known answer lo");
    mchk(&f, a[2] == 1 && a[3] == 2, "shuffle known answer hi");
    mchk(&f, a[4] == 0x5555, "shuffle stays inside n");
    mchk(&f, pos == 24, "shuffle draws n-1 words");

    node_id_t b[4] = { 1, 2, 3, 4 };
    const uint64_t s2[] = { 1, 3 };
    rng_begin(s2, 2);
    ok = dandelion_test_shuffle(b, 4);
    rng_end();
    mchk(&f, !ok, "shuffle refuses when the RNG drains");

    node_id_t c[2] = { 1, 2 };
    const uint64_t even[] = { 2 };
    rng_begin(even, 1);
    ok = dandelion_test_shuffle(c, 2);
    rng_end();
    mchk(&f, ok && c[0] == 2 && c[1] == 1, "even word swaps a pair");

    node_id_t d[3] = { 7, 8, 9 };
    rng_begin(NULL, 0);
    mchk(&f, dandelion_test_shuffle(d, 0), "n=0 ok");
    mchk(&f, dandelion_test_shuffle(d, 1), "n=1 ok");
    mchk(&f, g_rb_pos == 0, "n<=1 draws nothing");
    mchk(&f, !dandelion_test_shuffle(d, -1), "n<0 refused");
    mchk(&f, !dandelion_test_shuffle(NULL, 3), "NULL refused");
    rng_end();
    return f;
}

/* ── epoch rotation ────────────────────────────────────────────── */

static int check_rotate_filter_and_shuffle(void)
{
    int f = 0;
    nm_filter_fixture();
    struct dandelion_state ds;
    ds_stale(&ds);
    const uint64_t script[] = { 2 };
    clock_begin(1000);
    rng_begin(script, 1);
    dandelion_maybe_rotate_epoch(&ds, &g_nm);
    mchk(&f, g_rb_pos == 8, "one candidate pair draws one word");
    mchk(&f, g_rb_max_len == 8, "secret draw is 8 bytes");
    rng_end();
    clock_end();
    expect_stem(&f, &ds, 2, 12, 11, "filter picks 11 and 12 shuffled");
    mchk(&f, ds.stem_rr_index == 0, "rotate resets rr index");
    mchk(&f, ds.epoch_start == 1000, "rotate stamps the epoch");
    dandelion_free(&ds);
    nm_done();
    return f;
}

static void ten_peers(void)
{
    nm_reset();
    for (node_id_t id = 31; id <= 40; id++)
        nm_add(id, false, PEER_ACTIVE, false, true);
}

static int check_rotate_caps_candidates_at_eight(void)
{
    int f = 0;
    ten_peers();
    struct dandelion_state ds;
    ds_stale(&ds);
    /* Seven draws for eight candidates; a ninth candidate needs an eighth. */
    const uint64_t script[] = { 3, 5, 7, 2, 9, 4, 2 };
    clock_begin(1000);
    rng_begin(script, 7);
    dandelion_maybe_rotate_epoch(&ds, &g_nm);
    mchk(&f, g_rb_pos == 56, "eight candidates draw seven words");
    rng_end();
    clock_end();
    expect_stem(&f, &ds, 2, 35, 31, "eight-candidate shuffle known answer");
    mchk(&f, ds.stem_rr_index == 0, "rr index reset");
    dandelion_free(&ds);
    nm_done();
    return f;
}

static int check_rotate_small_candidate_sets(void)
{
    int f = 0;
    struct dandelion_state ds;

    nm_reset();
    nm_add(5, false, PEER_ACTIVE, false, true);
    nm_add(6, true, PEER_ACTIVE, false, true);
    ds_stale(&ds);
    clock_begin(1000);
    rng_begin(NULL, 0);
    dandelion_maybe_rotate_epoch(&ds, &g_nm);
    mchk(&f, g_rb_pos == 0, "one candidate draws nothing");
    rng_end();
    clock_end();
    expect_stem(&f, &ds, 1, 5, NO_PEER, "one candidate, stale slot cleared");
    mchk(&f, ds.stem_rr_index == 0, "rr reset with one candidate");
    dandelion_free(&ds);
    nm_done();

    nm_reset();
    nm_add(6, true, PEER_ACTIVE, false, true);
    ds_stale(&ds);
    clock_begin(1000);
    dandelion_maybe_rotate_epoch(&ds, &g_nm);
    clock_end();
    expect_stem(&f, &ds, 0, NO_PEER, NO_PEER, "no candidates clears every slot");
    mchk(&f, ds.stem_rr_index == 0, "rr reset with no candidates");
    dandelion_free(&ds);
    nm_done();
    return f;
}

static int check_rotate_rng_failure(void)
{
    int f = 0;
    struct dandelion_state ds;

    nm_filter_fixture();
    ds_stale(&ds);
    clock_begin(1000);
    rng_begin(NULL, 0);
    dandelion_maybe_rotate_epoch(&ds, &g_nm);
    rng_end();
    clock_end();
    expect_stem(&f, &ds, 0, NO_PEER, NO_PEER, "RNG refusal: no stem peers");
    mchk(&f, ds.stem_rr_index == 0, "RNG refusal resets rr");
    dandelion_free(&ds);
    nm_done();

    ten_peers();
    ds_stale(&ds);
    const uint64_t partial[] = { 3, 5 };
    clock_begin(1000);
    rng_begin(partial, 2);
    dandelion_maybe_rotate_epoch(&ds, &g_nm);
    rng_end();
    clock_end();
    expect_stem(&f, &ds, 0, NO_PEER, NO_PEER, "mid-shuffle refusal: no stem peers");
    dandelion_free(&ds);
    nm_done();
    return f;
}

/* One RNG refusal must not mean a whole epoch of fluffing. It waits a minute,
 * not a call: without the wait a down RNG would log on every call. */
static int check_rotate_rng_failure_retries_in_a_minute(void)
{
    int f = 0;
    struct dandelion_state ds;
    const uint64_t word[] = { 2 };

    nm_filter_fixture();
    dandelion_init(&ds);
    clock_begin(1000);
    rng_begin(NULL, 0);
    dandelion_maybe_rotate_epoch(&ds, &g_nm);
    mchk(&f, g_rb_pos == 8, "the refused rotation drew");
    expect_stem(&f, &ds, 0, NO_PEER, NO_PEER, "refused rotation fluffs");

    /* Still down at +60: a second refusal, and a further minute's wait. */
    atomic_store(&g_now_s, 1000 + 59);
    rng_begin(NULL, 0);
    dandelion_maybe_rotate_epoch(&ds, &g_nm);
    mchk(&f, g_rb_pos == 0, "no draw at +59");
    atomic_store(&g_now_s, 1000 + 60);
    dandelion_maybe_rotate_epoch(&ds, &g_nm);
    mchk(&f, g_rb_pos == 8, "retry draws at +60");
    expect_stem(&f, &ds, 0, NO_PEER, NO_PEER, "second refusal still fluffs");

    /* Back up: the next retry selects peers and starts a real epoch. */
    atomic_store(&g_now_s, 1060 + 59);
    rng_begin(word, 1);
    dandelion_maybe_rotate_epoch(&ds, &g_nm);
    mchk(&f, g_rb_pos == 0, "no draw at +59 after the second refusal");
    atomic_store(&g_now_s, 1060 + 60);
    dandelion_maybe_rotate_epoch(&ds, &g_nm);
    mchk(&f, g_rb_pos == 8, "second retry draws");
    expect_stem(&f, &ds, 2, 12, 11, "second retry selects stem peers");
    mchk(&f, ds.epoch_start == 1120, "a good rotation stamps a full epoch");

    atomic_store(&g_now_s, 1120 + 599);
    dandelion_maybe_rotate_epoch(&ds, &g_nm);
    mchk(&f, g_rb_pos == 8, "the good epoch runs its full length");
    rng_end();
    clock_end();
    dandelion_free(&ds);
    nm_done();
    return f;
}

static int check_rotate_epoch_window(void)
{
    int f = 0;
    struct dandelion_state ds;
    nm_reset();
    nm_add(5, false, PEER_ACTIVE, false, true);

    /* A fresh state rotates at once, even at a small clock reading. */
    dandelion_init(&ds);
    clock_begin(100);
    dandelion_maybe_rotate_epoch(&ds, &g_nm);
    expect_stem(&f, &ds, 1, 5, NO_PEER, "fresh state rotates at t=100");
    mchk(&f, ds.epoch_start == 100, "epoch stamped 100");

    g_peers[0].id = 6;
    atomic_store(&g_now_s, 100 + 599);
    dandelion_maybe_rotate_epoch(&ds, &g_nm);
    expect_stem(&f, &ds, 1, 5, NO_PEER, "no rotation at +599");
    mchk(&f, ds.epoch_start == 100, "epoch kept at +599");

    atomic_store(&g_now_s, 100 + 600);
    dandelion_maybe_rotate_epoch(&ds, &g_nm);
    expect_stem(&f, &ds, 1, 6, NO_PEER, "rotation at exactly +600");
    mchk(&f, ds.epoch_start == 700, "epoch restamped at +600");
    dandelion_free(&ds);

    /* epoch_start == 1 is a real, running epoch, not the unset marker. */
    ds_stale(&ds);
    ds.epoch_start = 1;
    atomic_store(&g_now_s, 5);
    dandelion_maybe_rotate_epoch(&ds, &g_nm);
    expect_stem(&f, &ds, 2, 99, 98, "epoch_start 1 at t=5 keeps peers");
    mchk(&f, ds.stem_rr_index == 1, "rr kept inside a running epoch");
    clock_end();
    dandelion_free(&ds);
    nm_done();
    return f;
}

static int check_rotate_null_args(void)
{
    int f = 0;
    struct dandelion_state ds;
    nm_reset();
    nm_add(5, false, PEER_ACTIVE, false, true);
    ds_stale(&ds);
    clock_begin(1000);
    dandelion_maybe_rotate_epoch(&ds, NULL);
    mchk(&f, ds.epoch_start == 0, "NULL nm leaves the epoch alone");
    expect_stem(&f, &ds, 2, 99, 98, "NULL nm leaves the peers alone");
    dandelion_maybe_rotate_epoch(NULL, &g_nm);
    clock_end();
    dandelion_free(&ds);
    nm_done();
    return f;
}

/* ── stem pool ─────────────────────────────────────────────────── */

static int check_pool_embargo_boundaries(void)
{
    int f = 0;
    struct dandelion_state ds;
    struct uint256 out[2];
    struct uint256 h1 = hash_of(1), h2 = hash_of(2), h3 = hash_of(3);
    dandelion_init(&ds);
    clock_begin(5000);
    dandelion_stempool_add(&ds, &h1, 7);
    atomic_store(&g_now_s, 5001);
    dandelion_stempool_add(&ds, &h2, 8);
    mchk(&f, ds.stempool[0].embargo_time == 5030, "embargo = now + 30");
    mchk(&f, ds.stempool[0].from_peer == 7, "from_peer recorded");
    mchk(&f, ds.stempool[1].embargo_time == 5031, "second embargo");

    atomic_store(&g_now_s, 5029);
    mchk(&f, dandelion_stempool_check_embargo(&ds, out, 2) == 0,
         "nothing released at +29");
    mchk(&f, ds.stempool_count == 2, "pool intact at +29");

    atomic_store(&g_now_s, 5030);
    mchk(&f, dandelion_stempool_check_embargo(&ds, out, 2) == 1,
         "one released at exactly +30");
    mchk(&f, uint256_eq(&out[0], &h1), "released the 5030 entry");
    mchk(&f, !dandelion_stempool_contains(&ds, &h1), "released entry gone");
    mchk(&f, dandelion_stempool_contains(&ds, &h2), "later entry stays");
    mchk(&f, ds.stempool_count == 1, "count drops on release");
    mchk(&f, ds.stat_embargo_fluff == 1, "embargo fluff counted");
    mchk(&f, dandelion_stempool_check_embargo(&ds, out, 2) == 0,
         "released entry not released twice");

    /* Two expired, room for one: exactly one comes out. h3 reuses slot 0. */
    dandelion_stempool_add(&ds, &h3, 9);
    atomic_store(&g_now_s, 5060);
    mchk(&f, dandelion_stempool_check_embargo(&ds, out, 1) == 1,
         "max_out 1 releases one");
    mchk(&f, uint256_eq(&out[0], &h3), "slot order release");
    mchk(&f, dandelion_stempool_contains(&ds, &h2), "second expired waits");
    mchk(&f, dandelion_stempool_check_embargo(&ds, out, 1) == 1,
         "next call releases the other");
    mchk(&f, uint256_eq(&out[0], &h2), "other released");
    mchk(&f, ds.stempool_count == 0, "pool drained");
    clock_end();
    dandelion_free(&ds);
    return f;
}

static int check_pool_embargo_null_args(void)
{
    int f = 0;
    struct dandelion_state ds;
    struct uint256 out[2];
    struct uint256 h = hash_of(1);
    dandelion_init(&ds);
    clock_begin(5000);
    dandelion_stempool_add(&ds, &h, 1);
    atomic_store(&g_now_s, 6000);
    mchk(&f, dandelion_stempool_check_embargo(&ds, NULL, 4) == 0, "NULL out");
    mchk(&f, dandelion_stempool_check_embargo(&ds, out, 0) == 0, "max_out 0");
    mchk(&f, dandelion_stempool_check_embargo(&ds, out, -1) == 0, "max_out -1");
    mchk(&f, dandelion_stempool_check_embargo(NULL, out, 4) == 0, "NULL ds");
    mchk(&f, dandelion_stempool_contains(&ds, &h), "refused calls keep entry");
    mchk(&f, ds.stempool_count == 1, "refused calls keep count");
    clock_end();
    dandelion_free(&ds);
    return f;
}

static void fill_pool(struct dandelion_state *ds)
{
    for (int i = 0; i < DANDELION_MAX_STEMPOOL; i++) {
        struct uint256 h = hash_of(i);
        dandelion_stempool_add(ds, &h, 1);
    }
}

static bool has(struct dandelion_state *ds, int i)
{
    struct uint256 h = hash_of(i);
    return dandelion_stempool_contains(ds, &h);
}

static int check_pool_eviction_picks_oldest(void)
{
    int f = 0;
    struct dandelion_state ds;
    struct uint256 extra = hash_of(0x7fff);
    clock_begin(7000);

    /* All embargoes tie: the first slot is the oldest. */
    dandelion_init(&ds);
    fill_pool(&ds);
    dandelion_stempool_add(&ds, &extra, 2);
    mchk(&f, !has(&ds, 0), "tie: first slot evicted");
    mchk(&f, has(&ds, DANDELION_MAX_STEMPOOL - 1), "tie: last slot kept");
    mchk(&f, dandelion_stempool_contains(&ds, &extra), "tie: new entry in");
    mchk(&f, ds.stempool_count == DANDELION_MAX_STEMPOOL, "tie: count");
    dandelion_free(&ds);

    /* One slot genuinely older than the rest. */
    dandelion_init(&ds);
    fill_pool(&ds);
    ds.stempool[5].embargo_time = 6000;
    dandelion_stempool_add(&ds, &extra, 2);
    mchk(&f, !has(&ds, 5), "oldest slot evicted");
    mchk(&f, has(&ds, 0), "younger first slot kept");
    mchk(&f, ds.stempool_count == DANDELION_MAX_STEMPOOL, "oldest: count");
    dandelion_free(&ds);

    /* Embargoes at the ceiling never beat the starting minimum: slot 0. */
    dandelion_init(&ds);
    fill_pool(&ds);
    for (int i = 0; i < DANDELION_MAX_STEMPOOL; i++)
        ds.stempool[i].embargo_time = INT64_MAX;
    dandelion_stempool_add(&ds, &extra, 2);
    mchk(&f, !has(&ds, 0), "ceiling: slot 0 evicted");
    mchk(&f, has(&ds, 1), "ceiling: slot 1 kept");
    clock_end();
    dandelion_free(&ds);
    return f;
}

static int check_pool_membership_precision(void)
{
    int f = 0;
    struct dandelion_state ds;
    struct uint256 a = hash_of(1), b = hash_of(2), z = hash_of(3);
    dandelion_init(&ds);
    dandelion_stempool_add(&ds, &a, 3);
    dandelion_stempool_add(&ds, &a, 4);
    mchk(&f, ds.stempool_count == 1, "duplicate add ignored");
    mchk(&f, ds.stempool[0].from_peer == 3, "duplicate keeps first sender");
    mchk(&f, !dandelion_stempool_remove(&ds, &z), "remove unknown is false");
    mchk(&f, ds.stempool_count == 1, "remove unknown keeps count");
    dandelion_stempool_add(&ds, &b, 5);
    mchk(&f, dandelion_stempool_remove(&ds, &b), "remove second hash");
    mchk(&f, dandelion_stempool_contains(&ds, &a), "first hash unharmed");
    mchk(&f, !dandelion_stempool_contains(&ds, &b), "second hash gone");
    mchk(&f, !dandelion_stempool_remove(&ds, &b), "second remove is false");
    mchk(&f, ds.stempool_count == 1, "second remove keeps count");

    /* NULL arguments with a live entry in the pool. */
    dandelion_stempool_add(&ds, NULL, 1);
    dandelion_stempool_add(NULL, &a, 1);
    mchk(&f, ds.stempool_count == 1, "NULL add changes nothing");
    mchk(&f, !dandelion_stempool_remove(&ds, NULL), "remove NULL hash");
    mchk(&f, !dandelion_stempool_remove(NULL, &a), "remove NULL ds");
    mchk(&f, !dandelion_stempool_contains(&ds, NULL), "contains NULL hash");
    mchk(&f, !dandelion_stempool_contains(NULL, &a), "contains NULL ds");
    dandelion_free(&ds);
    return f;
}

/* ── lock balance ──────────────────────────────────────────────── */

static void lk_should_stem(int *f)
{
    struct dandelion_state ds;
    dandelion_init(&ds);
    ds.enabled = false;
    zcl_mutex_lock(&ds.cs);
    (void)dandelion_should_stem(&ds, NO_PEER);
    bal(f, &ds.cs, "should_stem disabled");
    ds.enabled = true;
    zcl_mutex_lock(&ds.cs);
    (void)dandelion_should_stem(&ds, NO_PEER);
    bal(f, &ds.cs, "should_stem no peers");
    ds.num_stem_peers = 1;
    ds.stem_peers[0] = 5;
    const uint64_t coin[] = { 50 };
    rng_begin(coin, 1);
    zcl_mutex_lock(&ds.cs);
    (void)dandelion_should_stem(&ds, NO_PEER);
    bal(f, &ds.cs, "should_stem coin");
    rng_end();
    rng_begin(NULL, 0);
    zcl_mutex_lock(&ds.cs);
    (void)dandelion_should_stem(&ds, NO_PEER);
    bal(f, &ds.cs, "should_stem RNG refusal");
    rng_end();
    dandelion_free(&ds);
}

static void lk_get_stem_peer(int *f)
{
    struct dandelion_state ds;
    dandelion_init(&ds);
    zcl_mutex_lock(&ds.cs);
    (void)dandelion_get_stem_peer(&ds, NO_PEER);
    bal(f, &ds.cs, "get_stem_peer no peers");
    ds.num_stem_peers = 1;
    ds.stem_peers[0] = 5;
    zcl_mutex_lock(&ds.cs);
    (void)dandelion_get_stem_peer(&ds, NO_PEER);
    bal(f, &ds.cs, "get_stem_peer chosen");
    dandelion_free(&ds);
}

static void lk_pool(int *f)
{
    struct dandelion_state ds;
    struct uint256 h = hash_of(1), z = hash_of(2);
    struct uint256 out[2];
    dandelion_init(&ds);
    clock_begin(5000);
    zcl_mutex_lock(&ds.cs);
    dandelion_stempool_add(&ds, &h, 1);
    bal(f, &ds.cs, "stempool_add new");
    zcl_mutex_lock(&ds.cs);
    dandelion_stempool_add(&ds, &h, 1);
    bal(f, &ds.cs, "stempool_add duplicate");
    zcl_mutex_lock(&ds.cs);
    (void)dandelion_stempool_contains(&ds, &h);
    bal(f, &ds.cs, "contains found");
    zcl_mutex_lock(&ds.cs);
    (void)dandelion_stempool_contains(&ds, &z);
    bal(f, &ds.cs, "contains missing");
    atomic_store(&g_now_s, 5100);
    zcl_mutex_lock(&ds.cs);
    (void)dandelion_stempool_check_embargo(&ds, out, 2);
    bal(f, &ds.cs, "check_embargo");
    clock_end();
    dandelion_stempool_add(&ds, &h, 1);
    zcl_mutex_lock(&ds.cs);
    (void)dandelion_stempool_remove(&ds, &h);
    bal(f, &ds.cs, "remove found");
    zcl_mutex_lock(&ds.cs);
    (void)dandelion_stempool_remove(&ds, &h);
    bal(f, &ds.cs, "remove missing");
    dandelion_free(&ds);
}

/* One rotation with ds->cs and cs_nodes both held once by the caller. */
static void rotate_locked(int *f, struct dandelion_state *ds,
                          const char *what)
{
    zcl_mutex_lock(&ds->cs);
    zcl_mutex_lock(&g_nm.cs_nodes);
    dandelion_maybe_rotate_epoch(ds, &g_nm);
    bal(f, &ds->cs, what);
    bal(f, &g_nm.cs_nodes, what);
}

static void lk_rotate(int *f)
{
    struct dandelion_state ds;
    const uint64_t pair[] = { 2 };
    nm_filter_fixture();
    clock_begin(1000);

    dandelion_init(&ds);
    ds.epoch_start = 1000;
    rotate_locked(f, &ds, "rotate inside the epoch");
    dandelion_free(&ds);

    dandelion_init(&ds);
    rng_begin(pair, 1);
    rotate_locked(f, &ds, "rotate success");
    rng_end();
    dandelion_free(&ds);

    dandelion_init(&ds);
    rng_begin(NULL, 0);
    rotate_locked(f, &ds, "rotate RNG refusal");
    rng_end();
    dandelion_free(&ds);
    clock_end();
    nm_done();
}

static int check_lock_balance(void)
{
    int f = 0;
    struct dandelion_state probe;
    dandelion_init(&probe);
    zcl_mutex_lock(&probe.cs);
    bool recursive = zcl_mutex_trylock(&probe.cs);
    if (recursive)
        zcl_mutex_unlock(&probe.cs);
    zcl_mutex_unlock(&probe.cs);
    dandelion_free(&probe);
    mchk(&f, recursive, "state mutex is recursive (lock probe needs it)");
    if (!recursive)
        return f;
    lk_should_stem(&f);
    lk_get_stem_peer(&f);
    lk_pool(&f);
    lk_rotate(&f);
    return f;
}

/* ── driver ────────────────────────────────────────────────────── */

typedef int (*group_fn)(void);

static int run_group(const char *name, group_fn fn)
{
    printf("dandelion mutants: %s... ", name);
    int n = fn();
    if (n == 0)
        printf("OK\n");
    else
        printf("\n  (%d failures)\n", n);
    return n;
}

int dandelion_mutation_gap_tests(void)
{
    int failures = 0;
    failures += run_group("lifecycle", check_lifecycle);
    failures += run_group("get_stem_peer routing", check_get_stem_peer_routing);
    failures += run_group("coin hook", check_coin_hook);
    failures += run_group("should_stem decision", check_should_stem_decision);
    failures += run_group("shuffle", check_hook_shuffle);
    failures += run_group("rotate filter", check_rotate_filter_and_shuffle);
    failures += run_group("rotate cap", check_rotate_caps_candidates_at_eight);
    failures += run_group("rotate small sets", check_rotate_small_candidate_sets);
    failures += run_group("rotate RNG failure", check_rotate_rng_failure);
    failures += run_group("rotate RNG retry",
                          check_rotate_rng_failure_retries_in_a_minute);
    failures += run_group("rotate window", check_rotate_epoch_window);
    failures += run_group("rotate NULL", check_rotate_null_args);
    failures += run_group("embargo bounds", check_pool_embargo_boundaries);
    failures += run_group("embargo NULL", check_pool_embargo_null_args);
    failures += run_group("pool eviction", check_pool_eviction_picks_oldest);
    failures += run_group("pool membership", check_pool_membership_precision);
    failures += run_group("lock balance", check_lock_balance);
    return failures;
}
