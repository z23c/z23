/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Group `mesh_observation_compose` — the reader-side fold.
 *
 * WHAT THIS GROUP DEFENDS. The recurring defect in this tree is a gate that
 * reports confidently having examined nothing: a tripwire that said HEALTHY
 * over ZERO rungs, a cache audit that said PASS on "0 verified, 0 divergent",
 * a mesh gate whose passing condition (`state == active`) could never be
 * true. Every check below therefore carries a FAIL-ARM: an input for which
 * the check MUST report the negative. A suite that only proved the happy path
 * would be worthless here.
 *
 * The properties, each with its arm:
 *   1. Zero observations yields UNVERIFIED and never healthy.
 *   2. A silent node never reads as agreement — silence can only lower
 *      coverage, which moves the result toward UNVERIFIED.
 *   3. Disagreement never resolves by deferring to a designated box: no
 *      majority rule, no tie-break, no slot with ordering privilege, and no
 *      single record whose removal blocks the remaining readers.
 *   4. A slow-but-reachable node grades as reachable with slow telemetry and
 *      never as failed — the composer cannot even see timing.
 *   5. Every state and every basis token is shown REACHABLE by a constructed
 *      input, so no condition in the fold is a `state == active` repeat.
 */

#include "test/test_core.h"
#include "services/mesh_observation.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* ── fixtures ─────────────────────────────────────────────────────────── */

#define OBS_NOW        1756064111
#define OBS_BASE_TIP   2413907

/* Two deterministic hash families. `flavor` selects which chain the reader
 * believes it is on; the anti-trust arm flips it with the records untouched. */
static void obs_hash_for(int flavor, int64_t height, char out[65])
{
    snprintf(out, 65, "%064llx",
             (unsigned long long)(height + (flavor ? 0x1000000LL : 0LL)));
}

struct obs_reader_ctx {
    int     flavor;
    int64_t tip;
    int64_t floor;
};

static bool obs_reader_hash_at(void *vctx, int64_t height, char out[65])
{
    struct obs_reader_ctx *c = (struct obs_reader_ctx *)vctx;
    if (!c || !out) return false;
    if (height < c->floor || height > c->tip) return false;
    obs_hash_for(c->flavor, height, out);
    return true;
}

/* Bind to the production symbol, not a private copy — see the note in
 * test_mesh_observation.c. */
#define k_obs_back MESH_OBS_ANCHOR_BACK

/* Build one fresh, parsed slot whose five anchors sit on `flavor`'s chain. */
static void obs_make_slot(struct mesh_obs_slot *s, const char *onion,
                          int64_t tip_height, int flavor, int64_t sampled_unix)
{
    memset(s, 0, sizeof(*s));
    snprintf(s->onion, sizeof(s->onion), "%s", onion);
    s->fetch = MESH_OBS_CONFIRMED;
    s->parsed = true;
    s->fetched_unix = sampled_unix;
    s->deadline_us = 45000000;

    snprintf(s->rec.self.schema, sizeof(s->rec.self.schema), "%s",
             MESH_OBS_SCHEMA);
    snprintf(s->rec.self.onion, sizeof(s->rec.self.onion), "%s", onion);
    snprintf(s->rec.self.source_id, sizeof(s->rec.self.source_id), "%s",
             onion);
    s->rec.self.tip_height = tip_height;
    obs_hash_for(flavor, tip_height, s->rec.self.tip_hash_hex);
    snprintf(s->rec.self.tip_chainwork_hex,
             sizeof(s->rec.self.tip_chainwork_hex), "%064llx",
             (unsigned long long)(tip_height * 1000LL));
    s->rec.self.tip_time_unix = sampled_unix - 40;
    s->rec.self.sampled_unix = sampled_unix;
    s->rec.self.fsync_us = 900;
    s->rec.self.pread_us = 40;
    s->rec.self.cores = 32;

    for (int i = 0; i < MESH_OBS_ANCHORS; i++) {
        int64_t h = tip_height - k_obs_back[i];
        s->rec.self.anchors[i].height = h;
        s->rec.self.anchors[i].present = true;
        obs_hash_for(flavor, h, s->rec.self.anchors[i].hash_hex);
    }
}

/* Turn a slot silent: the fetch hit its budget. DEADLINE is the only outcome
 * a budget may ever produce; it is not REFUSED and not a failure. */
static void obs_make_silent(struct mesh_obs_slot *s, const char *onion)
{
    memset(s, 0, sizeof(*s));
    snprintf(s->onion, sizeof(s->onion), "%s", onion);
    s->fetch = MESH_OBS_DEADLINE;
    s->elapsed_us = 45000000;
    s->deadline_us = 45000000;
    s->parsed = false;
}

static void obs_fill_key_hex(char *dst, size_t dstsz, unsigned seed)
{
    static const char hexd[] = "0123456789abcdef";
    size_t want = (size_t)(NET_SERVICE_KEY_SIZE * 2);
    if (want >= dstsz) want = dstsz - 1;
    for (size_t i = 0; i < want; i++) {
        seed = seed * 1664525u + 1013904223u;
        dst[i] = hexd[(seed >> 16) & 0xF];
    }
    dst[want] = '\0';
}

static void obs_add_edge(struct mesh_obs_slot *s, const char *peer_onion,
                         int64_t claimed_height, const char *claimed_hash)
{
    if (s->rec.edge_count >= MESH_OBS_EDGES_MAX) return;
    struct mesh_obs_edge *e = &s->rec.edges[s->rec.edge_count++];
    memset(e, 0, sizeof(*e));
    snprintf(e->peer_onion, sizeof(e->peer_onion), "%s", peer_onion);
    obs_fill_key_hex(e->peer_key_hex, sizeof(e->peer_key_hex),
                     (unsigned)peer_onion[0]);
    e->transport = MESH_OBS_CONFIRMED;
    e->stage = MESH_STAGE_HANDSHAKE_COMPLETE;
    e->stage_elapsed_us = 38214000;
    e->deadline_us = 120000000;
    e->claimed_height = claimed_height;
    if (claimed_hash)
        snprintf(e->claimed_tip_hash_hex, sizeof(e->claimed_tip_hash_hex),
                 "%s", claimed_hash);
    e->header_service = MESH_OBS_CONFIRMED;
}

static const struct mesh_compose_budget k_obs_budget = {
    .freshness_secs = 900, .min_independent = 2
};

static void obs_reader_init(struct mesh_reader_chain *r,
                            struct obs_reader_ctx *c, int flavor)
{
    memset(r, 0, sizeof(*r));
    memset(c, 0, sizeof(*c));
    c->flavor = flavor;
    c->tip = OBS_BASE_TIP;
    c->floor = OBS_BASE_TIP - 1000;
    r->tip_height = c->tip;
    snprintf(r->tip_chainwork_hex, sizeof(r->tip_chainwork_hex), "%064llx",
             (unsigned long long)(OBS_BASE_TIP * 1000LL));
    r->hash_at = obs_reader_hash_at;
    r->ctx = c;
}

/* Field-by-field equality. memcmp would compare struct padding. */
static bool obs_conclusion_eq(const struct mesh_conclusion *a,
                              const struct mesh_conclusion *b)
{
    return a->records_offered == b->records_offered &&
           a->records_parsed == b->records_parsed &&
           a->records_fresh == b->records_fresh &&
           a->records_silent == b->records_silent &&
           a->records_not_probed == b->records_not_probed &&
           a->records_malformed == b->records_malformed &&
           a->distinct_identities == b->distinct_identities &&
           a->min_independent_required == b->min_independent_required &&
           a->agree_at_anchor == b->agree_at_anchor &&
           a->disagree_at_anchor == b->disagree_at_anchor &&
           a->no_common_height == b->no_common_height &&
           a->checked_height == b->checked_height &&
           strcmp(a->reader_hash_at_checked, b->reader_hash_at_checked) == 0 &&
           a->edges_asserted == b->edges_asserted &&
           a->edges_reciprocated == b->edges_reciprocated &&
           a->edges_one_sided == b->edges_one_sided &&
           a->edges_contradicted == b->edges_contradicted &&
           strcmp(a->max_chainwork_hex, b->max_chainwork_hex) == 0 &&
           a->reader_holds_max_chainwork == b->reader_holds_max_chainwork &&
           a->state == b->state &&
           strcmp(a->basis, b->basis) == 0;
}

/* ── 1. zero observations ─────────────────────────────────────────────── */

/* FAIL-ARM. Remove the `records_fresh == 0` early return and this case starts
 * returning AGREEING over an empty input — the exact shape that made a
 * tripwire report HEALTHY having compared zero rungs. */
static int t_zero_records_is_unverified(void)
{
    int failures = 0;
    TEST_CASE("compose: zero records is UNVERIFIED, never healthy")
    {
        struct mesh_reader_chain reader;
        struct obs_reader_ctx ctx;
        obs_reader_init(&reader, &ctx, 0);

        struct mesh_conclusion c;
        memset(&c, 0xAA, sizeof(c));   /* poisoned: nothing may survive */
        mesh_observation_compose(NULL, 0, &reader, &k_obs_budget, OBS_NOW, &c);

        ASSERT(c.state == MESH_UNVERIFIED);
        ASSERT(c.state != MESH_AGREEING);
        ASSERT(c.state != MESH_SPLIT_VIEW);
        ASSERT(c.state != MESH_DISAGREEING);
        ASSERT_STR_EQ(c.basis, "no_fresh_records");
        ASSERT_EQ(c.records_offered, 0);
        ASSERT_EQ(c.records_fresh, 0);
        ASSERT_EQ(c.agree_at_anchor, 0);
        ASSERT_EQ(c.disagree_at_anchor, 0);
        ASSERT_EQ(c.distinct_identities, 0);
        /* the control in force is echoed even on the empty path, so a reader
         * can see WHICH bar was not met */
        ASSERT_EQ(c.min_independent_required, 2);
        ASSERT_STR_EQ(mesh_state_name(c.state), "unverified");
    } TEST_END
    return failures;
}

/* FAIL-ARM. Four slots we never asked, and four we asked that timed out:
 * both are zero evidence. If a deadline ever leaked into a failure tally or
 * a not-probed slot ever counted as looked-at, these counts move. */
static int t_all_dark_is_unverified(void)
{
    int failures = 0;
    TEST_CASE("compose: all not_probed / all deadline is UNVERIFIED")
    {
        struct mesh_reader_chain reader;
        struct obs_reader_ctx ctx;
        obs_reader_init(&reader, &ctx, 0);

        struct mesh_obs_slot dark[4];
        memset(dark, 0, sizeof(dark));  /* zeroed == NOT_PROBED, by design */
        for (int i = 0; i < 4; i++)
            snprintf(dark[i].onion, sizeof(dark[i].onion), "dark%d.onion", i);

        struct mesh_conclusion c;
        mesh_observation_compose(dark, 4, &reader, &k_obs_budget, OBS_NOW, &c);
        ASSERT(c.state == MESH_UNVERIFIED);
        ASSERT_STR_EQ(c.basis, "no_fresh_records");
        ASSERT_EQ(c.records_offered, 4);
        ASSERT_EQ(c.records_not_probed, 4);
        ASSERT_EQ(c.records_silent, 0);
        ASSERT_EQ(c.records_fresh, 0);

        struct mesh_obs_slot late[4];
        for (int i = 0; i < 4; i++) {
            char on[64];
            snprintf(on, sizeof(on), "late%d.onion", i);
            obs_make_silent(&late[i], on);
        }
        struct mesh_conclusion d;
        mesh_observation_compose(late, 4, &reader, &k_obs_budget, OBS_NOW, &d);
        ASSERT(d.state == MESH_UNVERIFIED);
        ASSERT_STR_EQ(d.basis, "no_fresh_records");
        ASSERT_EQ(d.records_silent, 4);
        ASSERT_EQ(d.records_not_probed, 0);
        ASSERT_EQ(d.agree_at_anchor, 0);
        ASSERT_EQ(d.disagree_at_anchor, 0);
    } TEST_END
    return failures;
}

/* A stale-but-parsed document is coverage, not evidence. FAIL-ARM for a
 * freshness window that is silently ignored: the SAME two records flip to
 * AGREEING once the reader widens its own window. */
static int t_stale_record_is_not_fresh(void)
{
    int failures = 0;
    TEST_CASE("compose: a parsed-but-stale record is counted, never trusted")
    {
        struct mesh_reader_chain reader;
        struct obs_reader_ctx ctx;
        obs_reader_init(&reader, &ctx, 0);

        struct mesh_obs_slot s[2];
        obs_make_slot(&s[0], "aaa.onion", OBS_BASE_TIP, 0, OBS_NOW - 100000);
        obs_make_slot(&s[1], "bbb.onion", OBS_BASE_TIP, 0, OBS_NOW - 100000);

        struct mesh_conclusion c;
        mesh_observation_compose(s, 2, &reader, &k_obs_budget, OBS_NOW, &c);
        ASSERT(c.state == MESH_UNVERIFIED);
        ASSERT_STR_EQ(c.basis, "no_fresh_records");
        ASSERT_EQ(c.records_parsed, 2);
        ASSERT_EQ(c.records_fresh, 0);

        struct mesh_compose_budget wide = { .freshness_secs = 200000,
                                            .min_independent = 2 };
        struct mesh_conclusion w;
        mesh_observation_compose(s, 2, &reader, &wide, OBS_NOW, &w);
        ASSERT_EQ(w.records_fresh, 2);
        ASSERT(w.state == MESH_AGREEING);
    } TEST_END
    return failures;
}

/* ── 2. N = 1 ─────────────────────────────────────────────────────────── */

/* FAIL-ARM against the inverted shape at quorum_oracle_service.c:311, where a
 * lone honest node with one hash lands on SPLIT — "the network disagrees"
 * asserted from a sample of one. One record is neither agreement nor
 * disagreement; it is "I cannot corroborate". */
static int t_only_self_is_unverified(void)
{
    int failures = 0;
    TEST_CASE("compose: N=1 is UNVERIFIED/only_self, not split and not failed")
    {
        struct mesh_reader_chain reader;
        struct obs_reader_ctx ctx;
        obs_reader_init(&reader, &ctx, 0);

        struct mesh_obs_slot s[1];
        obs_make_slot(&s[0], "self.onion", OBS_BASE_TIP, 0, OBS_NOW - 5);

        struct mesh_conclusion c;
        mesh_observation_compose(s, 1, &reader, &k_obs_budget, OBS_NOW, &c);
        ASSERT(c.state == MESH_UNVERIFIED);
        ASSERT(c.state != MESH_SPLIT_VIEW);
        ASSERT(c.state != MESH_DISAGREEING);
        ASSERT(c.state != MESH_AGREEING);
        ASSERT_STR_EQ(c.basis, "only_self");
        ASSERT_EQ(c.records_fresh, 1);
        ASSERT_EQ(c.distinct_identities, 1);
        /* the fold refused BEFORE recomputing: no tally was invented */
        ASSERT_EQ(c.agree_at_anchor, 0);
        ASSERT_EQ(c.disagree_at_anchor, 0);
    } TEST_END
    return failures;
}

/* ── 3. a silent node is never agreement ──────────────────────────────── */

static int t_silence_never_becomes_agreement(void)
{
    int failures = 0;
    TEST_CASE("compose: silence lowers coverage and can never raise agreement")
    {
        struct mesh_reader_chain reader;
        struct obs_reader_ctx ctx;
        obs_reader_init(&reader, &ctx, 0);

        /* (a) three agreeing + one that hit its fetch budget */
        struct mesh_obs_slot a[4];
        obs_make_slot(&a[0], "n1.onion", OBS_BASE_TIP, 0, OBS_NOW - 10);
        obs_make_slot(&a[1], "n2.onion", OBS_BASE_TIP, 0, OBS_NOW - 20);
        obs_make_slot(&a[2], "n3.onion", OBS_BASE_TIP, 0, OBS_NOW - 30);
        obs_make_silent(&a[3], "n4.onion");

        struct mesh_conclusion c;
        mesh_observation_compose(a, 4, &reader, &k_obs_budget, OBS_NOW, &c);
        ASSERT_EQ(c.records_silent, 1);
        ASSERT_EQ(c.records_fresh, 3);
        ASSERT_EQ(c.agree_at_anchor, 3);
        ASSERT_EQ(c.disagree_at_anchor, 0);
        /* the silent slot touched nothing else */
        ASSERT_EQ(c.distinct_identities, 3);
        ASSERT_EQ(c.no_common_height, 0);
        ASSERT(c.state == MESH_AGREEING);

        /* (b) two agreeing + two silent: still AGREEING at min_independent=2,
         *     but the reader can SEE that half the fleet said nothing. */
        struct mesh_obs_slot b[4];
        obs_make_slot(&b[0], "n1.onion", OBS_BASE_TIP, 0, OBS_NOW - 10);
        obs_make_slot(&b[1], "n2.onion", OBS_BASE_TIP, 0, OBS_NOW - 20);
        obs_make_silent(&b[2], "n3.onion");
        obs_make_silent(&b[3], "n4.onion");
        struct mesh_conclusion d;
        mesh_observation_compose(b, 4, &reader, &k_obs_budget, OBS_NOW, &d);
        ASSERT(d.state == MESH_AGREEING);
        ASSERT_EQ(d.records_silent, 2);
        ASSERT_EQ(d.agree_at_anchor, 2);

        /* (c) one agreeing + three silent: coverage collapses -> UNVERIFIED.
         *     FAIL-ARM: if silence were ever treated as assent this stays
         *     AGREEING. */
        struct mesh_obs_slot e[4];
        obs_make_slot(&e[0], "n1.onion", OBS_BASE_TIP, 0, OBS_NOW - 10);
        obs_make_silent(&e[1], "n2.onion");
        obs_make_silent(&e[2], "n3.onion");
        obs_make_silent(&e[3], "n4.onion");
        struct mesh_conclusion f;
        mesh_observation_compose(e, 4, &reader, &k_obs_budget, OBS_NOW, &f);
        ASSERT(f.state == MESH_UNVERIFIED);
        ASSERT(f.state != MESH_AGREEING);
        ASSERT_EQ(f.records_silent, 3);
        ASSERT_EQ(f.records_fresh, 1);
        ASSERT_EQ(f.distinct_identities, 1);
    } TEST_END
    return failures;
}

/* A silent node whose last edge row still sits in a peer's document must show
 * up as one_sided, never reciprocated. FAIL-ARM for reciprocity computed from
 * the asserting side alone. */
static int t_silent_peer_edge_is_one_sided(void)
{
    int failures = 0;
    TEST_CASE("compose: an edge to a silent peer is one_sided, not reciprocated")
    {
        struct mesh_reader_chain reader;
        struct obs_reader_ctx ctx;
        obs_reader_init(&reader, &ctx, 0);

        struct mesh_obs_slot s[3];
        obs_make_slot(&s[0], "n1.onion", OBS_BASE_TIP, 0, OBS_NOW - 10);
        obs_make_slot(&s[1], "n2.onion", OBS_BASE_TIP, 0, OBS_NOW - 10);
        obs_make_silent(&s[2], "n3.onion");
        obs_add_edge(&s[0], "n3.onion", -1, NULL);   /* n3 said nothing */

        struct mesh_conclusion c;
        mesh_observation_compose(s, 3, &reader, &k_obs_budget, OBS_NOW, &c);
        ASSERT_EQ(c.edges_asserted, 1);
        ASSERT_EQ(c.edges_one_sided, 1);
        ASSERT_EQ(c.edges_reciprocated, 0);
        ASSERT_EQ(c.records_silent, 1);
    } TEST_END
    return failures;
}

/* ── 4. disagreement defers to nobody ─────────────────────────────────── */

/* FAIL-ARM against a majority rule. If anyone adds `if (agree > disagree)`
 * this returns AGREEING and the assertion fires. */
static int t_disagreement_is_never_outvoted(void)
{
    int failures = 0;
    TEST_CASE("compose: 9 agree + 1 disagree is SPLIT_VIEW, never AGREEING")
    {
        struct mesh_reader_chain reader;
        struct obs_reader_ctx ctx;
        obs_reader_init(&reader, &ctx, 0);

        struct mesh_obs_slot s[10];
        for (int i = 0; i < 9; i++) {
            char on[64];
            snprintf(on, sizeof(on), "agree%d.onion", i);
            obs_make_slot(&s[i], on, OBS_BASE_TIP, 0, OBS_NOW - 10);
        }
        obs_make_slot(&s[9], "rebel.onion", OBS_BASE_TIP, 1, OBS_NOW - 10);

        struct mesh_conclusion c;
        mesh_observation_compose(s, 10, &reader, &k_obs_budget, OBS_NOW, &c);
        ASSERT(c.state == MESH_SPLIT_VIEW);
        ASSERT(c.state != MESH_AGREEING);
        ASSERT_EQ(c.agree_at_anchor, 9);
        ASSERT_EQ(c.disagree_at_anchor, 1);
        /* both tallies survive into the output: a reader sees the split, not
         * a winner */
        ASSERT(strstr(c.basis, "agree=9") != NULL);
        ASSERT(strstr(c.basis, "disagree=1") != NULL);
        ASSERT_STR_EQ(mesh_state_name(c.state), "split_view");

        /* the mirror: 1 agree + 9 disagree is ALSO split, not "disagreeing
         * by majority". No tie-break exists, in either direction. */
        struct mesh_obs_slot m[10];
        for (int i = 0; i < 9; i++) {
            char on[64];
            snprintf(on, sizeof(on), "rebel%d.onion", i);
            obs_make_slot(&m[i], on, OBS_BASE_TIP, 1, OBS_NOW - 10);
        }
        obs_make_slot(&m[9], "loyal.onion", OBS_BASE_TIP, 0, OBS_NOW - 10);
        struct mesh_conclusion d;
        mesh_observation_compose(m, 10, &reader, &k_obs_budget, OBS_NOW, &d);
        ASSERT(d.state == MESH_SPLIT_VIEW);
        ASSERT_EQ(d.agree_at_anchor, 1);
        ASSERT_EQ(d.disagree_at_anchor, 9);
    } TEST_END
    return failures;
}

/* Unanimous counter-evidence is DISAGREEING — a distinct, reachable state. */
static int t_unanimous_counterevidence_is_disagreeing(void)
{
    int failures = 0;
    TEST_CASE("compose: all records contradict the reader -> DISAGREEING")
    {
        struct mesh_reader_chain reader;
        struct obs_reader_ctx ctx;
        obs_reader_init(&reader, &ctx, 0);

        struct mesh_obs_slot s[3];
        obs_make_slot(&s[0], "x1.onion", OBS_BASE_TIP, 1, OBS_NOW - 10);
        obs_make_slot(&s[1], "x2.onion", OBS_BASE_TIP, 1, OBS_NOW - 10);
        obs_make_slot(&s[2], "x3.onion", OBS_BASE_TIP, 1, OBS_NOW - 10);

        struct mesh_conclusion c;
        mesh_observation_compose(s, 3, &reader, &k_obs_budget, OBS_NOW, &c);
        ASSERT(c.state == MESH_DISAGREEING);
        ASSERT_EQ(c.agree_at_anchor, 0);
        ASSERT_EQ(c.disagree_at_anchor, 3);
        ASSERT_STR_EQ(mesh_state_name(c.state), "disagreeing");
    } TEST_END
    return failures;
}

/* THE ANTI-TRUST ARM. The records are byte-identical across both calls; only
 * the READER's own chain lookup changes. If the fold ever polled the records
 * against each other instead of recomputing against the reader's own data,
 * the state could not move. */
static int t_reader_recomputes_it_does_not_trust(void)
{
    int failures = 0;
    TEST_CASE("compose: flipping only the READER's chain flips the state")
    {
        struct mesh_obs_slot s[2];
        obs_make_slot(&s[0], "p1.onion", OBS_BASE_TIP, 0, OBS_NOW - 10);
        obs_make_slot(&s[1], "p2.onion", OBS_BASE_TIP, 0, OBS_NOW - 10);

        struct mesh_obs_slot before[2];
        memcpy(before, s, sizeof(s));

        struct mesh_reader_chain r0;
        struct obs_reader_ctx c0;
        obs_reader_init(&r0, &c0, 0);
        struct mesh_conclusion a;
        mesh_observation_compose(s, 2, &r0, &k_obs_budget, OBS_NOW, &a);
        ASSERT(a.state == MESH_AGREEING);
        ASSERT_EQ(a.agree_at_anchor, 2);

        struct mesh_reader_chain r1;
        struct obs_reader_ctx c1;
        obs_reader_init(&r1, &c1, 1);
        struct mesh_conclusion b;
        mesh_observation_compose(s, 2, &r1, &k_obs_budget, OBS_NOW, &b);
        ASSERT(b.state == MESH_DISAGREEING);
        ASSERT_EQ(b.disagree_at_anchor, 2);
        ASSERT_EQ(b.agree_at_anchor, 0);

        /* and the fold is pure: it did not touch its input */
        ASSERT(memcmp(before, s, sizeof(s)) == 0);
    } TEST_END
    return failures;
}

/* No slot has ordering privilege — there is no "primary" and no referee.
 *
 * The fixture is built so TWO different heights qualify at the SAME rung:
 * two nodes sit at the reader's tip (deepest rung tip-144) and two sit one
 * block back (deepest rung tip-145). A fold that took "the first qualifying
 * height it walked into" would pick whichever the slot order presented first
 * and would answer AGREEING or DISAGREEING depending on the shuffle. A fold
 * that picks the deepest qualifying height answers the same every time.
 * FAIL-ARM: replacing the deepest-wins pick with a first-wins pick makes
 * these three calls disagree with each other. */
static int t_no_slot_has_ordering_privilege(void)
{
    int failures = 0;
    TEST_CASE("compose: shuffling the slots cannot change the conclusion")
    {
        struct mesh_reader_chain reader;
        struct obs_reader_ctx ctx;
        obs_reader_init(&reader, &ctx, 0);

        struct mesh_obs_slot s[5];
        obs_make_slot(&s[0], "q1.onion", OBS_BASE_TIP, 0, OBS_NOW - 10);
        obs_make_slot(&s[1], "q2.onion", OBS_BASE_TIP, 0, OBS_NOW - 20);
        obs_make_slot(&s[2], "q3.onion", OBS_BASE_TIP - 1, 1, OBS_NOW - 30);
        obs_make_slot(&s[3], "q4.onion", OBS_BASE_TIP - 1, 1, OBS_NOW - 40);
        obs_make_silent(&s[4], "q5.onion");
        obs_add_edge(&s[0], "q2.onion", OBS_BASE_TIP,
                     s[1].rec.self.tip_hash_hex);
        obs_add_edge(&s[1], "q1.onion", OBS_BASE_TIP,
                     s[0].rec.self.tip_hash_hex);

        struct mesh_conclusion fwd;
        mesh_observation_compose(s, 5, &reader, &k_obs_budget, OBS_NOW, &fwd);

        struct mesh_obs_slot rev[5];
        for (int i = 0; i < 5; i++) rev[i] = s[4 - i];
        struct mesh_conclusion bak;
        mesh_observation_compose(rev, 5, &reader, &k_obs_budget, OBS_NOW, &bak);
        ASSERT(obs_conclusion_eq(&fwd, &bak));

        /* a rotation too, so the arm is not passing on a symmetric accident */
        struct mesh_obs_slot rot[5];
        for (int i = 0; i < 5; i++) rot[i] = s[(i + 1) % 5];
        struct mesh_conclusion rc;
        mesh_observation_compose(rot, 5, &reader, &k_obs_budget, OBS_NOW, &rc);
        ASSERT(obs_conclusion_eq(&fwd, &rc));

        /* the arm is live: this input really does decide, so the equalities
         * above compare a decided result rather than three UNVERIFIEDs, and
         * the rung actually used is the deepest one both cohorts could offer */
        ASSERT(fwd.state == MESH_DISAGREEING);
        ASSERT_EQ(fwd.checked_height, OBS_BASE_TIP - 1 - 144);
    } TEST_END
    return failures;
}

/* A record that publishes no anchor at the height the reader chose is
 * evidence NEITHER way. FAIL-ARM: folding those records into
 * `agree_at_anchor` — the "absence is assent" bug — changes both counts. */
static int t_missing_rung_is_not_agreement(void)
{
    int failures = 0;
    TEST_CASE("compose: a record missing the checked rung is not agreement")
    {
        struct mesh_reader_chain reader;
        struct obs_reader_ctx ctx;
        obs_reader_init(&reader, &ctx, 0);

        /* two cohorts one block apart, all on the reader's own chain */
        struct mesh_obs_slot s[4];
        obs_make_slot(&s[0], "u1.onion", OBS_BASE_TIP, 0, OBS_NOW - 10);
        obs_make_slot(&s[1], "u2.onion", OBS_BASE_TIP, 0, OBS_NOW - 10);
        obs_make_slot(&s[2], "u3.onion", OBS_BASE_TIP - 1, 0, OBS_NOW - 10);
        obs_make_slot(&s[3], "u4.onion", OBS_BASE_TIP - 1, 0, OBS_NOW - 10);

        struct mesh_conclusion c;
        mesh_observation_compose(s, 4, &reader, &k_obs_budget, OBS_NOW, &c);
        ASSERT_EQ(c.checked_height, OBS_BASE_TIP - 1 - 144);
        ASSERT_EQ(c.agree_at_anchor, 2);
        ASSERT_EQ(c.no_common_height, 2);   /* NOT rolled into agreement */
        ASSERT_EQ(c.disagree_at_anchor, 0);
        ASSERT_EQ(c.records_fresh, 4);
        ASSERT(c.state == MESH_AGREEING);
        /* the basis publishes the arithmetic, so a reader can see that only
         * half the fresh records were actually checkable */
        ASSERT(strstr(c.basis, "agree=2") != NULL);
        ASSERT(strstr(c.basis, "fresh=4") != NULL);
    } TEST_END
    return failures;
}

/* Dropping any single record can only lower coverage — never prevent the
 * remaining readers from concluding. Authority-test limb (a), mechanised. */
static int t_no_record_is_load_bearing(void)
{
    int failures = 0;
    TEST_CASE("compose: removing any one record never blocks a conclusion")
    {
        struct mesh_reader_chain reader;
        struct obs_reader_ctx ctx;
        obs_reader_init(&reader, &ctx, 0);

        struct mesh_obs_slot full[4];
        for (int i = 0; i < 4; i++) {
            char on[64];
            snprintf(on, sizeof(on), "m%d.onion", i);
            obs_make_slot(&full[i], on, OBS_BASE_TIP, 0, OBS_NOW - 10);
        }
        struct mesh_conclusion base;
        mesh_observation_compose(full, 4, &reader, &k_obs_budget, OBS_NOW,
                                 &base);
        ASSERT(base.state == MESH_AGREEING);
        ASSERT_EQ(base.agree_at_anchor, 4);

        for (int drop = 0; drop < 4; drop++) {
            struct mesh_obs_slot sub[3];
            int k = 0;
            for (int i = 0; i < 4; i++)
                if (i != drop) sub[k++] = full[i];
            struct mesh_conclusion c;
            mesh_observation_compose(sub, 3, &reader, &k_obs_budget, OBS_NOW,
                                     &c);
            ASSERT(c.state == MESH_AGREEING);
            ASSERT_EQ(c.agree_at_anchor, 3);
        }
    } TEST_END
    return failures;
}

/* ── 5. the anchor ladder, and "I cannot check" ───────────────────────── */

/* The 5-rung ladder exists so two nodes a few blocks apart still share a
 * comparable height. FAIL-ARM for a tip-only comparison: with a 1-block lead
 * the pair would be uncheckable and this would report no_common_height. */
static int t_ladder_bridges_a_one_block_lead(void)
{
    int failures = 0;
    TEST_CASE("compose: a one-block lead is still checkable through the ladder")
    {
        struct mesh_reader_chain reader;
        struct obs_reader_ctx ctx;
        obs_reader_init(&reader, &ctx, 0);

        struct mesh_obs_slot s[2];
        obs_make_slot(&s[0], "l1.onion", OBS_BASE_TIP, 0, OBS_NOW - 10);
        obs_make_slot(&s[1], "l2.onion", OBS_BASE_TIP - 1, 0, OBS_NOW - 10);

        struct mesh_conclusion c;
        mesh_observation_compose(s, 2, &reader, &k_obs_budget, OBS_NOW, &c);
        ASSERT(c.state == MESH_AGREEING);
        ASSERT_EQ(c.checked_height, OBS_BASE_TIP - 1);
        ASSERT_EQ(c.agree_at_anchor, 2);
        ASSERT_EQ(c.no_common_height, 0);
        /* the reader publishes the hash it compared against, so the fold is
         * replayable offline from the saved documents */
        char expect[65];
        obs_hash_for(0, OBS_BASE_TIP - 1, expect);
        ASSERT_STR_EQ(c.reader_hash_at_checked, expect);
    } TEST_END
    return failures;
}

static int t_no_common_height_is_unverified(void)
{
    int failures = 0;
    TEST_CASE("compose: a reader that cannot check says so, never 'agree'")
    {
        struct mesh_reader_chain reader;
        struct obs_reader_ctx ctx;
        obs_reader_init(&reader, &ctx, 0);

        /* every anchor above the reader's tip: hash_at() answers nothing */
        struct mesh_obs_slot s[2];
        obs_make_slot(&s[0], "far1.onion", OBS_BASE_TIP + 5000, 0,
                      OBS_NOW - 10);
        obs_make_slot(&s[1], "far2.onion", OBS_BASE_TIP + 5000, 0,
                      OBS_NOW - 10);

        struct mesh_conclusion c;
        mesh_observation_compose(s, 2, &reader, &k_obs_budget, OBS_NOW, &c);
        ASSERT(c.state == MESH_UNVERIFIED);
        ASSERT_STR_EQ(c.basis, "no_common_checkable_height");
        ASSERT_EQ(c.no_common_height, 2);
        ASSERT_EQ(c.agree_at_anchor, 0);
        ASSERT_EQ(c.disagree_at_anchor, 0);
        ASSERT_EQ(c.checked_height, -1);

        /* the deepest rung is exactly what rescues a reader 144 blocks behind */
        struct mesh_obs_slot n[2];
        obs_make_slot(&n[0], "near1.onion", OBS_BASE_TIP + 144, 0,
                      OBS_NOW - 10);
        obs_make_slot(&n[1], "near2.onion", OBS_BASE_TIP + 144, 0,
                      OBS_NOW - 10);
        struct mesh_conclusion d;
        mesh_observation_compose(n, 2, &reader, &k_obs_budget, OBS_NOW, &d);
        ASSERT(d.state == MESH_AGREEING);
        ASSERT_EQ(d.checked_height, OBS_BASE_TIP);
        ASSERT_EQ(d.agree_at_anchor, 2);
    } TEST_END
    return failures;
}

/* A reader with no chain to consult at all cannot conclude. FAIL-ARM for a
 * NULL-reader path that returns a cheerful default. */
static int t_reader_without_chain_cannot_conclude(void)
{
    int failures = 0;
    TEST_CASE("compose: a reader with no chain lookup reaches no verdict")
    {
        struct mesh_obs_slot s[2];
        obs_make_slot(&s[0], "z1.onion", OBS_BASE_TIP, 0, OBS_NOW - 10);
        obs_make_slot(&s[1], "z2.onion", OBS_BASE_TIP, 0, OBS_NOW - 10);

        struct mesh_conclusion c;
        mesh_observation_compose(s, 2, NULL, &k_obs_budget, OBS_NOW, &c);
        ASSERT(c.state == MESH_UNVERIFIED);
        ASSERT_STR_EQ(c.basis, "no_common_checkable_height");
        ASSERT_EQ(c.agree_at_anchor, 0);
    } TEST_END
    return failures;
}

/* ── 6. the hardware-franchise arm ────────────────────────────────────── */

/* RULING 2, mechanised. Two record sets identical in every CHAIN field; one
 * carries the measured HDD-box numbers (fsync 72.6 ms, pread truncated to
 * -1, a 9-second min ping, a probe that consumed its whole budget, a lost
 * trylock). The two conclusions must be indistinguishable. A slow node is
 * reachable and slow, never failed. */
static int t_slow_box_is_reachable_not_failed(void)
{
    int failures = 0;
    TEST_CASE("compose: a 7200-rpm box is graded identically to a fast one")
    {
        struct mesh_reader_chain reader;
        struct obs_reader_ctx ctx;
        obs_reader_init(&reader, &ctx, 0);

        struct mesh_obs_slot fast[2];
        obs_make_slot(&fast[0], "fast1.onion", OBS_BASE_TIP, 0, OBS_NOW - 10);
        obs_make_slot(&fast[1], "fast2.onion", OBS_BASE_TIP, 0, OBS_NOW - 10);
        obs_add_edge(&fast[0], "fast2.onion", OBS_BASE_TIP,
                     fast[1].rec.self.tip_hash_hex);
        obs_add_edge(&fast[1], "fast1.onion", OBS_BASE_TIP,
                     fast[0].rec.self.tip_hash_hex);

        struct mesh_obs_slot slow[2];
        memcpy(slow, fast, sizeof(fast));
        /* identical chain content; only capability + timing differ */
        slow[1].rec.self.cores = 8;
        slow[1].rec.self.ram_bytes = 16638836736LL;
        slow[1].rec.self.rotational_known = true;
        slow[1].rec.self.rotational = true;
        slow[1].rec.self.fsync_us = 72649;
        slow[1].rec.self.pread_us = -1;   /* truncated probe, published AS -1 */
        slow[1].rec.self.sample_elapsed_us = 411000;
        slow[1].rec.self.lock_contended = true;
        slow[1].elapsed_us = 44900000;    /* nearly the whole fetch budget */
        slow[1].rec.edges[0].min_ping_us = 9000000;
        slow[1].rec.edges[0].stage_elapsed_us = 120000000;
        slow[1].rec.edges[0].deadline_us = 120000000;   /* elapsed == budget */
        slow[1].rec.edges[0].transport = MESH_OBS_CONFIRMED;  /* reachable */

        struct mesh_conclusion a, b;
        mesh_observation_compose(fast, 2, &reader, &k_obs_budget, OBS_NOW, &a);
        mesh_observation_compose(slow, 2, &reader, &k_obs_budget, OBS_NOW, &b);

        ASSERT(a.state == MESH_AGREEING);
        ASSERT(a.state == b.state);
        ASSERT_EQ(a.agree_at_anchor, b.agree_at_anchor);
        ASSERT_EQ(a.disagree_at_anchor, b.disagree_at_anchor);
        ASSERT_EQ(a.no_common_height, b.no_common_height);
        ASSERT_EQ(a.records_fresh, b.records_fresh);
        ASSERT_EQ(a.edges_reciprocated, b.edges_reciprocated);
        ASSERT(obs_conclusion_eq(&a, &b));
    } TEST_END
    return failures;
}

/* The same ruling for the build target. A fleet that spans Linux, macOS and
 * Windows only stays honest if the platform a record came from can be READ
 * without ever being GRADED. FAIL-ARM: two runs whose records differ in
 * nothing but `os`/`arch` must produce byte-identical conclusions, and the
 * all-macOS run in particular must not be downgraded for being macOS. */
static int t_platform_is_weighted_never_graded(void)
{
    int failures = 0;
    TEST_CASE("compose: a macOS fleet grades identically to a Linux one")
    {
        struct mesh_reader_chain reader;
        struct obs_reader_ctx ctx;
        obs_reader_init(&reader, &ctx, 0);

        struct mesh_obs_slot linux_fleet[2];
        obs_make_slot(&linux_fleet[0], "lin1.onion", OBS_BASE_TIP, 0,
                      OBS_NOW - 10);
        obs_make_slot(&linux_fleet[1], "lin2.onion", OBS_BASE_TIP, 0,
                      OBS_NOW - 10);
        obs_add_edge(&linux_fleet[0], "lin2.onion", OBS_BASE_TIP,
                     linux_fleet[1].rec.self.tip_hash_hex);
        obs_add_edge(&linux_fleet[1], "lin1.onion", OBS_BASE_TIP,
                     linux_fleet[0].rec.self.tip_hash_hex);
        for (int i = 0; i < 2; i++) {
            snprintf(linux_fleet[i].rec.self.os,
                     sizeof(linux_fleet[i].rec.self.os), "%s", "linux");
            snprintf(linux_fleet[i].rec.self.arch,
                     sizeof(linux_fleet[i].rec.self.arch), "%s", "x86_64");
        }

        /* Identical chain content. The ONLY difference is the build target —
         * and the macOS records also carry the honest tor_stub_build that
         * platform forces, which must not be read as a fault either. */
        struct mesh_obs_slot mac_fleet[2];
        memcpy(mac_fleet, linux_fleet, sizeof(linux_fleet));
        for (int i = 0; i < 2; i++) {
            snprintf(mac_fleet[i].rec.self.os,
                     sizeof(mac_fleet[i].rec.self.os), "%s", "macos");
            snprintf(mac_fleet[i].rec.self.arch,
                     sizeof(mac_fleet[i].rec.self.arch), "%s", "arm64");
            mac_fleet[i].rec.self.tor_stub_build = true;
        }

        /* Positive control: the two inputs really are different, so an
         * equal verdict below is evidence and not a comparison of one
         * buffer with itself. */
        ASSERT(memcmp(linux_fleet, mac_fleet, sizeof(linux_fleet)) != 0);
        ASSERT(strcmp(mac_fleet[0].rec.self.os, "macos") == 0);

        struct mesh_conclusion a, b;
        mesh_observation_compose(linux_fleet, 2, &reader, &k_obs_budget,
                                 OBS_NOW, &a);
        mesh_observation_compose(mac_fleet, 2, &reader, &k_obs_budget,
                                 OBS_NOW, &b);

        ASSERT(a.state == MESH_AGREEING);
        ASSERT(b.state == MESH_AGREEING);
        ASSERT_EQ(a.records_fresh, b.records_fresh);
        ASSERT_EQ(a.distinct_identities, b.distinct_identities);
        ASSERT_EQ(a.agree_at_anchor, b.agree_at_anchor);
        ASSERT(obs_conclusion_eq(&a, &b));

        /* A mixed fleet is not a lesser fleet either. */
        struct mesh_obs_slot mixed[2];
        memcpy(&mixed[0], &linux_fleet[0], sizeof(mixed[0]));
        memcpy(&mixed[1], &mac_fleet[1], sizeof(mixed[1]));
        struct mesh_conclusion c;
        mesh_observation_compose(mixed, 2, &reader, &k_obs_budget, OBS_NOW,
                                 &c);
        ASSERT(obs_conclusion_eq(&a, &c));
    } TEST_END
    return failures;
}

/* RULING 2 as a source-text lint, in C — `printf ... | grep -q` under
 * pipefail returns 141 on a MATCH and would invert exactly this assertion.
 * FAIL-LOUD: an unreadable or short file is a FAILURE, never a skip, because
 * a lint that examined zero bytes reporting clean is this project's
 * signature bug. */
static int obs_open_repo_file(const char *rel, FILE **out)
{
    char path[512];
    static const char *prefixes[] = { "", "../", "../../", "../../../",
                                      "../../../../" };
    for (size_t i = 0; i < sizeof(prefixes) / sizeof(prefixes[0]); i++) {
        snprintf(path, sizeof(path), "%s%s", prefixes[i], rel);
        FILE *f = fopen(path, "rb");
        if (f) { *out = f; return 0; }
    }
    return -1;   /* raw-return-ok:caller-fails-loud */
}

static int t_composer_cannot_see_timing(void)
{
    int failures = 0;
    TEST_CASE("compose: the composer source names no timing or capability field")
    {
        FILE *f = NULL;
        int rc = obs_open_repo_file(
            "app/services/src/mesh_observation_compose.c", &f);
        ASSERT(rc == 0);
        ASSERT(f != NULL);

        static char buf[512 * 1024];
        size_t n = fread(buf, 1, sizeof(buf) - 1, f);
        fclose(f);
        buf[n] = '\0';
        /* a zero-byte or truncated read must FAIL, not silently pass */
        ASSERT(n > 512);

        static const char *const forbidden[] = {
            "fsync_us", "pread_us", "min_ping_us", "stage_elapsed_us",
            "rotational", "cores", "ram_bytes", "sample_elapsed_us",
            "hw_fingerprint",
            /* A platform is WEIGHTED by a reader, never a bar a machine is
             * graded against. The day the composer can name a build target
             * is the day "macOS" or "Windows" can become a failing grade. */
            "arch",
        };
        for (size_t i = 0; i < sizeof(forbidden) / sizeof(forbidden[0]); i++) {
            if (strstr(buf, forbidden[i]) != NULL) {
                printf("FAIL (timing/capability field \"%s\" reached the "
                       "composer)\n", forbidden[i]);
                failures++;
                goto _test_next;
            }
        }
        /* positive control: the scan CAN find a token, so a clean result is
         * evidence and not an empty buffer */
        ASSERT(strstr(buf, "mesh_observation_compose") != NULL);
    } TEST_END
    return failures;
}

/* ── 7. adjacency is reported, never graded ───────────────────────────── */

static int t_reciprocity(void)
{
    int failures = 0;
    TEST_CASE("compose: an unanswered edge is one_sided until the peer says so")
    {
        struct mesh_reader_chain reader;
        struct obs_reader_ctx ctx;
        obs_reader_init(&reader, &ctx, 0);

        struct mesh_obs_slot s[2];
        obs_make_slot(&s[0], "ra.onion", OBS_BASE_TIP, 0, OBS_NOW - 10);
        obs_make_slot(&s[1], "rb.onion", OBS_BASE_TIP, 0, OBS_NOW - 10);
        obs_add_edge(&s[0], "rb.onion", OBS_BASE_TIP,
                     s[1].rec.self.tip_hash_hex);

        struct mesh_conclusion c;
        mesh_observation_compose(s, 2, &reader, &k_obs_budget, OBS_NOW, &c);
        ASSERT_EQ(c.edges_asserted, 1);
        ASSERT_EQ(c.edges_one_sided, 1);
        ASSERT_EQ(c.edges_reciprocated, 0);

        obs_add_edge(&s[1], "ra.onion", OBS_BASE_TIP,
                     s[0].rec.self.tip_hash_hex);
        struct mesh_conclusion d;
        mesh_observation_compose(s, 2, &reader, &k_obs_budget, OBS_NOW, &d);
        ASSERT_EQ(d.edges_asserted, 2);
        ASSERT_EQ(d.edges_one_sided, 0);
        ASSERT(d.edges_reciprocated >= 1);
        /* adjacency never moved the state */
        ASSERT(c.state == d.state);
    } TEST_END
    return failures;
}

static int t_contradiction_is_reported_not_graded(void)
{
    int failures = 0;
    TEST_CASE("compose: a third-party claim its subject denies is counted only")
    {
        struct mesh_reader_chain reader;
        struct obs_reader_ctx ctx;
        obs_reader_init(&reader, &ctx, 0);

        struct mesh_obs_slot honest[3];
        obs_make_slot(&honest[0], "ca.onion", OBS_BASE_TIP, 0, OBS_NOW - 10);
        obs_make_slot(&honest[1], "cb.onion", OBS_BASE_TIP, 0, OBS_NOW - 10);
        obs_make_slot(&honest[2], "cc.onion", OBS_BASE_TIP, 0, OBS_NOW - 10);
        /* B reports C's tip correctly */
        obs_add_edge(&honest[1], "cc.onion", OBS_BASE_TIP,
                     honest[2].rec.self.tip_hash_hex);

        struct mesh_conclusion good;
        mesh_observation_compose(honest, 3, &reader, &k_obs_budget, OBS_NOW,
                                 &good);
        ASSERT_EQ(good.edges_contradicted, 0);

        struct mesh_obs_slot liar[3];
        memcpy(liar, honest, sizeof(honest));
        /* B now reports a tip hash for C that C itself does not publish */
        snprintf(liar[1].rec.edges[0].claimed_tip_hash_hex,
                 sizeof(liar[1].rec.edges[0].claimed_tip_hash_hex),
                 "%064llx", (unsigned long long)0xdeadbeefULL);

        struct mesh_conclusion bad;
        mesh_observation_compose(liar, 3, &reader, &k_obs_budget, OBS_NOW,
                                 &bad);
        ASSERT_EQ(bad.edges_contradicted, 1);
        /* the contradiction is DERIVED by the reader and reported; it grades
         * nobody */
        ASSERT(bad.state == good.state);
        ASSERT_EQ(bad.agree_at_anchor, good.agree_at_anchor);
        ASSERT_EQ(bad.disagree_at_anchor, good.disagree_at_anchor);
    } TEST_END
    return failures;
}

/* ── 8. every state and every basis token is REACHABLE ────────────────── */

/* RULING 5. A gate whose passing condition is unreachable is worse than no
 * gate, because it reports confidently. This arm constructs an input for each
 * state and each basis token and fails if any of them cannot be reached. */
static int t_every_outcome_is_reachable(void)
{
    int failures = 0;
    TEST_CASE("compose: all 4 states and all 5 basis tokens are reachable")
    {
        struct mesh_reader_chain reader;
        struct obs_reader_ctx ctx;
        obs_reader_init(&reader, &ctx, 0);
        struct mesh_conclusion c;

        bool seen_state[4] = { false, false, false, false };
        bool seen_no_fresh = false, seen_only_self = false;
        bool seen_no_common = false, seen_insufficient = false;
        bool seen_counted = false;

        /* UNVERIFIED / no_fresh_records */
        mesh_observation_compose(NULL, 0, &reader, &k_obs_budget, OBS_NOW, &c);
        seen_state[c.state] = true;
        if (strcmp(c.basis, "no_fresh_records") == 0) seen_no_fresh = true;

        /* UNVERIFIED / only_self */
        struct mesh_obs_slot one[1];
        obs_make_slot(&one[0], "s1.onion", OBS_BASE_TIP, 0, OBS_NOW - 5);
        mesh_observation_compose(one, 1, &reader, &k_obs_budget, OBS_NOW, &c);
        seen_state[c.state] = true;
        if (strcmp(c.basis, "only_self") == 0) seen_only_self = true;

        /* UNVERIFIED / insufficient_independent_records — reachable when the
         * reader demands more coverage than the fleet can offer */
        struct mesh_obs_slot two[2];
        obs_make_slot(&two[0], "s1.onion", OBS_BASE_TIP, 0, OBS_NOW - 5);
        obs_make_slot(&two[1], "s2.onion", OBS_BASE_TIP, 0, OBS_NOW - 5);
        struct mesh_compose_budget strict = { .freshness_secs = 900,
                                              .min_independent = 5 };
        mesh_observation_compose(two, 2, &reader, &strict, OBS_NOW, &c);
        seen_state[c.state] = true;
        if (strcmp(c.basis, "insufficient_independent_records") == 0)
            seen_insufficient = true;
        ASSERT_EQ(c.min_independent_required, 5);

        /* UNVERIFIED / no_common_checkable_height */
        struct mesh_obs_slot far[2];
        obs_make_slot(&far[0], "f1.onion", OBS_BASE_TIP + 5000, 0, OBS_NOW - 5);
        obs_make_slot(&far[1], "f2.onion", OBS_BASE_TIP + 5000, 0, OBS_NOW - 5);
        mesh_observation_compose(far, 2, &reader, &k_obs_budget, OBS_NOW, &c);
        seen_state[c.state] = true;
        if (strcmp(c.basis, "no_common_checkable_height") == 0)
            seen_no_common = true;

        /* AGREEING, with the arithmetic published */
        mesh_observation_compose(two, 2, &reader, &k_obs_budget, OBS_NOW, &c);
        seen_state[c.state] = true;
        if (strstr(c.basis, "agree=") && strstr(c.basis, "disagree=") &&
            strstr(c.basis, "fresh=") && strstr(c.basis, "indep="))
            seen_counted = true;

        /* DISAGREEING */
        struct mesh_obs_slot dis[2];
        obs_make_slot(&dis[0], "d1.onion", OBS_BASE_TIP, 1, OBS_NOW - 5);
        obs_make_slot(&dis[1], "d2.onion", OBS_BASE_TIP, 1, OBS_NOW - 5);
        mesh_observation_compose(dis, 2, &reader, &k_obs_budget, OBS_NOW, &c);
        seen_state[c.state] = true;

        /* SPLIT_VIEW */
        struct mesh_obs_slot spl[2];
        obs_make_slot(&spl[0], "p1.onion", OBS_BASE_TIP, 0, OBS_NOW - 5);
        obs_make_slot(&spl[1], "p2.onion", OBS_BASE_TIP, 1, OBS_NOW - 5);
        mesh_observation_compose(spl, 2, &reader, &k_obs_budget, OBS_NOW, &c);
        seen_state[c.state] = true;

        ASSERT(seen_state[MESH_UNVERIFIED]);
        ASSERT(seen_state[MESH_AGREEING]);
        ASSERT(seen_state[MESH_DISAGREEING]);
        ASSERT(seen_state[MESH_SPLIT_VIEW]);
        ASSERT(seen_no_fresh);
        ASSERT(seen_only_self);
        ASSERT(seen_insufficient);
        ASSERT(seen_no_common);
        ASSERT(seen_counted);
    } TEST_END
    return failures;
}

/* The names are a wire contract: a reader on an older build must be able to
 * refuse a state by name rather than mis-decode an integer. */
static int t_state_names_are_distinct_static_tokens(void)
{
    int failures = 0;
    TEST_CASE("compose: state names are distinct, verdict-free tokens")
    {
        ASSERT_STR_EQ(mesh_state_name(MESH_UNVERIFIED), "unverified");
        ASSERT_STR_EQ(mesh_state_name(MESH_AGREEING), "agreeing");
        ASSERT_STR_EQ(mesh_state_name(MESH_DISAGREEING), "disagreeing");
        ASSERT_STR_EQ(mesh_state_name(MESH_SPLIT_VIEW), "split_view");
        /* zeroed memory must read "I have not concluded", never "healthy" */
        ASSERT_EQ((int)MESH_UNVERIFIED, 0);
        for (int i = 0; i <= (int)MESH_SPLIT_VIEW; i++) {
            const char *n = mesh_state_name((enum mesh_state)i);
            ASSERT(strstr(n, "pass") == NULL);
            ASSERT(strstr(n, "fail") == NULL);
            ASSERT(strstr(n, "healthy") == NULL);
            ASSERT(strcmp(n, "ok") != 0);
        }
    } TEST_END
    return failures;
}

/* Work is reported so a reader can go validate for itself; it never grades. */
static int t_chainwork_is_reported_never_acted_on(void)
{
    int failures = 0;
    TEST_CASE("compose: a heavier claimed chainwork is reported, not obeyed")
    {
        struct mesh_reader_chain reader;
        struct obs_reader_ctx ctx;
        obs_reader_init(&reader, &ctx, 0);

        struct mesh_obs_slot s[2];
        obs_make_slot(&s[0], "w1.onion", OBS_BASE_TIP, 0, OBS_NOW - 10);
        obs_make_slot(&s[1], "w2.onion", OBS_BASE_TIP, 0, OBS_NOW - 10);
        snprintf(s[1].rec.self.tip_chainwork_hex,
                 sizeof(s[1].rec.self.tip_chainwork_hex), "%064llx",
                 (unsigned long long)0xffffffffffULL);

        struct mesh_conclusion c;
        mesh_observation_compose(s, 2, &reader, &k_obs_budget, OBS_NOW, &c);
        ASSERT_STR_EQ(c.max_chainwork_hex, s[1].rec.self.tip_chainwork_hex);
        ASSERT(c.reader_holds_max_chainwork == false);
        /* the claim changed nothing about the recomputed agreement */
        ASSERT(c.state == MESH_AGREEING);
        ASSERT_EQ(c.agree_at_anchor, 2);
    } TEST_END
    return failures;
}

int test_mesh_observation_compose(void)
{
    int failures = 0;
    failures += t_zero_records_is_unverified();
    failures += t_all_dark_is_unverified();
    failures += t_stale_record_is_not_fresh();
    failures += t_only_self_is_unverified();
    failures += t_silence_never_becomes_agreement();
    failures += t_silent_peer_edge_is_one_sided();
    failures += t_disagreement_is_never_outvoted();
    failures += t_unanimous_counterevidence_is_disagreeing();
    failures += t_reader_recomputes_it_does_not_trust();
    failures += t_no_slot_has_ordering_privilege();
    failures += t_missing_rung_is_not_agreement();
    failures += t_no_record_is_load_bearing();
    failures += t_ladder_bridges_a_one_block_lead();
    failures += t_no_common_height_is_unverified();
    failures += t_reader_without_chain_cannot_conclude();
    failures += t_slow_box_is_reachable_not_failed();
    failures += t_platform_is_weighted_never_graded();
    failures += t_composer_cannot_see_timing();
    failures += t_reciprocity();
    failures += t_contradiction_is_reported_not_graded();
    failures += t_every_outcome_is_reachable();
    failures += t_state_names_are_distinct_static_tokens();
    failures += t_chainwork_is_reported_never_acted_on();
    return failures;
}
