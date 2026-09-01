/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * test_zcode_swarm_complete — COMPLETE immediately ANNOUNCEs the exact
 * package root to known peers that have not already been announced it.
 * Completing a fetch does not pin. The frozen v1 swarm wire is unchanged. */

#include "test/test_core.h"

#include "vcs/blob_store.h"
#include "vcs/package_service.h"
#include "vcs/package_store.h"
#include "vcs/package_swarm_node.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define SC_DAY 20500
#define SC_SCORE UINT64_C(100)

struct sc_node {
    char datadir[1024];
    char zcode_dir[1100];
    struct vcs_package_store *store;
    struct vcs_service_book *book;
    struct vcs_swarm_engine *engine;
};

static uint64_t sc_score(const uint8_t contributor[33], void *ctx)
{
    (void)contributor;
    (void)ctx;
    return SC_SCORE;
}

static bool sc_node_open(struct sc_node *n, const char *tag)
{
    memset(n, 0, sizeof(*n));
    test_make_tmpdir(n->datadir, sizeof(n->datadir), "zcode_swarm_complete",
                     tag);
    snprintf(n->zcode_dir, sizeof(n->zcode_dir), "%s/zcode", n->datadir);
    n->store = vcs_package_store_open(
        n->datadir, VCS_PACKAGE_STORE_DEFAULT_QUOTA_BYTES);
    n->book = vcs_service_book_load(n->zcode_dir);
    if (!n->store || !n->book)
        return false;
    n->engine = vcs_swarm_engine_create(n->store, n->book, n->zcode_dir,
                                        sc_score, NULL);
    return n->engine != NULL;
}

static void sc_node_close(struct sc_node *n)
{
    vcs_swarm_engine_free(n->engine);
    vcs_service_book_free(n->book);
    vcs_package_store_close(n->store);
    n->engine = NULL;
    n->book = NULL;
    n->store = NULL;
}

static void sc_key(uint8_t seed, uint8_t out[33])
{
    memset(out, 0, 33);
    out[0] = 0x02;
    out[32] = seed;
    out[1] = (uint8_t)(seed ^ 0x5a);
}

static bool sc_drain_announce(struct vcs_swarm_engine *engine, uint64_t peer,
                              const uint8_t root[32], size_t *announce_count)
{
    uint64_t target = 0;
    uint8_t frame[VCS_SWARM_OUTBOUND_FRAME_MAX];
    size_t frame_len = 0;
    bool saw_root = false;
    while (vcs_swarm_engine_next_outbound(engine, peer, &target, frame,
                                          &frame_len)) {
        struct vcs_package_swarm_message msg;
        if (!vcs_package_swarm_parse(frame, frame_len, &msg))
            continue;
        if (msg.type != VCS_PACKAGE_SWARM_ANNOUNCE)
            continue;
        (*announce_count)++;
        if (memcmp(msg.body.announce.package_root, root, 32) == 0)
            saw_root = true;
    }
    return saw_root;
}

static int sc_t_announce_on_complete(void)
{
    int failures = 0;
    struct sc_node seed, leech;
    memset(&seed, 0, sizeof(seed));
    memset(&leech, 0, sizeof(leech));
    TEST("verified fetch COMPLETE immediately ANNOUNCEs the root to a "
         "peer that never received announce_to") {
        ASSERT(sc_node_open(&seed, "seed"));
        ASSERT(sc_node_open(&leech, "leech"));

        uint8_t blob[300];
        for (size_t i = 0; i < sizeof(blob); i++)
            blob[i] = (uint8_t)(i * 13u + 5u);
        uint8_t root[32];
        ASSERT(vcs_blob_put_to(seed.store, blob, sizeof(blob), root) ==
               VCS_BLOB_OK);

        const uint64_t peer_leech = 11;    /* seeder's handle for leecher */
        const uint64_t peer_seed = 13;     /* leecher's handle for seeder */
        const uint64_t peer_observer = 17; /* never received announce_to */
        uint8_t key_leech[33], key_seed[33], key_obs[33];
        sc_key(1, key_leech);
        sc_key(2, key_seed);
        sc_key(3, key_obs);
        ASSERT(vcs_swarm_engine_peer_add(seed.engine, peer_leech, key_leech));
        ASSERT(vcs_swarm_engine_peer_add(leech.engine, peer_seed, key_seed));
        ASSERT(vcs_swarm_engine_peer_add(leech.engine, peer_observer,
                                         key_obs));

        /* Observer is known but has never been announced_to. */
        size_t pre = 0;
        ASSERT(!sc_drain_announce(leech.engine, peer_observer, root, &pre));
        ASSERT_EQ(pre, 0u);

        /* Seeder advertises over the frozen ANNOUNCE frame. */
        ASSERT(vcs_blob_announce_via(seed.engine) >= 1);
        uint8_t frame[VCS_SWARM_OUTBOUND_FRAME_MAX];
        size_t frame_len = 0;
        uint64_t target = 0;
        while (vcs_swarm_engine_next_outbound(seed.engine, peer_leech,
                                              &target, frame, &frame_len)) {
            struct vcs_swarm_frame_result r = vcs_swarm_engine_handle_frame(
                leech.engine, peer_seed, frame, frame_len, SC_DAY, 1);
            free(r.reply);
        }

        struct vcs_swarm_advertised offered[8];
        size_t offered_n = vcs_swarm_engine_advertised(leech.engine, offered,
                                                       8);
        bool saw_ad = false;
        for (size_t i = 0; i < offered_n; i++) {
            if (memcmp(offered[i].root, root, 32) == 0 &&
                offered[i].advertisers >= 1u)
                saw_ad = true;
        }
        ASSERT(offered_n >= 1u);
        ASSERT(saw_ad);

        ASSERT(vcs_blob_fetch_via(leech.engine, root, SC_DAY, 2) ==
               VCS_BLOB_OK);

        bool complete = false;
        for (int round = 0; round < 32 && !complete; round++) {
            vcs_swarm_engine_tick(leech.engine, SC_DAY,
                                  (uint64_t)(round + 3));
            while (vcs_swarm_engine_next_outbound(leech.engine, peer_seed,
                                                  &target, frame,
                                                  &frame_len)) {
                struct vcs_swarm_frame_result served =
                    vcs_swarm_engine_handle_frame(
                        seed.engine, peer_leech, frame, frame_len, SC_DAY,
                        (uint64_t)(round + 3));
                if (served.reply && served.reply_len > 0) {
                    struct vcs_swarm_frame_result got =
                        vcs_swarm_engine_handle_frame(
                            leech.engine, peer_seed, served.reply,
                            served.reply_len, SC_DAY,
                            (uint64_t)(round + 3));
                    free(got.reply);
                }
                free(served.reply);
            }
            struct vcs_swarm_download_status ds;
            if (vcs_swarm_engine_download_status(leech.engine, root, &ds) &&
                ds.state == VCS_SWARM_DL_COMPLETE)
                complete = true;
        }
        ASSERT(complete);

        struct vcs_package_store_summary sums[8];
        size_t n = vcs_package_store_list_summaries(leech.store, true, sums,
                                                    8);
        bool listed = false;
        bool pinned = true;
        for (size_t i = 0; i < n; i++) {
            if (memcmp(sums[i].root, root, 32) != 0)
                continue;
            listed = true;
            pinned = sums[i].pinned;
            break;
        }
        ASSERT(listed);
        ASSERT(!pinned);

        /* No announce_to on the observer: COMPLETE itself queued ANNOUNCE. */
        size_t announces = 0;
        ASSERT(sc_drain_announce(leech.engine, peer_observer, root,
                                 &announces));
        ASSERT(announces >= 1u);
        PASS();
    } _test_next:;
    sc_node_close(&seed);
    sc_node_close(&leech);
    if (seed.datadir[0])
        test_rm_rf_recursive(seed.datadir);
    if (leech.datadir[0])
        test_rm_rf_recursive(leech.datadir);
    return failures;
}

int test_zcode_swarm_complete(void)
{
    int failures = 0;
    failures += sc_t_announce_on_complete();
    return failures;
}
