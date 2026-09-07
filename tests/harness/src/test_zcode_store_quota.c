/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * zcode_store scenario checks: staging pool exhaustion (in-flight
 * work preserved), deterministic HOT (LRU) and RARE (replicas desc)
 * eviction, pins never evicted plus pins budget, pre-existing pin
 * markers, the possession scheduler, and release-envelope storage
 * through the acceptance layer.
 *
 * Split out of test_zcode_store.c (which keeps the includes, the
 * fixture helpers shared across siblings, the dump_state scenarios,
 * and the group entry point) so no family member crosses the
 * 1,500-line ceiling. */

#include "test/test_core.h"

#include "models/build_fabric.h"
#include "services/build_fabric_cache.h"
#include "services/build_fabric_service.h"
#include "vcs/build_action.h"
#include "vcs/build_execution_observation.h"
#include "vcs/package_store.h"

#include "vcs/blob_store.h"
#include "vcs/package_deps.h"
#include "vcs/package_manifest.h"
#include "vcs/package_recipe.h"
#include "vcs/package_possession_scheduler.h"
#include "vcs/package_swarm_node.h"
#include "vcs/package_swarm_status.h"
#include "vcs/zcode_work_output.h"
#include "vcs/zcode_action_input.h"
#include "vcs/zcode_dev.h"
#include "vcs/zcode_task_authority.h"
#include "vcs/vcs.h"
#include "vcs/vcs_object.h"

#include "config/boot_zcode_swarm_receipt.h"
#include "controllers/diagnostics_internal.h"

#include "base/hex.h"
#include "chain/chainparams.h"
#include "core/uint256.h"
#include "crypto/ed25519.h"
#include "crypto/sha3.h"
#include "json/json.h"
#include "keys/key.h"
#include "keys/key_io.h"
#include "keys/pubkey.h"
#include "util/util.h"

#include <dirent.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include "test/test_zcode_store_priv.h"


/* ── 6: staging quota ─────────────────────────────────────────────── */
int t_store_staging_quota(void)
{
    int failures = 0;
    /* quota 10000: staging budget 1000 bytes. */
    char dd[256];
    struct vcs_package_store *s =
        zs_open(dd, sizeof(dd), "stagingq", 10000u);
    ZS_CHECK("stagingq: store opens", s != NULL);
    if (!s)
        return failures;

    const char *dpaths[] = { "d0", "d1", "d2", "d3", "d4",
                             "d5", "d6", "d7", "d8", "d9" };
    const size_t dlens[] = { 100, 100, 100, 100, 100,
                             100, 100, 100, 100, 100 };
    struct zs_pkg d;
    ZS_CHECK("stagingq: package D builds",
             zs_make_package(&d, 10, dpaths, dlens, 0x66));
    struct zs_pkg e;
    ZS_CHECK("stagingq: package E builds",
             zs_make_package(&e, 10, dpaths, dlens, 0x77));
    ZS_CHECK("stagingq: D + E admitted (manifests charge nothing)",
             vcs_package_store_put_manifest(s, d.wire, d.wire_len, NULL) ==
                 VCS_PACKAGE_STORE_OK &&
             vcs_package_store_put_manifest(s, e.wire, e.wire_len, NULL) ==
                 VCS_PACKAGE_STORE_OK);

    /* D stages 9 of 10 chunks (900 bytes, deliberately incomplete). */
    for (size_t i = 0; i < 9; i++) {
        char path[8];
        snprintf(path, sizeof(path), "d%zu", i);
        ZS_CHECK("stagingq: D chunk accepted",
                 vcs_package_store_put_chunk(s, d.root, path, 0,
                                             d.contents[i],
                                             d.lens[i]) ==
                     VCS_PACKAGE_STORE_OK);
    }
    ZS_CHECK("stagingq: staging pool at 900",
             vcs_package_store_pool_usage(
                 s, VCS_PACKAGE_STORE_POOL_STAGING) == 900);

    /* E's first chunk exactly fills the pool (900+100 = 1000, fits);
     * the second would exceed it and is refused BEFORE the byte lands. */
    ZS_CHECK("stagingq: E chunk filling the pool exactly accepted",
             vcs_package_store_put_chunk(s, e.root, "d0", 0, e.contents[0],
                                         e.lens[0]) ==
                 VCS_PACKAGE_STORE_OK);
    ZS_CHECK("stagingq: over-budget chunk refused with QUOTA",
             vcs_package_store_put_chunk(s, e.root, "d1", 0, e.contents[1],
                                         e.lens[1]) ==
                 VCS_PACKAGE_STORE_ERR_QUOTA);
    ZS_CHECK("stagingq: refused byte was not stored",
             vcs_package_store_pool_usage(
                 s, VCS_PACKAGE_STORE_POOL_STAGING) == 1000);
    struct vcs_package_store_status st;
    ZS_CHECK("stagingq: in-flight work is preserved, not discarded",
             vcs_package_store_package_status(s, d.root, &st) &&
             !st.complete && st.present_bytes == 900 &&
             vcs_package_store_package_status(s, e.root, &st) &&
             !st.complete && st.present_bytes == 100);
    uint8_t *got = NULL;
    size_t got_len = 0;
    ZS_CHECK("stagingq: accepted E chunk still readable",
             vcs_package_store_get_chunk(s, e.root, "d0", 0, &got,
                                         &got_len) == VCS_PACKAGE_STORE_OK);
    free(got);

    zs_free_package(&d);
    zs_free_package(&e);
    vcs_package_store_close(s);
    test_rm_rf_recursive(dd);
    return failures;
}

/* ── 7: deterministic HOT eviction (LRU) ──────────────────────────── */
static int store_case_hot_fill_and_promote(struct vcs_package_store *s,
                                            struct zs_pkg *quartet[4])
{
    int failures = 0;
    for (size_t q = 0; q < 4; q++) {
        ZS_CHECK("hot: package completes",
                 vcs_package_store_put_manifest(s, quartet[q]->wire,
                                                quartet[q]->wire_len,
                                                NULL) ==
                     VCS_PACKAGE_STORE_OK &&
                 zs_put_all(s, quartet[q]) == VCS_PACKAGE_STORE_OK);
        ZS_CHECK("hot: package promoted",
                 vcs_package_store_set_class(s, quartet[q]->root,
                                             VCS_PACKAGE_STORE_CLASS_HOT,
                                             0) == VCS_PACKAGE_STORE_OK);
    }
    ZS_CHECK("hot: hot pool exactly full",
             vcs_package_store_pool_usage(s, VCS_PACKAGE_STORE_POOL_HOT) ==
                 4000);
    return failures;
}

static int store_case_hot_access_requested(struct vcs_package_store *s,
                                            struct zs_pkg *requested[3])
{
    int failures = 0;
    /* G, H, I are requested; F is not. F is the only LRU victim. */
    for (size_t q = 0; q < 3; q++) {
        uint8_t *got = NULL;
        size_t got_len = 0;
        ZS_CHECK("hot: package accessed",
                 vcs_package_store_get_chunk(s, requested[q]->root, "x.bin",
                                             0, &got, &got_len) ==
                     VCS_PACKAGE_STORE_OK);
        free(got);
    }
    return failures;
}

static int store_case_hot_evict_and_verify(struct vcs_package_store *s,
                                            const char *dd, struct zs_pkg *f,
                                            struct zs_pkg *g,
                                            struct zs_pkg *h,
                                            struct zs_pkg *i2,
                                            struct zs_pkg *j2)
{
    int failures = 0;
    ZS_CHECK("hot: J completes into rare",
             vcs_package_store_put_manifest(s, j2->wire, j2->wire_len,
                                            NULL) == VCS_PACKAGE_STORE_OK &&
             zs_put_all(s, j2) == VCS_PACKAGE_STORE_OK);
    /* Promoting J (1000) into hot (4000/4000) evicts F (never accessed),
     * never a requested package and never the incoming J. */
    ZS_CHECK("hot: J promotion evicts the LRU package",
             vcs_package_store_set_class(s, j2->root,
                                         VCS_PACKAGE_STORE_CLASS_HOT, 0) ==
                 VCS_PACKAGE_STORE_OK);
    struct vcs_package_store_status st;
    ZS_CHECK("hot: evicted F is fully gone",
             !vcs_package_store_package_status(s, f->root, &st));
    char path[512];
    char suffix[160];
    snprintf(suffix, sizeof(suffix), "manifests/%s", f->root_hex);
    zs_store_path(path, sizeof(path), dd, suffix);
    ZS_CHECK("hot: evicted F's manifest deleted", !zs_path_exists(path));
    ZS_CHECK("hot: requested packages and incoming J survived",
             vcs_package_store_package_status(s, g->root, &st) &&
             st.pool == VCS_PACKAGE_STORE_POOL_HOT &&
             vcs_package_store_package_status(s, h->root, &st) &&
             st.pool == VCS_PACKAGE_STORE_POOL_HOT &&
             vcs_package_store_package_status(s, i2->root, &st) &&
             st.pool == VCS_PACKAGE_STORE_POOL_HOT &&
             vcs_package_store_package_status(s, j2->root, &st) &&
             st.pool == VCS_PACKAGE_STORE_POOL_HOT);
    ZS_CHECK("hot: hot pool within budget after eviction",
             vcs_package_store_pool_usage(s, VCS_PACKAGE_STORE_POOL_HOT) <=
                 4000);
    uint8_t *got = NULL;
    size_t got_len = 0;
    ZS_CHECK("hot: G still readable after F's eviction",
             vcs_package_store_get_chunk(s, g->root, "y.bin", 0, &got,
                                         &got_len) == VCS_PACKAGE_STORE_OK);
    free(got);
    return failures;
}

int t_store_hot_eviction(void)
{
    int failures = 0;
    /* quota 10000: staging 1000 (caps one package at 1000), hot 4000,
     * rare 3000. Five packages of 1000: four promoted hot fill the pool
     * exactly; promoting the fifth must evict the least-requested one. */
    char dd[256];
    struct vcs_package_store *s =
        zs_open(dd, sizeof(dd), "hotevict", 10000u);
    ZS_CHECK("hot: store opens", s != NULL);
    if (!s)
        return failures;

    const char *paths[] = { "x.bin", "y.bin" };
    const size_t lens[] = { 500, 500 };
    struct zs_pkg f, g, h, i2, j2;
    ZS_CHECK("hot: fixtures build",
             zs_make_package(&f, 2, paths, lens, 0x11) &&
             zs_make_package(&g, 2, paths, lens, 0x22) &&
             zs_make_package(&h, 2, paths, lens, 0x33) &&
             zs_make_package(&i2, 2, paths, lens, 0x44) &&
             zs_make_package(&j2, 2, paths, lens, 0x55));

    struct zs_pkg *quartet[] = { &f, &g, &h, &i2 };
    failures += store_case_hot_fill_and_promote(s, quartet);

    struct zs_pkg *requested[] = { &g, &h, &i2 };
    failures += store_case_hot_access_requested(s, requested);

    failures += store_case_hot_evict_and_verify(s, dd, &f, &g, &h, &i2, &j2);

    zs_free_package(&f);
    zs_free_package(&g);
    zs_free_package(&h);
    zs_free_package(&i2);
    zs_free_package(&j2);
    vcs_package_store_close(s);
    test_rm_rf_recursive(dd);
    return failures;
}

/* ── 8: deterministic RARE eviction (replicas desc) ───────────────── */
static int store_case_rare_fill_and_reclass(struct vcs_package_store *s,
                                             struct zs_pkg *trio[3],
                                             struct zs_pkg *i1)
{
    int failures = 0;
    for (size_t q = 0; q < 3; q++)
        ZS_CHECK("rare: package completes",
                 vcs_package_store_put_manifest(s, trio[q]->wire,
                                                trio[q]->wire_len,
                                                NULL) ==
                     VCS_PACKAGE_STORE_OK &&
                 zs_put_all(s, trio[q]) == VCS_PACKAGE_STORE_OK);
    ZS_CHECK("rare: rare pool exactly full",
             vcs_package_store_pool_usage(s, VCS_PACKAGE_STORE_POOL_RARE) ==
                 3000);
    /* I is well-replicated elsewhere; a replica update under an unchanged
     * class must not disturb the pools. */
    ZS_CHECK("rare: I's replica count recorded",
             vcs_package_store_set_class(s, i1->root,
                                         VCS_PACKAGE_STORE_CLASS_RARE, 5) ==
                 VCS_PACKAGE_STORE_OK);
    ZS_CHECK("rare: rare pool untouched by the replica update",
             vcs_package_store_pool_usage(s, VCS_PACKAGE_STORE_POOL_RARE) ==
                 3000);
    return failures;
}

static int store_case_rare_evict_and_verify(struct vcs_package_store *s,
                                             struct zs_pkg *i1,
                                             struct zs_pkg *j1,
                                             struct zs_pkg *k1,
                                             struct zs_pkg *l1)
{
    int failures = 0;
    ZS_CHECK("rare: L's completing chunk evicts the best-replicated I",
             vcs_package_store_put_manifest(s, l1->wire, l1->wire_len,
                                            NULL) == VCS_PACKAGE_STORE_OK &&
             zs_put_all(s, l1) == VCS_PACKAGE_STORE_OK);
    struct vcs_package_store_status st;
    ZS_CHECK("rare: best-replicated I evicted",
             !vcs_package_store_package_status(s, i1->root, &st));
    ZS_CHECK("rare: under-replicated J, K and incoming L survived",
             vcs_package_store_package_status(s, j1->root, &st) &&
             st.complete &&
             vcs_package_store_package_status(s, k1->root, &st) &&
             st.complete &&
             vcs_package_store_package_status(s, l1->root, &st) &&
             st.complete && st.pool == VCS_PACKAGE_STORE_POOL_RARE);
    ZS_CHECK("rare: rare pool within budget",
             vcs_package_store_pool_usage(s, VCS_PACKAGE_STORE_POOL_RARE) <=
                 3000);
    return failures;
}

int t_store_rare_eviction(void)
{
    int failures = 0;
    /* quota 10000: rare 3000. I, J, K at 1000 fill it exactly; L's
     * completion must evict the best-replicated victim (I). */
    char dd[256];
    struct vcs_package_store *s =
        zs_open(dd, sizeof(dd), "rareevict", 10000u);
    ZS_CHECK("rare: store opens", s != NULL);
    if (!s)
        return failures;

    const char *paths[] = { "p.bin", "q.bin" };
    const size_t lens[] = { 500, 500 };
    struct zs_pkg i1, j1, k1, l1;
    ZS_CHECK("rare: fixtures build",
             zs_make_package(&i1, 2, paths, lens, 0x66) &&
             zs_make_package(&j1, 2, paths, lens, 0x77) &&
             zs_make_package(&k1, 2, paths, lens, 0x88) &&
             zs_make_package(&l1, 2, paths, lens, 0x99));
    struct zs_pkg *trio[] = { &i1, &j1, &k1 };
    failures += store_case_rare_fill_and_reclass(s, trio, &i1);
    failures += store_case_rare_evict_and_verify(s, &i1, &j1, &k1, &l1);

    zs_free_package(&i1);
    zs_free_package(&j1);
    zs_free_package(&k1);
    zs_free_package(&l1);
    vcs_package_store_close(s);
    test_rm_rf_recursive(dd);
    return failures;
}

/* ── 9: pins ──────────────────────────────────────────────────────── */
static int store_case_pins_plan_token(struct vcs_package_store *s,
                                       struct zs_pkg *l)
{
    int failures = 0;
    uint8_t token_a[32], token_b[32];
    struct vcs_package_store_status plan_st;
    uint8_t *chunk = NULL;
    size_t chunk_len = 0;
    ZS_CHECK("pins: plan token is issued",
             vcs_package_store_pin_plan(s, l->root, true, &plan_st,
                                        token_a));
    ZS_CHECK("pins: a read after plan is allowed",
             vcs_package_store_get_chunk(s, l->root, "a.bin", 0, &chunk,
                                         &chunk_len) ==
                 VCS_PACKAGE_STORE_OK);
    free(chunk);
    ZS_CHECK("pins: plan token survives an access_count bump",
             vcs_package_store_pin_plan(s, l->root, true, &plan_st,
                                        token_b) &&
             memcmp(token_a, token_b, 32) == 0);
    ZS_CHECK("pins: unpin intent changes the plan token",
             vcs_package_store_pin_plan(s, l->root, false, &plan_st,
                                        token_b) &&
             memcmp(token_a, token_b, 32) != 0);
    return failures;
}

static int store_case_pins_l_completes_and_pins(struct vcs_package_store *s,
                                                 struct zs_pkg *l)
{
    int failures = 0;
    ZS_CHECK("pins: L completes and pins",
             vcs_package_store_put_manifest(s, l->wire, l->wire_len,
                                            NULL) == VCS_PACKAGE_STORE_OK &&
             zs_put_all(s, l) == VCS_PACKAGE_STORE_OK &&
             vcs_package_store_pin(s, l->root, true) ==
                 VCS_PACKAGE_STORE_OK);
    struct vcs_package_store_status st;
    ZS_CHECK("pins: L charges the pins pool",
             vcs_package_store_package_status(s, l->root, &st) &&
             st.pinned && st.pool == VCS_PACKAGE_STORE_POOL_PINS &&
             vcs_package_store_pool_usage(s, VCS_PACKAGE_STORE_POOL_PINS) ==
                 1000);
    ZS_CHECK("pins: full-byte possession proof accepts complete pinned L",
             vcs_package_store_verify_possession(s, l->root, true));
    failures += store_case_pins_plan_token(s, l);
    return failures;
}

static int store_case_pins_m_fills_pool_and_n_refused(
    struct vcs_package_store *s, struct zs_pkg *m, struct zs_pkg *n)
{
    int failures = 0;
    ZS_CHECK("pins: M completes and pins (pins pool exactly full)",
             vcs_package_store_put_manifest(s, m->wire, m->wire_len,
                                            NULL) == VCS_PACKAGE_STORE_OK &&
             zs_put_all(s, m) == VCS_PACKAGE_STORE_OK &&
             vcs_package_store_pin(s, m->root, true) ==
                 VCS_PACKAGE_STORE_OK &&
             vcs_package_store_pool_usage(s, VCS_PACKAGE_STORE_POOL_PINS) ==
                 2000);
    ZS_CHECK("pins: N completes into rare",
             vcs_package_store_put_manifest(s, n->wire, n->wire_len,
                                            NULL) == VCS_PACKAGE_STORE_OK &&
             zs_put_all(s, n) == VCS_PACKAGE_STORE_OK);
    struct vcs_package_store_status st;
    /* Pins are never made room for by eviction: a pin that does not fit
     * fails, and the package stays as it was. */
    ZS_CHECK("pins: over-budget pin refused without evicting",
             vcs_package_store_pin(s, n->root, true) ==
                 VCS_PACKAGE_STORE_ERR_QUOTA);
    ZS_CHECK("pins: refused pin left N unpinned",
             vcs_package_store_package_status(s, n->root, &st) &&
             !st.pinned && st.pool == VCS_PACKAGE_STORE_POOL_RARE);
    return failures;
}

static int store_case_pins_unpin_m(struct vcs_package_store *s,
                                    struct zs_pkg *m)
{
    int failures = 0;
    struct vcs_package_store_status st;
    ZS_CHECK("pins: unpin returns M to its class pool",
             vcs_package_store_pin(s, m->root, false) ==
                 VCS_PACKAGE_STORE_OK &&
             vcs_package_store_package_status(s, m->root, &st) &&
             !st.pinned && st.pool == VCS_PACKAGE_STORE_POOL_RARE);
    ZS_CHECK("pins: possession proof fails closed after unpin",
             !vcs_package_store_verify_possession(s, m->root, true));
    return failures;
}

static int store_case_pins_rare_pressure(struct vcs_package_store *s,
                                          struct zs_pkg *l, struct zs_pkg *m,
                                          struct zs_pkg *n, struct zs_pkg *o,
                                          struct zs_pkg *p2)
{
    int failures = 0;
    /* Rare-pool pressure: O fills rare exactly (3000), P's completion
     * must evict exactly one rare package and must never touch the
     * pinned L. (All rare candidates tie on replicas/access, so the
     * victim is the lowest root hex — which one is irrelevant here.) */
    ZS_CHECK("pins: O + P complete under rare-pool pressure",
             vcs_package_store_put_manifest(s, o->wire, o->wire_len,
                                            NULL) == VCS_PACKAGE_STORE_OK &&
             zs_put_all(s, o) == VCS_PACKAGE_STORE_OK &&
             vcs_package_store_put_manifest(s, p2->wire, p2->wire_len,
                                            NULL) == VCS_PACKAGE_STORE_OK &&
             zs_put_all(s, p2) == VCS_PACKAGE_STORE_OK);
    struct vcs_package_store_status st;
    ZS_CHECK("pins: pinned L survived rare-pool pressure",
             vcs_package_store_package_status(s, l->root, &st) &&
             st.pinned && st.complete &&
             st.pool == VCS_PACKAGE_STORE_POOL_PINS);
    size_t survivors =
        (vcs_package_store_package_status(s, m->root, &st) ? 1u : 0u) +
        (vcs_package_store_package_status(s, n->root, &st) ? 1u : 0u) +
        (vcs_package_store_package_status(s, o->root, &st) ? 1u : 0u) +
        (vcs_package_store_package_status(s, p2->root, &st) ? 1u : 0u);
    ZS_CHECK("pins: exactly one rare package was evicted",
             survivors == 3u);
    ZS_CHECK("pins: rare pool within budget",
             vcs_package_store_pool_usage(s, VCS_PACKAGE_STORE_POOL_RARE) <=
                 3000);
    uint8_t *got = NULL;
    size_t got_len = 0;
    ZS_CHECK("pins: L still readable",
             vcs_package_store_get_chunk(s, l->root, "a.bin", 0, &got,
                                         &got_len) == VCS_PACKAGE_STORE_OK);
    free(got);
    return failures;
}

static int store_case_pins_pre_existing_marker(struct vcs_package_store *s,
                                                const char *dd,
                                                const char *paths[2],
                                                const size_t lens[2],
                                                struct zs_pkg *pre)
{
    int failures = 0;
    /* A pin marker that pre-exists the manifest pins at admission. */
    ZS_CHECK("pins: pre-pinned fixture builds",
             zs_make_package(pre, 2, paths, lens, 0xf0));
    char marker[512];
    char suffix[160];
    snprintf(suffix, sizeof(suffix), "pins/%s", pre->root_hex);
    zs_store_path(marker, sizeof(marker), dd, suffix);
    FILE *f = fopen(marker, "wb");
    ZS_CHECK("pins: marker planted", f != NULL);
    if (f)
        fclose(f);
    struct vcs_package_store_status st;
    ZS_CHECK("pins: admission honors a pre-existing marker",
             vcs_package_store_put_manifest(s, pre->wire, pre->wire_len,
                                            NULL) == VCS_PACKAGE_STORE_OK &&
             vcs_package_store_package_status(s, pre->root, &st) &&
             st.pinned && st.pool == VCS_PACKAGE_STORE_POOL_PINS);
    return failures;
}

static int store_case_pins_possession_fails_after_missing_byte(
    struct vcs_package_store *s, const char *dd, struct zs_pkg *l)
{
    int failures = 0;
    /* A durable ACK is a claim about bytes that are still present, not a
     * sticky bit in package metadata. Removing one pinned CAS chunk must
     * immediately invalidate the possession proof used by ACK renewal. */
    uint8_t missing_hash[32];
    char missing_hex[65];
    char missing_suffix[160];
    char missing_path[512];
    ZS_CHECK("pins: missing-byte fixture hash",
             vcs_package_chunk_hash(l->contents[0], l->lens[0],
                                    missing_hash));
    zs_hex32(missing_hash, missing_hex);
    snprintf(missing_suffix, sizeof(missing_suffix), "cas/sha3/%02x/%s",
             missing_hash[0], missing_hex);
    zs_store_path(missing_path, sizeof(missing_path), dd, missing_suffix);
    ZS_CHECK("pins: pinned byte deletion planted", unlink(missing_path) == 0);
    ZS_CHECK("pins: possession proof fails after missing byte",
             !vcs_package_store_verify_possession(s, l->root, true));
    return failures;
}

int t_store_pins(void)
{
    int failures = 0;
    /* quota 10000: pins 2000, rare 3000, staging 1000. */
    char dd[256];
    struct vcs_package_store *s = zs_open(dd, sizeof(dd), "pins", 10000u);
    ZS_CHECK("pins: store opens", s != NULL);
    if (!s)
        return failures;

    const char *paths[] = { "a.bin", "b.bin" };
    const size_t lens[] = { 500, 500 };
    struct zs_pkg l, m, n, o, p2;
    ZS_CHECK("pins: fixtures build",
             zs_make_package(&l, 2, paths, lens, 0xaa) &&
             zs_make_package(&m, 2, paths, lens, 0xbb) &&
             zs_make_package(&n, 2, paths, lens, 0xcc) &&
             zs_make_package(&o, 2, paths, lens, 0xdd) &&
             zs_make_package(&p2, 2, paths, lens, 0xee));

    failures += store_case_pins_l_completes_and_pins(s, &l);
    failures += store_case_pins_m_fills_pool_and_n_refused(s, &m, &n);
    failures += store_case_pins_unpin_m(s, &m);
    failures += store_case_pins_rare_pressure(s, &l, &m, &n, &o, &p2);

    struct zs_pkg pre;
    failures += store_case_pins_pre_existing_marker(s, dd, paths, lens,
                                                     &pre);
    failures += store_case_pins_possession_fails_after_missing_byte(s, dd,
                                                                     &l);

    zs_free_package(&l);
    zs_free_package(&m);
    zs_free_package(&n);
    zs_free_package(&o);
    zs_free_package(&p2);
    zs_free_package(&pre);
    vcs_package_store_close(s);
    test_rm_rf_recursive(dd);
    return failures;
}

/* ── 10: bounded possession scheduler ────────────────────────────── */
static int store_case_possession_fixtures(struct vcs_package_store *store,
                                           struct zs_pkg packages[3])
{
    int failures = 0;
    const char *large_paths[] = {
        "a.bin", "b.bin", "c.bin", "d.bin"};
    const size_t large_lens[] = {500, 500, 500, 500};
    const char *small_paths[] = {"only.bin"};
    const size_t small_lens[] = {500};
    bool fixtures = true;
    fixtures &= zs_make_package(&packages[0], 4, large_paths, large_lens,
                                0x21);
    for (size_t i = 1; i < 3; i++)
        fixtures &= zs_make_package(&packages[i], 1, small_paths, small_lens,
                                    (uint8_t)(0x21 + i * 0x20));
    ZS_CHECK("possession scheduler: fixtures build", fixtures);
    bool stored = fixtures;
    for (size_t i = 0; i < 3 && stored; i++)
        stored = vcs_package_store_put_manifest(
                     store, packages[i].wire, packages[i].wire_len, NULL) ==
                     VCS_PACKAGE_STORE_OK &&
                 zs_put_all(store, &packages[i]) == VCS_PACKAGE_STORE_OK &&
                 vcs_package_store_pin(store, packages[i].root, true) ==
                     VCS_PACKAGE_STORE_OK;
    ZS_CHECK("possession scheduler: packages complete and pin", stored);
    return failures;
}

static int store_case_possession_incremental_proof(
    struct vcs_package_store *store, struct zs_pkg *pkg0)
{
    int failures = 0;
    struct vcs_package_store_status before;
    ZS_CHECK("possession scheduler: mutation generation is published",
             vcs_package_store_package_status(store, pkg0->root,
                                              &before) &&
                 before.mutation_generation != 0 && before.complete &&
                 before.pinned);

    struct vcs_package_possession_receipt receipt;
    struct vcs_package_possession_proof *proof =
        vcs_package_store_possession_begin(store, pkg0->root, true,
                                           &receipt);
    ZS_CHECK("possession scheduler: incremental proof begins", proof != NULL);
    uint64_t used = UINT64_MAX;
    enum vcs_package_possession_step step =
        vcs_package_store_possession_step(proof, 499, 1, &receipt, &used);
    ZS_CHECK("possession scheduler: strict byte budget reads nothing",
             step == VCS_PACKAGE_POSSESSION_BUDGET && used == 0 &&
                 receipt.bytes_verified == 0);
    step = vcs_package_store_possession_step(proof, 500, 1, &receipt,
                                             &used);
    ZS_CHECK("possession scheduler: one-chunk budget advances once",
             step == VCS_PACKAGE_POSSESSION_PROGRESS && used == 500 &&
                 receipt.bytes_verified == 500);
    ZS_CHECK("possession scheduler: unpin and repin mutate generation",
             vcs_package_store_pin(store, pkg0->root, false) ==
                     VCS_PACKAGE_STORE_OK &&
                 vcs_package_store_pin(store, pkg0->root, true) ==
                     VCS_PACKAGE_STORE_OK);
    do {
        step = vcs_package_store_possession_step(
            proof, VCS_PACKAGE_CHUNK_BYTES, 8, &receipt, &used);
    } while (step == VCS_PACKAGE_POSSESSION_PROGRESS);
    ZS_CHECK("possession scheduler: proof refuses post-snapshot mutation",
             step == VCS_PACKAGE_POSSESSION_FAILED &&
                 receipt.failure == VCS_PACKAGE_POSSESSION_MUTATED);
    vcs_package_store_possession_free(proof);
    return failures;
}

static int store_case_possession_bounded_scheduler(
    struct vcs_package_store *store, uint8_t roots[3][32],
    struct vcs_package_possession_scheduler **out_scheduler,
    uint64_t *out_bytes_before_idle)
{
    int failures = 0;
    struct vcs_package_possession_scheduler_config config = {
        .packages_per_cycle = 1,
        .chunks_per_package_cycle = 1,
        .bytes_per_cycle = VCS_PACKAGE_CHUNK_BYTES,
        .scrub_interval_s = 100,
        .failure_retry_s = 5,
    };
    struct vcs_package_possession_scheduler *scheduler =
        vcs_package_possession_scheduler_new(&config);
    ZS_CHECK("possession scheduler: bounded scheduler opens and watches",
             scheduler != NULL &&
                 vcs_package_possession_scheduler_reconcile(
                     scheduler, store, roots, 3, 1000));
    for (uint64_t now = 1000; now < 1040; now++)
        vcs_package_possession_scheduler_run(scheduler, store, now);
    bool all_current = true;
    for (size_t i = 0; i < 3; i++)
        all_current &= vcs_package_possession_scheduler_current(
            scheduler, store, roots[i], NULL);
    struct vcs_package_possession_scheduler_status status;
    vcs_package_possession_scheduler_status(scheduler, 1040, &status);
    ZS_CHECK("possession scheduler: large root cannot starve small roots",
             all_current && status.successful_proofs == 3 &&
                 status.tracked_roots == 3);
    ZS_CHECK("possession scheduler: per-cycle budgets stayed strict",
             status.last_cycle_packages <= 1 &&
                 status.last_cycle_bytes <= VCS_PACKAGE_CHUNK_BYTES);
    uint64_t bytes_before_idle = status.bytes_verified_total;
    vcs_package_possession_scheduler_run(scheduler, store, 1041);
    vcs_package_possession_scheduler_status(scheduler, 1041, &status);
    ZS_CHECK("possession scheduler: ordinary pass does not rehash",
             status.last_cycle_packages == 0 &&
                 status.last_cycle_bytes == 0 &&
                 status.bytes_verified_total == bytes_before_idle);
    *out_scheduler = scheduler;
    *out_bytes_before_idle = bytes_before_idle;
    return failures;
}

static int store_case_possession_unpin_and_requeue(
    struct vcs_package_store *store,
    struct vcs_package_possession_scheduler *scheduler,
    struct zs_pkg *pkg1, uint8_t roots[3][32], uint64_t bytes_before_idle)
{
    int failures = 0;
    ZS_CHECK("possession scheduler: unpin invalidates cached proof",
             vcs_package_store_pin(store, pkg1->root, false) ==
                     VCS_PACKAGE_STORE_OK &&
                 !vcs_package_possession_scheduler_current(
                     scheduler, store, pkg1->root, NULL));
    ZS_CHECK("possession scheduler: mutation queues only changed root",
             vcs_package_possession_scheduler_reconcile(
                 scheduler, store, roots, 3, 1042) &&
                 vcs_package_possession_scheduler_require(
                     scheduler, roots[1], 1042));
    struct vcs_package_possession_scheduler_status status;
    vcs_package_possession_scheduler_status(scheduler, 1042, &status);
    ZS_CHECK("possession scheduler: diagnostics expose queue/failure counts",
             status.queued_roots == 1 && status.next_due_mono == 1042 &&
                 status.bytes_verified_total == bytes_before_idle);
    vcs_package_possession_scheduler_run(scheduler, store, 1042);
    vcs_package_possession_scheduler_require(
        scheduler, roots[1], 1043);
    vcs_package_possession_scheduler_status(scheduler, 1043, &status);
    ZS_CHECK("possession scheduler: failed proof respects retry deadline",
             status.next_due_mono == 1047 && status.failed_proofs >= 1);
    return failures;
}

static int store_case_possession_raced_deletion(
    struct vcs_package_store *store, struct zs_pkg *pkg2, const char *dd)
{
    int failures = 0;
    struct vcs_package_possession_receipt receipt;
    struct vcs_package_possession_proof *proof =
        vcs_package_store_possession_begin(
            store, pkg2->root, true, &receipt);
    uint64_t used = UINT64_MAX;
    enum vcs_package_possession_step step =
        vcs_package_store_possession_step(proof, 500, 1, &receipt, &used);
    uint8_t raced_hash[32];
    char raced_hex[65], raced_suffix[160], raced_path[512];
    bool raced_path_ready =
        proof && step == VCS_PACKAGE_POSSESSION_PROGRESS &&
        vcs_package_chunk_hash(pkg2->contents[0],
                               pkg2->lens[0], raced_hash);
    if (raced_path_ready) {
        zs_hex32(raced_hash, raced_hex);
        snprintf(raced_suffix, sizeof(raced_suffix),
                 "cas/sha3/%02x/%s", raced_hash[0], raced_hex);
        zs_store_path(raced_path, sizeof(raced_path), dd, raced_suffix);
        raced_path_ready = unlink(raced_path) == 0;
    }
    do {
        step = vcs_package_store_possession_step(
            proof, VCS_PACKAGE_CHUNK_BYTES, 8, &receipt, &used);
    } while (step == VCS_PACKAGE_POSSESSION_PROGRESS);
    ZS_CHECK("possession scheduler: post-read byte deletion is not accepted",
             raced_path_ready &&
                 step == VCS_PACKAGE_POSSESSION_FAILED &&
                 receipt.failure == VCS_PACKAGE_POSSESSION_MUTATED);
    vcs_package_store_possession_free(proof);
    return failures;
}

static int store_case_possession_fresh_request_invalidates(
    struct vcs_package_store *store,
    struct vcs_package_possession_scheduler *scheduler,
    uint8_t roots[3][32])
{
    int failures = 0;
    for (size_t i = 0; i < 3; i++)
        vcs_package_possession_scheduler_run(scheduler, store, 1200);
    ZS_CHECK("possession scheduler: fresh request invalidates cached success",
             vcs_package_possession_scheduler_require(
                 scheduler, roots[0], 1200) &&
                 !vcs_package_possession_scheduler_current(
                     scheduler, store, roots[0], NULL));
    return failures;
}

int t_store_possession_scheduler(void)
{
    int failures = 0;
    char dd[256];
    struct vcs_package_store *store =
        zs_open(dd, sizeof(dd), "possession_scheduler", 10000000u);
    ZS_CHECK("possession scheduler: store opens", store != NULL);
    if (!store)
        return failures;

    struct zs_pkg packages[3];
    failures += store_case_possession_fixtures(store, packages);
    failures += store_case_possession_incremental_proof(store,
                                                         &packages[0]);

    uint8_t roots[3][32];
    for (size_t i = 0; i < 3; i++)
        memcpy(roots[i], packages[i].root, 32);
    struct vcs_package_possession_scheduler *scheduler = NULL;
    uint64_t bytes_before_idle = 0;
    failures += store_case_possession_bounded_scheduler(
        store, roots, &scheduler, &bytes_before_idle);
    failures += store_case_possession_unpin_and_requeue(
        store, scheduler, &packages[1], roots, bytes_before_idle);
    failures += store_case_possession_raced_deletion(store, &packages[2],
                                                      dd);
    failures += store_case_possession_fresh_request_invalidates(
        store, scheduler, roots);

    vcs_package_possession_scheduler_free(scheduler);
    for (size_t i = 0; i < 3; i++)
        zs_free_package(&packages[i]);
    vcs_package_store_close(store);
    test_rm_rf_recursive(dd);
    return failures;
}

/* ── 11: release envelopes ────────────────────────────────────────── */
int t_store_releases(void)
{
    int failures = 0;
    chain_params_select(CHAIN_MAIN);
    char dd[256];
    struct vcs_package_store *s =
        zs_open(dd, sizeof(dd), "releases", 1000000u);
    ZS_CHECK("releases: store opens", s != NULL);
    if (!s)
        return failures;

    struct vcs_package_release r;
    ZS_CHECK("releases: fixture signs",
             zs_release(&r, 0x11, 1u, "rhett/ring-buffer"));
    enum vcs_package_accept_result ar = VCS_PACKAGE_ACCEPT_ERR_NULL;
    ZS_CHECK("releases: accepted envelope stored",
             vcs_package_store_put_release(s, &r, &ar) ==
                 VCS_PACKAGE_STORE_OK && ar == VCS_PACKAGE_ACCEPT_OK);
    uint8_t id[VCS_PACKAGE_RELEASE_ID_BYTES];
    ZS_CHECK("releases: id computes",
             vcs_package_release_id(&r, id) == VCS_PACKAGE_RELEASE_OK);
    char hex[65];
    zs_hex32(id, hex);
    char path[512];
    char suffix[160];
    snprintf(suffix, sizeof(suffix), "releases/%s", hex);
    zs_store_path(path, sizeof(path), dd, suffix);
    ZS_CHECK("releases: envelope persisted under its id",
             zs_path_exists(path));

    ZS_CHECK("releases: redelivery is an idempotent store",
             vcs_package_store_put_release(s, &r, &ar) ==
                 VCS_PACKAGE_STORE_OK && ar == VCS_PACKAGE_ACCEPT_DUPLICATE);

    struct vcs_package_release forked;
    ZS_CHECK("releases: equivocation fixture signs",
             zs_release(&forked, 0x11, 1u, "rhett/ring-buffer-fork"));
    ZS_CHECK("releases: equivocation rejected, nothing stored",
             vcs_package_store_put_release(s, &forked, &ar) ==
                 VCS_PACKAGE_STORE_ERR_ACCEPT &&
             ar == VCS_PACKAGE_ACCEPT_EQUIVOCATION);
    uint8_t forked_id[VCS_PACKAGE_RELEASE_ID_BYTES];
    ZS_CHECK("releases: equivocation id computes",
             vcs_package_release_id(&forked, forked_id) ==
                 VCS_PACKAGE_RELEASE_OK);
    zs_hex32(forked_id, hex);
    snprintf(suffix, sizeof(suffix), "releases/%s", hex);
    zs_store_path(path, sizeof(path), dd, suffix);
    ZS_CHECK("releases: equivocated envelope not persisted",
             !zs_path_exists(path));

    ZS_CHECK("releases: null args rejected",
             vcs_package_store_put_release(NULL, &r, &ar) ==
                 VCS_PACKAGE_STORE_ERR_NULL &&
             vcs_package_store_put_release(s, NULL, &ar) ==
                 VCS_PACKAGE_STORE_ERR_NULL);

    vcs_package_store_close(s);
    test_rm_rf_recursive(dd);
    return failures;
}

