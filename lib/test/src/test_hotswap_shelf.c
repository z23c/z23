/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Tests for the hot-swap IMAGE COMMIT — the step that decides which module
 * image is live for a source and which superseded mapping may be released —
 * and for the depth-1 rollback SHELF built on top of it
 * (hotswap/hotswap_shelf.h).
 *
 * WHY THIS FILE EXISTS AT ALL, said plainly: an earlier version of the shelf
 * shipped with its concurrency story UNTESTED, and an integration review
 * reverted it for "an unsafe module-retirement race". The race is real. It is
 * reproduced here DETERMINISTICALLY, and every assertion below was checked to
 * FAIL against the code without the fix (see the discrimination notes on each
 * test).
 *
 * THE RACE, in one paragraph. A swap is two steps that are not one atomic
 * step: hotswap_module_publish() makes the registry dispatch into the new
 * image and assigns it a generation, and then the loader records that image
 * against its source and retires the previous one. The first step runs
 * resident probe/commit callbacks, so it cannot hold a loader lock — which
 * means two activations of the same source can publish in one order and
 * arrive at the commit in the other. The loser then hands the WINNER's image
 * to the retire path, and the old drain-only quiescence test cannot see the
 * problem: drain proves nothing is still inside a RETIRED snapshot, and the
 * ACTIVE snapshot is skipped by design because it is always live. The result
 * is an unmap of the code the live snapshot dispatches into.
 *
 * HOW THE RACE IS MADE DETERMINISTIC HERE, without instrumenting production.
 * The registry commit callback is a hook the CALLER supplies (see
 * test_hotswap_module_v2.c, and zcl_native_hotswap_publish_hooks() for the
 * resident's own). So this file's commit hook parks the "slow" publisher
 * inside the hook, immediately after zcl_command_registry_replace_batch() has
 * returned and its generation has been read, and releases it only once the
 * "fast" publisher has completed BOTH of its steps. That is exactly the
 * production window — registry published, loader commit not yet reached — and
 * it is reproduced 100% of the time rather than hoped for.
 *
 * WHAT IS DRIVEN, AND WHAT IS NOT. Publishes are REAL: the pure, always-
 * compiled hotswap_module_publish() gauntlet (admit -> probe -> ONE batch
 * commit) publishing into the REAL kernel command-registry override layer,
 * with real lock-free snapshots, real refcount drain, and real
 * zcl_command_registry_execute_json() dispatch running against it from other
 * threads. The image commit is the REAL production function
 * (hotswap_commit_image), reached by the loader through exactly this call.
 * What is NOT real is dlopen: an "image" here is a test-owned token and the
 * unmap seam is a test observer, because building a module .so needs a
 * compiler and a build rule this group does not have. That substitution costs
 * nothing for what is under test — the race is in the sequencing, not in the
 * dynamic loader — and it BUYS a stronger oracle than a crash would be: the
 * observer can ask, at the instant of the unmap, whether the live snapshot
 * still resolves that leaf to this image's handler. A SIGSEGV would only tell
 * us that something went wrong somewhere later.
 *
 * ⛔ STILL UNVERIFIED BY THIS FILE (no test here claims otherwise): a real
 * dlopen'd .so being unmapped; rollback COMPLETING (it re-runs the full
 * gauntlet, which needs the dev datadir plus -hotswap-activate plus
 * ZCL_HOTSWAP_ACTIVATE=1, none of which a test_parallel process has, so every
 * rollback below is driven to a refusal — its CLAIM, its shelf accounting and
 * its descriptor discipline are what is proven); and the rollback toggle.
 */

#include "test/test_helpers.h"

#include "hotswap/hotswap.h"
#include "hotswap/hotswap_module.h"
#include "hotswap/hotswap_retire_blocker.h"
#include "hotswap/hotswap_shelf.h"
#include "platform/os_proc.h"
#include "kernel/command_registry.h"
#include "json/json.h"
#include "util/blocker.h"

#include <fcntl.h>
#include <pthread.h>
#include <sched.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

/* The status controller row of config/hotswap_swappable.def; its declared
 * probe leaf in config/hotswap_eligible.def is core.status. Both leaves used
 * below are on that row, so hotswap_module_admit() accepts them. */
#define SHELF_TU      "app/controllers/src/status_native_handlers.c"
#define LEAF_PROBE    "core.status"
#define LEAF_SECOND   "core.sync.diagnose"
/* A different allowlisted row, touched by nothing here. */
#define SHELF_TU_META "app/controllers/src/meta_native_handlers.c"
/* Never allowlisted at all (a consensus TU). */
#define SHELF_TU_UNKNOWN "lib/consensus/src/pow.c"

/* ── The image pool ───────────────────────────────────────────────────────
 * One handler function per image, never shared, so a dispatch that lands in
 * an image can say WHICH image it landed in — the direct use-after-free
 * observation. `unmapped` is what the test's unmap seam sets; a handler that
 * runs with it set is a dispatch into released code. */
#define IMG_MAX 16

struct img {
    _Atomic bool unmapped;
    _Atomic int  inflight;
    uint32_t     generation;
    uint32_t     leaf_count;
    const char  *leaf[2];
    zcl_command_handler_fn fn;
    int          fd;
};
static struct img g_img[IMG_MAX];
static _Atomic uint64_t g_dispatch_into_unmapped;
static _Atomic uint64_t g_unmap_calls;
/* The unmap seam saw the live snapshot still resolving one of this image's
 * leaves to this image's handler. Every one of these is the reviewer's race,
 * caught in the act. */
static _Atomic uint64_t g_unmap_of_live_image;
/* The unmap seam saw a dispatch still inside a handler of an image that is
 * not the live one for any leaf. That is the drain gate failing. */
static _Atomic uint64_t g_unmap_with_dispatch_inside;

#define IMG_HANDLER(i)                                                       \
static void h_img##i(const struct zcl_command_request *rq,                   \
                     struct zcl_command_reply *rp)                           \
{                                                                            \
    (void)rq;                                                                \
    struct img *im = &g_img[i];                                              \
    atomic_fetch_add(&im->inflight, 1);                                      \
    if (atomic_load(&im->unmapped))                                          \
        atomic_fetch_add(&g_dispatch_into_unmapped, 1);                      \
    (void)json_push_kv_str(&rp->data, "who", "img" #i);                      \
    atomic_fetch_sub(&im->inflight, 1);                                      \
}

IMG_HANDLER(0)  IMG_HANDLER(1)  IMG_HANDLER(2)  IMG_HANDLER(3)
IMG_HANDLER(4)  IMG_HANDLER(5)  IMG_HANDLER(6)  IMG_HANDLER(7)
IMG_HANDLER(8)  IMG_HANDLER(9)  IMG_HANDLER(10) IMG_HANDLER(11)
IMG_HANDLER(12) IMG_HANDLER(13) IMG_HANDLER(14) IMG_HANDLER(15)

static const zcl_command_handler_fn k_img_fn[IMG_MAX] = {
    h_img0,  h_img1,  h_img2,  h_img3,  h_img4,  h_img5,  h_img6,  h_img7,
    h_img8,  h_img9,  h_img10, h_img11, h_img12, h_img13, h_img14, h_img15,
};

/* ── A registry the override layer can validate against ──────────────────
 * The override commit re-checks READY + read-only + resolvable, so the bound
 * registry must carry the real leaf paths under test. */
static void h_resident(const struct zcl_command_request *rq,
                       struct zcl_command_reply *rp)
{
    (void)rq;
    (void)json_push_kv_str(&rp->data, "who", "resident");
}

static const struct zcl_command_spec g_specs[] = {
    { .path = LEAF_PROBE, .summary = "swappable read leaf",
      .layer = ZCL_COMMAND_LAYER_CORE, .effect = ZCL_COMMAND_EFFECT_READ,
      .availability = ZCL_COMMAND_READY, .mode = ZCL_COMMAND_MODE_SYNC,
      .allowed_lanes = ZCL_COMMAND_LANE_LOCAL,
      .output_schema = "zcl.core_status.v2", .handler = h_resident },
    { .path = LEAF_SECOND, .summary = "swappable read leaf",
      .layer = ZCL_COMMAND_LAYER_CORE, .effect = ZCL_COMMAND_EFFECT_READ,
      .availability = ZCL_COMMAND_READY, .mode = ZCL_COMMAND_MODE_SYNC,
      .allowed_lanes = ZCL_COMMAND_LANE_LOCAL,
      .output_schema = "zcl.sync_diagnose.v1", .handler = h_resident },
};
static const struct zcl_command_registry g_reg = {
    .commands = g_specs,
    .count = sizeof(g_specs) / sizeof(g_specs[0]),
};

static const struct zcl_command_spec *find_spec(const char *path)
{
    for (size_t i = 0; i < g_reg.count; i++)
        if (strcmp(g_reg.commands[i].path, path) == 0)
            return &g_reg.commands[i];
    return NULL;
}

/* Dispatch a leaf through the REAL registry entry point, so the override
 * snapshot is acquired and released exactly as it is in the node. */
static enum zcl_command_exit exec_path(const char *path, char *out,
                                       size_t out_size)
{
    const struct zcl_command_spec *spec = find_spec(path);
    struct json_value input;
    json_init(&input);
    json_set_object(&input);
    enum zcl_command_exit exit_code = ZCL_COMMAND_EXIT_INTERNAL;
    (void)zcl_command_registry_execute_json(&g_reg, spec, NULL, &input, false,
                                            path, "normal", 0, 0, NULL, out,
                                            out_size, &exit_code);
    json_free(&input);
    return exit_code;
}

/* ── The unmap seam: the oracle ──────────────────────────────────────────
 * Called by the production retire path at the exact moment it has decided a
 * mapping may be released. Asking the registry here is what makes a wrong
 * decision observable without needing a real unmap to crash later. */
static bool handler_is_live_anywhere(zcl_command_handler_fn fn)
{
    for (size_t i = 0; i < g_reg.count; i++) {
        if (zcl_command_registry_effective_handler(&g_reg.commands[i]) == fn)
            return true;
    }
    return false;
}

static void test_unmap(void *handle)
{
    struct img *im = (struct img *)handle;
    atomic_fetch_add(&g_unmap_calls, 1);
    if (!im)
        return;
    for (uint32_t k = 0; k < im->leaf_count; k++) {
        const struct zcl_command_spec *spec = find_spec(im->leaf[k]);
        if (spec && zcl_command_registry_effective_handler(spec) == im->fn) {
            /* The live snapshot still resolves this leaf to this image. In a
             * real node the unmap that is about to happen makes the next
             * dispatch of that leaf a jump into unmapped pages. Recorded AND
             * carried out, so the dispatch threads see it too. */
            atomic_fetch_add(&g_unmap_of_live_image, 1);
            break;
        }
    }
    if (!handler_is_live_anywhere(im->fn) && atomic_load(&im->inflight) != 0)
        atomic_fetch_add(&g_unmap_with_dispatch_inside, 1);
    atomic_store(&im->unmapped, true);
}

/* ── Publish hooks ───────────────────────────────────────────────────────
 * Same shape as the resident's (tools/command/native_dev_hotswap.c): commit
 * publishes into the real registry and reports the generation by reading the
 * active generation back, so this file inherits the resident's own precision
 * — and its imprecision — rather than a friendlier version of it. */
static pthread_mutex_t g_sync_m = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t  g_sync_c = PTHREAD_COND_INITIALIZER;
static bool g_slow_published;      /* guarded by g_sync_m */
static bool g_fast_done;           /* guarded by g_sync_m */
static pthread_t g_slow_tid;
static _Atomic bool g_park_armed;

static bool t_commit(void *ctx, const struct zcl_hotswap_leaf *leaves,
                     size_t leaf_count, uint32_t *out_gen, char *why,
                     size_t why_sz)
{
    (void)ctx;
    if (!leaves || leaf_count == 0 ||
        leaf_count > ZCL_COMMAND_HANDLER_OVERRIDE_MAX) {
        if (why && why_sz) snprintf(why, why_sz, "bad batch size %zu", leaf_count);
        return false;
    }
    struct zcl_command_handler_override ovr[ZCL_COMMAND_HANDLER_OVERRIDE_MAX];
    for (size_t i = 0; i < leaf_count; i++) {
        ovr[i].path = leaves[i].name;
        ovr[i].handler = leaves[i].fn;
    }
    if (!zcl_command_registry_replace_batch(0, ovr, leaf_count, why, why_sz))
        return false;
    if (out_gen)
        *out_gen = zcl_command_registry_active_generation();

    /* THE WINDOW. Registry published, loader commit not yet reached. Parking
     * the slow publisher here — and only here — reproduces the production
     * interleaving exactly, with no production code aware of the test. */
    if (atomic_load(&g_park_armed) && pthread_equal(pthread_self(), g_slow_tid)) {
        pthread_mutex_lock(&g_sync_m);
        g_slow_published = true;
        pthread_cond_broadcast(&g_sync_c);
        while (!g_fast_done)
            pthread_cond_wait(&g_sync_c, &g_sync_m);
        pthread_mutex_unlock(&g_sync_m);
    }
    return true;
}

static bool t_probe(void *ctx, const char *leaf, zcl_hotswap_handler_fn fn,
                    char *why, size_t why_sz)
{
    (void)ctx;
    (void)leaf;
    if (!fn) {
        if (why && why_sz) snprintf(why, why_sz, "probe handler is NULL");
        return false;
    }
    return true;
}

static bool t_quiesced(void *ctx)
{
    (void)ctx;
    return zcl_command_registry_all_retired_quiesced();
}

static void t_hooks(struct hotswap_publish_hooks *h)
{
    memset(h, 0, sizeof(*h));
    h->commit = t_commit;
    h->probe = t_probe;
    h->quiesced = t_quiesced;
}

static bool selftest_true(char *err, size_t cap)
{
    (void)err;
    (void)cap;
    return true;
}

/* ── Driving one image all the way through publish + commit ──────────────
 * Exactly the two steps the loader runs, in the loader's order. */
static bool drive_image(int idx, const char *source_tu,
                        const char *const *leaves, uint32_t leaf_count,
                        const char *sha, const char *datadir,
                        struct hotswap_activate_report *report)
{
    struct img *im = &g_img[idx];
    struct zcl_hotswap_leaf leafv[2];
    for (uint32_t i = 0; i < leaf_count; i++) {
        leafv[i].name = leaves[i];
        leafv[i].fn = k_img_fn[idx];
        im->leaf[i] = leaves[i];
    }
    im->leaf_count = leaf_count;
    im->fn = k_img_fn[idx];

    struct zcl_hotswap_module mod = {
        .abi_version = ZCL_HOTSWAP_MODULE_ABI_V3,
        .core_sections = hotswap_core_sections_self(),
        .source_tu = source_tu,
        .leaves = leafv,
        .leaf_count = leaf_count,
        .self_test = selftest_true,
    };
    struct hotswap_publish_hooks hooks;
    t_hooks(&hooks);

    if (!hotswap_module_publish(&mod, /*request_activate=*/true, &hooks,
                                report))
        return false;
    im->generation = report->generation;

    struct hotswap_commit_image req = {
        .source_tu = source_tu,
        .handle = im,
        .fd = im->fd,
        .leaves = leafv,
        .leaf_count = leaf_count,
        .generation = report->generation,
        .artifact_sha256 = sha,
        .resolved_datadir = datadir,
        .unmap = test_unmap,
        .hooks = &hooks,
    };
    (void)hotswap_commit_image(&req);
    return true;
}

static size_t open_fd_count(void)
{
    size_t n = 0;
    /* Through the platform shim, so this test does not read /proc itself
     * and the census excludes the counting handle on every platform. */
    if (!os_proc_open_fd_count(&n))
        return 0;
    return n;
}

static void reset_fixture(void)
{
    hotswap_activation_reset_for_testing();
    hotswap_retire_blocker_reset_for_testing();
    blocker_reset_for_testing();
    zcl_command_registry_reset_overrides();
    zcl_command_registry_set_active(&g_reg);
    memset(g_img, 0, sizeof(g_img));
    for (int i = 0; i < IMG_MAX; i++)
        g_img[i].fd = -1;
    atomic_store(&g_dispatch_into_unmapped, 0);
    atomic_store(&g_unmap_calls, 0);
    atomic_store(&g_unmap_of_live_image, 0);
    atomic_store(&g_unmap_with_dispatch_inside, 0);
    atomic_store(&g_park_armed, false);
    g_slow_published = false;
    g_fast_done = false;
}

static void give_image_an_fd(int idx)
{
    g_img[idx].fd = open("/dev/null", O_RDONLY | O_CLOEXEC);
}

static void release_fixture(void)
{
    hotswap_activation_reset_for_testing();
    zcl_command_registry_reset_overrides();
    zcl_command_registry_set_active(NULL);
    hotswap_retire_blocker_reset_for_testing();
    blocker_reset_for_testing();
}

/* ── 1. An untouched process has an empty shelf ─────────────────────────── */
static int t_shelf_starts_empty(void)
{
    int failures = 0;
    TEST("shelf starts empty and answers for sources it never saw") {
        reset_fixture();
        struct hotswap_shelf_entry e;
        ASSERT_EQ(hotswap_shelf_list(NULL, 0), (size_t)0);
        ASSERT(!hotswap_shelf_peek(SHELF_TU, &e));
        ASSERT(!hotswap_shelf_peek(SHELF_TU_META, &e));
        ASSERT(!hotswap_shelf_peek(SHELF_TU_UNKNOWN, &e));
        ASSERT(!hotswap_shelf_peek(NULL, &e));
        ASSERT(!hotswap_shelf_peek("", &e));
        ASSERT(!e.present);
        release_fixture();
        PASS();
    } _test_next:;
    return failures;
}

/* ── 2. The pure gauntlet alone shelves NOTHING ──────────────────────────
 * hotswap_module_publish() compiles into every build and any caller may drive
 * it with a fabricated struct. If that could populate the shelf, rollback
 * would become a second way to publish live handlers with no datadir
 * confinement, no activation gate, no seal and no consensus pin. */
static int t_pure_publish_never_shelves(void)
{
    int failures = 0;
    TEST("publishing without an image commit shelves nothing, ever") {
        reset_fixture();
        const char *leaves[1] = { LEAF_PROBE };
        struct zcl_hotswap_leaf leafv[1] = { { LEAF_PROBE, h_img0 } };
        struct zcl_hotswap_module mod = {
            .abi_version = ZCL_HOTSWAP_MODULE_ABI_V3,
            .core_sections = hotswap_core_sections_self(),
            .source_tu = SHELF_TU,
            .leaves = leafv,
            .leaf_count = 1,
            .self_test = selftest_true,
        };
        (void)leaves;
        struct hotswap_publish_hooks hooks;
        t_hooks(&hooks);
        struct hotswap_activate_report report;
        for (int i = 0; i < 5; i++) {
            ASSERT(hotswap_module_publish(&mod, true, &hooks, &report));
            ASSERT(report.ok);
        }
        ASSERT_EQ(hotswap_shelf_list(NULL, 0), (size_t)0);
        struct hotswap_shelf_entry e;
        ASSERT(!hotswap_shelf_peek(SHELF_TU, &e));
        ASSERT_EQ(hotswap_stale_commit_count(), (uint64_t)0);
        release_fixture();
        PASS();
    } _test_next:;
    return failures;
}

/* ── 3. Rollback refuses cleanly when there is nothing to put back ─────── */
static int t_rollback_refuses_unknown_source(void)
{
    int failures = 0;
    TEST("rollback of a source with nothing shelved refuses and changes nothing") {
        reset_fixture();
        struct hotswap_publish_hooks hooks;
        t_hooks(&hooks);
        struct hotswap_activate_report report;

        ASSERT(!hotswap_rollback(NULL, &hooks, &report));
        ASSERT_STR_EQ(report.stage, "precheck");
        ASSERT(!hotswap_rollback("", &hooks, &report));
        ASSERT_STR_EQ(report.stage, "precheck");

        uint32_t gen_before = zcl_command_registry_active_generation();
        ASSERT(!hotswap_rollback(SHELF_TU, &hooks, &report));
        ASSERT(!report.ok);
        ASSERT(report.rolled_back);
        ASSERT_STR_EQ(report.stage, "shelf");
        ASSERT(report.error[0] != '\0');
        ASSERT(!hotswap_rollback(SHELF_TU_UNKNOWN, &hooks, &report));
        ASSERT_STR_EQ(report.stage, "shelf");
        ASSERT_EQ((unsigned)zcl_command_registry_active_generation(),
                  (unsigned)gen_before);
        release_fixture();
        PASS();
    } _test_next:;
    return failures;
}

/* ── 4. A commit shelves its predecessor, at depth exactly one ─────────── */
static int t_commit_shelves_predecessor_at_depth_one(void)
{
    int failures = 0;
    TEST("each commit shelves the image it superseded, keeping exactly one") {
        reset_fixture();
        const char *leaves[1] = { LEAF_PROBE };
        struct hotswap_activate_report r;
        struct hotswap_shelf_entry e;
        static const char sha0[65] =
            "0000000000000000000000000000000000000000000000000000000000000000";
        static const char sha1[65] =
            "1111111111111111111111111111111111111111111111111111111111111111";
        static const char sha2[65] =
            "2222222222222222222222222222222222222222222222222222222222222222";

        for (int i = 0; i < 3; i++)
            give_image_an_fd(i);

        /* First image: nothing is superseded, so nothing is shelved. */
        ASSERT(drive_image(0, SHELF_TU, leaves, 1, sha0, "/nonexistent", &r));
        ASSERT(!hotswap_shelf_peek(SHELF_TU, &e));
        ASSERT_EQ(hotswap_shelf_list(NULL, 0), (size_t)0);

        /* Second: image 0 is shelved, named by ITS digest and generation. */
        ASSERT(drive_image(1, SHELF_TU, leaves, 1, sha1, "/nonexistent", &r));
        ASSERT(hotswap_shelf_peek(SHELF_TU, &e));
        ASSERT(e.present);
        ASSERT_STR_EQ(e.source_tu, SHELF_TU);
        ASSERT_STR_EQ(e.artifact_sha256, sha0);
        ASSERT_EQ((unsigned)e.generation, (unsigned)g_img[0].generation);
        ASSERT_EQ(hotswap_shelf_list(NULL, 0), (size_t)1);

        /* Third: depth is 1, so image 0 leaves the shelf and image 1 takes
         * its place. The count never grows. */
        ASSERT(drive_image(2, SHELF_TU, leaves, 1, sha2, "/nonexistent", &r));
        ASSERT(hotswap_shelf_peek(SHELF_TU, &e));
        ASSERT_STR_EQ(e.artifact_sha256, sha1);
        ASSERT_EQ(hotswap_shelf_list(NULL, 0), (size_t)1);

        /* count-only mode is the true count, not what was written */
        struct hotswap_shelf_entry one;
        ASSERT_EQ(hotswap_shelf_list(&one, 1), (size_t)1);
        ASSERT_STR_EQ(one.artifact_sha256, sha1);

        /* Nothing raced, so nothing was stale and nothing was held back. */
        ASSERT_EQ(hotswap_stale_commit_count(), (uint64_t)0);
        ASSERT_EQ(hotswap_reference_hold_count(), (uint64_t)0);
        ASSERT_EQ(atomic_load(&g_unmap_of_live_image), (uint64_t)0);
        release_fixture();
        PASS();
    } _test_next:;
    return failures;
}

/* ── 5. THE RETIREMENT RACE ──────────────────────────────────────────────
 *
 * Deterministic reproduction of the interleaving the integration review named:
 *
 *   SLOW publishes  -> generation 2, registry dispatches into image SLOW
 *   FAST publishes  -> generation 3, registry dispatches into image FAST
 *   FAST commits    -> records FAST live, retires the image that was live (OLD)
 *   SLOW commits    -> arrives LAST with the OLDER generation
 *
 * Before the fix, SLOW's commit overwrote the slot with itself and handed
 * FAST — the image the live snapshot dispatches into — to the retire path,
 * which unmapped it because every RETIRED snapshot had drained.
 *
 * DISCRIMINATION (both measured, see the lane report):
 *   - delete the `req->generation > slot->generation` ordering test in
 *     hotswap_commit_image() and this test fails on stale_commit_count == 1
 *     and reference_hold_count == 0;
 *   - delete the reference proof as well and it fails on
 *     g_unmap_of_live_image == 0 — the live image is handed to unmap.
 */
struct race_ctx {
    int  fast_idx;
    bool fast_ok;
};

static _Atomic bool g_dispatch_stop;

static void *race_dispatch_thread(void *arg)
{
    (void)arg;
    char out[4096];
    while (!atomic_load(&g_dispatch_stop)) {
        (void)exec_path(LEAF_PROBE, out, sizeof(out));
        (void)exec_path(LEAF_SECOND, out, sizeof(out));
    }
    return NULL;
}

static void *race_fast_thread(void *arg)
{
    struct race_ctx *c = (struct race_ctx *)arg;
    static const char sha_fast[65] =
        "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff";
    const char *leaves[1] = { LEAF_PROBE };
    struct hotswap_activate_report r;

    pthread_mutex_lock(&g_sync_m);
    while (!g_slow_published)
        pthread_cond_wait(&g_sync_c, &g_sync_m);
    pthread_mutex_unlock(&g_sync_m);

    c->fast_ok = drive_image(c->fast_idx, SHELF_TU, leaves, 1, sha_fast,
                             "/nonexistent", &r);

    pthread_mutex_lock(&g_sync_m);
    g_fast_done = true;
    pthread_cond_broadcast(&g_sync_c);
    pthread_mutex_unlock(&g_sync_m);
    return NULL;
}

static int t_retirement_race_never_unmaps_the_live_image(void)
{
    int failures = 0;
    TEST("a commit that lost the registry race never retires the live image") {
        reset_fixture();
        const char *leaves[1] = { LEAF_PROBE };
        struct hotswap_activate_report r;
        static const char sha_old[65] =
            "0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d";
        static const char sha_slow[65] =
            "5105105105105105105105105105105105105105105105105105105105105105";
        const int OLD = 0, SLOW = 1, FAST = 2;
        for (int i = 0; i < 3; i++)
            give_image_an_fd(i);

        /* A first, uncontended image so there is something to supersede. */
        ASSERT(drive_image(OLD, SHELF_TU, leaves, 1, sha_old, "/nonexistent",
                           &r));
        ASSERT_EQ((unsigned)zcl_command_registry_active_generation(), 1u);

        atomic_store(&g_dispatch_stop, false);
        pthread_t dispatchers[3];
        for (int i = 0; i < 3; i++)
            ASSERT_EQ(pthread_create(&dispatchers[i], NULL,
                                     race_dispatch_thread, NULL), 0);

        /* Arm the park for THIS thread: it becomes the slow publisher. */
        g_slow_tid = pthread_self();
        atomic_store(&g_park_armed, true);

        struct race_ctx ctx = { .fast_idx = FAST, .fast_ok = false };
        pthread_t fast;
        ASSERT_EQ(pthread_create(&fast, NULL, race_fast_thread, &ctx), 0);

        /* Parks inside the commit hook after its generation is assigned, and
         * resumes only once FAST has published AND committed. */
        bool slow_ok = drive_image(SLOW, SHELF_TU, leaves, 1, sha_slow,
                                   "/nonexistent", &r);
        pthread_join(fast, NULL);
        atomic_store(&g_dispatch_stop, true);
        for (int i = 0; i < 3; i++)
            pthread_join(dispatchers[i], NULL);
        atomic_store(&g_park_armed, false);
        /* With the traffic stopped, finish any retirement whose drain the
         * traffic had left unconfirmed, so what follows tests the RETIREMENT
         * DECISION rather than how busy the box happened to be. */
        (void)hotswap_reclaim_retained_now();

        ASSERT(slow_ok);
        ASSERT(ctx.fast_ok);

        /* THE PROPERTY, asserted first so a regression names itself: the image
         * the live snapshot dispatches into was never handed to the unmap. */
        ASSERT(!atomic_load(&g_img[FAST].unmapped));
        ASSERT_EQ(atomic_load(&g_unmap_of_live_image), (uint64_t)0);
        ASSERT_EQ(atomic_load(&g_dispatch_into_unmapped), (uint64_t)0);
        ASSERT_EQ(atomic_load(&g_unmap_with_dispatch_inside), (uint64_t)0);
        ASSERT(zcl_command_registry_effective_handler(find_spec(LEAF_PROBE)) ==
               k_img_fn[FAST]);

        /* Dispatch still answers, and answers as the live image. */
        char out[4096];
        ASSERT_EQ((int)exec_path(LEAF_PROBE, out, sizeof(out)),
                  (int)ZCL_COMMAND_EXIT_OK);
        ASSERT(strstr(out, "\"who\":\"img2\"") != NULL);

        /* The slot tells the truth about which image is live, so the shelf
         * holds the image the registry actually superseded and not the loser.
         * A wrong entry here is a rollback that restores the wrong module. */
        struct hotswap_shelf_entry e;
        ASSERT(hotswap_shelf_peek(SHELF_TU, &e));
        ASSERT_STR_EQ(e.artifact_sha256, sha_old);

        /* The interleaving actually happened. Without this the assertions
         * above would be vacuous — a race test that never raced. */
        ASSERT_EQ(hotswap_stale_commit_count(), (uint64_t)1);
        ASSERT(g_img[SLOW].generation < g_img[FAST].generation);

        /* And the two images the registry really did supersede WERE released:
         * the fix must not degrade into "never unmap anything". */
        ASSERT(atomic_load(&g_img[OLD].unmapped));
        ASSERT(atomic_load(&g_img[SLOW].unmapped));
        ASSERT_EQ(hotswap_reference_hold_count(), (uint64_t)0);
        release_fixture();
        PASS();
    } _test_next:;
    return failures;
}

/* ── 6. A module that drops a leaf must not have its predecessor unmapped ─
 *
 * hotswap_module_admit() requires every leaf a module declares to be on its
 * allowlist row; it does NOT require the module to declare all of them. So a
 * v2 that drops a leaf leaves v1's handler live in the merged snapshot, and
 * releasing v1 would be a use-after-free on the next dispatch of the dropped
 * leaf. Not a race — a plain sequencing defect, and one rollback makes far
 * more likely, since the shelved image can have a different leaf set from the
 * one it replaces.
 *
 * DISCRIMINATION: delete the reference proof and this test fails on
 * !g_img[V1].unmapped, and the LEAF_SECOND dispatch below lands in a released
 * image (g_dispatch_into_unmapped becomes non-zero).
 */
static int t_shrinking_leaf_set_keeps_the_old_image_mapped(void)
{
    int failures = 0;
    TEST("an image is kept mapped while the live snapshot still reaches it") {
        reset_fixture();
        const char *both[2] = { LEAF_PROBE, LEAF_SECOND };
        const char *just_probe[1] = { LEAF_PROBE };
        struct hotswap_activate_report r;
        static const char sha[65] =
            "abababababababababababababababababababababababababababababababab";
        const int V1 = 0, V2 = 1, V3 = 2;
        for (int i = 0; i < 3; i++)
            give_image_an_fd(i);

        ASSERT(drive_image(V1, SHELF_TU, both, 2, sha, "/nonexistent", &r));
        ASSERT(drive_image(V2, SHELF_TU, just_probe, 1, sha, "/nonexistent",
                           &r));

        /* V1 still owns LEAF_SECOND in the live snapshot: keep it mapped. */
        ASSERT(!atomic_load(&g_img[V1].unmapped));
        ASSERT_EQ(atomic_load(&g_unmap_of_live_image), (uint64_t)0);
        ASSERT(zcl_command_registry_effective_handler(find_spec(LEAF_SECOND)) ==
               k_img_fn[V1]);
        ASSERT_EQ(hotswap_reference_hold_count(), (uint64_t)1);

        char out[4096];
        ASSERT_EQ((int)exec_path(LEAF_SECOND, out, sizeof(out)),
                  (int)ZCL_COMMAND_EXIT_OK);
        ASSERT(strstr(out, "\"who\":\"img0\"") != NULL);
        ASSERT_EQ(atomic_load(&g_dispatch_into_unmapped), (uint64_t)0);

        /* A later image that takes BOTH leaves back releases V2 (whose only
         * leaf it overwrote) and makes V1 reclaimable. */
        ASSERT(drive_image(V3, SHELF_TU, both, 2, sha, "/nonexistent", &r));
        ASSERT(atomic_load(&g_img[V2].unmapped));
        ASSERT(!atomic_load(&g_img[V1].unmapped));   /* not retried yet */
        ASSERT(hotswap_reclaim_retained_now());
        ASSERT(atomic_load(&g_img[V1].unmapped));
        ASSERT_EQ(atomic_load(&g_unmap_of_live_image), (uint64_t)0);
        release_fixture();
        PASS();
    } _test_next:;
    return failures;
}

/* ── 7. Rollback claims, racing forward swaps and each other ─────────────
 *
 * Rollback cannot COMPLETE in a test process (it re-runs the dev-datadir and
 * activation gate, which a test_parallel process does not satisfy), so what is
 * driven here is its CLAIM: the dup() of the shelved descriptor, the
 * in-flight flag, the refusal, and the release of both. Run against concurrent
 * forward swaps and concurrent dispatch, thousands of times, the properties
 * that must hold are that no descriptor leaks, the shelf never empties or
 * doubles, and nothing is ever unmapped while live.
 */
static _Atomic bool g_rb_stop;
static _Atomic uint64_t g_rb_attempts;
static _Atomic uint64_t g_rb_busy_refusals;
static _Atomic uint64_t g_rb_bad_stage;

static void *rollback_thread(void *arg)
{
    (void)arg;
    struct hotswap_publish_hooks hooks;
    t_hooks(&hooks);
    while (!atomic_load(&g_rb_stop)) {
        struct hotswap_activate_report r;
        bool ok = hotswap_rollback(SHELF_TU, &hooks, &r);
        atomic_fetch_add(&g_rb_attempts, 1);
        if (ok) {
            atomic_fetch_add(&g_rb_bad_stage, 1);  /* cannot pass the gate here */
            continue;
        }
        /* Every refusal must be one of the stages this path can reach: the
         * shelf claim, or the re-checked resident gate. Anything else means a
         * stage ran on a shelved image that should not have. */
        if (strcmp(r.stage, "shelf") != 0 &&
            strcmp(r.stage, "precheck") != 0 &&
            strcmp(r.stage, "authorize") != 0)
            atomic_fetch_add(&g_rb_bad_stage, 1);
        if (strcmp(r.stage, "shelf") == 0 && strstr(r.error, "in flight"))
            atomic_fetch_add(&g_rb_busy_refusals, 1);
    }
    return NULL;
}

static void *forward_swap_thread(void *arg)
{
    int *base = (int *)arg;
    static const char sha[65] =
        "cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd";
    const char *leaves[1] = { LEAF_PROBE };
    int idx = *base;
    while (!atomic_load(&g_rb_stop)) {
        struct hotswap_activate_report r;
        give_image_an_fd(idx);
        (void)drive_image(idx, SHELF_TU, leaves, 1, sha, "/nonexistent", &r);
        idx++;
        if (idx >= IMG_MAX)
            break;
    }
    return NULL;
}

static int t_rollback_races_forward_swaps(void)
{
    int failures = 0;
    TEST("rollback claims racing forward swaps leak no descriptor and no image") {
        reset_fixture();
        const char *leaves[1] = { LEAF_PROBE };
        struct hotswap_activate_report r;
        static const char sha[65] =
            "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee";

        /* Two commits so the shelf is genuinely populated. */
        give_image_an_fd(0);
        give_image_an_fd(1);
        ASSERT(drive_image(0, SHELF_TU, leaves, 1, sha, "/nonexistent", &r));
        ASSERT(drive_image(1, SHELF_TU, leaves, 1, sha, "/nonexistent", &r));
        struct hotswap_shelf_entry e;
        ASSERT(hotswap_shelf_peek(SHELF_TU, &e));

        size_t fds_before = open_fd_count();

        atomic_store(&g_rb_stop, false);
        atomic_store(&g_rb_attempts, 0);
        atomic_store(&g_rb_busy_refusals, 0);
        atomic_store(&g_rb_bad_stage, 0);
        atomic_store(&g_dispatch_stop, false);

        pthread_t rb[2], dispatchers[2], fwd;
        int fwd_base = 2;
        for (int i = 0; i < 2; i++)
            ASSERT_EQ(pthread_create(&rb[i], NULL, rollback_thread, NULL), 0);
        for (int i = 0; i < 2; i++)
            ASSERT_EQ(pthread_create(&dispatchers[i], NULL,
                                     race_dispatch_thread, NULL), 0);
        ASSERT_EQ(pthread_create(&fwd, NULL, forward_swap_thread, &fwd_base), 0);

        /* The forward thread stops on its own once it runs out of images. */
        pthread_join(fwd, NULL);
        /* Give the rollback threads a bounded amount of contention past that. */
        while (atomic_load(&g_rb_attempts) < 2000)
            sched_yield();
        atomic_store(&g_rb_stop, true);
        atomic_store(&g_dispatch_stop, true);
        for (int i = 0; i < 2; i++)
            pthread_join(rb[i], NULL);
        for (int i = 0; i < 2; i++)
            pthread_join(dispatchers[i], NULL);

        (void)hotswap_reclaim_retained_now();

        ASSERT_EQ(atomic_load(&g_rb_bad_stage), (uint64_t)0);
        ASSERT_EQ(atomic_load(&g_unmap_of_live_image), (uint64_t)0);
        ASSERT_EQ(atomic_load(&g_dispatch_into_unmapped), (uint64_t)0);
        ASSERT_EQ(atomic_load(&g_unmap_with_dispatch_inside), (uint64_t)0);

        /* The shelf holds exactly one entry for this source, still. */
        ASSERT_EQ(hotswap_shelf_list(NULL, 0), (size_t)1);
        ASSERT(hotswap_shelf_peek(SHELF_TU, &e));

        /* No descriptor leaked across thousands of claim/refuse cycles. The
         * live slot and its shelf entry account for the small fixed delta the
         * forward swaps left behind. */
        size_t fds_after = open_fd_count();
        ASSERT(fds_after <= fds_before + 4);

        /* A rollback issued alone afterwards must not be told one is already
         * in flight: every claim released its flag. */
        struct hotswap_publish_hooks hooks;
        t_hooks(&hooks);
        struct hotswap_activate_report solo;
        ASSERT(!hotswap_rollback(SHELF_TU, &hooks, &solo));
        ASSERT(strstr(solo.error, "in flight") == NULL);

        printf("[rollback attempts=%llu busy_refusals=%llu] ",
               (unsigned long long)atomic_load(&g_rb_attempts),
               (unsigned long long)atomic_load(&g_rb_busy_refusals));
        release_fixture();
        PASS();
    } _test_next:;
    return failures;
}

int test_hotswap_shelf(void)
{
    int failures = 0;
    failures += t_shelf_starts_empty();
    failures += t_pure_publish_never_shelves();
    failures += t_rollback_refuses_unknown_source();
    failures += t_commit_shelves_predecessor_at_depth_one();
    failures += t_retirement_race_never_unmaps_the_live_image();
    failures += t_shrinking_leaf_set_keeps_the_old_image_mapped();
    failures += t_rollback_races_forward_swaps();
    return failures;
}
