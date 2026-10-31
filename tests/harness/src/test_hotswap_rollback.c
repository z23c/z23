/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * A hot-swap rollback that SUCCEEDS, end to end, against real module images.
 *
 * test_hotswap_shelf.c only drives rollback to refusals. This group verifies
 * the two properties that need a real success:
 *   1. The toggle takes effect: after activating A, then B, rolling back makes
 *      command dispatch run A's code again.
 *   2. The registry generation stays strictly monotonic across a rollback (it
 *      is the one ordering authority; hotswap_commit_image() orders by it).
 *
 * The loader path is real: hotswap_rollback() re-runs the admission gauntlet
 * over a sealed image (ELF probe, SHA-256 + SHA3-256, sealed-core pin, symbol
 * resolution, admit, probe-before-publish, one registry batch), skipping only
 * path confinement since a shelved image has no path. Two module .so images
 * built from tests/harness/fixtures/hotswap_rollback_module.c, differing only
 * in the marker their handlers render, are activated and the live registry is
 * asked which one answers. The test supplies the resident's seam (commit hook,
 * probe hook, quiescence hook), as test_hotswap_shelf.c does.
 *
 * Authority: activation needs -hotswap-activate, ZCL_HOTSWAP_ACTIVATE=1 and
 * the exact dev datadir ~/.zclassic-c23-dev, all re-checked at rollback time.
 * The group satisfies them by pointing HOME at a throwaway directory under
 * ./test-tmp (restored on exit); no real datadir is named or opened.
 *
 * Discrimination: a rollback that leaves B live fails the dispatch marker
 * checks; one that reuses or lowers the generation fails the generation
 * checks; one that republishes a remembered struct fails artifact_sha256
 * equality; one that consumes the shelf on refusal fails the refuse-then-
 * rollback sequence; one that leaks the dup()ed descriptor fails the fd census.
 */

#if !defined(__linux__)

/* Declares realpath() under the fortify inline; must precede every include. */
#if !defined(_WIN32) && !defined(_DEFAULT_SOURCE)
#define _DEFAULT_SOURCE
#endif

#include <stdio.h>

int test_hotswap_rollback(void);
int test_hotswap_rollback(void)
{
    printf("\n=== hot-swap rollback platform contract ===\n");
    printf("hotswap_rollback: PASS platform=non-linux "
           "dynamic_rollback=unsupported fixture_required=false\n");
    return 0;
}

#else

#include "test/test_helpers.h"

#include "hotswap/hotswap.h"
#include "hotswap/hotswap_module.h"
#include "hotswap/hotswap_retire_blocker.h"
#include "hotswap/hotswap_shelf.h"
#include "json/json.h"
#include "kernel/command_registry.h"
#include "platform/os_proc.h"
#include "util/blocker.h"

#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

/* The status controller row of config/hotswap_swappable.def. Its declared
 * probe leaf in engine/composition/hotswap_eligible.def is core.status, and both leaves
 * used below are on that row — the same identity the fixture module stamps
 * itself with. */
#define RB_TU        "engine/controllers/src/status_native_handlers.c"
#define RB_LEAF      "core.status"
#define RB_LEAF2     "core.sync.diagnose"

/* The two module images, built by `make $(HOTSWAP_ROLLBACK_FIXTURE_SOS)` and
 * carried as a prerequisite of every test binary. Under build/hotswap so the
 * loader's path confinement accepts them. */
#define RB_SO_A "build/hotswap/zcl_rollback_fixture_a.so"
#define RB_SO_B "build/hotswap/zcl_rollback_fixture_b.so"

/* What each image's handlers render into the reply, so a dispatch names the
 * image that answered it rather than merely proving something answered. */
#define RB_MARK_A "\"image\":\"a\""
#define RB_MARK_B "\"image\":\"b\""

static char g_so_a[PATH_MAX];
static char g_so_b[PATH_MAX];
static char g_home[PATH_MAX];
static char g_datadir[PATH_MAX];
static char g_home_saved[PATH_MAX];
static bool g_had_home;
static bool g_fixture_ready;
static bool g_rb_env_started;

/* ── a registry the override layer can validate against ───────────────────
 * The batch commit independently re-checks READY + read-only + resolvable for
 * every leaf, so the bound registry must carry the real leaf paths. */
static void rb_resident(const struct zcl_command_request *request,
                        struct zcl_command_reply *reply)
{
    (void)request;
    (void)json_push_kv_str(&reply->data, "image", "resident");
}

static const struct zcl_command_spec g_rb_specs[] = {
    { .path = RB_LEAF, .summary = "swappable read leaf",
      .layer = ZCL_COMMAND_LAYER_CORE, .effect = ZCL_COMMAND_EFFECT_READ,
      .availability = ZCL_COMMAND_READY, .mode = ZCL_COMMAND_MODE_SYNC,
      .allowed_lanes = ZCL_COMMAND_LANE_LOCAL,
      .output_schema = "zcl.core_status.v2", .handler = rb_resident },
    { .path = RB_LEAF2, .summary = "swappable read leaf",
      .layer = ZCL_COMMAND_LAYER_CORE, .effect = ZCL_COMMAND_EFFECT_READ,
      .availability = ZCL_COMMAND_READY, .mode = ZCL_COMMAND_MODE_SYNC,
      .allowed_lanes = ZCL_COMMAND_LANE_LOCAL,
      .output_schema = "zcl.sync_diagnose.v1", .handler = rb_resident },
};

static const struct zcl_command_registry g_rb_reg = {
    .commands = g_rb_specs,
    .count = sizeof(g_rb_specs) / sizeof(g_rb_specs[0]),
};

static const struct zcl_command_spec *rb_find_spec(const char *path)
{
    for (size_t i = 0; i < g_rb_reg.count; i++)
        if (strcmp(g_rb_reg.commands[i].path, path) == 0)
            return &g_rb_reg.commands[i];
    return NULL;
}

/* Dispatch through the REAL registry entry point, so the override snapshot is
 * acquired and released exactly as it is in the node. */
static enum zcl_command_exit rb_exec(const char *path, char *out,
                                     size_t out_size)
{
    const struct zcl_command_spec *spec = rb_find_spec(path);
    struct json_value input;
    json_init(&input);
    json_set_object(&input);
    enum zcl_command_exit exit_code = ZCL_COMMAND_EXIT_INTERNAL;
    (void)zcl_command_registry_execute_json(&g_rb_reg, spec, NULL, &input,
                                            false, path, "normal", 0, 0, NULL,
                                            out, out_size, &exit_code);
    json_free(&input);
    return exit_code;
}

/* ── publish hooks ────────────────────────────────────────────────────────
 * Same shape as the resident's (tools/command/native_dev_hotswap.c): the
 * commit publishes into the real registry and reports the generation the
 * publish itself assigned. */
static bool rb_commit(void *ctx, const struct zcl_hotswap_leaf *leaves,
                      size_t leaf_count, uint32_t *out_gen, char *why,
                      size_t why_sz)
{
    (void)ctx;
    if (!leaves || leaf_count == 0 ||
        leaf_count > ZCL_COMMAND_HANDLER_OVERRIDE_MAX) {
        if (why && why_sz)
            snprintf(why, why_sz, "bad batch size %zu", leaf_count);
        return false;
    }
    struct zcl_command_handler_override ovr[ZCL_COMMAND_HANDLER_OVERRIDE_MAX];
    for (size_t i = 0; i < leaf_count; i++) {
        ovr[i].path = leaves[i].name;
        ovr[i].handler = leaves[i].fn;
    }
    if (!zcl_command_registry_replace_batch(0, ovr, leaf_count, why, why_sz,
                                            out_gen))
        return false;
    return true;
}

static bool rb_probe(void *ctx, const char *leaf, zcl_hotswap_handler_fn fn,
                     char *why, size_t why_sz)
{
    (void)ctx;
    (void)leaf;
    if (!fn) {
        if (why && why_sz)
            snprintf(why, why_sz, "probe handler is NULL");
        return false;
    }
    return true;
}

static bool rb_quiesced(void *ctx)
{
    (void)ctx;
    return zcl_command_registry_all_retired_quiesced();
}

static void rb_hooks(struct hotswap_publish_hooks *h)
{
    memset(h, 0, sizeof(*h));
    h->commit = rb_commit;
    h->probe = rb_probe;
    h->quiesced = rb_quiesced;
}

/* ── fixture ──────────────────────────────────────────────────────────────
 * HOME is redirected so `~/.zclassic-c23-dev` resolves into a throwaway tree. */
/* Refusal leaves fixture globals and the filesystem/environment unchanged. */
static bool rb_env_paths(const char *cwd, char home[PATH_MAX],
                         char datadir[PATH_MAX])
{
    int n = snprintf(home, PATH_MAX, "%s/test-tmp/hs_rollback_home_%d", cwd,
                     (int)getpid());
    if (n < 0 || (size_t)n >= PATH_MAX)
        return false;
    n = snprintf(datadir, PATH_MAX, "%s/.zclassic-c23-dev", home);
    return n >= 0 && (size_t)n < PATH_MAX;
}

static bool rb_env_apply(const char *home_path, const char *datadir_path)
{
    snprintf(g_home, sizeof(g_home), "%s", home_path);
    snprintf(g_datadir, sizeof(g_datadir), "%s", datadir_path);
    const char *home = getenv("HOME");
    g_had_home = home != NULL;
    if (g_had_home)
        snprintf(g_home_saved, sizeof(g_home_saved), "%s", home);
    g_rb_env_started = true;

    (void)mkdir("test-tmp", 0700);
    test_rm_rf_recursive(g_home);
    if (mkdir(g_home, 0700) != 0)
        return false;
    if (mkdir(g_datadir, 0700) != 0)
        return false;

    if (setenv("HOME", g_home, 1) != 0)
        return false;
    if (setenv("ZCL_HOTSWAP_ACTIVATE", "1", 1) != 0)
        return false;
    hotswap_set_activate_flag(true);
    return true;
}

static bool rb_env_begin_at(const char *cwd,
                            bool (*apply)(const char *, const char *))
{
    char home[PATH_MAX], datadir[PATH_MAX];
    if (!rb_env_paths(cwd, home, datadir)) {
        fprintf(stderr, "hotswap_rollback: fixture path exceeds capacity\n");
        return false;
    }
    return apply(home, datadir);
}

static bool rb_env_begin(void)
{
    char cwd[PATH_MAX];
    if (!getcwd(cwd, sizeof(cwd)))
        return false;
    return rb_env_begin_at(cwd, rb_env_apply);
}

/* All setup effects are behind apply; this recorder never touches a path. */
static unsigned g_rb_setup_calls;
static char g_rb_recorded_home[PATH_MAX], g_rb_recorded_datadir[PATH_MAX];

static bool rb_env_record(const char *home, const char *datadir)
{
    ++g_rb_setup_calls;
    snprintf(g_rb_recorded_home, sizeof(g_rb_recorded_home), "%s", home);
    snprintf(g_rb_recorded_datadir, sizeof(g_rb_recorded_datadir), "%s", datadir);
    return true;
}

static void rb_env_end(void);

static int t_fixture_path_bounds(void)
{
    int failures = 0;
    TEST("fixture path overflow refuses before cleanup, mkdir or environment writes") {
        char saved_home[PATH_MAX];
        const char *original_home = getenv("HOME");
        bool had_home = original_home != NULL;
        int saved_n = snprintf(saved_home, sizeof(saved_home), "%s",
                               original_home ? original_home : "");
        ASSERT(saved_n >= 0 && (size_t)saved_n < sizeof(saved_home));
        char cwd[PATH_MAX], suffix[64];
        int n = snprintf(suffix, sizeof(suffix),
                         "/test-tmp/hs_rollback_home_%d", (int)getpid());
        ASSERT(n > 0 && (size_t)n < sizeof(suffix));
        ASSERT((size_t)n + sizeof("/.zclassic-c23-dev") < sizeof(cwd));
        memset(cwd, 'x', sizeof(cwd) - 1);
        cwd[0] = '/';
        cwd[sizeof(cwd) - 1] = '\0';
        g_rb_setup_calls = 0;
        ASSERT(!rb_env_begin_at(cwd, rb_env_record));
        ASSERT_EQ(g_rb_setup_calls, 0u);
        ASSERT(!g_rb_env_started);
        rb_env_end();
        ASSERT_EQ(getenv("HOME") != NULL, had_home);
        if (had_home)
            ASSERT_STR_EQ(getenv("HOME"), saved_home);
        /* HOME fits exactly, but its datadir suffix cannot fit. */
        cwd[PATH_MAX - 1 - (size_t)n] = '\0';
        ASSERT(!rb_env_begin_at(cwd, rb_env_record));
        ASSERT_EQ(g_rb_setup_calls, 0u);
        /* Datadir at capacity-1 fits; one more byte must refuse. */
        size_t limit = PATH_MAX - 1 - (size_t)n - strlen("/.zclassic-c23-dev");
        cwd[limit] = '\0';
        ASSERT(rb_env_begin_at(cwd, rb_env_record));
        ASSERT_EQ(strlen(g_rb_recorded_datadir), (size_t)PATH_MAX - 1);
        cwd[limit] = 'x';
        cwd[limit + 1] = '\0';
        ASSERT(!rb_env_begin_at(cwd, rb_env_record));
        ASSERT_EQ(g_rb_setup_calls, 1u);
        ASSERT(rb_env_begin_at("/fixture", rb_env_record));
        ASSERT_EQ(g_rb_setup_calls, 2u);
        ASSERT(strncmp(g_rb_recorded_home, "/fixture/test-tmp/", 18) == 0);
        ASSERT_STR_EQ(g_rb_recorded_datadir + strlen(g_rb_recorded_home),
                      "/.zclassic-c23-dev");
        PASS();
    } _test_next:;
    return failures;
}

static void rb_env_end(void)
{
    if (!g_rb_env_started)
        return;
    hotswap_set_activate_flag(false);
    (void)unsetenv("ZCL_HOTSWAP_ACTIVATE");
    if (g_had_home)
        (void)setenv("HOME", g_home_saved, 1);
    else
        (void)unsetenv("HOME");
    if (g_home[0])
        test_rm_rf_recursive(g_home);
    g_rb_env_started = false;
}

/* Resolve the two module images. Absent images are a hard failure: they are a
 * declared build prerequisite. */
static bool rb_resolve_images(void)
{
    if (!realpath(RB_SO_A, g_so_a) || !realpath(RB_SO_B, g_so_b))
        return false;
    return g_so_a[0] == '/' && g_so_b[0] == '/';
}

static void rb_reset(void)
{
    hotswap_activation_reset_for_testing();
    hotswap_retire_blocker_reset_for_testing();
    blocker_reset_for_testing();
    zcl_command_registry_reset_overrides();
    zcl_command_registry_set_active(&g_rb_reg);
}

static void rb_release(void)
{
    hotswap_activation_reset_for_testing();
    zcl_command_registry_reset_overrides();
    zcl_command_registry_set_active(NULL);
    hotswap_retire_blocker_reset_for_testing();
    blocker_reset_for_testing();
}

static size_t rb_open_fd_count(void)
{
    size_t n = 0;
    if (!os_proc_open_fd_count(&n))
        return 0;
    return n;
}

/* The successful-rollback counter, read from the subsystem telemetry (distinct
 * from the failed-activation unwind counter). */
static int64_t rb_shelf_rollback_count(void)
{
    struct json_value doc;
    json_init(&doc);
    json_set_object(&doc);
    hotswap_activate_dump_json(&doc);
    static char buf[65536];
    size_t n = json_write(&doc, buf, sizeof(buf));
    json_free(&doc);
    if (n == 0 || n >= sizeof(buf))
        return -1;
    const char *p = strstr(buf, "\"shelf_rollback_count\":");
    if (!p)
        return -1;
    return (int64_t)strtoll(p + strlen("\"shelf_rollback_count\":"), NULL, 10);
}

/* ── 1. The images load, and the fixture is honest about what it loaded ──── */
static int t_images_activate(void)
{
    int failures = 0;
    TEST("two real module images activate through the production loader") {
        ASSERT(g_fixture_ready);
        rb_reset();

        struct hotswap_publish_hooks hooks;
        rb_hooks(&hooks);
        struct hotswap_activate_report ra, rb;
        char out[8192];

        /* Baseline: the catalog handler answers before anything is swapped. */
        ASSERT_EQ((int)rb_exec(RB_LEAF, out, sizeof(out)),
                  (int)ZCL_COMMAND_EXIT_OK);
        ASSERT(strstr(out, "\"image\":\"resident\"") != NULL);

        ASSERT(hotswap_activate(g_so_a, g_datadir, true, &hooks, &ra));
        /* Not the release stub: this binary carries the real loader. */
        ASSERT(strcmp(ra.stage, "release") != 0);
        ASSERT(ra.ok);
        ASSERT(ra.activated);
        ASSERT(!ra.verify_only);
        ASSERT(ra.probed);
        ASSERT_STR_EQ(ra.stage, "activated");
        ASSERT_STR_EQ(ra.source_tu, RB_TU);
        ASSERT_STR_EQ(ra.probe_leaf, RB_LEAF);
        ASSERT_EQ((unsigned)ra.leaf_count, 2u);
        ASSERT(ra.generation > 0);
        /* Both hash families were computed over the same sealed image. */
        ASSERT_EQ(strlen(ra.artifact_sha256), (size_t)64);
        ASSERT_EQ(strlen(ra.artifact_sha3_256), (size_t)64);

        ASSERT(hotswap_activate(g_so_b, g_datadir, true, &hooks, &rb));
        ASSERT(rb.activated);
        ASSERT_EQ((unsigned)rb.leaf_count, 2u);
        /* Distinct artifacts, so a later digest comparison means something. */
        ASSERT(strcmp(ra.artifact_sha256, rb.artifact_sha256) != 0);
        ASSERT(rb.generation > ra.generation);

        rb_release();
        PASS();
    } _test_next:;
    return failures;
}

/* ── 2. The toggle and the generation ───────────────────────────────────
 * A -> B -> rollback -> rollback: the first rollback restores A to dispatch
 * with a generation strictly newer than B's; the second lands back on B. */
static int t_rollback_toggles_dispatch(void)
{
    int failures = 0;
    TEST("a successful rollback puts the previous image back on the wire") {
        ASSERT(g_fixture_ready);
        rb_reset();

        struct hotswap_publish_hooks hooks;
        rb_hooks(&hooks);
        struct hotswap_activate_report ra, rb, r1, r2;
        struct hotswap_shelf_entry e;
        char out[8192];

        ASSERT(hotswap_activate(g_so_a, g_datadir, true, &hooks, &ra));
        ASSERT(ra.activated);
        zcl_command_handler_fn fn_a =
            zcl_command_registry_effective_handler(rb_find_spec(RB_LEAF));
        ASSERT(fn_a != rb_resident);
        ASSERT_EQ((int)rb_exec(RB_LEAF, out, sizeof(out)),
                  (int)ZCL_COMMAND_EXIT_OK);
        ASSERT(strstr(out, RB_MARK_A) != NULL);

        /* The first image supersedes nothing, so nothing is shelved and a
         * rollback of this source is impossible by construction. */
        ASSERT(!hotswap_shelf_peek(RB_TU, &e));

        ASSERT(hotswap_activate(g_so_b, g_datadir, true, &hooks, &rb));
        ASSERT(rb.activated);
        zcl_command_handler_fn fn_b =
            zcl_command_registry_effective_handler(rb_find_spec(RB_LEAF));
        ASSERT(fn_b != fn_a);
        ASSERT_EQ((int)rb_exec(RB_LEAF, out, sizeof(out)),
                  (int)ZCL_COMMAND_EXIT_OK);
        ASSERT(strstr(out, RB_MARK_B) != NULL);
        ASSERT(strstr(out, RB_MARK_A) == NULL);

        /* The shelf now names image A, by ITS digest and ITS generation. */
        ASSERT(hotswap_shelf_peek(RB_TU, &e));
        ASSERT(e.present);
        ASSERT_STR_EQ(e.source_tu, RB_TU);
        ASSERT_STR_EQ(e.artifact_sha256, ra.artifact_sha256);
        ASSERT_EQ((unsigned)e.generation, (unsigned)ra.generation);
        ASSERT_EQ(rb_shelf_rollback_count(), (int64_t)0);

        /* ── THE ROLLBACK ─────────────────────────────────────────────── */
        ASSERT(hotswap_rollback(RB_TU, &hooks, &r1));
        ASSERT(r1.ok);
        ASSERT(r1.activated);
        ASSERT(!r1.verify_only);
        ASSERT(r1.probed);
        ASSERT_STR_EQ(r1.stage, "activated");
        ASSERT_STR_EQ(r1.source_tu, RB_TU);
        ASSERT_EQ((unsigned)r1.leaf_count, 2u);

        /* PROPERTY 2 — the ordering authority never goes backwards and is
         * never reused. The rollback is a NEW publish, not a rewind. */
        ASSERT(r1.generation > rb.generation);
        ASSERT_EQ((unsigned)zcl_command_registry_active_generation(),
                  (unsigned)r1.generation);

        /* The bytes that came back are the bytes that were shelved: the
         * gauntlet re-hashed the sealed image, it did not republish a
         * remembered struct. */
        ASSERT_STR_EQ(r1.artifact_sha256, ra.artifact_sha256);
        ASSERT_STR_EQ(r1.artifact_sha3_256, ra.artifact_sha3_256);

        /* PROPERTY 1 — dispatch observes A's behaviour again, on BOTH leaves
         * the image published, through the real registry entry point. */
        zcl_command_handler_fn fn_r1 =
            zcl_command_registry_effective_handler(rb_find_spec(RB_LEAF));
        ASSERT(fn_r1 != fn_b);
        ASSERT(fn_r1 != rb_resident);
        ASSERT_EQ((int)rb_exec(RB_LEAF, out, sizeof(out)),
                  (int)ZCL_COMMAND_EXIT_OK);
        ASSERT(strstr(out, RB_MARK_A) != NULL);
        ASSERT(strstr(out, RB_MARK_B) == NULL);
        ASSERT_EQ((int)rb_exec(RB_LEAF2, out, sizeof(out)),
                  (int)ZCL_COMMAND_EXIT_OK);
        ASSERT(strstr(out, RB_MARK_A) != NULL);

        /* The rollback's own commit shelved what it superseded, so the shelf
         * now names B — the toggle's other half. */
        ASSERT(hotswap_shelf_peek(RB_TU, &e));
        ASSERT_STR_EQ(e.artifact_sha256, rb.artifact_sha256);
        ASSERT_EQ((unsigned)e.generation, (unsigned)rb.generation);
        ASSERT_EQ(hotswap_shelf_list(NULL, 0), (size_t)1);
        ASSERT_EQ(rb_shelf_rollback_count(), (int64_t)1);

        /* ── ROLL BACK AGAIN: back where we started ───────────────────── */
        ASSERT(hotswap_rollback(RB_TU, &hooks, &r2));
        ASSERT(r2.activated);
        ASSERT(r2.generation > r1.generation);
        ASSERT_EQ((unsigned)zcl_command_registry_active_generation(),
                  (unsigned)r2.generation);
        ASSERT_STR_EQ(r2.artifact_sha256, rb.artifact_sha256);
        ASSERT_EQ((int)rb_exec(RB_LEAF, out, sizeof(out)),
                  (int)ZCL_COMMAND_EXIT_OK);
        ASSERT(strstr(out, RB_MARK_B) != NULL);
        ASSERT(strstr(out, RB_MARK_A) == NULL);
        ASSERT(hotswap_shelf_peek(RB_TU, &e));
        ASSERT_STR_EQ(e.artifact_sha256, ra.artifact_sha256);
        ASSERT_EQ((unsigned)e.generation, (unsigned)r1.generation);
        ASSERT_EQ(rb_shelf_rollback_count(), (int64_t)2);

        /* Nothing raced, and no image was ever unmapped while the live
         * snapshot could still reach it. */
        ASSERT_EQ(hotswap_stale_commit_count(), (uint64_t)0);

        rb_release();
        PASS();
    } _test_next:;
    return failures;
}

/* ── 3. The gate is re-checked at rollback time ─────────────────────────
 * A rollback re-runs the same authorization as the forward swap. Both
 * directions run over ONE shelf entry; a refusal must not consume it or leak
 * the duplicated descriptor. */
static int t_refused_rollback_changes_nothing(void)
{
    int failures = 0;
    TEST("a rollback refused by the live gate consumes nothing and leaks nothing") {
        ASSERT(g_fixture_ready);
        rb_reset();

        struct hotswap_publish_hooks hooks;
        rb_hooks(&hooks);
        struct hotswap_activate_report ra, rb, refused, allowed;
        struct hotswap_shelf_entry e;
        char out[8192];

        ASSERT(hotswap_activate(g_so_a, g_datadir, true, &hooks, &ra));
        ASSERT(ra.activated);
        ASSERT(hotswap_activate(g_so_b, g_datadir, true, &hooks, &rb));
        ASSERT(rb.activated);
        ASSERT(hotswap_shelf_peek(RB_TU, &e));

        uint32_t gen_before = zcl_command_registry_active_generation();
        size_t fds_before = rb_open_fd_count();
        ASSERT(fds_before > 0);

        /* (a) the operator flag is withdrawn */
        hotswap_set_activate_flag(false);
        ASSERT(!hotswap_rollback(RB_TU, &hooks, &refused));
        ASSERT(!refused.ok);
        ASSERT(!refused.activated);
        ASSERT(refused.rolled_back);
        ASSERT_STR_EQ(refused.stage, "authorize");
        hotswap_set_activate_flag(true);

        /* (b) the environment opt-in is withdrawn */
        ASSERT_EQ(unsetenv("ZCL_HOTSWAP_ACTIVATE"), 0);
        ASSERT(!hotswap_rollback(RB_TU, &hooks, &refused));
        ASSERT_STR_EQ(refused.stage, "authorize");
        ASSERT_EQ(setenv("ZCL_HOTSWAP_ACTIVATE", "1", 1), 0);

        /* Nothing moved: not the generation, not the live handler, not the
         * shelf entry, not the descriptor table. */
        ASSERT_EQ((unsigned)zcl_command_registry_active_generation(),
                  (unsigned)gen_before);
        ASSERT_EQ((int)rb_exec(RB_LEAF, out, sizeof(out)),
                  (int)ZCL_COMMAND_EXIT_OK);
        ASSERT(strstr(out, RB_MARK_B) != NULL);
        ASSERT(hotswap_shelf_peek(RB_TU, &e));
        ASSERT_STR_EQ(e.artifact_sha256, ra.artifact_sha256);
        ASSERT_EQ(hotswap_shelf_list(NULL, 0), (size_t)1);
        ASSERT_EQ(rb_shelf_rollback_count(), (int64_t)0);
        ASSERT_EQ(rb_open_fd_count(), fds_before);

        /* The very same shelf entry still rolls back once the gate is
         * satisfied again — a refusal is not a consumption. */
        ASSERT(hotswap_rollback(RB_TU, &hooks, &allowed));
        ASSERT(allowed.activated);
        ASSERT(allowed.generation > gen_before);
        ASSERT_STR_EQ(allowed.artifact_sha256, ra.artifact_sha256);
        ASSERT_EQ((int)rb_exec(RB_LEAF, out, sizeof(out)),
                  (int)ZCL_COMMAND_EXIT_OK);
        ASSERT(strstr(out, RB_MARK_A) != NULL);
        ASSERT_EQ(rb_shelf_rollback_count(), (int64_t)1);

        rb_release();
        PASS();
    } _test_next:;
    return failures;
}

/* ── 4. An undeclared import is refused before map or dlopen ─────────────────
 * The bad image is image A with the imported name json_push_kv_str rewritten,
 * same length, to a name absent from hotswap_module_imports.def. Everything
 * else (identity, seal, ABI) is untouched, so the import policy is the only
 * thing that can refuse it. Written under /tmp, which the loader confines to. */
#define RB_BAD_IMPORT_OLD "json_push_kv_str"
#define RB_BAD_IMPORT_NEW "json_push_kv_sxx"

static unsigned char *rb_slurp(const char *path, size_t *n_out)
{
    FILE *f = fopen(path, "rb");
    if (!f)
        return NULL;
    unsigned char *buf = NULL;
    long len = (fseek(f, 0, SEEK_END) == 0) ? ftell(f) : -1;
    if (len > 0 && fseek(f, 0, SEEK_SET) == 0 &&
        (buf = malloc((size_t)len)) != NULL &&
        fread(buf, 1, (size_t)len, f) != (size_t)len) {
        free(buf);
        buf = NULL;
    }
    (void)fclose(f);
    if (buf)
        *n_out = (size_t)len;
    return buf;
}

static size_t rb_patch_name(unsigned char *img, size_t n)
{
    const size_t len = sizeof(RB_BAD_IMPORT_OLD) - 1;
    size_t hits = 0;
    for (size_t i = 0; i + len <= n; i++) {
        if (memcmp(img + i, RB_BAD_IMPORT_OLD, len) == 0) {
            memcpy(img + i, RB_BAD_IMPORT_NEW, len);
            hits++;
        }
    }
    return hits;
}

static bool rb_write_bad_image(const char *dir, char path[PATH_MAX])
{
    size_t n = 0;
    unsigned char *img = rb_slurp(g_so_a, &n);
    if (!img)
        return false;
    bool ok = rb_patch_name(img, n) > 0 &&
              snprintf(path, PATH_MAX, "%s/bad_import.so", dir) > 0;
    FILE *f = ok ? fopen(path, "wb") : NULL;
    if (!f)
        path[0] = '\0';
    ok = f != NULL && fwrite(img, 1, n, f) == n;
    if (f)
        ok = (fclose(f) == 0) && ok;
    free(img);
    return ok;
}

static int t_undeclared_import_refused_before_map(void)
{
    int failures = 0;
    TEST("a module importing an undeclared symbol is refused at activate, nothing published") {
        ASSERT(g_fixture_ready);
        rb_reset();
        struct hotswap_publish_hooks hooks;
        rb_hooks(&hooks);

        /* Results are computed first; the temp file, temp dir and registry
         * state are released before any assertion, so a failure leaks none. */
        /* The loader confines images to /tmp or a build/hotswap dir, and the
         * fixture lint keeps new tests off bare /tmp: mint beside the images. */
        char dir[] = "build/hotswap/hs_import_policy_XXXXXX";
        char bad[PATH_MAX] = {0};
        bool have_dir = mkdtemp(dir) != NULL;
        bool wrote = have_dir && rb_write_bad_image(dir, bad);

        struct hotswap_activate_report refused = {0}, ok = {0};
        uint32_t gen_before = zcl_command_registry_active_generation();
        size_t fds_before = rb_open_fd_count();
        bool activated = wrote && hotswap_activate(bad, g_datadir, true, &hooks, &refused);
        if (bad[0] != '\0')
            (void)unlink(bad);
        if (have_dir)
            (void)rmdir(dir);
        uint32_t gen_after = zcl_command_registry_active_generation();
        size_t shelf = hotswap_shelf_list(NULL, 0);
        size_t fds_after = rb_open_fd_count();

        /* The same image with its declared import set is admitted as before. */
        bool good = hotswap_activate(g_so_a, g_datadir, true, &hooks, &ok);
        bool good_live = good && ok.activated;
        rb_release();

        ASSERT(wrote);
        ASSERT(!activated);
        ASSERT(!refused.activated);
        ASSERT_STR_EQ(refused.stage, "shape");
        ASSERT(strstr(refused.error,
                      "undeclared resident symbol '" RB_BAD_IMPORT_NEW "'") != NULL);
        ASSERT_EQ((unsigned)gen_after, (unsigned)gen_before);
        ASSERT_EQ(shelf, (size_t)0);
        ASSERT_EQ(fds_after, fds_before);
        ASSERT(good_live);
        PASS();
    } _test_next:;
    return failures;
}

int test_hotswap_rollback(void)
{
    printf("\n=== hot-swap rollback: a real image put back live ===\n");
    int failures = t_fixture_path_bounds();

    g_fixture_ready = rb_env_begin() && rb_resolve_images();
    if (!g_fixture_ready) {
        printf("hotswap_rollback: FAIL — module images are missing; expected "
               "%s and %s (built as a prerequisite of every test binary; "
               "run `make test_parallel`)\n", RB_SO_A, RB_SO_B);
    }

    failures += t_images_activate();
    failures += t_rollback_toggles_dispatch();
    failures += t_refused_rollback_changes_nothing();
    failures += t_undeclared_import_refused_before_map();

    rb_release();
    rb_env_end();
    printf("=== hotswap_rollback: %d failures ===\n", failures);
    return failures;
}

#endif
