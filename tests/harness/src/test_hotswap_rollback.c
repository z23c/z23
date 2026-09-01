/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * A hot-swap rollback that SUCCEEDS, end to end, against real module images.
 *
 * ── WHY THIS FILE EXISTS ──────────────────────────────────────────────────
 * The rollback shelf shipped with every one of its assertions driven to a
 * REFUSAL. test_hotswap_shelf.c says so in its own header: a rollback there
 * re-runs the dev-datadir and activation gate, which that process does not
 * satisfy, so what it proves is the CLAIM — the dup() of the shelved
 * descriptor, the in-flight flag, the refusal, and the release of both. The
 * two properties that decide whether rollback is a feature or a report were
 * therefore unverified by anything in the tree:
 *
 *   1. THE TOGGLE TAKES EFFECT. After activating image A, then image B, then
 *      rolling back, does command dispatch actually run A's code again — or
 *      does rollback report success while the live registry snapshot still
 *      routes into B?
 *   2. THE REGISTRY GENERATION STAYS STRICTLY MONOTONIC ACROSS A REAL
 *      ROLLBACK. Generation is the ONE ordering authority the whole subsystem
 *      rests on (hotswap_commit_image() orders every commit by it and refuses
 *      to unmap anything a newer generation has not taken over). A rollback
 *      that reused or decremented a generation would hand a concurrent reader
 *      a superseded snapshot it believes is current.
 *
 * ── WHAT IS REAL HERE, AND WHY IT HAD TO BE ───────────────────────────────
 * Everything on the loader path. hotswap_rollback() re-enters the full
 * admission gauntlet over a SEALED IMAGE — ELF shape probe, SHA-256 + SHA3-256
 * over the mapped bytes, the sealed-core consensus pin, symbol resolution,
 * admit, probe-before-publish, and ONE all-or-nothing registry batch — and the
 * single stage it skips is path confinement, because a shelved image has no
 * path. None of that can be driven with a module struct fabricated in a test
 * translation unit: a shelf entry is BYTES. So this group activates two REAL
 * module .so images built by the Makefile from tests/harness/fixtures/
 * hotswap_rollback_module.c, differing only in the marker string their
 * handlers render, and asks the live command registry which one answers.
 *
 * What is supplied by the test, exactly as test_hotswap_shelf.c supplies it,
 * is the resident's own seam: the registry commit hook, the probe hook, and
 * the quiescence hook. Those are caller-provided by design (engine/modules/hotswap never
 * links kernel headers) and the resident's versions live in
 * tools/command/native_dev_hotswap.c.
 *
 * ── THE AUTHORITY THIS PROCESS TAKES, AND THE AUTHORITY IT DOES NOT ───────
 * Activation is gated on the -hotswap-activate flag, ZCL_HOTSWAP_ACTIVATE=1,
 * and the EXACT dev datadir ~/.zclassic-c23-dev. All three are re-checked at
 * the moment of the rollback, never remembered from the forward swap. This
 * group satisfies them honestly rather than weakening them: it points HOME at
 * a throwaway directory under ./test-tmp and creates .zclassic-c23-dev inside
 * it, so `~` resolves there for the length of the group and no real datadir is
 * ever named, opened, read or written. HOME is restored before the group
 * returns. The loader never opens the datadir on this path — it classifies the
 * string — but the directory is created anyway so the classification is the
 * same one a real dev lane gets.
 *
 * ── DISCRIMINATION ────────────────────────────────────────────────────────
 * Every assertion below was chosen so that it fails against a rollback that
 * only LOOKS successful:
 *   - a rollback that reported ok while leaving B live fails the dispatch
 *     assertions (the reply names the image by marker, not by liveness);
 *   - a rollback that reused or lowered the generation fails
 *     `> previous generation` and the active-generation equality;
 *   - a rollback that republished from a remembered struct instead of the
 *     shelved bytes fails artifact_sha256 equality with the ORIGINAL
 *     activation report for that image;
 *   - a rollback that consumed the shelf on a refusal fails the "refused,
 *     then the same shelf entry still rolls back" sequence;
 *   - a rollback that leaked the descriptor it dup()ed fails the fd census.
 */

#if !defined(__linux__)

/* realpath() reaches this TU only through the glibc fortify inline that
 * -D_FORTIFY_SOURCE=2 pulls in at -O1 and above; the build's
 * -D_POSIX_C_SOURCE=200809L declares it nowhere. Without this the file
 * compiles by accident of optimisation and breaks at -O0, under
 * -U_FORTIFY_SOURCE, and on any non-glibc libc. It must precede every
 * include: after them it does nothing. See platform/modules/util/src/hw_profile.c. */
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
 *
 * HOME is redirected for the length of the group so `~/.zclassic-c23-dev`
 * resolves into a throwaway tree. Nothing real is ever named. */
static bool rb_env_begin(void)
{
    char cwd[PATH_MAX];
    if (!getcwd(cwd, sizeof(cwd)))
        return false;

    const char *home = getenv("HOME");
    g_had_home = home != NULL;
    if (g_had_home)
        snprintf(g_home_saved, sizeof(g_home_saved), "%s", home);

    snprintf(g_home, sizeof(g_home), "%s/test-tmp/hs_rollback_home_%d", cwd,
             (int)getpid());
    (void)mkdir("test-tmp", 0700);
    test_rm_rf_recursive(g_home);
    if (mkdir(g_home, 0700) != 0)
        return false;
    snprintf(g_datadir, sizeof(g_datadir), "%s/.zclassic-c23-dev", g_home);
    if (mkdir(g_datadir, 0700) != 0)
        return false;

    if (setenv("HOME", g_home, 1) != 0)
        return false;
    if (setenv("ZCL_HOTSWAP_ACTIVATE", "1", 1) != 0)
        return false;
    hotswap_set_activate_flag(true);
    return true;
}

static void rb_env_end(void)
{
    hotswap_set_activate_flag(false);
    (void)unsetenv("ZCL_HOTSWAP_ACTIVATE");
    if (g_had_home)
        (void)setenv("HOME", g_home_saved, 1);
    else
        (void)unsetenv("HOME");
    if (g_home[0])
        test_rm_rf_recursive(g_home);
}

/* Resolve the two module images. Absent images are a hard failure, never a
 * skip: they are a build product this group declares as a prerequisite, so
 * "not built" means the wiring broke, not that there is nothing to prove. */
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

/* The successful-rollback counter, read out of the subsystem's own telemetry
 * rather than inferred. It is DELIBERATELY not the failed-activation unwind
 * counter, so reading it proves the distinct thing fired. */
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

/* ── 2. THE TOGGLE, AND THE GENERATION ───────────────────────────────────
 *
 * A -> B -> rollback -> rollback. The first rollback must put A back where
 * dispatch can see it and must take a generation strictly newer than B's; the
 * second must land back on B, so rollback is the toggle its contract claims.
 */
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

/* ── 3. THE GATE IS RE-CHECKED AT THE MOMENT OF THE ROLLBACK ─────────────
 *
 * hotswap/hotswap_shelf.h states that a rollback re-runs the SAME
 * authorization the forward swap ran, now, rather than remembering it. Until a
 * rollback could succeed at all, that sentence could not be tested in either
 * direction: everything refused. Both directions are driven here, back to
 * back, over ONE shelf entry — which also proves a refusal does not consume
 * the shelf and does not leak the descriptor it duplicated.
 */
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

int test_hotswap_rollback(void)
{
    printf("\n=== hot-swap rollback: a real image put back live ===\n");
    int failures = 0;

    g_fixture_ready = rb_env_begin() && rb_resolve_images();
    if (!g_fixture_ready) {
        printf("hotswap_rollback: FAIL — module images are missing; expected "
               "%s and %s (built as a prerequisite of every test binary; "
               "run `make test_parallel`)\n", RB_SO_A, RB_SO_B);
    }

    failures += t_images_activate();
    failures += t_rollback_toggles_dispatch();
    failures += t_refused_rollback_changes_nothing();

    rb_release();
    rb_env_end();
    printf("=== hotswap_rollback: %d failures ===\n", failures);
    return failures;
}

#endif
