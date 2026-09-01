/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * test_golden_dev_cycle — Wave 4.1 golden test: the dev-loop
 * classify->prove->publish pipeline mechanism, driven hermetically as far
 * as the existing test seams allow.
 *
 * This test binary is NOT built with ZCL_DEV_BUILD (see
 * tests/harness/src/test_dev_platform.c's own note on this), so the actual
 * hotswap build/dlopen and transactional-reload subprocess legs of
 * tools/dev/devloop_cycle.c:zcl_devloop_run_cycle() are compiled out for
 * this harness. The load-bearing MECHANISM invariants that ARE reachable
 * hermetically, and that this file proves:
 *
 *   1. classify: an eligible-TU edit classifies to hotswap, not a full
 *      rebuild (zcl_devloop_plan_files — tools/dev/devloop.h).
 *   2. a sealed core/ apply is contained before authority, even with a token
 *      exit-3 semantics, BEFORE any publish step and regardless of
 *      ZCL_DEV_BUILD (zcl_devloop_run_cycle + zcl_devloop_refusal_json —
 *      the refusal check in devloop_cycle.c runs before the ZCL_DEV_BUILD
 *      #ifdef, so it is real in every build configuration).
 *   3. a green cycle auto-anchors with verdict+generation bound
 *      (vcs_devloop_anchor_cycle() — the exact call
 *      tools/dev/devloop_cycle.c:finish_cycle() makes on every "passed"
 *      verdict; see tests/harness/src/test_vcs_devloop.c for the same seam).
 *   4. elapsed_ms is plumbed end to end into the anchored commit.
 *
 * TIMING: strict wall-clock assertions (<=1s for the hotswap classify+
 * anchor leg, <=3s for a real dev_activation restart transaction) are
 * load-flaky under the 32-worker parallel test harness — measuring wall
 * time deterministically requires a quiet machine. They are gated behind
 * the env var ZCL_GOLDEN_TIMING_STRICT=1 and SKIPPED (with a printed SKIP
 * note) otherwise, so `make t ONLY=golden_dev_cycle` stays deterministic by
 * default. Set ZCL_GOLDEN_TIMING_STRICT=1 for the manual demo / quality
 * linger run: `ZCL_GOLDEN_TIMING_STRICT=1 make t ONLY=golden_dev_cycle`. */

/* realpath() needs __USE_MISC; -D_POSIX_C_SOURCE=200809L alone does not
 * declare it. Without this the TU only builds by accident of the glibc
 * fortify inline at -O3. */
#define _DEFAULT_SOURCE

#include "test/test_core.h"

#include "dev_activation.h"
#include "devloop.h"
#include "json/json.h"

#include "platform/time_compat.h"
#include "vcs/vcs.h"
#include "vcs/vcs_devloop.h"
#include "vcs/vcs_index.h"

#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

#ifndef PATH_MAX
#define PATH_MAX 4096
#endif

/* Write content to <dir>/<rel>, creating parent dirs. */
static bool gdc_write(const char *dir, const char *rel, const char *content)
{
    char full[PATH_MAX];
    snprintf(full, sizeof(full), "%s/%s", dir, rel);
    for (char *p = full + strlen(dir) + 1; *p; p++) {
        if (*p == '/') {
            *p = '\0';
            mkdir(full, 0755);
            *p = '/';
        }
    }
    FILE *f = fopen(full, "wb");
    if (!f)
        return false;
    size_t n = content ? strlen(content) : 0;
    if (n)
        fwrite(content, 1, n, f);
    fclose(f);
    return true;
}

/* Read and verify the worktree-scoped SHA3-sealed cycle verdict. */
static size_t read_native_cycle(const char *repo_root, char *buf, size_t cap)
{
    size_t len = 0;
    return zcl_devloop_cycle_state_read(repo_root, buf, cap, &len, NULL,
                                        NULL, 0) ==
                   ZCL_DEVLOOP_STATE_FOUND
               ? len : 0;
}

struct captured_commit {
    struct vcs_commit c;
    uint8_t            id[32];
    bool                got;
};

static bool capture_first_commit(const struct vcs_commit *c,
                                 const uint8_t commit_id[32], void *user)
{
    struct captured_commit *cap = user;
    cap->c = *c;
    memcpy(cap->id, commit_id, 32);
    cap->got = true;
    return false; /* newest-first log: stop after the first one */
}

/* ── test 1: classify — eligible TU maps to hotswap, not full rebuild ── */

static int t_classify_hotswap(void)
{
    int failures = 0;
    TEST("golden dev cycle: eligible-TU edit classifies to hotswap, not full rebuild") {
        struct zcl_devloop_plan plan;
        const char *files[] = { "contexts/wallet/controllers/src/wallet_native_handlers.c" };
        ASSERT(zcl_devloop_plan_files(files, 1, &plan));
        ASSERT(plan.action == ZCL_DEVLOOP_HOTSWAP);
        ASSERT(strcmp(plan.proof_group, "hotswap_simnet") == 0);
        ASSERT(!plan.sealed_core);
        ASSERT(!plan.consensus_risk);

        /* A sealed core/ file, in contrast, never routes to hotswap. */
        const char *core[] = { "core/consensus/src/check_block.c" };
        ASSERT(zcl_devloop_plan_files(core, 1, &plan));
        ASSERT(plan.action != ZCL_DEVLOOP_HOTSWAP);
        ASSERT(plan.sealed_core);
        PASS();
    } _test_next:;
    return failures;
}

/* ── test 2: apply containment precedes sealed-core authority ───────── */

static int t_sealed_refusal(void)
{
    int failures = 0;
    TEST("golden dev cycle: sealed core apply is contained with structured envelope (exit 3)") {
        char dir[512];
        test_make_tmpdir(dir, sizeof(dir), "golden_dev_cycle", "sealed");
        char *saved_home = getenv("HOME");
        saved_home = saved_home ? strdup(saved_home) : NULL;
        setenv("HOME", dir, 1);

        const char *core[] = {
            "core/consensus/src/check_block.c", "docs/notes.md"
        };
        ASSERT(!zcl_devloop_unseal_token_present(dir));
        int rc = zcl_devloop_run_cycle(dir, core, 2);
        ASSERT_EQ(rc, 3);  /* blocked-by-precondition, before any publish */

        /* Phase-0 publication containment is persisted before seal authority. */
        char verdict[8192];
        size_t vn = read_native_cycle(dir, verdict, sizeof(verdict));
        ASSERT(vn > 0);
        struct json_value v = {0};
        ASSERT(json_read(&v, verdict, vn));
        ASSERT_STR_EQ(json_get_str(json_get(&v, "schema")), "zcl.dev_cycle.v1");
        ASSERT_STR_EQ(json_get_str(json_get(&v, "status")), "blocked");
        ASSERT_STR_EQ(json_get_str(json_get(&v, "reason")),
                      "consensus_or_chain_state_is_never_swappable");
        ASSERT_STR_EQ(json_get_str(json_get(&v, "phase")),
                      "publication_contained");
        ASSERT(!json_get_bool(json_get(&v, "runtime_published")));
        ASSERT_STR_EQ(json_get_str(json_get(&v, "why_not_live")),
                      "runtime publication is contained until the source "
                      "epoch, proof receipts, resident CAS, and rollback are "
                      "durably bound");
        json_free(&v);

        /* The envelope itself: only the sealed member names in "paths". */
        char body[4096];
        size_t n = zcl_devloop_refusal_json(core, 2, body, sizeof(body));
        ASSERT(n > 0 && n < sizeof(body));
        ASSERT(strstr(body, "core/consensus/src/check_block.c") != NULL);
        ASSERT(strstr(body, "docs/notes.md") == NULL);

        /* A valid unseal token is never publication authority. */
        char tok[PATH_MAX];
        snprintf(tok, sizeof(tok), "%s/.core-unseal-token", dir);
        FILE *tf = fopen(tok, "w");
        ASSERT(tf != NULL);
        if (tf) { fputs("golden unseal\n", tf); fclose(tf); }
        int rc2 = zcl_devloop_run_cycle(dir, core, 2);
        ASSERT_EQ(rc2, 3);

        if (saved_home) {
            setenv("HOME", saved_home, 1);
            free(saved_home);
        } else {
            unsetenv("HOME");
        }
        test_rm_rf_recursive(dir);
        PASS();
    } _test_next:;
    return failures;
}

/* ── test 3: a green cycle auto-anchors with verdict+generation+elapsed_ms ── */

static int t_green_cycle_anchor(void)
{
    int failures = 0;
    TEST("golden dev cycle: a green cycle auto-anchors verdict+generation+elapsed_ms") {
        char dir[512];
        test_make_tmpdir(dir, sizeof(dir), "golden_dev_cycle", "anchor");
        ASSERT(gdc_write(dir, "src/hotswap_target.c",
                         "int f(void){return 1;}\n"));

        char hex[65];
        for (int i = 0; i < 32; i++)
            snprintf(hex + 2 * i, 3, "%02x", (uint8_t)(0x5a + i));
        hex[64] = 0;

        struct vcs_devloop_verdict v = {0};
        v.verdict_status = 0;
        v.phase = "resident_commit";
        v.elapsed_ms = 777;
        v.generation_hex = hex;
        v.agent_id = "golden-agent";
        v.session_id = "golden-session";
        v.task_ref = "wave4.1-golden";

        struct vcs_devloop_anchor_result ar = {0};
        vcs_devloop_anchor_cycle(dir, &v, &ar);
        ASSERT_EQ(ar.status, VCS_DEVLOOP_ANCHOR_OK);

        struct vcs_repo *r = vcs_open(dir);
        ASSERT(r != NULL);
        struct captured_commit cap = {0};
        ASSERT_EQ(vcs_log(r, 1, capture_first_commit, &cap), VCS_OK);
        ASSERT(cap.got);
        ASSERT(memcmp(cap.id, ar.commit_id, 32) == 0);
        ASSERT_EQ(cap.c.verdict_status, 0u);
        ASSERT_STR_EQ(cap.c.phase, "resident_commit");
        /* elapsed_ms plumbed end to end into the anchored commit. */
        ASSERT_EQ(cap.c.elapsed_ms, (uint64_t)777);
        uint8_t want_gen[32];
        ASSERT(vcs_devloop_hex32_decode(hex, want_gen));
        ASSERT(memcmp(cap.c.generation_sha256, want_gen, 32) == 0);
        ASSERT_STR_EQ(cap.c.agent_id, "golden-agent");
        ASSERT_STR_EQ(cap.c.session_id, "golden-session");
        ASSERT_STR_EQ(cap.c.task_ref, "wave4.1-golden");
        vcs_close(r);

        test_rm_rf_recursive(dir);
        PASS();
    } _test_next:;
    return failures;
}

/* ── strict timing (opt-in, manual demo / quality linger only) ──────── */

/* Minimal happy-path fake dev_activation ops, just enough to drive one real
 * activation transaction end to end (real filesystem/hash/atomic-rename
 * mechanics, fake systemctl/proc — same fake-ops harness shape as
 * tests/harness/src/test_dev_activation.c and test_golden_revert_roundtrip.c). */
struct timing_fake_ctx {
    char gen_root[PATH_MAX];
    bool service_up;
};

static int tfk_stop(void *ctx) { ((struct timing_fake_ctx *)ctx)->service_up = false; return 0; }
static int tfk_start(void *ctx) { ((struct timing_fake_ctx *)ctx)->service_up = true; return 0; }
static int tfk_reload(void *ctx) { (void)ctx; return 0; }
static int tfk_reset(void *ctx) { (void)ctx; return 0; }
static int tfk_active(void *ctx)
{
    return ((struct timing_fake_ctx *)ctx)->service_up ? 0 : 1;
}
static int tfk_main_pid(void *ctx, long *pid_out) { (void)ctx; *pid_out = 4242; return 0; }
static int tfk_running_exe(void *ctx, long pid, char *out, size_t out_sz)
{
    struct timing_fake_ctx *c = ctx;
    (void)pid;
    char link[PATH_MAX], gen[80];
    snprintf(link, sizeof(link), "%s/current", c->gen_root);
    ssize_t n = readlink(link, gen, sizeof(gen) - 1);
    if (n <= 0)
        return -1;
    gen[n] = 0;
    snprintf(out, out_sz, "%s/%s/zclassic23-dev", c->gen_root, gen);
    return 0;
}
static int tfk_preflight(void *ctx, const char *bin, const char *commit)
{
    (void)ctx; (void)bin; (void)commit;
    return 0;
}
static int tfk_probe(void *ctx, const char *gen_id, const char *commit)
{
    (void)ctx; (void)gen_id; (void)commit;
    return 0;
}

static void timing_fake_ops(struct dev_activation_ops *ops,
                            struct timing_fake_ctx *c)
{
    memset(ops, 0, sizeof(*ops));
    ops->service_stop = tfk_stop;
    ops->service_start = tfk_start;
    ops->service_daemon_reload = tfk_reload;
    ops->service_reset_failed = tfk_reset;
    ops->service_active = tfk_active;
    ops->service_main_pid = tfk_main_pid;
    ops->running_exe = tfk_running_exe;
    ops->preflight = tfk_preflight;
    ops->activation_probe = tfk_probe;
    ops->ctx = c;
}

static bool timing_write_binary(const char *path)
{
    FILE *f = fopen(path, "wb");
    if (!f)
        return false;
    char buf[256];
    memset(buf, 'T', sizeof(buf));
    fwrite(buf, 1, sizeof(buf), f);
    fclose(f);
    return chmod(path, 0755) == 0;
}

static double elapsed_ms_between(const struct timespec *a, const struct timespec *b)
{
    return (double)(b->tv_sec - a->tv_sec) * 1000.0 +
           (double)(b->tv_nsec - a->tv_nsec) / 1e6;
}

static int t_strict_timing(void)
{
    int failures = 0;
    if (!getenv("ZCL_GOLDEN_TIMING_STRICT")) {
        printf("golden dev cycle: strict timing... SKIP "
               "(set ZCL_GOLDEN_TIMING_STRICT=1 to run; load-flaky under the "
               "parallel harness by design, see file header)\n");
        return 0;
    }
    TEST("golden dev cycle: strict timing (hotswap classify+anchor <=1s, activation transaction <=3s)") {
        struct timespec a, b;

        /* Leg 1 ("hotswap"): the in-process classify + auto-anchor
         * mechanism a real hotswap-eligible dev-cycle drives before/after
         * the actual dynamic-load step (which needs ZCL_DEV_BUILD + a real
         * build and is out of scope for this hermetic harness). */
        char hdir[512];
        test_make_tmpdir(hdir, sizeof(hdir), "golden_dev_cycle", "timing_hotswap");
        ASSERT(gdc_write(hdir, "contexts/wallet/controllers/src/wallet_native_handlers.c",
                         "/* golden timing */\n"));
        struct zcl_devloop_plan plan;
        const char *files[] = { "contexts/wallet/controllers/src/wallet_native_handlers.c" };
        platform_time_monotonic_timespec(&a);
        ASSERT(zcl_devloop_plan_files(files, 1, &plan));
        ASSERT(plan.action == ZCL_DEVLOOP_HOTSWAP);
        struct vcs_devloop_verdict hv = {0};
        hv.phase = "resident_commit";
        struct vcs_devloop_anchor_result har = {0};
        vcs_devloop_anchor_cycle(hdir, &hv, &har);
        platform_time_monotonic_timespec(&b);
        ASSERT_EQ(har.status, VCS_DEVLOOP_ANCHOR_OK);
        double hotswap_ms = elapsed_ms_between(&a, &b);
        printf("  golden_dev_cycle: hotswap classify+anchor leg = %.2f ms\n",
               hotswap_ms);
        ASSERT(hotswap_ms < 1000.0);
        test_rm_rf_recursive(hdir);

        /* Leg 2 ("restart"): one real dev_activation transaction end to
         * end — real filesystem/hash/atomic-rename mechanics, fake
         * systemctl/proc. Captures the actual activation engine's own
         * mechanical cost (minus the process-exec legs a real restart
         * would pay). */
        char rdir[512];
        test_make_tmpdir(rdir, sizeof(rdir), "golden_dev_cycle", "timing_restart");
        char *saved_home = getenv("HOME");
        saved_home = saved_home ? strdup(saved_home) : NULL;
        char home_abs[PATH_MAX];
        ASSERT(realpath(rdir, home_abs) != NULL);
        setenv("HOME", home_abs, 1);
        setenv("ZCL_DEV_ACTIVATION_VERIFY_TIMEOUT_S", "0", 1);

        char gen_root[PATH_MAX], datadir[PATH_MAX], artifact[PATH_MAX];
        snprintf(gen_root, sizeof(gen_root), "%s/lib/gens", home_abs);
        snprintf(datadir, sizeof(datadir), "%s/.zclassic-c23-dev", home_abs);
        snprintf(artifact, sizeof(artifact), "%s/cand", home_abs);
        ASSERT(timing_write_binary(artifact));

        struct timing_fake_ctx tc = {0};
        snprintf(tc.gen_root, sizeof(tc.gen_root), "%s", gen_root);
        struct dev_activation_ops tops;
        timing_fake_ops(&tops, &tc);
        struct dev_activation_request treq = {0};
        treq.repo_root = home_abs;
        treq.artifact_path = artifact;
        treq.build_commit = "timingcommit";
        treq.source_identity =
            "1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef";
        treq.build_type = "fast";
        treq.gen_root = gen_root;
        treq.datadir = datadir;
        treq.unit = "zcl23-dev.service";
        treq.rpcport = 18252;
        treq.mode = DEV_ACTIVATION_MODE_ACTIVATE;
        struct dev_activation_result tres = {0};

        platform_time_monotonic_timespec(&a);
        int rc = dev_activation_run(&treq, &tops, &tres);
        platform_time_monotonic_timespec(&b);
        ASSERT_EQ(rc, DEV_ACTIVATION_OK);
        double activation_ms = elapsed_ms_between(&a, &b);
        printf("  golden_dev_cycle: activation transaction leg = %.2f ms\n",
               activation_ms);
        ASSERT(activation_ms < 3000.0);

        unsetenv("ZCL_DEV_ACTIVATION_VERIFY_TIMEOUT_S");
        if (saved_home) {
            setenv("HOME", saved_home, 1);
            free(saved_home);
        } else {
            unsetenv("HOME");
        }
        test_rm_rf_recursive(rdir);
        PASS();
    } _test_next:;
    return failures;
}

int test_golden_dev_cycle(void)
{
    int failures = 0;
    failures += t_classify_hotswap();
    failures += t_sealed_refusal();
    failures += t_green_cycle_anchor();
    failures += t_strict_timing();
    printf("=== golden_dev_cycle: %d failures ===\n", failures);
    return failures;
}
