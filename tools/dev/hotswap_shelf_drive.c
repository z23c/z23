/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * hotswap_shelf_drive — EXECUTE the hot-swap shelf: activate, supersede, roll
 * back, roll back again, supersede again, and refuse.
 *
 * WHY THIS EXISTS. The shelf (hotswap/hotswap_shelf.h — hotswap_shelf_list,
 * hotswap_shelf_peek, hotswap_rollback) was verified by construction and by
 * code reading only. It cannot be driven from a test_parallel group, for three
 * independent reasons:
 *
 *   1. Only the dynamic-loading activation path shelves anything, so the sequence
 *      needs REAL compiled, consensus-pinned, ELF-shape-clean module .so files
 *      — a separate build step, not a test link.
 *   2. test_parallel's module mode (ZCL_HOTSWAP_TEST_MODULE) reads its module
 *      ONCE in the parent before any group forks and activates exactly one
 *      module for the whole process. A supersede is not expressible there.
 *   3. hotswap_rollback() re-checks hotswap_activation_authorized() AT ROLLBACK
 *      TIME: the exact dev datadir, the -hotswap-activate flag, and
 *      ZCL_HOTSWAP_ACTIVATE=1. A test process that satisfied that would be
 *      holding live-activation authority for its whole run.
 *
 * So this is a standalone dev CLI with its own main(), linked against the dev
 * node's own objects (so a module's kernel imports — zcl_native_bridge_run,
 * json_*, the resident policy counters — resolve exactly as they do in
 * zclassic23-dev) and driven by tools/dev/hotswap-shelf-selftest.sh.
 *
 * NOTHING HERE IS A TEST-ONLY LOADER. Every activation goes through
 * hotswap_activate(request_activate=true, require_authorization=true) — the
 * full resident gate — and every publish uses the canonical resident hooks
 * (zcl_native_hotswap_publish_hooks), so the registry commit re-checks
 * READY + EFFECT_READ + non-alias and the probe-before-publish gate runs. A
 * module that would be refused in the node is refused here.
 *
 * HERMETIC DATADIR. hotswap_datadir_is_dev() derives the one admissible path
 * from $HOME. The driver script runs this binary under a scratch HOME, so the
 * "exact dev datadir" is a disposable directory inside scratch and the real
 * ~/.zclassic-c23-dev (63 GB of chain state) is never opened, read, or
 * written. The gate itself is NOT relaxed: the identical predicate runs, and
 * this binary refuses to start if it does not pass.
 *
 * WHAT IT ASSERTS (each printed with the real value it compared):
 *   a  three modules from ONE swappable TU with three distinct digests
 *   b  activate A, then activate B — a genuine supersede
 *   c  the shelf holds A: peek reports A's REAL sha256 and A's generation
 *   d  roll back: dispatch answers as A again
 *   e  roll back again: it toggles to B; generation rises STRICTLY every step
 *   f  activate C: depth is 1 — the shelf holds B, not A
 *   g  a REFUSED rollback leaves the live implementation and the shelf intact
 */

/* Contained exactly like the APIs it drives: the publish hooks and the
 * probe-buffer release are declared only under ZCL_DEV_BUILD/ZCL_TESTING.
 * A build without either macro (the clang portability gate compiles this
 * tree with the node flags) then sees a tool that refuses, not one that
 * fails to parse. */
#if defined(ZCL_DEV_BUILD) || defined(ZCL_TESTING)

#include "command/native_dev_hotswap.h"
#include "config/command_catalog.h"
#include "crypto/sha256.h"
#include "base/hex.h"
#include "hotswap/hotswap_module.h"
#include "hotswap/hotswap_shelf.h"
#include "json/json.h"
#include "kernel/command_registry.h"

#include <signal.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* This binary links the dev node's objects but supplies its OWN main(), so it
 * also owns the one datum src/main.c defines for the whole program: the signal
 * handler's shutdown flag that several services read. It is never set here —
 * nothing in this process installs a signal handler, boots a service, or runs
 * a shutdown — but the definition has to exist for the link, and a stub that
 * silently diverged from the real declaration would be worse than none, so it
 * is spelled exactly as src/main.c spells it. */
volatile sig_atomic_t g_shutdown_requested = 0;

/* ── result accounting ────────────────────────────────────────────────────
 * A harness that passes because it silently did nothing is worse than no
 * harness, so every assertion is counted and the count is printed. Zero
 * assertions is a FAILURE, not a pass. */
static unsigned g_checks;
static unsigned g_failures;

static void check(bool ok, const char *what, const char *detail)
{
    g_checks++;
    if (ok) {
        printf("    ok    %-52s %s\n", what, detail ? detail : "");
    } else {
        g_failures++;
        printf("    FAIL  %-52s %s\n", what, detail ? detail : "");
    }
}

/* A precondition whose failure makes every later assertion meaningless. */
__attribute__((noreturn))
static void fatal(const char *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    fprintf(stderr, "hotswap-shelf-drive: FATAL: ");
    vfprintf(stderr, fmt, ap);
    fprintf(stderr, "\n");
    va_end(ap);
    exit(2);
}

/* ── independent digest of the artifact bytes ─────────────────────────────
 * The shelf's digest claim is checked against a hash this file computes from
 * the .so on disk, NOT merely against the loader's own earlier report. */
static bool file_sha256_hex(const char *path, char out[65])
{
    out[0] = '\0';
    FILE *f = fopen(path, "rb");
    if (!f)
        return false;
    struct sha256_ctx ctx;
    sha256_init(&ctx);
    unsigned char buf[65536];
    size_t n;
    while ((n = fread(buf, 1, sizeof(buf), f)) > 0)
        sha256_write(&ctx, buf, n);
    bool ok = (ferror(f) == 0);
    fclose(f);
    if (!ok)
        return false;
    unsigned char digest[SHA256_OUTPUT_SIZE];
    sha256_finalize(&ctx, digest);
    zcl_hex_encode(digest, sizeof(digest), out);
    return true;
}

/* ── dispatch through the REAL registry ───────────────────────────────────
 * Not a call to a remembered function pointer: the leaf is resolved in the
 * public catalog and executed through zcl_command_registry_execute_json,
 * which consults the published override snapshot exactly as the node does. */
static char g_dispatch_json[ZCL_COMMAND_EXTENDED_LIST_BUDGET + 1];

static bool dispatch_marker(const char *leaf, const char *marker_key,
                            int64_t *out_marker, int64_t *out_dispatches)
{
    const struct zcl_command_registry *reg = zcl_command_catalog();
    bool was_alias = false;
    const struct zcl_command_spec *spec =
        zcl_command_registry_find(reg, leaf, &was_alias);
    if (!spec)
        return false;

    struct zcl_command_context context = {
        .registry = reg,
        .granted_capabilities = ~(uint64_t)0,
        .authority_ceiling = ZCL_COMMAND_AUTH_OWNER,
        .dev_build = true,
    };
    struct json_value input;
    json_init(&input);
    json_set_object(&input);
    enum zcl_command_exit exit_code = ZCL_COMMAND_EXIT_INTERNAL;
    size_t n = zcl_command_registry_execute_json(
        reg, spec, &context, &input, false, spec->path, "normal", 0, 0, NULL,
        g_dispatch_json, sizeof(g_dispatch_json) - 1, &exit_code);
    json_free(&input);
    if (n == 0 || n >= sizeof(g_dispatch_json))
        return false;
    g_dispatch_json[n] = '\0';
    if (exit_code != ZCL_COMMAND_EXIT_OK)
        return false;

    struct json_value root;
    json_init(&root);
    if (!json_read(&root, g_dispatch_json, n)) {
        json_free(&root);
        return false;
    }
    const struct json_value *data = json_get(&root, "data");
    const struct json_value *marker = data ? json_get(data, marker_key) : NULL;
    const struct json_value *dispatches =
        data ? json_get(data, "resident_dispatches") : NULL;
    bool ok = marker != NULL;
    if (ok)
        *out_marker = json_get_int(marker);
    if (out_dispatches)
        *out_dispatches = dispatches ? json_get_int(dispatches) : -1;
    json_free(&root);
    return ok;
}

/* ── one activation, fully reported ───────────────────────────────────────*/
struct act_result {
    uint32_t generation;
    char     sha256[65];
};

static void activate_or_die(const char *label, const char *so_path,
                            const char *datadir,
                            const struct hotswap_publish_hooks *hooks,
                            struct act_result *out)
{
    struct hotswap_activate_report report;
    bool ok = hotswap_activate(so_path, datadir, /*request_activate=*/true,
                               hooks, &report);
    zcl_native_hotswap_probe_rendered_clear();
    if (!ok || !report.activated)
        fatal("activation of module %s REFUSED at stage=%s: %s\n  artifact: %s",
              label, report.stage[0] ? report.stage : "(none)",
              report.error[0] ? report.error : "(no error text)", so_path);
    printf("    activated module %s  gen=%u leaves=%u probed=%s sha256=%s\n",
           label, report.generation, report.leaf_count,
           report.probed ? "yes" : "no", report.artifact_sha256);
    out->generation = report.generation;
    (void)snprintf(out->sha256, sizeof(out->sha256), "%s",
                   report.artifact_sha256);
}

static bool rollback(const char *source_tu,
                     const struct hotswap_publish_hooks *hooks,
                     struct hotswap_activate_report *report)
{
    bool ok = hotswap_rollback(source_tu, hooks, report);
    zcl_native_hotswap_probe_rendered_clear();
    return ok;
}

static const char *arg_value(int argc, char **argv, const char *key)
{
    size_t klen = strlen(key);
    for (int i = 1; i < argc; i++) {
        if (strncmp(argv[i], key, klen) == 0 && argv[i][klen] == '=')
            return argv[i] + klen + 1;
    }
    return NULL;
}

int main(int argc, char **argv)
{
    const char *datadir   = arg_value(argc, argv, "--datadir");
    const char *source_tu = arg_value(argc, argv, "--source-tu");
    const char *leaf      = arg_value(argc, argv, "--leaf");
    const char *marker_key = arg_value(argc, argv, "--marker-key");
    const char *so_a      = arg_value(argc, argv, "--module-a");
    const char *so_b      = arg_value(argc, argv, "--module-b");
    const char *so_c      = arg_value(argc, argv, "--module-c");
    /* A source that is on the swappable allowlist but was never activated in
     * this process: the "nothing shelved" refusal. */
    const char *unshelved = arg_value(argc, argv, "--unshelved-source");

    if (!datadir || !source_tu || !leaf || !marker_key || !so_a || !so_b ||
        !so_c || !unshelved) {
        fprintf(stderr,
            "usage: hotswap_shelf_drive --datadir=<dev datadir>\n"
            "         --source-tu=<repo-relative swappable .c>\n"
            "         --leaf=<canonical leaf> --marker-key=<reply field>\n"
            "         --module-a=<so> --module-b=<so> --module-c=<so>\n"
            "         --unshelved-source=<another allowlist row>\n");
        return 2;
    }

    /* The loader logs its refusals on stderr. With stdout redirected to a
     * file it would be block-buffered and those lines would land inside an
     * assertion line, which makes the transcript unreadable exactly where it
     * matters most. Line-buffer stdout so the two interleave in real order. */
    setvbuf(stdout, NULL, _IOLBF, 0);

    printf("══════════ HOT-SWAP SHELF — REAL END-TO-END DRIVE ══════════\n");
    printf("  source_tu   %s\n", source_tu);
    printf("  leaf        %s   (marker field '%s')\n", leaf, marker_key);
    printf("  datadir     %s\n", datadir);
    printf("  module A    %s\n", so_a);
    printf("  module B    %s\n", so_b);
    printf("  module C    %s\n\n", so_c);

    /* ── preconditions ────────────────────────────────────────────────── */
    const char *env = getenv("ZCL_HOTSWAP_ACTIVATE");
    if (!env || strcmp(env, "1") != 0)
        fatal("ZCL_HOTSWAP_ACTIVATE=1 is not set — rollback would be refused "
              "at stage=authorize and nothing would be exercised");
    /* The resident node sets this from -hotswap-activate during argv parse. */
    hotswap_set_activate_flag(true);

    char why[256] = {0};
    if (!hotswap_activation_authorized(datadir, why, sizeof(why)))
        fatal("activation gate refuses this datadir: %s", why);
    printf("  gate        hotswap_activation_authorized() PASSES for this "
           "datadir\n");

    zcl_command_registry_set_active(zcl_command_catalog());
    struct hotswap_publish_hooks hooks;
    /* with_quiesce=TRUE, which is what the RESIDENT node uses and is the
     * harder case for the shelf. It lets the loader confirm that every retired
     * override snapshot has drained and then unmap the superseded module's
     * mapping. A rollback that then still works is proof the shelf really does
     * re-map its retained sealed image from scratch rather than quietly reusing a
     * mapping that happened to still be there — which is the whole reason the
     * shelf holds bytes and not a struct pointer. With false, every superseded
     * .so stays mapped forever and that distinction is untestable. */
    zcl_native_hotswap_publish_hooks(&hooks, /*with_quiesce=*/true);

    char sha_file_a[65], sha_file_b[65], sha_file_c[65];
    if (!file_sha256_hex(so_a, sha_file_a) ||
        !file_sha256_hex(so_b, sha_file_b) ||
        !file_sha256_hex(so_c, sha_file_c))
        fatal("could not hash one of the module artifacts");

    printf("\n── (a) three modules, one TU, three distinct artifacts\n");
    printf("    A sha256 %s\n    B sha256 %s\n    C sha256 %s\n",
           sha_file_a, sha_file_b, sha_file_c);
    check(strcmp(sha_file_a, sha_file_b) != 0 &&
          strcmp(sha_file_b, sha_file_c) != 0 &&
          strcmp(sha_file_a, sha_file_c) != 0,
          "A, B and C are three DIFFERENT artifacts", "");

    struct hotswap_shelf_entry entry;
    memset(&entry, 0, sizeof(entry));
    check(!hotswap_shelf_peek(source_tu, &entry),
          "shelf is empty before the first activation", source_tu);

    /* ── (b) activate A, then B — a genuine supersede ──────────────────── */
    printf("\n── (b) activate A, then supersede with B\n");
    struct act_result act_a, act_b;
    activate_or_die("A", so_a, datadir, &hooks, &act_a);
    check(strcmp(act_a.sha256, sha_file_a) == 0,
          "loader hashed A's real bytes", act_a.sha256);

    int64_t marker = -1, dispatches = -1;
    if (!dispatch_marker(leaf, marker_key, &marker, &dispatches))
        fatal("dispatch of %s produced no '%s' field. Raw reply:\n%s",
              leaf, marker_key, g_dispatch_json);
    int64_t marker_a = marker;
    printf("    dispatch  %s -> %s=%lld (resident_dispatches=%lld)\n", leaf,
           marker_key, (long long)marker_a, (long long)dispatches);

    memset(&entry, 0, sizeof(entry));
    check(!hotswap_shelf_peek(source_tu, &entry),
          "one activation shelves NOTHING (no predecessor yet)", "");

    activate_or_die("B", so_b, datadir, &hooks, &act_b);
    check(strcmp(act_b.sha256, sha_file_b) == 0,
          "loader hashed B's real bytes", act_b.sha256);
    check(act_b.generation > act_a.generation,
          "generation rose on the supersede", "");

    int64_t marker_b = -1;
    if (!dispatch_marker(leaf, marker_key, &marker_b, &dispatches))
        fatal("dispatch after activating B produced no '%s'", marker_key);
    printf("    dispatch  %s -> %s=%lld\n", leaf, marker_key,
           (long long)marker_b);
    check(marker_b != marker_a,
          "dispatch now answers as B, not A", "A and B are distinguishable");

    /* ── (c) the shelf holds A — its REAL digest and generation ────────── */
    printf("\n── (c) the shelf holds A\n");
    memset(&entry, 0, sizeof(entry));
    bool peeked = hotswap_shelf_peek(source_tu, &entry);
    check(peeked, "hotswap_shelf_peek reports an entry", source_tu);
    if (!peeked)
        fatal("nothing shelved after a supersede — the rest cannot be driven");
    printf("    shelf     sha256=%s generation=%u present=%s\n",
           entry.artifact_sha256, entry.generation,
           entry.present ? "true" : "false");
    check(strcmp(entry.artifact_sha256, sha_file_a) == 0,
          "shelf digest == A's REAL sha256 (hashed from the file)",
          sha_file_a);
    check(entry.generation == act_a.generation,
          "shelf generation == the generation A had when live", "");
    check(strcmp(entry.source_tu, source_tu) == 0,
          "shelf entry names the right source TU", entry.source_tu);
    check(hotswap_shelf_list(NULL, 0) == 1,
          "exactly one source has a shelved image", "");

    /* ── (d) roll back — dispatch answers as A again ───────────────────── */
    printf("\n── (d) roll back\n");
    struct hotswap_activate_report r1;
    if (!rollback(source_tu, &hooks, &r1))
        fatal("rollback REFUSED at stage=%s: %s",
              r1.stage[0] ? r1.stage : "(none)",
              r1.error[0] ? r1.error : "(no error text)");
    printf("    rollback  gen=%u sha256=%s leaves=%u probed=%s\n",
           r1.generation, r1.artifact_sha256, r1.leaf_count,
           r1.probed ? "yes" : "no");
    check(r1.activated, "rollback ACTIVATED (a real commit, not verify-only)",
          "");
    check(strcmp(r1.artifact_sha256, sha_file_a) == 0,
          "the republished image is A's bytes", r1.artifact_sha256);
    check(r1.generation > act_b.generation,
          "generation rose again (rollback is a forward publish)", "");
    int64_t marker_now = -1;
    if (!dispatch_marker(leaf, marker_key, &marker_now, &dispatches))
        fatal("dispatch after rollback produced no '%s'", marker_key);
    printf("    dispatch  %s -> %s=%lld\n", leaf, marker_key,
           (long long)marker_now);
    check(marker_now == marker_a, "dispatch answers as A again", "");

    /* ── (e) roll back again — it toggles ──────────────────────────────── */
    printf("\n── (e) roll back again (the toggle)\n");
    memset(&entry, 0, sizeof(entry));
    check(hotswap_shelf_peek(source_tu, &entry) &&
          strcmp(entry.artifact_sha256, sha_file_b) == 0 &&
          entry.generation == act_b.generation,
          "after the rollback the shelf holds B", entry.artifact_sha256);

    struct hotswap_activate_report r2;
    if (!rollback(source_tu, &hooks, &r2))
        fatal("second rollback REFUSED at stage=%s: %s",
              r2.stage[0] ? r2.stage : "(none)",
              r2.error[0] ? r2.error : "(no error text)");
    printf("    rollback  gen=%u sha256=%s\n", r2.generation,
           r2.artifact_sha256);
    check(strcmp(r2.artifact_sha256, sha_file_b) == 0,
          "the second rollback republished B", r2.artifact_sha256);
    check(r2.generation > r1.generation, "generation rose a fourth time", "");
    if (!dispatch_marker(leaf, marker_key, &marker_now, &dispatches))
        fatal("dispatch after the second rollback produced no '%s'",
              marker_key);
    printf("    dispatch  %s -> %s=%lld\n", leaf, marker_key,
           (long long)marker_now);
    check(marker_now == marker_b, "dispatch toggled back to B", "");

    /* ── (f) depth is 1 ────────────────────────────────────────────────── */
    printf("\n── (f) depth is 1: a third activation shelves the IMMEDIATELY "
           "previous image\n");
    struct act_result act_c;
    activate_or_die("C", so_c, datadir, &hooks, &act_c);
    check(strcmp(act_c.sha256, sha_file_c) == 0,
          "loader hashed C's real bytes", act_c.sha256);
    check(act_c.generation > r2.generation, "generation rose a fifth time",
          "");
    int64_t marker_c = -1;
    if (!dispatch_marker(leaf, marker_key, &marker_c, &dispatches))
        fatal("dispatch after activating C produced no '%s'", marker_key);
    printf("    dispatch  %s -> %s=%lld\n", leaf, marker_key,
           (long long)marker_c);
    check(marker_c != marker_a && marker_c != marker_b,
          "dispatch answers as C", "");

    memset(&entry, 0, sizeof(entry));
    peeked = hotswap_shelf_peek(source_tu, &entry);
    check(peeked, "the shelf still holds exactly one entry", "");
    printf("    shelf     sha256=%s generation=%u\n", entry.artifact_sha256,
           entry.generation);
    check(peeked && strcmp(entry.artifact_sha256, sha_file_b) == 0,
          "the shelf holds B — the image C superseded", sha_file_b);
    check(peeked && strcmp(entry.artifact_sha256, sha_file_a) != 0,
          "the shelf does NOT hold A (depth 1, not a stack)", sha_file_a);
    check(peeked && entry.generation == r2.generation,
          "shelf generation == B's generation while it was live", "");
    check(hotswap_shelf_list(NULL, 0) == 1,
          "still exactly one shelved source", "");

    /* ── (g) a REFUSED rollback changes nothing ────────────────────────── */
    printf("\n── (g) a REFUSED rollback leaves the live module and the shelf "
           "untouched\n");
    char shelf_before[65];
    (void)snprintf(shelf_before, sizeof(shelf_before), "%s",
                   entry.artifact_sha256);
    uint32_t shelf_gen_before = entry.generation;
    uint32_t registry_gen_before = zcl_command_registry_active_generation();

    /* g.1 — the gate is re-checked AT ROLLBACK TIME, never remembered from
     * the original activation. Drop the env opt-in and the same call must
     * refuse. */
    if (unsetenv("ZCL_HOTSWAP_ACTIVATE") != 0)
        fatal("could not unset ZCL_HOTSWAP_ACTIVATE");
    struct hotswap_activate_report r_ref;
    bool refused_ok = rollback(source_tu, &hooks, &r_ref);
    printf("    refused   ok=%s stage=%s error=%s\n",
           refused_ok ? "true" : "false",
           r_ref.stage[0] ? r_ref.stage : "(none)",
           r_ref.error[0] ? r_ref.error : "(none)");
    check(!refused_ok, "rollback REFUSED once the activation gate is closed",
          "");
    check(strcmp(r_ref.stage, "authorize") == 0,
          "refusal names the authorize stage", r_ref.stage);
    check(!r_ref.activated, "the refused rollback published nothing", "");
    if (setenv("ZCL_HOTSWAP_ACTIVATE", "1", 1) != 0)
        fatal("could not restore ZCL_HOTSWAP_ACTIVATE");

    /* g.2 — a source that has nothing shelved refuses at stage=shelf. */
    struct hotswap_activate_report r_unshelved;
    bool unshelved_ok = rollback(unshelved, &hooks, &r_unshelved);
    printf("    unshelved %s -> ok=%s stage=%s\n", unshelved,
           unshelved_ok ? "true" : "false",
           r_unshelved.stage[0] ? r_unshelved.stage : "(none)");
    check(!unshelved_ok, "rollback of a source with nothing shelved refuses",
          unshelved);
    check(strcmp(r_unshelved.stage, "shelf") == 0,
          "that refusal names the shelf stage", r_unshelved.stage);

    /* the live implementation and the shelf are both untouched */
    int64_t marker_after = -1;
    if (!dispatch_marker(leaf, marker_key, &marker_after, &dispatches))
        fatal("dispatch after the refusals produced no '%s'", marker_key);
    printf("    dispatch  %s -> %s=%lld\n", leaf, marker_key,
           (long long)marker_after);
    check(marker_after == marker_c,
          "the live implementation is still C", "");
    check(zcl_command_registry_active_generation() == registry_gen_before,
          "no new registry generation was published", "");
    memset(&entry, 0, sizeof(entry));
    check(hotswap_shelf_peek(source_tu, &entry) &&
          strcmp(entry.artifact_sha256, shelf_before) == 0 &&
          entry.generation == shelf_gen_before,
          "the shelf entry is byte-identical to before the refusals",
          shelf_before);

    /* ── verdict ──────────────────────────────────────────────────────── */
    printf("\n════════════════════════════════════════════════════════════\n");
    printf("  assertions driven : %u\n", g_checks);
    printf("  failures          : %u\n", g_failures);
    if (g_checks == 0) {
        printf("  SHELF DRIVE FAILED — zero assertions executed\n");
        return 1;
    }
    if (g_failures != 0) {
        printf("  SHELF DRIVE FAILED\n");
        return 1;
    }
    printf("  SHELF DRIVE PASSED\n");
    return 0;
}

#else /* neither ZCL_DEV_BUILD nor ZCL_TESTING */

#include <stdio.h>

int main(void)
{
    fprintf(stderr,
            "hotswap_shelf_drive: dev-only tool; build with ZCL_DEV_BUILD.\n");
    return 2;
}

#endif /* ZCL_DEV_BUILD || ZCL_TESTING */
