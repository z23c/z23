/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Unit tests for the postmortem-capsule -> chaos-scenario skeleton bridge
 * (tools/postmortem_to_scenario.c, Super-Reliability program lane B5).
 *
 * Builds synthetic capsules with the REAL postmortem_capture_write() API
 * (never hand-crafts the .cap format), runs the converter's core function
 * in-process, then feeds the emitted skeleton through the REAL chaos
 * scenario parser (tools/sim/chaos.c's run_scenario()) to prove it
 * actually PARSES -- the same in-process-inclusion pattern
 * tests/harness/src/test_chaos_harness.c already uses to unit-test chaos.c
 * itself. Both included .c files define only `static` symbols, so two
 * separate translation units (this file and test_chaos_harness.c) each
 * including the same source text is safe -- no link collision.
 */

#include "test/test_core.h"
#include "sim/postmortem.h"
#include "sim/seed_tape.h"

#include <errno.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#define POSTMORTEM_TO_SCENARIO_NO_MAIN
#include "../../../tools/postmortem_to_scenario.c"

#define CHAOS_NO_MAIN
#include "../../../tools/sim/chaos.c"

#define P2S_CHECK(name, expr) do { \
    printf("postmortem_to_scenario: %s... ", (name)); \
    if ((expr)) printf("OK\n"); \
    else { printf("FAIL\n"); failures++; } \
} while (0)

static char *p2s_mkdtemp(char *tmpl)
{
    return mkdtemp(tmpl);
}

static bool p2s_file_contains(const char *path, const char *needle)
{
    FILE *fp = fopen(path, "rb");
    if (!fp) return false;
    char *buf = (char *)malloc(65536); // raw-alloc-ok:test-scratch-buffer
    if (!buf) {
        fclose(fp);
        return false;
    }
    size_t n = fread(buf, 1, 65535, fp);
    fclose(fp);
    buf[n] = '\0';
    bool found = strstr(buf, needle) != NULL;
    free(buf);
    return found;
}

/* Builds an unpacked postmortem capsule under `parent_dir` via the real
 * postmortem_capture_write() API. `n_events` injected events are recorded
 * before the snapshot, cycling through a few taxonomy types (including an
 * app-defined one) so the category-summary and overflow-listing paths in
 * the converter both get exercised. Returns the capsule directory path
 * (caller-owned buffer) or NULL on failure. */
static bool p2s_build_capsule(const char *parent_dir, size_t n_events,
                              int crash_signal, const char *reason,
                              char *cap_path_out, size_t cap_path_cap)
{
    seed_tape_t *tape = seed_tape_open(0xC0FFEE1234ULL, 1750000000LL);
    if (!tape) return false;

    static const uint8_t kTypes[] = { 1, 1, 3, 4, 200 };
    for (size_t i = 0; i < n_events; i++) {
        uint8_t type = kTypes[i % (sizeof(kTypes) / sizeof(kTypes[0]))];
        char payload[24];
        int pn = snprintf(payload, sizeof(payload), "ev-%zu", i);
        if (seed_tape_inject(tape, type, payload, (size_t)pn) != 0) {
            seed_tape_close(tape);
            return false;
        }
        if (i % 3 == 0 && seed_tape_advance(tape, 1000) != 0) {
            seed_tape_close(tape);
            return false;
        }
    }

    struct postmortem_capture_opts opts = {
        .dir = parent_dir,
        .tape = tape,
        .crash_signal = crash_signal,
        .crash_unix = 1750000450,
        .reason = reason,
        .log_path = NULL,
    };
    int rc = postmortem_capture_write(&opts, cap_path_out, cap_path_cap);
    seed_tape_close(tape);
    return rc == 0;
}

static bool p2s_write_text(const char *path, const char *text)
{
    FILE *fp = fopen(path, "wb");
    if (!fp) return false;
    bool ok = fputs(text, fp) >= 0;
    return fclose(fp) == 0 && ok;
}

int test_postmortem_to_scenario(void)
{
    printf("\n=== postmortem_to_scenario tests ===\n");
    int failures = 0;

    char root_tmpl[128];
    snprintf(root_tmpl, sizeof(root_tmpl),
             "/tmp/zcl_p2s_test_%d_XXXXXX", (int)getpid());
    char *root = p2s_mkdtemp(root_tmpl);
    P2S_CHECK("mkdtemp scratch root", root != NULL);
    if (!root) return failures + 1;

    /* ── Happy path: a synthetic capsule with a handful of events ─────── */
    char caps_dir[256];
    snprintf(caps_dir, sizeof(caps_dir), "%s/postmortems", root);
    char cap_path[300];
    bool built = p2s_build_capsule(caps_dir, 7, 11 /* SIGSEGV */,
                                   "synthetic crash for postmortem_to_scenario",
                                   cap_path, sizeof(cap_path));
    P2S_CHECK("build synthetic capsule", built);
    if (!built) {
        test_rm_rf_recursive(root);
        return failures + 1;
    }

    char out_path[350];
    snprintf(out_path, sizeof(out_path), "%s/repro.scenario", root);

    struct postmortem_to_scenario_stats st;
    char err[512];
    err[0] = '\0';
    int rc = postmortem_to_scenario_convert(cap_path, out_path, &st, err, sizeof(err));
    P2S_CHECK("convert succeeds", rc == 0);
    P2S_CHECK("stats: seed slot valid", st.seed_slot_valid);
    P2S_CHECK("stats: crash_signal recorded", st.crash_signal == 11);
    P2S_CHECK("stats: crash_unix recorded", st.crash_unix == 1750000450);
    P2S_CHECK("stats: reason recorded",
              strcmp(st.reason,
                     "synthetic crash for postmortem_to_scenario") == 0);
    P2S_CHECK("stats: events walked == injected", st.inject_count_walked == 7);
    P2S_CHECK("stats: events shown <= walked",
              st.events_shown <= st.inject_count_walked);

    struct stat out_st;
    P2S_CHECK("output file exists", stat(out_path, &out_st) == 0);

    char seed_line[64];
    snprintf(seed_line, sizeof(seed_line), "seed        0x%016" PRIx64,
             st.seed_slot);
    P2S_CHECK("skeleton contains seed line",
              p2s_file_contains(out_path, seed_line));
    P2S_CHECK("skeleton contains reason",
              p2s_file_contains(out_path,
                                "synthetic crash for postmortem_to_scenario"));
    P2S_CHECK("skeleton contains category summary header",
              p2s_file_contains(out_path, "Injected event category summary"));
    P2S_CHECK("skeleton contains PEER_MESSAGE category",
              p2s_file_contains(out_path, "PEER_MESSAGE"));
    P2S_CHECK("skeleton contains app-defined category (type 200)",
              p2s_file_contains(out_path, "app-defined"));
    P2S_CHECK("skeleton contains manual-steps TODO block",
              p2s_file_contains(out_path, "TODO (manual steps 3-5"));
    P2S_CHECK("skeleton contains honest-scope note",
              p2s_file_contains(out_path, "HONEST SCOPE"));
    P2S_CHECK("skeleton contains no-op expect assertion",
              p2s_file_contains(out_path, "expect      no_crash"));
    P2S_CHECK("skeleton flags seed as informational-only",
              p2s_file_contains(out_path, "informational seed slot"));

    /* ── The emitted skeleton must PARSE via the real chaos DSL parser ── */
    struct chaos_ctx cctx;
    chaos_ctx_init(&cctx);
    cctx.scenario_path = out_path;
    int parse_rc = run_scenario(&cctx);
    P2S_CHECK("skeleton parses via zclassic23-chaos run_scenario()",
              parse_rc == 0);
    P2S_CHECK("parsed seed matches converter's seed slot",
              cctx.seed_set && cctx.seed == st.seed_slot);
    P2S_CHECK("parsed scenario has >=1 expect assertion",
              cctx.expect_count >= 1);

    /* ── boot_phase derivation: a log.txt with a [boot-stage] line ─────── */
    char caps_dir2[256];
    snprintf(caps_dir2, sizeof(caps_dir2), "%s/postmortems2", root);
    char cap_path2[300];
    built = p2s_build_capsule(caps_dir2, 2, 6 /* SIGABRT */,
                              "second synthetic crash", cap_path2,
                              sizeof(cap_path2));
    P2S_CHECK("build second synthetic capsule", built);
    if (built) {
        char log_path[356];
        snprintf(log_path, sizeof(log_path), "%s/log.txt", cap_path2);
        P2S_CHECK("overwrite log.txt with boot-stage trace",
                  p2s_write_text(log_path,
                      "some earlier noise\n"
                      "[boot-stage] chain_tip_resolved -> network_ready\n"
                      "[boot-stage] network_ready -> services_running\n"
                      "trailing noise after crash\n"));

        char out_path2[350];
        snprintf(out_path2, sizeof(out_path2), "%s/repro2.scenario", root);
        struct postmortem_to_scenario_stats st2;
        rc = postmortem_to_scenario_convert(cap_path2, out_path2, &st2, err,
                                            sizeof(err));
        P2S_CHECK("convert (with boot-stage log) succeeds", rc == 0);
        P2S_CHECK("boot_phase derived == listening",
                  st2.boot_phase_derived &&
                  strcmp(st2.boot_phase, "listening") == 0);
        P2S_CHECK("skeleton records derived boot_phase line",
                  p2s_file_contains(out_path2, "boot_phase  listening"));

        struct chaos_ctx cctx2;
        chaos_ctx_init(&cctx2);
        cctx2.scenario_path = out_path2;
        P2S_CHECK("second skeleton also parses", run_scenario(&cctx2) == 0);
    } else {
        failures++;
    }

    /* ── boot_phase NOT derivable (no log.txt trace) -> honest default ─── */
    char caps_dir3[256];
    snprintf(caps_dir3, sizeof(caps_dir3), "%s/postmortems3", root);
    char cap_path3[300];
    built = p2s_build_capsule(caps_dir3, 1, 0 /* no signal */,
                              "no boot-stage trace", cap_path3,
                              sizeof(cap_path3));
    if (built) {
        struct postmortem_to_scenario_stats st3;
        char out_path3[350];
        snprintf(out_path3, sizeof(out_path3), "%s/repro3.scenario", root);
        rc = postmortem_to_scenario_convert(cap_path3, out_path3, &st3, err,
                                            sizeof(err));
        P2S_CHECK("convert (no boot-stage trace) succeeds", rc == 0);
        P2S_CHECK("boot_phase falls back to idb_complete, marked UNDETECTED",
                  !st3.boot_phase_derived &&
                  strcmp(st3.boot_phase, "idb_complete") == 0);
        P2S_CHECK("skeleton says UNDETECTED",
                  p2s_file_contains(out_path3, "UNDETECTED"));
    } else {
        failures++;
    }

    /* ── Event-listing overflow: more than P2S_EVENTS_SHOWN_MAX events ── */
    char caps_dir4[256];
    snprintf(caps_dir4, sizeof(caps_dir4), "%s/postmortems4", root);
    char cap_path4[300];
    built = p2s_build_capsule(caps_dir4, P2S_EVENTS_SHOWN_MAX + 10, 11,
                              "overflow test", cap_path4, sizeof(cap_path4));
    P2S_CHECK("build overflow capsule", built);
    if (built) {
        struct postmortem_to_scenario_stats st4;
        char out_path4[350];
        snprintf(out_path4, sizeof(out_path4), "%s/repro4.scenario", root);
        rc = postmortem_to_scenario_convert(cap_path4, out_path4, &st4, err,
                                            sizeof(err));
        P2S_CHECK("convert (overflow) succeeds", rc == 0);
        P2S_CHECK("walked count exceeds shown cap",
                  st4.inject_count_walked == P2S_EVENTS_SHOWN_MAX + 10);
        P2S_CHECK("shown count capped at P2S_EVENTS_SHOWN_MAX",
                  st4.events_shown == P2S_EVENTS_SHOWN_MAX);
        P2S_CHECK("skeleton notes the unshown overflow",
                  p2s_file_contains(out_path4, "more event(s) not shown"));

        struct chaos_ctx cctx4;
        chaos_ctx_init(&cctx4);
        cctx4.scenario_path = out_path4;
        P2S_CHECK("overflow skeleton still parses (bounded output)",
                  run_scenario(&cctx4) == 0);
    } else {
        failures++;
    }

    /* ── A genuinely-failing skeleton (unmet manual `expect`) reports
     * failure loudly via the same artifact path a real chaos regression
     * would use, rather than silently passing. This also exercises
     * chaos.c's write_failure_artifacts() (otherwise unreferenced once
     * main() is compiled out under CHAOS_NO_MAIN in this translation
     * unit) the same way test_chaos_harness.c does. ─────────────────── */
    char fail_scenario_path[350];
    snprintf(fail_scenario_path, sizeof(fail_scenario_path),
             "%s/fails_on_purpose.scenario", root);
    P2S_CHECK("write a scenario with an unmet expect",
              p2s_write_text(fail_scenario_path,
                             "seed 0x1\n"
                             "expect tip_height == 999\n"));

    char fail_artifact_dir[350];
    snprintf(fail_artifact_dir, sizeof(fail_artifact_dir),
             "%s/chaos-fail-artifacts", root);

    struct chaos_ctx fail_ctx;
    chaos_ctx_init(&fail_ctx);
    fail_ctx.scenario_path = fail_scenario_path;
    fail_ctx.artifact_dir = fail_artifact_dir;
    int fail_rc = run_scenario(&fail_ctx);
    P2S_CHECK("scenario with unmet expect fails loudly", fail_rc != 0);

    int artifact_rc = write_failure_artifacts(&fail_ctx);
    P2S_CHECK("failure artifacts written", artifact_rc == 0);
    struct stat fail_artifact_st;
    P2S_CHECK("failure artifact directory created",
              stat(fail_artifact_dir, &fail_artifact_st) == 0 &&
              S_ISDIR(fail_artifact_st.st_mode));

    /* ── Error paths ────────────────────────────────────────────────── */
    struct postmortem_to_scenario_stats bad_st;
    rc = postmortem_to_scenario_convert(NULL, NULL, &bad_st, err, sizeof(err));
    P2S_CHECK("NULL capsule path rejected", rc != 0);

    char missing_dir[300];
    snprintf(missing_dir, sizeof(missing_dir), "%s/does-not-exist", root);
    rc = postmortem_to_scenario_convert(missing_dir, NULL, &bad_st, err,
                                        sizeof(err));
    P2S_CHECK("missing capsule directory rejected", rc != 0);

    char not_a_dir[300];
    snprintf(not_a_dir, sizeof(not_a_dir), "%s/plain_file", root);
    P2S_CHECK("create a plain file (not a directory)",
              p2s_write_text(not_a_dir, "not a capsule\n"));
    rc = postmortem_to_scenario_convert(not_a_dir, NULL, &bad_st, err,
                                        sizeof(err));
    P2S_CHECK("plain-file (non-directory) capsule path rejected", rc != 0);

    char empty_dir[300];
    snprintf(empty_dir, sizeof(empty_dir), "%s/empty_cap_dir", root);
    P2S_CHECK("mkdir empty capsule-shaped dir", mkdir(empty_dir, 0755) == 0);
    rc = postmortem_to_scenario_convert(empty_dir, NULL, &bad_st, err,
                                        sizeof(err));
    P2S_CHECK("directory missing manifest.json rejected", rc != 0);

    test_rm_rf_recursive(root);

    printf("\n=== postmortem_to_scenario tests complete: %d failure(s) ===\n",
           failures);
    return failures;
}
