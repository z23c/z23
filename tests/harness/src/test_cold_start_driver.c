/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * -cold-start staged, resumable driver (config/boot_cold_start.h).
 *
 * Proves the properties that make the one-command cold start RESUMABLE, correctly
 * ORDERED, and REFUSAL-STICKY, without spawning a real node:
 *
 *   (a) plan configuration + stage naming/params.
 *   (b) receipt round-trip: write is durable (temp file gone, receipt present,
 *       fields correct) and read matches only on the SAME bound parameter; a
 *       REFUSAL receipt records its reason verbatim, never counts as a success,
 *       and is read back by cold_start_receipt_refused().
 *   (c) resume decision: cold_start_plan_next() returns the first configured
 *       prep stage whose success receipt is absent; a present receipt is skipped;
 *       a parameter-changed receipt is NOT skipped.
 *   (d) drive loop with an injected recording runner: a fresh datadir runs
 *       [headers, seed] then reaches SERVE (the BUNDLE stage is SKIPPED when no
 *       bundle is configured); after a simulated kill following stage 1 (only the
 *       headers receipt on disk), a re-drive runs ONLY [seed].
 *   (e) drive halts on a TRANSIENT stage failure WITHOUT writing that stage's
 *       receipt, so the failed stage is retried (and completes) on the next run.
 *   (f) a DECISION refusal records a refusal receipt (verbatim reason), returns
 *       COLD_START_BLOCKED, and is STICKY: a re-drive with the SAME bound
 *       parameter stays blocked WITHOUT re-running the stage; changing the bound
 *       parameter re-arms it.
 *
 * Hermetic: temp datadirs only, no child processes, no node boot. */

#include "test/test_core.h"
#include "config/boot_cold_start.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>

/* True iff the file at `path` contains `needle` (small receipt files). */
static bool file_contains(const char *path, const char *needle)
{
    FILE *f = fopen(path, "rb");
    if (!f)
        return false;
    char buf[4096];
    size_t n = fread(buf, 1, sizeof(buf) - 1, f);
    fclose(f);
    buf[n] = '\0';
    return strstr(buf, needle) != NULL;
}

/* ── Injected recording runner ──────────────────────────────────────── */

struct fake_runner {
    enum cold_start_stage ran[8];
    int n;
    enum cold_start_stage fail_on;   /* return COLD_START_TRANSIENT on this stage */
    bool use_fail;
    enum cold_start_stage refuse_on; /* return COLD_START_BLOCKED on this stage   */
    bool use_refuse;
    const char *refuse_reason;
};

static enum cold_start_result fake_run_stage(const struct cold_start_plan *plan,
                                             enum cold_start_stage stage,
                                             void *user, char *reason,
                                             size_t reason_n)
{
    (void)plan;
    struct fake_runner *f = (struct fake_runner *)user;
    if (f->n < (int)(sizeof(f->ran) / sizeof(f->ran[0])))
        f->ran[f->n++] = stage;
    if (f->use_refuse && stage == f->refuse_on) {
        if (reason && reason_n)
            snprintf(reason, reason_n, "%s",
                     f->refuse_reason ? f->refuse_reason : "refused");
        return COLD_START_BLOCKED; /* a decision — driver writes a refusal receipt */
    }
    if (f->use_fail && stage == f->fail_on) {
        if (reason && reason_n)
            snprintf(reason, reason_n, "simulated transient failure");
        return COLD_START_TRANSIENT; /* driver halts, writes NO receipt */
    }
    return COLD_START_OK; /* success => driver writes the success receipt */
}

static bool made_tmp(char *dir /* size >= 32 */)
{
    strcpy(dir, "/tmp/zcl_coldstart_XXXXXX");
    return mkdtemp(dir) != NULL;
}

/* rm -rf on a small, known coldstart tree (receipts + dir). */
static void cleanup_tree(const char *datadir)
{
    char p[512];
    const enum cold_start_stage prep[] = { COLD_START_STAGE_HEADERS,
                                           COLD_START_STAGE_SEED,
                                           COLD_START_STAGE_BUNDLE };
    for (size_t i = 0; i < sizeof(prep) / sizeof(prep[0]); i++) {
        if (cold_start_receipt_path(datadir, prep[i], p, sizeof(p)) > 0)
            unlink(p);
    }
    snprintf(p, sizeof(p), "%s/coldstart", datadir);
    rmdir(p);
    rmdir(datadir);
}

int test_cold_start_driver(void)
{
    int failures = 0;

    /* (a) plan configuration + stage naming/params. */
    printf("cold_start plan configuration + stage names ... ");
    {
        struct cold_start_plan plan = {
            .datadir = "/tmp/x", .header_source = "/src",
            .seed_snapshot = "/seed.snap", .install_bundle = NULL,
        };
        bool ok =
            strcmp(cold_start_stage_name(COLD_START_STAGE_HEADERS), "headers") == 0 &&
            strcmp(cold_start_stage_name(COLD_START_STAGE_SEED), "seed") == 0 &&
            strcmp(cold_start_stage_name(COLD_START_STAGE_BUNDLE), "bundle") == 0 &&
            strcmp(cold_start_stage_name(COLD_START_STAGE_SERVE), "serve") == 0 &&
            cold_start_stage_configured(&plan, COLD_START_STAGE_HEADERS) &&
            cold_start_stage_configured(&plan, COLD_START_STAGE_SEED) &&
            !cold_start_stage_configured(&plan, COLD_START_STAGE_BUNDLE) &&
            cold_start_stage_configured(&plan, COLD_START_STAGE_SERVE) &&
            strcmp(cold_start_stage_param(&plan, COLD_START_STAGE_HEADERS), "/src") == 0 &&
            cold_start_stage_param(&plan, COLD_START_STAGE_BUNDLE) == NULL &&
            cold_start_stage_param(&plan, COLD_START_STAGE_SERVE) == NULL;
        if (ok) printf("OK\n"); else { printf("FAIL\n"); failures++; }
    }

    /* (b) receipt round-trip: durable write, correct fields, parameter match,
     *     plus the refusal-receipt shape (outcome=refused + verbatim reason). */
    printf("cold_start receipt write is durable + parameter-bound + refusal-aware ... ");
    {
        char dir[64];
        bool ok = made_tmp(dir);
        if (ok) {
            ok &= cold_start_receipt_write(dir, COLD_START_STAGE_HEADERS,
                                           "/home/.zclassic", false, NULL);
            char rpath[512], tmp[600];
            ok &= cold_start_receipt_path(dir, COLD_START_STAGE_HEADERS, rpath,
                                          sizeof(rpath)) > 0;
            /* The receipt exists; the temp file does NOT (atomic rename). */
            ok &= access(rpath, F_OK) == 0;
            snprintf(tmp, sizeof(tmp), "%s.tmp", rpath);
            ok &= access(tmp, F_OK) != 0;
            ok &= file_contains(rpath, "magic=ZCLCOLDSTART\n");
            ok &= file_contains(rpath, "stage=headers\n");
            ok &= file_contains(rpath, "outcome=ok\n");
            ok &= file_contains(rpath, "has_param=1\n");
            ok &= file_contains(rpath, "param=/home/.zclassic\n");
            /* Matches only on the same bound parameter. */
            ok &= cold_start_receipt_matches(dir, COLD_START_STAGE_HEADERS,
                                             "/home/.zclassic");
            ok &= !cold_start_receipt_matches(dir, COLD_START_STAGE_HEADERS,
                                              "/home/.other");
            ok &= !cold_start_receipt_matches(dir, COLD_START_STAGE_HEADERS,
                                              NULL);
            /* A success receipt is NOT a refusal. */
            ok &= !cold_start_receipt_refused(dir, COLD_START_STAGE_HEADERS,
                                              "/home/.zclassic", NULL, 0);
            /* A never-written stage never matches. */
            ok &= !cold_start_receipt_matches(dir, COLD_START_STAGE_SEED,
                                              "/seed.snap");
            /* A parameter-less stage receipt matches NULL only. */
            ok &= cold_start_receipt_write(dir, COLD_START_STAGE_BUNDLE, NULL,
                                           false, NULL);
            ok &= cold_start_receipt_matches(dir, COLD_START_STAGE_BUNDLE, NULL);
            ok &= !cold_start_receipt_matches(dir, COLD_START_STAGE_BUNDLE,
                                              "/b");

            /* A REFUSAL receipt: records outcome=refused + verbatim reason, is
             * NOT a success, and is read back by cold_start_receipt_refused. */
            const char *why = "REFUSED: -install-consensus-bundle: datadir is "
                              "the canonical lane";
            ok &= cold_start_receipt_write(dir, COLD_START_STAGE_SEED,
                                           "/seed.snap", true, why);
            char seedr[512];
            ok &= cold_start_receipt_path(dir, COLD_START_STAGE_SEED, seedr,
                                          sizeof(seedr)) > 0;
            ok &= file_contains(seedr, "outcome=refused\n");
            ok &= file_contains(seedr, "reason=REFUSED: -install-consensus-bundle: "
                                       "datadir is the canonical lane\n");
            ok &= !cold_start_receipt_matches(dir, COLD_START_STAGE_SEED,
                                              "/seed.snap");
            char got[COLD_START_REASON_MAX] = {0};
            ok &= cold_start_receipt_refused(dir, COLD_START_STAGE_SEED,
                                             "/seed.snap", got, sizeof(got));
            ok &= strstr(got, "canonical lane") != NULL;
            /* A refusal is parameter-bound too. */
            ok &= !cold_start_receipt_refused(dir, COLD_START_STAGE_SEED,
                                              "/other.snap", NULL, 0);
            cleanup_tree(dir);
        }
        if (ok) printf("OK\n"); else { printf("FAIL\n"); failures++; }
    }

    /* (c) resume decision via receipts. */
    printf("cold_start plan_next resume decision ... ");
    {
        char dir[64];
        bool ok = made_tmp(dir);
        if (ok) {
            struct cold_start_plan plan = {
                .datadir = dir, .header_source = "/src",
                .seed_snapshot = "/seed.snap", .install_bundle = NULL,
            };
            /* Fresh: no receipts => first configured stage is HEADERS. */
            ok &= cold_start_plan_next(&plan) == COLD_START_STAGE_HEADERS;
            /* After headers receipt: skip to SEED. */
            ok &= cold_start_receipt_write(dir, COLD_START_STAGE_HEADERS, "/src",
                                           false, NULL);
            ok &= cold_start_plan_next(&plan) == COLD_START_STAGE_SEED;
            /* After seed receipt: all configured prep done => SERVE (bundle is
             * unconfigured, so it is not required). */
            ok &= cold_start_receipt_write(dir, COLD_START_STAGE_SEED,
                                           "/seed.snap", false, NULL);
            ok &= cold_start_plan_next(&plan) == COLD_START_STAGE_SERVE;
            /* Changing the source parameter re-arms the HEADERS stage — a stale
             * receipt for a different source must NOT be skipped. */
            plan.header_source = "/src2";
            ok &= cold_start_plan_next(&plan) == COLD_START_STAGE_HEADERS;
            cleanup_tree(dir);
        }
        if (ok) printf("OK\n"); else { printf("FAIL\n"); failures++; }
    }

    /* (d) drive loop + resume-after-kill + skip-when-no-bundle (core property). */
    printf("cold_start drive runs stages in order, skips absent bundle, resumes after kill ... ");
    {
        char dir[64];
        bool ok = made_tmp(dir);
        if (ok) {
            struct cold_start_plan plan = {
                .datadir = dir, .header_source = "/src",
                .seed_snapshot = "/seed.snap", .install_bundle = NULL,
            };
            char reason[COLD_START_REASON_MAX];

            /* Full drive on a fresh datadir with NO bundle configured: runs
             * [headers, seed], SKIPS the bundle stage, reaches SERVE, and leaves
             * both receipts. */
            struct fake_runner f1 = {0};
            enum cold_start_stage reached = COLD_START_STAGE_HEADERS;
            ok &= cold_start_drive(&plan, fake_run_stage, &f1, &reached, reason,
                                   sizeof(reason)) == COLD_START_OK;
            ok &= reached == COLD_START_STAGE_SERVE;
            ok &= f1.n == 2 &&
                  f1.ran[0] == COLD_START_STAGE_HEADERS &&
                  f1.ran[1] == COLD_START_STAGE_SEED;
            /* Explicitly: the bundle stage was never run and never receipted. */
            for (int i = 0; i < f1.n; i++)
                ok &= f1.ran[i] != COLD_START_STAGE_BUNDLE;
            ok &= !cold_start_receipt_matches(dir, COLD_START_STAGE_BUNDLE, NULL);

            /* Simulate a KILL after stage 1: keep only the HEADERS receipt,
             * remove the SEED receipt as if the process died mid-seed. */
            char seedr[512];
            ok &= cold_start_receipt_path(dir, COLD_START_STAGE_SEED, seedr,
                                          sizeof(seedr)) > 0;
            unlink(seedr);
            ok &= cold_start_receipt_matches(dir, COLD_START_STAGE_HEADERS,
                                             "/src");
            ok &= !cold_start_receipt_matches(dir, COLD_START_STAGE_SEED,
                                              "/seed.snap");

            /* Re-drive: resume MUST skip the completed headers stage and run
             * ONLY the seed stage, then reach SERVE. */
            struct fake_runner f2 = {0};
            reached = COLD_START_STAGE_HEADERS;
            ok &= cold_start_drive(&plan, fake_run_stage, &f2, &reached, reason,
                                   sizeof(reason)) == COLD_START_OK;
            ok &= reached == COLD_START_STAGE_SERVE;
            ok &= f2.n == 1 && f2.ran[0] == COLD_START_STAGE_SEED;

            /* A third drive with everything receipted runs NOTHING. */
            struct fake_runner f3 = {0};
            ok &= cold_start_drive(&plan, fake_run_stage, &f3, &reached, reason,
                                   sizeof(reason)) == COLD_START_OK;
            ok &= reached == COLD_START_STAGE_SERVE && f3.n == 0;
            cleanup_tree(dir);
        }
        if (ok) printf("OK\n"); else { printf("FAIL\n"); failures++; }
    }

    /* (e) a TRANSIENT stage failure halts WITHOUT a receipt (retryable). */
    printf("cold_start drive halts on transient failure without a receipt ... ");
    {
        char dir[64];
        bool ok = made_tmp(dir);
        if (ok) {
            struct cold_start_plan plan = {
                .datadir = dir, .header_source = "/src",
                .seed_snapshot = "/seed.snap",
                .install_bundle = "/bundle.db",
            };
            char reason[COLD_START_REASON_MAX];
            /* Fail on SEED: headers should complete + receipt; seed runs, fails,
             * no seed receipt; bundle never runs. */
            struct fake_runner f = { .use_fail = true,
                                     .fail_on = COLD_START_STAGE_SEED };
            enum cold_start_stage reached = COLD_START_STAGE_HEADERS;
            enum cold_start_result rc = cold_start_drive(&plan, fake_run_stage,
                                                         &f, &reached, reason,
                                                         sizeof(reason));
            ok &= rc == COLD_START_TRANSIENT;
            ok &= reached == COLD_START_STAGE_SEED;
            ok &= strstr(reason, "transient") != NULL;
            ok &= f.n == 2 &&
                  f.ran[0] == COLD_START_STAGE_HEADERS &&
                  f.ran[1] == COLD_START_STAGE_SEED;
            ok &= cold_start_receipt_matches(dir, COLD_START_STAGE_HEADERS,
                                             "/src");
            ok &= !cold_start_receipt_matches(dir, COLD_START_STAGE_SEED,
                                              "/seed.snap");
            ok &= !cold_start_receipt_matches(dir, COLD_START_STAGE_BUNDLE,
                                              "/bundle.db");

            /* Next run (no failure) resumes at SEED and completes to SERVE,
             * running seed then bundle. */
            struct fake_runner f2 = {0};
            reached = COLD_START_STAGE_HEADERS;
            ok &= cold_start_drive(&plan, fake_run_stage, &f2, &reached, reason,
                                   sizeof(reason)) == COLD_START_OK;
            ok &= reached == COLD_START_STAGE_SERVE;
            ok &= f2.n == 2 &&
                  f2.ran[0] == COLD_START_STAGE_SEED &&
                  f2.ran[1] == COLD_START_STAGE_BUNDLE;
            cleanup_tree(dir);
        }
        if (ok) printf("OK\n"); else { printf("FAIL\n"); failures++; }
    }

    /* (f) a DECISION refusal records a blocker + is STICKY (never auto-retried);
     *     changing the bound parameter re-arms it. */
    printf("cold_start drive records + honors a sticky refusal (never retried) ... ");
    {
        char dir[64];
        bool ok = made_tmp(dir);
        if (ok) {
            struct cold_start_plan plan = {
                .datadir = dir, .header_source = "/src",
                .seed_snapshot = "/seed.snap",
                .install_bundle = "/bundle.db",
            };
            char reason[COLD_START_REASON_MAX];
            const char *why = "REFUSED: -install-consensus-bundle: bundle "
                              "height/hash does not bind to a validated header";

            /* Bundle stage refuses: headers+seed complete; bundle runs, refuses;
             * drive returns BLOCKED with the verbatim reason and writes a refusal
             * receipt. */
            struct fake_runner f = { .use_refuse = true,
                                     .refuse_on = COLD_START_STAGE_BUNDLE,
                                     .refuse_reason = why };
            enum cold_start_stage reached = COLD_START_STAGE_HEADERS;
            enum cold_start_result rc = cold_start_drive(&plan, fake_run_stage,
                                                         &f, &reached, reason,
                                                         sizeof(reason));
            ok &= rc == COLD_START_BLOCKED;
            ok &= reached == COLD_START_STAGE_BUNDLE;
            ok &= strstr(reason, "does not bind") != NULL;
            ok &= f.n == 3 &&
                  f.ran[0] == COLD_START_STAGE_HEADERS &&
                  f.ran[1] == COLD_START_STAGE_SEED &&
                  f.ran[2] == COLD_START_STAGE_BUNDLE;
            /* The refusal is recorded, and does NOT count as a success. */
            ok &= cold_start_receipt_refused(dir, COLD_START_STAGE_BUNDLE,
                                             "/bundle.db", NULL, 0);
            ok &= !cold_start_receipt_matches(dir, COLD_START_STAGE_BUNDLE,
                                              "/bundle.db");

            /* Re-drive with the SAME bundle parameter: STICKY — the bundle stage
             * is NOT re-run (runner records nothing), drive stays BLOCKED, and
             * the reason is re-emitted from the receipt. */
            struct fake_runner f2 = { .use_refuse = true,
                                      .refuse_on = COLD_START_STAGE_BUNDLE,
                                      .refuse_reason = why };
            reached = COLD_START_STAGE_HEADERS;
            char reason2[COLD_START_REASON_MAX] = {0};
            rc = cold_start_drive(&plan, fake_run_stage, &f2, &reached, reason2,
                                  sizeof(reason2));
            ok &= rc == COLD_START_BLOCKED;
            ok &= reached == COLD_START_STAGE_BUNDLE;
            ok &= f2.n == 0; /* the refused stage was NOT re-run */
            ok &= strstr(reason2, "does not bind") != NULL;

            /* Changing the bound bundle parameter RE-ARMS the stage — a refusal
             * is bound to its parameter, so a different bundle re-runs. */
            plan.install_bundle = "/bundle-v2.db";
            struct fake_runner f3 = {0}; /* this time the new bundle succeeds */
            reached = COLD_START_STAGE_HEADERS;
            rc = cold_start_drive(&plan, fake_run_stage, &f3, &reached, reason,
                                  sizeof(reason));
            ok &= rc == COLD_START_OK;
            ok &= reached == COLD_START_STAGE_SERVE;
            ok &= f3.n == 1 && f3.ran[0] == COLD_START_STAGE_BUNDLE;
            cleanup_tree(dir);
        }
        if (ok) printf("OK\n"); else { printf("FAIL\n"); failures++; }
    }

    return failures;
}
