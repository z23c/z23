/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Purpose: measure whether every registered test group gives the same answer
 * under deliberately perturbed environments, and partition the registry into
 * DETERMINISTIC / NONDETERMINISTIC / UNKNOWN.
 *
 * ── HOW IT MEASURES ────────────────────────────────────────────────────────
 * One `build/bin/test_parallel --verbose --no-cache` run per perturbation. The
 * runner replays every dispatched group's captured output behind a header
 * line, so ONE suite run yields ~1000 verdict vectors; running per group
 * instead would multiply an already long measurement by a thousand process
 * startups for no extra information.
 *
 * `--verbose` is not optional: a green full-suite run deliberately prints no
 * group transcripts at all (46k lines of "OK" has no diagnostic value), and
 * without the replay there is no vector to hash. `--no-cache` is not optional
 * either: a cache HIT prints a PASS header with an EMPTY body, which would
 * read as "this group asserts nothing" and quietly mark ~740 groups UNKNOWN.
 *
 * ── WHAT IT CANNOT DO ──────────────────────────────────────────────────────
 * This is a LOWER BOUND on non-determinism. A group whose hidden input none of
 * these perturbations moves is reported DETERMINISTIC and is not thereby
 * deterministic. A group that is wrong the same way every run has a perfectly
 * stable vector and is never caught. Determinism is not correctness.
 *
 * A perturbation this host refuses is DROPPED from the applied set and named
 * in the report, never silently pretended. See --list-profiles. */

#define _POSIX_C_SOURCE 200809L

#include "determinism/classify.h"
#include "determinism/perturbation.h"
#include "determinism/receipt.h"
#include "determinism/verdict.h"

#include <errno.h>
#include <fcntl.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

extern char **environ;

/* ── the registry ─────────────────────────────────────────────────────────
 * Compiled in from the same catalog the runner uses, so the tool and the
 * runner can never disagree about which groups exist. */
#define ZCL_TEST_GROUP(name) "test_" #name,
#define ZCL_SPEC_GROUP(name) "spec_" #name,
static const char *const k_registry[] = {
#include "test_group_catalog.def"
};
#undef ZCL_SPEC_GROUP
#undef ZCL_TEST_GROUP

static const size_t k_registry_len = sizeof(k_registry) / sizeof(k_registry[0]);

/* ── perturbation environments ────────────────────────────────────────────*/

#define ENV_PAD_VARS 512      /* x ~128 bytes each ~= 64 KiB of environment */
#define MAX_EXTRA_ENV (ENV_PAD_VARS + 32)

struct env_plan {
    const char *drop[16];      /* names removed (NUL-terminated list) */
    size_t drop_len;
    char *add[MAX_EXTRA_ENV];  /* owned "K=V" strings */
    size_t add_len;
    int jobs;
};

static void plan_free(struct env_plan *p)
{
    for (size_t i = 0; i < p->add_len; i++) free(p->add[i]);
    p->add_len = 0;
}

static bool plan_add(struct env_plan *p, const char *fmt, ...)
    __attribute__((format(printf, 2, 3)));

static bool plan_add(struct env_plan *p, const char *fmt, ...)
{
    if (p->add_len >= MAX_EXTRA_ENV) {
        fprintf(stderr, "determinism_scan: environment plan overflow\n");
        return false;
    }
    char buf[512];
    va_list ap;
    va_start(ap, fmt);
    int n = vsnprintf(buf, sizeof(buf), fmt, ap);
    va_end(ap);
    if (n < 0 || (size_t)n >= sizeof(buf)) {
        fprintf(stderr, "determinism_scan: environment entry too long\n");
        return false;
    }
    char *dup = strdup(buf);
    if (!dup) {
        fprintf(stderr, "determinism_scan: out of memory building environment\n");
        return false;
    }
    p->add[p->add_len++] = dup;
    return true;
}

static void plan_drop(struct env_plan *p, const char *name)
{
    if (p->drop_len + 1 >= sizeof(p->drop) / sizeof(p->drop[0])) return;
    p->drop[p->drop_len++] = name;
}

/* The build's own two-token compiler invocation. This is the exact shape that
 * split test_mutation_harness: a developer's shell has no CC at all, the build
 * sets "<root>/build/bin/zcc gcc", and the group answered differently to each. */
static bool cc_value(char *out, size_t cap)
{
    char cwd[512];
    if (!getcwd(cwd, sizeof(cwd))) return false;
    int n = snprintf(out, cap, "%s/build/bin/zcc gcc", cwd);
    return n > 0 && (size_t)n < cap;
}

static bool build_plan(enum zcl_det_perturbation p, int base_jobs,
                       const char *alt_tmp, struct env_plan *out)
{
    memset(out, 0, sizeof(*out));
    out->jobs = base_jobs;

    switch (p) {
    case ZCL_DET_P_BASE:
    case ZCL_DET_P_BASE_REPEAT:
        return true;

    case ZCL_DET_P_CC_SET: {
        char cc[600];
        if (!cc_value(cc, sizeof(cc))) return false;
        return plan_add(out, "CC=%s", cc) && plan_add(out, "CXX=%s", cc);
    }

    case ZCL_DET_P_CC_UNSET:
        plan_drop(out, "CC");
        plan_drop(out, "CXX");
        plan_drop(out, "CFLAGS");
        return true;

    case ZCL_DET_P_CWD_TMP:
        return plan_add(out, "TMPDIR=%s", alt_tmp) &&
               plan_add(out, "TMP=%s", alt_tmp) &&
               plan_add(out, "TEMP=%s", alt_tmp) &&
               plan_add(out, "PWD=%s", alt_tmp);

    case ZCL_DET_P_LOCALE_TZ:
        return plan_add(out, "TZ=Pacific/Kiritimati") &&
               plan_add(out, "LC_ALL=C") &&
               plan_add(out, "LANG=C") &&
               plan_add(out, "LC_TIME=C") &&
               plan_add(out, "LC_COLLATE=C");

    case ZCL_DET_P_ENV_PAD:
        for (int i = 0; i < ENV_PAD_VARS; i++) {
            /* Fixed content, so the padding itself is deterministic; only its
             * SIZE matters, and its size is what shifts the initial stack. */
            if (!plan_add(out, "ZCL_DET_PAD_%03d="
                               "0123456789012345678901234567890123456789"
                               "0123456789012345678901234567890123456789"
                               "01234567890123456789012345678901", i))
                return false;
        }
        return true;

    case ZCL_DET_P_JOBS_LOW:
        out->jobs = base_jobs > 2 ? base_jobs - 3 : 1;
        return true;

    case ZCL_DET_P_HOSTNAME:
        /* Reaching a different UTS hostname needs CAP_SYS_ADMIN in a user
         * namespace, and this host refuses an identity uid map to an
         * unprivileged process. Mapping to root instead would perturb far more
         * than the hostname (every capability, sandbox and "am I root" test),
         * so the honest move is to refuse the profile rather than measure
         * something else and label it HOSTNAME. */
        fprintf(stderr, "determinism_scan: HOSTNAME not applicable without "
                        "an unprivileged user namespace that keeps the uid\n");
        return false;

    case ZCL_DET_P__COUNT:
        break;
    }
    return false;
}

static char **compose_environ(const struct env_plan *p)
{
    size_t base = 0;
    while (environ[base]) base++;
    char **out = calloc(base + p->add_len + 1, sizeof(char *));
    if (!out) return NULL;
    size_t n = 0;
    for (size_t i = 0; i < base; i++) {
        const char *eq = strchr(environ[i], '=');
        size_t name_len = eq ? (size_t)(eq - environ[i]) : strlen(environ[i]);
        bool dropped = false;
        for (size_t d = 0; d < p->drop_len; d++) {
            if (strlen(p->drop[d]) == name_len &&
                strncmp(environ[i], p->drop[d], name_len) == 0) {
                dropped = true;
                break;
            }
        }
        /* An explicit addition replaces an inherited value of the same name. */
        for (size_t a = 0; a < p->add_len && !dropped; a++) {
            const char *aeq = strchr(p->add[a], '=');
            size_t alen = aeq ? (size_t)(aeq - p->add[a]) : strlen(p->add[a]);
            if (alen == name_len && strncmp(environ[i], p->add[a], alen) == 0)
                dropped = true;
        }
        if (!dropped) out[n++] = environ[i];
    }
    for (size_t a = 0; a < p->add_len; a++) out[n++] = p->add[a];
    out[n] = NULL;
    return out;
}

/* ── collect ──────────────────────────────────────────────────────────────*/

struct sink_ctx {
    FILE *out;
    size_t groups;
};

static bool digest_sink(void *ctx, const struct zcl_det_group_digest *g)
{
    struct sink_ctx *s = ctx;
    char hex[ZCL_DET_DIGEST_LEN * 2 + 1];
    zcl_det_hex(g->digest, ZCL_DET_DIGEST_LEN, hex, sizeof(hex));
    if (fprintf(s->out, "%s\t%s\t%u\t%d\n", g->group, hex, g->check_count,
                (int)g->status) < 0)
        return false;
    s->groups++;
    return true;
}

static int run_collect(const char *profile_name, const char *out_dir,
                       const char *runner, int jobs, const char *alt_tmp)
{
    enum zcl_det_perturbation p;
    if (!zcl_det_perturbation_from_name(profile_name, &p)) {
        fprintf(stderr, "determinism_scan: unknown profile '%s'\n", profile_name);
        return 2;
    }

    struct env_plan plan;
    if (!build_plan(p, jobs, alt_tmp, &plan)) {
        fprintf(stderr, "determinism_scan: profile %s NOT APPLIED on this host\n",
                profile_name);
        return 3;
    }

    char transcript[1024];
    char digests[1024];
    if (snprintf(transcript, sizeof(transcript), "%s/%s.transcript", out_dir,
                 profile_name) >= (int)sizeof(transcript) ||
        snprintf(digests, sizeof(digests), "%s/%s.digests", out_dir,
                 profile_name) >= (int)sizeof(digests)) {
        fprintf(stderr, "determinism_scan: output path too long\n");
        plan_free(&plan);
        return 2;
    }

    char jobs_arg[32];
    snprintf(jobs_arg, sizeof(jobs_arg), "--jobs=%d", plan.jobs);
    char *const argv[] = { (char *)runner, (char *)"--verbose",
                           (char *)"--no-cache", jobs_arg, NULL };

    char **envp = compose_environ(&plan);
    if (!envp) {
        fprintf(stderr, "determinism_scan: out of memory composing environ\n");
        plan_free(&plan);
        return 2;
    }

    fprintf(stderr, "determinism_scan: %s -> %s (%s)\n", profile_name,
            transcript, zcl_det_perturbation_why(p));

    pid_t pid = fork();
    if (pid < 0) {
        fprintf(stderr, "determinism_scan: fork failed: %s\n", strerror(errno));
        free(envp);
        plan_free(&plan);
        return 2;
    }
    if (pid == 0) {
        int fd = open(transcript, O_WRONLY | O_CREAT | O_TRUNC, 0644);
        if (fd < 0) _exit(120);
        if (dup2(fd, STDOUT_FILENO) < 0 || dup2(fd, STDERR_FILENO) < 0)
            _exit(121);
        if (fd > STDERR_FILENO) close(fd);
        execve(runner, argv, envp);
        _exit(122);
    }

    int status = 0;
    while (waitpid(pid, &status, 0) < 0 && errno == EINTR) {}
    free(envp);
    plan_free(&plan);

    /* A non-zero runner exit is EXPECTED when the tree has failing groups, and
     * it is not a reason to discard the measurement: a group that fails the
     * same way under every perturbation is deterministic, and one that fails
     * only sometimes is exactly what this tool is looking for. Only a runner
     * that never produced a transcript is a measurement failure. */
    FILE *in = fopen(transcript, "r");
    if (!in) {
        fprintf(stderr, "determinism_scan: no transcript at %s\n", transcript);
        return 2;
    }
    FILE *out = fopen(digests, "w");
    if (!out) {
        fprintf(stderr, "determinism_scan: cannot write %s\n", digests);
        fclose(in);
        return 2;
    }
    struct sink_ctx ctx = { .out = out, .groups = 0 };
    struct zcl_det_scan_stats stats;
    bool ok = zcl_det_transcript_scan(in, digest_sink, &ctx, &stats);
    fclose(in);
    if (fclose(out) != 0) ok = false;
    if (!ok) {
        fprintf(stderr, "determinism_scan: transcript scan failed\n");
        return 2;
    }
    fprintf(stderr,
            "determinism_scan: %s — runner status %d, %llu groups, "
            "%llu checks, %llu without a vector\n",
            profile_name, status, (unsigned long long)stats.groups,
            (unsigned long long)stats.checks,
            (unsigned long long)stats.groups_without_vector);
    return 0;
}

/* Re-derive one profile's digests from a transcript already on disk. The
 * measurement is the expensive half; parsing is free. Keeping the transcripts
 * means the parser can be tightened later and EVERY profile re-derived with
 * the SAME parser — deriving two profiles with two different parsers would
 * manufacture splits, which is the one mistake this tool must not make. */
static int run_parse(const char *transcript, const char *digests)
{
    FILE *in = fopen(transcript, "r");
    if (!in) {
        fprintf(stderr, "determinism_scan: cannot read %s\n", transcript);
        return 2;
    }
    FILE *out = fopen(digests, "w");
    if (!out) {
        fprintf(stderr, "determinism_scan: cannot write %s\n", digests);
        fclose(in);
        return 2;
    }
    struct sink_ctx ctx = { .out = out, .groups = 0 };
    struct zcl_det_scan_stats stats;
    bool ok = zcl_det_transcript_scan(in, digest_sink, &ctx, &stats);
    fclose(in);
    if (fclose(out) != 0) ok = false;
    if (!ok) {
        fprintf(stderr, "determinism_scan: transcript scan failed\n");
        return 2;
    }
    fprintf(stderr, "determinism_scan: %s -> %llu groups, %llu checks, "
                    "%llu without a vector\n",
            transcript, (unsigned long long)stats.groups,
            (unsigned long long)stats.checks,
            (unsigned long long)stats.groups_without_vector);
    return 0;
}

/* ── classify ─────────────────────────────────────────────────────────────*/

struct table {
    struct zcl_det_observation *cells; /* k_registry_len * n_profiles */
    size_t n_profiles;
};

static long registry_index(const char *group)
{
    for (size_t i = 0; i < k_registry_len; i++)
        if (strcmp(k_registry[i], group) == 0) return (long)i;
    return -1;
}

static bool load_profile(struct table *t, size_t slot, const char *path,
                         size_t *unknown_groups)
{
    FILE *f = fopen(path, "r");
    if (!f) {
        fprintf(stderr, "determinism_scan: cannot read %s\n", path);
        return false;
    }
    char line[1024];
    while (fgets(line, sizeof(line), f)) {
        char group[ZCL_DET_GROUP_MAX];
        char hex[ZCL_DET_DIGEST_LEN * 2 + 1];
        unsigned count = 0;
        int status = 0;
        if (sscanf(line, "%95s %64s %u %d", group, hex, &count, &status) != 4)
            continue;
        long idx = registry_index(group);
        if (idx < 0) {
            (*unknown_groups)++;
            continue;
        }
        struct zcl_det_observation *cell =
            &t->cells[(size_t)idx * t->n_profiles + slot];
        cell->observed = true;
        cell->check_count = count;
        if (!zcl_det_unhex(hex, cell->digest, ZCL_DET_DIGEST_LEN)) {
            fclose(f);
            fprintf(stderr, "determinism_scan: bad digest for %s in %s\n",
                    group, path);
            return false;
        }
    }
    fclose(f);
    return true;
}

static int run_classify(const char *in_dir, const char *profile_csv,
                        const char *baseline_path)
{
    enum zcl_det_perturbation order[ZCL_DET_P__COUNT];
    size_t n = 0;
    char csv[512];
    snprintf(csv, sizeof(csv), "%s", profile_csv);
    for (char *tok = strtok(csv, ","); tok; tok = strtok(NULL, ",")) {
        if (n >= ZCL_DET_P__COUNT) {
            fprintf(stderr, "determinism_scan: too many profiles\n");
            return 2;
        }
        if (!zcl_det_perturbation_from_name(tok, &order[n])) {
            fprintf(stderr, "determinism_scan: unknown profile '%s'\n", tok);
            return 2;
        }
        n++;
    }
    if (n < 2) {
        fprintf(stderr, "determinism_scan: need at least BASE and one more\n");
        return 2;
    }
    if (order[0] != ZCL_DET_P_BASE) {
        fprintf(stderr, "determinism_scan: BASE must be the first profile\n");
        return 2;
    }

    struct table t = { .cells = NULL, .n_profiles = n };
    t.cells = calloc(k_registry_len * n, sizeof(*t.cells));
    if (!t.cells) {
        fprintf(stderr, "determinism_scan: out of memory\n");
        return 2;
    }

    size_t unknown_groups = 0;
    for (size_t i = 0; i < n; i++) {
        char path[1024];
        snprintf(path, sizeof(path), "%s/%s.digests", in_dir,
                 zcl_det_perturbation_name(order[i]));
        if (!load_profile(&t, i, path, &unknown_groups)) {
            free(t.cells);
            return 2;
        }
    }

    /* Reindex so classify() sees BASE at slot 0 in ITS enum order. The table
     * is already built in the caller's order with BASE first, which is what
     * zcl_det_classify expects; the enum values are only used for naming. */
    /* Pass one: count the non-deterministic set, so the baseline file can be
     * written with its "# count: N" header already correct. The gate rejects a
     * header that disagrees with the rows, and a tool that emitted a file its
     * own gate rejects would be a rail nobody could use. */
    size_t nd_total = 0;
    for (size_t g = 0; g < k_registry_len; g++) {
        struct zcl_det_verdict v;
        if (!zcl_det_classify(&t.cells[g * n], n, &v)) {
            free(t.cells);
            return 2;
        }
        if (v.klass == ZCL_DET_CLASS_NONDETERMINISTIC) nd_total++;
    }

    struct zcl_det_partition part = {0};
    FILE *bl = NULL;
    if (baseline_path) {
        bl = fopen(baseline_path, "w");
        if (!bl) {
            fprintf(stderr, "determinism_scan: cannot write %s\n", baseline_path);
            free(t.cells);
            return 2;
        }
        fprintf(bl,
"# Determinism ratchet baseline — registered test groups whose verdict vector\n"
"# is NOT bitwise identical across every applied perturbation.\n"
"#\n"
"# GENERATED by 'determinism_scan classify --baseline='. One row per group:\n"
"# \"<group> <PERTURBATION>[+<PERTURBATION>...]\". The perturbation names the\n"
"# CAUSE. \"It varies\" is not a finding; \"it varies when CC is set\" is.\n"
"#\n"
"# THIS LIST MAY ONLY SHRINK. A group appearing here means a test stopped\n"
"# giving the same answer twice, and the fix is the test, not this file. There\n"
"# is no flag, allowlist or environment variable that admits a new row;\n"
"# tools/lint/check_determinism_ratchet.sh enforces that against the\n"
"# merge-base with origin/main.\n"
"#\n"
"# Re-measure with 'make determinism-scan', then one\n"
"# 'determinism_scan collect --profile=<P>' per perturbation and one\n"
"# 'determinism_scan classify'. That drives build/bin/test_parallel once per\n"
"# perturbation — hours of wall clock — and is never part of 'make lint'.\n"
"#\n"
"# perturbations applied:");
        for (size_t i = 0; i < n; i++)
            fprintf(bl, " %s", zcl_det_perturbation_name(order[i]));
        fprintf(bl, "\n#\n# count: %zu\n", nd_total);
    }

    printf("determinism scan — %zu registered groups, %zu perturbations\n",
           k_registry_len, n);
    for (size_t i = 0; i < n; i++)
        printf("  profile %zu: %s\n", i, zcl_det_perturbation_name(order[i]));
    printf("\nNONDETERMINISTIC (group — perturbation that split it):\n");

    size_t nd_count = 0;
    for (size_t g = 0; g < k_registry_len; g++) {
        struct zcl_det_verdict v;
        if (!zcl_det_classify(&t.cells[g * n], n, &v)) {
            free(t.cells);
            if (bl) fclose(bl);
            return 2;
        }
        zcl_det_partition_add(&part, &v);
        if (v.klass != ZCL_DET_CLASS_NONDETERMINISTIC) continue;

        /* Translate slot positions into perturbation names — through the
         * library, with THIS run's profile order, so the report and the
         * baseline can never disagree about what split a group. */
        char cause[512];
        zcl_det_split_mask_string(v.split_mask, order, n, cause, sizeof(cause));
        printf("  %-56s %s\n", k_registry[g], cause);
        if (bl) fprintf(bl, "%s %s\n", k_registry[g], cause);
        nd_count++;
    }
    if (nd_count == 0) printf("  (none)\n");

    printf("\nUNKNOWN (could not be measured — never folded into either "
           "other bucket):\n");
    for (size_t g = 0; g < k_registry_len; g++) {
        struct zcl_det_verdict v;
        if (!zcl_det_classify(&t.cells[g * n], n, &v)) continue;
        if (v.klass != ZCL_DET_CLASS_UNKNOWN) continue;
        printf("  %-56s %s\n", k_registry[g],
               zcl_det_unknown_reason_name(v.reason));
    }

    printf("\nPARTITION over %zu registered groups\n", part.total);
    printf("  DETERMINISTIC      %6zu\n", part.deterministic);
    printf("  NONDETERMINISTIC   %6zu\n", part.nondeterministic);
    printf("  UNKNOWN/not-run    %6zu\n", part.unknown_not_run);
    printf("  UNKNOWN/no-vector  %6zu\n", part.unknown_no_vector);
    printf("  UNKNOWN/partial    %6zu\n", part.unknown_partial);
    printf("  ---------------------------\n");
    printf("  sum                %6zu  %s\n",
           part.deterministic + part.nondeterministic + part.unknown_not_run +
               part.unknown_no_vector + part.unknown_partial,
           zcl_det_partition_is_exact(&part) ? "(exact)" : "(NOT EXACT)");
    if (unknown_groups)
        printf("  note: %zu transcript group(s) were not in the registry\n",
               unknown_groups);

    bool exact = zcl_det_partition_is_exact(&part);
    if (bl && fclose(bl) != 0) exact = false;
    free(t.cells);
    return exact ? 0 : 1;
}

/* ── main ─────────────────────────────────────────────────────────────────*/

/* ── receipt golden vector ────────────────────────────────────────────────
 * Prints the hex encoding of ONE fixed receipt. `make determinism-receipt-abi`
 * builds this file at -O0 and at -O2 and requires the two outputs to be
 * byte-identical. That is the check that would have caught the struct-padding
 * leak a previous lane found in this tree: padding bytes between members are
 * not required to be zero and -O0 and -O2 need not choose the same ones, so an
 * encoder that touched the struct's storage would print two different lines
 * here from one source file. */
static int run_receipt_golden(void)
{
    struct zcl_det_receipt r;
    memset(&r, 0, sizeof(r));
    r.version = ZCL_DET_RECEIPT_VERSION;
    if (!zcl_det_receipt_set_commit(
            &r, "0123456789abcdef0123456789abcdef01234567"))
        return 2;
    snprintf(r.group, sizeof(r.group), "test_determinism");
    zcl_det_receipt_label_digest("gcc-13.3.0/glibc-2.39/x86_64", r.toolchain);
    zcl_det_receipt_label_digest("gate:ZCL_STRESS_TESTS=0,jobs=8", r.env_class);
    r.verdict = ZCL_DET_CLASS_NONDETERMINISTIC;
    r.reason = ZCL_DET_UNKNOWN_NONE;
    r.perturbations = 8;
    r.split_mask = (1u << ZCL_DET_P_CC_SET) | (1u << ZCL_DET_P_ENV_PAD);
    r.check_count = 41;
    for (size_t i = 0; i < ZCL_DET_DIGEST_LEN; i++) {
        r.vector[i] = (uint8_t)(i * 7u + 3u);
        r.producer[i] = (uint8_t)(0xA0u ^ i);
    }

    uint8_t bytes[ZCL_DET_RECEIPT_SIZE];
    size_t len = 0;
    if (!zcl_det_receipt_encode(&r, bytes, sizeof(bytes), &len)) return 2;
    for (size_t i = 0; i < len; i++) printf("%02x", bytes[i]);
    printf("\n");

    /* Round-trip in the same breath: an encoding nobody can read back is not
     * an encoding. */
    struct zcl_det_receipt back;
    if (!zcl_det_receipt_decode(bytes, len, &back)) return 2;
    if (memcmp(&back.commit, &r.commit, sizeof(r.commit)) != 0 ||
        strcmp(back.group, r.group) != 0 || back.version != r.version ||
        back.verdict != r.verdict || back.reason != r.reason ||
        back.perturbations != r.perturbations ||
        back.split_mask != r.split_mask ||
        back.check_count != r.check_count ||
        memcmp(back.vector, r.vector, sizeof(r.vector)) != 0 ||
        memcmp(back.producer, r.producer, sizeof(r.producer)) != 0 ||
        memcmp(back.toolchain, r.toolchain, sizeof(r.toolchain)) != 0 ||
        memcmp(back.env_class, r.env_class, sizeof(r.env_class)) != 0) {
        fprintf(stderr, "determinism_scan: receipt round-trip mismatch\n");
        return 2;
    }
    return 0;
}

static void usage(void)
{
    fprintf(stderr,
        "usage:\n"
        "  determinism_scan collect --profile=NAME --out=DIR [--runner=PATH]\n"
        "                           [--jobs=N] [--alt-tmp=DIR]\n"
        "  determinism_scan parse --transcript=FILE --profile=NAME --out=DIR\n"
        "  determinism_scan classify --in=DIR --profiles=BASE,A,B[,...]\n"
        "                           [--baseline=FILE]\n"
        "  determinism_scan list-profiles\n"
        "  determinism_scan receipt-golden\n");
}

int main(int argc, char **argv)
{
    if (argc < 2) { usage(); return 2; }

    if (strcmp(argv[1], "receipt-golden") == 0) return run_receipt_golden();

    if (strcmp(argv[1], "list-profiles") == 0) {
        for (int i = 0; i < ZCL_DET_P__COUNT; i++)
            printf("%-14s %s\n",
                   zcl_det_perturbation_name((enum zcl_det_perturbation)i),
                   zcl_det_perturbation_why((enum zcl_det_perturbation)i));
        return 0;
    }

    const char *profile = NULL, *dir = NULL, *runner = "build/bin/test_parallel";
    const char *profiles = NULL, *baseline = NULL, *alt_tmp = "/tmp";
    const char *transcript_in = NULL;
    int jobs = 8;
    for (int i = 2; i < argc; i++) {
        if (strncmp(argv[i], "--profile=", 10) == 0)       profile = argv[i] + 10;
        else if (strncmp(argv[i], "--transcript=", 13) == 0)
            transcript_in = argv[i] + 13;
        else if (strncmp(argv[i], "--out=", 6) == 0)       dir = argv[i] + 6;
        else if (strncmp(argv[i], "--in=", 5) == 0)        dir = argv[i] + 5;
        else if (strncmp(argv[i], "--runner=", 9) == 0)    runner = argv[i] + 9;
        else if (strncmp(argv[i], "--profiles=", 11) == 0) profiles = argv[i] + 11;
        else if (strncmp(argv[i], "--baseline=", 11) == 0) baseline = argv[i] + 11;
        else if (strncmp(argv[i], "--alt-tmp=", 10) == 0)  alt_tmp = argv[i] + 10;
        else if (strncmp(argv[i], "--jobs=", 7) == 0)      jobs = atoi(argv[i] + 7);
        else { usage(); return 2; }
    }

    if (strcmp(argv[1], "collect") == 0) {
        if (!profile || !dir) { usage(); return 2; }
        return run_collect(profile, dir, runner, jobs, alt_tmp);
    }
    if (strcmp(argv[1], "parse") == 0) {
        if (!transcript_in || !profile || !dir) { usage(); return 2; }
        char digests[1024];
        if (snprintf(digests, sizeof(digests), "%s/%s.digests", dir, profile)
                >= (int)sizeof(digests)) {
            fprintf(stderr, "determinism_scan: output path too long\n");
            return 2;
        }
        return run_parse(transcript_in, digests);
    }
    if (strcmp(argv[1], "classify") == 0) {
        if (!dir || !profiles) { usage(); return 2; }
        return run_classify(dir, profiles, baseline);
    }
    usage();
    return 2;
}
