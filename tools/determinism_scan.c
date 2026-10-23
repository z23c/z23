/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Purpose: measure whether every registered test group gives the same answer
 * under deliberately perturbed environments, and partition the registry into
 * DETERMINISTIC / NONDETERMINISTIC / TIMING_SENSITIVE / UNKNOWN.
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

#include "base/hex.h"
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

/* Worker count for LOAD_HIGH: every online cpu, floored at 16 so the profile
 * still means something on a small box, capped at 64 so it cannot turn into a
 * fork bomb on a large one. */
static int load_high_jobs(void)
{
    long online = sysconf(_SC_NPROCESSORS_ONLN);
    int jobs = (online > 0) ? (int)online : 16;
    if (jobs < 16) jobs = 16;
    if (jobs > 64) jobs = 64;
    return jobs;
}

/* The 1-minute load average as INTEGER hundredths — 1.23 becomes 123.
 *
 * Parsed by hand rather than with strtod because this number ends up in a
 * recorded measurement, and no part of a measurement in this tree is allowed
 * to depend on floating-point rounding or on the locale's decimal separator.
 * /proc/loadavg is always C-locale "N.NN", so two integers and a fixed scale
 * are exact. Returns -1 when the file cannot be read, which the caller records
 * as "unknown" rather than as zero — a load of 0.00 and an unreadable load are
 * very different claims. */
static long load_centi(void)
{
    FILE *f = fopen("/proc/loadavg", "re");
    if (!f) return -1;
    char buf[128];
    if (!fgets(buf, sizeof(buf), f)) { fclose(f); return -1; }
    fclose(f);

    const char *s = buf;
    long whole = 0;
    if (*s < '0' || *s > '9') return -1;
    while (*s >= '0' && *s <= '9') whole = whole * 10 + (*s++ - '0');
    long frac = 0;
    if (*s == '.') {
        s++;
        for (int i = 0; i < 2; i++) {
            frac *= 10;
            if (*s >= '0' && *s <= '9') frac += *s++ - '0';
        }
    }
    if (whole > 100000) return -1;   /* implausible; report unknown */
    return whole * 100 + frac;
}

/* CC and CXX both name the build's own compiler wrapper. A wrapper path that
 * does not fit the buffer is refused before either variable is planned. */
static bool plan_cc_set(struct env_plan *out)
{
    char cc[600];
    if (!cc_value(cc, sizeof(cc))) return false;
    return plan_add(out, "CC=%s", cc) && plan_add(out, "CXX=%s", cc);
}

static bool plan_cwd_tmp(struct env_plan *out, const char *alt_tmp)
{
    return plan_add(out, "TMPDIR=%s", alt_tmp) &&
           plan_add(out, "TMP=%s", alt_tmp) &&
           plan_add(out, "TEMP=%s", alt_tmp) &&
           plan_add(out, "PWD=%s", alt_tmp);
}

static bool plan_locale_tz(struct env_plan *out)
{
    return plan_add(out, "TZ=Pacific/Kiritimati") &&
           plan_add(out, "LC_ALL=C") &&
           plan_add(out, "LANG=C") &&
           plan_add(out, "LC_TIME=C") &&
           plan_add(out, "LC_COLLATE=C");
}

static bool plan_env_pad(struct env_plan *out)
{
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

    case ZCL_DET_P_CC_SET:
        return plan_cc_set(out);

    case ZCL_DET_P_CC_UNSET:
        plan_drop(out, "CC");
        plan_drop(out, "CXX");
        plan_drop(out, "CFLAGS");
        return true;

    case ZCL_DET_P_CWD_TMP:
        return plan_cwd_tmp(out, alt_tmp);

    case ZCL_DET_P_LOCALE_TZ:
        return plan_locale_tz(out);

    case ZCL_DET_P_ENV_PAD:
        return plan_env_pad(out);

    case ZCL_DET_P_JOBS_LOW:
        out->jobs = base_jobs > 2 ? base_jobs - 3 : 1;
        return true;

    case ZCL_DET_P_LOAD_HIGH:
        /* Deliberately oversubscribe. JOBS_LOW alone is an 8-to-5 nudge, which
         * does not move a 60 s budget; the evidence that prompted this profile
         * was a group taking 22.6 s idle and 124 s under 32 workers. Taking
         * every online cpu (floor 16) makes "the machine got busier" a delta
         * big enough for a wall-clock assertion to notice. */
        out->jobs = load_high_jobs();
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
    char **out = calloc(base + p->add_len + 1, sizeof(char *)); // raw-alloc-ok:build-tool
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
    zcl_hex_encode(g->digest, ZCL_DET_DIGEST_LEN, hex);
    if (fprintf(s->out, "%s\t%s\t%u\t%d\n", g->group, hex, g->check_count,
                (int)g->status) < 0)
        return false;
    s->groups++;
    return true;
}

/* The digests file a profile writes under out_dir. False when it does not fit. */
static bool digests_path(const char *dir, const char *profile, char *out,
                         size_t cap)
{
    return snprintf(out, cap, "%s/%s.digests", dir, profile) < (int)cap;
}

/* The transcript and digests paths of one profile, both under out_dir. */
static bool profile_paths(const char *out_dir, const char *profile_name,
                          char *transcript, size_t tcap,
                          char *digests, size_t dcap)
{
    return snprintf(transcript, tcap, "%s/%s.transcript", out_dir,
                    profile_name) < (int)tcap &&
           digests_path(out_dir, profile_name, digests, dcap);
}

/* Runs the runner with stdout and stderr redirected to transcript, and waits
 * for it. Returns false only when fork fails; the runner's wait status lands
 * in *status. */
static bool run_profile_runner(const char *runner, char *const argv[],
                               char *const envp[], const char *transcript,
                               int *status)
{
    pid_t pid = fork();
    if (pid < 0) {
        fprintf(stderr, "determinism_scan: fork failed: %s\n", strerror(errno));
        return false;
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
    while (waitpid(pid, status, 0) < 0 && errno == EINTR) {}
    return true;
}

/* Turns the runner's transcript into the profile's digests file. A non-zero
 * runner exit is EXPECTED when the tree has failing groups, and it is not a
 * reason to discard the measurement: a group that fails the same way under
 * every perturbation is deterministic, and one that fails only sometimes is
 * exactly what this tool is looking for. Only a runner that never produced a
 * transcript is a measurement failure. */
static int write_profile_digests(const char *transcript, const char *digests,
                                 const char *profile_name, int applied_jobs,
                                 long load_start, long load_end, int status)
{
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

    /* The load this profile ran at, recorded in the file the verdict is
     * derived from rather than in a log nobody keeps.
     *
     * This exists because the first sweep of this tree was contaminated and
     * the contamination was invisible in the output: an unrelated `make lint`
     * ran beside the BASE_REPEAT profile, 587 s of work took 847 s, and every
     * finding in that sweep came from BASE_REPEAT — the one probe that is
     * supposed to be unstable against nothing. Without these two numbers there
     * was no way to tell that from a real result. `classify` reads them back
     * and refuses to write a baseline when the reference profiles disagree. */
    fprintf(out, "# profile=%s jobs=%d load_start=%ld load_end=%ld\n",
            profile_name, applied_jobs, load_start, load_end);

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
            "determinism_scan: %s — jobs %d, load %ld -> %ld (centi), "
            "runner status %d, %llu groups, "
            "%llu checks, %llu without a vector\n",
            profile_name, applied_jobs, load_start, load_end,
            status, (unsigned long long)stats.groups,
            (unsigned long long)stats.checks,
            (unsigned long long)stats.groups_without_vector);
    return 0;
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
    if (!profile_paths(out_dir, profile_name, transcript, sizeof(transcript),
                       digests, sizeof(digests))) {
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

    /* Load at the START of the run, before the runner's own workers land. */
    const long load_start = load_centi();
    int status = 0;
    const bool ran = run_profile_runner(runner, argv, envp, transcript, &status);
    const long load_end = ran ? load_centi() : -1;
    const int applied_jobs = plan.jobs;
    free(envp);
    plan_free(&plan);
    if (!ran) return 2;

    return write_profile_digests(transcript, digests, profile_name,
                                 applied_jobs, load_start, load_end, status);
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

/* What one profile ran at. -1 means the file recorded no load, which is not
 * the same claim as a load of zero and is never rounded to one. */
struct profile_load {
    long start;
    long end;
    int jobs;
    bool present;
};

static bool load_profile(struct table *t, size_t slot, const char *path,
                         size_t *unknown_groups, struct profile_load *load)
{
    if (load) { load->start = -1; load->end = -1; load->jobs = 0;
                load->present = false; }
    FILE *f = fopen(path, "r");
    if (!f) {
        fprintf(stderr, "determinism_scan: cannot read %s\n", path);
        return false;
    }
    char line[1024];
    while (fgets(line, sizeof(line), f)) {
        if (line[0] == '#') {
            /* The header collect() wrote. A digests file from before this
             * header existed simply has none, and its load reads as unknown
             * rather than as zero. */
            long s = -1, e = -1;
            int j = 0;
            if (load && !load->present &&
                sscanf(line, "# profile=%*s jobs=%d load_start=%ld load_end=%ld",
                       &j, &s, &e) == 3) {
                load->start = s;
                load->end = e;
                load->jobs = j;
                load->present = true;
            }
            continue;
        }
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
        /* Canonical-only: we generate this file with zcl_hex_encode, so an
         * upper-case digit means the file was hand-edited, not measured. */
        if (!zcl_hex_decode_lower(hex, cell->digest, ZCL_DET_DIGEST_LEN)) {
            fclose(f);
            fprintf(stderr, "determinism_scan: bad digest for %s in %s\n",
                    group, path);
            return false;
        }
    }
    fclose(f);
    return true;
}

/* The profile names of a --profiles= list, in measurement order. BASE must be
 * first, and at least one more profile must follow it. */
static bool parse_profile_csv(const char *profile_csv,
                              enum zcl_det_perturbation *order, size_t *n_out)
{
    char csv[512];
    size_t n = 0;
    snprintf(csv, sizeof(csv), "%s", profile_csv);
    for (char *tok = strtok(csv, ","); tok; tok = strtok(NULL, ",")) {
        if (n >= ZCL_DET_P__COUNT) {
            fprintf(stderr, "determinism_scan: too many profiles\n");
            return false;
        }
        if (!zcl_det_perturbation_from_name(tok, &order[n])) {
            fprintf(stderr, "determinism_scan: unknown profile '%s'\n", tok);
            return false;
        }
        n++;
    }
    if (n < 2) {
        fprintf(stderr, "determinism_scan: need at least BASE and one more\n");
        return false;
    }
    if (order[0] != ZCL_DET_P_BASE) {
        fprintf(stderr, "determinism_scan: BASE must be the first profile\n");
        return false;
    }
    *n_out = n;
    return true;
}

/* Loads every profile's digests file in measurement order. Stops at the first
 * file that cannot be read or parsed; the caller discards the table. */
static bool load_all_profiles(struct table *t, const char *in_dir,
                              const enum zcl_det_perturbation *order, size_t n,
                              size_t *unknown_groups, struct profile_load *loads)
{
    for (size_t i = 0; i < n; i++) {
        char path[1024];
        snprintf(path, sizeof(path), "%s/%s.digests", in_dir,
                 zcl_det_perturbation_name(order[i]));
        if (!load_profile(t, i, path, unknown_groups, &loads[i])) return false;
    }
    return true;
}

/* A profile's peak load: the higher of its start and end. A profile that
 * started quiet and ended busy was contended for part of its run. */
static long profile_peak(const struct profile_load *l)
{
    return l->start > l->end ? l->start : l->end;
}

/* ── was the box quiet? ────────────────────────────────────────────────────
 * BASE and BASE_REPEAT are the same environment run twice, so every
 * difference between them is supposed to be the tests' fault. If the
 * machine's load moved between them, that assumption is void and the
 * NONDETERMINISTIC set is not a finding — it is a measurement of the box.
 *
 * Returns false (load not comparable) when either reference profile recorded
 * no load, or when their peaks are further apart than max_load_delta. *ref_delta
 * is -1 unless both loads were compared. */
static bool check_reference_load(const struct profile_load *loads,
                                 const enum zcl_det_perturbation *order,
                                 size_t n, long max_load_delta, long *ref_delta)
{
    bool load_ok = true;
    *ref_delta = -1;
    size_t repeat_slot = 0;
    for (size_t i = 1; i < n; i++)
        if (order[i] == ZCL_DET_P_BASE_REPEAT) repeat_slot = i;
    if (repeat_slot == 0) return load_ok;

    const struct profile_load *a = &loads[0];
    const struct profile_load *b = &loads[repeat_slot];
    if (!a->present || !b->present ||
        a->start < 0 || a->end < 0 || b->start < 0 || b->end < 0) {
        fprintf(stderr,
                "determinism_scan: BASE or BASE_REPEAT recorded no load; "
                "the sweep cannot be shown to have been clean\n");
        return false;
    }
    const long pa = profile_peak(a);
    const long pb = profile_peak(b);
    *ref_delta = pa > pb ? pa - pb : pb - pa;
    if (*ref_delta > max_load_delta) load_ok = false;
    return load_ok;
}

/* ── did the scheduling contrast actually happen? ──────────────────────────
 * The load guard above asks whether the two REFERENCE profiles matched.
 * This asks the opposite question about the SCHEDULING ones, and it is a
 * separate failure that the first check cannot see.
 *
 * LOAD_HIGH exists to be the busiest profile in the sweep. If an unrelated
 * job happened to saturate the box during BASE and then finished before
 * LOAD_HIGH ran, LOAD_HIGH is the QUIETEST profile instead, and the
 * contrast the TIMING_SENSITIVE verdict rests on never occurred. Nothing
 * in the digests would look wrong: a genuinely load-sensitive group simply
 * would not split, and would be reported DETERMINISTIC. A false green, not
 * a false accusation.
 *
 * So when a SCHEDULING profile did not reach a higher load than BASE, the
 * separation is UNMEASURED and says so. NONDETERMINISTIC rows are
 * unaffected — they do not depend on the load contrast — so the baseline
 * is still written, but the run cannot be mistaken for a clean one. */
static bool check_scheduling_contrast(const struct profile_load *loads,
                                      const enum zcl_det_perturbation *order,
                                      size_t n)
{
    bool sched_ok = true;
    for (size_t i = 1; i < n; i++) {
        if (zcl_det_perturbation_class(order[i]) != ZCL_DET_PC_SCHEDULING)
            continue;
        if (!loads[0].present || !loads[i].present ||
            loads[0].start < 0 || loads[i].start < 0) {
            sched_ok = false;
            continue;
        }
        const long base_peak = profile_peak(&loads[0]);
        const long this_peak = profile_peak(&loads[i]);
        if (this_peak <= base_peak) {
            sched_ok = false;
            fprintf(stderr,
                    "determinism_scan: %s peaked at %ld.%02ld, no higher than "
                    "BASE at %ld.%02ld — the scheduling contrast did not "
                    "happen\n",
                    zcl_det_perturbation_name(order[i]),
                    this_peak / 100, this_peak % 100,
                    base_peak / 100, base_peak % 100);
        }
    }
    return sched_ok;
}

/* Counts the rows the baseline will carry, so its "# count: N" header is
 * already correct before anything is written. Both varying classes are rows.
 * Returns false when a group cannot be classified. */
static bool count_baseline_rows(struct table *t,
                                const enum zcl_det_perturbation *order,
                                size_t n, size_t *nd_total)
{
    *nd_total = 0;
    for (size_t g = 0; g < k_registry_len; g++) {
        struct zcl_det_verdict v;
        if (!zcl_det_classify(&t->cells[g * n], order, n, &v)) return false;
        if (v.klass == ZCL_DET_CLASS_NONDETERMINISTIC ||
            v.klass == ZCL_DET_CLASS_TIMING_SENSITIVE)
            (*nd_total)++;
    }
    return true;
}

/* Printed instead of a baseline when the reference loads were not comparable:
 * every row this sweep would record is UNCONFIRMED. */
static void report_refused_baseline(long ref_delta, long max_load_delta)
{
    fprintf(stderr,
            "\ndeterminism_scan: REFUSING to write a baseline.\n"
            "  BASE and BASE_REPEAT did not run at comparable load");
    if (ref_delta >= 0)
        fprintf(stderr, " (peak delta %ld.%02ld, limit %ld.%02ld)",
                ref_delta / 100, ref_delta % 100,
                max_load_delta / 100, max_load_delta % 100);
    fprintf(stderr,
            ".\n"
            "  Every row this sweep would record is UNCONFIRMED: load, not\n"
            "  the tests, is the leading explanation for any split. Re-run\n"
            "  the sweep on a quiet box, or raise --max-load-delta only if\n"
            "  you can say why the delta is harmless.\n");
}

static void write_baseline_header(FILE *bl,
                                  const enum zcl_det_perturbation *order,
                                  size_t n, const struct profile_load *loads,
                                  long ref_delta, long max_load_delta,
                                  bool sched_ok, size_t nd_total)
{
    fprintf(bl,
"# Determinism ratchet baseline — registered test groups whose verdict vector\n"
"# is NOT bitwise identical across every applied perturbation.\n"
"#\n"
"# GENERATED by 'determinism_scan classify --baseline='. One row per group:\n"
"# \"<group> <CLASS> <PERTURBATION>[+<PERTURBATION>...]\". The perturbation\n"
"# names the CAUSE. \"It varies\" is not a finding; \"it varies when CC is\n"
"# set\" is.\n"
"#\n"
"# CLASS is NONDETERMINISTIC or TIMING_SENSITIVE, and the difference decides\n"
"# what to do about the row:\n"
"#\n"
"#   NONDETERMINISTIC  the vector moved on a plain re-run at identical load,\n"
"#                     or moved with the environment. The test's own logic\n"
"#                     does not settle on one answer. Fix the logic.\n"
"#   TIMING_SENSITIVE  the vector moved ONLY when the machine's load moved.\n"
"#                     The logic is settled and the grading rule is a wall\n"
"#                     clock. Replace the grading rule.\n"
"#\n"
"# The second is the one that manufactures false accusations: an honest node\n"
"# re-running such a group on a busier box computes a different vector and\n"
"# REFUTES a receipt that was never wrong. Neither class may carry a receipt.\n"
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
    /* The load each profile ran at, carried INTO the record. A later
     * reader has no other way to tell a finding from a busy box, and the
     * first sweep of this tree was contaminated in exactly that way. */
    fprintf(bl, "\n#\n# load per profile (1-min average, hundredths, "
                "start -> end):\n");
    for (size_t i = 0; i < n; i++) {
        if (loads[i].present)
            fprintf(bl, "#   %-12s jobs=%-3d %ld -> %ld\n",
                    zcl_det_perturbation_name(order[i]), loads[i].jobs,
                    loads[i].start, loads[i].end);
        else
            fprintf(bl, "#   %-12s (no load recorded)\n",
                    zcl_det_perturbation_name(order[i]));
    }
    if (ref_delta >= 0)
        fprintf(bl, "#   BASE vs BASE_REPEAT peak delta: %ld.%02ld "
                    "(limit %ld.%02ld)\n",
                ref_delta / 100, ref_delta % 100,
                max_load_delta / 100, max_load_delta % 100);
    if (!sched_ok)
        fprintf(bl,
"#\n"
"# WARNING — THE SCHEDULING CONTRAST DID NOT HAPPEN IN THIS SWEEP.\n"
"# A SCHEDULING profile did not reach a higher load than BASE, so load\n"
"# sensitivity was never actually tested. There may be TIMING_SENSITIVE\n"
"# groups missing from this file, and a group absent from it has NOT been\n"
"# shown to be load-insensitive. Re-measure before trusting the absence of\n"
"# a row here as evidence of anything.\n");
    fprintf(bl, "#\n# count: %zu\n", nd_total);
}

static void print_scan_header(const enum zcl_det_perturbation *order, size_t n,
                              const struct profile_load *loads, long ref_delta,
                              long max_load_delta, bool load_ok, bool sched_ok)
{
    printf("determinism scan — %zu registered groups, %zu perturbations\n",
           k_registry_len, n);
    for (size_t i = 0; i < n; i++) {
        if (loads[i].present)
            printf("  profile %zu: %-12s jobs=%-3d load %ld -> %ld\n", i,
                   zcl_det_perturbation_name(order[i]), loads[i].jobs,
                   loads[i].start, loads[i].end);
        else
            printf("  profile %zu: %-12s (no load recorded)\n", i,
                   zcl_det_perturbation_name(order[i]));
    }
    if (ref_delta >= 0)
        printf("  BASE vs BASE_REPEAT peak load delta: %ld.%02ld "
               "(limit %ld.%02ld) — %s\n",
               ref_delta / 100, ref_delta % 100,
               max_load_delta / 100, max_load_delta % 100,
               load_ok ? "comparable" : "NOT COMPARABLE, results UNCONFIRMED");
    if (!sched_ok)
        printf("\n  WARNING: a SCHEDULING profile did not reach a higher load\n"
               "  than BASE, so this sweep did not test load sensitivity at\n"
               "  all. A group reading DETERMINISTIC below has NOT been shown\n"
               "  to be insensitive to load — it was simply never loaded.\n");
}

/* One verdict row: the group, its split cause, and (when bl is set) the same
 * row in the baseline. label is the class name the baseline records. */
static void print_split_row(FILE *bl, const char *group, const char *label,
                            const struct zcl_det_verdict *v,
                            const enum zcl_det_perturbation *order, size_t n)
{
    /* Translate slot positions into perturbation names — through the
     * library, with THIS run's profile order, so the report and the
     * baseline can never disagree about what split a group. */
    char cause[512];
    zcl_det_split_mask_string(v->split_mask, order, n, cause, sizeof(cause));
    printf("  %-56s %s\n", group, cause);
    if (bl) fprintf(bl, "%s %s %s\n", group, label, cause);
}

/* Every group is folded into the partition here, and each NONDETERMINISTIC
 * group is printed with its cause. Returns false when a group cannot be
 * classified. */
static bool report_nondeterministic(struct table *t,
                                    const enum zcl_det_perturbation *order,
                                    size_t n, FILE *bl, const char *tag,
                                    struct zcl_det_partition *part)
{
    printf("\nNONDETERMINISTIC — the vector moved on a re-run or with the "
           "environment%s:\n", tag);
    size_t nd_count = 0;
    for (size_t g = 0; g < k_registry_len; g++) {
        struct zcl_det_verdict v;
        if (!zcl_det_classify(&t->cells[g * n], order, n, &v)) return false;
        zcl_det_partition_add(part, &v);
        if (v.klass != ZCL_DET_CLASS_NONDETERMINISTIC) continue;
        print_split_row(bl, k_registry[g], "NONDETERMINISTIC", &v, order, n);
        nd_count++;
    }
    if (nd_count == 0) printf("  (none)\n");
    return true;
}

/* Its own section, never folded into the one above. A group here has settled
 * logic and a grading rule that reads a clock; re-running it on a busier box
 * refutes a receipt that was never wrong. */
static void report_timing_sensitive(struct table *t,
                                    const enum zcl_det_perturbation *order,
                                    size_t n, FILE *bl, const char *tag,
                                    const char *sched_tag)
{
    printf("\nTIMING_SENSITIVE — the vector moved ONLY when load moved%s%s:\n",
           tag, sched_tag);
    size_t ts_count = 0;
    for (size_t g = 0; g < k_registry_len; g++) {
        struct zcl_det_verdict v;
        if (!zcl_det_classify(&t->cells[g * n], order, n, &v)) continue;
        if (v.klass != ZCL_DET_CLASS_TIMING_SENSITIVE) continue;
        print_split_row(bl, k_registry[g], "TIMING_SENSITIVE", &v, order, n);
        ts_count++;
    }
    if (ts_count == 0) printf("  (none)\n");
}

static void report_unknown(struct table *t,
                           const enum zcl_det_perturbation *order, size_t n)
{
    printf("\nUNKNOWN (could not be measured — never folded into any "
           "other bucket):\n");
    for (size_t g = 0; g < k_registry_len; g++) {
        struct zcl_det_verdict v;
        if (!zcl_det_classify(&t->cells[g * n], order, n, &v)) continue;
        if (v.klass != ZCL_DET_CLASS_UNKNOWN) continue;
        printf("  %-56s %s\n", k_registry[g],
               zcl_det_unknown_reason_name(v.reason));
    }
}

/* The three verdict sections, in the order they print. Returns false when the
 * NONDETERMINISTIC pass cannot classify a group; nothing after it is printed. */
static bool report_verdicts(struct table *t,
                            const enum zcl_det_perturbation *order, size_t n,
                            FILE *bl, bool load_ok, bool sched_ok,
                            struct zcl_det_partition *part)
{
    const char *tag = load_ok ? "" : " [UNCONFIRMED — load not comparable]";
    const char *sched_tag =
        sched_ok ? "" : " [UNMEASURED — the scheduling contrast did not happen]";

    if (!report_nondeterministic(t, order, n, bl, tag, part)) return false;
    report_timing_sensitive(t, order, n, bl, tag, sched_tag);
    report_unknown(t, order, n);
    return true;
}

static void print_partition(const struct zcl_det_partition *part,
                            size_t unknown_groups)
{
    printf("\nPARTITION over %zu registered groups\n", part->total);
    printf("  DETERMINISTIC      %6zu\n", part->deterministic);
    printf("  NONDETERMINISTIC   %6zu\n", part->nondeterministic);
    printf("  TIMING_SENSITIVE   %6zu\n", part->timing_sensitive);
    printf("  UNKNOWN/not-run    %6zu\n", part->unknown_not_run);
    printf("  UNKNOWN/no-vector  %6zu\n", part->unknown_no_vector);
    printf("  UNKNOWN/partial    %6zu\n", part->unknown_partial);
    printf("  ---------------------------\n");
    printf("  sum                %6zu  %s\n",
           part->deterministic + part->nondeterministic +
               part->timing_sensitive + part->unknown_not_run +
               part->unknown_no_vector + part->unknown_partial,
           zcl_det_partition_is_exact(part) ? "(exact)" : "(NOT EXACT)");
    if (unknown_groups)
        printf("  note: %zu transcript group(s) were not in the registry\n",
               unknown_groups);

    /* The ceiling, printed with every result rather than left in a header
     * nobody opens. DETERMINISTIC here is necessary for a receipt and is not
     * sufficient for one. */
    printf("\nThis is a LOWER BOUND. A group whose hidden input none of these\n"
           "perturbations moves reads DETERMINISTIC and is not thereby\n"
           "deterministic, and a test that is wrong the same way every time\n"
           "has a perfectly stable vector. What the SCHEDULING perturbations\n"
           "measure is a small worker pool against a large one on an otherwise\n"
           "quiet box — not arbitrary contention — so a group can read\n"
           "DETERMINISTIC here and still refute a receipt on a loaded node.\n");
}

/* The exit code for a finished classify: a contaminated sweep is not a result,
 * even when the partition is exact, and neither is one whose scheduling
 * contrast never happened. */
static int classify_exit_code(bool load_ok, bool sched_ok, bool exact)
{
    if (!load_ok) return 4;
    if (!sched_ok) return 5;
    return exact ? 0 : 1;
}

static int run_classify(const char *in_dir, const char *profile_csv,
                        const char *baseline_path, long max_load_delta)
{
    enum zcl_det_perturbation order[ZCL_DET_P__COUNT];
    size_t n = 0;
    if (!parse_profile_csv(profile_csv, order, &n)) return 2;

    struct table t = { .cells = NULL, .n_profiles = n };
    t.cells = calloc(k_registry_len * n, sizeof(*t.cells)); // raw-alloc-ok:build-tool
    if (!t.cells) {
        fprintf(stderr, "determinism_scan: out of memory\n");
        return 2;
    }

    size_t unknown_groups = 0;
    struct profile_load loads[ZCL_DET_P__COUNT];
    if (!load_all_profiles(&t, in_dir, order, n, &unknown_groups, loads)) {
        free(t.cells);
        return 2;
    }

    long ref_delta = -1;
    bool load_ok = check_reference_load(loads, order, n, max_load_delta,
                                        &ref_delta);
    bool sched_ok = check_scheduling_contrast(loads, order, n);

    /* Pass one: count the rows the baseline will carry. */
    size_t nd_total = 0;
    if (!count_baseline_rows(&t, order, n, &nd_total)) {
        free(t.cells);
        return 2;
    }

    if (!load_ok) {
        report_refused_baseline(ref_delta, max_load_delta);
        baseline_path = NULL;
    }

    FILE *bl = NULL;
    if (baseline_path) {
        bl = fopen(baseline_path, "w");
        if (!bl) {
            fprintf(stderr, "determinism_scan: cannot write %s\n", baseline_path);
            free(t.cells);
            return 2;
        }
        write_baseline_header(bl, order, n, loads, ref_delta, max_load_delta,
                              sched_ok, nd_total);
    }

    print_scan_header(order, n, loads, ref_delta, max_load_delta, load_ok,
                      sched_ok);

    struct zcl_det_partition part = {0};
    if (!report_verdicts(&t, order, n, bl, load_ok, sched_ok, &part)) {
        free(t.cells);
        if (bl) fclose(bl);
        return 2;
    }
    print_partition(&part, unknown_groups);

    bool exact = zcl_det_partition_is_exact(&part);
    if (bl && fclose(bl) != 0) exact = false;
    free(t.cells);
    return classify_exit_code(load_ok, sched_ok, exact);
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
/* Fills r with the one fixed receipt the golden vector encodes. */
static bool golden_receipt_fill(struct zcl_det_receipt *r)
{
    r->version = ZCL_DET_RECEIPT_VERSION;
    if (!zcl_det_receipt_set_commit(
            r, "0123456789abcdef0123456789abcdef01234567"))
        return false;
    snprintf(r->group, sizeof(r->group), "test_determinism");
    zcl_det_receipt_label_digest("gcc-13.3.0/glibc-2.39/x86_64", r->toolchain);
    zcl_det_receipt_label_digest("gate:ZCL_STRESS_TESTS=0,jobs=8", r->env_class);
    r->verdict = ZCL_DET_CLASS_NONDETERMINISTIC;
    r->reason = ZCL_DET_UNKNOWN_NONE;
    r->perturbations = 8;
    r->split_mask = (1u << ZCL_DET_P_CC_SET) | (1u << ZCL_DET_P_ENV_PAD);
    r->check_count = 41;
    for (size_t i = 0; i < ZCL_DET_DIGEST_LEN; i++) {
        r->vector[i] = (uint8_t)(i * 7u + 3u);
        r->producer[i] = (uint8_t)(0xA0u ^ i);
    }
    return true;
}

/* True when every field the encoder is required to carry survived the round
 * trip. Pure comparison; the caller decides what a mismatch means. */
static bool receipt_matches(const struct zcl_det_receipt *back,
                            const struct zcl_det_receipt *r)
{
    return memcmp(&back->commit, &r->commit, sizeof(r->commit)) == 0 &&
           strcmp(back->group, r->group) == 0 &&
           back->version == r->version &&
           back->verdict == r->verdict &&
           back->reason == r->reason &&
           back->perturbations == r->perturbations &&
           back->split_mask == r->split_mask &&
           back->check_count == r->check_count &&
           memcmp(back->vector, r->vector, sizeof(r->vector)) == 0 &&
           memcmp(back->producer, r->producer, sizeof(r->producer)) == 0 &&
           memcmp(back->toolchain, r->toolchain, sizeof(r->toolchain)) == 0 &&
           memcmp(back->env_class, r->env_class, sizeof(r->env_class)) == 0;
}

static int run_receipt_golden(void)
{
    struct zcl_det_receipt r;
    memset(&r, 0, sizeof(r));
    if (!golden_receipt_fill(&r)) return 2;

    uint8_t bytes[ZCL_DET_RECEIPT_SIZE];
    size_t len = 0;
    if (!zcl_det_receipt_encode(&r, bytes, sizeof(bytes), &len)) return 2;
    for (size_t i = 0; i < len; i++) printf("%02x", bytes[i]);
    printf("\n");

    /* Round-trip in the same breath: an encoding nobody can read back is not
     * an encoding. */
    struct zcl_det_receipt back;
    if (!zcl_det_receipt_decode(bytes, len, &back)) return 2;
    if (!receipt_matches(&back, &r)) {
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
        "                           [--baseline=FILE] [--max-load-delta=N]\n"
        "        --max-load-delta is in hundredths of a load average "
        "(default 200 = 2.00).\n"
        "        If BASE and BASE_REPEAT ran at loads further apart than that,\n"
        "        no baseline is written and the results are UNCONFIRMED.\n"
        "  determinism_scan list-profiles\n"
        "  determinism_scan receipt-golden\n");
}

/* The options a command line may carry, with the defaults this tool has always
 * used. parse_option() sets them; one command reads each. */
struct scan_opts {
    const char *profile;
    const char *dir;
    const char *runner;
    const char *profiles;
    const char *baseline;
    const char *alt_tmp;
    const char *transcript_in;
    int jobs;
    long max_load_delta;
};

/* Reads one --name=value argument into o. Returns false for an argument this
 * tool does not know; the caller answers that with usage. */
static bool parse_option(struct scan_opts *o, const char *arg)
{
    if (strncmp(arg, "--profile=", 10) == 0)       o->profile = arg + 10;
    else if (strncmp(arg, "--transcript=", 13) == 0)
        o->transcript_in = arg + 13;
    else if (strncmp(arg, "--out=", 6) == 0)       o->dir = arg + 6;
    else if (strncmp(arg, "--in=", 5) == 0)        o->dir = arg + 5;
    else if (strncmp(arg, "--runner=", 9) == 0)    o->runner = arg + 9;
    else if (strncmp(arg, "--profiles=", 11) == 0) o->profiles = arg + 11;
    else if (strncmp(arg, "--baseline=", 11) == 0) o->baseline = arg + 11;
    else if (strncmp(arg, "--alt-tmp=", 10) == 0)  o->alt_tmp = arg + 10;
    else if (strncmp(arg, "--jobs=", 7) == 0)      o->jobs = atoi(arg + 7);
    else if (strncmp(arg, "--max-load-delta=", 17) == 0)
        o->max_load_delta = atol(arg + 17);
    else return false;
    return true;
}

static int run_parse_opts(const struct scan_opts *o)
{
    if (!o->transcript_in || !o->profile || !o->dir) { usage(); return 2; }
    char digests[1024];
    if (!digests_path(o->dir, o->profile, digests, sizeof(digests))) {
        fprintf(stderr, "determinism_scan: output path too long\n");
        return 2;
    }
    return run_parse(o->transcript_in, digests);
}

static int run_list_profiles(void)
{
    for (int i = 0; i < ZCL_DET_P__COUNT; i++)
        printf("%-14s %s\n",
               zcl_det_perturbation_name((enum zcl_det_perturbation)i),
               zcl_det_perturbation_why((enum zcl_det_perturbation)i));
    return 0;
}

static int dispatch_command(const char *cmd, const struct scan_opts *o)
{
    if (strcmp(cmd, "collect") == 0) {
        if (!o->profile || !o->dir) { usage(); return 2; }
        return run_collect(o->profile, o->dir, o->runner, o->jobs, o->alt_tmp);
    }
    if (strcmp(cmd, "parse") == 0) return run_parse_opts(o);
    if (strcmp(cmd, "classify") == 0) {
        if (!o->dir || !o->profiles) { usage(); return 2; }
        return run_classify(o->dir, o->profiles, o->baseline,
                            o->max_load_delta);
    }
    usage();
    return 2;
}

int main(int argc, char **argv)
{
    if (argc < 2) { usage(); return 2; }

    if (strcmp(argv[1], "receipt-golden") == 0) return run_receipt_golden();
    if (strcmp(argv[1], "list-profiles") == 0) return run_list_profiles();

    struct scan_opts o = {
        .runner = "build/bin/test_parallel",
        .alt_tmp = "/tmp",
        .jobs = 8,
        /* Peak 1-minute load, in hundredths, that BASE and BASE_REPEAT may
         * differ by before the sweep is treated as contaminated. 2.00 is
         * roughly one busy core plus slack — about the smallest delta that
         * could plausibly move a wall-clock assertion. */
        .max_load_delta = 200,
    };
    for (int i = 2; i < argc; i++) {
        if (!parse_option(&o, argv[i])) { usage(); return 2; }
    }
    return dispatch_command(argv[1], &o);
}
