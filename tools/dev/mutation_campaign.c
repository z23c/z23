/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * mutation-campaign — measure whether a registered test group would NOTICE
 * if the code it covers were wrong.
 *
 *   build/bin/mutation-campaign --file=contexts/commons/modules/metaverse/src/node_character.c \
 *                               --group=test_node_character
 *
 * It enumerates every realistic one-token defect in the file, compiles each
 * one, runs ONLY that group, and prints the fraction the group killed —
 * followed by the survivors, which are the actual product: each survivor is
 * a specific line the group's assertions cannot see.
 *
 * THIS IS A REPORTING TOOL. It is not on the default test path and not in
 * the push gate, and it must not become a threshold anybody has to clear
 * before a mutation score exists for the tree it would judge.
 *
 * It never edits the checkout. The mutant is compiled from a scratch copy
 * carrying a `#line` back to the real path, so there is no restore step to
 * get wrong: interrupt it at any moment and the source file is byte-identical
 * because it was never opened for writing. The report prints the file's
 * digest before and after so the reader does not have to take that on faith.
 */

#include "mutation_harness.h"

#include "base/hex.h"
#include "base/safe_alloc.h"
#include "command/native_devagent.h"
#include "platform/clock.h"
#include "util/supervised_retirement.h"
#include "util/thread_registry.h"

#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#if defined(ZCL_TESTING) && defined(__linux__)
#include "platform/supervised_process.h"
#include <fcntl.h>
#include <poll.h>
#include <sys/file.h>
#include <unistd.h>
#endif

struct mc_opts {
    const char *file;
    const char *group;
    const char *target;
    const char *work;
    const char *report;
    size_t limit;
    bool list;
    bool no_cache;
    bool quiet;
    int build_timeout_ms;
    int test_timeout_ms;
#if defined(ZCL_TESTING) && defined(__linux__)
    bool fixture_cleanup;
#endif
};

static void mc_usage(FILE *f)
{
    fprintf(f,
            "usage: mutation-campaign --file=REL.c --group=TEST_GROUP [options]\n"
            "       mutation-campaign --file=REL.c --list\n"
            "\n"
            "  --file=REL       checkout-relative C source to mutate\n"
            "  --group=NAME     registered test group to run per mutant\n"
            "  --target=NAME    make target that builds the runner\n"
            "                   (default: test_parallel)\n"
            "  --work=DIR       scratch directory (default: build/mutation-campaign)\n"
            "  --limit=N        stop after N mutants (0 = full campaign)\n"
            "  --report=PATH    also write a machine-readable report\n"
            "  --list           enumerate mutants and exit; builds nothing\n"
            "  --no-cache       ignore and do not write the per-mutant cache\n"
            "  --quiet          only the summary and the survivors\n"
            "  --build-timeout=SEC   default 900; 0 = runner fallback\n"
            "  --test-timeout=SEC    default 300; 0 = runner fallback\n"
            "  Numeric values are unsigned decimal integers; timeouts must\n"
            "  fit in int milliseconds.\n");
}

static bool mc_prefix(const char *arg, const char *key, const char **val)
{
    size_t n = strlen(key);
    if (strncmp(arg, key, n) != 0)
        return false;
    *val = arg + n;
    return true;
}

static bool mc_unsigned(const char *text, size_t maximum, size_t *out)
{
    if (!*text)
        return false;
    size_t value = 0;
    for (const char *digit = text; *digit; digit++) {
        if (*digit < '0' || *digit > '9')
            return false;
        size_t next = (size_t)(*digit - '0');
        if (value > maximum / 10 ||
            (value == maximum / 10 && next > maximum % 10))
            return false;
        value = value * 10 + next;
    }
    *out = value;
    return true;
}

static bool mc_timeout(const char *text, int *milliseconds)
{
    size_t seconds;
    if (!mc_unsigned(text, INT_MAX / 1000, &seconds))
        return false;
    *milliseconds = (int)seconds * 1000;
    return true;
}

/* Recognise one `--key=value` argument and store its value in o, trying the
 * keys in the same order mc_parse always has. Returns false when a is not a
 * value option, so the caller can try the flag and help forms. */
static bool mc_parse_value_option(const char *a, struct mc_opts *o)
{
    const char *v = NULL;
    if (mc_prefix(a, "--file=", &v))
        o->file = v;
    else if (mc_prefix(a, "--group=", &v))
        o->group = v;
    else if (mc_prefix(a, "--target=", &v))
        o->target = v;
    else if (mc_prefix(a, "--work=", &v))
        o->work = v;
    else if (mc_prefix(a, "--report=", &v))
        o->report = v;
    else if (mc_prefix(a, "--limit=", &v))
        return mc_unsigned(v, SIZE_MAX, &o->limit);
    else if (mc_prefix(a, "--build-timeout=", &v))
        return mc_timeout(v, &o->build_timeout_ms);
    else if (mc_prefix(a, "--test-timeout=", &v))
        return mc_timeout(v, &o->test_timeout_ms);
    else
        return false;
    return true;
}

/* Recognise one valueless flag argument and set it in o. Returns false when
 * a is not one of the flags, so the caller can try -h/--help. */
static bool mc_parse_flag_option(const char *a, struct mc_opts *o)
{
#if defined(ZCL_TESTING) && defined(__linux__)
    if (strcmp(a, "--_fixture-cleanup-refusal") == 0) {
        o->fixture_cleanup = true;
        return true;
    }
#endif
    if (strcmp(a, "--list") == 0)
        o->list = true;
    else if (strcmp(a, "--no-cache") == 0)
        o->no_cache = true;
    else if (strcmp(a, "--quiet") == 0)
        o->quiet = true;
    else
        return false;
    return true;
}

static bool mc_parse(int argc, char **argv, struct mc_opts *o)
{
    memset(o, 0, sizeof *o);
    o->target = "test_parallel";
    o->work = "build/mutation-campaign";
    o->build_timeout_ms = 900000;
    o->test_timeout_ms = 300000;
    for (int i = 1; i < argc; i++) {
        const char *a = argv[i];
        if (mc_parse_value_option(a, o))
            continue;
        if (mc_parse_flag_option(a, o))
            continue;
        if (strcmp(a, "-h") == 0 || strcmp(a, "--help") == 0) {
            mc_usage(stdout);
            exit(0);
        }
        fprintf(stderr, "mutation-campaign: unknown argument: %s\n", a);
        return false;
    }
    if (!o->file) {
        fprintf(stderr, "mutation-campaign: --file is required\n");
        return false;
    }
    if (!o->list && !o->group) {
        fprintf(stderr, "mutation-campaign: --group is required unless "
                        "--list\n");
        return false;
    }
    /* The campaign writes only under --work and reads only the named file.
     * An absolute path or a `..` would put both outside the checkout the
     * root resolution just proved, so it is refused rather than normalised. */
    if (o->file[0] == '/' || strstr(o->file, "..") != NULL) {
        fprintf(stderr, "mutation-campaign: --file must be checkout-relative "
                        "with no '..'\n");
        return false;
    }
    return true;
}

/* ── listing ─────────────────────────────────────────────────────────── */

static int mc_list(const char *root, const char *rel)
{
    char abs[PATH_MAX];
    if (snprintf(abs, sizeof abs, "%s/%s", root, rel) >= (int)sizeof abs) {
        fprintf(stderr, "mutation-campaign: path too long\n");
        return 2;
    }
    size_t len = 0;
    char *text = zcl_mut_read_file(abs, &len);
    if (!text) {
        fprintf(stderr, "mutation-campaign: cannot read %s\n", abs);
        return 2;
    }
    size_t total = zcl_mut_enumerate(text, len, NULL, 0);
    struct zcl_mut_site *sites = total
        ? zcl_calloc(total, sizeof *sites, "mutation.list")
        : NULL;
    if (total && !sites) {
        free(text);
        return 2;
    }
    if (total)
        (void)zcl_mut_enumerate(text, len, sites, total);
    size_t per_class[ZCL_MUT_CLASS_COUNT] = { 0 };
    for (size_t i = 0; i < total; i++) {
        per_class[sites[i].cls]++;
        printf("%s:%zu:%zu  %-14s %-10s  %s -> %s\n", rel, sites[i].line,
               sites[i].column, sites[i].rule,
               zcl_mut_class_name(sites[i].cls), sites[i].before,
               sites[i].after[0] ? sites[i].after : "(deleted)");
    }
    printf("\n%zu mutation sites in %s\n", total, rel);
    for (int i = 0; i < ZCL_MUT_CLASS_COUNT; i++)
        printf("  %-12s %zu\n", zcl_mut_class_name((enum zcl_mut_class)i),
               per_class[i]);
    free(sites);
    free(text);
    return 0;
}

/* ── build plan ─────────────────────────────────────────────────────── */

/* `make -n -W SRC TARGET` asks make what it WOULD do if SRC had just been
 * edited, without editing it and without building anything. Everything the
 * campaign needs — the exact compiler, the exact flags, the object path and
 * the link response file — comes from that one transcript, so this harness
 * can never disagree with the real build about how the file is compiled. */
static bool mc_plan(struct zcl_mut_owner *owner, const char *root, const char *rel, const char *target,
                    struct zcl_mut_plan *plan, bool quiet)
{
    char *argv[10];
    int n = 0;
    argv[n++] = (char *)"tools/dev/checkout-lock.sh";
    argv[n++] = (char *)"foreground";
    argv[n++] = (char *)"build/.checkout.lock";
    argv[n++] = (char *)"--";
    argv[n++] = (char *)"make";
    argv[n++] = (char *)"-n";
    argv[n++] = (char *)"-W";
    argv[n++] = (char *)rel;
    argv[n++] = (char *)target;
    argv[n] = NULL;

    if (!quiet)
        fprintf(stderr, "== deriving the build plan (make -n -W %s %s)\n", rel,
                target);
    char *text = NULL;
    size_t len = 0;
    int rc = zcl_mut_spawn_owned(owner, root, argv, 600000, &text, &len);
    if (rc != 0) {
        fprintf(stderr,
                "mutation-campaign: `make -n -W %s %s` exited %d; the build "
                "plan cannot be derived\n",
                rel, target, rc);
        if (text && len)
            fprintf(stderr, "%.*s\n", (int)(len > 2000 ? 2000 : len), text);
        free(text);
        return false;
    }
    char err[256];
    bool ok = zcl_mut_plan_from_dryrun(text, rel, plan, err, sizeof err);
    free(text);
    if (!ok)
        fprintf(stderr, "mutation-campaign: %s\n", err);
    return ok;
}

/* ── reporting ──────────────────────────────────────────────────────── */

/* The tree has one hex encoder; a report is not a reason for a second. */
static void mc_hex(const unsigned char d[32], char *hex)
{
    zcl_hex_encode(d, 32, hex);
}

static void mc_print(const struct mc_opts *o, const struct zcl_mut_report *r)
{
    int score = zcl_mut_score_tenths(r);
    printf("\n══ mutation score: %s covering %s ══\n", o->group, o->file);
    printf("  sites enumerated  %zu\n", r->total_sites);
    printf("  mutants run       %zu\n", r->result_count);
    printf("  KILLED            %zu\n", r->counts[ZCL_MUT_OUTCOME_KILLED]);
    printf("  SURVIVED          %zu\n", r->counts[ZCL_MUT_OUTCOME_SURVIVED]);
    printf("  STILLBORN         %zu   (rejected by -Werror, excluded)\n",
           r->counts[ZCL_MUT_OUTCOME_STILLBORN]);
    printf("  EQUIVALENT        %zu   (byte-identical object, excluded)\n",
           r->counts[ZCL_MUT_OUTCOME_EQUIVALENT]);
    printf("  ERROR             %zu   (no usable verdict, excluded)\n",
           r->counts[ZCL_MUT_OUTCOME_ERROR]);
    if (score < 0)
        printf("  MUTATION SCORE    n/a   (nothing scorable)\n");
    else
        printf("  MUTATION SCORE    %d.%d%%   (killed / (killed + survived))\n",
               score / 10, score % 10);
    printf("  wall clock        %lld.%03llds  (%lld ms/mutant)\n",
           r->wall_ms / 1000, r->wall_ms % 1000,
           r->result_count ? r->wall_ms / (long long)r->result_count : 0);

    char before[65], after[65];
    mc_hex(r->source_digest_before, before);
    mc_hex(r->source_digest_after, after);
    printf("  source sha3-256   %s (before)\n", before);
    printf("                    %s (after)\n", after);
    printf("  source unchanged  %s\n", r->source_unchanged ? "yes" : "NO");
    if (r->aborted)
        printf("  stopped early     yes (--limit)\n");

    if (r->counts[ZCL_MUT_OUTCOME_SURVIVED] == 0) {
        printf("\nNo survivors.\n");
        return;
    }
    printf("\n── SURVIVORS: %zu holes in %s ──\n",
           r->counts[ZCL_MUT_OUTCOME_SURVIVED], o->group);
    printf("Each line is a change the group did not notice.\n\n");
    for (size_t i = 0; i < r->result_count; i++) {
        const struct zcl_mut_result *x = &r->results[i];
        if (x->outcome != ZCL_MUT_OUTCOME_SURVIVED)
            continue;
        printf("  %s:%zu:%zu  %-14s  %s -> %s\n", o->file, x->site.line,
               x->site.column, x->site.rule, x->site.before,
               x->site.after[0] ? x->site.after : "(deleted)");
    }
    if (r->counts[ZCL_MUT_OUTCOME_EQUIVALENT]) {
        printf("\n── EQUIVALENT (proved: identical object code) ──\n");
        for (size_t i = 0; i < r->result_count; i++) {
            const struct zcl_mut_result *x = &r->results[i];
            if (x->outcome != ZCL_MUT_OUTCOME_EQUIVALENT)
                continue;
            printf("  %s:%zu:%zu  %-14s  %s -> %s\n", o->file, x->site.line,
                   x->site.column, x->site.rule, x->site.before,
                   x->site.after[0] ? x->site.after : "(deleted)");
        }
    }
}

static bool mc_write_report(const struct mc_opts *o,
                            const struct zcl_mut_report *r)
{
    FILE *f = fopen(o->report, "w");
    if (!f) {
        fprintf(stderr, "mutation-campaign: cannot write %s\n", o->report);
        return false;
    }
    char before[65], after[65];
    mc_hex(r->source_digest_before, before);
    mc_hex(r->source_digest_after, after);
    fprintf(f, "schema=zcl.mutation_campaign.v1\n");
    fprintf(f, "file=%s\ngroup=%s\n", o->file, o->group);
    fprintf(f, "sites=%zu\nran=%zu\n", r->total_sites, r->result_count);
    for (int i = 0; i < ZCL_MUT_OUTCOME_COUNT; i++)
        fprintf(f, "%s=%zu\n", zcl_mut_outcome_name((enum zcl_mut_outcome)i),
                r->counts[i]);
    fprintf(f, "score_tenths=%d\n", zcl_mut_score_tenths(r));
    fprintf(f, "wall_ms=%lld\n", r->wall_ms);
    fprintf(f, "source_sha3_before=%s\nsource_sha3_after=%s\n", before, after);
    fprintf(f, "source_unchanged=%s\n", r->source_unchanged ? "1" : "0");
    for (size_t i = 0; i < r->result_count; i++) {
        const struct zcl_mut_result *x = &r->results[i];
        fprintf(f, "mutant %s %zu %zu %s %s %s %lld\n",
                zcl_mut_outcome_name(x->outcome), x->site.line, x->site.column,
                x->site.rule, zcl_mut_class_name(x->site.cls),
                x->killed_by && x->killed_by[0] ? x->killed_by : "-", x->ms);
    }
    bool ok = fclose(f) == 0;
    if (!ok)
        fprintf(stderr, "mutation-campaign: short write to %s\n", o->report);
    return ok;
}

static bool mc_campaign(const struct mc_opts *o, const char *root,
    struct zcl_mut_owner *owner, struct zcl_mut_report *report)
{
    struct zcl_mut_plan plan;
    if (!mc_plan(owner, root, o->file, o->target, &plan, o->quiet))
        return false;

    struct zcl_mut_config cfg = {
        .owner = owner,
        .root = root,
        .src_rel = o->file,
        .group = o->group,
        .work_dir = o->work,
        .runner_arg_fmt = "--exact=%s",
        .build_timeout_ms = o->build_timeout_ms,
        .test_timeout_ms = o->test_timeout_ms,
        .use_cache = !o->no_cache,
        .verbose = !o->quiet,
        .abort_after = o->limit,
    };
    char work_abs[PATH_MAX];
    if (o->work[0] != '/') {
        if (snprintf(work_abs, sizeof work_abs, "%s/%s", root, o->work) >=
            (int)sizeof work_abs) {
            fprintf(stderr, "mutation-campaign: --work path too long\n");
            zcl_mut_plan_free(&plan);
            return false;
        }
        cfg.work_dir = work_abs;
    }

    bool ok = zcl_mut_campaign_run(&cfg, &plan, report);
    zcl_mut_plan_free(&plan);
    return ok;
}

/* Standalone owns this explicit lifecycle. Embedded calls only borrow it.
 * Never join a worker until bounded drain has observed STOPPED. */
static bool mc_finish_owner(struct zcl_mut_owner *owner)
{
#if defined(__linux__)
    bool closed = zcl_mut_owner_close(owner);
    zcl_supervised_retirement_request_stop();
    if (!closed) closed = zcl_mut_owner_close(owner); /* reserved late transfer */
    bool drained = zcl_supervised_retirement_drain(clock_now_monotonic_ns() + 1000000000);
    bool joined = drained && thread_registry_join_all(1) == 0;
    if (!closed || !joined)
        fprintf(stderr, "mutation-campaign: cleanup pending, orderly join unconfirmed; no score\n");
    return closed && joined;
#else
    (void)owner;
    return false;
#endif
}

#if defined(ZCL_TESTING) && defined(__linux__)
static char mc_destructor_path[PATH_MAX];
static int mc_fixture_compiler(int argc, char **argv)
{
    if (argc != ZCL_MUT_ARGV_MAX) return 126;
    for (unsigned i = 0; i < 65; ++i) {
        char key[40], expected[80];
        (void)snprintf(key, sizeof(key), "Z23_MUT_ENV_%u", i);
        (void)snprintf(expected, sizeof(expected), "%u a b utf8-\xc3\xa9", i);
        const char *value = getenv(key);
        if (!value || strcmp(value, expected)) return 126;
    }
    const char *path = getenv("Z23_MUT_ENDPOINT_LOG");
    FILE *log = path ? fopen(path, "ab") : NULL;
    if (!log) return 126;
    bool recorded = fprintf(log, "%s argv=%d env65=1\n", argv[2], argc) > 0;
    if (fclose(log) != 0 || !recorded) return 126;
    execvp(argv[3], argv + 3);
    return 127;
}
static void mc_fixture_destructor(void)
{
    FILE *file = fopen(mc_destructor_path, "wb");
    if (file) { (void)fputs("ordinary teardown\n", file); (void)fclose(file); }
}

static bool mc_fixture_atexit(const char *work)
{
    int n = snprintf(mc_destructor_path, sizeof(mc_destructor_path), "%s/destructor", work);
    return n > 0 && (size_t)n < sizeof(mc_destructor_path) && atexit(mc_fixture_destructor) == 0;
}

/* Actual escaped descendant with a kernel-owned lock, not a canned outcome.
 * This mode exists only in the private test build of this maintained source. */
static void mc_fixture_escape_child(const char *work, int ready[2])
{
    (void)close(ready[0]);
    if (setsid() < 0) _exit(126);
    pid_t leaf = fork();
    if (leaf < 0) _exit(126);
    if (leaf > 0) _exit(0);
    char path[PATH_MAX];
    int n = snprintf(path, sizeof(path), "%s/leaf", work);
    FILE *record = n > 0 && (size_t)n < sizeof(path) ? fopen(path, "wb") : NULL;
    if (!record) _exit(126);
    bool saved = fprintf(record, "%lld\n", (long long)getpid()) > 0;
    if (fclose(record) != 0 || !saved) _exit(126);
    if (write(ready[1], "r", 1) != 1) _exit(126);
    (void)close(ready[1]); (void)close(1); (void)close(2);
    for (;;) (void)poll(NULL, 0, 1000);
}

static int mc_fixture_escape(const char *work)
{
    char path[PATH_MAX];
    int n = snprintf(path, sizeof(path), "%s/held.lock", work);
    if (n <= 0 || (size_t)n >= sizeof(path)) return 126;
    int lock = open(path, O_RDWR | O_CREAT, 0600), ready[2];
    if (lock < 0 || flock(lock, LOCK_EX | LOCK_NB) != 0 || pipe(ready) != 0) return 126;
    pid_t child = fork();
    if (child == 0) {
        mc_fixture_escape_child(work, ready);
        _exit(126);
    }
    (void)close(ready[1]);
    struct pollfd notification = {.fd = ready[0], .events = POLLIN};
    char byte = 0;
    bool observed = child > 0 && poll(&notification, 1, 1000) > 0 && read(ready[0], &byte, 1) == 1;
    (void)close(ready[0]); (void)close(lock);
    return observed && byte == 'r' ? 0 : 126;
}

static bool mc_fixture_workload(const struct mc_opts *o, const char *root,
    struct zcl_mut_owner *owner, const char *executable)
{
    int gate[2];
    if (!mc_fixture_atexit(o->work) || pipe(gate) != 0) return false;
    platform_supervised_fixture_cleanup_gate(gate[0]);
    zcl_mut_fixture_retirement_refuse(true);
    char *arguments[] = {(char *)executable, "--_fixture-escape", (char *)o->work, NULL};
    int rc = zcl_mut_spawn_owned(owner, root, arguments, 60, NULL, NULL);
    /* Intentionally keep the cleanup gate open until actual process exit.
     * Only its EOF/adoption path may settle this unacknowledged custody. */
    char path[PATH_MAX];
    int n = snprintf(path, sizeof(path), "%s/supervisor", o->work);
    FILE *file = n > 0 && (size_t)n < sizeof(path) ? fopen(path, "wb") : NULL;
    if (!file) return false;
    bool recorded = fprintf(file, "%lld\n", (long long)zcl_mut_fixture_supervisor(owner)) > 0;
    recorded = fclose(file) == 0 && recorded;
    struct zcl_mut_config cfg = {.owner = owner, .root = root, .src_rel = o->file,
        .group = o->group, .work_dir = o->work};
    struct zcl_mut_plan plan = {0};
    struct zcl_mut_report report = {0};
    bool rerun = zcl_mut_campaign_run(&cfg, &plan, &report);
    fprintf(stderr, "fixture next_refused=%d credited=%zu retained=%d status=%d\n",
        !rerun, report.result_count, owner->pending != NULL, rc);
    zcl_mut_report_free(&report);
    /* The independent driver must observe the live escaped leaf and held
     * lock before authorizing this actual main's exit/owner-EOF path. */
    n = snprintf(path, sizeof(path), "%s/allow-exit", o->work);
    int64_t deadline = clock_now_monotonic_ns() + 5000000000;
    while (n > 0 && (size_t)n < sizeof(path) && access(path, F_OK) != 0 &&
           clock_now_monotonic_ns() < deadline)
        (void)poll(NULL, 0, 10);
    return recorded && rerun; /* A pending execution must never complete. */
}
#endif

static int mc_report_result(const struct mc_opts *o, const struct zcl_mut_owner *owner,
    struct zcl_mut_report *report, bool ok)
{
    if (!ok) {
        fprintf(stderr, "mutation-campaign: %s\n",
                owner->error[0] ? owner->error : report->error[0] ? report->error :
                "the campaign could not produce qualified execution evidence");
        zcl_mut_report_free(report);
        return 1;
    }
    mc_print(o, report);
    int rc = 0;
    if (o->report && !mc_write_report(o, report))
        rc = 1;
    /* A survivor is a finding, not a failure: this tool reports, it does not
     * gate. The only nonzero exits are "could not run" and "could not write
     * the report you asked for". */
    if (!report->source_unchanged) {
        fprintf(stderr,
                "mutation-campaign: the source digest CHANGED across the run; "
                "this is a harness defect, report it\n");
        rc = 1;
    }
    zcl_mut_report_free(report);
    return rc;
}

static int mc_execute(struct mc_opts o, const char *root, const char *executable)
{
    (void)executable;
    if (!zcl_supervised_retirement_begin()) {
        fprintf(stderr, "mutation-campaign: qualified Linux lifecycle unavailable\n");
        return 1;
    }
    struct zcl_mut_owner owner = ZCL_MUT_OWNER_INIT;
    struct zcl_mut_report report = {0};
    bool opened = zcl_mut_owner_open(&owner, root);
    bool ok;
#if defined(ZCL_TESTING) && defined(__linux__)
    if (o.fixture_cleanup) ok = opened && mc_fixture_workload(&o, root, &owner, executable);
    else
#endif
        ok = opened && mc_campaign(&o, root, &owner, &report);
    bool clean = mc_finish_owner(&owner);
    if (!clean) {
        /* Explicit unclean process exit: do not unwind a still-owned handle
         * or run destructors while the registry may access its dependencies.
         * OS EOF/adoption is not orderly join or proven descendant cleanup. */
        fprintf(stderr, "mutation-campaign: UNCLEAN_EXIT cleanup custody unresolved, no score\n");
#if defined(ZCL_TESTING) && defined(__linux__)
        fprintf(stderr, "fixture refusals=%u retained=%d\n",
            zcl_mut_fixture_retirement_refusals(), owner.pending != NULL);
#endif
        _Exit(ZCL_MUT_EXIT_CLEANUP_PENDING);
    }
    return mc_report_result(&o, &owner, &report, ok && clean);
}

int main(int argc, char **argv)
{
#if defined(ZCL_TESTING) && defined(__linux__)
    if (argc > 3 && strcmp(argv[1], "--_fixture-compiler") == 0)
        return mc_fixture_compiler(argc, argv);
    if (argc == 3 && strcmp(argv[1], "--_fixture-escape") == 0)
        return mc_fixture_escape(argv[2]);
    if (argc == 3 && strcmp(argv[1], "--_fixture-destructor-control") == 0)
        return mc_fixture_atexit(argv[2]) ? 0 : 1;
#endif
    struct mc_opts o;
    if (!mc_parse(argc, argv, &o)) {
        mc_usage(stderr);
        return 2;
    }
    char root[PATH_MAX];
    if (!zcl_devagent_checkout_root(NULL, root, sizeof root)) {
        fprintf(stderr, "mutation-campaign: no Z23 checkout above the current directory\n");
        return 2;
    }
    if (o.list) return mc_list(root, o.file);
#if !defined(__linux__)
    fprintf(stderr, "mutation-campaign: full execution unsupported without qualified host cleanup\n");
    return 2;
#endif
    return mc_execute(o, root, argv[0]);
}
