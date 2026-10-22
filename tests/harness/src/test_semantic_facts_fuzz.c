/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * ACCEPTANCE BAR for the facts-narrowed change closure against a cold
 * compiler: a differential fuzzer. Each case is a small multi-TU C23
 * project before and after one edit, either generated from a seed
 * (semantic_fuzz_gen.c, deterministic from seed and profile) or one of the
 * fixed reproducers (semantic_fuzz_repro.c), every one of which runs every
 * time. For each case every TU is compiled (the clang of the LLVM the
 * sensor links, -std=c23 -O1 -ffunction-sections, the project's flags) and
 * sensed (build/bin/z23-clang-manifest emit --facts) on both sides, the
 * change set is planned in process from the facts directory exactly as
 * dev.change.plan {"facts":...} plans it, and two oracles judge the plan:
 *
 *   objects     every TU the plan leaves unaffected (or out of its
 *               universe) has a byte-identical object;
 *   symbols     in a changed object, every function and data object
 *               whose bytes changed, or whose relocations now address
 *               other content (a relocation into a section or a local
 *               symbol is resolved to the string, constant or object
 *               bytes it addresses; an addend that resolves to the same
 *               content does not count), is a seed of a narrowed plan by
 *               canonical id (or is covered by a fallback, or by a
 *               broadened TU after a header change), and so is every other
 *               symbol at its address.
 *
 * A false negative prints the case (seed, profile, mutation), the TU and
 * the function, and fails. Every fixed reproducer (semantic_fuzz_repro.c,
 * known-RED and pass guards alike) runs every time regardless of mode:
 * they are the regressions this group exists to catch. On top of those,
 * three seed modes, printed in the summary line as `mode=...`:
 *   default   a fixed list of 6 seeds (~45s standalone with the fixed
 *             reproducers on an unloaded devbuild lane) covering every
 *             mutation kind and every profile;
 *   full      ZCL_STRESS_TESTS=1 (this repo's existing opt-in-to-the-slow-
 *             path convention): the full fixed list of 51 seeds;
 *   custom    ZCL_SEMANTIC_FUZZ_SEEDS=FIRST:COUNT[:PROFILE[:KIND[:CC[:OPT]]]]
 *             runs a long range instead (PROFILE all, no-ctr-line or
 *             gcc-deps; KIND forces one mutation kind, any draws it; CC
 *             names the object compiler, BEFORE>AFTER one that drifts
 *             between the sides; OPT replaces -O1), and wins over
 *             ZCL_STRESS_TESTS.
 * Both the default and full seed lists must yield narrowed plans that seed
 * a changed function, so the group cannot pass on fallbacks alone; a
 * custom range is not held to that (it may deliberately probe a
 * fallback-only slice). Cases run in
 * forked children, SFZ_CASES_AT_ONCE at once, each handing its outcome
 * back over a pipe; reports print in case order. Self-skips,
 * visibly, where the sensor has not been built (`make clang-manifest`),
 * where no clang sits beside the libclang it links, or where the sensor is
 * not ELF. A reproducer marked known-RED names the fix it waits for and the
 * exact false-negative lines it reports until then: it holds only when it
 * fails with exactly those lines. Any other outcome fails the group: an
 * ERROR, another miss, or a PASS (the mark is stale and must go). A fixed
 * reproducer or default seed whose edit changes no file (NOOP) fails too;
 * only a ZCL_SEMANTIC_FUZZ_SEEDS range run may draw one.
 */

#if !defined(_WIN32) && !defined(_DEFAULT_SOURCE)
#define _DEFAULT_SOURCE
#endif

#include "test/test_core.h"

#include "test/semantic_fuzz.h"

#include "devloop.h"

#include "base/safe_alloc.h"

#include "platform/clock.h"

#include <errno.h>
#include <poll.h>
#include <signal.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

#define SFZ_SENSOR "build/bin/z23-clang-manifest"
/* Cases run SFZ_CASES_AT_ONCE at once, each compiling and sensing
 * SFZ_JOBS files at once: SFZ_CASES_AT_ONCE * SFZ_JOBS processes in all.
 * A devbuild lane reserves dozens of CPUs; 4 badly underused one, so this
 * is raised toward that, capped well under a lane's full width so a case's
 * own SFZ_JOBS burst and other lint/test workers sharing the box still
 * have room. */
#define SFZ_CASES_AT_ONCE 8
#define SFZ_JOBS 2
/* A case of at most eight TUs compiles and senses each twice, SFZ_JOBS
 * runs at once, every run bounded by its own deadline; a case whose
 * process has not reported after this is killed and is an ERROR. */
#define SFZ_CASE_BUDGET_S 240
/* The exact false negatives a reproducer reports with the unbound-lookup
 * rule dropped (sfz_t_unbound_mutant): t0 is left out of the facts
 * universe. F13 deletes the file its __has_embed names; the -D case
 * creates the file a probe no file's text spells names (gcc's depfiles
 * omit it). Either plan falls back on the include graph, but the facts
 * alone would miss t0. */
#define SFZ_UNBOUND_MUTANT_WHY                                               \
    "src/t0.c object changed, planned unaffected (not in the universe)\n"

enum sfz_profile { PROF_ALL, PROF_NO_CTR_LINE, PROF_GCC_DEPS, PROF_COUNT };

static const char *const k_profile_names[PROF_COUNT] = {"all", "no-ctr-line",
                                                     "gcc-deps"};

struct sfz_seed {
    uint64_t seed;
    enum sfz_profile profile;
    const char *kind; /* the mutation kind, NULL: drawn from the seed */
};

/* The full run (ZCL_STRESS_TESTS=1): 51 (seed, profile, kind) cases
 * covering every mutation kind, most in the no-ctr-line profile where
 * plans narrow, some whose plans must fall back (flag, counter_c), and
 * gcc depfiles for the probed paths gcc omits. Chosen from a 4,900-case
 * run at this rule set; each passed there and most narrowed with seeds.
 * The four data-kind cases come from 150-case runs of each kind with the
 * symbol oracle; the seven path kinds (links, __FILE__, #pragma once
 * aliases, macro-named includes, #embed, __has_embed, macro and _next
 * __has_include probes), which a range draws only when forced, from
 * 64-case no-ctr-line runs. */
static const struct sfz_seed k_default_seeds_full[] = {
    {20007, PROF_ALL, "hasinc"},
    {20015, PROF_ALL, "shadow"},
    {20029, PROF_ALL, "body_extern"},
    {20048, PROF_ALL, "counter_c"},
    {20055, PROF_ALL, "header_inline"},
    {20061, PROF_ALL, "flag"},
    {20122, PROF_ALL, "multi"},
    {20005, PROF_ALL, "macro_cond"},
    {20168, PROF_ALL, "macro_value"},
    {20259, PROF_ALL, "comment_ws"},
    {22402, PROF_GCC_DEPS, "shadow"},
    {22408, PROF_GCC_DEPS, "macro_new"},
    {22410, PROF_GCC_DEPS, "hasinc"},
    {22414, PROF_GCC_DEPS, "typedef"},
    {22422, PROF_GCC_DEPS, "hasinc"},
    {22426, PROF_GCC_DEPS, "header_const"},
    {22430, PROF_GCC_DEPS, "signature"},
    {22449, PROF_GCC_DEPS, "layout"},
    {23000, PROF_NO_CTR_LINE, "header_const"},
    {23003, PROF_NO_CTR_LINE, "layout"},
    {23004, PROF_NO_CTR_LINE, "macro_new"},
    {23005, PROF_NO_CTR_LINE, "body_static"},
    {23006, PROF_NO_CTR_LINE, "signature"},
    {23008, PROF_NO_CTR_LINE, "macro_value"},
    {23013, PROF_NO_CTR_LINE, "multi"},
    {23022, PROF_NO_CTR_LINE, "body_extern"},
    {23023, PROF_NO_CTR_LINE, "typedef"},
    {23027, PROF_NO_CTR_LINE, "body_static"},
    {23030, PROF_NO_CTR_LINE, "header_inline"},
    {23031, PROF_NO_CTR_LINE, "body_extern"},
    {23037, PROF_NO_CTR_LINE, "enum_value"},
    {23051, PROF_NO_CTR_LINE, "shadow"},
    {23053, PROF_NO_CTR_LINE, "comment_ws"},
    {23057, PROF_NO_CTR_LINE, "hasinc"},
    {23058, PROF_NO_CTR_LINE, "flag"},
    {23059, PROF_NO_CTR_LINE, "body_static"},
    {23061, PROF_NO_CTR_LINE, "body_extern"},
    {23062, PROF_NO_CTR_LINE, "multi"},
    {23073, PROF_NO_CTR_LINE, "body_static"},
    {23149, PROF_NO_CTR_LINE, "macro_cond"},
    /* the data kinds: data_table falls back (file-scope-changed) */
    {31000, PROF_NO_CTR_LINE, "data_string"},
    {32000, PROF_NO_CTR_LINE, "data_table"},
    {33000, PROF_NO_CTR_LINE, "data_hconst"},
    {34000, PROF_NO_CTR_LINE, "data_index"},
    /* the path kinds, each from a 64-seed no-ctr-line range: symlink_retarget
     * falls back (include-graph-truncated: a changed link is no regular
     * file); a hasembed or hasinc_macro seed that deletes a file only a
     * probe names misses (F13, F14), these two narrow and pass */
    {41001, PROF_NO_CTR_LINE, "symlink_retarget"},
    {42000, PROF_NO_CTR_LINE, "file_macro"},
    {43002, PROF_NO_CTR_LINE, "pragma_alias"},
    {44000, PROF_NO_CTR_LINE, "macro_include"},
    {45002, PROF_NO_CTR_LINE, "embed_data"},
    {46000, PROF_NO_CTR_LINE, "hasembed"},
    {47000, PROF_NO_CTR_LINE, "hasinc_macro"},
};

/* The default run: 6 of the 44 above, a subset of k_default_seeds_full
 * chosen to keep every profile and a data kind represented; the fixed
 * reproducers alone already cost most of a fast gate's budget, so this
 * list is deliberately small, and every one of the 6 is known (from a
 * run of the full list) to produce a seeded verdict, so the invariant
 * below holds with margin. Standalone (with the fixed reproducers) this
 * is about 45s at SFZ_CASES_AT_ONCE; ZCL_STRESS_TESTS=1 runs the full
 * list instead. */
static const struct sfz_seed k_default_seeds_fast[] = {
    {20055, PROF_ALL, "header_inline"},
    {22414, PROF_GCC_DEPS, "typedef"},
    {23005, PROF_NO_CTR_LINE, "body_static"},
    {23037, PROF_NO_CTR_LINE, "enum_value"},
    {31000, PROF_NO_CTR_LINE, "data_string"},
    {34000, PROF_NO_CTR_LINE, "data_index"},
};

struct sfz_tally {
    size_t cases, pass, fail, noop, error, skipped, narrowed;
    size_t tus, predicted, changed, cfun, cobj, covered_seed, reloc, over;
    double plan_s;
};

struct sfz_group {
    struct sfz_env env;
    char scratch[PATH_MAX];
    struct sfz_tally t;
    bool kept; /* a failing case directory was left for inspection */
    bool noop_ok; /* a range run: an edit that changed nothing is no failure */
    const char *seed_mode; /* "default", "full" or "custom": printed in the summary */
};

/* ---- discovery -------------------------------------------------------------- */

static bool executable(const char *path)
{
    return access(path, X_OK) == 0;
}

/* <prefix>/bin/clang for the first "<prefix>/lib" entry of the sensor's
 * runpath. The pinned system libclang 18 fallback has no runpath; its exact
 * DT_NEEDED instead binds the root-owned matching Clang executable. */
static bool find_clang(const char *sensor, char *out, size_t n)
{
    char rp[PATH_MAX], *save = NULL;
    if (sfz_elf_runpath(sensor, rp, sizeof(rp))) {
        for (char *d = strtok_r(rp, ":", &save); d != NULL;
             d = strtok_r(NULL, ":", &save)) {
            size_t len = strlen(d);
            if (len < 4 || strcmp(d + len - 4, "/lib") != 0)
                continue;
            if ((size_t)snprintf(out, n, "%.*s/bin/clang", (int)(len - 4), d) < n &&
                executable(out))
                return true;
        }
        return false;
    }
    const char *system_clang = "/usr/lib/llvm-18/bin/clang";
    struct stat st;
    return sfz_elf_needs_without_runpath(sensor, "libclang-18.so.18") &&
           stat(system_clang, &st) == 0 && S_ISREG(st.st_mode) &&
           st.st_uid == 0 && (st.st_mode & 022) == 0 &&
           (size_t)snprintf(out, n, "%s", system_clang) < n &&
           executable(out);
}

static bool find_on_path(const char *name, char *out, size_t n)
{
    const char *path = getenv("PATH");
    char buf[4096], *save = NULL;
    if (path == NULL || (size_t)snprintf(buf, sizeof(buf), "%s", path) >= sizeof(buf))
        return false;
    for (char *d = strtok_r(buf, ":", &save); d != NULL;
         d = strtok_r(NULL, ":", &save))
        if ((size_t)snprintf(out, n, "%s/%s", d, name) < n && executable(out))
            return true;
    out[0] = '\0';
    return false;
}

/* The sensor, its clang and gcc; prints the SKIP line when absent. */
static bool discover(struct sfz_env *env)
{
    struct stat sb;
    memset(env, 0, sizeof(*env));
    env->jobs = SFZ_JOBS;
    if (stat(SFZ_SENSOR, &sb) != 0 || realpath(SFZ_SENSOR, env->sensor) == NULL) {
        printf("semantic_facts_fuzz: SKIP (needs %s from `make clang-manifest`)\n",
               SFZ_SENSOR);
        return false;
    }
    if (!find_clang(env->sensor, env->clang, sizeof(env->clang))) {
        printf("semantic_facts_fuzz: SKIP (no clang beside the libclang %s links, "
               "or it is not an ELF executable)\n", SFZ_SENSOR);
        return false;
    }
    /* The universal host gate probes this exact root-owned GCC. A PATH
     * shadow must not change the compiler after the capability decision. */
    if (executable("/usr/bin/gcc"))
        (void)snprintf(env->gcc, sizeof(env->gcc), "%s", "/usr/bin/gcc");
    return true;
}

/* ---- one case ------------------------------------------------------------------ */

static void tally(struct sfz_tally *t, const struct sfz_outcome *o)
{
    t->cases++;
    t->pass += o->status == SFZ_PASS;
    t->fail += o->status == SFZ_FAIL;
    t->noop += o->status == SFZ_NOOP;
    t->error += o->status == SFZ_ERROR;
    if (o->status != SFZ_PASS && o->status != SFZ_FAIL)
        return;
    t->narrowed += o->narrowed;
    t->tus += o->tus;
    t->predicted += o->predicted;
    t->changed += o->changed;
    t->cfun += o->cfun;
    t->cobj += o->cobj;
    t->covered_seed += o->covered_seed;
    t->reloc += o->reloc;
    t->over += o->over;
    t->plan_s += o->plan_s;
}

static const char *status_name(enum sfz_status s)
{
    static const char *const names[] = {"PASS", "FAIL", "NOOP", "ERROR"};
    return names[s];
}

static void report(const struct sfz_case *c, const struct sfz_outcome *o)
{
    printf("semantic_facts_fuzz: %s kind=%s %s narrowed=%s%s%s tus=%zu "
           "pred=%zu changed=%zu missed=%zu over=%zu cfun=%zu cobj=%zu seeded=%zu "
           "reloc=%zu notcov=%zu seeds=%zu plan=%.2fs\n",
           c->label, c->kind, status_name(o->status), o->narrowed ? "yes" : "no",
           o->narrowed ? "" : " reason=", o->vreason, o->tus, o->predicted,
           o->changed, o->missed, o->over, o->cfun, o->cobj, o->covered_seed,
           o->reloc, o->notcov, o->seeds, o->plan_s);
    if (o->status != SFZ_PASS && o->status != SFZ_NOOP)
        printf("  detail: %s\n  case: %s\n%s", c->detail, c->dir, o->why);
}

static bool gcc_missing(struct sfz_group *g, const char *label)
{
    if (g->env.gcc[0] != '\0')
        return false;
    printf("semantic_facts_fuzz: %s SKIP (gcc-deps needs gcc on PATH)\n", label);
    g->t.skipped++;
    return true;
}

/* The absolute path of object compiler `name` into out: NULL, "" or
 * "clang" is the sensor's clang (out ""), anything else is looked up on
 * PATH. False, with a visible SKIP, when it is absent. */
static bool resolve_cc(struct sfz_group *g, const char *label, const char *name,
                       char *out, size_t n)
{
    out[0] = '\0';
    if (name == NULL || name[0] == '\0' || strcmp(name, "clang") == 0)
        return true;
    if (find_on_path(name, out, n))
        return true;
    printf("semantic_facts_fuzz: %s SKIP (needs %s on PATH)\n", label, name);
    g->t.skipped++;
    return false;
}

/* Set c's toolchain: before and after object compilers and optimizer
 * flags. False (skipped) when a compiler is absent. */
static bool set_tools(struct sfz_group *g, struct sfz_case *c, const char *before,
                      const char *after, const char *opt)
{
    (void)snprintf(c->opt, sizeof(c->opt), "%s", opt != NULL ? opt : "");
    return resolve_cc(g, c->label, before, c->cc[0], sizeof(c->cc[0])) &&
           resolve_cc(g, c->label, after, c->cc[1], sizeof(c->cc[1]));
}

/* ---- the case pool: SFZ_CASES_AT_ONCE cases, each in its own process ---------- */

/* One case, prepared in the group's process and run in a child that hands
 * its outcome back over a pipe. */
struct sfz_item {
    struct sfz_case c;
    const char *known_red; /* a reproducer's known-RED mark */
    const char *known_red_why; /* ...and the exact lines it must report */
    bool over_pinned;      /* a reproducer's exact over-selection pin */
    size_t over_want;
    bool run;              /* false: skipped, or failed before it could run */
    bool collected;        /* outcome read and reaped by item_collect */
    bool ok;               /* passed, or held as recorded (NOOP only in a
                              range run) */
    pid_t pid;
    int64_t deadline;      /* monotonic ns: killed and an ERROR after it */
    int fd;
    struct sfz_outcome o;
};

static bool write_all(int fd, const void *buf, size_t n)
{
    const uint8_t *p = buf;
    while (n > 0) {
        ssize_t w = write(fd, p, n);
        if (w < 0 && errno == EINTR)
            continue;
        if (w <= 0)
            return false;
        p += w;
        n -= (size_t)w;
    }
    return true;
}

/* Read n bytes from fd by `deadline` (monotonic ns): 1 read, 0 closed or
 * failed, -1 out of time. */
static int read_by(int fd, void *buf, size_t n, int64_t deadline)
{
    uint8_t *p = buf;
    while (n > 0) {
        int64_t left = (deadline - clock_now_monotonic_ns()) / 1000000;
        struct pollfd pfd = {.fd = fd, .events = POLLIN};
        int ready = left > 0 ? poll(&pfd, 1, left > INT_MAX ? INT_MAX : (int)left) : 0;
        ssize_t r;
        if (ready < 0 && errno == EINTR)
            continue;
        if (ready == 0)
            return -1;
        r = ready > 0 ? read(fd, p, n) : -1;
        if (r < 0 && errno == EINTR)
            continue;
        if (r <= 0)
            return 0;
        p += r;
        n -= (size_t)r;
    }
    return 1;
}

static void item_start(const struct sfz_env *env, struct sfz_item *it)
{
    int p[2];
    it->pid = -1;
    it->fd = -1;
    if (pipe(p) != 0) {
        fprintf(stderr, "sfz: pipe for %s: %s\n", it->c.label, strerror(errno));
        return;
    }
    (void)fflush(stdout);
    (void)fflush(stderr);
    it->pid = fork();
    if (it->pid == 0) {
        (void)close(p[0]);
        (void)sfz_run_case(env, &it->c, &it->o);
        _exit(write_all(p[1], &it->o, sizeof(it->o)) ? 0 : 1);
    }
    (void)close(p[1]);
    if (it->pid < 0) {
        fprintf(stderr, "sfz: fork for %s: %s\n", it->c.label, strerror(errno));
        (void)close(p[0]);
        return;
    }
    it->fd = p[0];
    it->deadline = clock_now_monotonic_ns() + (int64_t)SFZ_CASE_BUDGET_S * 1000000000;
}

/* True when `why` is exactly the lines of `want`, each reported with the
 * two-space indent sfz_why() gives a false-negative line. */
static bool why_is(const char *why, const char *want)
{
    while (*want != '\0') {
        const char *eol = strchr(want, '\n');
        size_t len = eol != NULL ? (size_t)(eol - want) + 1 : strlen(want);
        if (strncmp(why, "  ", 2) != 0 || strncmp(why + 2, want, len) != 0)
            return false;
        why += 2 + len;
        want += len;
    }
    return *why == '\0';
}

/* A known-RED reproducer holds only when it fails with exactly its
 * recorded lines: an ERROR, a NOOP, another miss or a PASS (a stale mark)
 * each fail the group. */
static bool known_red_holds(const struct sfz_item *it)
{
    bool holds = it->o.status == SFZ_FAIL && it->known_red_why != NULL &&
                 why_is(it->o.why, it->known_red_why);
    if (holds)
        printf("semantic_facts_fuzz: %s KNOWN-RED as recorded, expected until %s\n",
               it->c.label, it->known_red);
    else if (it->o.status == SFZ_PASS)
        printf("semantic_facts_fuzz: %s now passes: its known-RED mark is stale, "
               "remove it\n", it->c.label);
    else
        printf("semantic_facts_fuzz: %s KNOWN-RED MISMATCH: expected FAIL "
               "reporting exactly:\n%s", it->c.label,
               it->known_red_why != NULL ? it->known_red_why : "(nothing recorded)\n");
    return holds;
}

/* A pinned reproducer holds only when its measured over-selection (TUs
 * the plan predicted affected whose cold object did not change) is
 * exactly the recorded count: a rise is a false-WIDE precision
 * regression, a fall means the pin is stale and must come down. Checked
 * whenever the case ran to a verdict (not an ERROR, which reports
 * nothing reliable). */
static bool over_holds(const struct sfz_item *it)
{
    bool ran = it->o.status == SFZ_PASS || it->o.status == SFZ_FAIL;
    bool holds = !ran || it->o.over == it->over_want;
    if (!it->over_pinned)
        return true;
    if (holds)
        printf("semantic_facts_fuzz: %s over-selection %zu as pinned\n",
               it->c.label, it->over_want);
    else
        printf("semantic_facts_fuzz: %s OVER-SELECTION MISMATCH: pinned %zu, "
               "measured %zu (%s)\n",
               it->c.label, it->over_want, it->o.over,
               it->o.over > it->over_want
                   ? "a precision regression"
                   : "the pin is stale and must come down");
    return holds;
}

/* Whether the finished item holds: a PASS, a known-RED reproducer failing
 * exactly as recorded, or a NOOP in a range run, and (when pinned) its
 * over-selection count unchanged. */
static void judge_item(struct sfz_group *g, struct sfz_item *it)
{
    if (it->known_red != NULL)
        it->ok = known_red_holds(it);
    else
        it->ok = it->o.status == SFZ_PASS ||
                 (it->o.status == SFZ_NOOP && g->noop_ok);
    it->ok = over_holds(it) && it->ok;
    if (it->o.status == SFZ_NOOP && !it->ok)
        printf("semantic_facts_fuzz: %s NOOP fails: a fixed reproducer or default "
               "seed must change a file; only a range run may draw a no-op\n",
               it->c.label);
    /* a case that failed as recorded leaves nothing to inspect */
    if (it->known_red != NULL && it->ok)
        (void)test_rm_rf_recursive(it->c.dir);
    else
        g->kept = g->kept || it->o.status == SFZ_FAIL || it->o.status == SFZ_ERROR;
}

/* Read a started item's outcome by its deadline, kill it if it ran out of
 * time, reap it, and fill an ERROR outcome when it did not report. */
static void item_collect(struct sfz_item *it)
{
    int st = 0;
    int got = it->fd >= 0 ? read_by(it->fd, &it->o, sizeof(it->o), it->deadline) : 0;
    if (it->fd >= 0)
        (void)close(it->fd);
    /* out of time: its compile and sensor runs die with it (PDEATHSIG) */
    if (got < 0 && it->pid > 0)
        (void)kill(it->pid, SIGKILL);
    if (it->pid > 0 && waitpid(it->pid, &st, 0) != it->pid)
        fprintf(stderr, "sfz: waitpid for %s: %s\n", it->c.label, strerror(errno));
    if (got != 1) {
        memset(&it->o, 0, sizeof(it->o));
        it->o.status = SFZ_ERROR;
        if (got < 0)
            (void)snprintf(it->o.why, sizeof(it->o.why),
                           "the case process ran past its %d s budget and was "
                           "killed\n", SFZ_CASE_BUDGET_S);
        else
            (void)snprintf(it->o.why, sizeof(it->o.why),
                           "the case process did not report (status %d)\n", st);
    }
    it->collected = true;
}

/* Tally, print and judge a collected item. */
static void item_report(struct sfz_group *g, struct sfz_item *it)
{
    tally(&g->t, &it->o);
    report(&it->c, &it->o);
    judge_item(g, it);
}

/* Milliseconds until the earliest live deadline, rounded up; 0 once one
 * has passed. `live` is at least 1. */
static int live_timeout_ms(const struct sfz_item *v, const size_t *idx, size_t live)
{
    int64_t best = v[idx[0]].deadline, left;
    for (size_t i = 1; i < live; i++)
        if (v[idx[i]].deadline < best)
            best = v[idx[i]].deadline;
    left = best - clock_now_monotonic_ns();
    if (left <= 0)
        return 0;
    left = (left + 999999) / 1000000;
    return left > INT_MAX ? INT_MAX : (int)left;
}

/* Poll the live cases until one is readable or hung up, or its deadline
 * passes (a failed poll makes every live case due, so none can block),
 * then collect each due one. The live ones that remain are packed to the
 * front of idx; returns their count. */
static size_t live_collect(struct sfz_item *v, size_t *idx, size_t live)
{
    struct pollfd pf[SFZ_CASES_AT_ONCE];
    int ret;
    size_t kept = 0;
    for (size_t i = 0; i < live; i++)
        pf[i] = (struct pollfd){.fd = v[idx[i]].fd, .events = POLLIN};
    do
        ret = poll(pf, (nfds_t)live, live_timeout_ms(v, idx, live));
    while (ret < 0 && errno == EINTR);
    for (size_t i = 0; i < live; i++) {
        struct sfz_item *it = &v[idx[i]];
        bool due = ret < 0 || pf[i].revents != 0 ||
                   clock_now_monotonic_ns() >= it->deadline;
        if (due)
            item_collect(it);
        else
            idx[kept++] = idx[i];
    }
    return kept;
}

/* Start runnable items from v[k] on in free slots, at most
 * SFZ_CASES_AT_ONCE live. An item that did not start (no pipe or fork)
 * is collected at once as an ERROR. Returns the next unstarted index. */
static size_t live_fill(const struct sfz_env *env, struct sfz_item *v, size_t n,
                        size_t k, size_t *idx, size_t *live)
{
    for (; k < n && *live < SFZ_CASES_AT_ONCE; k++) {
        if (!v[k].run)
            continue;
        item_start(env, &v[k]);
        if (v[k].fd < 0)
            item_collect(&v[k]);
        else
            idx[(*live)++] = k;
    }
    return k;
}

/* Report, in index order, the collected run items from v[next] on; stops
 * at the first run item still live. Returns the next index to report. */
static size_t report_ready(struct sfz_group *g, struct sfz_item *v, size_t n,
                           size_t next)
{
    for (; next < n; next++) {
        if (!v[next].run)
            continue;
        if (!v[next].collected)
            break;
        item_report(g, &v[next]);
    }
    return next;
}

/* Run every runnable item, at most SFZ_CASES_AT_ONCE at once, finishing
 * whichever is ready first but reporting them in index order; the number
 * that did not pass. */
static size_t run_items(struct sfz_group *g, struct sfz_item *v, size_t n)
{
    size_t idx[SFZ_CASES_AT_ONCE], live = 0, k = 0, next = 0, bad = 0;
    for (size_t j = 0; j < n; j++)
        v[j].collected = false;
    while (k < n || live > 0) {
        k = live_fill(&g->env, v, n, k, idx, &live);
        next = report_ready(g, v, n, next);
        if (live > 0)
            live = live_collect(v, idx, live);
    }
    (void)report_ready(g, v, n, next);
    for (size_t j = 0; j < n; j++)
        bad += !v[j].ok;
    return bad;
}

/* ---- the fixed reproducers ------------------------------------------------------ */

/* Reproducer r, with toolchain t (NULL: the sensor's clang at -O1). */
static void prep_repro(struct sfz_group *g, const struct sfz_repro *r,
                       const struct sfz_tool_repro *t, struct sfz_item *it)
{
    struct sfz_case *c = &it->c;
    c->gcc_deps = r->gcc_deps;
    (void)snprintf(c->label, sizeof(c->label), "%s", r->name);
    (void)snprintf(c->dir, sizeof(c->dir), "%s/%s", g->scratch, r->name);
    (void)snprintf(c->kind, sizeof(c->kind), "%s", r->kind);
    (void)snprintf(c->detail, sizeof(c->detail), "%s", r->detail);
    it->known_red = r->known_red;
    it->known_red_why = r->known_red_why;
    it->over_pinned = r->over_pinned;
    it->over_want = r->over_want;
    it->ok = true;
    if (r->gcc_deps && gcc_missing(g, r->name))
        return;
    if (t != NULL && !set_tools(g, c, t->cc_before, t->cc_after, t->opt))
        return;
    it->ok = sfz_write_repro(r, c->dir);
    it->run = it->ok;
    if (!it->ok)
        printf("semantic_facts_fuzz: %s ERROR: cannot write the reproducer\n",
               r->name);
}

/* True when kind names a negative-lookup, ordering or search-dir family. */
static bool is_new_family_kind(const char *kind)
{
    static const char *const prefixes[] = {"neg_", "xmacro_", "order_",
                                           "sdir_"};
    for (size_t k = 0; k < sizeof(prefixes) / sizeof(prefixes[0]); k++)
        if (strncmp(kind, prefixes[k], strlen(prefixes[k])) == 0)
            return true;
    return false;
}

/* Per-family (kind) over-selection totals for the negative-lookup,
 * ordering and search-dir families, one line per family in the run summary. */
static void report_over_by_family(const struct sfz_item *v, size_t n)
{
    char seen[16][32];
    size_t nseen = 0;
    for (size_t k = 0; k < n; k++) {
        const char *kind = v[k].c.kind;
        bool found = false;
        if (!is_new_family_kind(kind))
            continue;
        for (size_t q = 0; q < nseen && !found; q++)
            found = strcmp(seen[q], kind) == 0;
        if (!found && nseen < sizeof(seen) / sizeof(seen[0]))
            (void)snprintf(seen[nseen++], sizeof(seen[0]), "%s", kind);
    }
    for (size_t q = 0; q < nseen; q++) {
        size_t total = 0, cases = 0;
        for (size_t k = 0; k < n; k++)
            if (strcmp(v[k].c.kind, seen[q]) == 0) {
                total += v[k].o.over;
                cases++;
            }
        printf("semantic_facts_fuzz: family kind=%s cases=%zu over-selected=%zu\n",
               seen[q], cases, total);
    }
}

static int sfz_t_repros(struct sfz_group *g)
{
    int failures = 0;
    size_t n = k_sfz_nrepros + k_sfz_ntool_repros;
    struct sfz_item *v = zcl_calloc(n, sizeof(*v), "sfz.repros");
    TEST_CASE("semantic_facts_fuzz: every fixed reproducer plans safely") {
        ASSERT(v != NULL);
        for (size_t k = 0; k < k_sfz_nrepros; k++)
            prep_repro(g, &k_sfz_repros[k], NULL, &v[k]);
        for (size_t k = 0; k < k_sfz_ntool_repros; k++)
            prep_repro(g, &k_sfz_tool_repros[k].r, &k_sfz_tool_repros[k],
                       &v[k_sfz_nrepros + k]);
        ASSERT_EQ(run_items(g, v, n), (size_t)0);
    } TEST_END
    if (v != NULL)
        report_over_by_family(v, n);
    free(v);
    return failures;
}

/* ---- the search-dir replay is load-bearing --------------------------------------- */

/* SD3 with the consumer's search-dir replay dropped, so every
 * search-dir-only identity change reads as resolving as before: t0, whose
 * __has_include answer the added dir flips while its file set stays the
 * same, must be missed, exactly. */
static int sfz_t_sdir_mutant(struct sfz_group *g)
{
    int failures = 0;
    const struct sfz_tool_repro *t = NULL;
    struct sfz_item it;
    struct sfz_repro r;
    size_t bad;
    for (size_t k = 0; k < k_sfz_ntool_repros; k++)
        if (strcmp(k_sfz_tool_repros[k].r.name, "SD3_dir_satisfies_probe") == 0)
            t = &k_sfz_tool_repros[k];
    TEST_CASE("semantic_facts_fuzz: without the search-dir replay the TU whose probe an added dir answers is missed") {
        ASSERT(t != NULL);
        memset(&it, 0, sizeof(it));
        r = t->r;
        r.name = "SD3_dir_satisfies_probe_mutant";
        r.known_red = "the search-dir replay returns (mutant NO_SDIR_REPLAY "
                      "drops it)";
        r.known_red_why =
            "src/t0.c object changed, planned unaffected (not in the universe)\n";
        prep_repro(g, &r, t, &it);
        ASSERT(it.run);
        zcl_devloop_test_consumer_mutant = ZCL_DEVLOOP_MUTANT_NO_SDIR_REPLAY;
        bad = run_items(g, &it, 1);
        zcl_devloop_test_consumer_mutant = ZCL_DEVLOOP_MUTANT_NONE;
        ASSERT_EQ(bad, (size_t)0);
    } TEST_END
    return failures;
}

/* ---- the static_assert rule is load-bearing -------------------------------------- */

/* SA1 with the consumer's static_assert rule dropped: t1 and t2, which read
 * shape.h only through guard.h's assertion, fall back to unaffected, so the
 * over-selection falls from its pin of 2 to exactly 0. Their objects do not
 * change, so no object oracle sees the miss; only the pin does. */
static int sfz_t_assert_mutant(struct sfz_group *g)
{
    int failures = 0;
    const struct sfz_repro *base = NULL;
    struct sfz_item it;
    struct sfz_repro r;
    size_t bad;
    for (size_t k = 0; k < k_sfz_nrepros; k++)
        if (strcmp(k_sfz_repros[k].name, "SA1_assert_struct_grows") == 0)
            base = &k_sfz_repros[k];
    TEST_CASE("semantic_facts_fuzz: without the static_assert rule the assertion's readers are left unaffected") {
        ASSERT(base != NULL && base->over_pinned && base->over_want == 2);
        memset(&it, 0, sizeof(it));
        r = *base;
        r.name = "SA1_assert_struct_grows_mutant";
        r.over_want = 0;
        prep_repro(g, &r, NULL, &it);
        ASSERT(it.run);
        zcl_devloop_test_consumer_mutant = ZCL_DEVLOOP_MUTANT_NO_ASSERT;
        bad = run_items(g, &it, 1);
        zcl_devloop_test_consumer_mutant = ZCL_DEVLOOP_MUTANT_NONE;
        ASSERT_EQ(bad, (size_t)0);
        ASSERT_EQ(it.o.status, SFZ_PASS);
        ASSERT_EQ(it.o.over, (size_t)0);
    } TEST_END
    return failures;
}

/* ---- the unbound-lookup rule is load-bearing ------------------------------------- */

/* A reproducer with the consumer's unbound-lookup rule dropped: t0's probe
 * (a __has_embed; a -D value's __has_include) makes no negative claim, so
 * nothing names the deleted or created file and t0, whose object changes,
 * must be missed, exactly. */
static const struct {
    const char *base, *name, *why;
} k_sfz_unbound_mutants[] = {
    {"F13_has_embed_deleted", "F13_has_embed_deleted_mutant",
     SFZ_UNBOUND_MUTANT_WHY},
    {"pass_probe_dash_d_gcc_deps", "pass_probe_dash_d_gcc_deps_mutant",
     SFZ_UNBOUND_MUTANT_WHY},
};

static size_t sfz_unbound_mutant_one(struct sfz_group *g, size_t m)
{
    const struct sfz_repro *base = NULL;
    struct sfz_item it;
    struct sfz_repro r;
    size_t bad;
    for (size_t k = 0; k < k_sfz_nrepros; k++)
        if (strcmp(k_sfz_repros[k].name, k_sfz_unbound_mutants[m].base) == 0)
            base = &k_sfz_repros[k];
    if (base == NULL || base->known_red != NULL)
        return 1;
    memset(&it, 0, sizeof(it));
    r = *base;
    r.name = k_sfz_unbound_mutants[m].name;
    r.known_red = "the unbound-lookup rule returns (mutant NO_UNBOUND drops it)";
    r.known_red_why = k_sfz_unbound_mutants[m].why;
    r.over_pinned = false;
    prep_repro(g, &r, NULL, &it);
    if (!it.run)
        return 1;
    zcl_devloop_test_consumer_mutant = ZCL_DEVLOOP_MUTANT_NO_UNBOUND;
    bad = run_items(g, &it, 1);
    zcl_devloop_test_consumer_mutant = ZCL_DEVLOOP_MUTANT_NONE;
    return bad;
}

static int sfz_t_unbound_mutant(struct sfz_group *g)
{
    int failures = 0;
    TEST_CASE("semantic_facts_fuzz: without the unbound-lookup rule the TU whose unbound probe a deleted or created file answers is missed") {
        for (size_t m = 0; m < sizeof(k_sfz_unbound_mutants) /
                                   sizeof(k_sfz_unbound_mutants[0]);
             m++)
            ASSERT_EQ(sfz_unbound_mutant_one(g, m), (size_t)0);
    } TEST_END
    return failures;
}

/* ---- the seeds ------------------------------------------------------------------- */

static unsigned profile_bits(enum sfz_profile p)
{
    return p == PROF_NO_CTR_LINE ? SFZ_NO_CTR | SFZ_NO_LINE : 0u;
}

/* The toolchain of a range run: "CC" for both sides or "BEFORE>AFTER"
 * (a compiler that drifts between the sides), and optimizer flags. */
struct sfz_tools {
    char cc[64];
    char opt[128];
};

static bool seed_tools(struct sfz_group *g, struct sfz_case *c,
                       const struct sfz_tools *t)
{
    char before[64];
    const char *gt;
    if (t == NULL)
        return true;
    gt = strchr(t->cc, '>');
    (void)snprintf(before, sizeof(before), "%.*s",
                   gt != NULL ? (int)(gt - t->cc) : (int)strlen(t->cc), t->cc);
    return set_tools(g, c, before, gt != NULL ? gt + 1 : t->cc, t->opt);
}

static void prep_seed(struct sfz_group *g, struct sfz_seed s,
                      const struct sfz_tools *t, struct sfz_item *it)
{
    struct sfz_case *c = &it->c;
    struct sfz_meta meta;
    c->gcc_deps = s.profile == PROF_GCC_DEPS;
    (void)snprintf(c->label, sizeof(c->label), "seed=%llu profile=%s",
                   (unsigned long long)s.seed, k_profile_names[s.profile]);
    (void)snprintf(c->dir, sizeof(c->dir), "%s/seed_%llu_%s", g->scratch,
                   (unsigned long long)s.seed, k_profile_names[s.profile]);
    it->ok = true;
    if (c->gcc_deps && gcc_missing(g, c->label))
        return;
    if (!seed_tools(g, c, t))
        return;
    it->ok = sfz_generate(s.seed, profile_bits(s.profile), s.kind, c->dir, &meta);
    it->run = it->ok;
    if (!it->ok) {
        printf("semantic_facts_fuzz: %s ERROR: the generator failed\n", c->label);
        return;
    }
    (void)snprintf(c->kind, sizeof(c->kind), "%s", meta.kind);
    (void)snprintf(c->detail, sizeof(c->detail), "%s", meta.detail);
}

/* ZCL_SEMANTIC_FUZZ_SEEDS=FIRST:COUNT[:PROFILE[:KIND[:CC[:OPT]]]]: COUNT
 * consecutive seeds from FIRST, the kind drawn unless KIND names one (any:
 * drawn). CC is the object compiler of both sides ("clang", the sensor's,
 * by default; "gcc", or any name on PATH), or BEFORE>AFTER for a compiler
 * that changes between the sides; OPT replaces -O1 with comma-separated
 * flags (-O0, -O2, -Og,-fno-inline, ...), or COMPILE/SENSOR when the
 * sensor is handed other flags than the compile (-O2/-Og), each side's
 * own as BEFORE>AFTER (-O0>-O2). */
struct sfz_range {
    uint64_t first;
    size_t count;
    enum sfz_profile profile;
    char kind[32];
    struct sfz_tools tools;
};

/* False when unset; *bad when set but malformed. */
static bool seeds_override(struct sfz_range *r, bool *bad)
{
    const char *v = getenv("ZCL_SEMANTIC_FUZZ_SEEDS");
    char prof[32] = "all";
    unsigned long long f = 0, n = 0;
    int got;
    memset(r, 0, sizeof(*r));
    *bad = false;
    if (v == NULL || v[0] == '\0')
        return false;
    got = sscanf(v, "%llu:%llu:%31[^:]:%31[^:]:%63[^:]:%127s", &f, &n, prof,
                 r->kind, r->tools.cc, r->tools.opt);
    r->first = f;
    r->count = (size_t)n;
    r->profile = PROF_COUNT;
    for (int p = 0; p < PROF_COUNT; p++)
        if (strcmp(prof, k_profile_names[p]) == 0)
            r->profile = (enum sfz_profile)p;
    if (strcmp(r->kind, "any") == 0)
        r->kind[0] = '\0';
    *bad = got < 2 || n == 0 || r->profile == PROF_COUNT ||
           (r->kind[0] != '\0' && !sfz_kind_known(r->kind));
    return true;
}

static int sfz_t_seeds(struct sfz_group *g)
{
    int failures = 0;
    struct sfz_range r;
    bool bad_env = false, custom = seeds_override(&r, &bad_env);
    /* ZCL_SEMANTIC_FUZZ_SEEDS wins over ZCL_STRESS_TESTS; otherwise
     * ZCL_STRESS_TESTS=1 (the repo's existing opt-in-to-the-slow-path
     * convention) runs the full 51-seed list, and a plain run stays to
     * the fast 6-seed default. */
    bool stress = !custom && getenv("ZCL_STRESS_TESTS") != NULL;
    const struct sfz_seed *dseeds = stress ? k_default_seeds_full
                                            : k_default_seeds_fast;
    size_t dn = stress ? sizeof(k_default_seeds_full) / sizeof(k_default_seeds_full[0])
                        : sizeof(k_default_seeds_fast) / sizeof(k_default_seeds_fast[0]);
    size_t n = custom ? r.count : dn;
    size_t narrowed0 = g->t.narrowed, seeded0 = g->t.covered_seed;
    struct sfz_item *v = NULL;
    g->seed_mode = custom ? "custom" : stress ? "full" : "default";
    TEST_CASE("semantic_facts_fuzz: generated seeds plan safely") {
        /* FIRST:COUNT[:all|no-ctr-line|gcc-deps[:KIND[:CC[:OPT]]]] */
        ASSERT(!bad_env);
        g->noop_ok = custom;
        v = zcl_calloc(n, sizeof(*v), "sfz.seeds");
        ASSERT(v != NULL);
        for (size_t k = 0; k < n; k++)
            prep_seed(g, custom ? (struct sfz_seed){r.first + k, r.profile,
                                                    r.kind[0] ? r.kind : NULL}
                                : dseeds[k],
                      custom ? &r.tools : NULL, &v[k]);
        ASSERT_EQ(run_items(g, v, n), (size_t)0);
        /* the default and full seed lists must exercise narrowed plans
         * that seed a changed function, not only fallbacks; a custom
         * range is not held to that (it may probe a fallback-only slice) */
        ASSERT(custom || g->t.narrowed > narrowed0);
        ASSERT(custom || g->t.covered_seed > seeded0);
    } TEST_END
    free(v);
    return failures;
}

int test_semantic_facts_fuzz(void)
{
    int failures = 0;
    struct sfz_group *g = zcl_calloc(1, sizeof(*g), "sfz.group");
    int64_t t0 = clock_now_monotonic_ns();
    if (g == NULL)
        return 1;
    if (!discover(&g->env)) {
        free(g);
        return 0;
    }
    TEST_CASE("semantic_facts_fuzz: scratch") {
        ASSERT(test_mkdtemp(g->scratch, sizeof(g->scratch), "semfacts_fuzz") != NULL);
    } TEST_END
    if (failures == 0) {
        failures += sfz_t_repros(g);
        failures += sfz_t_sdir_mutant(g);
        failures += sfz_t_assert_mutant(g);
        failures += sfz_t_unbound_mutant(g);
        failures += sfz_t_seeds(g);
    }
    printf("semantic_facts_fuzz: mode=%s %zu cases (%zu fixed) in %.1f s: %zu pass, "
           "%zu fail, %zu noop, %zu error, %zu skipped; %zu narrowed verdicts; %zu "
           "TUs, %zu predicted, %zu changed, %zu over-selected; %zu changed "
           "functions, %zu changed data objects, %zu seeded, "
           "%zu relocation-only; planning %.1f s\n",
           g->seed_mode != NULL ? g->seed_mode : "unknown", g->t.cases,
           k_sfz_nrepros + k_sfz_ntool_repros,
           (double)(clock_now_monotonic_ns() - t0) / 1e9, g->t.pass, g->t.fail,
           g->t.noop, g->t.error, g->t.skipped, g->t.narrowed, g->t.tus,
           g->t.predicted, g->t.changed, g->t.over, g->t.cfun, g->t.cobj,
           g->t.covered_seed, g->t.reloc, g->t.plan_s);
    if (failures == 0 && !g->kept)
        (void)test_rm_rf_recursive(g->scratch);
    free(g);
    return failures;
}
