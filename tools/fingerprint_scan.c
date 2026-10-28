/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * fingerprint_scan — run behavioral fingerprinting over the whole tree.
 *
 * Orchestration only: cognition/modules/fingerprint decides what is fingerprintable and
 * writes the harness; this drives the compiler, the linker, and the runs, and
 * then reports what was actually observed.
 *
 * The run is repeated under configurations that differ only in things a PURE
 * function's result must not depend on:
 *
 *   A  output memory pre-filled with 0x00, probes at -O2
 *   B  pre-filled with 0xA5 — catches a callee that leaves padding or a tail
 *      unwritten, and an uninitialised read
 *   C  a separate process with a large environment block — ASLR and the
 *      stack base both move, so an address-dependent result changes
 *   D  probes and link at -O0
 *   E  probes and link at -O0 with the 0xA5 fill
 *
 * A candidate is FINGERPRINTED only when all of them agree byte for byte.
 * The ones that pass the static purity analysis and then disagree are the
 * MEASURED false-purity rate, printed rather than assumed.
 *
 * Two kinds of probe translation unit reach this far. One includes a header
 * and calls an externally linkable function; the other includes a whole
 * DEFINING .c so that a file-local function is callable at all. The second
 * kind is where this driver earns its keep: it inherits a real unit's
 * includes, its file-scope state and its link-time appetite, so a unit that
 * will not compile or will not link costs every candidate in it. Every one of
 * those is counted, attributed and printed by route, never dropped quietly.
 *
 * Every reported fingerprint MATCH is then re-tested on a second, disjoint,
 * 16x larger corpus. A pair that matched on the first corpus and diverges on
 * the second is a measured FALSE POSITIVE of the technique, and that number
 * is printed too. It is the number that decides whether any of this is worth
 * paying attention to.
 *
 * Nothing here writes to a datadir, opens a socket, or contacts a node.
 */

#include "fingerprint/fingerprint.h"
#include "fingerprint/fp_runtime.h"

#include "base/safe_alloc.h"

#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

#define FP_MAX_FILES     32768
#define FP_MAX_CANDS     20000
#define FP_MAX_ARGS       8192
#define FP_PRUNE_ROUNDS     16
#define FP_CFG_COUNT         5

/* The generated stub unit is the ONE translation unit built without LTO, and
 * that is a correctness requirement rather than a speed one. A stub defines a
 * symbol the object tree did not supply, as a zeroed byte array — but some of
 * those symbols are FUNCTIONS that a probe TU's header also declares. Under
 * LTO the linker plugin compares the two declarations across translation
 * units and rejects the whole link ("variable redeclared as function"), so
 * the run dies at the finish line having measured nothing. Compiled without
 * LTO the stub is a plain ELF symbol with no type for the plugin to argue
 * with. Nothing is weakened by this: a stub is unreachable from any probe by
 * construction (see fp_write_stubs), so its type was never load-bearing. */
#define FP_STUB_CFLAG "-fno-lto"

enum fp_state { FP_S_ABSENT = 0, FP_S_OK, FP_S_CRASH, FP_S_TIMEOUT, FP_S_SKIP };

struct fp_obs {
    unsigned char state;
    uint64_t h1;
    uint64_t h2;
    unsigned distinct;
};

struct fp_cfg {
    const char *name;
    int driver;            /* 0 = the -O2 driver, 1 = the -O0 driver */
    unsigned fill;
    bool big_env;
};

static const struct fp_cfg k_cfg[FP_CFG_COUNT] = {
    { "A.O2.fill00",   0, 0x00u, false },
    { "B.O2.fillA5",   0, 0xA5u, false },
    { "C.O2.relocate", 0, 0x00u, true  },
    { "D.O0.fill00",   1, 0x00u, false },
    { "E.O0.fillA5",   1, 0xA5u, false }
};

/* ── process helpers ─────────────────────────────────────────────────── */

static int fp_split(char *s, char **argv, int at, int cap)
{
    char *p = s;
    while (*p != '\0' && at < cap - 1) {
        while (*p == ' ' || *p == '\t' || *p == '\n') p++;
        if (*p == '\0') break;
        argv[at++] = p;
        while (*p != '\0' && *p != ' ' && *p != '\t' && *p != '\n') p++;
        if (*p != '\0') *p++ = '\0';
    }
    argv[at] = NULL;
    return at;
}

static int fp_wait(pid_t pid)
{
    int status = 0;
    while (waitpid(pid, &status, 0) < 0) { }
    if (WIFEXITED(status))
        return WEXITSTATUS(status);
    return 128 + (WIFSIGNALED(status) ? WTERMSIG(status) : 0);
}

static pid_t fp_spawn(char *const *argv, const char *out_log, bool big_env)
{
    pid_t pid = fork();
    if (pid != 0)
        return pid;
    if (out_log != NULL) {
        int fd = open(out_log, O_WRONLY | O_CREAT | O_TRUNC, 0644);
        if (fd >= 0) {
            dup2(fd, 1);
            dup2(fd, 2);
            if (fd > 2) close(fd);
        }
    }
    if (big_env) {
        static char pad[16384];
        memset(pad, 'P', sizeof pad - 1u);
        pad[sizeof pad - 1u] = '\0';
        setenv("ZCL_FP_RELOCATE", pad, 1);
    }
    execvp(argv[0], argv);
    _exit(127);
    return -1;
}

static int fp_run(char *const *argv, const char *out_log, bool big_env)
{
    pid_t pid = fp_spawn(argv, out_log, big_env);
    if (pid < 0)
        return -1;
    return fp_wait(pid);
}

/* ── input ───────────────────────────────────────────────────────────── */

static size_t fp_read_list(const char *path, char **store, char ***outv)
{
    FILE *fh = (strcmp(path, "-") == 0) ? stdin : fopen(path, "r");
    char line[FP_MAX_PATH];
    size_t n = 0;
    char **v;

    if (fh == NULL) {
        fprintf(stderr, "fpscan: cannot open file list '%s': %s\n", path,
                strerror(errno));
        return 0;
    }
    v = (char **)zcl_calloc(FP_MAX_FILES, sizeof *v, "fp.list");
    if (v == NULL) {
        if (fh != stdin) fclose(fh);
        return 0;
    }
    while (n < FP_MAX_FILES && fgets(line, sizeof line, fh) != NULL) {
        size_t l = strlen(line);
        while (l > 0 && (line[l - 1] == '\n' || line[l - 1] == '\r')) line[--l] = '\0';
        if (l == 0)
            continue;
        v[n] = zcl_strdup(line, "fp.path");
        if (v[n] == NULL)
            break;
        n++;
    }
    if (fh != stdin)
        fclose(fh);
    *store = NULL;
    *outv = v;
    return n;
}

/* ── compile / link ──────────────────────────────────────────────────── */

struct fp_env {
    char root[FP_MAX_PATH];
    char work[FP_MAX_PATH];
    char *cc;
    char *cflags;
    char *ldflags;
    char *libs;
    char archive[FP_MAX_PATH];
    int  jobs;
};

/* Compile one probe TU. Returns the compiler's exit status; diagnostics land
 * in <work>/fp_probes_<g>.err so the pruning pass can read them. */
static pid_t fp_compile_group(const struct fp_env *e, size_t g, const char *opt,
                              const char *suffix)
{
    char *argv[FP_MAX_ARGS];
    char src[FP_MAX_PATH * 2];
    char obj[FP_MAX_PATH * 2];
    char err[FP_MAX_PATH * 2];
    char incwork[FP_MAX_PATH * 2];
    char *flags;
    int at = 0;

    snprintf(src, sizeof src, "%s/fp_probes_%zu.c", e->work, g);
    snprintf(obj, sizeof obj, "%s/fp_probes_%zu%s.o", e->work, g, suffix);
    snprintf(err, sizeof err, "%s/fp_probes_%zu%s.err", e->work, g, suffix);
    snprintf(incwork, sizeof incwork, "-I%s", e->work);
    /* Remove the object BEFORE compiling. Whether a group compiled is decided
     * downstream by whether its object exists, and the work directory
     * survives between runs — so an object left by an EARLIER run satisfies
     * that test even when this run's compile failed. The stale object then
     * goes into the link, carrying whatever unrelated unit that group held
     * last time: measured here as two probe TUs both defining
     * `register_download_queue_starved`, a "multiple definition" that named
     * a file which does not contain the symbol, and a run that died at the
     * link having measured nothing. */
    (void)unlink(obj);
    flags = zcl_strdup(e->cflags, "fp.cflags");
    if (flags == NULL)
        return -1;
    {
        char *ccwords = zcl_strdup(e->cc, "fp.cc");
        if (ccwords == NULL) return -1;
        at = fp_split(ccwords, argv, at, FP_MAX_ARGS);
    }
    at = fp_split(flags, argv, at, FP_MAX_ARGS);
    argv[at++] = (char *)opt;
    argv[at++] = (char *)"-w";
    argv[at++] = incwork;
    argv[at++] = (char *)"-c";
    argv[at++] = (char *)"-o";
    argv[at++] = obj;
    argv[at++] = src;
    argv[at] = NULL;
    return fp_spawn(argv, err, false);
}

static bool fp_group_load_map(const char *path, long *marks,
                              unsigned long *idx, size_t *nmark)
{
    FILE *fh = fopen(path, "r");
    if (fh == NULL) return false;
    char line[2048];
    *nmark = 0;
    while (*nmark < FP_MAX_CANDS && fgets(line, sizeof line, fh) != NULL) {
        unsigned long i2;
        long l2;
        if (sscanf(line, "%lu %ld", &i2, &l2) == 2) {
            idx[*nmark] = i2;
            marks[*nmark] = l2;
            (*nmark)++;
        }
    }
    fclose(fh);
    return true;
}

static long fp_group_marker(const long *marks, size_t nmark, long ln)
{
    long best = -1;
    for (size_t k = 0; k < nmark; k++)
        if (marks[k] <= ln && (best < 0 || marks[k] > marks[(size_t)best]))
            best = (long)k;
    return best;
}

/* Attribute compiler errors in one group back to individual probes. Returns
 * the number newly disabled; -1 means the whole group must go (the failure
 * was in the include block, before any probe). */
static long fp_prune_group(const struct fp_env *e, size_t g,
                           const struct fp_candidate *cands, size_t n_cands,
                           unsigned char *disabled, const char *suffix)
{
    char err[FP_MAX_PATH * 2], map[FP_MAX_PATH * 2], line[2048], tag[64];
    static long marks[FP_MAX_CANDS];
    static unsigned long idx[FP_MAX_CANDS];
    size_t nmark = 0;
    long newly = 0;
    bool any = false;
    snprintf(map, sizeof map, "%s/fp_probes_%zu.map", e->work, g);
    if (!fp_group_load_map(map, marks, idx, &nmark)) return -1;
    snprintf(err, sizeof err, "%s/fp_probes_%zu%s.err", e->work, g, suffix);
    FILE *fh = fopen(err, "r");
    if (fh == NULL) return -1;
    snprintf(tag, sizeof tag, "fp_probes_%zu.c:", g);
    while (fgets(line, sizeof line, fh) != NULL) {
        const char *p = strstr(line, tag);
        if (p == NULL || strstr(line, "error") == NULL) continue;
        long ln = strtol(p + strlen(tag), NULL, 10);
        any = true;
        long best = fp_group_marker(marks, nmark, ln);
        if (best >= 0) {
            size_t which = (size_t)idx[(size_t)best];
            if (which < n_cands && !disabled[which]) {
                disabled[which] = 1u;
                newly++;
            }
        }
    }
    fclose(fh);
    (void)cands;
    if (!any || newly == 0) return -1;
    return newly;
}

static int fp_link(const struct fp_env *e, size_t ngroups, const char *opt,
                   const char *suffix, const char *out)
{
    static char *argv[FP_MAX_ARGS];
    char (*obj)[FP_MAX_PATH * 2];
    char *ldf;
    char *libs;
    int at = 0;
    size_t g;
    int rc;
    char err[FP_MAX_PATH * 2 + 32];

    if (ngroups + 8u > (size_t)FP_MAX_ARGS / 2u) {
        fprintf(stderr, "fpscan: too many probe groups to link (%zu)\n", ngroups);
        return -1;
    }
    obj = zcl_calloc(ngroups + 4u, sizeof *obj, "fp.linkobjs");
    if (obj == NULL)
        return -1;
    ldf = zcl_strdup(e->ldflags, "fp.ldflags");
    libs = zcl_strdup(e->libs, "fp.libs");
    if (ldf == NULL || libs == NULL)
        return -1;
    {
        char *ccwords = zcl_strdup(e->cc, "fp.cc");
        if (ccwords == NULL) return -1;
        at = fp_split(ccwords, argv, at, FP_MAX_ARGS);
    }
    at = fp_split(ldf, argv, at, FP_MAX_ARGS);
    argv[at++] = (char *)opt;
    argv[at++] = (char *)"-o";
    argv[at++] = (char *)out;
    snprintf(obj[0], sizeof obj[0], "%s/fp_main%s.o", e->work, suffix);
    argv[at++] = obj[0];
    snprintf(obj[1], sizeof obj[1], "%s/fp_stubs%s.o", e->work, suffix);
    argv[at++] = obj[1];
    for (g = 0; g < ngroups; g++) {
        snprintf(obj[g + 2u], sizeof obj[0], "%s/fp_probes_%zu%s.o", e->work,
                 g, suffix);
        argv[at++] = obj[g + 2u];
    }
    argv[at++] = (char *)"-Wl,--start-group";
    argv[at++] = (char *)e->archive;
    argv[at++] = (char *)"-Wl,--end-group";
    at = fp_split(libs, argv, at, FP_MAX_ARGS);
    argv[at] = NULL;
    snprintf(err, sizeof err, "%s.link.err", out);
    rc = fp_run(argv, err, false);
    free(obj);
    return rc;
}

/* Compile one generated support unit (the driver main, the stub unit) from
 * the work directory into <stem><suffix>.o. */
static int fp_compile_support(const struct fp_env *e, const char *stem,
                              const char *opt, const char *suffix,
                              const char *extra)
{
    static char *argv[FP_MAX_ARGS];
    char src[FP_MAX_PATH * 2];
    char obj[FP_MAX_PATH * 2];
    char err[FP_MAX_PATH * 2];
    char incwork[FP_MAX_PATH * 2];
    char *flags;
    int at = 0;

    snprintf(src, sizeof src, "%s/%s.c", e->work, stem);
    snprintf(obj, sizeof obj, "%s/%s%s.o", e->work, stem, suffix);
    snprintf(err, sizeof err, "%s/%s%s.err", e->work, stem, suffix);
    snprintf(incwork, sizeof incwork, "-I%s", e->work);
    flags = zcl_strdup(e->cflags, "fp.cflags");
    if (flags == NULL)
        return -1;
    {
        char *ccw = zcl_strdup(e->cc, "fp.cc");
        if (ccw == NULL) return -1;
        at = fp_split(ccw, argv, at, FP_MAX_ARGS);
    }
    at = fp_split(flags, argv, at, FP_MAX_ARGS);
    argv[at++] = (char *)opt;
    argv[at++] = (char *)"-w";
    if (extra != NULL)
        argv[at++] = (char *)extra;
    argv[at++] = incwork;
    argv[at++] = (char *)"-c";
    argv[at++] = (char *)"-o";
    argv[at++] = obj;
    argv[at++] = src;
    argv[at] = NULL;
    return fp_run(argv, err, false);
}

/* Some undefined references belong to no candidate at all: they are symbols
 * the NODE'S OWN main() defines (`g_shutdown_requested`) or that a link
 * profile supplies, and the archive drags their users in as a side effect of
 * resolving something else entirely. Define them here as zeroed data.
 *
 * This is safe in exactly one direction, and that is why it is acceptable: a
 * probe only ever calls functions whose whole callee closure was proven pure,
 * so none of these can be reached from a probe. If one somehow were — a
 * stubbed FUNCTION whose address now points at a data object — the call
 * faults, the forked child dies, and that probe is EXCLUDED. The failure mode
 * is a lost candidate, never a wrong fingerprint. */
static bool fp_write_stubs(const struct fp_env *e, char (*names)[FP_MAX_NAME],
                           size_t n)
{
    char path[FP_MAX_PATH * 2];
    FILE *out;
    size_t i;
    snprintf(path, sizeof path, "%s/fp_stubs.c", e->work);
    out = fopen(path, "w");
    if (out == NULL)
        return false;
    fprintf(out, "/* GENERATED by cognition/modules/fingerprint. Do not edit.\n"
                 " * Zeroed definitions for symbols owned by the node's own\n"
                 " * main(), which this driver replaces. Unreachable from any\n"
                 " * probe by construction; see fingerprint_scan.c. */\n");
    fprintf(out, "unsigned char fp_stub_present = 1;\n");
    for (i = 0; i < n; i++)
        fprintf(out, "__attribute__((aligned(16))) unsigned char %s[64];\n",
                names[i]);
    return fclose(out) == 0;
}

static bool fp_undefined_name(const char *line, char name[FP_MAX_NAME])
{
    const char *p = strstr(line, "undefined reference to ");
    if (p == NULL) return false;
    p += strlen("undefined reference to ");
    while (*p == '`' || *p == '\'' || *p == '"') p++;
    size_t k = 0;
    while (p[k] != '\0' && (isalnum((unsigned char)p[k]) || p[k] == '_') &&
           k + 1u < FP_MAX_NAME) {
        name[k] = p[k];
        k++;
    }
    name[k] = '\0';
    return k != 0;
}

static bool fp_name_seen(char (*names)[FP_MAX_NAME], size_t n, const char *name)
{
    for (size_t j = 0; j < n; j++)
        if (strcmp(names[j], name) == 0) return true;
    return false;
}

static size_t fp_collect_undefined(const char *errpath,
                                   char (*names)[FP_MAX_NAME], size_t n,
                                   size_t cap)
{
    FILE *fh = fopen(errpath, "r");
    char line[4096];
    if (fh == NULL) return n;
    while (fgets(line, sizeof line, fh) != NULL) {
        char name[FP_MAX_NAME];
        if (n >= cap || !fp_undefined_name(line, name)) continue;
        if (fp_name_seen(names, n, name)) continue;
        snprintf(names[n], FP_MAX_NAME, "%s", name);
        n++;
    }
    fclose(fh);
    return n;
}

/* Undefined references are the link-time twin of a compile error: the
 * candidate exists in source but not in the object tree this build produced
 * (a `contexts/commons/packages/` unit outside the node's own build). Disable exactly those
 * candidates rather than losing the whole run. Returns how many were newly
 * disabled.
 *
 * Two attributions, in order, and the order is what keeps the accounting
 * honest:
 *
 *  - BY NAME, but only against a candidate the harness calls through a
 *    HEADER. A source-included candidate is compiled into the probe's own
 *    translation unit, so it can never be the undefined symbol; matching it
 *    by name would blame an innocent probe for somebody else's missing
 *    object — and, because `static` helpers share short names across the
 *    tree, would blame several at once and drag the whole-run refusal below
 *    with it.
 *  - BY PROBE, from the `in function 'fp_p_<N>'` line the linker prints
 *    above the reference. That is exact, survives LTO renaming the object
 *    file to an ltrans temporary, and is the only attribution available when
 *    the missing symbol is something a source-included unit calls rather
 *    than the candidate itself. */
struct fp_link_prune_state {
    const struct fp_candidate *cands;
    size_t n_cands;
    unsigned char *disabled;
    const size_t *gof;
    unsigned char *dirty;
    long newly, in_probe, in_group;
};

static void fp_link_disable(struct fp_link_prune_state *s, size_t i)
{
    s->disabled[i] = 1u;
    s->dirty[s->gof[i]] = 1u;
    s->newly++;
}

static void fp_link_multiple(struct fp_link_prune_state *s)
{
    for (size_t c = 0; c < s->n_cands; c++)
        if (!s->disabled[c] && s->cands[c].via_source &&
            s->gof[c] == (size_t)s->in_group)
            fp_link_disable(s, c);
}

static void fp_link_context(struct fp_link_prune_state *s, const char *line,
                            const char *p)
{
    const char *o = strstr(line, "fp_probes_");
    s->in_group = o ? strtol(o + strlen("fp_probes_"), NULL, 10) : -1;
    p += strlen("in function `");
    s->in_probe = strncmp(p, "fp_p_", 5) == 0 ? strtol(p + 5, NULL, 10) : -1;
}

static void fp_link_undefined(struct fp_link_prune_state *s, const char *name)
{
    bool hit = false;
    for (size_t c = 0; c < s->n_cands; c++)
        if (!s->disabled[c] && !s->cands[c].via_source &&
            strcmp(s->cands[c].name, name) == 0) {
            fp_link_disable(s, c);
            hit = true;
        }
    if (hit) return;
    if (s->in_probe >= 0 && (size_t)s->in_probe < s->n_cands &&
        !s->disabled[(size_t)s->in_probe])
        fp_link_disable(s, (size_t)s->in_probe);
}

static long fp_prune_link(const char *errpath, const struct fp_candidate *cands,
                          size_t n_cands, unsigned char *disabled,
                          const size_t *gof, unsigned char *dirty)
{
    FILE *fh = fopen(errpath, "r");
    if (fh == NULL) return 0;
    struct fp_link_prune_state state = {
        .cands = cands, .n_cands = n_cands, .disabled = disabled,
        .gof = gof, .dirty = dirty, .in_probe = -1, .in_group = -1,
    };
    char line[4096];
    while (fgets(line, sizeof line, fh) != NULL) {
        /* The prior referencing group owns a multiple-definition error. */
        if (strstr(line, "multiple definition of ") != NULL && state.in_group >= 0) {
            fp_link_multiple(&state);
            continue;
        }
        const char *p = strstr(line, "in function `");
        if (p != NULL) {
            /* A nonprobe function clears the previous probe attribution. */
            fp_link_context(&state, line, p);
            continue;
        }
        char name[FP_MAX_NAME];
        if (fp_undefined_name(line, name)) fp_link_undefined(&state, name);
    }
    fclose(fh);
    return state.newly;
}

/* ── result parsing ──────────────────────────────────────────────────── */

static void fp_parse_results(const char *path, struct fp_obs *obs, size_t cap)
{
    FILE *fh = fopen(path, "r");
    char line[1024];
    if (fh == NULL)
        return;
    while (fgets(line, sizeof line, fh) != NULL) {
        unsigned long i;
        char verb[32];
        char hex[64];
        unsigned d = 0;
        if (sscanf(line, "%lu %31s", &i, verb) != 2 || i >= cap)
            continue;
        if (strcmp(verb, "OK") == 0) {
            if (sscanf(line, "%lu %31s %63s %u", &i, verb, hex, &d) != 4)
                continue;
            if (strlen(hex) != 32u)
                continue;
            obs[i].state = FP_S_OK;
            obs[i].distinct = d;
            {
                char half[17];
                memcpy(half, hex, 16); half[16] = '\0';
                obs[i].h1 = strtoull(half, NULL, 16);
                memcpy(half, hex + 16, 16); half[16] = '\0';
                obs[i].h2 = strtoull(half, NULL, 16);
            }
        } else if (strcmp(verb, "CRASH") == 0) {
            obs[i].state = FP_S_CRASH;
        } else if (strcmp(verb, "TIMEOUT") == 0) {
            obs[i].state = FP_S_TIMEOUT;
        } else if (strcmp(verb, "SKIP") == 0 || strcmp(verb, "ERR") == 0) {
            obs[i].state = FP_S_SKIP;
        }
        /* Anything else is not a result row and is IGNORED rather than
         * recorded. Treating an unrecognised line as a verdict is how a
         * stray diagnostic overwrites a real probe's observation with
         * "skipped" and quietly shrinks the coverage number. */
    }
    fclose(fh);
}

/* ── reporting ───────────────────────────────────────────────────────── */

struct fp_final {
    unsigned char status;   /* see below */
    uint64_t h1;
    uint64_t h2;
    unsigned distinct;
};

#define FP_F_COMPILE   0
#define FP_F_CRASH     1
#define FP_F_TIMEOUT   2
#define FP_F_UNSTABLE  3
#define FP_F_FLAT      4
#define FP_F_GOOD      5
#define FP_F_COUNT     6

static const char *const k_final_name[] = {
    "did-not-compile", "crashed-on-generated-input", "timed-out",
    "FALSE PURITY (unstable across configurations)",
    "constant on the whole corpus (not discriminated)", "fingerprinted"
};

static int fp_cmp_idx(const void *a, const void *b);

static const struct fp_candidate *g_cands;
static const struct fp_final *g_final;

static int fp_cmp_idx(const void *a, const void *b)
{
    size_t x = *(const size_t *)a;
    size_t y = *(const size_t *)b;
    if (g_cands[x].shape != g_cands[y].shape)
        return g_cands[x].shape < g_cands[y].shape ? -1 : 1;
    if (g_final[x].h1 != g_final[y].h1)
        return g_final[x].h1 < g_final[y].h1 ? -1 : 1;
    if (g_final[x].h2 != g_final[y].h2)
        return g_final[x].h2 < g_final[y].h2 ? -1 : 1;
    return strcmp(g_cands[x].name, g_cands[y].name);
}

struct fp_scan_state {
    struct fp_env env;
    struct fp_index *ix;
    struct fp_candidate *cands;
    struct fp_final *final;
    struct fp_obs *obs, *confirm;
    unsigned char *disabled, *need_confirm;
    size_t tally[FP_V_COUNT];
    char **files;
    char jobsarg[32];
    char *store;
    size_t nfiles, ngroups, total_defs;
    long ncands;
    bool select_only, no_source;
    const char *list;
};

static bool fp_option_first(struct fp_scan_state *s, const char *a)
{
    if (strncmp(a, "--root=", 7) == 0)
        snprintf(s->env.root, sizeof s->env.root, "%s", a + 7);
    else if (strncmp(a, "--work=", 7) == 0)
        snprintf(s->env.work, sizeof s->env.work, "%s", a + 7);
    else if (strncmp(a, "--cc=", 5) == 0)
        s->env.cc = zcl_strdup(a + 5, "fp.cc");
    else if (strncmp(a, "--archive=", 10) == 0)
        snprintf(s->env.archive, sizeof s->env.archive, "%s", a + 10);
    else if (strncmp(a, "--cflags=", 9) == 0)
        s->env.cflags = zcl_strdup(a + 9, "fp.cflags");
    else return false;
    return true;
}

static int fp_option_rest(struct fp_scan_state *s, const char *a)
{
    if (strncmp(a, "--ldflags=", 10) == 0)
        s->env.ldflags = zcl_strdup(a + 10, "fp.ldflags");
    else if (strncmp(a, "--libs=", 7) == 0)
        s->env.libs = zcl_strdup(a + 7, "fp.libs");
    else if (strncmp(a, "--files-from=", 13) == 0)
        s->list = a + 13;
    else if (strncmp(a, "--jobs=", 7) == 0)
        s->env.jobs = atoi(a + 7);
    else if (strcmp(a, "--select-only") == 0)
        s->select_only = true;
    else if (strcmp(a, "--no-source-include") == 0)
        s->no_source = true;
    else {
        fprintf(stderr, "fpscan: unknown argument '%s'\n", a);
        return 2;
    }
    return 0;
}

static int fp_options(struct fp_scan_state *s, int argc, char **argv)
{
    int c;
    memset(&s->env, 0, sizeof s->env);
    snprintf(s->env.root, sizeof s->env.root, "%s", ".");
    snprintf(s->env.work, sizeof s->env.work, "%s", "build/fingerprint");
    s->env.cc = zcl_strdup("cc", "fp.cc");
    s->env.jobs = 8;
    s->env.cflags = zcl_strdup("", "fp.cflags");
    s->env.ldflags = zcl_strdup("", "fp.ldflags");
    s->env.libs = zcl_strdup("", "fp.libs");
    if (s->env.cflags == NULL || s->env.ldflags == NULL || s->env.libs == NULL)
        return 2;

    for (c = 1; c < argc; c++) {
        const char *a = argv[c];
        if (!fp_option_first(s, a) && fp_option_rest(s, a) != 0) return 2;
    }
    if (s->env.cflags == NULL || s->env.ldflags == NULL || s->env.libs == NULL)
        return 2;
    if (s->env.jobs < 1) s->env.jobs = 1;

    return 0;
}

static int fp_select(struct fp_scan_state *s)
{
    s->nfiles = fp_read_list(s->list, &s->store, &s->files);
    if (s->nfiles == 0) {
        fprintf(stderr, "fpscan: empty source list — refusing to report a "
                        "coverage number over nothing\n");
        return 2;
    }
    s->ix = fp_index_build(s->env.root, (const char *const *)s->files, s->nfiles);
    if (s->ix == NULL) {
        fprintf(stderr, "fpscan: index build failed\n");
        return 2;
    }
    fp_index_allow_source_route(s->ix, !s->no_source);
    s->cands = (struct fp_candidate *)zcl_calloc(FP_MAX_CANDS, sizeof *s->cands,
                                              "fp.cands");
    if (s->cands == NULL) { fp_index_free(s->ix); return 2; }
    s->ncands = fp_index_select(s->ix, s->cands, FP_MAX_CANDS, s->tally);
    if (s->ncands < 0) {
        fprintf(stderr, "fpscan: candidate selection failed\n");
        fp_index_free(s->ix);
        return 2;
    }
    s->total_defs = fp_index_function_count(s->ix);

    return 0;
}

static int fp_coverage(struct fp_scan_state *s)
{
    long i;
    printf("== fingerprint coverage ==\n");
    printf("source files scanned          %zu\n", s->nfiles);
    printf("function definitions found    %zu\n", s->total_defs);
    for (i = 0; i < FP_V_COUNT; i++)
        printf("  %-46s %8zu  %5.2f%%\n", fp_verdict_text((enum fp_verdict)i),
               s->tally[i],
               s->total_defs ? 100.0 * (double)s->tally[i] / (double)s->total_defs : 0.0);
    printf("candidates emitted            %ld\n", s->ncands);
    {
        long via_src = 0;
        for (i = 0; i < s->ncands; i++)
            if (s->cands[i].via_source)
                via_src++;
        printf("  through a header prototype  %8ld\n", s->ncands - via_src);
        printf("  by including the defining unit (file-local) %8ld\n", via_src);
    }
    {
        static const enum fp_verdict interesting[] = {
            FP_V_UNRESOLVED_CALL, FP_V_IMPURE_GLOBAL, FP_V_FUNCTION_POINTER,
            FP_V_FUNCTION_STATIC, FP_V_STATIC_LINKAGE, FP_V_NO_PROTOTYPE
        };
        size_t w;
        for (w = 0; w < sizeof interesting / sizeof interesting[0]; w++) {
            char names[8][FP_MAX_NAME];
            size_t counts[8];
            int got = fp_index_top_causes(s->ix, interesting[w], names, counts, 8);
            int k;
            if (got <= 0)
                continue;
            printf("  top causes of \"%s\":\n",
                   fp_verdict_text(interesting[w]));
            for (k = 0; k < got; k++)
                printf("      %-40s %6zu\n", names[k], counts[k]);
        }
    }
    fflush(stdout);

    return 0;
}

static void fp_print_selection(struct fp_scan_state *s)
{
    for (long i = 0; i < s->ncands; i++)
        printf("CAND %s %s:%d %s %s\n", s->cands[i].name, s->cands[i].def_path,
               s->cands[i].def_line, s->cands[i].shape_text, s->cands[i].include);
    fp_index_free(s->ix);
}

static int fp_prepare(struct fp_scan_state *s)
{
    {
        char cmd[FP_MAX_PATH * 2];
        snprintf(cmd, sizeof cmd, "%s", s->env.work);
        if (mkdir(cmd, 0755) != 0 && errno != EEXIST) {
            fprintf(stderr, "fpscan: cannot create %s: %s\n", cmd,
                    strerror(errno));
            fp_index_free(s->ix);
            return 2;
        }
    }

    s->disabled = (unsigned char *)zcl_calloc((size_t)s->ncands ? (size_t)s->ncands : 1u,
                                           1u, "fp.disabled");
    if (s->disabled == NULL) { fp_index_free(s->ix); return 2; }
    if (!fp_emit_harness(s->cands, (size_t)s->ncands, s->env.work, s->disabled, &s->ngroups)) {
        fprintf(stderr, "fpscan: harness emission failed\n");
        fp_index_free(s->ix);
        return 2;
    }
    printf("probe translation units       %zu\n", s->ngroups);
    fflush(stdout);

    return 0;
}

struct fp_build_state {
    size_t *gof;
    unsigned char *dirty;
    char (*stubs)[FP_MAX_NAME];
    size_t nstubs;
    char out0[FP_MAX_PATH * 2], out1[FP_MAX_PATH * 2];
};

static int fp_build_init(struct fp_scan_state *s, struct fp_build_state *b)
{
    static char stubs[4096][FP_MAX_NAME];
    b->stubs = stubs;
    snprintf(b->out0, sizeof b->out0, "%s/fp_driver_O2", s->env.work);
    snprintf(b->out1, sizeof b->out1, "%s/fp_driver_O0", s->env.work);
    if (!fp_write_stubs(&s->env, b->stubs, b->nstubs)) {
        fprintf(stderr, "fpscan: cannot write the generated stub unit\n");
        fp_index_free(s->ix);
        return 2;
    }
    b->gof = (size_t *)zcl_calloc((size_t)s->ncands + 1u, sizeof *b->gof, "fp.gof");
    b->dirty = (unsigned char *)zcl_calloc(s->ngroups + 1u, 1u, "fp.dirty");
    if (b->gof == NULL || b->dirty == NULL) { fp_index_free(s->ix); return 2; }
    size_t g = 0;
    for (size_t k = 0; k < (size_t)s->ncands; k++) {
        if (k > 0 && strcmp(s->cands[k].include, s->cands[k - 1].include) != 0)
            g++;
        b->gof[k] = g;
    }
    memset(b->dirty, 1, s->ngroups);
    return 0;
}

static int fp_compile_round(struct fp_scan_state *s, struct fp_build_state *b)
{
    if (!fp_emit_harness(s->cands, (size_t)s->ncands, s->env.work, s->disabled,
                         &s->ngroups)) {
        fprintf(stderr, "fpscan: harness emission failed\n");
        fp_index_free(s->ix);
        return 2;
    }
    pid_t *pool = (pid_t *)zcl_calloc((size_t)s->env.jobs + 1u, sizeof *pool, "fp.pool");
    if (pool == NULL) { fp_index_free(s->ix); return 2; }
    for (int v = 0; v < 2; v++) {
        const char *opt = (v == 0) ? "-O2" : "-O0";
        const char *sfx = (v == 0) ? "" : ".o0";
        size_t inflight = 0;
        for (size_t g = 0; g < s->ngroups; g++) {
            if (!b->dirty[g]) continue;
            pool[inflight++] = fp_compile_group(&s->env, g, opt, sfx);
            if ((int)inflight >= s->env.jobs) {
                for (size_t k = 0; k < inflight; k++) fp_wait(pool[k]);
                inflight = 0;
            }
        }
        for (size_t k = 0; k < inflight; k++) fp_wait(pool[k]);
        if (fp_compile_support(&s->env, "fp_main", opt, sfx, NULL) != 0 ||
            fp_compile_support(&s->env, "fp_stubs", opt, sfx, FP_STUB_CFLAG) != 0) {
            fprintf(stderr, "fpscan: a generated support unit did not compile at %s\n", opt);
            fp_index_free(s->ix);
            return 2;
        }
    }
    free(pool);
    return 0;
}

static long fp_prune_failed_group(struct fp_scan_state *s, struct fp_build_state *b,
                                  size_t g, long *failed)
{
    char obj0[FP_MAX_PATH * 2], obj1[FP_MAX_PATH * 2];
    struct stat st;
    if (!b->dirty[g]) return 0;
    snprintf(obj0, sizeof obj0, "%s/fp_probes_%zu.o", s->env.work, g);
    snprintf(obj1, sizeof obj1, "%s/fp_probes_%zu.o0.o", s->env.work, g);
    if (stat(obj0, &st) == 0 && stat(obj1, &st) == 0) {
        b->dirty[g] = 0u;
        return 0;
    }
    (*failed)++;
    long n = fp_prune_group(&s->env, g, s->cands, (size_t)s->ncands, s->disabled, "");
    if (n > 0) return n;
    long pruned = 0;
    for (size_t k = 0; k < (size_t)s->ncands; k++)
        if (b->gof[k] == g && !s->disabled[k]) {
            s->disabled[k] = 1u;
            pruned++;
        }
    return pruned;
}

static bool fp_prune_compile_round(struct fp_scan_state *s, struct fp_build_state *b,
                                   int round)
{
    long failed = 0, pruned = 0;
    for (size_t g = 0; g < s->ngroups; g++)
        pruned += fp_prune_failed_group(s, b, g, &failed);
    if (failed == 0) return false;
    printf("compile round %d: %ld group(s) refused, %ld probe(s) excluded\n",
           round, failed, pruned);
    fflush(stdout);
    return true;
}

/* Returns 0 on success, 1 to retry, and 2 on refusal. */
static int fp_link_one(struct fp_scan_state *s, struct fp_build_state *b,
                       int round, int which)
{
    const char *opt = which == 0 ? "-O2" : "-O0";
    const char *sfx = which == 0 ? "" : ".o0";
    const char *out = which == 0 ? b->out0 : b->out1;
    char errp[FP_MAX_PATH * 2 + 32];
    if (fp_link(&s->env, s->ngroups, opt, sfx, out) == 0) return 0;
    snprintf(errp, sizeof errp, "%s.link.err", out);
    long n = fp_prune_link(errp, s->cands, (size_t)s->ncands, s->disabled,
                           b->gof, b->dirty);
    if (n > (long)s->ncands / 2) {
        fprintf(stderr, "fpscan: link pruning blamed %ld of "
                "%ld probes in one round. That is an "
                "environment failure, not a candidate "
                "failure (check that the link flags still "
                "carry -flto, since $(OBJ_DIR) holds slim "
                "LTO objects). See %s\n", n, s->ncands, errp);
        fp_index_free(s->ix);
        return 2;
    }
    if (n > 0) {
        printf("link round %d: %ld probe(s) excluded (undefined reference)\n", round, n);
        fflush(stdout);
        return 1;
    }
    size_t before = b->nstubs;
    b->nstubs = fp_collect_undefined(errp, b->stubs, b->nstubs, 4096);
    if (b->nstubs == before) {
        fprintf(stderr, "fpscan: the %s driver did not link, "
                "and the failure is not an undefined reference; see %s\n", opt, errp);
        fp_index_free(s->ix);
        return 2;
    }
    if (!fp_write_stubs(&s->env, b->stubs, b->nstubs)) {
        fp_index_free(s->ix);
        return 2;
    }
    printf("link round %d: %zu symbol(s) owned by the node's own main() stubbed\n",
           round, b->nstubs - before);
    fflush(stdout);
    if (fp_compile_support(&s->env, "fp_stubs", "-O2", "", FP_STUB_CFLAG) != 0 ||
        fp_compile_support(&s->env, "fp_stubs", "-O0", ".o0", FP_STUB_CFLAG) != 0) {
        fprintf(stderr, "fpscan: the generated stub unit did not compile\n");
        fp_index_free(s->ix);
        return 2;
    }
    return 1;
}

static int fp_build_harness(struct fp_scan_state *s)
{
    struct fp_build_state b = {0};
    if (fp_build_init(s, &b) != 0) return 2;
    bool built = false;
    for (int round = 0; round < FP_PRUNE_ROUNDS; round++) {
        if (fp_compile_round(s, &b) != 0) return 2;
        if (fp_prune_compile_round(s, &b, round)) continue;
        int result = fp_link_one(s, &b, round, 0);
        if (result == 2) return 2;
        if (result == 1) continue;
        result = fp_link_one(s, &b, round, 1);
        if (result == 2) return 2;
        if (result == 1) continue;
        built = true;
        break;
    }
    free(b.gof);
    free(b.dirty);
    if (!built) {
        fprintf(stderr, "fpscan: the harness did not converge in %d "
                "rounds; refusing to report partial results\n", FP_PRUNE_ROUNDS);
        fp_index_free(s->ix);
        return 2;
    }
    return 0;
}

static int fp_observe(struct fp_scan_state *s)
{
    long i;
    s->obs = (struct fp_obs *)zcl_calloc((size_t)s->ncands * FP_CFG_COUNT + 1u,
                                      sizeof *s->obs, "fp.obs");
    s->confirm = (struct fp_obs *)zcl_calloc((size_t)s->ncands + 1u, sizeof *s->confirm,
                                          "fp.confirm");
    s->final = (struct fp_final *)zcl_calloc((size_t)s->ncands + 1u, sizeof *s->final,
                                          "fp.final");
    s->need_confirm = (unsigned char *)zcl_calloc((size_t)s->ncands + 1u, 1u,
                                               "fp.needconfirm");
    if (s->obs == NULL || s->confirm == NULL || s->final == NULL ||
        s->need_confirm == NULL)
        return 2;

    snprintf(s->jobsarg, sizeof s->jobsarg, "--jobs=%d", s->env.jobs);

    for (i = 0; i < FP_CFG_COUNT; i++) {
        char *rargv[16];
        char drv[FP_MAX_PATH * 2];
        char res[FP_MAX_PATH * 2];
        char log[FP_MAX_PATH * 2];
        char outarg[FP_MAX_PATH * 2 + 8];
        char fill[32];
        char iters[32];
        int at = 0;
        snprintf(drv, sizeof drv, "%s/fp_driver_%s", s->env.work,
                 k_cfg[i].driver == 0 ? "O2" : "O0");
        /* Results and NOISE go to two different files. See the driver's
         * main(): a probe compiled against a whole tree unit can print, and a
         * printed line sharing the result stream is parsed as a result. */
        snprintf(res, sizeof res, "%s/res_%s.txt", s->env.work, k_cfg[i].name);
        snprintf(log, sizeof log, "%s/run_%s.txt", s->env.work, k_cfg[i].name);
        snprintf(outarg, sizeof outarg, "--out=%s", res);
        snprintf(fill, sizeof fill, "--fill=%u", k_cfg[i].fill);
        snprintf(iters, sizeof iters, "--iters=%u", (unsigned)FP_ITERATIONS);
        rargv[at++] = drv;
        rargv[at++] = fill;
        rargv[at++] = iters;
        rargv[at++] = (char *)"--salt=0";
        rargv[at++] = (char *)"--timeout=5";
        rargv[at++] = s->jobsarg;
        rargv[at++] = outarg;
        rargv[at] = NULL;
        if (fp_run(rargv, log, k_cfg[i].big_env) != 0)
            fprintf(stderr, "fpscan: driver run %s exited non-zero\n",
                    k_cfg[i].name);
        fp_parse_results(res, s->obs + (size_t)i * (size_t)s->ncands, (size_t)s->ncands);
    }

    return 0;
}

static int fp_classify_candidate(struct fp_scan_state *s, long i)
{
    const struct fp_obs *a = &s->obs[(size_t)i];
    int status = FP_F_GOOD;
    if (s->disabled[i]) status = FP_F_COMPILE;
    else for (int cfg = 0; cfg < FP_CFG_COUNT; cfg++) {
        const struct fp_obs *o = &s->obs[(size_t)cfg * (size_t)s->ncands + (size_t)i];
        if (o->state == FP_S_CRASH) { status = FP_F_CRASH; break; }
        if (o->state == FP_S_TIMEOUT) { status = FP_F_TIMEOUT; break; }
        if (o->state != FP_S_OK) { status = FP_F_COMPILE; break; }
        if (o->h1 != a->h1 || o->h2 != a->h2) { status = FP_F_UNSTABLE; break; }
    }
    if (status == FP_F_GOOD && a->distinct < FP_MIN_DISTINCT)
        status = FP_F_FLAT;
    s->final[i].status = status;
    if (status == FP_F_GOOD) {
        s->final[i].h1 = a->h1;
        s->final[i].h2 = a->h2;
        s->final[i].distinct = a->distinct;
    }
    return status;
}

static int fp_classify(struct fp_scan_state *s)
{
    long i;
    /* Fold the configurations into one verdict per candidate. */
    {
        long counts[FP_F_COUNT] = {0};
        for (i = 0; i < s->ncands; i++)
            counts[fp_classify_candidate(s, i)]++;
        printf("\n== empirical filter ==\n");
        for (i = 0; i < FP_F_COUNT; i++)
            printf("  %-48s %8ld\n", k_final_name[i], counts[i]);
        long good = counts[FP_F_GOOD];
        long flat = counts[FP_F_FLAT];
        long unstable = counts[FP_F_UNSTABLE];
        /* The same partition split by HOW the probe reached its function.
         * Including a whole translation unit is the risky route and it has
         * to be possible to see, run by run, what it actually costs: a
         * source-included unit that will not compile or will not link takes
         * every candidate in it, and that has to show up as a number rather
         * than as a quietly smaller coverage figure. */
        {
            long by_route[2][FP_F_COUNT];
            long total[2] = { 0, 0 };
            int r;
            memset(by_route, 0, sizeof by_route);
            for (i = 0; i < s->ncands; i++) {
                int r2 = s->cands[i].via_source ? 1 : 0;
                by_route[r2][s->final[i].status]++;
                total[r2]++;
            }
            printf("  by route (header-reached / file-local, unit included):\n");
            for (r = 0; r < FP_F_COUNT; r++)
                printf("      %-46s %8ld %8ld\n", k_final_name[r],
                       by_route[0][r], by_route[1][r]);
            printf("      %-46s %8ld %8ld\n", "candidates on this route",
                   total[0], total[1]);
        }
        printf("fingerprintable functions     %ld  (%.3f%% of %zu definitions)\n",
               good, s->total_defs ? 100.0 * (double)good / (double)s->total_defs : 0.0,
               s->total_defs);
        {
            long judged = good + flat + unstable;
            printf("MEASURED FALSE-PURITY RATE    %ld / %ld = %.2f%%\n",
                   unstable, judged,
                   judged ? 100.0 * (double)unstable / (double)judged : 0.0);
        }
    }

    return 0;
}

static int fp_select_confirmation(struct fp_scan_state *s)
{
    long i;
    /* Which candidates corpus B actually has to re-test: exactly those that
     * share a (shape, fingerprint) with another candidate. A lone
     * fingerprint is not a claim about anything, so re-testing it on a
     * corpus 32x larger answers a question nobody asked. */
    {
        size_t *order = (size_t *)zcl_calloc((size_t)s->ncands + 1u, sizeof *order,
                                             "fp.preorder");
        size_t n = 0;
        size_t start;
        if (order == NULL) { fp_index_free(s->ix); return 2; }
        for (i = 0; i < s->ncands; i++)
            if (s->final[i].status == FP_F_GOOD)
                order[n++] = (size_t)i;
        g_cands = s->cands;
        g_final = s->final;
        if (n > 1)
            qsort(order, n, sizeof *order, fp_cmp_idx);
        for (start = 0; start < n; ) {
            size_t e2 = start + 1u;
            while (e2 < n &&
                   s->cands[order[e2]].shape == s->cands[order[start]].shape &&
                   s->final[order[e2]].h1 == s->final[order[start]].h1 &&
                   s->final[order[e2]].h2 == s->final[order[start]].h2)
                e2++;
            if (e2 - start >= 2u) {
                size_t k;
                for (k = start; k < e2; k++)
                    s->need_confirm[order[k]] = 1u;
            }
            start = e2;
        }
        free(order);
    }

    return 0;
}

static int fp_confirm(struct fp_scan_state *s)
{
    long i;
    /* Corpus B: a disjoint, 32x larger input set used only to re-test the
     * matches the first corpus produced. It runs LAST and it runs NARROW.
     * Last, because which candidates it must re-test is not knowable until
     * the five configurations have been folded into a verdict; narrow,
     * because at 32x the iterations it costs HOURS over the whole candidate
     * set — measured, once file-local functions made that set three times
     * bigger — and its answer is only ever read for a candidate that landed
     * in a match group. Narrowing changes no verdict: every index the
     * reporting pass consults is in the list handed to the driver. */
    {
        char *rargv[16];
        char drv[FP_MAX_PATH * 2];
        char res[FP_MAX_PATH * 2];
        char log[FP_MAX_PATH * 2];
        char sel[FP_MAX_PATH * 2];
        char outarg[FP_MAX_PATH * 2 + 8];
        char onlyarg[FP_MAX_PATH * 2 + 8];
        char salt[64];
        char iters[32];
        int at = 0;
        long nsel = 0;
        FILE *fh;

        snprintf(sel, sizeof sel, "%s/confirm_only.txt", s->env.work);
        fh = fopen(sel, "w");
        if (fh == NULL) {
            fprintf(stderr, "fpscan: cannot write the confirm selection\n");
            fp_index_free(s->ix);
            return 2;
        }
        for (i = 0; i < s->ncands; i++)
            if (s->need_confirm[i]) { fprintf(fh, "%ld\n", i); nsel++; }
        if (fclose(fh) != 0) { fp_index_free(s->ix); return 2; }
        printf("corpus B re-tests               %ld of %ld candidates\n",
               nsel, s->ncands);
        fflush(stdout);

        snprintf(drv, sizeof drv, "%s/fp_driver_O2", s->env.work);
        snprintf(res, sizeof res, "%s/res_confirm.txt", s->env.work);
        snprintf(log, sizeof log, "%s/run_confirm.txt", s->env.work);
        snprintf(outarg, sizeof outarg, "--out=%s", res);
        snprintf(onlyarg, sizeof onlyarg, "--only=%s", sel);
        snprintf(salt, sizeof salt, "--salt=%llu",
                 (unsigned long long)FP_CONFIRM_SALT);
        snprintf(iters, sizeof iters, "--iters=%u",
                 (unsigned)FP_CONFIRM_ITERATIONS);
        rargv[at++] = drv;
        rargv[at++] = (char *)"--fill=0";
        rargv[at++] = iters;
        rargv[at++] = salt;
        rargv[at++] = (char *)"--timeout=30";
        rargv[at++] = s->jobsarg;
        rargv[at++] = onlyarg;
        rargv[at++] = outarg;
        rargv[at] = NULL;
        (void)fp_run(rargv, log, false);
        fp_parse_results(res, s->confirm, (size_t)s->ncands);
    }

    return 0;
}

struct fp_report_state {
    size_t *order;
    size_t n;
    long pairs_a, pairs_tested, pairs_false;
    long groups_reported, groups_rejected, groups_weak;
};

static size_t fp_group_end(const struct fp_scan_state *s,
                           const struct fp_report_state *r, size_t start)
{
    size_t end = start + 1u;
    while (end < r->n &&
           s->cands[r->order[end]].shape == s->cands[r->order[start]].shape &&
           s->final[r->order[end]].h1 == s->final[r->order[start]].h1 &&
           s->final[r->order[end]].h2 == s->final[r->order[start]].h2)
        end++;
    return end;
}

static bool fp_group_confirmed(const struct fp_scan_state *s,
                               const struct fp_report_state *r,
                               size_t start, size_t end, bool *any_missing)
{
    bool all_conf = true;
    for (size_t k = start; k < end; k++) {
        const struct fp_obs *cb = &s->confirm[r->order[k]];
        if (cb->state != FP_S_OK) { *any_missing = true; continue; }
        if (cb->h1 != s->confirm[r->order[start]].h1 ||
            cb->h2 != s->confirm[r->order[start]].h2)
            all_conf = false;
    }
    return all_conf;
}

static void fp_report_group(struct fp_scan_state *s, struct fp_report_state *r,
                            size_t start, size_t end, int pass)
{
    bool distinct_impl = false;
    for (size_t k = start + 1u; k < end; k++)
        if (strcmp(s->cands[r->order[k]].name, s->cands[r->order[start]].name) != 0)
            distinct_impl = true;
    long pairs = (long)((end - start) * (end - start - 1u) / 2u);
    if (pass == 0) r->pairs_a += pairs;
    if (!distinct_impl) return;
    bool weak = s->final[r->order[start]].distinct < FP_REPORT_MIN_DISTINCT;
    if ((pass == 0) == weak) return;

    bool any_missing = false;
    bool all_conf = fp_group_confirmed(s, r, start, end, &any_missing);
    if (!any_missing) r->pairs_tested += pairs;
    if (!all_conf) {
        r->pairs_false += pairs;
        r->groups_rejected++;
        return;
    }
    if (pass == 0) r->groups_reported++;
    else r->groups_weak++;
    printf("\n[%s] fingerprint %016llx%016llx  shape %s\n",
           weak ? "WEAK" : (any_missing ? "UNCONFIRMED" : "CONFIRMED"),
           (unsigned long long)s->final[r->order[start]].h1,
           (unsigned long long)s->final[r->order[start]].h2,
           s->cands[r->order[start]].shape_text);
    printf("  evidence: %u inputs (corpus A) + %u inputs "
           "(corpus B); %u distinct observed outputs%s\n",
           (unsigned)FP_ITERATIONS,
           any_missing ? 0u : (unsigned)FP_CONFIRM_ITERATIONS,
           s->final[r->order[start]].distinct,
           s->final[r->order[start]].distinct <= 2u
               ? "  [LOW ENTROPY — weak evidence]" : "");
    for (size_t k = start; k < end; k++)
        printf("    %s  %s:%d\n", s->cands[r->order[k]].name,
               s->cands[r->order[k]].def_path, s->cands[r->order[k]].def_line);
}

static void fp_report_pass(struct fp_scan_state *s, struct fp_report_state *r, int pass)
{
    if (pass == 1)
        printf("\n== below the evidence bar — NOT candidates (fewer than "
               "%u distinct outputs over the whole corpus, so the match "
               "carries no information) ==\n", (unsigned)FP_REPORT_MIN_DISTINCT);
    for (size_t start = 0; start < r->n; ) {
        size_t end = fp_group_end(s, r, start);
        if (end - start >= 2u) fp_report_group(s, r, start, end, pass);
        start = end;
    }
    if (pass == 0 && r->groups_reported == 0)
        printf("  none: no two DIFFERENTLY-NAMED fingerprintable functions "
               "agreed on enough inputs to say anything\n");
}

static int fp_report(struct fp_scan_state *s)
{
    struct fp_report_state r = {0};
    r.order = (size_t *)zcl_calloc((size_t)s->ncands + 1u, sizeof *r.order, "fp.order");
    if (r.order == NULL) return 2;
    for (long i = 0; i < s->ncands; i++)
        if (s->final[i].status == FP_F_GOOD)
            r.order[r.n++] = (size_t)i;
    g_cands = s->cands;
    g_final = s->final;
    if (r.n > 1) qsort(r.order, r.n, sizeof *r.order, fp_cmp_idx);
    printf("\n== fingerprint collisions (candidate semantic duplicates) ==\n");
    for (int pass = 0; pass < 2; pass++) fp_report_pass(s, &r, pass);
    printf("\n== false-positive measurement ==\n");
    printf("matched pairs on corpus A                    %ld\n", r.pairs_a);
    printf("distinct-name pairs re-tested on corpus B    %ld\n", r.pairs_tested);
    printf("pairs that DIVERGED on corpus B (false pos)  %ld\n", r.pairs_false);
    printf("MEASURED FALSE-POSITIVE RATE (corpus A only) %.2f%%\n",
           r.pairs_tested ? 100.0 * (double)r.pairs_false / (double)r.pairs_tested : 0.0);
    printf("groups rejected by corpus B                  %ld\n", r.groups_rejected);
    printf("groups reported as candidates                %ld\n", r.groups_reported);
    printf("groups held below the evidence bar           %ld\n", r.groups_weak);
    printf("NOTE: the rate above is the rate a ONE-CORPUS tool would\n"
           "      have shipped. Every one of those pairs was caught here\n"
           "      and is not in the list. The residual rate among the\n"
           "      reported candidates can only be measured by reading\n"
           "      them; it is not derivable from the hashes.\n");
    free(r.order);
    return 0;
}

int main(int argc, char **argv)
{
    struct fp_scan_state state = { .list = "-" };
    if (fp_options(&state, argc, argv) != 0) return 2;
    if (fp_select(&state) != 0) return 2;
    if (fp_coverage(&state) != 0) return 2;
    if (state.select_only) { fp_print_selection(&state); return 0; }
    if (fp_prepare(&state) != 0) return 2;
    if (fp_build_harness(&state) != 0) return 2;
    if (fp_observe(&state) != 0) return 2;
    if (fp_classify(&state) != 0) return 2;
    if (fp_select_confirmation(&state) != 0) return 2;
    if (fp_confirm(&state) != 0) return 2;
    if (fp_report(&state) != 0) return 2;
    fp_index_free(state.ix);
    return 0;
}
