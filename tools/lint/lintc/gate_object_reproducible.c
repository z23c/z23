/* Copyright 2026 Rhett Creighton - Licensed under Apache-2.0
 *
 * purpose: C23 lint gate - check-object-reproducible. Proves that an object
 * file does not depend on the checkout path, per compiler and per target.
 * For each CASE (the host C compiler; clang host; clang riscv64 for the
 * freebsd system-call ABI the fleet failsafe serves; clang aarch64 linux) the
 * gate copies a fixed, small set of translation units and the platform-module
 * headers they need into two temporary roots of DIFFERENT path length,
 * compiles the same unit in each with the tree's reproducibility flags, and
 * compares the SHA-256 of the two objects.
 *
 * One source of truth: the Makefile recipe passes every compile and link flag
 * as an argument (REPRO_CFLAGS whose -ffile-prefix-map names the tree root,
 * which the gate rewrites to each test root; the base language and
 * optimisation flags; the cross-case flags; each cross case's --target
 * flag; the link flags and libraries; the per-unit random seed with the unit
 * name replaced by @UNIT@; the node object flags). The only compile or link
 * text this file types is -c, -o and the -I list it derives from its own
 * payload and unit tables.
 *
 * Every compile starts by deleting the previous out.o and must end with exit
 * status zero observed (spawn merged capture, so the compiler diagnostic is
 * kept) and a non-empty, well-formed ELF relocatable whose section table lies
 * inside the file. A failed compile can therefore never be compared against a
 * stale object. The plain --selftest proves that by driving the real compile
 * runner with a compiler that fails (false), one that writes a valid object
 * and then exits non-zero (find), one that exits 0 and writes
 * nothing (true), one that writes a non-ELF file, and a positive control
 * that copies a valid object, each with a stale valid out.o already present.
 *
 * The shipped-link case compiles real units (astro_time.c, astro_exact.c,
 * astro_mag.c, log_throttle.c) plus a tiny main written by the gate
 * (identical bytes in both roots) with the shipped node object flags, links
 * them with the host driver and the tree's LDFLAGS plus -Wl,--build-id=none
 * (--link-flags) and --link-libs, and compares the SHA-256 of the two linked
 * programs. The linked output must also contain neither root path string. It
 * gates the verdict.
 *
 * Controls (what each case proves it can observe):
 *   host-cc, clang-host, clang-riscv64, clang-aarch64: unit-level GREEN (the
 *     first unit under two roots WITH the prefix map must match) and RED (the
 *     same unit WITHOUT the prefix-map flag must differ), before the units.
 *   shipped-link: link-level GREEN (the real link must match) and RED (the
 *     same compile and link WITHOUT the prefix-map flag must differ across
 *     roots or contain a root path), after the real link.
 *   shipped-recipe: NO control. It is the LTO node recipe, run report-only.
 * If a RED control does not differ the check observes nothing and the gate
 * fails with SELFTEST_UNOBSERVED.
 *
 * A compiler that is not installed is SKIPPED by name and fails the gate
 * unless the case is named in --allow-missing; a missing clang is reported as
 * such (clang is required for the clang cases). A compiler that is found but
 * cannot be read or hashed is always a failure.
 *
 * The case named by --report-only is run and printed; only a hash MISMATCH of
 * that case is excused. Every other refusal in it (cleanup failed, I/O error,
 * compiler unreadable, compile failed, a leaked root path, a failed control)
 * fails the gate.
 *
 * Host support: the gate compares ELF objects and links with GNU-ld style
 * flags. A host that is not that kind (Darwin, Windows) is skipped through
 * the explicit --unsupported-host NAME, which the Makefile passes ONLY on such
 * a host; the skip prints one named line per case and exits 0. On an ELF host
 * the argument is never passed, so a missing clang or a driver that rejects
 * the flags fails the gate with a clear message.
 *
 * Stopping: one process-wide deadline (OR_DEADLINE_S) bounds the whole run,
 * and each compile is also bounded by OR_TIMEOUT_MS and by the time left.
 * SIGINT and SIGTERM only set a volatile sig_atomic_t flag (async-signal-
 * safe; no sibling lint tool installs handlers). The flag is checked before
 * every compile, the run unwinds through the normal cleanup that removes the
 * temp roots, then the signal is re-raised with its default action. A
 * SIGKILL cannot be caught and leaves the temp root under TMPDIR.
 *
 * Output: one machine-readable line per (case, unit), prefixed OBJREPRO, with
 * full 64-hex SHA-256 values of source, compiler binary, flags text and both
 * objects, and the exact argv of both compiles (the temp base directory is
 * the only text replaced, by <BASE>). EVERY verdict, refusal and skip line of
 * every case, the link case included, ends with the same src=, flags= and
 * argv_a=/argv_b= evidence (the link case lists its compile steps and the
 * link, joined by " ; "), so a failure can be reproduced from the log alone.
 *
 * Children are spawned by argv with a deadline (util/spawn.h); no shell. The
 * cross cases compile only freestanding units because no target libc headers
 * are assumed on a build host.
 *
 * SHA-256, the file helpers, the ELF walk and the pure self-test live in
 * gate_object_reproducible_support.c (shared declarations in the _priv.h), only
 * to keep each file under the 1500-line ceiling.
 */
#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#endif
#include <dirent.h>
#include <errno.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>
#include "lintc.h"
#include "gate_object_reproducible_priv.h"
#include "base/safe_alloc.h"
#include "base/serialize_le.h"
#include "platform/time_compat.h"
#include "util/spawn.h"

#define OR_ROOT_A "r"
#define OR_ROOT_B "checkout-root-with-a-longer-name-0123456789"
#define OR_LINK_MAIN "link_main.c"

struct or_unit {
    const char *path;
    bool hosted_only;
};

static const struct or_case k_or_cases[] = {
    { "host-cc", NULL, false, false, false },
    { "clang-host", "clang", false, false, false },
    { "clang-riscv64", "clang", true, false, false },
    { "clang-aarch64", "clang", true, false, false },
    { "shipped-recipe", NULL, false, true, false },
    { "shipped-link", NULL, false, true, true },
};
enum { OR_NCASES = (int)(sizeof k_or_cases / sizeof k_or_cases[0]) };

static const struct or_unit k_or_units[] = {
    { "platform/modules/astro/src/astro_time.c", false },
    { "platform/modules/platform/src/process_lock.c", false },
    { "platform/modules/support/src/log_throttle.c", false },
    { "platform/modules/json/src/json.c", true },
};
enum { OR_NUNITS = (int)(sizeof k_or_units / sizeof k_or_units[0]) };

/* Tree-relative payload copied into each root besides the units. The -I list
 * is derived from it (every "/include" entry) and from the unit directories. */
static const char *const k_or_payload[] = {
    "platform/modules/base/include",
    "platform/modules/json/include",
    "platform/modules/platform/include",
    "platform/modules/astro/include",
    "platform/modules/support/include",
    "platform/modules/astro/src/astro_priv.h",
    "platform/modules/astro/src/astro_exact.c",
    "platform/modules/astro/src/astro_mag.c",
};
enum { OR_NPAYLOAD = (int)(sizeof k_or_payload / sizeof k_or_payload[0]) };

/* ---- stop control: signals and the process-wide deadline --------------- */

volatile sig_atomic_t g_or_sig;
int64_t g_or_deadline_ms;
static int g_or_runs; /* compiler invocations, reported on the last line */

int64_t or_now_ms(void)
{
    return platform_time_monotonic_ms();
}

/* Async-signal-safe: the handler only stores the signal number. */
static void or_on_signal(int sig)
{
    g_or_sig = sig;
}

static bool or_signals_install(void)
{
    struct sigaction sa;
    memset(&sa, 0, sizeof sa);
    sa.sa_handler = or_on_signal;
    sigemptyset(&sa.sa_mask);
    return sigaction(SIGINT, &sa, NULL) == 0
           && sigaction(SIGTERM, &sa, NULL) == 0;
}

/* NULL while the run may continue, else why it must stop. */
static const char *or_stop_reason(void)
{
    if (g_or_sig)
        return "interrupted by SIGINT or SIGTERM";
    if (or_now_ms() >= g_or_deadline_ms)
        return "process-wide deadline OR_DEADLINE_S exceeded";
    return NULL;
}

/* Time a compile may take: the per-compile bound or the time left, 0 = stop. */
static int or_budget_ms(void)
{
    int64_t left = g_or_deadline_ms - or_now_ms();
    if (g_or_sig || left <= 0)
        return 0;
    return left < OR_TIMEOUT_MS ? (int)left : OR_TIMEOUT_MS;
}

/* ---- command construction ------------------------------------------- */

struct or_roots {
    char base[OR_PATH];
    char a[OR_PATH];
    char b[OR_PATH];
};

struct or_ctx {
    const struct or_cfg *cfg;
    const struct or_case *cs;
    const char *cc;     /* the --host-cc / case name until resolved */
    char ccbuf[OR_PATH];
    char target[OR_PATH]; /* the case's --target flag from --targets, or "" */
    char ccsha[65];
    const struct or_roots *roots;
};


bool or_add(struct or_cmd *c, const char *s)
{
    if (c->n >= OR_MAXTOK || strlen(s) >= OR_PATH)
        return false;
    (void)snprintf(c->tok[c->n], OR_PATH, "%s", s);
    c->n++;
    return true;
}

/* Append one token with the first occurrence of `from` replaced by `to`. */
static bool or_add_subst(struct or_cmd *c, const char *s, const char *from,
                         const char *to)
{
    const char *hit = (from && from[0]) ? strstr(s, from) : NULL;
    char buf[OR_PATH];
    if (!hit)
        return or_add(c, s);
    int n = snprintf(buf, sizeof buf, "%.*s%s%s", (int)(hit - s), s, to,
                     hit + strlen(from));
    return n > 0 && n < (int)sizeof buf && or_add(c, buf);
}

/* Split a Makefile flag string on spaces, rewriting the tree root to `root`;
 * drop every token starting with --red-strip when `prefix_map` is false (the
 * RED control). */
static bool or_add_words(struct or_cmd *c, const struct or_cfg *cfg,
                         const char *words, const char *root, bool prefix_map)
{
    const char *p = words;
    size_t sl = cfg->strip ? strlen(cfg->strip) : 0;
    while (*p) {
        while (*p == ' ')
            p++;
        size_t n = strcspn(p, " ");
        char tok[OR_PATH];
        if (n >= sizeof tok)
            return false;
        memcpy(tok, p, n);
        tok[n] = '\0';
        p += n;
        if (n == 0)
            continue;
        if (!prefix_map && sl > 0 && strncmp(tok, cfg->strip, sl) == 0)
            continue;
        if (!or_add_subst(c, tok, cfg->tree, root))
            return false;
    }
    return true;
}

static bool or_add_seed(struct or_cmd *c, const struct or_cfg *cfg,
                        const char *unit)
{
    if (cfg->seed_none)
        return true;
    return or_add_subst(c, cfg->seed, "@UNIT@", unit);
}

static bool or_has_suffix(const char *s, const char *suf)
{
    size_t n = strlen(s), m = strlen(suf);
    return n >= m && strcmp(s + n - m, suf) == 0;
}

static bool or_add_inc(struct or_cmd *c, const char *dir, size_t n)
{
    char t[OR_PATH];
    int w = snprintf(t, sizeof t, "-I%.*s", (int)n, dir);
    return w > 0 && w < (int)sizeof t && or_add(c, t);
}

/* The -I list, derived from the tables: every payload "/include" directory
 * and the directory of every unit. */
static bool or_add_incs(struct or_cmd *c)
{
    bool ok = true;
    for (int i = 0; ok && i < OR_NPAYLOAD; i++) {
        if (or_has_suffix(k_or_payload[i], "/include"))
            ok = or_add_inc(c, k_or_payload[i], strlen(k_or_payload[i]));
    }
    for (int i = 0; ok && i < OR_NUNITS; i++) {
        const char *p = k_or_units[i].path;
        ok = or_add_inc(c, p, (size_t)(strrchr(p, '/') - p));
    }
    return ok;
}

/* Finish argv; false (and an empty argv) when building failed. */
bool or_seal(struct or_cmd *c, bool ok)
{
    for (int i = 0; ok && i < c->n; i++)
        c->argv[i] = c->tok[i];
    c->argv[ok ? c->n : 0] = NULL;
    return ok;
}

/* Compiler, target, language, optimization and include arguments. */
static bool or_add_head(struct or_cmd *c, const struct or_ctx *x,
                        const char *cc)
{
    const struct or_cfg *cfg = x->cfg;
    bool ok = or_add(c, cc) && (!x->target[0] || or_add(c, x->target))
              && or_add_words(c, cfg, cfg->base, cfg->tree, true)
              && or_add(c, "-c");
    if (ok && x->cs->cross)
        ok = or_add_words(c, cfg, x->cfg->cross, cfg->tree, true);
    return ok && or_add_incs(c);
}

static bool or_build_cmd(const struct or_ctx *x, const char *cc,
                         const char *root, const char *unit, bool prefix_map,
                         struct or_cmd *c)
{
    const struct or_cfg *cfg = x->cfg;
    c->n = 0;
    bool ok = x->cs->shipped
        ? or_add(c, cc) && or_add_words(c, cfg, cfg->shipped, root, prefix_map)
              && or_add(c, "-c")
        : or_add_head(c, x, cc)
              && or_add_words(c, cfg, cfg->repro, root, prefix_map);
    ok = ok && or_add_seed(c, cfg, unit) && or_add(c, unit)
         && or_add(c, "-o") && or_add(c, "out.o");
    return or_seal(c, ok);
}

/* The shipped-link case: compile these (the last is the gate's own main),
 * then link the objects. */
static const char *const k_or_link_src[] = {
    "platform/modules/astro/src/astro_time.c",
    "platform/modules/astro/src/astro_exact.c",
    "platform/modules/astro/src/astro_mag.c",
    "platform/modules/support/src/log_throttle.c",
    OR_LINK_MAIN,
};
enum { OR_NLINKSRC = (int)(sizeof k_or_link_src / sizeof k_or_link_src[0]) };

static bool or_link_cmd(const struct or_ctx *x, const char *cc,
                        const char *root, bool prefix_map, struct or_cmd *c)
{
    const struct or_cfg *cfg = x->cfg;
    char obj[32];
    c->n = 0;
    bool ok = or_add(c, cc)
              && or_add_words(c, cfg, cfg->shipped, root, prefix_map)
              && or_add_words(c, cfg, cfg->link, root, prefix_map)
              && or_add(c, "-o") && or_add(c, "out.bin");
    for (int i = 0; ok && i < OR_NLINKSRC; i++) {
        (void)snprintf(obj, sizeof obj, "obj%d.o", i);
        ok = or_add(c, obj);
    }
    /* the libraries come after the objects */
    ok = ok && or_add_words(c, cfg, cfg->libs, cfg->tree, true);
    return or_seal(c, ok);
}

/* Steps of one root's work: one compile, or OR_NLINKSRC compiles and a link. */
static int or_nsteps(const struct or_ctx *x)
{
    return x->cs->link ? OR_NLINKSRC + 1 : 1;
}

static bool or_step(const struct or_ctx *x, const char *cc, const char *root,
                    const char *unit, int step, bool prefix_map,
                    struct or_cmd *c)
{
    if (!x->cs->link)
        return or_build_cmd(x, cc, root, unit, prefix_map, c);
    if (step < OR_NLINKSRC)
        return or_build_cmd(x, cc, root, k_or_link_src[step], prefix_map, c);
    return or_link_cmd(x, cc, root, prefix_map, c);
}

/* Hash of everything after argv[0] of every step, the root shown as <ROOT>. */
static bool or_flags_hash(const struct or_ctx *x, const char *unit,
                          char out[65])
{
    struct or_cmd *c = zcl_malloc(sizeof *c, "or_flags_hash");
    struct or_sha s;
    bool ok = c != NULL;
    or_sha_init(&s);
    for (int st = 0; ok && st < or_nsteps(x); st++) {
        ok = or_step(x, "cc", "<ROOT>", unit, st, true, c);
        for (int i = 1; ok && i < c->n; i++)
            or_sha_update(&s, c->tok[i], strlen(c->tok[i]) + 1);
    }
    if (ok)
        or_sha_hex(&s, out);
    free(c);
    return ok;
}

/* Is `name` an element of the comma list? */
static bool or_listed(const char *list, const char *name)
{
    size_t nl = strlen(name);
    const char *p = list;
    while (*p) {
        size_t n = strcspn(p, ",");
        if (n == nl && strncmp(p, name, n) == 0)
            return true;
        p += n + (p[n] == ',' ? 1 : 0);
    }
    return false;
}

/* The value of NAME=VALUE in a comma list (the value may contain '='). */
bool or_target_of(const char *list, const char *name, char *out,
                         size_t cap)
{
    size_t nl = strlen(name);
    const char *p = list ? list : "";
    while (*p) {
        size_t n = strcspn(p, ",");
        if (n > nl + 1 && strncmp(p, name, nl) == 0 && p[nl] == '=') {
            int w = snprintf(out, cap, "%.*s", (int)(n - nl - 1), p + nl + 1);
            return w > 0 && w < (int)cap;
        }
        p += n + (p[n] == ',' ? 1 : 0);
    }
    return false;
}

static void or_ctx_init(struct or_ctx *x, const struct or_cfg *cfg,
                        const struct or_case *cs)
{
    memset(x, 0, sizeof *x);
    x->cfg = cfg;
    x->cs = cs;
    x->cc = cs->cc ? cs->cc : cfg->host_cc;
    (void)snprintf(x->ccsha, sizeof x->ccsha, "-");
    (void)or_target_of(cfg->targets, cs->name, x->target, sizeof x->target);
}

/* A report-only case prints REPORTED where a gating case prints REFUSED, for
 * a hash MISMATCH only. Every other refusal prints REFUSED. */
static const char *or_tag(const struct or_cfg *cfg, const struct or_case *cs)
{
    return or_listed(cfg->report, cs->name) ? "REPORTED" : "REFUSED";
}

/* ---- evidence: source hashes, flags hash, exact argv ---------------------- */

/* The shipped-link case's main, identical bytes in every root. */
static const char k_or_link_main[] =
    "#include \"astro/astro_time.h\"\n"
    "#include \"support/log_throttle.h\"\n"
    "int main(void)\n"
    "{\n"
    "    struct astro_instant t = { 2026, 10, 10, 1, 2, 3 };\n"
    "    static struct log_throttle th;\n"
    "    uint64_t reps = 0;\n"
    "    bool ok = astro_instant_is_valid(&t);\n"
    "    return log_throttle_should_emit(&th, 7, 1, 1, &reps) && ok ? 0 : 1;\n"
    "}\n";

/* "-" when the source cannot be read. */
static void or_src_hash(const struct or_cfg *cfg, const char *rel, char out[65])
{
    char path[OR_PATH];
    if (strcmp(rel, OR_LINK_MAIN) == 0) {
        or_sha_buf(k_or_link_main, sizeof k_or_link_main - 1, out);
        return;
    }
    if (!or_join(path, sizeof path, cfg->tree, rel) || !or_hash_file(path, out))
        (void)snprintf(out, 65, "-");
}

static void or_print_srcs(const struct or_ctx *x, const char *unit)
{
    char h[65];
    printf(" src=");
    if (!x->cs->link) {
        or_src_hash(x->cfg, unit, h);
        printf("%s", h);
        return;
    }
    for (int i = 0; i < OR_NLINKSRC; i++) {
        or_src_hash(x->cfg, k_or_link_src[i], h);
        printf("%s%s", i ? "+" : "", h);
    }
}

/* Both argvs (root a, root b); a link case lists each step joined by " ; ".
 * The temp base directory is the only text replaced, by <BASE>. */
static void or_print_argvs(const struct or_ctx *x, const char *unit,
                           bool prefix_map, const char *label)
{
    struct or_cmd *c = zcl_malloc(sizeof *c, "or_print_argvs");
    if (!c) {
        printf(" %sargv=UNAVAILABLE", label);
        return;
    }
    for (int side = 0; side < 2; side++) {
        const char *root = side ? "<BASE>/" OR_ROOT_B : "<BASE>/" OR_ROOT_A;
        printf(" %sargv_%c=", label, side ? 'b' : 'a');
        for (int st = 0; st < or_nsteps(x); st++) {
            printf("%s", st ? " ; " : "");
            if (!or_step(x, x->cc, root, unit, st, prefix_map, c)) {
                printf("<UNBUILDABLE>");
                continue;
            }
            for (int i = 0; i < c->n; i++)
                printf("%s%s", i ? " " : "", c->tok[i]);
        }
    }
    free(c);
}

/* src=, flags= and argv_a=/argv_b= of one unit (NULL for the link case). */
static void or_print_evidence(const struct or_ctx *x, const char *unit)
{
    char fh[65] = "-";
    (void)or_flags_hash(x, unit, fh);
    or_print_srcs(x, unit);
    printf(" flags=%s", fh);
    or_print_argvs(x, unit, true, "");
}

static bool or_unit_applies(const struct or_ctx *x, int i)
{
    if (x->cs->shipped && i > 0)
        return false;
    return !(k_or_units[i].hosted_only && x->cs->cross);
}

/* The evidence of every unit the case runs (the program for the link case). */
static void or_print_case_evidence(const struct or_ctx *x)
{
    if (x->cs->link) {
        or_print_evidence(x, NULL);
        return;
    }
    for (int i = 0; i < OR_NUNITS; i++) {
        if (!or_unit_applies(x, i))
            continue;
        printf(" unit=%s", k_or_units[i].path);
        or_print_evidence(x, k_or_units[i].path);
    }
}

/* ---- two-root compile ------------------------------------------------ */

struct or_obj {
    unsigned char *a, *b;
    size_t la, lb;
    char ha[65], hb[65];
};

static void or_obj_free(struct or_obj *o)
{
    free(o->a);
    free(o->b);
    o->a = NULL;
    o->b = NULL;
}

static bool or_write_fixture(const char *root)
{
    char p[OR_PATH];
    if (!or_join(p, sizeof p, root, OR_LINK_MAIN) || !or_mkparent(p))
        return false;
    FILE *f = fopen(p, "wb");
    if (!f)
        return false;
    bool ok = fwrite(k_or_link_main, 1, sizeof k_or_link_main - 1, f)
              == sizeof k_or_link_main - 1;
    return fclose(f) == 0 && ok;
}

/* A refusal that happens outside a compile: it names the case and carries the
 * case's evidence like every other line. */
static void or_refuse_case(const struct or_ctx *x, const char *kind,
                           const char *what, const char *arg)
{
    printf("check-object-reproducible: REFUSED %s: case %s: %s%s", kind,
           x->cs->name, what, arg);
    or_print_case_evidence(x);
    printf("\n");
}

static bool or_copy_payload(const struct or_ctx *x, const char *root)
{
    char s[OR_PATH], d[OR_PATH];
    if (!or_write_fixture(root)) {
        or_refuse_case(x, "IO_ERROR", "cannot write the link fixture into "
                       "the test root", "");
        return false;
    }
    for (int i = 0; i < OR_NPAYLOAD + OR_NUNITS; i++) {
        const char *rel = i < OR_NPAYLOAD ? k_or_payload[i]
                                          : k_or_units[i - OR_NPAYLOAD].path;
        if (!or_join(s, sizeof s, x->cfg->tree, rel)
            || !or_join(d, sizeof d, root, rel)
            || !or_copy_tree(s, d, 0)) {
            or_refuse_case(x, "IO_ERROR", "cannot copy into the test root: ",
                           rel);
            return false;
        }
    }
    return true;
}

static bool or_absolute(const char *in, char *out, size_t cap)
{
    char cwd[OR_PATH];
    if (in[0] == '/')
        return snprintf(out, cap, "%s", in) < (int)cap;
    return getcwd(cwd, sizeof cwd) && or_join(out, cap, cwd, in);
}

/* Remove a temp tree; a failure to remove is itself a gate failure. */
static bool or_remove_checked(const struct or_ctx *x, const char *path)
{
    if (or_rm_rf(path, 0))
        return true;
    char why[OR_PATH + 64];
    (void)snprintf(why, sizeof why, "could not remove the temp root %s (%s)",
                   path, strerror(errno));
    or_refuse_case(x, "CLEANUP_FAILED", why, "");
    return false;
}

/* base is set the moment the directory exists, so every later failure path
 * can still remove it through or_roots_drop. */
static bool or_roots_make(const struct or_ctx *x, struct or_roots *r)
{
    const char *tmp = env_or("TMPDIR", "test-tmp");
    char tmpl[OR_PATH];
    if (csr_mkdirs(tmp) != 0
        || !or_join(tmpl, sizeof tmpl, tmp, "z23-lint-objrepro.XXXXXX")
        || !mkdtemp(tmpl)) {
        or_refuse_case(x, "IO_ERROR", "cannot create the temp area", "");
        return false;
    }
    if (!or_absolute(tmpl, r->base, sizeof r->base)) {
        r->base[0] = '\0';
        (void)or_remove_checked(x, tmpl);
        or_refuse_case(x, "IO_ERROR", "cannot resolve the temp area", "");
        return false;
    }
    if (snprintf(r->a, sizeof r->a, "%s/" OR_ROOT_A, r->base) >= (int)sizeof r->a
        || snprintf(r->b, sizeof r->b, "%s/" OR_ROOT_B, r->base)
               >= (int)sizeof r->b) {
        or_refuse_case(x, "IO_ERROR", "temp root path too long", "");
        return false;
    }
    return or_copy_payload(x, r->a) && or_copy_payload(x, r->b);
}

static bool or_roots_drop(const struct or_ctx *x, struct or_roots *r)
{
    bool ok = !r->base[0] || or_remove_checked(x, r->base);
    r->base[0] = '\0';
    return ok;
}

/* Run the compiler: true only for an observed exit status of zero, inside the
 * time budget (per-compile bound, process deadline, no stop signal). */
static bool or_run_compiler(const struct or_cmd *c, char *diag)
{
    struct zcl_spawn_binary_observation ob = { 0 };
    int budget = or_budget_ms();
    diag[0] = '\0';
    if (budget <= 0) {
        const char *why = or_stop_reason();
        (void)snprintf(diag, OR_DIAG, "not run: %s", why ? why : "no time left");
        return false;
    }
    g_or_runs++;
    struct zcl_result r = zcl_spawn_capture_binary_merged(
        c->argv, diag, OR_DIAG - 1, budget, &ob);
    diag[ob.output_len < OR_DIAG - 1 ? ob.output_len : OR_DIAG - 1] = '\0';
    return r.ok && ob.exit_observed && ob.exit_code == 0 && ob.eof
           && !ob.timed_out && !ob.overflow;
}

/* out.o in the working directory: a regular, non-empty, well-formed ELF. */
static unsigned char *or_take_object(size_t *len)
{
    struct stat st;
    if (stat("out.o", &st) != 0 || !S_ISREG(st.st_mode) || st.st_size <= 0)
        return NULL;
    unsigned char *b = or_read_file("out.o", len);
    if (b && !or_elf_valid(b, *len)) {
        free(b);
        return NULL;
    }
    return b;
}

/* The previous object is deleted first, so a compiler that fails leaves
 * nothing to read. */
unsigned char *or_compile_run(const struct or_cmd *c, char *diag,
                                     size_t *len, const char **why)
{
    if (unlink("out.o") != 0 && errno != ENOENT) {
        *why = "cannot delete the previous object";
        return NULL;
    }
    if (!or_run_compiler(c, diag)) {
        *why = or_stop_reason() ? "gate stopped (signal or deadline)"
                                : "compiler did not exit with status 0";
        return NULL;
    }
    unsigned char *o = or_take_object(len);
    if (!o)
        *why = "no non-empty well-formed ELF object was produced";
    return o;
}

static void or_refuse_compile(const struct or_ctx *x, const char *unit,
                              const char *why, const char *diag)
{
    printf("check-object-reproducible: REFUSED COMPILE_FAILED: case %s unit "
           "%s: %s", x->cs->name, unit ? unit : "-", why);
    or_print_evidence(x, unit);
    printf("\n");
    const char *p = diag;
    for (int line = 0; *p && line < OR_DIAG_LINES; line++) {
        size_t n = strcspn(p, "\n");
        printf("    compiler: %.*s\n", (int)(n > 200 ? 200 : n), p);
        p += n + (p[n] == '\n' ? 1 : 0);
    }
}

/* Compile `unit` in `root` (as the working directory) and read out.o. */
static unsigned char *or_compile_in(const struct or_ctx *x, const char *root,
                                    const char *unit, bool prefix_map,
                                    size_t *len)
{
    struct or_cmd *c = zcl_malloc(sizeof *c, "or_compile_in cmd");
    char *diag = zcl_malloc(OR_DIAG, "or_compile_in diag");
    char saved[OR_PATH];
    unsigned char *obj = NULL;
    const char *why = "could not set up the compile";
    if (diag)
        diag[0] = '\0';
    if (c && diag && or_build_cmd(x, x->cc, root, unit, prefix_map, c)
        && getcwd(saved, sizeof saved) && chdir(root) == 0) {
        obj = or_compile_run(c, diag, len, &why);
        if (chdir(saved) != 0) {
            free(obj);
            obj = NULL;
            why = "cannot return to the working directory";
        }
    }
    if (!obj)
        or_refuse_compile(x, unit, why, diag ? diag : "");
    free(c);
    free(diag);
    return obj;
}

static bool or_pair(const struct or_ctx *x, const char *unit, bool prefix_map,
                    struct or_obj *o)
{
    memset(o, 0, sizeof *o);
    o->a = or_compile_in(x, x->roots->a, unit, prefix_map, &o->la);
    if (o->a)
        o->b = or_compile_in(x, x->roots->b, unit, prefix_map, &o->lb);
    if (!o->a || !o->b) {
        or_obj_free(o);
        return false;
    }
    or_sha_buf(o->a, o->la, o->ha);
    or_sha_buf(o->b, o->lb, o->hb);
    return true;
}

/* ---- shipped-link: compile the units, link, hash the program ----------- */

/* Step `st` in the current directory (the root): a compile to obj<st>.o, or
 * the link to out.bin. Each output is deleted first, so a step that fails or
 * writes nothing cannot be satisfied by a leftover. */
static bool or_link_step_run(const struct or_ctx *x, const char *root, int st,
                             bool prefix_map, struct or_cmd *c, char *diag)
{
    char obj[32];
    if (!or_step(x, x->cc, root, NULL, st, prefix_map, c))
        return false;
    if (st == OR_NLINKSRC)
        return (unlink("out.bin") == 0 || errno == ENOENT)
               && or_run_compiler(c, diag);
    (void)snprintf(obj, sizeof obj, "obj%d.o", st);
    return (unlink("out.o") == 0 || errno == ENOENT)
           && or_run_compiler(c, diag) && rename("out.o", obj) == 0;
}

/* In the root as working directory: objects, link, read out.bin. */
static unsigned char *or_link_build(const struct or_ctx *x, const char *root,
                                    bool prefix_map, struct or_cmd *c,
                                    char *diag, size_t *len)
{
    bool ok = true;
    for (int st = 0; ok && st <= OR_NLINKSRC; st++)
        ok = or_link_step_run(x, root, st, prefix_map, c, diag);
    return ok ? or_read_file("out.bin", len) : NULL;
}

/* Build the program in `root` and return out.bin (NULL on any failure). */
static unsigned char *or_link_in(const struct or_ctx *x, const char *root,
                                 bool prefix_map, size_t *len)
{
    struct or_cmd *c = zcl_malloc(sizeof *c, "or_link_in cmd");
    char *diag = zcl_malloc(OR_DIAG, "or_link_in diag");
    char saved[OR_PATH];
    unsigned char *bin = NULL;
    if (diag)
        diag[0] = '\0';
    bool ok = c && diag && getcwd(saved, sizeof saved) && chdir(root) == 0;
    if (ok) {
        bin = or_link_build(x, root, prefix_map, c, diag, len);
        ok = chdir(saved) == 0;
    }
    if (!bin || !ok || !or_elf_linked(bin, *len)) {
        free(bin);
        bin = NULL;
        or_refuse_compile(x, NULL, "the compile or link (host driver; it may "
                          "reject the link flags) did not yield a well-formed "
                          "linked ELF", diag ? diag : "");
    }
    free(c);
    free(diag);
    return bin;
}

/* Does the buffer contain the text of `needle`? */
bool or_contains(const unsigned char *h, size_t hl, const char *needle)
{
    size_t nl = strlen(needle);
    if (nl == 0 || hl < nl)
        return false;
    for (size_t i = 0; i + nl <= hl; i++) {
        const unsigned char *p = memchr(h + i, (unsigned char)needle[0],
                                        hl - nl + 1 - i);
        if (!p)
            return false;
        i = (size_t)(p - h);
        if (memcmp(p, needle, nl) == 0)
            return true;
    }
    return false;
}

static bool or_link_leak(const struct or_ctx *x, const struct or_obj *o)
{
    const struct or_roots *r = x->roots;
    return or_contains(o->a, o->la, r->a) || or_contains(o->a, o->la, r->b)
           || or_contains(o->b, o->lb, r->a)
           || or_contains(o->b, o->lb, r->b);
}

/* Both programs, built with or without the prefix map. */
static bool or_link_pair(const struct or_ctx *x, bool prefix_map,
                         struct or_obj *o)
{
    memset(o, 0, sizeof *o);
    o->a = or_link_in(x, x->roots->a, prefix_map, &o->la);
    if (o->a)
        o->b = or_link_in(x, x->roots->b, prefix_map, &o->lb);
    if (!o->a || !o->b) {
        or_obj_free(o);
        return false;
    }
    or_sha_buf(o->a, o->la, o->ha);
    or_sha_buf(o->b, o->lb, o->hb);
    return true;
}

static int or_link_verdict(const struct or_ctx *x, const struct or_obj *o)
{
    char sec[OR_NAME] = "";
    bool same = strcmp(o->ha, o->hb) == 0;
    bool leak = or_link_leak(x, o);
    if (!same)
        or_elf_first_diff(o->a, o->la, o->b, o->lb, sec, sizeof sec);
    printf("OBJREPRO case=%s units=%s+%s+%s+%s+%s verdict=%s cc=%s bin_a=%s "
           "bin_b=%s section=%s root_path_in_output=%s", x->cs->name,
           k_or_link_src[0], k_or_link_src[1], k_or_link_src[2],
           k_or_link_src[3], k_or_link_src[4], same ? "MATCH" : "DIFFER",
           x->ccsha, o->ha, o->hb, sec[0] ? sec : "-",
           leak ? "FOUND" : "none");
    or_print_evidence(x, NULL);
    printf("\n");
    if (!same) {
        printf("check-object-reproducible: %s MISMATCH: case %s linked "
               "output root-a=%s root-b=%s first-differing-section=%s",
               or_tag(x->cfg, x->cs), x->cs->name, o->ha, o->hb, sec);
        or_print_evidence(x, NULL);
        printf("\n");
    }
    if (leak) {
        printf("check-object-reproducible: REFUSED ROOT_PATH_IN_OUTPUT: case "
               "%s: the linked output contains a temp root path", x->cs->name);
        or_print_evidence(x, NULL);
        printf("\n");
    }
    return leak ? OR_REFUSED : same ? OR_OK : OR_MISMATCH;
}

/* RED control of the link: the same compile and link WITHOUT the prefix map
 * must differ across roots or hold a root path, or nothing is observed. */
static int or_link_control(const struct or_ctx *x, int green_rc)
{
    struct or_obj r;
    if (!or_link_pair(x, false, &r))
        return OR_REFUSED;
    bool differ = strcmp(r.ha, r.hb) != 0;
    bool leak = or_link_leak(x, &r);
    or_obj_free(&r);
    printf("OBJREPRO-SELFTEST case=%s kind=link green=%s red=%s", x->cs->name,
           green_rc == OR_OK ? "MATCH" : "NOT-MATCH",
           differ ? "DIFFER" : leak ? "LEAK" : "MATCH");
    or_print_evidence(x, NULL);
    or_print_argvs(x, NULL, false, "red_");
    printf("\n");
    if (differ || leak)
        return OR_OK;
    printf("check-object-reproducible: REFUSED SELFTEST_UNOBSERVED: case %s: "
           "the link built WITHOUT the prefix map neither differed across "
           "roots nor held a root path, so this check observes nothing",
           x->cs->name);
    or_print_evidence(x, NULL);
    or_print_argvs(x, NULL, false, "red_");
    printf("\n");
    return OR_REFUSED;
}

static int or_link_case(const struct or_ctx *x)
{
    struct or_obj o;
    if (!or_link_pair(x, true, &o))
        return OR_REFUSED;
    int rc = or_link_verdict(x, &o);
    or_obj_free(&o);
    int ctl = or_link_control(x, rc);
    return ctl > rc ? ctl : rc;
}

/* ---- reporting -------------------------------------------------------- */

/* One machine-readable line per (case, unit). */
static void or_print_line(const struct or_ctx *x, const char *unit,
                          const char *verdict, const char *ha, const char *hb,
                          const char *section)
{
    printf("OBJREPRO case=%s unit=%s verdict=%s target=%s cc=%s obj_a=%s "
           "obj_b=%s section=%s", x->cs->name, unit, verdict,
           x->target[0] ? x->target : "host", x->ccsha, ha, hb,
           section[0] ? section : "-");
    or_print_evidence(x, unit);
    printf("\n");
}

/* ---- case driver ------------------------------------------------------ */

/* Unit-level control: GREEN must match, RED (no prefix map) must differ.
 * 0 ok, else a refusal. */
static int or_unit_control(const struct or_ctx *x)
{
    const char *unit = k_or_units[0].path;
    struct or_obj o;
    if (!or_pair(x, unit, true, &o))
        return OR_REFUSED;
    bool green = strcmp(o.ha, o.hb) == 0;
    or_obj_free(&o);
    if (!green) {
        printf("check-object-reproducible: REFUSED SELFTEST_GREEN_DIFFERS: "
               "case %s: the control unit differs with the prefix map",
               x->cs->name);
        or_print_evidence(x, unit);
        printf("\n");
        return OR_REFUSED;
    }
    if (!or_pair(x, unit, false, &o))
        return OR_REFUSED;
    bool red = strcmp(o.ha, o.hb) != 0;
    or_obj_free(&o);
    printf("OBJREPRO-SELFTEST case=%s kind=unit unit=%s green=MATCH red=%s",
           x->cs->name, unit, red ? "DIFFER" : "MATCH");
    or_print_evidence(x, unit);
    or_print_argvs(x, unit, false, "red_");
    printf("\n");
    if (red)
        return OR_OK;
    printf("check-object-reproducible: REFUSED SELFTEST_UNOBSERVED: case %s: "
           "objects built WITHOUT the prefix map did not differ across "
           "roots, so this check observes nothing", x->cs->name);
    or_print_evidence(x, unit);
    or_print_argvs(x, unit, false, "red_");
    printf("\n");
    return OR_REFUSED;
}

static int or_run_unit(const struct or_ctx *x, const char *unit)
{
    struct or_obj o;
    char sec[OR_NAME] = "";
    if (!or_pair(x, unit, true, &o)) {
        or_print_line(x, unit, "COMPILE_FAILED", "-", "-", "");
        return OR_REFUSED;
    }
    bool same = strcmp(o.ha, o.hb) == 0;
    if (!same)
        or_elf_first_diff(o.a, o.la, o.b, o.lb, sec, sizeof sec);
    or_print_line(x, unit, same ? "MATCH" : "DIFFER", o.ha, o.hb, sec);
    if (!same) {
        printf("check-object-reproducible: %s MISMATCH: case %s unit %s "
               "root-a=%s root-b=%s first-differing-section=%s",
               or_tag(x->cfg, x->cs), x->cs->name, unit, o.ha, o.hb, sec);
        or_print_evidence(x, unit);
        printf("\n");
    }
    or_obj_free(&o);
    return same ? OR_OK : OR_MISMATCH;
}

static int or_case_units(const struct or_ctx *x)
{
    int rc = OR_OK;
    for (int i = 0; i < OR_NUNITS; i++) {
        const struct or_unit *u = &k_or_units[i];
        if (x->cs->shipped && i > 0)
            break;
        if (u->hosted_only && x->cs->cross) {
            or_print_line(x, u->path, "NOT-APPLICABLE", "-", "-", "");
            continue;
        }
        int r = or_run_unit(x, u->path);
        if (r > rc)
            rc = r;
    }
    return rc;
}

static int or_case_body(const struct or_ctx *x)
{
    if (x->cs->link)
        return or_link_case(x);
    int rc = x->cs->shipped ? OR_OK : or_unit_control(x);
    return rc == OR_OK ? or_case_units(x) : rc;
}

/* The compiler binary is not on PATH: skipped only when allowed. */
static int or_case_missing(const struct or_ctx *x, const char *want)
{
    bool ok = or_listed(x->cfg->allow, x->cs->name);
    printf("OBJREPRO case=%s unit=- verdict=SKIPPED compiler=%s%s",
           x->cs->name, want, ok ? " allowed-missing" : "");
    or_print_case_evidence(x);
    printf("\n");
    if (ok)
        return OR_OK;
    if (strcmp(want, "clang") == 0)
        printf("check-object-reproducible: REFUSED MISSING_COMPILER: case %s: "
               "clang is required for the clang and cross cases "
               "(clang-host, clang-riscv64, clang-aarch64) but is not on "
               "PATH; install clang, or name %s in --allow-missing (the "
               "Makefile list is: %s)", x->cs->name, x->cs->name,
               x->cfg->allow[0] ? x->cfg->allow : "empty");
    else
        printf("check-object-reproducible: REFUSED MISSING_COMPILER: case %s "
               "needs %s, which is not on PATH", x->cs->name, want);
    or_print_case_evidence(x);
    printf("\n");
    return OR_REFUSED;
}

static int or_case_inner(struct or_ctx *x)
{
    const char *want = x->cc;
    if (!or_find_exe(want, x->ccbuf, sizeof x->ccbuf))
        return or_case_missing(x, want);
    x->cc = x->ccbuf;
    if (!or_hash_file(x->ccbuf, x->ccsha)) {
        printf("OBJREPRO case=%s unit=- verdict=COMPILER_UNREADABLE "
               "compiler=%s", x->cs->name, want);
        or_print_case_evidence(x);
        printf("\ncheck-object-reproducible: REFUSED COMPILER_UNREADABLE: "
               "case %s: %s was found but could not be read and hashed",
               x->cs->name, x->ccbuf);
        or_print_case_evidence(x);
        printf("\n");
        return OR_REFUSED;
    }
    struct or_roots r = { "", "", "" };
    x->roots = &r;
    int rc = or_roots_make(x, &r) ? or_case_body(x) : OR_REFUSED;
    if (!or_roots_drop(x, &r))
        rc = OR_REFUSED;
    x->roots = NULL;
    return rc;
}

/* What a --report-only case's result counts as: only a hash MISMATCH is
 * excused; every other refusal stays a refusal. */
int or_excuse(const struct or_cfg *cfg, const struct or_case *cs,
                     int rc)
{
    return rc == OR_MISMATCH && or_listed(cfg->report, cs->name) ? OR_OK : rc;
}

static int or_run_case(const struct or_cfg *cfg, const struct or_case *cs)
{
    struct or_ctx x;
    or_ctx_init(&x, cfg, cs);
    int rc = or_case_inner(&x);
    int eff = or_excuse(cfg, cs, rc);
    if (or_listed(cfg->report, cs->name)) {
        printf("check-object-reproducible: REPORT-ONLY case %s rc=%d: %s",
               cs->name, rc,
               rc == OR_MISMATCH ? "hash MISMATCH excused, not part of the "
                                   "verdict"
               : rc == OR_OK ? "no mismatch"
                             : "REFUSED, not excused: this fails the gate");
        or_print_case_evidence(&x);
        printf("\n");
    }
    return eff;
}

/* ---- entry points ----------------------------------------------------- */

struct or_opt {
    const char *key;
    const char **slot;
};

bool or_parse(int argc, char **argv, struct or_cfg *cfg)
{
    memset(cfg, 0, sizeof *cfg);
    cfg->allow = "";
    cfg->report = "";
    cfg->host_cc = "gcc";
    cfg->unsupported = "";
    const struct or_opt tab[] = {
        { "--tree-root", &cfg->tree }, { "--repro-cflags", &cfg->repro },
        { "--base-cflags", &cfg->base }, { "--shipped-cflags", &cfg->shipped },
        { "--link-flags", &cfg->link }, { "--link-libs", &cfg->libs },
        { "--cross-flags", &cfg->cross }, { "--targets", &cfg->targets },
        { "--red-strip", &cfg->strip },
        { "--seed-flag", &cfg->seed }, { "--allow-missing", &cfg->allow },
        { "--report-only", &cfg->report }, { "--host-cc", &cfg->host_cc },
        { "--unsupported-host", &cfg->unsupported },
    };
    if (argc % 2 != 0)
        return false;
    for (int i = 0; i < argc; i += 2) {
        bool hit = false;
        for (size_t k = 0; k < sizeof tab / sizeof tab[0]; k++) {
            if (strcmp(argv[i], tab[k].key) == 0) {
                *tab[k].slot = argv[i + 1];
                hit = true;
            }
        }
        if (!hit)
            return false;
    }
    cfg->seed_none = cfg->seed && strcmp(cfg->seed, "none") == 0;
    return true;
}

/* Every cross case needs a --targets entry. */
static const char *or_cfg_targets_flaw(const struct or_cfg *cfg)
{
    char t[OR_PATH];
    for (int i = 0; i < OR_NCASES; i++) {
        if (k_or_cases[i].cross
            && !or_target_of(cfg->targets, k_or_cases[i].name, t, sizeof t))
            return "--targets has no NAME=--target=TRIPLE entry for a cross "
                   "case";
    }
    return NULL;
}

/* NULL when the configuration is usable, else the reason it is refused. */
const char *or_cfg_flaw(const struct or_cfg *cfg)
{
    const struct { const char *val, *msg; } req[] = {
        { cfg->tree, "--tree-root is required" },
        { cfg->repro, "--repro-cflags is required and must not be empty" },
        { cfg->base, "--base-cflags is required and must not be empty" },
        { cfg->shipped, "--shipped-cflags is required and must not be empty" },
        { cfg->link, "--link-flags is required and must not be empty" },
        { cfg->libs, "--link-libs is required and must not be empty" },
        { cfg->cross, "--cross-flags is required and must not be empty" },
        { cfg->targets, "--targets is required and must not be empty" },
        { cfg->strip, "--red-strip is required and must not be empty" },
        { cfg->seed, "--seed-flag is empty (pass none on a host with no "
                     "per-unit seed)" },
    };
    for (size_t i = 0; i < sizeof req / sizeof req[0]; i++) {
        if (!req[i].val || !req[i].val[0])
            return req[i].msg;
    }
    if (!cfg->seed_none && !strstr(cfg->seed, "@UNIT@"))
        return "--seed-flag has no @UNIT@ placeholder: the unit name was "
               "not substituted";
    return or_cfg_targets_flaw(cfg);
}

/* An explicit, named skip for a host that is not an ELF and GNU-ld host. One
 * line per case carries the evidence; nothing is compiled. */
static int or_skip_host(const struct or_cfg *cfg)
{
    for (int i = 0; i < OR_NCASES; i++) {
        struct or_ctx x;
        or_ctx_init(&x, cfg, &k_or_cases[i]);
        printf("OBJREPRO case=%s unit=- verdict=SKIPPED_HOST host=%s",
               x.cs->name, cfg->unsupported);
        or_print_case_evidence(&x);
        printf("\n");
    }
    printf("check-object-reproducible: SKIPPED_HOST: host OS %s is not an ELF "
           "and GNU-ld style host, and this gate compares ELF sections and "
           "links with --build-id=none; no case was run (the Makefile passes "
           "--unsupported-host only on Darwin and Windows hosts). This is a "
           "skip, not a PASS\n", cfg->unsupported);
    return OR_OK;
}

static int or_run_all(const struct or_cfg *cfg)
{
    int64_t t0 = or_now_ms();
    int worst = OR_OK;
    g_or_deadline_ms = t0 + (int64_t)OR_DEADLINE_S * 1000;
    g_or_runs = 0;
    if (!or_signals_install()) {
        fprintf(stderr, "check-object-reproducible: REFUSED SIGNALS: cannot "
                "install the SIGINT and SIGTERM handlers\n");
        return OR_REFUSED;
    }
    for (int i = 0; i < OR_NCASES && !g_or_sig; i++) {
        int rc = or_run_case(cfg, &k_or_cases[i]);
        if (rc > worst)
            worst = rc;
    }
    int sig = g_or_sig;
    if (sig) {
        printf("check-object-reproducible: REFUSED INTERRUPTED: signal %d "
               "received; the temp roots were removed and the run stopped\n",
               sig);
        worst = OR_REFUSED;
    }
    printf("check-object-reproducible: %s compiler_invocations=%d "
           "wall_s=%.1f\n", worst == 0 ? "PASS" : "FAIL", g_or_runs,
           (double)(or_now_ms() - t0) / 1000.0);
    (void)fflush(stdout);
    if (sig) {
        (void)signal(sig, SIG_DFL);
        (void)raise(sig);
    }
    return worst;
}

int check_object_reproducible_run(int argc, char **argv)
{
    struct or_cfg cfg;
    const char *flaw = NULL;
    if (!or_parse(argc, argv, &cfg) || (flaw = or_cfg_flaw(&cfg)) != NULL) {
        fprintf(stderr, "check-object-reproducible: REFUSED BAD_ARGS: %s; "
                "need --tree-root DIR --repro-cflags STR --base-cflags STR "
                "--shipped-cflags STR --link-flags STR --link-libs STR "
                "--cross-flags STR --targets NAME=FLAG,.. --red-strip STR "
                "--seed-flag STR|none [--allow-missing a,b] "
                "[--report-only a,b] [--host-cc CC] [--unsupported-host OS]; "
                "the Makefile recipe passes them\n",
                flaw ? flaw : "unknown or unpaired option");
        return OR_REFUSED;
    }
    if (cfg.unsupported[0])
        return or_skip_host(&cfg);
    return or_run_all(&cfg);
}

