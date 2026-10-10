/* Copyright 2026 Rhett Creighton - Licensed under Apache-2.0
 *
 * purpose: z23-lint riscv64-universal - the riscv64 FreeBSD "universal copy"
 * of the tree: a build sub-command, not a lint rule. It builds, into --out
 * (build/universal/riscv64-unknown-freebsd), the libc-free fixture program as
 * two static ET_EXEC executables (the default ISA string, and the rv64im
 * variant whose flags come in as --xcc-rv64im-flags, i.e.
 * REPRO_GATE_XCC_RV64IM_FLAGS) and a relocatable object for every freestanding
 * tree unit the check-object-reproducible cross case compiles (the list is
 * read from that gate: or_cross_unit). Every artifact is checked for its ELF
 * kind before it is listed. MANIFEST is written last and atomically: an old
 * MANIFEST is removed at the start, the new one goes to MANIFEST.tmp and is
 * renamed into place only after every artifact succeeded. The MANIFEST has
 * two toolchain header lines (toolchain-compiler and toolchain-linker, the
 * sha256 of each binary), then one tab-separated line per artifact, sorted
 * bytewise by name:
 *   name, sha256, size, source=sha256 list, sha256 of the exact flag text,
 *   target triple.
 * Artifact lines are expected to match across hosts only when the toolchain
 * lines match. No time, absolute path or host name reaches the file. The flag
 * text is hashed with the tree root shown as <ROOT> and the output paths left
 * out. Every compile and link flag comes from the Makefile (REPRO_GATE_* and
 * REPRO_CFLAGS); the only compiler tokens typed in this file are -c, -o, -x c
 * and the include directories. With --twice it builds twice into two
 * differently named temp roots and refuses unless the two MANIFEST files are
 * byte-identical; that proves independence from the OUTPUT root only.
 * Checkout-path independence of the same compile is proven by
 * check-object-reproducible case riscv64-link. Programs are linked, never
 * executed. A missing cross compiler or linker is one named refusal line
 * naming the tool and the variable to set; under --allow-missing (the
 * check-riscv64-universal recipe) it is one SKIPPED line and exit 0.
 * --unsupported-host NAME (the Makefile passes it only when uname -s is not
 * Linux) prints one SKIPPED_HOST line and exits 0. Hashing and formatting
 * live here, in C, on the SHA-256 of the object-reproducible gate's support
 * file.
 */
#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#endif
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>
#include "lintc.h"
#include "gate_object_reproducible_priv.h"
#include "base/safe_alloc.h"

#define RU "riscv64-universal"
#define RU_TARGET_CASE "riscv64-link"
#define RU_TARGET_PREFIX "--target="
#define RU_MANIFEST "MANIFEST"
#define RU_MANIFEST_TMP "MANIFEST.tmp"
#define RU_HDR_CC "toolchain-compiler"
#define RU_HDR_LD "toolchain-linker"

enum { RU_MAX_ART = 24, RU_SRCS = 640, RU_LINE = 1024 };
/* Outcome of a build step. RU_FAILED is OR_REFUSED (an exit code); RU_SKIPPED
 * is not an exit code: the entry point maps it to 0 after its one line. */
enum { RU_OK = 0, RU_FAILED = 2, RU_SKIPPED = 3 };
/* ELF header fields of an object: ELF64, little endian, ET_REL, EM_RISCV. */
enum { RU_ELF_CLASS64 = 2, RU_ELF_LE = 1, RU_ET_REL = 1, RU_EM_RISCV = 243 };

struct ru_cfg {
    const char *tree, *out, *repro, *base, *cross, *xcc_flags, *xcc_rv64im,
        *xcc, *xld, *xld_flags, *targets, *unsupported;
    bool twice, allow_missing;
};

struct ru_art {
    char name[OR_NAME];
    char sha[65];
    char flags[65];
    char srcs[RU_SRCS];
    uint64_t size;
};

struct ru_job {
    char name[OR_NAME];
    const char *src;
    const char *extra; /* ISA flags of a program, "" otherwise */
    bool prog;
};

struct ru_run {
    const struct ru_cfg *cfg;
    struct or_cfg oc;
    struct or_cmd *cmd;
    char *diag;
    char out[OR_PATH];
    char cc[OR_PATH], ld[OR_PATH];
    char ccsha[65], ldsha[65];
    char target[OR_PATH];
    struct ru_art art[RU_MAX_ART];
    int nart;
};

/* One named refusal line, in the style of check-object-reproducible. Always
 * returns false, so a bool caller can return it directly. */
static bool ru_refuse(const char *code, const char *what)
{
    printf(RU ": REFUSED %s: %s\n", code, what);
    return false;
}

/* ---- manifest lines (pure: the self-test drives these) ------------------- */

/* "--target=<triple>" -> the triple, NULL when it is not that shape. */
static const char *ru_triple(const char *target)
{
    size_t n = strlen(RU_TARGET_PREFIX);
    return strncmp(target, RU_TARGET_PREFIX, n) == 0 && target[n] ? target + n
                                                                   : NULL;
}

static int ru_art_cmp(const void *a, const void *b)
{
    return strcmp(((const struct ru_art *)a)->name,
                  ((const struct ru_art *)b)->name);
}

/* One artifact line, '\n'-terminated; false when it does not fit. */
static bool ru_format_line(const struct ru_art *a, const char *triple,
                           char *out, size_t cap)
{
    int n = snprintf(out, cap, "%s\t%s\t%llu\t%s\t%s\t%s\n", a->name, a->sha,
                     (unsigned long long)a->size, a->srcs, a->flags, triple);
    return n > 0 && (size_t)n < cap;
}

/* One toolchain header line: key, tab, sha256, newline. */
static bool ru_format_header(const char *key, const char *sha, char *out,
                             size_t cap)
{
    int n = snprintf(out, cap, "%s\t%s\n", key, sha);
    return n > 0 && (size_t)n < cap;
}

static bool ru_write_lines(FILE *f, const struct ru_run *r, const char *triple)
{
    char line[RU_LINE];
    if (!ru_format_header(RU_HDR_CC, r->ccsha, line, sizeof line)
        || fputs(line, f) < 0)
        return false;
    if (!ru_format_header(RU_HDR_LD, r->ldsha, line, sizeof line)
        || fputs(line, f) < 0)
        return false;
    for (int i = 0; i < r->nart; i++) {
        if (!ru_format_line(&r->art[i], triple, line, sizeof line)
            || fputs(line, f) < 0)
            return false;
    }
    return true;
}

/* Sorted, written to MANIFEST.tmp, then renamed over MANIFEST. */
static bool ru_write_manifest(struct ru_run *r, const char *triple)
{
    char path[OR_PATH], tmp[OR_PATH];
    FILE *f;
    bool ok;
    qsort(r->art, (size_t)r->nart, sizeof r->art[0], ru_art_cmp);
    if (!or_join(path, sizeof path, r->out, RU_MANIFEST)
        || !or_join(tmp, sizeof tmp, r->out, RU_MANIFEST_TMP))
        return ru_refuse("PATH_TOO_LONG", "the MANIFEST path does not fit");
    f = fopen(tmp, "wb");
    if (!f)
        return ru_refuse("IO_ERROR", "cannot create the MANIFEST temporary");
    ok = ru_write_lines(f, r, triple);
    if (fclose(f) != 0 || !ok) {
        (void)unlink(tmp);
        return ru_refuse("IO_ERROR", "cannot write the MANIFEST");
    }
    if (rename(tmp, path) != 0) {
        (void)unlink(tmp);
        return ru_refuse("IO_ERROR", "cannot move the MANIFEST into place");
    }
    return true;
}

/* Remove an old MANIFEST and any leftover temporary, so that a build which
 * fails never leaves a MANIFEST behind for a later reader to trust. */
static bool ru_drop_manifest(const char *out)
{
    char path[OR_PATH], tmp[OR_PATH];
    if (!or_join(path, sizeof path, out, RU_MANIFEST)
        || !or_join(tmp, sizeof tmp, out, RU_MANIFEST_TMP))
        return ru_refuse("PATH_TOO_LONG", "the MANIFEST path does not fit");
    if ((unlink(path) != 0 && errno != ENOENT)
        || (unlink(tmp) != 0 && errno != ENOENT))
        return ru_refuse("IO_ERROR", "cannot remove the old MANIFEST");
    return true;
}

/* ---- commands ------------------------------------------------------------ */

static bool ru_cmd_head(struct ru_run *r, const char *root)
{
    struct or_cmd *c = r->cmd;
    c->n = 0;
    return or_add(c, r->cc) && or_add(c, r->target)
           && or_add_words(c, &r->oc, r->cfg->base, root, true)
           && or_add(c, "-c");
}

static bool ru_cmd_flags(struct ru_run *r, const char *root,
                         const struct ru_job *j)
{
    struct or_cmd *c = r->cmd;
    if (j->prog)
        return or_add_words(c, &r->oc, r->cfg->xcc_flags, root, true)
               && or_add_words(c, &r->oc, j->extra, root, true)
               && or_add_words(c, &r->oc, r->cfg->repro, root, true)
               && or_add(c, "-x") && or_add(c, "c");
    return or_add_words(c, &r->oc, r->cfg->cross, root, true)
           && or_add_incs(c)
           && or_add_words(c, &r->oc, r->cfg->repro, root, true);
}

static bool ru_cmd_compile(struct ru_run *r, const char *root,
                           const struct ru_job *j, const char *obj)
{
    bool ok = ru_cmd_head(r, root) && ru_cmd_flags(r, root, j);
    ok = ok && or_add(r->cmd, j->src) && or_add(r->cmd, "-o")
         && or_add(r->cmd, obj);
    return or_seal(r->cmd, ok);
}

static bool ru_cmd_link(struct ru_run *r, const char *root, const char *exe,
                        const char *obj)
{
    struct or_cmd *c = r->cmd;
    c->n = 0;
    bool ok = or_add(c, r->ld)
              && or_add_words(c, &r->oc, r->cfg->xld_flags, root, true)
              && or_add(c, "-o") && or_add(c, exe) && or_add(c, obj);
    return or_seal(c, ok);
}

/* Tokens after argv[0], without "-o <path>", NUL-separated into the hash. */
static void ru_hash_cmd(struct or_sha *s, const struct or_cmd *c)
{
    for (int i = 1; i < c->n; i++) {
        if (strcmp(c->tok[i], "-o") == 0) {
            i++;
            continue;
        }
        or_sha_update(s, c->tok[i], strlen(c->tok[i]) + 1);
    }
}

/* The exact flag text of the job, the tree root shown as <ROOT>. */
static bool ru_flags_hash(struct ru_run *r, const struct ru_job *j,
                          bool linked, char out[65])
{
    struct or_sha s;
    or_sha_init(&s);
    if (!ru_cmd_compile(r, "<ROOT>", j, "-"))
        return false;
    ru_hash_cmd(&s, r->cmd);
    if (linked) {
        if (!ru_cmd_link(r, "<ROOT>", "-", "-"))
            return false;
        ru_hash_cmd(&s, r->cmd);
    }
    or_sha_hex(&s, out);
    return true;
}

/* ---- execution ----------------------------------------------------------- */

static bool ru_exec(struct ru_run *r, const char *what, const char *out)
{
    int tmo = 0;
    if (unlink(out) != 0 && errno != ENOENT)
        return ru_refuse("IO_ERROR", "cannot remove a stale artifact first");
    if (!or_run_compiler(r->cmd, r->diag, &tmo)) {
        printf(RU ": REFUSED STEP_FAILED: %s\n%.2000s\n", what, r->diag);
        return false;
    }
    return true;
}

/* An object is ELF64 little-endian RISC-V ET_REL with sections in bounds. */
static bool ru_obj_ok(const unsigned char *b, size_t len)
{
    return len >= 20 && or_elf_valid(b, len) && b[4] == RU_ELF_CLASS64
           && b[5] == RU_ELF_LE && (b[16] | (b[17] << 8)) == RU_ET_REL
           && (b[18] | (b[19] << 8)) == RU_EM_RISCV;
}

/* A program is ELF64 RISC-V ET_EXEC (or_xlink_elf_ok); an object is ET_REL. */
static bool ru_format_ok(const char *path, bool linked)
{
    size_t len = 0;
    unsigned char *b = or_read_file(path, &len);
    bool ok = b && (linked ? or_xlink_elf_ok(b, len) : ru_obj_ok(b, len));
    free(b);
    return ok;
}

static bool ru_add_art(struct ru_run *r, const struct ru_job *j,
                       const char *name, const char *path, bool linked)
{
    struct ru_art *a = &r->art[r->nart];
    struct stat st;
    char h[65];
    if (r->nart >= RU_MAX_ART)
        return ru_refuse("TOO_MANY_ARTIFACTS", "more artifacts than RU_MAX_ART");
    if (stat(path, &st) != 0 || st.st_size <= 0)
        return ru_refuse("ARTIFACT_MISSING", "an artifact was not written");
    if (!ru_format_ok(path, linked))
        return ru_refuse("ARTIFACT_FORMAT",
                         linked ? "a program is not ELF64 RISC-V ET_EXEC"
                                : "an object is not ELF64 RISC-V ET_REL");
    if (!or_hash_file(path, a->sha) || !or_hash_file(j->src, h))
        return ru_refuse("IO_ERROR", "an artifact or its source cannot be hashed");
    if (!ru_flags_hash(r, j, linked, a->flags))
        return ru_refuse("COMMAND_TOO_LONG", "a flag list does not fit");
    (void)snprintf(a->name, sizeof a->name, "%s", name);
    (void)snprintf(a->srcs, sizeof a->srcs, "%s=%s", j->src, h);
    a->size = (uint64_t)st.st_size;
    r->nart++;
    return true;
}

/* Compile (and for a program link) one job into the output directory. */
static bool ru_job_run(struct ru_run *r, const struct ru_job *j)
{
    char obj[OR_PATH], exe[OR_PATH], oname[OR_NAME + 4];
    (void)snprintf(oname, sizeof oname, "%s.o", j->name);
    if (!or_join(obj, sizeof obj, r->out, oname)
        || !or_join(exe, sizeof exe, r->out, j->name))
        return ru_refuse("PATH_TOO_LONG", "an artifact path does not fit");
    if (!ru_cmd_compile(r, r->cfg->tree, j, obj))
        return ru_refuse("COMMAND_TOO_LONG", "a compile command does not fit");
    if (!ru_exec(r, j->name, obj) || !ru_add_art(r, j, oname, obj, false))
        return false;
    if (!j->prog)
        return true;
    if (!ru_cmd_link(r, r->cfg->tree, exe, obj))
        return ru_refuse("COMMAND_TOO_LONG", "a link command does not fit");
    return ru_exec(r, j->name, exe) && ru_add_art(r, j, j->name, exe, true);
}

/* "dir/name.c" -> "name.o"-less job name "name". */
static void ru_unit_name(const char *path, char *out, size_t cap)
{
    const char *b = strrchr(path, '/');
    const char *dot;
    b = b ? b + 1 : path;
    dot = strrchr(b, '.');
    (void)snprintf(out, cap, "%.*s", (int)(dot ? (size_t)(dot - b) : strlen(b)),
                   b);
}

static bool ru_all_jobs(struct ru_run *r)
{
    static const struct { const char *name; bool isa; } k_prog[] = {
        { "hello-default", false }, { "hello-rv64im", true },
    };
    struct ru_job j = { .src = OR_XLINK_SRC, .prog = true };
    for (size_t i = 0; i < sizeof k_prog / sizeof k_prog[0]; i++) {
        (void)snprintf(j.name, sizeof j.name, "%s", k_prog[i].name);
        j.extra = k_prog[i].isa ? r->cfg->xcc_rv64im : "";
        if (!ru_job_run(r, &j))
            return false;
    }
    j.prog = false;
    j.extra = "";
    for (int i = 0; (j.src = or_cross_unit(i)) != NULL; i++) {
        ru_unit_name(j.src, j.name, sizeof j.name);
        if (!ru_job_run(r, &j))
            return false;
    }
    return true;
}

/* Resolve and hash one tool. A missing tool is a refusal naming the variable,
 * or under --allow-missing one SKIPPED line; an unreadable one is a refusal. */
static int ru_tool(const char *what, const char *name, const char *var,
                   bool allow, char *path, size_t cap, char sha[65])
{
    if (!or_find_exe(name, path, cap)) {
        if (allow) {
            printf(RU ": SKIPPED MISSING_TOOL: %s '%s' not found; the cross "
                   "case is skipped (--allow-missing); set %s to its path to "
                   "run it\n", what, name, var);
            return RU_SKIPPED;
        }
        printf(RU ": REFUSED MISSING_TOOL: %s '%s' not found; set %s to its "
               "path\n", what, name, var);
        return RU_FAILED;
    }
    if (!or_hash_file(path, sha)) {
        printf(RU ": REFUSED TOOL_UNREADABLE: %s '%s' could not be read; set "
               "%s to a readable one\n", what, name, var);
        return RU_FAILED;
    }
    return RU_OK;
}

static int ru_setup(struct ru_run *r, const char *out)
{
    const struct ru_cfg *cfg = r->cfg;
    int st = ru_tool("cross compiler", cfg->xcc, "REPRO_GATE_XCC",
                     cfg->allow_missing, r->cc, sizeof r->cc, r->ccsha);
    if (st == RU_OK)
        st = ru_tool("cross linker", cfg->xld, "REPRO_GATE_XLD",
                     cfg->allow_missing, r->ld, sizeof r->ld, r->ldsha);
    if (st != RU_OK)
        return st;
    if (!or_target_of(cfg->targets, RU_TARGET_CASE, r->target,
                      sizeof r->target)
        || !ru_triple(r->target)) {
        printf(RU ": REFUSED NO_TARGET: REPRO_GATE_TARGETS has no %s=--target"
               "=<triple> entry\n", RU_TARGET_CASE);
        return RU_FAILED;
    }
    r->oc.tree = cfg->tree;
    if (snprintf(r->out, sizeof r->out, "%s", out) >= (int)sizeof r->out) {
        (void)ru_refuse("PATH_TOO_LONG", "the output path does not fit");
        return RU_FAILED;
    }
    return RU_OK;
}

/* Remove the old MANIFEST, set up, build every artifact, write MANIFEST. */
static int ru_run_all(struct ru_run *r, const char *out)
{
    int st;
    if (!ru_drop_manifest(out))
        return RU_FAILED;
    st = ru_setup(r, out);
    if (st != RU_OK)
        return st;
    if (csr_mkdirs(out) != 0) {
        (void)ru_refuse("IO_ERROR", "cannot create the output directory");
        return RU_FAILED;
    }
    if (chdir(r->cfg->tree) != 0) {
        (void)ru_refuse("IO_ERROR", "cannot enter the tree root");
        return RU_FAILED;
    }
    if (!ru_all_jobs(r) || !ru_write_manifest(r, ru_triple(r->target)))
        return RU_FAILED;
    return RU_OK;
}

/* Build everything into `out` (absolute) and write its MANIFEST. */
static int ru_build(const struct ru_cfg *cfg, const char *out)
{
    struct ru_run *r = zcl_malloc(sizeof *r, "ru_run");
    int st = RU_FAILED;
    if (!r) {
        (void)ru_refuse("IO_ERROR", "cannot allocate the build state");
        return RU_FAILED;
    }
    memset(r, 0, sizeof *r);
    r->cfg = cfg;
    r->cmd = zcl_malloc(sizeof *r->cmd, "ru_cmd");
    r->diag = zcl_malloc(OR_DIAG, "ru_diag");
    if (r->cmd && r->diag) {
        g_or_deadline_ms = or_now_ms() + (int64_t)OR_DEADLINE_S * 1000;
        st = ru_run_all(r, out);
    } else {
        (void)ru_refuse("IO_ERROR", "cannot allocate the build buffers");
    }
    free(r->cmd);
    free(r->diag);
    free(r);
    return st;
}

/* ---- --twice: the reproducibility check ----------------------------------- */

static bool ru_abs(const char *in, char *out, size_t cap)
{
    char cwd[OR_PATH];
    if (in[0] == '/')
        return snprintf(out, cap, "%s", in) < (int)cap;
    return getcwd(cwd, sizeof cwd) && or_join(out, cap, cwd, in);
}

/* Name the first differing line of two MANIFEST texts. */
static void ru_report_diff(const unsigned char *a, size_t la,
                           const unsigned char *b, size_t lb)
{
    size_t i = 0, line = 1;
    while (i < la && i < lb && a[i] == b[i]) {
        line += a[i] == '\n';
        i++;
    }
    printf(RU ": MISMATCH: the two MANIFEST files differ at line %zu "
           "(byte %zu; sizes %zu and %zu)\n", line, i, la, lb);
}

/* Pure: OR_OK when the two MANIFEST texts are byte-identical, else OR_MISMATCH.
 * Prints nothing; the caller reports. */
static int ru_compare_bytes(const unsigned char *a, size_t la,
                            const unsigned char *b, size_t lb)
{
    return la == lb && (la == 0 || memcmp(a, b, la) == 0) ? OR_OK
                                                          : OR_MISMATCH;
}

/* Read <dir>/MANIFEST into a buffer; false when it cannot be read. */
static bool ru_load_manifest(const char *dir, unsigned char **buf, size_t *len)
{
    char path[OR_PATH];
    *buf = NULL;
    if (!or_join(path, sizeof path, dir, RU_MANIFEST))
        return false;
    *buf = or_read_file(path, len);
    return *buf != NULL;
}

static int ru_compare(const char *ra, const char *rb)
{
    size_t la = 0, lb = 0;
    unsigned char *a = NULL, *b = NULL;
    int rc = OR_REFUSED;
    if (!ru_load_manifest(ra, &a, &la) || !ru_load_manifest(rb, &b, &lb)) {
        (void)ru_refuse("IO_ERROR", "a MANIFEST could not be read");
    } else {
        rc = ru_compare_bytes(a, la, b, lb);
        if (rc == OR_MISMATCH)
            ru_report_diff(a, la, b, lb);
        else
            printf(RU ": PASS two builds, two output roots, byte-identical "
                   "MANIFEST (%zu bytes)\n", la);
    }
    free(a);
    free(b);
    return rc;
}

/* Build into two roots under `base` (absolute) and compare their MANIFESTs. */
static int ru_twice_in(const struct ru_cfg *cfg, const char *base)
{
    char ra[OR_PATH], rb[OR_PATH];
    int st;
    if (!or_join(ra, sizeof ra, base, "r")
        || !or_join(rb, sizeof rb, base,
                    "output-root-with-a-longer-name-0123")) {
        (void)ru_refuse("PATH_TOO_LONG", "a temp output root does not fit");
        return RU_FAILED;
    }
    st = ru_build(cfg, ra);
    if (st != RU_OK)
        return st;
    st = ru_build(cfg, rb);
    if (st != RU_OK)
        return st;
    return ru_compare(ra, rb);
}

/* Two roots with different names and lengths under the tool temp area. Every
 * path after mkdtemp removes the root; a failed removal is a refusal. */
static int ru_twice(const struct ru_cfg *cfg)
{
    char tmpl[OR_PATH], base[OR_PATH];
    const char *root = tmpl;
    const char *tmp = env_or("TMPDIR", "test-tmp");
    int st = RU_FAILED;
    if (csr_mkdirs(tmp) != 0
        || !or_join(tmpl, sizeof tmpl, tmp, "z23-lint-rv64univ.XXXXXX")
        || !mkdtemp(tmpl)) {
        (void)ru_refuse("IO_ERROR", "cannot create the temp area");
        return RU_FAILED;
    }
    if (ru_abs(tmpl, base, sizeof base)) {
        root = base;
        st = ru_twice_in(cfg, base);
    } else {
        (void)ru_refuse("PATH_TOO_LONG", "the temp root path does not fit");
    }
    if (!or_rm_rf(root, 0)) {
        (void)ru_refuse("CLEANUP_FAILED", "could not remove the temp root");
        return RU_FAILED;
    }
    return st;
}

/* ---- entry points --------------------------------------------------------- */

static bool ru_complete(const struct ru_cfg *cfg)
{
    bool flags = cfg->repro && cfg->base && cfg->cross && cfg->xcc_flags
                 && cfg->xcc_rv64im && cfg->xld_flags && cfg->targets;
    return flags && cfg->tree && cfg->xcc && cfg->xld
           && (cfg->twice || cfg->out);
}

/* Boolean flags: --twice and --allow-missing. */
static bool ru_flag(const char *a, struct ru_cfg *cfg)
{
    if (strcmp(a, "--twice") == 0) {
        cfg->twice = true;
        return true;
    }
    if (strcmp(a, "--allow-missing") == 0) {
        cfg->allow_missing = true;
        return true;
    }
    return false;
}

static bool ru_parse(int argc, char **argv, struct ru_cfg *cfg)
{
    struct { const char *key; const char **slot; } tab[] = {
        { "--tree-root", &cfg->tree }, { "--out", &cfg->out },
        { "--repro-cflags", &cfg->repro }, { "--base-cflags", &cfg->base },
        { "--cross-flags", &cfg->cross }, { "--xcc-flags", &cfg->xcc_flags },
        { "--xcc-rv64im-flags", &cfg->xcc_rv64im },
        { "--xcc", &cfg->xcc }, { "--xld", &cfg->xld },
        { "--xld-flags", &cfg->xld_flags }, { "--targets", &cfg->targets },
        { "--unsupported-host", &cfg->unsupported },
    };
    memset(cfg, 0, sizeof *cfg);
    for (int i = 0; i < argc; i++) {
        bool hit = ru_flag(argv[i], cfg);
        for (size_t k = 0; !hit && i + 1 < argc && k < sizeof tab / sizeof tab[0];
             k++) {
            if (strcmp(argv[i], tab[k].key) == 0) {
                *tab[k].slot = argv[++i];
                hit = true;
            }
        }
        if (!hit)
            return false;
    }
    return ru_complete(cfg);
}

int riscv64_universal_run(int argc, char **argv)
{
    struct ru_cfg cfg;
    char out[OR_PATH], tree[OR_PATH];
    int st;
    if (!ru_parse(argc, argv, &cfg)) {
        fprintf(stderr, RU ": REFUSED BAD_ARGS: need --tree-root DIR --out DIR "
                "(or --twice) --repro-cflags STR --base-cflags STR "
                "--cross-flags STR --xcc-flags STR --xcc-rv64im-flags STR "
                "--xcc PROG --xld PROG --xld-flags STR --targets NAME=FLAG,..; "
                "optional --allow-missing and --unsupported-host NAME; the "
                "Makefile recipe passes them\n");
        return OR_REFUSED;
    }
    if (cfg.unsupported) {
        printf(RU ": SKIPPED_HOST host=%s reason=the build host is not Linux, "
               "and this gate links with GNU-ld flags; nothing was built, so "
               "this is a skip, not a PASS\n", cfg.unsupported);
        return OR_OK;
    }
    if (!ru_abs(cfg.tree, tree, sizeof tree)
        || (!cfg.twice && !ru_abs(cfg.out, out, sizeof out))) {
        (void)ru_refuse("PATH_TOO_LONG", "a path does not fit");
        return OR_REFUSED;
    }
    cfg.tree = tree;
    st = cfg.twice ? ru_twice(&cfg) : ru_build(&cfg, out);
    return st == RU_SKIPPED ? OR_OK : st;
}

/* Pure: artifact line shape, sort order, header line, triple parse. */
static bool ru_selftest_lines(void)
{
    struct ru_art a[2] = {
        { .name = "z.o", .sha = "s1", .flags = "f1", .srcs = "p=h", .size = 7 },
        { .name = "a", .sha = "s2", .flags = "f2", .srcs = "q=i", .size = 9 },
    };
    char line[RU_LINE];
    qsort(a, 2, sizeof a[0], ru_art_cmp);
    return strcmp(a[0].name, "a") == 0
           && ru_format_line(&a[0], "t", line, sizeof line)
           && strcmp(line, "a\ts2\t9\tq=i\tf2\tt\n") == 0
           && ru_format_line(&a[1], "t", line, sizeof line)
           && strcmp(line, "z.o\ts1\t7\tp=h\tf1\tt\n") == 0
           && !ru_format_line(&a[1], "t", line, 8)
           && ru_format_header(RU_HDR_CC, "h1", line, sizeof line)
           && strcmp(line, "toolchain-compiler\th1\n") == 0
           && ru_triple("--target=x-y") && !ru_triple("--target=")
           && !ru_triple("x");
}

/* Pure: two differing buffers report a mismatch; equal ones pass; a missing
 * second MANIFEST is refused (its load fails). */
static bool ru_selftest_compare(void)
{
    const unsigned char *ab = (const unsigned char *)"ab\n";
    const unsigned char *ac = (const unsigned char *)"ac\n";
    unsigned char *buf = NULL;
    size_t len = 0;
    bool ok = ru_compare_bytes(ab, 3, ab, 3) == OR_OK
              && ru_compare_bytes(ab, 3, ac, 3) == OR_MISMATCH
              && ru_compare_bytes(ab, 3, ab, 2) == OR_MISMATCH
              && !ru_load_manifest("no-such-rv64univ-dir-zz", &buf, &len);
    free(buf);
    return ok;
}

int riscv64_universal_selftest(void)
{
    bool ok = ru_selftest_lines() && ru_selftest_compare();
    if (!ok)
        fprintf(stderr, RU ": selftest FAILED\n");
    return ok ? 0 : 1;
}
