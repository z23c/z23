/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * zcc — in-tree, content-addressed compile cache. A native replacement for
 * ccache/sccache that ships WITH the repository, so a developer who cloned
 * five minutes ago gets the same fast rebuilds as the maintainer without
 * installing anything. That is the same promise the node itself makes: stock
 * libc plus in-tree sources, no runtime dependency to fetch.
 *
 * WHY THIS EXISTS, measured. `check-standalone-tools-link` builds 47
 * standalone tool binaries. Each rule is ONE compile-and-link command over a
 * dozen or more lib sources, so every tool recompiles the same
 * sha3.c/safe_alloc.c/... from scratch: 11 m 29 s of CPU inside a 117 s wall,
 * and it goes cold whenever a timestamp moves rather than when a byte does.
 * A per-object cache would not touch it — those commands have no -c. This
 * cache is therefore keyed on ANY single-output compiler invocation, link
 * steps included.
 *
 * USAGE — transparent wrapper, exec-compatible with the compiler:
 *     zcc cc -O2 -c foo.c -o foo.o
 *     zcc cc -O2 a.c b.c -o build/bin/tool -lm
 *     zcc --zcc-stats | --zcc-clear | --zcc-trim <MB>
 *
 * THE KEY. Two levels, both SHA3-256.
 *
 *   Level 1 (probe key + manifest) — compiler identity, cwd, normalized
 *   argv, and for every input file named on the command line its (path, size,
 *   mtime_ns, inode). Cheap: no preprocessing at all. This is the level that
 *   makes "the Makefile timestamp moved but no source changed" free, which is
 *   the measured case above. It maps to a MANIFEST, not to an artifact: the
 *   manifest records the level-2 key plus the stat triple of every file that
 *   compile actually read, harvested for free from the `# 1 "..."` line
 *   markers already present in the level-2 preprocessor output. Serving from
 *   level 1 requires every one of those files to still match.
 *
 *   That manifest is not an optimization, it is the correctness of level 1.
 *   The first version of this cache keyed level 1 on the argv inputs alone
 *   and served a stale object after a header edit: the .c file's stat triple
 *   had not moved, so nothing noticed. The test suite now pins that case.
 *
 *   Level 2 (content key) — compiler identity, cwd, normalized argv, the
 *   PREPROCESSED text of every .c input (so headers, -I paths, -D macros and
 *   include order are all folded in exactly), and the raw bytes of every
 *   object/archive input. An @response-file is expanded
 *   first, so the objects one link names through it are keyed exactly like
 *   objects spelled on the command line.
 *
 * A level-1 hit trusts (size, mtime_ns, inode) to stand for content, for the
 * inputs AND for every recorded include. That is the one place this cache
 * trades a theoretical correctness margin for speed, exactly as ccache's
 * direct mode does. ZCC_STRICT=1 removes the trade by skipping level 1
 * entirely, and ZCC_AUDIT=1 proves it empirically: every hit is recompiled
 * for real and byte-compared, and a divergence is reported loudly and served
 * from the fresh build. Run the audit after touching this file; that is what
 * makes the fast path believable rather than asserted.
 *
 * WHAT IS NEVER CACHED (bypass, exec the compiler unchanged):
 *   - no -o, or -o -            : no single artifact to store
 *   - -E, -M, -MM               : the output IS the preprocessor's
 *   - --coverage, -fprofile-*   : writes .gcno/.gcda beside the object
 *   - a -E probe that fails     : let the real compiler print the real error
 *   - an unusable cache dir     : never fail a build over a cache
 *   - an @response-file this cache cannot parse (quotes, escapes, or a
 *     token that names no readable file)
 *
 * DEPFILES. -MD/-MMD/-MF produce a second artifact. It is stored and restored
 * with the object; a hit that silently skipped the .d file would corrupt
 * make's header tracking, which is worse than a slow build.
 *
 * THE HONEST HOLE. A link step naming a system library (-lm, -lpthread) that
 * this cache cannot resolve under a -L directory folds only the literal token
 * into the key, so a libc upgrade underneath a cached link is not detected.
 * Clear the cache after a toolchain change (`make cc-cache-clear`). The
 * hermetic goals (ci-reproducible, repro-verify) already force
 * ZCL_USE_CCACHE=0, so no reproducibility claim is ever served from here.
 */

#define _POSIX_C_SOURCE 200809L

#include "base/hex.h"
#include "base/safe_alloc.h"
#include "base/serialize_le.h"
#include "sha3/sha3.h"

#include <ctype.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#define ZCC_MAGIC "zcc.cache.v1"
#define HEXLEN (SHA3_256_OUTPUT_SIZE * 2u)

/* ── tiny growable buffer ────────────────────────────────────────────── */

struct buf {
    unsigned char *p;
    size_t len;
    size_t cap;
};

static bool buf_reserve(struct buf *b, size_t extra)
{
    if (b->len + extra <= b->cap)
        return true;
    size_t cap = b->cap ? b->cap : 4096;
    while (cap < b->len + extra) {
        if (cap > SIZE_MAX / 2)
            return false;
        cap *= 2;
    }
    unsigned char *np = zcl_realloc(b->p, cap, "zcc buffer");
    if (!np)
        return false;
    b->p = np;
    b->cap = cap;
    return true;
}

static bool buf_add(struct buf *b, const void *data, size_t len)
{
    if (!buf_reserve(b, len))
        return false;
    memcpy(b->p + b->len, data, len);
    b->len += len;
    return true;
}

static void buf_free(struct buf *b)
{
    free(b->p);
    b->p = NULL;
    b->len = b->cap = 0;
}

/* ── hashing ─────────────────────────────────────────────────────────── */

/* Every field is length-prefixed so no two different field sequences can
 * serialize to the same byte stream. */
static void hfield(struct sha3_256_ctx *h, const void *data, size_t len)
{
    uint8_t hdr[8];
    zcl_write_u64_le(hdr, (uint64_t)len);
    sha3_256_write(h, hdr, sizeof hdr);
    sha3_256_write(h, (const unsigned char *)data, len);
}

static void hstr(struct sha3_256_ctx *h, const char *s)
{
    hfield(h, s, s ? strlen(s) : 0u);
}

static void hu64(struct sha3_256_ctx *h, uint64_t v)
{
    uint8_t b[8];
    zcl_write_u64_le(b, v);
    hfield(h, b, sizeof b);
}

static void hex_of(const unsigned char d[SHA3_256_OUTPUT_SIZE],
                   char out[HEXLEN + 1u])
{
    zcl_hex_encode(d, SHA3_256_OUTPUT_SIZE, out);
}

/* ── file helpers ────────────────────────────────────────────────────── */

static bool read_file(const char *path, struct buf *out)
{
    int fd = open(path, O_RDONLY | O_CLOEXEC);
    if (fd < 0)
        return false;
    unsigned char chunk[65536];
    for (;;) {
        ssize_t n = read(fd, chunk, sizeof chunk);
        if (n < 0) {
            if (errno == EINTR)
                continue;
            close(fd);
            return false;
        }
        if (n == 0)
            break;
        if (!buf_add(out, chunk, (size_t)n)) {
            close(fd);
            return false;
        }
    }
    close(fd);
    return true;
}

static bool write_all(int fd, const unsigned char *p, size_t len)
{
    while (len > 0) {
        ssize_t n = write(fd, p, len);
        if (n < 0) {
            if (errno == EINTR)
                continue;
            return false;
        }
        p += n;
        len -= (size_t)n;
    }
    return true;
}

static bool mkdir_p(const char *path)
{
    char tmp[PATH_MAX];
    if (snprintf(tmp, sizeof tmp, "%s", path) >= (int)sizeof tmp)
        return false;
    for (char *p = tmp + 1; *p; p++) {
        if (*p != '/')
            continue;
        *p = '\0';
        if (mkdir(tmp, 0700) != 0 && errno != EEXIST)
            return false;
        *p = '/';
    }
    return mkdir(tmp, 0700) == 0 || errno == EEXIST;
}

/* Write through a temp file in the same directory, then rename: a parallel
 * make must never observe a half-written cache entry. */
static bool store_atomic(const char *dir, const char *final_path,
                         const unsigned char *data, size_t len, mode_t mode)
{
    char tmp[PATH_MAX];
    if (snprintf(tmp, sizeof tmp, "%.3000s/.zcc.XXXXXX", dir) >= (int)sizeof tmp)
        return false;
    int fd = mkstemp(tmp);
    if (fd < 0)
        return false;
    bool ok = write_all(fd, data, len);
    if (ok)
        ok = (fchmod(fd, mode) == 0);
    if (close(fd) != 0)
        ok = false;
    if (ok && rename(tmp, final_path) == 0)
        return true;
    unlink(tmp);
    return false;
}

static bool copy_out(const char *cached, const char *dest)
{
    struct buf b = { 0 };
    struct stat st;
    if (stat(cached, &st) != 0 || !read_file(cached, &b)) {
        buf_free(&b);
        return false;
    }
    char dir[PATH_MAX];
    snprintf(dir, sizeof dir, "%s", dest);
    char *slash = strrchr(dir, '/');
    if (slash)
        *slash = '\0';
    else
        snprintf(dir, sizeof dir, ".");
    bool ok = store_atomic(dir, dest, b.p, b.len, st.st_mode & 07777u);
    buf_free(&b);
    return ok;
}

/* ── process launch (no shell, ever) ─────────────────────────────────── */

static int run_argv(char *const argv[], const char *stdout_path,
                    const char *stderr_path)
{
    pid_t pid = fork();
    if (pid < 0)
        return -1;
    if (pid == 0) {
        /* async-signal-safe only until exec */
        if (stdout_path) {
            int fd = open(stdout_path, O_WRONLY | O_CREAT | O_TRUNC, 0600);
            if (fd < 0 || dup2(fd, STDOUT_FILENO) < 0)
                _exit(127);
            close(fd);
        }
        if (stderr_path) {
            int fd = open(stderr_path, O_WRONLY | O_CREAT | O_TRUNC, 0600);
            if (fd < 0 || dup2(fd, STDERR_FILENO) < 0)
                _exit(127);
            close(fd);
        }
        execvp(argv[0], argv);
        _exit(127);
    }
    int status = 0;
    while (waitpid(pid, &status, 0) < 0) {
        if (errno != EINTR)
            return -1;
    }
    if (WIFEXITED(status))
        return WEXITSTATUS(status);
    return 128 + (WIFSIGNALED(status) ? WTERMSIG(status) : 0);
}

/* ── argv analysis ───────────────────────────────────────────────────── */

struct plan {
    char **argv;      /* the compiler command, NULL-terminated */
    int argc;
    int out_idx;      /* index of the -o VALUE, or -1 */
    const char *out_path;
    const char *dep_path;
    int dep_idx;          /* index of the -MF VALUE, or -1 */
    int dep_inline_idx;   /* index of a joined -MFvalue, or -1 */
    char dep_buf[PATH_MAX];
    int *src;         /* indexes of .c inputs */
    int src_n;
    int *blob;        /* indexes of existing non-source file inputs */
    int blob_n;
    char **libdir;    /* -L directories */
    int libdir_n;
    /* Inputs named INSIDE an @response-file, plus the response file itself.
     * They are file inputs like any other; they simply are not spelled on
     * the command line. Owned strings, because nothing in argv points at
     * them. */
    char **rsp;
    int rsp_n;
    const char *bypass;
};

static bool has_suffix(const char *s, const char *suf)
{
    size_t ls = strlen(s), lf = strlen(suf);
    return ls >= lf && strcmp(s + ls - lf, suf) == 0;
}

static bool is_regular(const char *p)
{
    struct stat st;
    return stat(p, &st) == 0 && S_ISREG(st.st_mode);
}

/* Grow-on-demand list of owned input paths harvested from response files. */
static bool plan_push_rsp(struct plan *pl, const char *path, size_t len)
{
    if (len == 0)
        return true;
    char *copy = zcl_malloc(len + 1u, "zcc response-file input");
    if (!copy) {
        pl->bypass = "out of memory";
        return false;
    }
    memcpy(copy, path, len);
    copy[len] = '\0';
    if (!is_regular(copy)) {
        /* A token that names no readable file cannot be keyed on, and
         * guessing what it meant is how a cache starts lying. */
        free(copy);
        pl->bypass = "response file names something this cache cannot stat";
        return false;
    }
    char **np = zcl_realloc(pl->rsp, ((size_t)pl->rsp_n + 1u) * sizeof *np,
                            "zcc response-file inputs");
    if (!np) {
        free(copy);
        pl->bypass = "out of memory";
        return false;
    }
    pl->rsp = np;
    pl->rsp[pl->rsp_n++] = copy;
    return true;
}

/* A response file (`@path`) is how one link names thousands of objects
 * without overflowing ARG_MAX. Every one of those objects is an input, yet
 * none of them appears in argv — so a cache that keys only on what argv
 * names sees a link whose inputs never change. This tree hit exactly that:
 * an edited test object recompiled, relinked, and the resulting binary still
 * ran the OLD code, because the link was served from the cache on a key that
 * had not moved. A suite then reported results for a function that no longer
 * existed in the source. Absorb the listed files as the real inputs they
 * are, and hash the response file itself so a changed object LIST changes
 * the key too.
 *
 * Only whitespace-separated plain paths are understood. Quoting and
 * backslash escapes are legal in GNU response files; rather than key on a
 * guess about them, a response file that uses them bypasses the cache. */
static bool plan_absorb_response_file(struct plan *pl, const char *path)
{
    struct buf b = { 0 };
    if (!read_file(path, &b)) {
        buf_free(&b);
        pl->bypass = "response file could not be read";
        return false;
    }
    /* The list itself is an input: dropping one object changes nothing about
     * the remaining objects' bytes. */
    if (!plan_push_rsp(pl, path, strlen(path))) {
        buf_free(&b);
        return false;
    }
    size_t i = 0;
    while (i < b.len) {
        while (i < b.len && isspace((unsigned char)b.p[i]))
            i++;
        if (i >= b.len)
            break;
        if (b.p[i] == '"' || b.p[i] == '\'' || b.p[i] == '\\') {
            buf_free(&b);
            pl->bypass = "response file uses quoting this cache does not parse";
            return false;
        }
        size_t start = i;
        while (i < b.len && !isspace((unsigned char)b.p[i]))
            i++;
        if (!plan_push_rsp(pl, (const char *)b.p + start, i - start)) {
            buf_free(&b);
            return false;
        }
    }
    buf_free(&b);
    return true;
}

static void plan_build(struct plan *pl, int argc, char **argv)
{
    pl->argv = argv;
    pl->argc = argc;
    pl->out_idx = -1;
    pl->dep_idx = -1;
    pl->dep_inline_idx = -1;
    pl->src = zcl_calloc((size_t)argc, sizeof *pl->src, "zcc sources");
    pl->blob = zcl_calloc((size_t)argc, sizeof *pl->blob, "zcc blob inputs");
    pl->libdir = zcl_calloc((size_t)argc, sizeof *pl->libdir, "zcc -L dirs");
    if (!pl->src || !pl->blob || !pl->libdir) {
        pl->bypass = "out of memory";
        return;
    }

    bool want_dep = false;
    const char *dep_explicit = NULL;

    for (int i = 1; i < argc; i++) {
        const char *a = argv[i];
        if (strcmp(a, "-o") == 0 && i + 1 < argc) {
            pl->out_idx = ++i;
            pl->out_path = argv[i];
        } else if (strcmp(a, "-E") == 0 || strcmp(a, "-M") == 0 ||
                   strcmp(a, "-MM") == 0) {
            pl->bypass = "preprocessor-only invocation";
            return;
        } else if (strcmp(a, "--coverage") == 0 ||
                   strncmp(a, "-fprofile", 9) == 0 ||
                   strcmp(a, "-ftest-coverage") == 0) {
            pl->bypass = "coverage writes artifacts beside the object";
            return;
        } else if (strcmp(a, "-MD") == 0 || strcmp(a, "-MMD") == 0) {
            want_dep = true;
        } else if (strcmp(a, "-MF") == 0 && i + 1 < argc) {
            dep_explicit = argv[++i];
            pl->dep_idx = i;
        } else if (strncmp(a, "-MF", 3) == 0 && a[3]) {
            dep_explicit = a + 3;
            pl->dep_inline_idx = i;
        } else if ((strcmp(a, "-MT") == 0 || strcmp(a, "-MQ") == 0) &&
                   i + 1 < argc) {
            /* -MT/-MQ NAME the make target in the depfile. Their value is an
             * object path, not an input. Leaving it unconsumed made it look
             * like a positional input, which broke the -E probe and silently
             * bypassed EVERY node object in this repository. */
            i++;
        } else if (strcmp(a, "-L") == 0 && i + 1 < argc) {
            pl->libdir[pl->libdir_n++] = argv[++i];
        } else if (strncmp(a, "-L", 2) == 0 && a[2]) {
            pl->libdir[pl->libdir_n++] = argv[i] + 2;
        } else if (a[0] == '@' && a[1]) {
            if (!plan_absorb_response_file(pl, a + 1))
                return;
        } else if (a[0] == '-') {
            continue;
        } else if (has_suffix(a, ".c")) {
            pl->src[pl->src_n++] = i;
        } else if (is_regular(a)) {
            pl->blob[pl->blob_n++] = i;
        }
    }

    if (!pl->out_path || strcmp(pl->out_path, "-") == 0) {
        pl->bypass = "no single -o artifact";
        return;
    }
    if (pl->src_n == 0 && pl->blob_n == 0 && pl->rsp_n == 0) {
        pl->bypass = "no file inputs to key on";
        return;
    }

    if (dep_explicit) {
        pl->dep_path = dep_explicit;
    } else if (want_dep) {
        /* gcc -MD without -MF writes <output-with-.d>. */
        snprintf(pl->dep_buf, sizeof pl->dep_buf, "%s", pl->out_path);
        char *dot = strrchr(pl->dep_buf, '.');
        char *slash = strrchr(pl->dep_buf, '/');
        if (dot && (!slash || dot > slash))
            *dot = '\0';
        size_t n = strlen(pl->dep_buf);
        if (n + 3u < sizeof pl->dep_buf) {
            memcpy(pl->dep_buf + n, ".d", 3);
            pl->dep_path = pl->dep_buf;
        }
    }
}

/* ── keying ──────────────────────────────────────────────────────────── */

/* THE RECORDED WORKING DIRECTORY.
 *
 * -g writes the working directory into the object as DW_AT_comp_dir, so the
 * directory is part of the artifact's identity even though it appears in no
 * flag. It is the RECORDED directory that is part of that identity, though,
 * not the real one, and this repository compiles everything with
 * -ffile-prefix-map=$(CURDIR)=/zclassic23 (Makefile REPRO_CFLAGS) precisely
 * so the recorded one is a constant. Hashing the raw getcwd() therefore keyed
 * on a path the compiler had already erased: two checkouts produced
 * byte-identical objects and this cache called the second one a miss. Every
 * worktree got a 100% cold compile cache — measured 5.0% fleet hit rate with
 * 24 worktrees on one host, 195 GB of cache serving almost nothing.
 *
 * What goes in the key is therefore the directory the compiler will ACTUALLY
 * record: getcwd() with the prefix maps named in argv applied to it.
 *
 * GCC's parsing and matching rules, each VERIFIED on this toolchain rather
 * than assumed, because a wrong rule here serves a wrong object:
 *   - -ffile-prefix-map=ARG and -fdebug-prefix-map=ARG split ARG into OLD and
 *     NEW at the LAST '=', not the first. A build directory whose name
 *     contains '=' IS remapped by a map naming it, and a replacement that
 *     contains '=' is NOT parsed as one.
 *   - the match is a raw string prefix with no directory-boundary check:
 *     OLD=/a/plain rewrites /a/plainX to <NEW>X, so the remainder is appended
 *     verbatim.
 *   - when several maps match, the LAST one on the command line wins.
 *   - -fmacro-prefix-map moves __FILE__, never DW_AT_comp_dir, and is
 *     deliberately not consulted here.
 *
 * SAFETY DIRECTION. Every case this cannot model with certainty — no map, an
 * unparseable value, a getcwd() that failed — falls back to hashing the real
 * cwd exactly as before. This change may only ever make the key match MORE
 * builds that produce identical bytes; it must never make the key weaker in a
 * case that was not proven, so do not "simplify" a fallback away. */

/* The length of the prefix-map option name at the head of `a`, or 0 when `a`
 * is not one of the two options that can move DW_AT_comp_dir. */
static size_t prefix_map_opt(const char *a)
{
    static const char *const opt[] = { "-ffile-prefix-map=",
                                       "-fdebug-prefix-map=" };
    for (size_t i = 0; i < sizeof opt / sizeof opt[0]; i++) {
        size_t n = strlen(opt[i]);
        if (strncmp(a, opt[i], n) == 0)
            return n;
    }
    return 0;
}

/* Split a map's OLD=NEW value at the last '=' and report whether OLD is a
 * prefix of `cwd`, which is exactly when this map is the one that rewrites
 * the recorded directory. On a match `old_len` is OLD's length and `repl`
 * points at NEW inside `val`. */
static bool prefix_map_covers(const char *val, const char *cwd,
                              size_t *old_len, const char **repl)
{
    const char *eq = strrchr(val, '=');
    if (!eq)
        return false;
    size_t n = (size_t)(eq - val);
    /* An OLD of "", "/" or a relative path would rewrite paths this cache has
     * not reasoned about — every system header, for one. Decline to model it
     * and keep the raw cwd in the key. */
    if (n < 2u || val[0] != '/')
        return false;
    if (strncmp(cwd, val, n) != 0)
        return false;
    *old_len = n;
    *repl = eq + 1;
    return true;
}

/* Does this invocation write GCC LTO IR? MEASURED, and the reason this whole
 * mechanism has to be able to decline: a slim -flto object is NOT made
 * directory-independent by a prefix map. Same source, same pinned
 * -frandom-seed, two directories, the repository's release flag set with
 * -ffile-prefix-map pointing each one at /zclassic23 — the non-LTO objects
 * come out byte-identical and the LTO objects do not (they differ inside the
 * streamed .gnu.lto_* IR, which the map never touches). Sharing an LTO object
 * across directories would hand the linker IR carrying another checkout's
 * identity, so an -flto compile keeps the real cwd in its key and stays
 * unshared. -fno-lto later on the command line wins, as it does for GCC. */
static bool lto_in_effect(const struct plan *pl)
{
    bool lto = false;
    for (int i = 1; i < pl->argc; i++) {
        const char *a = pl->argv[i];
        if (strcmp(a, "-fno-lto") == 0)
            lto = false;
        else if (strcmp(a, "-flto") == 0 || strncmp(a, "-flto=", 6) == 0)
            lto = true;
    }
    return lto;
}

/* The directory the compiler will record, given the real one. False means no
 * map applies, or none can be trusted to, and the real cwd is the answer. */
static bool recorded_cwd(const struct plan *pl, const char *cwd,
                         char out[PATH_MAX])
{
    if (lto_in_effect(pl))
        return false;
    size_t old_len = 0;
    const char *repl = NULL;
    for (int i = 1; i < pl->argc; i++) {
        size_t opt = prefix_map_opt(pl->argv[i]);
        size_t n;
        const char *r;
        if (opt && prefix_map_covers(pl->argv[i] + opt, cwd, &n, &r)) {
            old_len = n; /* a later matching option overrides an earlier one */
            repl = r;
        }
    }
    if (!repl)
        return false;
    int w = snprintf(out, PATH_MAX, "%s%s", repl, cwd + old_len);
    return w > 0 && (size_t)w < PATH_MAX;
}

/* argv with the -o VALUE replaced by a fixed placeholder: the artifact's
 * destination must not change the key, but every other flag must. */
/* Where an artifact is WRITTEN does not change the bytes written, so the key
 * must not contain it. This is not a nicety: the node's per-object rule
 * compiles into a fresh mktemp staging directory and publishes atomically, so
 * `-o` and `-MF` both carry a random path on every single invocation. Hashing
 * them verbatim gave this cache a 0% hit rate on 1733 objects while looking
 * perfectly healthy.
 *
 * `-MT`/`-MQ` are different and stay in the key: they set the target name
 * written INSIDE the depfile, so two invocations differing only there produce
 * different depfile bytes, and this cache restores depfiles.
 *
 * A prefix map that covers `cwd` gets the same treatment for the same reason:
 * the flag spells out the very build directory the compiler is being told to
 * erase, so hashing it verbatim would reintroduce the path that the recorded
 * comp_dir above just took out, and the two halves have to agree or nothing
 * is shared. Its EFFECT is already in the key as that recorded directory;
 * what stays here is which option it was (-ffile- also moves __FILE__,
 * -fdebug- does not) and what it maps to. `cwd` is NULL — and every argument
 * hashed verbatim — whenever the caller could not model the maps. */
static void hash_argv(struct sha3_256_ctx *h, const struct plan *pl,
                      const char *cwd)
{
    for (int i = 1; i < pl->argc; i++) {
        size_t opt = cwd ? prefix_map_opt(pl->argv[i]) : 0u;
        size_t old_len;
        const char *repl;
        if (i == pl->out_idx || i == pl->dep_idx)
            hstr(h, "<output>");
        else if (i == pl->dep_inline_idx)
            hstr(h, "-MF<output>");
        else if (opt && prefix_map_covers(pl->argv[i] + opt, cwd, &old_len,
                                          &repl)) {
            hstr(h, "zcc:cwd-prefix-map");
            hfield(h, pl->argv[i], opt);
            hstr(h, repl);
        } else
            hstr(h, pl->argv[i]);
    }
}

static bool resolve_cc(const char *cc, char out[PATH_MAX])
{
    if (strchr(cc, '/')) {
        snprintf(out, PATH_MAX, "%s", cc);
        return is_regular(out);
    }
    const char *path = getenv("PATH");
    if (!path)
        path = "/usr/bin:/bin";
    const char *p = path;
    while (*p) {
        const char *sep = strchr(p, ':');
        size_t n = sep ? (size_t)(sep - p) : strlen(p);
        if (n > 0 && n + 1u + strlen(cc) < PATH_MAX) {
            snprintf(out, PATH_MAX, "%.*s/%s", (int)n, p, cc);
            if (access(out, X_OK) == 0)
                return true;
        }
        if (!sep)
            break;
        p = sep + 1;
    }
    return false;
}

static void hash_toolchain(struct sha3_256_ctx *h, const struct plan *pl)
{
    char ccpath[PATH_MAX];
    struct stat st;
    hstr(h, ZCC_MAGIC);
    if (resolve_cc(pl->argv[0], ccpath) && stat(ccpath, &st) == 0) {
        hstr(h, ccpath);
        hu64(h, (uint64_t)st.st_size);
        hu64(h, (uint64_t)st.st_mtim.tv_sec);
        hu64(h, (uint64_t)st.st_mtim.tv_nsec);
    } else {
        hstr(h, pl->argv[0]);
        hstr(h, "<unresolved-compiler>");
    }
    /* The directory the compiler will RECORD, not the one it runs in — see
     * "THE RECORDED WORKING DIRECTORY" above for why the difference is the
     * whole cross-worktree hit rate, and for the fallback rule. */
    char cwd[PATH_MAX], recorded[PATH_MAX];
    const char *real = getcwd(cwd, sizeof cwd) ? cwd : NULL;
    if (real && recorded_cwd(pl, real, recorded)) {
        hstr(h, recorded);
        hash_argv(h, pl, real);
    } else {
        hstr(h, real ? real : "<nocwd>");
        hash_argv(h, pl, NULL);
    }
}

/* Archives named by -l are real inputs; fold in the ones we can resolve. */
static void hash_named_libs(struct sha3_256_ctx *h, const struct plan *pl,
                            bool content)
{
    for (int i = 1; i < pl->argc; i++) {
        const char *a = pl->argv[i];
        if (strncmp(a, "-l", 2) != 0 || !a[2])
            continue;
        for (int d = 0; d < pl->libdir_n; d++) {
            char cand[PATH_MAX];
            snprintf(cand, sizeof cand, "%s/lib%s.a", pl->libdir[d], a + 2);
            struct stat st;
            if (stat(cand, &st) != 0)
                continue;
            hstr(h, cand);
            if (content) {
                struct buf b = { 0 };
                if (read_file(cand, &b))
                    hfield(h, b.p, b.len);
                buf_free(&b);
            } else {
                hu64(h, (uint64_t)st.st_size);
                hu64(h, (uint64_t)st.st_mtim.tv_nsec);
                hu64(h, (uint64_t)st.st_ino);
            }
            break;
        }
    }
}

static bool probe_key(const struct plan *pl, char out[HEXLEN + 1u])
{
    struct sha3_256_ctx h;
    sha3_256_init(&h);
    hstr(&h, "probe");
    hash_toolchain(&h, pl);
    for (int i = 0; i < pl->src_n + pl->blob_n; i++) {
        int idx = i < pl->src_n ? pl->src[i] : pl->blob[i - pl->src_n];
        const char *p = pl->argv[idx];
        struct stat st;
        if (stat(p, &st) != 0)
            return false;
        hstr(&h, p);
        hu64(&h, (uint64_t)st.st_size);
        hu64(&h, (uint64_t)st.st_mtim.tv_sec);
        hu64(&h, (uint64_t)st.st_mtim.tv_nsec);
        hu64(&h, (uint64_t)st.st_ino);
    }
    for (int i = 0; i < pl->rsp_n; i++) {
        struct stat st;
        if (stat(pl->rsp[i], &st) != 0)
            return false;
        hstr(&h, pl->rsp[i]);
        hu64(&h, (uint64_t)st.st_size);
        hu64(&h, (uint64_t)st.st_mtim.tv_sec);
        hu64(&h, (uint64_t)st.st_mtim.tv_nsec);
        hu64(&h, (uint64_t)st.st_ino);
    }
    hash_named_libs(&h, pl, false);
    unsigned char d[SHA3_256_OUTPUT_SIZE];
    sha3_256_finalize(&h, d);
    hex_of(d, out);
    return true;
}

/* ── dependency set ──────────────────────────────────────────────────── */

/* The level-1 fast path is only sound if it can see EVERY file the compile
 * read, not just the ones named on the command line. A first version of this
 * cache keyed level 1 on the argv inputs alone and served a stale object
 * after a header edit — the source's stat triple had not moved, so nothing
 * noticed. The fix is to record the actual include set. It costs nothing to
 * collect: the -E output already carries a `# <line> "<file>"` marker for
 * every file the preprocessor entered. */

struct deps {
    char **path;
    size_t n;
    size_t cap;
};

static void deps_free(struct deps *d)
{
    for (size_t i = 0; i < d->n; i++)
        free(d->path[i]);
    free(d->path);
    d->path = NULL;
    d->n = d->cap = 0;
}

static void deps_add(struct deps *d, const char *p, size_t len)
{
    if (len == 0 || p[0] == '<')          /* <built-in>, <command-line> */
        return;
    for (size_t i = 0; i < d->n; i++)
        if (strncmp(d->path[i], p, len) == 0 && d->path[i][len] == '\0')
            return;
    if (d->n == d->cap) {
        size_t nc = d->cap ? d->cap * 2 : 128;
        char **np = zcl_realloc(d->path, nc * sizeof *np, "zcc dep set");
        if (!np)
            return;
        d->path = np;
        d->cap = nc;
    }
    char *copy = zcl_malloc(len + 1u, "zcc dep path");
    if (!copy)
        return;
    memcpy(copy, p, len);
    copy[len] = '\0';
    d->path[d->n++] = copy;
}

/* Harvest `# 1 "some/header.h"` line markers out of preprocessed text. */
static void deps_scan(struct deps *d, const unsigned char *p, size_t len)
{
    size_t i = 0;
    while (i < len) {
        size_t eol = i;
        while (eol < len && p[eol] != '\n')
            eol++;
        if (eol - i > 4 && p[i] == '#' && p[i + 1] == ' ') {
            size_t q = i + 2;
            while (q < eol && p[q] != '"')
                q++;
            if (q < eol) {
                size_t start = ++q;
                char unesc[PATH_MAX];
                size_t u = 0;
                while (q < eol && p[q] != '"' && u + 1u < sizeof unesc) {
                    if (p[q] == '\\' && q + 1u < eol)
                        q++;
                    unesc[u++] = (char)p[q++];
                }
                if (q < eol && u > 0 && start < eol)
                    deps_add(d, unesc, u);
            }
        }
        i = eol + 1u;
    }
}

/* Preprocess ONE source with the same flags, minus everything that would
 * make the compiler do more than preprocess or write a second artifact. */
static bool preprocess(const struct plan *pl, int src_idx, const char *tmpdir,
                       struct buf *out)
{
    char **pa = zcl_calloc((size_t)pl->argc + 3u, sizeof *pa, "zcc -E argv");
    if (!pa)
        return false;
    int n = 0;
    pa[n++] = pl->argv[0];
    for (int i = 1; i < pl->argc; i++) {
        if (i == pl->out_idx)
            continue;
        const char *a = pl->argv[i];
        if (strcmp(a, "-o") == 0 || strcmp(a, "-c") == 0 ||
            strcmp(a, "-MD") == 0 || strcmp(a, "-MMD") == 0 ||
            strcmp(a, "-MP") == 0)
            continue;
        if (strcmp(a, "-MF") == 0 || strcmp(a, "-MT") == 0 ||
            strcmp(a, "-MQ") == 0) {
            i++;   /* also drop the value, or it becomes a phantom input */
            continue;
        }
        if (strncmp(a, "-MF", 3) == 0 && a[3])
            continue;
        if ((strncmp(a, "-MT", 3) == 0 || strncmp(a, "-MQ", 3) == 0) && a[3])
            continue;
        /* other inputs would only produce "linker input unused" noise */
        bool other_input = false;
        for (int s = 0; s < pl->src_n; s++)
            if (pl->src[s] == i && i != src_idx)
                other_input = true;
        for (int b = 0; b < pl->blob_n; b++)
            if (pl->blob[b] == i)
                other_input = true;
        if (other_input)
            continue;
        if (strncmp(a, "-l", 2) == 0 && a[2])
            continue;
        pa[n++] = pl->argv[i];
    }
    pa[n++] = (char *)"-E";
    pa[n] = NULL;

    char path[PATH_MAX];
    snprintf(path, sizeof path, "%.3000s/pp.%d.%d", tmpdir, (int)getpid(),
             src_idx);
    int rc = run_argv(pa, path, "/dev/null");
    free(pa);
    if (rc != 0) {
        unlink(path);
        return false;
    }
    bool ok = read_file(path, out);
    unlink(path);
    return ok;
}

/* The SECOND half of keying on the recorded directory instead of the real
 * one. cpp announces its working directory to the compiler proper as a
 * `# 1 "<cwd>//"` line marker, the second line of every -E output, and
 * -ffile-prefix-map does NOT rewrite it — the map is applied later, by the
 * compiler, when it emits DW_AT_comp_dir. So the raw build directory rides
 * into the level-2 content key inside the preprocessed text even after the
 * toolchain hash has stopped keying on it, and two checkouts that produce
 * byte-identical objects still miss. Hash the text AROUND that one line: what
 * it announces is the working directory, and the working directory is already
 * in the key above, in the form the artifact actually carries.
 *
 * Only the marker's own line is skipped, and only when a prefix map really
 * covers this directory (`raw` is NULL otherwise, and the whole text is
 * hashed verbatim as before). Every other absolute path in the preprocessed
 * text — a header reached through an absolute -I, say — still keys the
 * compile to this checkout, which is the conservative answer: such a compile
 * simply is not shared. */
static void hash_pp(struct sha3_256_ctx *h, const unsigned char *p, size_t len,
                    const char *raw)
{
    char needle[PATH_MAX + 8u];
    int nw = raw ? snprintf(needle, sizeof needle, "\"%s//\"", raw) : -1;
    if (nw > 0 && (size_t)nw < sizeof needle) {
        size_t nl = (size_t)nw;
        size_t i = 0;
        /* cpp emits it immediately after `# 0 "<source>"`, before any text.
         * Bounding the search there keeps this off the hot path for the
         * multi-megabyte outputs this hashes, and keeps it from matching a
         * line marker deeper in the stream that means something else. */
        for (int line = 0; line < 4 && i < len; line++) {
            size_t eol = i;
            while (eol < len && p[eol] != '\n')
                eol++;
            if (eol - i > nl + 2u && p[i] == '#' && p[i + 1] == ' ' &&
                memcmp(p + eol - nl, needle, nl) == 0) {
                hfield(h, p, i);
                hfield(h, p + eol, len - eol);
                return;
            }
            i = eol + 1u;
        }
    }
    hfield(h, p, len);
}

static bool content_key(const struct plan *pl, const char *tmpdir,
                        struct deps *d,
                        char out[HEXLEN + 1u])
{
    struct sha3_256_ctx h;
    sha3_256_init(&h);
    hstr(&h, "content");
    hash_toolchain(&h, pl);
    char cwd[PATH_MAX], recorded[PATH_MAX];
    const char *real = getcwd(cwd, sizeof cwd) ? cwd : NULL;
    const char *raw = real && recorded_cwd(pl, real, recorded) ? real : NULL;
    for (int i = 0; i < pl->src_n; i++) {
        struct buf pp = { 0 };
        if (!preprocess(pl, pl->src[i], tmpdir, &pp)) {
            buf_free(&pp);
            return false;
        }
        deps_scan(d, pp.p, pp.len);
        hstr(&h, pl->argv[pl->src[i]]);
        hash_pp(&h, pp.p, pp.len, raw);
        buf_free(&pp);
    }
    for (int i = 0; i < pl->blob_n; i++) {
        struct buf b = { 0 };
        if (!read_file(pl->argv[pl->blob[i]], &b)) {
            buf_free(&b);
            return false;
        }
        hstr(&h, pl->argv[pl->blob[i]]);
        hfield(&h, b.p, b.len);
        buf_free(&b);
    }
    for (int i = 0; i < pl->rsp_n; i++) {
        struct buf b = { 0 };
        if (!read_file(pl->rsp[i], &b)) {
            buf_free(&b);
            return false;
        }
        hstr(&h, pl->rsp[i]);
        hfield(&h, b.p, b.len);
        buf_free(&b);
    }
    hash_named_libs(&h, pl, true);
    unsigned char dg[SHA3_256_OUTPUT_SIZE];
    sha3_256_finalize(&h, dg);
    hex_of(dg, out);
    return true;
}

/* ── cache layout ────────────────────────────────────────────────────── */

struct cache {
    char root[PATH_MAX];
    char tmp[PATH_MAX];
};

static bool cache_open(struct cache *c)
{
    const char *dir = getenv("ZCC_DIR");
    if (dir && dir[0]) {
        snprintf(c->root, sizeof c->root, "%s", dir);
    } else {
        const char *xdg = getenv("XDG_CACHE_HOME");
        const char *home = getenv("HOME");
        if (xdg && xdg[0])
            snprintf(c->root, sizeof c->root, "%s/zcc", xdg);
        else if (home && home[0])
            snprintf(c->root, sizeof c->root, "%s/.cache/zcc", home);
        else
            return false;
    }
    snprintf(c->tmp, sizeof c->tmp, "%.3000s/tmp", c->root);
    return mkdir_p(c->tmp);
}

static void entry_path(const struct cache *c, const char *kind,
                       const char *key, const char *ext, char out[PATH_MAX])
{
    /* Precision-bounded so the compiler can prove the join fits PATH_MAX. */
    snprintf(out, PATH_MAX, "%.3000s/%.16s/%.2s/%.64s%.8s", c->root, kind,
             key, key, ext);
}

static bool entry_dir(const struct cache *c, const char *kind,
                      const char *key, char out[PATH_MAX])
{
    snprintf(out, PATH_MAX, "%.3000s/%.16s/%.2s", c->root, kind, key);
    return mkdir_p(out);
}

/* One byte appended per event; the counter IS the file size, so concurrent
 * makes never need a lock and never lose a count. */
static void bump(const struct cache *c, const char *name)
{
    char p[PATH_MAX];
    snprintf(p, sizeof p, "%.3000s/stat.%.16s", c->root, name);
    int fd = open(p, O_WRONLY | O_CREAT | O_APPEND | O_CLOEXEC, 0600);
    if (fd < 0)
        return;
    (void)!write(fd, "x", 1);
    close(fd);
}

static long counter(const struct cache *c, const char *name)
{
    char p[PATH_MAX];
    struct stat st;
    snprintf(p, sizeof p, "%.3000s/stat.%.16s", c->root, name);
    return stat(p, &st) == 0 ? (long)st.st_size : 0L;
}

/* ── serve / store ───────────────────────────────────────────────────── */

static void replay_stderr(const struct cache *c, const char *ckey)
{
    char p[PATH_MAX];
    struct buf b = { 0 };
    entry_path(c, "obj", ckey, ".err", p);
    if (read_file(p, &b) && b.len > 0)
        (void)!write(STDERR_FILENO, b.p, b.len);
    buf_free(&b);
}

static bool serve(const struct cache *c, const char *ckey,
                  const struct plan *pl)
{
    char art[PATH_MAX];
    entry_path(c, "obj", ckey, ".bin", art);
    if (!is_regular(art))
        return false;
    if (pl->dep_path) {
        char dep[PATH_MAX];
        entry_path(c, "obj", ckey, ".dep", dep);
        if (is_regular(dep) && !copy_out(dep, pl->dep_path))
            return false;
    }
    if (!copy_out(art, pl->out_path))
        return false;
    replay_stderr(c, ckey);
    return true;
}

static void store(const struct cache *c, const char *ckey,
                  const struct plan *pl, const char *errfile)
{
    char dir[PATH_MAX], dst[PATH_MAX];
    struct buf b = { 0 };
    struct stat st;
    if (!entry_dir(c, "obj", ckey, dir))
        return;
    if (stat(pl->out_path, &st) != 0 || !read_file(pl->out_path, &b)) {
        buf_free(&b);
        return;
    }
    entry_path(c, "obj", ckey, ".bin", dst);
    bool ok = store_atomic(dir, dst, b.p, b.len, st.st_mode & 07777u);
    buf_free(&b);
    if (!ok)
        return;

    if (pl->dep_path && is_regular(pl->dep_path)) {
        struct buf d = { 0 };
        if (read_file(pl->dep_path, &d)) {
            entry_path(c, "obj", ckey, ".dep", dst);
            (void)store_atomic(dir, dst, d.p, d.len, 0600);
        }
        buf_free(&d);
    }
    struct buf e = { 0 };
    if (errfile && read_file(errfile, &e)) {
        entry_path(c, "obj", ckey, ".err", dst);
        (void)store_atomic(dir, dst, e.p, e.len, 0600);
    }
    buf_free(&e);
}

/* ── level-1 manifest ────────────────────────────────────────────────── */

/* probe key -> { content key, the exact file set that compile read }.
 * Serving from level 1 requires every recorded file to still carry the same
 * (size, mtime, inode). */


static bool manifest_write(const struct cache *c, const char *pkey,
                           const char *ckey, const struct deps *d)
{
    char dir[PATH_MAX], dst[PATH_MAX];
    if (!entry_dir(c, "man", pkey, dir))
        return false;
    struct buf b = { 0 };
    char line[PATH_MAX + 128];
    int n = snprintf(line, sizeof line, "zcc.manifest.v1\n%s\n", ckey);
    if (n < 0 || !buf_add(&b, line, (size_t)n)) {
        buf_free(&b);
        return false;
    }
    for (size_t i = 0; i < d->n; i++) {
        struct stat st;
        if (stat(d->path[i], &st) != 0)
            continue;
        n = snprintf(line, sizeof line, "%lld %lld %lld %llu %s\n",
                     (long long)st.st_size, (long long)st.st_mtim.tv_sec,
                     (long long)st.st_mtim.tv_nsec,
                     (unsigned long long)st.st_ino, d->path[i]);
        if (n > 0)
            (void)buf_add(&b, line, (size_t)n);
    }
    entry_path(c, "man", pkey, "", dst);
    bool ok = store_atomic(dir, dst, b.p, b.len, 0600);
    buf_free(&b);
    return ok;
}

/* Returns true only when the manifest exists AND every file it records is
 * unchanged. Any doubt is a miss — a miss costs time, a wrong hit costs a
 * wrong binary. */
static bool manifest_verify(const struct cache *c, const char *pkey,
                            char ckey[HEXLEN + 1u])
{
    char p[PATH_MAX];
    struct buf b = { 0 };
    entry_path(c, "man", pkey, "", p);
    if (!read_file(p, &b)) {
        buf_free(&b);
        return false;
    }
    bool ok = false;
    char *text = zcl_malloc(b.len + 1u, "zcc manifest text");
    if (!text) {
        buf_free(&b);
        return false;
    }
    memcpy(text, b.p, b.len);
    text[b.len] = '\0';
    buf_free(&b);

    char *save = NULL;
    char *line = strtok_r(text, "\n", &save);
    if (!line || strcmp(line, "zcc.manifest.v1") != 0)
        goto done;
    line = strtok_r(NULL, "\n", &save);
    if (!line || strlen(line) != HEXLEN)
        goto done;
    memcpy(ckey, line, HEXLEN + 1u);

    ok = true;
    while ((line = strtok_r(NULL, "\n", &save)) != NULL) {
        long long size = 0, sec = 0, nsec = 0;
        unsigned long long ino = 0;
        int off = 0;
        if (sscanf(line, "%lld %lld %lld %llu %n", &size, &sec, &nsec, &ino,
                   &off) != 4 || off <= 0 || !line[off]) {
            ok = false;
            break;
        }
        struct stat st;
        if (stat(line + off, &st) != 0 ||
            (long long)st.st_size != size ||
            (long long)st.st_mtim.tv_sec != sec ||
            (long long)st.st_mtim.tv_nsec != nsec ||
            (unsigned long long)st.st_ino != ino) {
            ok = false;
            break;
        }
    }
done:
    free(text);
    return ok;
}

/* ── maintenance ─────────────────────────────────────────────────────── */

static void rm_tree(const char *path)
{
    DIR *d = opendir(path);
    if (!d) {
        unlink(path);
        return;
    }
    struct dirent *e;
    while ((e = readdir(d))) {
        if (strcmp(e->d_name, ".") == 0 || strcmp(e->d_name, "..") == 0)
            continue;
        char sub[PATH_MAX];
        if (snprintf(sub, sizeof sub, "%s/%s", path, e->d_name) >=
            (int)sizeof sub)
            continue;
        struct stat st;
        if (lstat(sub, &st) == 0 && S_ISDIR(st.st_mode))
            rm_tree(sub);
        else
            unlink(sub);
    }
    closedir(d);
    rmdir(path);
}

static long long tree_bytes(const char *path)
{
    DIR *d = opendir(path);
    if (!d)
        return 0;
    long long total = 0;
    struct dirent *e;
    while ((e = readdir(d))) {
        if (strcmp(e->d_name, ".") == 0 || strcmp(e->d_name, "..") == 0)
            continue;
        char sub[PATH_MAX];
        if (snprintf(sub, sizeof sub, "%s/%s", path, e->d_name) >=
            (int)sizeof sub)
            continue;
        struct stat st;
        if (lstat(sub, &st) != 0)
            continue;
        if (S_ISDIR(st.st_mode))
            total += tree_bytes(sub);
        else
            total += (long long)st.st_size;
    }
    closedir(d);
    return total;
}

/* Oldest-first eviction until the tree fits. Deliberately simple: the cache
 * is a speed aid, and a wrong eviction only costs a rebuild. */
struct victim {
    char path[PATH_MAX];
    long long size;
    time_t atime;
};

static void collect(const char *path, struct victim **v, size_t *n, size_t *cap)
{
    DIR *d = opendir(path);
    if (!d)
        return;
    struct dirent *e;
    while ((e = readdir(d))) {
        if (strcmp(e->d_name, ".") == 0 || strcmp(e->d_name, "..") == 0)
            continue;
        char sub[PATH_MAX];
        if (snprintf(sub, sizeof sub, "%s/%s", path, e->d_name) >=
            (int)sizeof sub)
            continue;
        struct stat st;
        if (lstat(sub, &st) != 0)
            continue;
        if (S_ISDIR(st.st_mode)) {
            collect(sub, v, n, cap);
            continue;
        }
        if (*n == *cap) {
            size_t nc = *cap ? *cap * 2 : 256;
            struct victim *nv = zcl_realloc(*v, nc * sizeof **v, "zcc trim list");
            if (!nv) {
                closedir(d);
                return;
            }
            *v = nv;
            *cap = nc;
        }
        snprintf((*v)[*n].path, PATH_MAX, "%s", sub);
        (*v)[*n].size = (long long)st.st_size;
        (*v)[*n].atime = st.st_mtime;
        (*n)++;
    }
    closedir(d);
}

static int by_age(const void *a, const void *b)
{
    const struct victim *x = a, *y = b;
    if (x->atime < y->atime)
        return -1;
    if (x->atime > y->atime)
        return 1;
    return 0;
}

static int cmd_trim(struct cache *c, long long max_mb)
{
    long long limit = max_mb * 1024LL * 1024LL;
    long long have = tree_bytes(c->root);
    if (have <= limit) {
        printf("zcc: %lld MB cached, limit %lld MB — nothing to trim\n",
               have / (1024 * 1024), max_mb);
        return 0;
    }
    struct victim *v = NULL;
    size_t n = 0, cap = 0;
    collect(c->root, &v, &n, &cap);
    qsort(v, n, sizeof *v, by_age);
    long long freed = 0;
    for (size_t i = 0; i < n && have - freed > limit; i++) {
        if (unlink(v[i].path) == 0)
            freed += v[i].size;
    }
    free(v);
    printf("zcc: trimmed %lld MB to fit %lld MB\n", freed / (1024 * 1024),
           max_mb);
    return 0;
}

static int cmd_stats(struct cache *c)
{
    long hit = counter(c, "hit"), miss = counter(c, "miss");
    long bypass = counter(c, "bypass"), total = hit + miss;
    long unkeyable = counter(c, "unkeyable");
    printf("zcc cache      %s\n", c->root);
    printf("  size         %lld MB\n", tree_bytes(c->root) / (1024 * 1024));
    printf("  hits         %ld\n", hit);
    printf("  misses       %ld\n", miss);
    printf("  bypassed     %ld\n", bypass);
    /* Never hide this behind a zero: an unkeyable compile is a compile this
     * cache silently failed to speed up, and it is worth naming. */
    printf("  unkeyable    %ld%s\n", unkeyable,
           unkeyable > 0 ? "  (ZCC_LOG=<path> names them)" : "");
    if (total > 0)
        printf("  hit rate     %.1f%%\n", 100.0 * (double)hit / (double)total);
    return 0;
}

/* ZCC_LOG=<path>: one line per invocation, appended with a single write() so
 * concurrent makes interleave whole lines. This is how you find out WHY a
 * build is not being cached — a bypass that nobody can see is a silent
 * performance bug, and this cache exists because of one. */
static void logline(const char *disposition, const char *detail,
                    const struct plan *pl)
{
    const char *path = getenv("ZCC_LOG");
    if (!path || !path[0])
        return;
    int fd = open(path, O_WRONLY | O_CREAT | O_APPEND | O_CLOEXEC, 0600);
    if (fd < 0)
        return;
    char line[1024];
    int n = snprintf(line, sizeof line, "%-8s %-28s %s\n", disposition,
                     detail ? detail : "-",
                     pl->out_path ? pl->out_path : "<none>");
    if (n > 0)
        (void)!write(fd, line, (size_t)n > sizeof line ? sizeof line : (size_t)n);
    close(fd);
}

/* ── main ────────────────────────────────────────────────────────────── */

static int exec_direct(char **argv)
{
    execvp(argv[0], argv);
    fprintf(stderr, "zcc: cannot execute %s: %s\n", argv[0], strerror(errno));
    return 127;
}

int main(int argc, char **argv)
{
    if (argc < 2) {
        fprintf(stderr,
                "usage: zcc <compiler> [args...]\n"
                "       zcc --zcc-stats | --zcc-clear | --zcc-trim <MB>\n");
        return 2;
    }

    struct cache c;
    if (strncmp(argv[1], "--zcc-", 6) == 0) {
        if (!cache_open(&c)) {
            fprintf(stderr, "zcc: no usable cache directory\n");
            return 1;
        }
        if (strcmp(argv[1], "--zcc-stats") == 0)
            return cmd_stats(&c);
        if (strcmp(argv[1], "--zcc-clear") == 0) {
            rm_tree(c.root);
            printf("zcc: cleared %s\n", c.root);
            return 0;
        }
        if (strcmp(argv[1], "--zcc-trim") == 0 && argc > 2)
            return cmd_trim(&c, strtoll(argv[2], NULL, 10));
        fprintf(stderr, "zcc: unknown option %s\n", argv[1]);
        return 2;
    }

    char **cc_argv = argv + 1;
    int cc_argc = argc - 1;

    struct plan pl = { 0 };
    plan_build(&pl, cc_argc, cc_argv);
    bool disabled = getenv("ZCC_DISABLE") != NULL;

    if (disabled || pl.bypass || !cache_open(&c)) {
        if (!disabled && pl.bypass && cache_open(&c)) {
            bump(&c, "bypass");
            logline("BYPASS", pl.bypass, &pl);
        }
        return exec_direct(cc_argv);
    }

    const bool strict = getenv("ZCC_STRICT") != NULL;
    const bool audit = getenv("ZCC_AUDIT") != NULL;

    /* Level 1 (probe): the argv inputs still carry the stat triples they had
     * last time AND every file that compile actually included still does.
     * Level 2 (content): preprocess and hash what the compiler would really
     * see. Level 1 is a shortcut past level 2, never past correctness — it
     * only ever serves a content key that level 2 previously computed. */
    char pkey[HEXLEN + 1u], ckey[HEXLEN + 1u];
    struct deps deps = { 0 };
    bool have_deps = false;
    bool have_pkey = !strict && probe_key(&pl, pkey);
    bool have_ckey = false;

    if (have_pkey && manifest_verify(&c, pkey, ckey))
        have_ckey = true;

    if (have_ckey && !audit && serve(&c, ckey, &pl)) {
        bump(&c, "hit");
        logline("HIT", "level 1 (probe manifest)", &pl);
        return 0;
    }

    if (!have_ckey || audit) {
        if (!content_key(&pl, c.tmp, &deps, ckey)) {
            /* The -E probe did not work here. Run the real compiler, but say
             * so: an invocation that silently declines to be cached is a
             * performance bug nobody can see. A -MT value left unconsumed
             * once made EVERY node object take this path. */
            deps_free(&deps);
            bump(&c, "unkeyable");
            logline("UNKEY", "the -E probe failed", &pl);
            return exec_direct(cc_argv);
        }
        have_deps = true;
        if (!audit && serve(&c, ckey, &pl)) {
            if (have_pkey && have_deps)
                (void)manifest_write(&c, pkey, ckey, &deps);
            deps_free(&deps);
            bump(&c, "hit");
            logline("HIT", "level 2 (content)", &pl);
            return 0;
        }
    }

    /* Miss (or audit): run the real compiler, capturing stderr so a later
     * hit can reproduce the warnings the developer would have seen. */
    char errfile[PATH_MAX];
    snprintf(errfile, sizeof errfile, "%.3000s/err.%d", c.tmp,
             (int)getpid());

    struct buf cached_before = { 0 };
    bool had_cached = false;
    if (audit) {
        char art[PATH_MAX];
        entry_path(&c, "obj", ckey, ".bin", art);
        had_cached = read_file(art, &cached_before);
    }

    int rc = run_argv(cc_argv, NULL, errfile);

    struct buf errbytes = { 0 };
    if (read_file(errfile, &errbytes) && errbytes.len > 0)
        (void)!write(STDERR_FILENO, errbytes.p, errbytes.len);
    buf_free(&errbytes);

    if (rc == 0) {
        if (audit && had_cached) {
            struct buf fresh = { 0 };
            if (read_file(pl.out_path, &fresh)) {
                bool same = fresh.len == cached_before.len &&
                            memcmp(fresh.p, cached_before.p, fresh.len) == 0;
                fprintf(stderr, "zcc: AUDIT %s %s (%s)\n",
                        same ? "MATCH" : "DIVERGENCE", ckey, pl.out_path);
                if (!same)
                    fprintf(stderr,
                            "zcc: AUDIT the cached artifact did NOT match a "
                            "fresh build — the fresh one was kept; report "
                            "this and run --zcc-clear\n");
            }
            buf_free(&fresh);
        }
        store(&c, ckey, &pl, errfile);
        if (have_pkey && have_deps)
            (void)manifest_write(&c, pkey, ckey, &deps);
        bump(&c, "miss");
        logline("MISS", "compiled and stored", &pl);
    }
    buf_free(&cached_before);
    deps_free(&deps);
    unlink(errfile);
    return rc;
}
