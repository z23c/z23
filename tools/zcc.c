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
 *     zcc --epoch-object dep OUTPUT SOURCE SOURCE_ID COMPLETE MUTATION \
 *         EPOCH COMPILER_ID SESSION -- cc [args...]
 *     zcc --zcc-stats | --zcc-clear | --zcc-trim [MB]
 *
 * THE KEY. Two levels, both SHA3-256.
 *
 *   Level 1 (probe key + manifest) — compiler bytes, cwd, normalized argv,
 *   and byte digests of every command-line input. No preprocessing is needed
 *   on a hit. This is the level that
 *   makes "the Makefile timestamp moved but no source changed" free, which is
 *   the measured case above. It maps to a MANIFEST, not to an artifact: the
 *   manifest records the level-2 key plus a byte digest of every file that
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
 * ZCC_STRICT=1 skips level 1, and ZCC_AUDIT=1 checks it empirically: every
 * hit is recompiled
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
 * make's header tracking, which is worse than a slow build. An entry that
 * cannot hand back a depfile the compile asked for is therefore not a hit at
 * all — see serve().
 *
 * `-MT`/`-MQ` name the make target written INSIDE that depfile. The node's
 * per-object publisher passes the final object path, which contains the
 * compile-epoch hash (`build/<profile>-obj/epochs/<64 hex>/...`). Hashing
 * that path verbatim made a new epoch a 100% miss of otherwise identical
 * objects — measured on this host: `make -j8 t-fast ONLY=hex_codec` cold
 * compiled 3239 objects at a 0.0% zcc hit rate after a fresh epoch, while
 * the same non-LTO flags with -ffile-prefix-map should have been shared.
 * The key now treats the -MT value like `-o` (a placeholder). The stored
 * depfile rewrites the target to a placeholder and serve() rewrites it
 * back to the CURRENT -MT, so make still sees the right object path.
 *
 * THE BOUND. This cache enforces its own size ceiling; nothing outside it has
 * to remember to. Left unbounded it reached 196 GB on the maintainer host and
 * 60 GB on the second one, because `make cc-cache-trim` was the only thing
 * that ever deleted anything and no build runs it. ZCC_MAX_MB sets the
 * ceiling (default ZCC_DEFAULT_MAX_MB below, justified there from measured
 * footprints); ZCC_MAX_MB=0 turns the bound off. See "THE BOUND" in the body
 * for what triggers a trim, why it is not a directory walk per compile, and
 * why an eviction interrupted at any point cannot produce a torn hit.
 *
 * A link step naming a system library (-lm, -lpthread) that this cache cannot
 * resolve under a -L directory bypasses reuse. The hermetic goals
 * (ci-reproducible, repro-verify) already force
 * ZCL_USE_CCACHE=0, so no reproducibility claim is ever served from here.
 */

#define _POSIX_C_SOURCE 200809L

#include "base/hex.h"
#include "base/safe_alloc.h"
#include "base/serialize_le.h"
#include "platform/fd_path.h"
#include "sha3/sha3.h"

#include <ctype.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <spawn.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

extern char **environ;

/* v2 retires entries produced while cache controls were visible to compiler
 * children but absent from the key. The child environment is now filtered. */
#define ZCC_MAGIC "zcc.cache.v2"
#define HEXLEN (SHA3_256_OUTPUT_SIZE * 2u)
/* Stored in cached depfiles in place of the -MT path so two epochs of the
 * same flags share one entry. Must not appear in a real object path. */
#define ZCC_MT_PLACEHOLDER "__ZCC_DEP_TARGET__"

/* ── tiny growable buffer ────────────────────────────────────────────── */

struct buf {
    unsigned char *p;
    size_t len;
    size_t cap;
};

/* zcc is bootstrapped before the node platform library exists and links only
 * its hashing and allocation primitives. Keep its filesystem-age clock read
 * in one named boundary so cache eviction cannot acquire a hidden platform
 * link dependency. */
static time_t zcc_wall_time(void)
{
    return time(NULL); // platform-ok: standalone bootstrap filesystem clock
}

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

static bool file_hex(const char *path, char out[HEXLEN + 1u])
{
    int fd = open(path, O_RDONLY | O_CLOEXEC);
    if (fd < 0)
        return false;
    struct sha3_256_ctx h;
    sha3_256_init(&h);
    unsigned char block[16384];
    ssize_t n;
    while ((n = read(fd, block, sizeof block)) > 0)
        sha3_256_write(&h, block, (size_t)n);
    int closed = close(fd);
    bool ok = n == 0 && closed == 0;
    if (!ok)
        return false;
    unsigned char digest[SHA3_256_OUTPUT_SIZE];
    sha3_256_finalize(&h, digest);
    hex_of(digest, out);
    return true;
}

/* ── file helpers ────────────────────────────────────────────────────── */

static bool read_file(const char *path, struct buf *out)
{
    int fd = open(path, O_RDONLY | O_CLOEXEC);
    if (fd < 0)
        return false;
#if defined(__APPLE__)
    /* Opening /dev/fd/N duplicates the existing open-file description on
     * Darwin, including its current offset. Epoch compiler outputs therefore
     * need an explicit rewind before cache capture. */
    if (strncmp(path, "/dev/fd/", 8u) == 0 && lseek(fd, 0, SEEK_SET) < 0) {
        close(fd);
        return false;
    }
#endif
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

static bool buf_replace_prefix(struct buf *b, const char *from, const char *to)
{
    size_t flen, tlen;

    if (!b || !from || !to || !from[0])
        return false;
    flen = strlen(from);
    tlen = strlen(to);
    if (b->len < flen || memcmp(b->p, from, flen) != 0)
        return false;
    if (tlen > flen) {
        size_t extra = tlen - flen;
        if (!buf_reserve(b, extra))
            return false;
        memmove(b->p + tlen, b->p + flen, b->len - flen);
        b->len += extra;
    } else if (tlen < flen) {
        memmove(b->p + tlen, b->p + flen, b->len - flen);
        b->len -= flen - tlen;
    }
    memcpy(b->p, to, tlen);
    return true;
}

static bool write_buf_dest(struct buf *b, const char *dest, mode_t mode)
{
#if defined(__APPLE__)
    if (strncmp(dest, "/dev/fd/", 8u) == 0) {
        int fd = open(dest, O_WRONLY | O_TRUNC);
        bool ok = fd >= 0 && lseek(fd, 0, SEEK_SET) >= 0 &&
                  write_all(fd, b->p, b->len) &&
                  fchmod(fd, mode) == 0;
        if (fd >= 0 && close(fd) != 0)
            ok = false;
        return ok;
    }
#endif
    char dir[PATH_MAX];
    snprintf(dir, sizeof dir, "%s", dest);
    char *slash = strrchr(dir, '/');
    if (slash)
        *slash = '\0';
    else
        snprintf(dir, sizeof dir, ".");
    return store_atomic(dir, dest, b->p, b->len, mode);
}

/* Restore a depfile, rewriting a placeholder target to the current -MT path
 * so two compile epochs share one cache entry. An entry stored before this
 * rewrite (no placeholder) is copied through unchanged: those keys still
 * included the -MT path, so they cannot match a different epoch. */
/* ── process launch (no shell, ever) ─────────────────────────────────── */

/* Make's epoch and scheduling controls change between otherwise identical
 * compiles. Keep them out of the compiler CHILD as well as the cache key:
 * a child cannot read a value that the key intentionally ignores. All other
 * environment entries, including search paths and toolchain selectors,
 * remain byte-bound by hash_environment(). */
static bool orchestration_env(const char *entry)
{
    static const char *const names[] = {
        "BUILD_SOURCE_RECORD=", "BUILD_COMPILER_ID=", "BUILD_SYSTEM_ID=",
        "BUILD_EPOCH_KEEP=", "MAKEFLAGS=", "MFLAGS=", "MAKELEVEL=",
        "ZCL_CHECKOUT_LOCK_HELD=", "ZCL_HOST_JOBS=",
        /* Per-session and per-job bookkeeping. Each of these differs between
         * two otherwise identical compiles (measured: 17,780 compiles in an
         * hour, 21 hits, because every agent session carried its own ids), and
         * no compiler driver reads any of them. */
        "ONLY=", "MAKEOVERRIDES=", "DEVBUILD_ACTIVE=", "INVOCATION_ID=",
        "JOURNAL_STREAM=", "SHLVL=", "OLDPWD=", "_=",
        "SSH_CONNECTION=", "SSH_CLIENT=", "SSH_TTY=", "XDG_SESSION_ID=",
        "CLAUDE_", "CLAUDECODE=", "AI_AGENT="
    };
    for (size_t i = 0; i < sizeof(names) / sizeof(names[0]); i++)
        if (strncmp(entry, names[i], strlen(names[i])) == 0)
            return true;
    return false;
}

static bool child_env_excluded(const char *entry)
{
    if (orchestration_env(entry)) return true;
    static const char *const controls[] = {
        "ZCC_DIR=", "ZCC_LOG=", "ZCC_MAX_MB=", "ZCC_STRICT=",
        "ZCC_AUDIT=", "ZCC_DISABLE="
    };
    for (size_t i = 0; i < sizeof(controls) / sizeof(controls[0]); i++)
        if (strncmp(entry, controls[i], strlen(controls[i])) == 0)
            return true;
    return false;
}

static char **compiler_child_env(void)
{
    size_t count = 0;
    for (char **ep = environ; ep && *ep; ep++)
        if (!child_env_excluded(*ep)) count++;
    char **child_env = zcl_malloc((count + 1u) * sizeof(*child_env),
                                  "zcc child environment");
    if (!child_env) return NULL;
    size_t used = 0;
    for (char **ep = environ; ep && *ep; ep++)
        if (!child_env_excluded(*ep)) child_env[used++] = *ep;
    child_env[used] = NULL;
    return child_env;
}

static int run_argv(char *const argv[], const char *stdout_path,
                    const char *stderr_path)
{
    char **child_env = compiler_child_env();
    if (!child_env) return -1;
    posix_spawn_file_actions_t actions;
    if (posix_spawn_file_actions_init(&actions) != 0) {
        free(child_env);
        return -1;
    }
    int prep = 0;
    if (stdout_path)
        prep = posix_spawn_file_actions_addopen(&actions, STDOUT_FILENO,
                 stdout_path, O_WRONLY | O_CREAT | O_TRUNC, 0600);
    if (prep == 0 && stderr_path)
        prep = posix_spawn_file_actions_addopen(&actions, STDERR_FILENO,
                 stderr_path, O_WRONLY | O_CREAT | O_TRUNC, 0600);
    pid_t pid = -1;
    int launched = prep == 0 ? posix_spawnp(&pid, argv[0], &actions, NULL,
                                            argv, child_env) : prep;
    (void)posix_spawn_file_actions_destroy(&actions);
    free(child_env);
    if (launched != 0)
        return -1;
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
    /* -MD/-MMD was asked for, so the compiler WILL write dep_path and a
     * complete cache entry owes one back. dep_path alone is not the same
     * question: a bare -MF names a file the compiler then never writes. */
    bool want_dep;
    int dep_idx;          /* index of the -MF VALUE, or -1 */
    int dep_inline_idx;   /* index of a joined -MFvalue, or -1 */
    int mt_idx;           /* index of the -MT/-MQ VALUE, or -1 */
    int mt_inline_idx;    /* index of a joined -MTvalue/-MQvalue, or -1 */
    const char *mt_path;
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

/* Only these positional inputs are inert linker data. An unrecognized file
 * may be a compiler source selected by its suffix; hashing its raw bytes
 * without preprocessing would miss headers. */
static bool is_link_input(const char *p)
{
    return has_suffix(p, ".o") || has_suffix(p, ".a") ||
           has_suffix(p, ".so") || has_suffix(p, ".dylib") ||
           has_suffix(p, ".obj") || has_suffix(p, ".lib");
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

static bool plan_push_rsp_link(struct plan *pl, const unsigned char *bytes,
                               size_t len)
{
    char token[PATH_MAX];
    if (len == 0 || len >= sizeof token || memchr(bytes, '\0', len)) {
        pl->bypass = "response file input type not modeled";
        return false;
    }
    memcpy(token, bytes, len);
    token[len] = '\0';
    if (!is_link_input(token)) {
        pl->bypass = "response file input type not modeled";
        return false;
    }
    return plan_push_rsp(pl, (const char *)bytes, len);
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
        if (!plan_push_rsp_link(pl, b.p + start, i - start)) {
            buf_free(&b);
            return false;
        }
    }
    buf_free(&b);
    return true;
}

static bool plan_parse_input(struct plan *pl, const char *a, int i)
{
    if (a[0] == '@' && a[1])
        return plan_absorb_response_file(pl, a + 1);
    if (strcmp(a, "-x") == 0 ||
        (strncmp(a, "-x", 2) == 0 && a[2]) ||
        strcmp(a, "-include") == 0 || strcmp(a, "-imacros") == 0) {
        pl->bypass = "explicit language or hidden include not modeled";
        return false;
    }
    if (a[0] == '-')
        return true;
    if (has_suffix(a, ".c")) {
        pl->src[pl->src_n++] = i;
        return true;
    }
    if (is_regular(a)) {
        if (!is_link_input(a)) {
            pl->bypass = "input file type not modeled";
            return false;
        }
        pl->blob[pl->blob_n++] = i;
    }
    return true;
}

static void plan_build(struct plan *pl, int argc, char **argv)
{
    pl->argv = argv;
    pl->argc = argc;
    pl->out_idx = -1;
    pl->dep_idx = -1;
    pl->dep_inline_idx = -1;
    pl->mt_idx = -1;
    pl->mt_inline_idx = -1;
    pl->mt_path = NULL;
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
             * bypassed EVERY node object in this repository. The value is
             * recorded so the key can placeholder it and serve() can rewrite
             * the restored depfile onto the current target. */
            pl->mt_idx = ++i;
            pl->mt_path = argv[i];
        } else if ((strncmp(a, "-MT", 3) == 0 || strncmp(a, "-MQ", 3) == 0) &&
                   a[3]) {
            pl->mt_inline_idx = i;
            pl->mt_path = a + 3;
        } else if (strcmp(a, "-L") == 0 && i + 1 < argc) {
            pl->libdir[pl->libdir_n++] = argv[++i];
        } else if (strncmp(a, "-L", 2) == 0 && a[2]) {
            pl->libdir[pl->libdir_n++] = argv[i] + 2;
        } else if (!plan_parse_input(pl, a, i))
            return;
    }

    if (!pl->out_path || strcmp(pl->out_path, "-") == 0) {
        pl->bypass = "no single -o artifact";
        return;
    }
    if (pl->src_n == 0 && pl->blob_n == 0 && pl->rsp_n == 0) {
        pl->bypass = "no file inputs to key on";
        return;
    }

    pl->want_dep = want_dep;
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

static void plan_free(struct plan *pl)
{
    for (int i = 0; i < pl->rsp_n; i++)
        free(pl->rsp[i]);
    free(pl->rsp);
    free(pl->libdir);
    free(pl->blob);
    free(pl->src);
    memset(pl, 0, sizeof *pl);
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
 * `-MT`/`-MQ` used to stay in the key because they appear inside the
 * depfile. That was correct for the depfile bytes and wrong for the object
 * bytes: the epoch publisher's -MT value is the epoch-qualified object path,
 * so a new compile epoch — including a Makefile comment that only changes
 * BUILD_SYSTEM_ID — missed every TU. The key now placeholders the value the
 * same way it placeholders `-o`. store()/serve() rewrite the depfile target
 * so make still receives the current path.
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
        if (i == pl->out_idx || i == pl->dep_idx || i == pl->mt_idx)
            hstr(h, "<output>");
        else if (i == pl->dep_inline_idx)
            hstr(h, "-MF<output>");
        else if (i == pl->mt_inline_idx)
            hstr(h, pl->argv[i][2] == 'Q' ? "-MQ<output>" : "-MT<output>");
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

static int env_entry_compare(const void *a, const void *b)
{
    const char *const *ea = a, *const *eb = b;
    return strcmp(*ea, *eb);
}

static bool env_same_name(const char *a, const char *b)
{
    const char *end = strchr(a, '=');
    return end && strncmp(a, b, (size_t)(end - a) + 1u) == 0;
}

static bool hash_environment(struct sha3_256_ctx *h)
{
    size_t n = 0;
    for (char **ep = environ; ep && *ep; ep++)
        n++;
    const char **items = zcl_malloc((n ? n : 1u) * sizeof *items,
                                    "zcc environment key");
    if (!items)
        return false;
    for (size_t i = 0; i < n; i++)
        items[i] = environ[i];
    qsort(items, n, sizeof *items, env_entry_compare);
    bool ok = true;
    for (size_t i = 0; i < n; i++) {
        const char *e = items[i];
        if (i > 0 && env_same_name(items[i - 1u], e)) {
            ok = false;
            break;
        }
        if (child_env_excluded(e))
            continue;
        hstr(h, e);
    }
    free(items);
    return ok;
}

#if defined(__APPLE__)
/* Apple Clang normally assembles inside the driver. With external assembly,
 * the executable chosen through -B or COMPILER_PATH is another code producer.
 * Ask the same driver to resolve it, and refuse cache admission if that fact
 * is unavailable. Version output does not identify an in-place replacement. */
static bool apple_assembler_external(const struct plan *pl)
{
    bool external = false;
    bool has_search_override = false;
    for (int i = 1; i < pl->argc; i++) {
        const char *arg = pl->argv[i];
        if (strcmp(arg, "-fno-integrated-as") == 0 ||
            strcmp(arg, "-no-integrated-as") == 0)
            external = true;
        else if (strcmp(arg, "-fintegrated-as") == 0 ||
                 strcmp(arg, "-integrated-as") == 0)
            external = false;
        if (strcmp(arg, "-B") == 0 ||
            (strncmp(arg, "-B", 2) == 0 && arg[2]))
            has_search_override = true;
    }
    return external || has_search_override;
}
#endif

#if defined(__APPLE__) || defined(__linux__)
static char **apple_tool_query_argv(const struct plan *pl,
                                    const char *query_flag)
{
    char **query = zcl_calloc((size_t)pl->argc + 2u, sizeof(*query),
                              "zcc Apple tool query argv");
    if (!query) return NULL;
    int n = 0;
    query[n++] = pl->argv[0];
    for (int i = 1; i < pl->argc; i++) {
        const char *arg = pl->argv[i];
        bool value = strcmp(arg, "-B") == 0 ||
                     strcmp(arg, "-target") == 0 ||
                     strcmp(arg, "--target") == 0 ||
                     strcmp(arg, "-arch") == 0;
        if (value) {
            if (i + 1 >= pl->argc) { free(query); return NULL; }
            query[n++] = arg;
            query[n++] = pl->argv[++i];
        } else if ((strncmp(arg, "-B", 2) == 0 && arg[2]) ||
                   strncmp(arg, "-target=", 8) == 0 ||
                   strncmp(arg, "--target=", 9) == 0) {
            query[n++] = arg;
        }
    }
    query[n++] = (char *)query_flag;
    query[n] = NULL;
    return query;
}

static bool apple_tool_read_output(const char *scratch,
                                   char output[PATH_MAX])
{
    size_t output_len = 0;
    int fd = open(scratch, O_RDONLY | O_CLOEXEC);
    struct stat output_stat;
    bool ok = fd >= 0 && fstat(fd, &output_stat) == 0 &&
              S_ISREG(output_stat.st_mode) && output_stat.st_size >= 2 &&
              output_stat.st_size < PATH_MAX;
    if (ok) {
        while (output_len < (size_t)output_stat.st_size) {
            ssize_t got = read(fd, output + output_len,
                               (size_t)output_stat.st_size - output_len);
            if (got < 0 && errno == EINTR) continue;
            if (got <= 0) { ok = false; break; }
            output_len += (size_t)got;
        }
    }
    if (fd >= 0 && close(fd) != 0) ok = false;
    if (!ok || output[output_len - 1u] != '\n') return false;
    output[--output_len] = '\0';
    return !strchr(output, '\n') && !strchr(output, '\r');
}

static bool apple_tool_query_output(char *const query[],
                                    char output[PATH_MAX])
{
    char scratch[PATH_MAX];
    const char *temp = getenv("TMPDIR");
    if (!temp || !*temp) temp = "/tmp";
    int written = snprintf(scratch, sizeof scratch, "%s/zcc-tool.XXXXXX", temp);
    if (written < 0 || (size_t)written >= sizeof scratch) return false;
    int fd = mkstemp(scratch);
    if (fd < 0) return false;
    bool ok = close(fd) == 0 && run_argv(query, scratch, NULL) == 0;
    if (ok) ok = apple_tool_read_output(scratch, output);
    (void)unlink(scratch);
    return ok;
}

/* The selected Clang is large (257 MiB in the CLT used for this probe).
 * Rehashing it for every object would turn a cold build into hours. Keep the
 * verified byte digest in zcc's existing private cache, keyed by path and by
 * the file identity/change stamp. ctime catches an in-place same-size edit
 * even when mtime is restored. A changed or unreadable stamp falls back to
 * hashing; it never admits an old digest. */
struct apple_tool_stamp {
    uint64_t dev, ino, size, mtime_sec, mtime_nsec, ctime_sec, ctime_nsec;
};

struct apple_tool_digest_record {
    char magic[8];
    uint8_t path_root[SHA3_256_OUTPUT_SIZE];
    struct apple_tool_stamp stamp;
    char digest[HEXLEN + 1u];
};

#if defined(__APPLE__)
struct apple_tool_selection_record {
    char magic[8];
    uint8_t selector_root[SHA3_256_OUTPUT_SIZE];
    struct apple_tool_stamp tool_stamp;
    struct apple_tool_stamp parent_stamp;
    char selected[PATH_MAX];
};
#endif

static struct apple_tool_stamp apple_tool_stamp_of(const struct stat *st)
{
    return (struct apple_tool_stamp) {
        .dev = (uint64_t)st->st_dev, .ino = (uint64_t)st->st_ino,
        .size = (uint64_t)st->st_size,
#if defined(__APPLE__)
        .mtime_sec = (uint64_t)st->st_mtimespec.tv_sec,
        .mtime_nsec = (uint64_t)st->st_mtimespec.tv_nsec,
        .ctime_sec = (uint64_t)st->st_ctimespec.tv_sec,
        .ctime_nsec = (uint64_t)st->st_ctimespec.tv_nsec,
#else
        .mtime_sec = (uint64_t)st->st_mtim.tv_sec,
        .mtime_nsec = (uint64_t)st->st_mtim.tv_nsec,
        .ctime_sec = (uint64_t)st->st_ctim.tv_sec,
        .ctime_nsec = (uint64_t)st->st_ctim.tv_nsec,
#endif
    };
}

static bool apple_tool_stamp_equal(const struct stat *a,
                                   const struct stat *b)
{
    struct apple_tool_stamp x = apple_tool_stamp_of(a);
    struct apple_tool_stamp y = apple_tool_stamp_of(b);
    return memcmp(&x, &y, sizeof x) == 0;
}

#if defined(__APPLE__)
static bool apple_tool_parent_stat(const char *path, struct stat *out)
{
    char parent[PATH_MAX];
    size_t len = strlen(path);
    if (len >= sizeof parent) return false;
    memcpy(parent, path, len + 1u);
    char *slash = strrchr(parent, '/');
    if (!slash) return stat(".", out) == 0 && S_ISDIR(out->st_mode);
    if (slash == parent) slash[1] = '\0';
    else *slash = '\0';
    return stat(parent, out) == 0 && S_ISDIR(out->st_mode);
}

static void apple_hash_stamp(struct sha3_256_ctx *h, const struct stat *st)
{
    struct apple_tool_stamp s = apple_tool_stamp_of(st);
    hu64(h, s.dev); hu64(h, s.ino); hu64(h, s.size);
    hu64(h, s.mtime_sec); hu64(h, s.mtime_nsec);
    hu64(h, s.ctime_sec); hu64(h, s.ctime_nsec);
}

static bool apple_hash_search_dir(struct sha3_256_ctx *h, const char *dir)
{
    struct stat st;
    hstr(h, dir);
    if (stat(dir, &st) != 0) {
        if (errno != ENOENT) return false;
        hstr(h, "absent");
        char ancestor[PATH_MAX];
        memcpy(ancestor, dir, strlen(dir) + 1u);
        for (;;) {
            char *slash = strrchr(ancestor, '/');
            if (!slash) memcpy(ancestor, ".", 2u);
            else if (slash == ancestor) slash[1] = '\0';
            else *slash = '\0';
            if (stat(ancestor, &st) == 0) break;
            if (errno != ENOENT || strcmp(ancestor, ".") == 0 ||
                strcmp(ancestor, "/") == 0) return false;
        }
    }
    if (!S_ISDIR(st.st_mode)) return false;
    apple_hash_stamp(h, &st);
    return true;
}

static bool apple_hash_search_candidate(struct sha3_256_ctx *h,
                                        const char *dir, const char *name)
{
    char path[PATH_MAX];
    struct stat st;
    int n = snprintf(path, sizeof path, "%s/%s", dir, name);
    if (n <= 0 || (size_t)n >= sizeof path) return false;
    if (stat(path, &st) != 0) {
        if (errno != ENOENT) return false;
        hstr(h, "candidate-absent");
        return true;
    }
    hstr(h, "candidate-present");
    apple_hash_stamp(h, &st);
    return true;
}

/* A selector can change while its argv and environment stay fixed when a
 * tool appears earlier in PATH or COMPILER_PATH. Bind directory stamps as well
 * as the selected file; any unreadable directory refuses the memo. */
static bool apple_hash_search_dirs(struct sha3_256_ctx *h, const char *paths,
                                   const char *name)
{
    if (!paths) return true;
    const char *p = paths;
    for (;;) {
        const char *end = strchr(p, ':');
        size_t len = end ? (size_t)(end - p) : strlen(p);
        char dir[PATH_MAX];
        if (len >= sizeof dir) return false;
        if (len) memcpy(dir, p, len);
        dir[len] = '\0';
        if (!len) memcpy(dir, ".", 2u);
        if (!apple_hash_search_dir(h, dir) ||
            !apple_hash_search_candidate(h, dir, name)) return false;
        if (!end) break;
        p = end + 1;
    }
    return true;
}

static bool apple_tool_selection_cacheable(char *const query[],
                                           const char *label)
{
    /* The driver can apply target prefixes and -B prefix rules that are not
     * a plain directory search. Query it on every request for those modes;
     * they still key the returned executable's path and bytes. The memo is
     * only for the default integrated Clang backend. */
    if (strcmp(label, "apple-backend") != 0 ||
        (getenv("COMPILER_PATH") && *getenv("COMPILER_PATH"))) return false;
    for (size_t i = 0; query[i]; i++)
        if (strcmp(query[i], "-B") == 0 ||
            strncmp(query[i], "-B", 2) == 0 ||
            strcmp(query[i], "-target") == 0 ||
            strncmp(query[i], "-target=", 8) == 0 ||
            strcmp(query[i], "--target") == 0 ||
            strncmp(query[i], "--target=", 9) == 0 ||
            strcmp(query[i], "-arch") == 0) return false;
    return true;
}

static bool apple_tool_selection_key(char *const query[],
                                     const char *label,
                                     uint8_t root[SHA3_256_OUTPUT_SIZE])
{
    if (!apple_tool_selection_cacheable(query, label)) return false;
    char driver[PATH_MAX], digest[HEXLEN + 1u], developer[PATH_MAX];
    char *const select_argv[] = { "/usr/bin/xcode-select", "-p", NULL };
    if (!resolve_cc(query[0], driver) || !file_hex(driver, digest) ||
        !apple_tool_query_output(select_argv, developer)) return false;
    struct sha3_256_ctx h;
    sha3_256_init(&h);
    hstr(&h, "zcc.apple_tool_selection.v1");
    hstr(&h, label); hstr(&h, driver); hstr(&h, digest);
    hstr(&h, developer);
    for (size_t i = 0; query[i]; i++) hstr(&h, query[i]);
    if (!hash_environment(&h) ||
        !apple_hash_search_dirs(&h, getenv("PATH"), "clang")) return false;
    sha3_256_finalize(&h, root);
    return true;
}

static bool apple_tool_selection_path(const char *cache_root,
                                      const char *label,
                                      const uint8_t root[SHA3_256_OUTPUT_SIZE],
                                      char path[PATH_MAX])
{
    const char *name = strcmp(label, "apple-backend") == 0
        ? "apple-backend.selection" : "apple-assembler.selection";
    /* 256 bounded slots prevent a second compiler in the same build from
     * evicting the first. A collision only costs a fresh driver query. */
    int n = snprintf(path, PATH_MAX, "%s/%s.%02x", cache_root, name,
                     (unsigned)root[0]);
    return n > 0 && n < PATH_MAX;
}

static bool apple_tool_selection_load(const char *path,
                                      struct apple_tool_selection_record *record)
{
    int fd = open(path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (fd < 0) return false;
    struct stat cache_stat;
    bool ok = fstat(fd, &cache_stat) == 0 &&
              S_ISREG(cache_stat.st_mode) &&
              cache_stat.st_size == (off_t)sizeof *record;
    size_t done = 0;
    while (ok && done < sizeof *record) {
        ssize_t got = read(fd, (char *)record + done, sizeof *record - done);
        if (got < 0 && errno == EINTR) continue;
        if (got <= 0) { ok = false; break; }
        done += (size_t)got;
    }
    if (close(fd) != 0) ok = false;
    return ok;
}

static bool apple_tool_selection_read(const char *path,
                                      const uint8_t root[SHA3_256_OUTPUT_SIZE],
                                      char selected[PATH_MAX])
{
    struct apple_tool_selection_record record;
    struct stat tool_stat, parent_stat;
    if (!apple_tool_selection_load(path, &record) ||
        memcmp(record.magic, "ZATS001", 8) != 0 ||
        memcmp(record.selector_root, root, SHA3_256_OUTPUT_SIZE) != 0 ||
        !memchr(record.selected, '\0', sizeof record.selected) ||
        stat(record.selected, &tool_stat) != 0 ||
        !S_ISREG(tool_stat.st_mode) ||
        !apple_tool_parent_stat(record.selected, &parent_stat)) return false;
    struct apple_tool_stamp tool = apple_tool_stamp_of(&tool_stat);
    struct apple_tool_stamp parent = apple_tool_stamp_of(&parent_stat);
    if (memcmp(&tool, &record.tool_stamp, sizeof tool) != 0 ||
        memcmp(&parent, &record.parent_stamp, sizeof parent) != 0) return false;
    memcpy(selected, record.selected, sizeof record.selected);
    return true;
}

static void apple_tool_selection_write(const char *cache_root,
                                       const char *path,
                                       const uint8_t root[SHA3_256_OUTPUT_SIZE],
                                       const char *selected)
{
    struct stat tool_stat, parent_stat;
    if (stat(selected, &tool_stat) != 0 ||
        !S_ISREG(tool_stat.st_mode) ||
        !apple_tool_parent_stat(selected, &parent_stat)) return;
    struct apple_tool_selection_record record = { 0 };
    memcpy(record.magic, "ZATS001", 8);
    memcpy(record.selector_root, root, SHA3_256_OUTPUT_SIZE);
    record.tool_stamp = apple_tool_stamp_of(&tool_stat);
    record.parent_stamp = apple_tool_stamp_of(&parent_stat);
    memcpy(record.selected, selected, strlen(selected) + 1u);
    char tmp[PATH_MAX];
    int n = snprintf(tmp, sizeof tmp, "%s/tmp", cache_root);
    if (n > 0 && (size_t)n < sizeof tmp)
        (void)store_atomic(tmp, path, (const uint8_t *)&record,
                           sizeof record, 0600);
}

#endif

static bool apple_tool_digest_path(const char *root, const char *tool,
                                   const char *slot,
                                   char path[PATH_MAX],
                                   uint8_t path_root[SHA3_256_OUTPUT_SIZE])
{
    struct sha3_256_ctx sha;
    sha3_256_init(&sha);
    hstr(&sha, "zcc.apple_tool_digest_path.v1");
    hstr(&sha, tool);
    sha3_256_finalize(&sha, path_root);
    /* One slot bounds this memo even when many different toolchains are
     * selected. A path change causes a fresh byte hash and replaces it. */
    int n = snprintf(path, PATH_MAX, "%s/%s.digest", root, slot);
    return n > 0 && n < PATH_MAX;
}

static bool apple_tool_digest_record_valid(
    const struct apple_tool_digest_record *record,
    const struct stat *tool_stat,
    const uint8_t path_root[SHA3_256_OUTPUT_SIZE])
{
    struct apple_tool_stamp wanted = apple_tool_stamp_of(tool_stat);
    if (memcmp(record->magic, "ZATD001", 8) != 0 ||
        memcmp(record->path_root, path_root, SHA3_256_OUTPUT_SIZE) != 0 ||
        memcmp(&record->stamp, &wanted, sizeof wanted) != 0 ||
        record->digest[HEXLEN] != '\0') return false;
    for (size_t i = 0; i < HEXLEN; i++)
        if (!isxdigit((unsigned char)record->digest[i])) return false;
    return true;
}

static bool apple_tool_digest_read(const char *path,
                                   const struct stat *tool_stat,
                                   const uint8_t path_root[SHA3_256_OUTPUT_SIZE],
                                   char out[HEXLEN + 1u])
{
    struct apple_tool_digest_record record;
    int fd = open(path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (fd < 0) return false;
    struct stat cache_stat;
    bool ok = fstat(fd, &cache_stat) == 0 &&
              S_ISREG(cache_stat.st_mode) &&
              cache_stat.st_size == (off_t)sizeof record;
    size_t done = 0;
    while (ok && done < sizeof record) {
        ssize_t got = read(fd, (char *)&record + done,
                           sizeof record - done);
        if (got < 0 && errno == EINTR) continue;
        if (got <= 0) { ok = false; break; }
        done += (size_t)got;
    }
    if (close(fd) != 0) ok = false;
    if (!ok || !apple_tool_digest_record_valid(&record, tool_stat,
                                               path_root)) return false;
    memcpy(out, record.digest, HEXLEN + 1u);
    return true;
}

static void apple_tool_digest_write(const char *root, const char *path,
                                    const struct stat *tool_stat,
                                    const uint8_t path_root[SHA3_256_OUTPUT_SIZE],
                                    const char digest[HEXLEN + 1u])
{
    struct apple_tool_digest_record record = { 0 };
    memcpy(record.magic, "ZATD001", 8);
    memcpy(record.path_root, path_root, SHA3_256_OUTPUT_SIZE);
    record.stamp = apple_tool_stamp_of(tool_stat);
    memcpy(record.digest, digest, HEXLEN + 1u);
    char tmp[PATH_MAX];
    int n = snprintf(tmp, sizeof tmp, "%s/tmp", root);
    if (n > 0 && (size_t)n < sizeof tmp)
        (void)store_atomic(tmp, path, (const uint8_t *)&record,
                           sizeof record, 0600);
}

static bool apple_tool_digest_cached(const char *tool, const char *root,
                                     const char *slot,
                                     char out[HEXLEN + 1u])
{
    struct stat before, after;
    char path[PATH_MAX];
    uint8_t path_root[SHA3_256_OUTPUT_SIZE];
    if (stat(tool, &before) != 0 || !S_ISREG(before.st_mode)) return false;
    bool cache_path = apple_tool_digest_path(root, tool, slot, path, path_root);
    if (cache_path && apple_tool_digest_read(path, &before, path_root, out) &&
        stat(tool, &after) == 0 && apple_tool_stamp_equal(&before, &after))
        return true;
    if (!file_hex(tool, out) || stat(tool, &after) != 0 ||
        !apple_tool_stamp_equal(&before, &after)) return false;
    if (cache_path) apple_tool_digest_write(root, path, &after,
                                            path_root, out);
    return true;
}

#if defined(__APPLE__)
static bool hash_apple_selected_tool(struct sha3_256_ctx *h,
                                     const struct plan *pl,
                                     const char *query_flag,
                                     const char *label,
                                     const char *cache_root)
{
    char **query = apple_tool_query_argv(pl, query_flag);
    if (!query) return false;
    char selected[PATH_MAX], selection_path[PATH_MAX];
    uint8_t selection_root[SHA3_256_OUTPUT_SIZE];
    bool memo = apple_tool_selection_key(query, label, selection_root) &&
                apple_tool_selection_path(cache_root, label, selection_root,
                                          selection_path);
    bool ok = memo && apple_tool_selection_read(selection_path,
                                                 selection_root, selected);
    if (!ok) {
        char output[PATH_MAX];
        ok = apple_tool_query_output(query, output) &&
             resolve_cc(output, selected);
        if (ok && memo) apple_tool_selection_write(cache_root, selection_path,
                                                    selection_root, selected);
    }
    free(query);
    if (!ok) return false;
    char digest[HEXLEN + 1u];
    ok = (strcmp(label, "apple-backend") == 0
              ? apple_tool_digest_cached(selected, cache_root, label, digest)
              : file_hex(selected, digest));
    if (ok) {
        hstr(h, label);
        hstr(h, selected);
        hstr(h, digest);
    }
    return ok;
}

static bool hash_apple_backend(struct sha3_256_ctx *h,
                               const struct plan *pl,
                               const char *cache_root)
{
    /* /usr/bin/cc is a launcher. -cc1 executes inside the Clang selected by
     * the driver, whose bytes can change while the launcher stays fixed. */
    return hash_apple_selected_tool(h, pl, "-print-prog-name=clang",
                                    "apple-backend", cache_root);
}

static bool hash_apple_assembler(struct sha3_256_ctx *h,
                                 const struct plan *pl,
                                 const char *cache_root)
{
    if (!apple_assembler_external(pl)) return true;
    return hash_apple_selected_tool(h, pl, "-print-prog-name=as",
                                    "apple-assembler", cache_root);
}
#endif
#endif

#if defined(__linux__)
/* GCC executes these producers outside its driver. Resolve them anew: a
 * previously absent earlier -B candidate can change selection. The private
 * development memo avoids rehashing an unchanged large frontend, while a
 * changed file identity or ctime forces a new byte digest. */
static bool hash_linux_selected_tool(struct sha3_256_ctx *h,
                                     const struct plan *pl,
                                     const char *query_flag,
                                     const char *label,
                                     const char *cache_root)
{
    char **query = apple_tool_query_argv(pl, query_flag);
    if (!query) return false;
    char output[PATH_MAX], selected[PATH_MAX], digest[HEXLEN + 1u];
    bool ok = apple_tool_query_output(query, output) &&
              resolve_cc(output, selected) &&
              apple_tool_digest_cached(selected, cache_root, label, digest);
    free(query);
    if (!ok) return false;
    hstr(h, label);
    hstr(h, selected);
    hstr(h, digest);
    return true;
}
#endif

static bool hash_toolchain(struct sha3_256_ctx *h, const struct plan *pl,
                           const char *cache_root)
{
    char ccpath[PATH_MAX];
    hstr(h, ZCC_MAGIC);
    char digest[HEXLEN + 1u];
    if (!resolve_cc(pl->argv[0], ccpath) || !file_hex(ccpath, digest))
        return false;
    hstr(h, ccpath);
    hstr(h, digest);
#if defined(__APPLE__)
    if (!hash_apple_backend(h, pl, cache_root) ||
        !hash_apple_assembler(h, pl, cache_root))
        return false;
#elif defined(__linux__)
    if (!hash_linux_selected_tool(h, pl, "-print-prog-name=cc1",
                                  "linux-cc1", cache_root) ||
        !hash_linux_selected_tool(h, pl, "-print-prog-name=as",
                                  "linux-as", cache_root))
        return false;
#else
    (void)cache_root;
#endif
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
    /* Compiler drivers can read CPATH, SDKROOT, LANG, and custom selectors.
     * Environment entry order is irrelevant unless a name is duplicated;
     * reject duplicates rather than guessing which value the compiler sees. */
    return hash_environment(h);
}

/* Archives named by -l are real inputs; fold in the ones we can resolve. */
static bool hash_named_libs(struct sha3_256_ctx *h, const struct plan *pl)
{
    for (int i = 1; i < pl->argc; i++) {
        const char *a = pl->argv[i];
        if (strncmp(a, "-l", 2) != 0 || !a[2])
            continue;
        bool found = false;
        for (int d = 0; d < pl->libdir_n; d++) {
            char cand[PATH_MAX];
            snprintf(cand, sizeof cand, "%s/lib%s.a", pl->libdir[d], a + 2);
            struct stat st;
            if (stat(cand, &st) != 0)
                continue;
            hstr(h, cand);
            char digest[HEXLEN + 1u];
            if (!file_hex(cand, digest))
                return false;
            hstr(h, digest);
            found = true;
            break;
        }
        if (!found)
            return false;
    }
    return true;
}

static bool probe_key(const struct plan *pl, const char *cache_root,
                      char out[HEXLEN + 1u])
{
    struct sha3_256_ctx h;
    sha3_256_init(&h);
    hstr(&h, "probe");
    if (!hash_toolchain(&h, pl, cache_root))
        return false;
    for (int i = 0; i < pl->src_n + pl->blob_n; i++) {
        int idx = i < pl->src_n ? pl->src[i] : pl->blob[i - pl->src_n];
        const char *p = pl->argv[idx];
        struct stat st;
        char digest[HEXLEN + 1u];
        if (stat(p, &st) != 0)
            return false;
        if (!file_hex(p, digest))
            return false;
        hstr(&h, p);
        hstr(&h, digest);
        hu64(&h, (uint64_t)st.st_size);
        hu64(&h, (uint64_t)st.st_mtim.tv_sec);
        hu64(&h, (uint64_t)st.st_mtim.tv_nsec);
        hu64(&h, (uint64_t)st.st_ino);
    }
    for (int i = 0; i < pl->rsp_n; i++) {
        struct stat st;
        char digest[HEXLEN + 1u];
        if (stat(pl->rsp[i], &st) != 0 ||
            !file_hex(pl->rsp[i], digest))
            return false;
        hstr(&h, pl->rsp[i]);
        hstr(&h, digest);
        hu64(&h, (uint64_t)st.st_size);
        hu64(&h, (uint64_t)st.st_mtim.tv_sec);
        hu64(&h, (uint64_t)st.st_mtim.tv_nsec);
        hu64(&h, (uint64_t)st.st_ino);
    }
    if (!hash_named_libs(&h, pl))
        return false;
    unsigned char d[SHA3_256_OUTPUT_SIZE];
    sha3_256_finalize(&h, d);
    hex_of(d, out);
    return true;
}

static bool probe_for_plan(const struct plan *pl, const char *cache_root,
                           bool strict,
                           char out[HEXLEN + 1u])
{
    /* A source compile can change when an earlier include-search candidate
     * appears, without changing the stat of any previously opened file. */
    return !strict && pl->src_n == 0 &&
           probe_key(pl, cache_root, out);
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
    bool failed;
};

static void deps_free(struct deps *d)
{
    for (size_t i = 0; i < d->n; i++)
        free(d->path[i]);
    free(d->path);
    d->path = NULL;
    d->n = d->cap = 0;
    d->failed = false;
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
        if (!np) {
            d->failed = true;
            return;
        }
        d->path = np;
        d->cap = nc;
    }
    char *copy = zcl_malloc(len + 1u, "zcc dep path");
    if (!copy) {
        d->failed = true;
        return;
    }
    memcpy(copy, p, len);
    copy[len] = '\0';
    d->path[d->n++] = copy;
}

/* Harvest `# 1 "some/header.h"` line markers out of preprocessed text. */
static void deps_marker(struct deps *d, const unsigned char *p,
                        size_t start, size_t eol)
{
    if (eol - start <= 4 || p[start] != '#' || p[start + 1u] != ' ')
        return;
    size_t q = start + 2u;
    while (q < eol && p[q] != '"')
        q++;
    if (q == eol)
        return;
    q++;
    char unesc[PATH_MAX];
    size_t u = 0;
    while (q < eol && p[q] != '"' && u + 1u < sizeof unesc) {
        if (p[q] == '\\' && q + 1u < eol)
            q++;
        unesc[u++] = (char)p[q++];
    }
    if (q < eol && p[q] == '"' && u > 0)
        deps_add(d, unesc, u);
    else
        d->failed = true;
}

static void deps_scan(struct deps *d, const unsigned char *p, size_t len)
{
    size_t i = 0;
    while (i < len) {
        size_t eol = i;
        while (eol < len && p[eol] != '\n')
            eol++;
        deps_marker(d, p, i, eol);
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
                        const char *cache_root,
                        struct deps *d,
                        char out[HEXLEN + 1u])
{
    struct sha3_256_ctx h;
    sha3_256_init(&h);
    hstr(&h, "content");
    if (!hash_toolchain(&h, pl, cache_root))
        return false;
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
        if (d->failed)
            return false;
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
    if (!hash_named_libs(&h, pl))
        return false;
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

static void logline(const char *disposition, const char *detail,
                    const struct plan *pl);

/* One fixed inode keeps coordination storage bounded. A byte range selected
 * by the content key serializes only matching work (or a hash collision).
 * Ordinary obj/probe eviction never removes this inode. */
static bool flight_current(int fd, const char *path)
{
    struct stat opened, named;
    return fstat(fd, &opened) == 0 && S_ISREG(opened.st_mode) &&
           lstat(path, &named) == 0 && S_ISREG(named.st_mode) &&
           opened.st_dev == named.st_dev && opened.st_ino == named.st_ino;
}

static int64_t flight_clock_ms(void)
{
    struct timespec now;
    if (clock_gettime(CLOCK_MONOTONIC, &now) != 0) // platform-ok: standalone bootstrap deadline
        return -1;
    return (int64_t)now.tv_sec * 1000 + now.tv_nsec / 1000000;
}

static off_t flight_offset(const char *key)
{
    uint64_t offset = 0;
    size_t digits = sizeof(off_t) >= 8 ? 15 : 7;
    for (size_t i = 0; i < digits; i++) {
        int nibble = zcl_hex_nibble(key[i], false);
        if (nibble < 0)
            return (off_t)-1;
        offset = (offset << 4) | (unsigned)nibble;
    }
    return (off_t)offset;
}

static bool flight_wait(int fd, const char *path, struct flock *lock,
                        const struct plan *pl, bool *waited)
{
    int64_t start = flight_clock_ms();
    while (start >= 0 && flight_current(fd, path)) {
        if (fcntl(fd, F_SETLK, lock) == 0)
            return flight_current(fd, path);
        if (errno != EACCES && errno != EAGAIN && errno != EINTR)
            break;
        if (!*waited)
            logline("WAIT", "concurrent content", pl);
        *waited = true;
        int64_t now = flight_clock_ms();
        if (now < start || now - start >= 120000)
            break;
        struct timespec pause = { .tv_sec = 0, .tv_nsec = 20000000 };
        (void)nanosleep(&pause, NULL); // platform-ok: standalone bootstrap lock wait
    }
    return false;
}

static int flight_acquire(const struct cache *c, const char *key,
                           const struct plan *pl, bool *waited)
{
    char path[PATH_MAX];
    *waited = false;
    off_t offset = flight_offset(key);
    if (offset < 0)
        return -1;
    snprintf(path, sizeof path, "%.3000s/flight.lock", c->root);
    int fd = open(path, O_RDWR | O_CREAT | O_NOFOLLOW | O_CLOEXEC, 0600);
    if (fd < 0)
        return -1;
    struct flock lock = { .l_type = F_WRLCK, .l_whence = SEEK_SET,
                          .l_start = offset, .l_len = 1 };
    if (flight_wait(fd, path, &lock, pl, waited))
        return fd;
    close(fd);
    return -1;
}

static void flight_release(int fd)
{
    if (fd >= 0)
        close(fd);
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

/* ── the bound ───────────────────────────────────────────────────────── */

/* THE BOUND.
 *
 * WHY. Nothing ever reclaimed this cache. Eviction existed, but only as
 * `make cc-cache-trim`, which no build runs, so on the maintainer host it
 * reached 196 GB across 1 176 577 files and on the second host 60 GB. A cache
 * whose size depends on a human remembering a make target does not have a
 * size; it has a leak with a fast path attached. So the ceiling is enforced
 * here, by the same binary that does the storing.
 *
 * WHAT TRIGGERS A TRIM. Not a directory walk per compile: this sits on the
 * hot path of every compile in the tree, and the walk it guards was MEASURED
 * at 1.0 s over that 1 176 577-file cache (`find obj -type f -printf` on a
 * warm page cache). Instead every store adds to a byte counter — grow(), one
 * appended byte per ZCC_GROWTH_UNIT stored, the same lock-free trick bump()
 * uses for events — and a walk is paid for only once the cache has grown by
 * an eighth of its ceiling since the last trim. Reading "how much have we
 * grown" is a single stat(). A warm rebuild stores nothing and so triggers
 * nothing at all; a cold build of every profile stores ~8 GB and so pays for
 * two walks at the default ceiling.
 *
 * CONCURRENCY. flock() on one file, non-blocking, so the other 31 compiles of
 * a `make -j32` that arrive mid-trim find it taken and simply carry on. The
 * kernel drops that lock when the holder dies, which an O_EXCL sentinel would
 * not: a SIGKILL mid-trim cannot wedge the bound off. The lock file's mtime
 * is a second, independent floor, so even a growth counter that could not be
 * reset cannot turn every compile into a walk.
 *
 * WHY AN INTERRUPTED TRIM CANNOT SERVE HALF AN ENTRY. Two rules, and they are
 * the reason the deletion order in OBJ_EXT and the write order in store() are
 * both spelled out rather than incidental:
 *   1. store() publishes the .bin LAST and evict() deletes it FIRST. serve()
 *      decides an entry exists by the .bin, so a store or an eviction cut
 *      short at any instant — SIGKILL, ENOSPC, the OOM killer — leaves at
 *      worst an unservable remainder, never an entry that answers a hit with
 *      part of itself.
 *   2. Rule 1 orders one process against itself; it cannot order a trim
 *      against a concurrent store of the same key, whose unlinks and writes
 *      interleave freely. So serve() does not trust the entry at all: it
 *      requires the depfile to be there NOW, and restores it BEFORE the
 *      object, so a .dep that vanishes between the check and the copy is a
 *      miss rather than an object served without its dependencies.
 * A missing .err costs a replayed warning, not a wrong byte, and rule 1 is
 * what bounds that to the same-key store/trim interleaving.
 *
 * FAILURE IS NEVER FATAL. Every step here returns quietly on any error and
 * prints nothing: the artifact is already on disk and already handed to make
 * before any of this runs. A cache that can fail a build is not a speed aid. */

/* Bytes of cache per byte of the growth counter. */
#define ZCC_GROWTH_UNIT 65536LL

/* WHAT THE CEILING COUNTS: disk, not content. The complaint that produced
 * this bound was "196 GB on node1", which is what `du` says, so that is what
 * the ceiling has to mean. st_blocks is in 512-byte units by POSIX regardless
 * of the filesystem's block size, and it is already in the stat this walk
 * performs, so counting the real thing is free. On the live cache the two
 * differ by under 1% (193 GiB of blocks against 191.2 GiB of content), but on
 * a small one the 8.5 KB depfiles and 0-byte .err files round hard enough
 * that an apparent-size ceiling is not the ceiling the operator set. */
#define ZCC_DISK(st) ((long long)(st).st_blocks * 512LL)

/* THE DEFAULT CEILING, from measured footprints on the maintainer host rather
 * than a round number. One complete generation of everything this tree builds
 * is:
 *   objects  41 907 across the 8 profiles present in build/ (dev, dev-asan,
 *            dev-tsan, release, test, test-rel, test-tsan, fuzz), 6 273 MB on
 *            disk (du -sm per profile directory);
 *   sidecars 17.8 KB per entry — .dep mean 8.5 KB (3 401 096 610 B over
 *            390 753 files), manifest mean 9.3 KB (3.3 GB over 366 759), .err
 *            mean ~0 (38 019 B over 392 912) — so 746 MB;
 *   links    68 binaries in build/bin, 1 398 MB, cached like any other
 *            single-output invocation because this cache keys link steps too.
 * That is ~8.4 GB for one generation. The ceiling has to hold more than one
 * or it is a stopwatch, not a cache: the value of the thing is hitting on the
 * build you did before the branch switch, or before the edit you just
 * reverted. 24 GB is ~2.9 generations — the current build plus roughly two
 * more — and eight times smaller than what this host had accumulated. */
#define ZCC_DEFAULT_MAX_MB 24576LL

/* No trim may start within this many seconds of the last one, whatever the
 * growth counter says. This is a BACKSTOP, not the trigger — the growth
 * counter is the trigger, and at the default ceiling it fires once per 3 GB
 * stored, which the floor never even reaches. The floor only engages when the
 * ceiling is small enough that an eighth of it is a few hundred KB, and it
 * has to stay small because it is also the overshoot: a burst of -j32 stores
 * lands unbounded during it. MEASURED — at 10 s, a 200-object build against
 * a 4 MB ceiling trimmed once, too early to free anything, and finished at
 * 7 560 KB. At 1 s the same build holds the ceiling, and a walk once a second
 * on a cache small enough to need one is not a cost worth avoiding. */
#define ZCC_TRIM_FLOOR_SEC 1

/* A file in an entry directory that is not part of an entry is only swept
 * once it is older than any in-flight store could be. */
#define ZCC_STRAY_AGE_SEC 3600

/* A hit older than this refreshes the artifact's mtime — see touch_if_stale. */
#define ZCC_TOUCH_AFTER_SEC 3600

/* The sibling files one obj entry owns, in the order evict() must remove
 * them: .bin first and always, per rule 1 above. Keep in sync with store(). */
static const char *const OBJ_EXT[] = { ".bin", ".meta", ".dep", ".err" };

/* A ceiling in MB that cannot overflow when turned into bytes. Without the
 * clamp a large enough ZCC_MAX_MB wraps `mb * 1024 * 1024` NEGATIVE, every
 * total compares as "over the limit", and the bound deletes the entire cache
 * — the exact opposite of what the operator typed. 8 TB is past any real
 * ceiling and 1000× short of the wrap. */
#define ZCC_MAX_CEILING_MB (8LL * 1024LL * 1024LL)

static long long clamp_mb(long long v)
{
    if (v < 0)
        return 0;
    return v > ZCC_MAX_CEILING_MB ? ZCC_MAX_CEILING_MB : v;
}

static long long ceiling_mb(void)
{
    const char *s = getenv("ZCC_MAX_MB");
    if (!s || !s[0])
        return ZCC_DEFAULT_MAX_MB;
    errno = 0;
    char *end = NULL;
    long long v = strtoll(s, &end, 10);
    /* Anything unparseable falls back to the default rather than to "no
     * bound": a typo in an environment variable must not restore the leak. */
    if (errno != 0 || end == s || *end || v < 0)
        return ZCC_DEFAULT_MAX_MB;
    return clamp_mb(v);
}

/* One appended byte per ZCC_GROWTH_UNIT stored. The counter IS the file size,
 * so concurrent makes never need a lock and never lose a count. Rounded UP,
 * because an estimate that can run late is not a bound; the cost of running
 * early is one extra walk. */
static void grow(const struct cache *c, long long bytes)
{
    if (bytes <= 0)
        return;
    unsigned long long units =
        ((unsigned long long)bytes + (unsigned long long)ZCC_GROWTH_UNIT - 1u) /
        (unsigned long long)ZCC_GROWTH_UNIT;
    char p[PATH_MAX];
    snprintf(p, sizeof p, "%.3000s/stat.grown", c->root);
    int fd = open(p, O_WRONLY | O_CREAT | O_APPEND | O_CLOEXEC, 0600);
    if (fd < 0)
        return;
    static const char pad[4096];
    while (units > 0) {
        size_t want = units > sizeof pad ? sizeof pad : (size_t)units;
        ssize_t n = write(fd, pad, want);
        if (n <= 0)
            break;
        units -= (unsigned long long)n;
    }
    close(fd);
}

/* AGE FOR EVICTION. Nothing else in this file ever writes to an entry after
 * it is stored, so eviction by mtime would be eviction by CREATION time: a
 * hot object built a month ago goes before a cold one built an hour ago, and
 * the bound would systematically discard exactly what the build keeps asking
 * for. A hit therefore refreshes the artifact, but only once it has gone
 * stale, so a fully warm rebuild of 41 907 objects performs zero writes. */
static void touch_if_stale(const char *path, time_t mtime)
{
    time_t now = zcc_wall_time();
    if (now == (time_t)-1 || now - mtime < ZCC_TOUCH_AFTER_SEC)
        return;
    (void)utimensat(AT_FDCWD, path, NULL, 0);
}

/* One cache entry: every file sharing a key, treated as a unit. Compact on
 * purpose — the previous eviction list held a PATH_MAX string per FILE, which
 * on this host's cache is a 4.8 GB allocation inside a compile. This is 88
 * bytes per ENTRY, 35 MB for the same cache. */
struct entry {
    char kind;                 /* 'o' = obj, 'm' = man */
    char shard[3];             /* the 2-hex fan-out directory */
    char stem[HEXLEN + 1u];    /* the 64-hex key */
    long long size;            /* every sibling of this entry, summed */
    time_t mtime;              /* the newest sibling: this is its age */
};

struct filerec {
    char stem[HEXLEN + 1u];
    long long size;
    time_t mtime;
};

struct evict_list {
    struct entry *v;
    size_t n, cap;
};

static bool is_hex(const char *s, size_t n, size_t want)
{
    if (n != want)
        return false;
    for (size_t i = 0; i < n; i++)
        if (!isxdigit((unsigned char)s[i]))
            return false;
    return true;
}

/* Is `name` a file this cache owns, and if so which entry? Anything else in
 * an entry directory is a stray. */
static bool entry_name(char kind, const char *name, char stem[HEXLEN + 1u])
{
    size_t n = strlen(name);
    if (kind == 'm') {
        if (!is_hex(name, n, HEXLEN))
            return false;
    } else {
        const char *dot = strrchr(name, '.');
        if (!dot || !is_hex(name, (size_t)(dot - name), HEXLEN))
            return false;
        bool known = false;
        for (size_t i = 0; i < sizeof OBJ_EXT / sizeof OBJ_EXT[0]; i++)
            if (strcmp(dot, OBJ_EXT[i]) == 0)
                known = true;
        if (!known)
            return false;
    }
    memcpy(stem, name, HEXLEN);
    stem[HEXLEN] = '\0';
    return true;
}

static bool ev_push(struct evict_list *l, const struct entry *e)
{
    if (l->n == l->cap) {
        size_t nc = l->cap ? l->cap * 2u : 4096u;
        struct entry *nv = zcl_realloc(l->v, nc * sizeof *nv, "zcc trim list");
        if (!nv)
            return false;
        l->v = nv;
        l->cap = nc;
    }
    l->v[l->n++] = *e;
    return true;
}

static int by_stem(const void *a, const void *b)
{
    return strcmp(((const struct filerec *)a)->stem,
                  ((const struct filerec *)b)->stem);
}

/* Oldest first, with a deterministic tie-break so two hosts (or two trims)
 * evict in the same order rather than in readdir order. */
static int by_age(const void *a, const void *b)
{
    const struct entry *x = a, *y = b;
    if (x->mtime != y->mtime)
        return x->mtime < y->mtime ? -1 : 1;
    return strcmp(x->stem, y->stem);
}

/* Sweep the staging directory of work nobody owns any more. main() unlinks
 * its own err.<pid>, but a compile killed before that point leaves one, and
 * nothing else ever removed them: MEASURED on this host, 30 of the 35 files
 * in tmp/ were over an hour old and the oldest was three days. Tiny, and
 * unbounded, which is the part that matters in a cache that now polices its
 * own size. The old eviction walked tmp/ as ordinary content and could unlink
 * a file a live compile was still writing; this one only touches what is too
 * old for any running store to own, and returns what it left behind. */
static long long sweep_tmp(const struct cache *c, time_t now)
{
    DIR *d = opendir(c->tmp);
    if (!d)
        return 0;
    long long kept = 0;
    struct dirent *e;
    while ((e = readdir(d))) {
        char p[PATH_MAX];
        if (snprintf(p, sizeof p, "%.4000s/%.80s", c->tmp, e->d_name) >=
            (int)sizeof p)
            continue;
        struct stat st;
        if (lstat(p, &st) != 0 || !S_ISREG(st.st_mode))
            continue;
        if (now != (time_t)-1 && now - st.st_mtime > ZCC_STRAY_AGE_SEC)
            unlink(p);
        else
            kept += ZCC_DISK(st);
    }
    closedir(d);
    return kept;
}

/* Total bytes held, and one record per entry into `l`. Returns -1 only when
 * it ran out of memory, which abandons the trim entirely: trimming against a
 * partial total would evict against a number that is not the cache's size.
 * A directory it cannot read contributes nothing and is not an error. */
static long long scan_entries(const struct cache *c, struct evict_list *l)
{
    static const char kinds[] = { 'o', 'm' };
    static const char *const dirs[] = { "obj", "man" };
    time_t now = zcc_wall_time();
    long long total = sweep_tmp(c, now);
    struct filerec *fr = NULL;
    size_t fr_cap = 0;
    bool oom = false;

    for (size_t k = 0; k < sizeof kinds && !oom; k++) {
        char kdir[PATH_MAX];
        snprintf(kdir, sizeof kdir, "%.3000s/%.8s", c->root, dirs[k]);
        DIR *kd = opendir(kdir);
        if (!kd)
            continue;
        struct dirent *se;
        while (!oom && (se = readdir(kd))) {
            if (!is_hex(se->d_name, strlen(se->d_name), 2u))
                continue;
            char sdir[PATH_MAX];
            if (snprintf(sdir, sizeof sdir, "%.4000s/%.2s", kdir, se->d_name) >=
                (int)sizeof sdir)
                continue;
            DIR *sd = opendir(sdir);
            if (!sd)
                continue;
            /* The fan-out directory's own blocks are part of what du reports,
             * and at a few thousand entries a shard they are not nothing. */
            struct stat dst;
            if (lstat(sdir, &dst) == 0)
                total += ZCC_DISK(dst);
            size_t fn = 0;
            struct dirent *fe;
            while ((fe = readdir(sd))) {
                char fp[PATH_MAX];
                if (snprintf(fp, sizeof fp, "%.4000s/%.80s", sdir,
                             fe->d_name) >= (int)sizeof fp)
                    continue;
                struct stat st;
                if (lstat(fp, &st) != 0 || !S_ISREG(st.st_mode))
                    continue;
                char stem[HEXLEN + 1u];
                if (!entry_name(kinds[k], fe->d_name, stem)) {
                    /* A STRAY. store_atomic() stages through .zcc.XXXXXX in
                     * this very directory, so a process killed between
                     * mkstemp() and rename() leaves one here and nothing else
                     * would ever remove it. A stray the bound can count but
                     * never evict is how a self-bounding cache starves
                     * itself: once strays alone exceed the ceiling, every
                     * trim deletes every real entry and is STILL over. Sweep
                     * the ones too old for any live store to own. */
                    if (now != (time_t)-1 &&
                        now - st.st_mtime > ZCC_STRAY_AGE_SEC)
                        unlink(fp);
                    else
                        total += ZCC_DISK(st);
                    continue;
                }
                if (fn == fr_cap) {
                    size_t nc = fr_cap ? fr_cap * 2u : 8192u;
                    struct filerec *nf =
                        zcl_realloc(fr, nc * sizeof *nf, "zcc shard scan");
                    if (!nf) {
                        oom = true;
                        break;
                    }
                    fr = nf;
                    fr_cap = nc;
                }
                memcpy(fr[fn].stem, stem, HEXLEN + 1u);
                fr[fn].size = ZCC_DISK(st);
                fr[fn].mtime = st.st_mtime;
                fn++;
            }
            closedir(sd);
            if (oom)
                break;
            /* Coalesce this shard's files into entries before moving on, so
             * only entries are ever held in memory. */
            qsort(fr, fn, sizeof *fr, by_stem);
            for (size_t i = 0; i < fn;) {
                struct entry e = { .kind = kinds[k], .size = 0, .mtime = 0 };
                snprintf(e.shard, sizeof e.shard, "%.2s", se->d_name);
                memcpy(e.stem, fr[i].stem, HEXLEN + 1u);
                size_t j = i;
                while (j < fn && strcmp(fr[j].stem, e.stem) == 0) {
                    e.size += fr[j].size;
                    if (fr[j].mtime > e.mtime)
                        e.mtime = fr[j].mtime;
                    j++;
                }
                total += e.size;
                if (!ev_push(l, &e)) {
                    oom = true;
                    break;
                }
                i = j;
            }
        }
        closedir(kd);
    }
    free(fr);
    return oom ? -1 : total;
}

/* Remove one entry, .bin first. True when every file it owns is gone. */
static bool evict(const struct cache *c, const struct entry *e)
{
    char p[PATH_MAX];
    if (e->kind == 'm') {
        snprintf(p, sizeof p, "%.3000s/man/%.2s/%.64s", c->root, e->shard,
                 e->stem);
        return unlink(p) == 0 || errno == ENOENT;
    }
    bool gone = true;
    for (size_t i = 0; i < sizeof OBJ_EXT / sizeof OBJ_EXT[0]; i++) {
        snprintf(p, sizeof p, "%.3000s/obj/%.2s/%.64s%.8s", c->root, e->shard,
                 e->stem, OBJ_EXT[i]);
        if (unlink(p) != 0 && errno != ENOENT)
            gone = false;
    }
    return gone;
}

/* Bytes freed, or -1 when the scan could not run. Quiet by design: this runs
 * inside ordinary compiles, and a cache that prints into a build log is a
 * cache that gets switched off. */
static long long trim_to(const struct cache *c, long long limit,
                         long long *have_out)
{
    struct evict_list l = { 0 };
    long long have = scan_entries(c, &l);
    if (have_out)
        *have_out = have;
    if (have < 0) {
        free(l.v);
        return -1;
    }
    /* WHAT EVICTION CANNOT REACH. The fan-out directories themselves hold
     * disk, and ext4 never gives a directory's blocks back: MEASURED, the 512
     * shards on this host still hold 168.9 MB after the file count fell from
     * 392 912 to 174 628. That is 0.7% of the default ceiling and irrelevant
     * there — but a ceiling BELOW it can never be met, and a trim that chases
     * one deletes every entry, walks again a second later, and deletes
     * everything again forever. A ceiling that cannot be reached by evicting
     * is a misconfiguration, not an instruction to empty the cache; decline
     * it, leave the cache alone, and let cmd_trim say so. */
    long long evictable = 0;
    for (size_t i = 0; i < l.n; i++)
        evictable += l.v[i].size;
    long long freed = 0;
    if (have > limit && limit >= have - evictable) {
        qsort(l.v, l.n, sizeof *l.v, by_age);
        for (size_t i = 0; i < l.n && have - freed > limit; i++)
            if (evict(c, &l.v[i]))
                freed += l.v[i].size;
    }
    free(l.v);
    return freed;
}

/* The trim lock. `wait` blocks — an operator who asked for a trim gets one;
 * a compile never waits. -1 means "not now", never an error to report. */
static int trim_lock(const struct cache *c, bool wait)
{
    char p[PATH_MAX];
    snprintf(p, sizeof p, "%.3000s/trim.lock", c->root);
    int fd = open(p, O_WRONLY | O_CREAT | O_CLOEXEC, 0600);
    if (fd < 0)
        return -1;
    if (flock(fd, LOCK_EX | (wait ? 0 : LOCK_NB)) != 0) {
        close(fd);
        return -1;
    }
    return fd;
}

/* Stores that land while a trim runs belong to the NEXT interval, so the
 * counter is cleared BEFORE the walk, not after. truncate() rather than
 * unlink() so the other compiles keep appending to the same inode. */
static void reset_growth(const struct cache *c)
{
    char p[PATH_MAX];
    snprintf(p, sizeof p, "%.3000s/stat.grown", c->root);
    (void)!truncate(p, 0);
}

/* Called wherever bytes were added to the cache. Cheap to decline: one stat.
 * Everything about it is best-effort — see "FAILURE IS NEVER FATAL" above. */
static void maybe_trim(const struct cache *c, const struct plan *pl)
{
    long long max_mb = ceiling_mb();
    if (max_mb <= 0)
        return; /* ZCC_MAX_MB=0: the operator owns the size */
    /* HOW FAR ABOVE THE CEILING THE CACHE MAY DRIFT between trims: an eighth
     * of it. Not a fixed floor in bytes — ZCC_TRIM_FLOOR_SEC already bounds
     * how OFTEN a walk can happen, which is the resource that matters, and a
     * byte floor on top of it just makes a small ceiling stop meaning what it
     * says. The 1 MB is only to keep a degenerate ceiling from trimming on
     * every single store. */
    long long limit = max_mb * 1024LL * 1024LL;
    long long slack = limit / 8LL;
    if (slack < 1024LL * 1024LL)
        slack = 1024LL * 1024LL;
    if ((long long)counter(c, "grown") * ZCC_GROWTH_UNIT < slack)
        return;

    int fd = trim_lock(c, false);
    if (fd < 0)
        return; /* another compile is already trimming */
    /* The floor is "not within N seconds of the LAST trim", and a lock file
     * that has never been used has no last trim — its mtime is the instant
     * open(O_CREAT) just made it, which would read as "trimmed a moment ago"
     * and suppress the first trim on every fresh cache. Measured: with the
     * floor applied unconditionally, a 200-object build against a 4 MB
     * ceiling finished at 7 560 KB having trimmed exactly zero times. One
     * byte of content is the difference between the two states. */
    struct stat st;
    time_t now = zcc_wall_time();
    bool stamped = fstat(fd, &st) == 0 && st.st_size > 0;
    if (stamped && now != (time_t)-1 &&
        now - st.st_mtime < ZCC_TRIM_FLOOR_SEC) {
        close(fd);
        return;
    }
    if (!stamped)
        (void)!write(fd, "1", 1);
    (void)futimens(fd, NULL);
    reset_growth(c);

    long long have = 0;
    long long freed = trim_to(c, limit, &have);
    if (freed > 0) {
        char detail[96];
        snprintf(detail, sizeof detail, "%lld MB freed, %lld MB ceiling",
                 freed / (1024 * 1024), max_mb);
        logline("TRIM", detail, pl);
    }
    close(fd);
}

/* ── serve / store ───────────────────────────────────────────────────── */

#define ZCC_RESULT_MAGIC "ZCCRES2\0"
#define ZCC_RESULT_DEP 0x01u
#define ZCC_RESULT_ERR 0x02u
struct zcc_result_meta {
    char magic[8];
    char key[HEXLEN];
    uint8_t flags;
    uint8_t reserved[7];
    uint64_t lengths[3];
    uint8_t hashes[3][SHA3_256_OUTPUT_SIZE];
};

static void result_hash(const struct buf *b, uint8_t out[SHA3_256_OUTPUT_SIZE])
{
    struct sha3_256_ctx h;
    sha3_256_init(&h);
    sha3_256_write(&h, b->p, b->len);
    sha3_256_finalize(&h, out);
}

static bool result_matches(const struct buf *b, const struct zcc_result_meta *m,
                           size_t slot)
{
    uint8_t digest[SHA3_256_OUTPUT_SIZE];
    result_hash(b, digest);
    return (uint64_t)b->len == m->lengths[slot] &&
           memcmp(digest, m->hashes[slot], sizeof digest) == 0;
}

static bool result_read_meta(const struct cache *c, const char *ckey,
                             const struct plan *pl,
                             struct zcc_result_meta *meta,
                             const char **reason)
{
    char path[PATH_MAX];
    struct buf b = { 0 };
    entry_path(c, "obj", ckey, ".meta", path);
    bool read_ok = read_file(path, &b);
    bool ok = read_ok && b.len == sizeof *meta;
    *reason = "meta-invalid";
    if (!read_ok) {
        struct stat st;
        *reason = stat(path, &st) != 0 && errno == ENOENT
            ? "meta-missing" : "meta-unavailable";
    }
    if (ok) {
        memcpy(meta, b.p, sizeof *meta);
        ok = memcmp(meta->magic, ZCC_RESULT_MAGIC, sizeof meta->magic) == 0 &&
             memcmp(meta->key, ckey, HEXLEN) == 0 &&
             (meta->flags & ~(ZCC_RESULT_DEP | ZCC_RESULT_ERR)) == 0 &&
             (!pl->want_dep || (meta->flags & ZCC_RESULT_DEP));
    }
    buf_free(&b);
    return ok;
}

static bool result_read_artifact(const struct cache *c, const char *ckey,
                                 const char *ext,
                                 const struct zcc_result_meta *meta,
                                 size_t slot, struct buf *out,
                                 struct stat *st, const char **reason)
{
    static const char *const unavailable[] = {
        "bin-unavailable", "dep-unavailable", "err-unavailable"
    };
    static const char *const integrity[] = {
        "bin-integrity", "dep-integrity", "err-integrity"
    };
    char path[PATH_MAX];
    entry_path(c, "obj", ckey, ext, path);
    *reason = unavailable[slot];
    if (stat(path, st) != 0 || !S_ISREG(st->st_mode) || !read_file(path, out))
        return false;
    *reason = integrity[slot];
    return result_matches(out, meta, slot);
}

static void log_lookup_failure(const char *reason, const char *ckey,
                               const struct plan *pl)
{
    if (!reason)
        return;
    char detail[128];
    snprintf(detail, sizeof detail, "reason=%s key=%.64s", reason, ckey);
    logline("LOOKUP", detail, pl);
}

static bool serve(const struct cache *c, const char *ckey,
                  const struct plan *pl)
{
    char art[PATH_MAX];
    struct buf bin = { 0 }, dep = { 0 }, err = { 0 };
    struct zcc_result_meta meta;
    struct stat bin_st, dep_st, err_st;
    const char *reason = NULL;
    bool ok = false;
    if (!result_read_meta(c, ckey, pl, &meta, &reason))
        goto done;
    entry_path(c, "obj", ckey, ".bin", art);
    if (!result_read_artifact(c, ckey, ".bin", &meta, 0, &bin, &bin_st, &reason))
        goto done;
    if ((meta.flags & ZCC_RESULT_DEP) &&
        !result_read_artifact(c, ckey, ".dep", &meta, 1, &dep, &dep_st, &reason))
        goto done;
    if ((meta.flags & ZCC_RESULT_ERR) &&
        !result_read_artifact(c, ckey, ".err", &meta, 2, &err, &err_st, &reason))
        goto done;
    /* Verify all stored bytes before writing either output. The verified
     * buffers are also the bytes copied out, closing a cache-file swap race. */
    if (pl->dep_path && (meta.flags & ZCC_RESULT_DEP)) {
        if (pl->mt_path && pl->mt_path[0])
            (void)buf_replace_prefix(&dep, ZCC_MT_PLACEHOLDER, pl->mt_path);
        reason = "dep-restore";
        if (!write_buf_dest(&dep, pl->dep_path, dep_st.st_mode & 07777u))
            goto done;
    }
    reason = "bin-restore";
    if (!write_buf_dest(&bin, pl->out_path, bin_st.st_mode & 07777u))
        goto done;
    if (err.len > 0)
        (void)!write(STDERR_FILENO, err.p, err.len);
    touch_if_stale(art, bin_st.st_mtime);
    ok = true;
done:
    if (!ok)
        log_lookup_failure(reason, ckey, pl);
    buf_free(&bin);
    buf_free(&dep);
    buf_free(&err);
    return ok;
}

static bool store_sidecar(const struct cache *c, const char *ckey,
                          const char *dir, const char *ext,
                          const char *source, const struct plan *pl,
                          struct zcc_result_meta *meta, size_t slot,
                          struct buf *data, long long *added)
{
    char dst[PATH_MAX];
    if (!read_file(source, data))
        return false;
    if (slot == 1u && pl->mt_path && pl->mt_path[0] &&
        !buf_replace_prefix(data, pl->mt_path, ZCC_MT_PLACEHOLDER))
        return false;
    meta->flags |= slot == 1u ? ZCC_RESULT_DEP : ZCC_RESULT_ERR;
    meta->lengths[slot] = (uint64_t)data->len;
    result_hash(data, meta->hashes[slot]);
    entry_path(c, "obj", ckey, ext, dst);
    if (!store_atomic(dir, dst, data->p, data->len, 0600))
        return false;
    *added += (long long)data->len;
    return true;
}

static void store(const struct cache *c, const char *ckey,
                  const struct plan *pl, const char *errfile)
{
    char dir[PATH_MAX], dst[PATH_MAX];
    struct buf b = { 0 }, d = { 0 }, e = { 0 };
    struct zcc_result_meta meta = { 0 };
    struct stat st;
    if (!entry_dir(c, "obj", ckey, dir))
        return;
    if (stat(pl->out_path, &st) != 0 || !read_file(pl->out_path, &b)) {
        buf_free(&b);
        return;
    }
    memcpy(meta.magic, ZCC_RESULT_MAGIC, sizeof meta.magic);
    memcpy(meta.key, ckey, HEXLEN);
    meta.lengths[0] = (uint64_t)b.len;
    result_hash(&b, meta.hashes[0]);

    /* THE OBJECT IS PUBLISHED LAST. serve() decides an entry exists by the
     * presence of the .bin, so writing it first made every sibling a window:
     * a build interrupted in between — Ctrl-C on a -j32 make is the ordinary
     * case, not the exotic one — left a .bin with no .dep, and the next build
     * took it as a hit and restored no depfile. Sidecars first, artifact
     * last, and an interrupted store leaves nothing servable. evict() deletes
     * in the mirror order for the same reason.
     *
     * Sidecars orphaned by a .bin that then failed to store are deliberately
     * NOT cleaned up here: they are a well-formed entry with no artifact, the
     * bound below ages them out like anything else, and an extra unlink on an
     * error path is one more way to interfere with a concurrent store of the
     * same key. */
    long long added = 0;
    if (pl->dep_path && is_regular(pl->dep_path)) {
        if (!store_sidecar(c, ckey, dir, ".dep", pl->dep_path, pl,
                           &meta, 1u, &d, &added))
            goto done;
    } else if (pl->want_dep) {
        goto done;
    }
    if (errfile && !store_sidecar(c, ckey, dir, ".err", errfile, pl,
                                  &meta, 2u, &e, &added))
        goto done;
    entry_path(c, "obj", ckey, ".meta", dst);
    if (!store_atomic(dir, dst, (const unsigned char *)&meta,
                      sizeof meta, 0600))
        goto done;
    added += (long long)sizeof meta;
    entry_path(c, "obj", ckey, ".bin", dst);
    if (store_atomic(dir, dst, b.p, b.len, st.st_mode & 07777u))
        added += (long long)b.len;
done:
    buf_free(&b);
    buf_free(&d);
    buf_free(&e);
    grow(c, added);
}

/* ── level-1 manifest ────────────────────────────────────────────────── */

/* probe key -> { content key, the exact file set that compile read }.
 * A counted, digested manifest refuses a truncated or partially captured set.
 * Serving from level 1 requires every recorded file's bytes to match. */

static bool manifest_append_dep(struct buf *b, const char *path)
{
    struct stat st;
    char filehash[HEXLEN + 1u], line[PATH_MAX + 128];
    if (strchr(path, '\n') || strchr(path, '\r') ||
        stat(path, &st) != 0 || !S_ISREG(st.st_mode) ||
        !file_hex(path, filehash))
        return false;
    int n = snprintf(line, sizeof line, "%lld %lld %lld %llu %s %s\n",
                     (long long)st.st_size, (long long)st.st_mtim.tv_sec,
                     (long long)st.st_mtim.tv_nsec,
                     (unsigned long long)st.st_ino, filehash, path);
    return n >= 0 && (size_t)n < sizeof line && buf_add(b, line, (size_t)n);
}

static bool manifest_append_checksum(struct buf *b)
{
    struct sha3_256_ctx h;
    unsigned char digest[SHA3_256_OUTPUT_SIZE];
    char hex[HEXLEN + 1u], line[HEXLEN + 7u];
    sha3_256_init(&h);
    sha3_256_write(&h, b->p, b->len);
    sha3_256_finalize(&h, digest);
    hex_of(digest, hex);
    int n = snprintf(line, sizeof line, "sha3=%s\n", hex);
    return n >= 0 && (size_t)n < sizeof line && buf_add(b, line, (size_t)n);
}

static bool manifest_write(const struct cache *c, const char *pkey,
                           const char *ckey, const struct deps *d)
{
    char dir[PATH_MAX], dst[PATH_MAX];
    if (d->failed || d->n > 100000u || !entry_dir(c, "man", pkey, dir))
        return false;
    struct buf b = { 0 };
    char line[PATH_MAX + 128];
    int n = snprintf(line, sizeof line, "zcc.manifest.v3\n%s\n%zu\n",
                     ckey, d->n);
    if (n < 0 || (size_t)n >= sizeof line ||
        !buf_add(&b, line, (size_t)n)) {
        buf_free(&b);
        return false;
    }
    for (size_t i = 0; i < d->n; i++) {
        if (!manifest_append_dep(&b, d->path[i])) {
            buf_free(&b);
            return false;
        }
    }
    if (!manifest_append_checksum(&b)) {
        buf_free(&b);
        return false;
    }
    entry_path(c, "man", pkey, "", dst);
    bool ok = store_atomic(dir, dst, b.p, b.len, 0600);
    if (ok)
        grow(c, (long long)b.len);
    buf_free(&b);
    return ok;
}

static bool manifest_payload_valid(const struct buf *b)
{
    if (b->len < 72u || b->p[b->len - 1u] != '\n')
        return false;
    size_t start = b->len - 1u;
    while (start > 0u && b->p[start - 1u] != '\n')
        start--;
    if (b->len - start != 70u || memcmp(b->p + start, "sha3=", 5u) != 0)
        return false;
    struct sha3_256_ctx h;
    unsigned char digest[SHA3_256_OUTPUT_SIZE];
    char hex[HEXLEN + 1u];
    sha3_256_init(&h);
    sha3_256_write(&h, b->p, start);
    sha3_256_finalize(&h, digest);
    hex_of(digest, hex);
    return memcmp(b->p + start + 5u, hex, HEXLEN) == 0;
}

static bool manifest_dep_matches(char *line)
{
    long long size = 0, sec = 0, nsec = 0;
    unsigned long long ino = 0;
    int off = 0;
    if (sscanf(line, "%lld %lld %lld %llu %n", &size, &sec, &nsec, &ino,
               &off) != 4 || off <= 0 || !line[off] ||
        strlen(line + off) < HEXLEN + 2u || line[off + HEXLEN] != ' ')
        return false;
    const char *path = line + off + HEXLEN + 1u;
    char filehash[HEXLEN + 1u];
    struct stat st;
    return file_hex(path, filehash) &&
           memcmp(line + off, filehash, HEXLEN) == 0 &&
           stat(path, &st) == 0 &&
           (long long)st.st_size == size &&
           (long long)st.st_mtim.tv_sec == sec &&
           (long long)st.st_mtim.tv_nsec == nsec &&
           (unsigned long long)st.st_ino == ino;
}

static bool manifest_count(const char *line, unsigned long long *out)
{
    if (!line || !line[0])
        return false;
    char *end = NULL;
    errno = 0;
    *out = strtoull(line, &end, 10);
    return errno == 0 && end && *end == '\0' && *out <= 100000u;
}

static bool manifest_text_matches(char *text, char ckey[HEXLEN + 1u])
{
    char *save = NULL;
    char *line = strtok_r(text, "\n", &save);
    if (!line || strcmp(line, "zcc.manifest.v3") != 0)
        return false;
    line = strtok_r(NULL, "\n", &save);
    if (!line || strlen(line) != HEXLEN)
        return false;
    memcpy(ckey, line, HEXLEN + 1u);
    line = strtok_r(NULL, "\n", &save);
    unsigned long long expected = 0;
    if (!manifest_count(line, &expected))
        return false;
    for (unsigned long long i = 0; i < expected; i++) {
        line = strtok_r(NULL, "\n", &save);
        if (!line || !manifest_dep_matches(line))
            return false;
    }
    line = strtok_r(NULL, "\n", &save);
    return line && strncmp(line, "sha3=", 5u) == 0 &&
           strlen(line) == 5u + HEXLEN && !strtok_r(NULL, "\n", &save);
}

/* Any doubt about the manifest or its files is a miss. */
static bool manifest_verify(const struct cache *c, const char *pkey,
                            char ckey[HEXLEN + 1u])
{
    char p[PATH_MAX];
    struct buf b = { 0 };
    struct stat mst;
    entry_path(c, "man", pkey, "", p);
    if (stat(p, &mst) != 0 || !read_file(p, &b)) {
        buf_free(&b);
        return false;
    }
    bool ok = false;
    if (manifest_payload_valid(&b)) {
        char *text = zcl_malloc(b.len + 1u, "zcc manifest text");
        if (text) {
            memcpy(text, b.p, b.len);
            text[b.len] = '\0';
            ok = manifest_text_matches(text, ckey);
            free(text);
        }
    }
    buf_free(&b);
    if (ok)
        touch_if_stale(p, mst.st_mtime);
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
        /* Disk, in the same units as the ceiling — see ZCC_DISK. Directories
         * count too, or the reported size does not match `du` and the number
         * beside the ceiling means something slightly different from it. */
        total += ZCC_DISK(st);
        if (S_ISDIR(st.st_mode))
            total += tree_bytes(sub);
    }
    closedir(d);
    return total;
}

/* The manual trim. Same eviction the cache performs on itself — see "THE
 * BOUND" — but it waits for the lock instead of stepping aside, because an
 * operator who typed the command is owed the trim, and it says what it did. */
static int cmd_trim(struct cache *c, long long max_mb)
{
    if (max_mb < 0) {
        fprintf(stderr, "zcc: a negative ceiling is not a ceiling\n");
        return 2;
    }
    max_mb = clamp_mb(max_mb);
    int fd = trim_lock(c, true);
    long long have = 0;
    long long freed = trim_to(c, max_mb * 1024LL * 1024LL, &have);
    if (fd >= 0) {
        (void)futimens(fd, NULL);
        reset_growth(c);
        close(fd);
    }
    if (freed < 0) {
        fprintf(stderr, "zcc: could not scan %s\n", c->root);
        return 1;
    }
    printf("zcc: %lld MB held, %lld MB ceiling, %lld MB freed\n",
           have / (1024 * 1024), max_mb, freed / (1024 * 1024));
    if (freed == 0 && have > max_mb * 1024LL * 1024LL)
        printf("zcc: this ceiling cannot be reached by evicting entries — the "
               "directory skeleton alone exceeds it; nothing was deleted\n");
    return 0;
}

static int cmd_stats(struct cache *c)
{
    long hit = counter(c, "hit"), miss = counter(c, "miss");
    long bypass = counter(c, "bypass"), total = hit + miss;
    long unkeyable = counter(c, "unkeyable");
    long long max_mb = ceiling_mb();
    printf("zcc cache      %s\n", c->root);
    printf("  size         %lld MB\n", tree_bytes(c->root) / (1024 * 1024));
    /* The ceiling is not decoration: it is what this cache will hold itself
     * to without anyone running a make target, so it belongs next to the
     * size. "grown" is the trigger — a trim runs once it passes an eighth of
     * the ceiling. */
    if (max_mb > 0)
        printf("  ceiling      %lld MB  (ZCC_MAX_MB, self-enforced)\n", max_mb);
    else
        printf("  ceiling      off  (ZCC_MAX_MB=0)\n");
    printf("  grown        %lld MB since the last trim\n",
           (long long)counter(c, "grown") * ZCC_GROWTH_UNIT / (1024 * 1024));
    printf("  hits         %ld\n", hit);
    printf("  provenance   NON-AUTHORITATIVE DEV reuse (no isolated signer)\n");
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
    int n = snprintf(line, sizeof line, "%-8s %-28s %s%s\n", disposition,
                     detail ? detail : "-",
                     strcmp(disposition, "HIT") == 0
                         ? "NON-AUTHORITATIVE DEV " : "",
                     pl->out_path ? pl->out_path : "<none>");
    if (n > 0)
        (void)!write(fd, line, (size_t)n > sizeof line ? sizeof line : (size_t)n);
    close(fd);
}

/* ── native compile-epoch object publication ────────────────────────── */

struct epoch_authority {
    struct stat stamp;
    struct stat epoch_stamp;
    struct stat object_root_stamp;
    struct stat admission_dir_stamp;
    int epoch_fd;
    int object_root_fd;
    int admission_dir_fd;
    int session_parent_fd;
    int session_fd;
    char epoch_path[PATH_MAX];
    char object_root_path[PATH_MAX];
    char admission_lock_name[NAME_MAX + 1u];
    char session_leaf[NAME_MAX + 1u];
    char unverified[512];
    size_t unverified_len;
};

struct epoch_artifacts {
    struct stat parent_stamp;
    struct stat staging_stamp;
    int parent_fd;
    int staging_fd;
    int object_fd;
    int dep_fd;
    int note_fd;
    char parent_relative[PATH_MAX];
    char parent_path[PATH_MAX];
    char staging_name[NAME_MAX + 1u];
    char object_name[NAME_MAX + 1u];
    char dep_name[NAME_MAX + 1u];
    char note_name[NAME_MAX + 1u];
    char record_name[NAME_MAX + 1u];
    char lock_name[NAME_MAX + 1u];
    char depfile[PATH_MAX];
    char object[PATH_MAX];
    char note[PATH_MAX];
    char note_option[PATH_MAX + 32u];
};

static int epoch_fail(const char *message)
{
    fprintf(stderr, "zcc --epoch-object: %s\n", message);
    return 2;
}

static bool epoch_is_sha256(const char *value)
{
    if (!value || strlen(value) != 64u)
        return false;
    for (size_t i = 0; i < 64u; i++) {
        if (!((value[i] >= '0' && value[i] <= '9') ||
              (value[i] >= 'a' && value[i] <= 'f')))
            return false;
    }
    return true;
}

static bool epoch_same_stamp(const struct stat *a, const struct stat *b)
{
    bool same = a->st_dev == b->st_dev && a->st_ino == b->st_ino &&
                a->st_size == b->st_size;
#if defined(__APPLE__)
    return same && a->st_mtimespec.tv_sec == b->st_mtimespec.tv_sec &&
           a->st_mtimespec.tv_nsec == b->st_mtimespec.tv_nsec &&
           a->st_ctimespec.tv_sec == b->st_ctimespec.tv_sec &&
           a->st_ctimespec.tv_nsec == b->st_ctimespec.tv_nsec;
#else
    return same && a->st_mtim.tv_sec == b->st_mtim.tv_sec &&
           a->st_mtim.tv_nsec == b->st_mtim.tv_nsec &&
           a->st_ctim.tv_sec == b->st_ctim.tv_sec &&
           a->st_ctim.tv_nsec == b->st_ctim.tv_nsec;
#endif
}

static bool epoch_same_identity(const struct stat *a, const struct stat *b)
{
    return a->st_dev == b->st_dev && a->st_ino == b->st_ino;
}

static bool epoch_session_bytes(const struct buf *text, const char *source_id,
                                const char *complete, const char *mutation,
                                const char *compiler_id, const char *epoch)
{
    char fixed[512];
    int n = snprintf(fixed, sizeof fixed,
                     "schema=zcl.build_epoch_session.v1\n"
                     "source_id=%s\ncomplete=%s\nmutation=%s\n"
                     "compiler_id=%s\nepoch=%s\nprofile=",
                     source_id, complete, mutation, compiler_id, epoch);
    if (n <= 0 || n >= (int)sizeof fixed || text->len <= (size_t)n ||
        memcmp(text->p, fixed, (size_t)n) != 0)
        return false;
    const unsigned char *profile = text->p + (size_t)n;
    const unsigned char *newline = memchr(profile, '\n',
                                           text->len - (size_t)n);
    if (!newline || newline == profile)
        return false;
    static const char flags[] = "flags_sha256=";
    const unsigned char *value = newline + 1u;
    size_t remaining = text->len - (size_t)(value - text->p);
    if (remaining != sizeof flags - 1u + 64u + 1u ||
        memcmp(value, flags, sizeof flags - 1u) != 0 ||
        value[remaining - 1u] != '\n')
        return false;
    char digest[65];
    memcpy(digest, value + sizeof flags - 1u, 64u);
    digest[64] = '\0';
    return epoch_is_sha256(digest);
}

static bool epoch_read_fd(int fd, struct buf *text, struct stat *stamp)
{
    struct stat before;
    bool ok = lseek(fd, 0, SEEK_SET) == 0 && fstat(fd, &before) == 0 &&
              S_ISREG(before.st_mode);
    unsigned char chunk[4096];
    while (ok) {
        ssize_t n = read(fd, chunk, sizeof chunk);
        if (n < 0 && errno == EINTR)
            continue;
        if (n < 0) {
            ok = false;
            break;
        }
        if (n == 0)
            break;
        ok = text->len + (size_t)n <= 65536u &&
             buf_add(text, chunk, (size_t)n);
    }
    struct stat after;
    ok = ok && fstat(fd, &after) == 0 && epoch_same_stamp(&before, &after);
    if (ok) {
        *stamp = after;
        return true;
    }
    return false;
}

static bool epoch_component(const char *part, size_t length,
                            char name[NAME_MAX + 1u])
{
    if (length == 0u || length > NAME_MAX ||
        (length == 1u && part[0] == '.') ||
        (length == 2u && part[0] == '.' && part[1] == '.'))
        return false;
    memcpy(name, part, length);
    name[length] = '\0';
    return true;
}

static int epoch_dup_cloexec(int fd)
{
    int copy = dup(fd);
    if (copy >= 0 && fcntl(copy, F_SETFD, FD_CLOEXEC) != 0) {
        close(copy);
        return -1;
    }
    return copy;
}

static int epoch_open_relative_dir(int root_fd, const char *relative,
                                   bool create)
{
    int current = epoch_dup_cloexec(root_fd);
    if (current < 0)
        return -1;
    const char *part = relative;
    while (*part) {
        const char *slash = strchr(part, '/');
        size_t length = slash ? (size_t)(slash - part) : strlen(part);
        char name[NAME_MAX + 1u];
        if (!epoch_component(part, length, name)) {
            close(current);
            errno = EINVAL;
            return -1;
        }
        int next = openat(current, name, O_RDONLY | O_DIRECTORY | O_NOFOLLOW |
                                          O_CLOEXEC);
        if (next < 0 && create && errno == ENOENT) {
            if (mkdirat(current, name, 0700) != 0 && errno != EEXIST) {
                close(current);
                return -1;
            }
            next = openat(current, name, O_RDONLY | O_DIRECTORY | O_NOFOLLOW |
                                          O_CLOEXEC);
        }
        close(current);
        if (next < 0)
            return -1;
        current = next;
        if (!slash)
            break;
        part = slash + 1u;
        if (!*part) {
            close(current);
            errno = EINVAL;
            return -1;
        }
    }
    return current;
}

static int epoch_open_path_dir(const char *path)
{
    int root = open(path[0] == '/' ? "/" : ".",
                    O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (root < 0)
        return -1;
    const char *relative = path + (path[0] == '/');
    int result = epoch_open_relative_dir(root, relative, false);
    close(root);
    return result;
}

static bool epoch_path_root(const char *path, const char *epoch,
                            size_t *root_len)
{
    char needle[80];
    if (snprintf(needle, sizeof needle, "epochs/%s/", epoch) >=
        (int)sizeof needle)
        return false;
    const char *match = strstr(path, needle);
    while (match && match != path && match[-1] != '/')
        match = strstr(match + 1, needle);
    if (!match)
        return false;
    *root_len = (size_t)(match - path) + strlen(needle) - 1u;
    return path[*root_len] == '/';
}

static bool epoch_path_parts(const char *path)
{
    const char *part = path + (path[0] == '/');
    while (*part) {
        const char *slash = strchr(part, '/');
        size_t length = slash ? (size_t)(slash - part) : strlen(part);
        char name[NAME_MAX + 1u];
        if (!epoch_component(part, length, name))
            return false;
        if (!slash)
            return true;
        part = slash + 1u;
    }
    return false;
}

static bool epoch_paths_contained(const char *output, const char *session,
                                  const char *epoch)
{
    size_t output_root = 0, session_root = 0;
    return epoch_path_root(output, epoch, &output_root) &&
           epoch_path_root(session, epoch, &session_root) &&
           output_root == session_root &&
           memcmp(output, session, output_root) == 0 &&
           epoch_path_parts(output) && epoch_path_parts(session);
}

static bool epoch_split_output(const char *output, char dir[PATH_MAX],
                               const char **base)
{
    if (snprintf(dir, PATH_MAX, "%s", output) >= PATH_MAX)
        return false;
    char *slash = strrchr(dir, '/');
    if (!slash) {
        *base = output;
        snprintf(dir, PATH_MAX, ".");
        return output[0] != '\0';
    }
    *base = strrchr(output, '/') + 1;
    if (!(*base)[0])
        return false;
    if (slash == dir)
        slash[1] = '\0';
    else
        *slash = '\0';
    return true;
}

static bool epoch_split_relative(const char *path, char parent[PATH_MAX],
                                 char leaf[NAME_MAX + 1u])
{
    if (snprintf(parent, PATH_MAX, "%s", path) >= PATH_MAX)
        return false;
    char *slash = strrchr(parent, '/');
    const char *base = slash ? slash + 1u : parent;
    if (!epoch_component(base, strlen(base), leaf))
        return false;
    if (slash)
        *slash = '\0';
    else
        parent[0] = '\0';
    return true;
}

static void epoch_authority_close(struct epoch_authority *authority)
{
    if (authority->session_fd >= 0)
        close(authority->session_fd);
    if (authority->session_parent_fd >= 0)
        close(authority->session_parent_fd);
    if (authority->epoch_fd >= 0)
        close(authority->epoch_fd);
    if (authority->admission_dir_fd >= 0)
        close(authority->admission_dir_fd);
    if (authority->object_root_fd >= 0)
        close(authority->object_root_fd);
    authority->session_fd = -1;
    authority->session_parent_fd = authority->epoch_fd = -1;
    authority->admission_dir_fd = authority->object_root_fd = -1;
}

static bool epoch_authority_open(const char *output, const char *session,
                                 const char *source_id, const char *complete,
                                 const char *mutation, const char *compiler_id,
                                 const char *epoch,
                                 struct epoch_authority *authority)
{
    size_t root_len = 0;
    memset(authority, 0, sizeof *authority);
    authority->epoch_fd = authority->session_parent_fd = -1;
    authority->session_fd = authority->object_root_fd = -1;
    authority->admission_dir_fd = -1;
    int marker_len = snprintf(
        authority->unverified, sizeof authority->unverified,
        "schema=zcl.build_epoch_unverified.v1\n"
        "source_id=%s\nmutation=%s\ncompiler_id=%s\nepoch=%s\n",
        source_id, mutation, compiler_id, epoch);
    if (marker_len <= 0 || marker_len >= (int)sizeof authority->unverified)
        return false;
    authority->unverified_len = (size_t)marker_len;
    if (!epoch_path_root(output, epoch, &root_len) || root_len >= PATH_MAX)
        return false;
    memcpy(authority->epoch_path, output, root_len);
    authority->epoch_path[root_len] = '\0';
    size_t epoch_suffix_len = strlen(epoch) + strlen("/epochs/");
    if (root_len < epoch_suffix_len)
        return false;
    size_t object_root_len = root_len - epoch_suffix_len;
    if (object_root_len == 0u) {
        if (output[0] == '/')
            memcpy(authority->object_root_path, "/", 2u);
        else
            memcpy(authority->object_root_path, ".", 2u);
    } else {
        memcpy(authority->object_root_path, output, object_root_len);
        authority->object_root_path[object_root_len] = '\0';
    }
    authority->object_root_fd = epoch_open_path_dir(
        authority->object_root_path);
    char epoch_relative[NAME_MAX + 9u];
    if (snprintf(epoch_relative, sizeof epoch_relative, "epochs/%s", epoch) >=
        (int)sizeof epoch_relative || authority->object_root_fd < 0)
        goto fail;
    authority->epoch_fd = epoch_open_relative_dir(
        authority->object_root_fd, epoch_relative, false);
    authority->admission_dir_fd = epoch_open_relative_dir(
        authority->object_root_fd, ".epoch-admission", true);
    if (authority->epoch_fd < 0 || authority->admission_dir_fd < 0 ||
        fstat(authority->object_root_fd, &authority->object_root_stamp) != 0 ||
        fstat(authority->epoch_fd, &authority->epoch_stamp) != 0 ||
        fstat(authority->admission_dir_fd,
              &authority->admission_dir_stamp) != 0)
        goto fail;
    if (snprintf(authority->admission_lock_name,
                 sizeof authority->admission_lock_name, "%s.lock", epoch) >=
        (int)sizeof authority->admission_lock_name)
        goto fail;
    const char *session_relative = session + root_len + 1u;
    char session_parent[PATH_MAX];
    if (!epoch_split_relative(session_relative, session_parent,
                              authority->session_leaf))
        goto fail;
    authority->session_parent_fd = epoch_open_relative_dir(
        authority->epoch_fd, session_parent, false);
    if (authority->session_parent_fd < 0)
        goto fail;
    authority->session_fd = openat(authority->session_parent_fd,
                                    authority->session_leaf,
                                    O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
    if (authority->session_fd < 0)
        goto fail;
    struct buf text = { 0 };
    bool ok = epoch_read_fd(authority->session_fd, &text, &authority->stamp) &&
              text.len != 0u && memchr(text.p, '\0', text.len) == NULL &&
              epoch_session_bytes(&text, source_id, complete, mutation,
                                  compiler_id, epoch);
    buf_free(&text);
    if (ok)
        return true;
fail:
    epoch_authority_close(authority);
    return false;
}

static bool epoch_lookup_same(int parent_fd, const char *name,
                              const struct stat *expected)
{
    struct stat now;
    return fstatat(parent_fd, name, &now, AT_SYMLINK_NOFOLLOW) == 0 &&
           S_ISREG(now.st_mode) && epoch_same_stamp(expected, &now);
}

static bool epoch_authority_current(const struct epoch_authority *authority)
{
    struct stat session_now, epoch_now, object_root_now, admission_now;
    int object_root = epoch_open_path_dir(authority->object_root_path);
    int root = epoch_open_path_dir(authority->epoch_path);
    int admission = epoch_open_relative_dir(authority->object_root_fd,
                                            ".epoch-admission", false);
    bool root_ok = object_root >= 0 &&
                   fstat(object_root, &object_root_now) == 0 &&
                   epoch_same_identity(&authority->object_root_stamp,
                                       &object_root_now) &&
                   root >= 0 && fstat(root, &epoch_now) == 0 &&
                   epoch_same_identity(&authority->epoch_stamp, &epoch_now) &&
                   admission >= 0 && fstat(admission, &admission_now) == 0 &&
                   epoch_same_identity(&authority->admission_dir_stamp,
                                       &admission_now);
    if (object_root >= 0)
        close(object_root);
    if (root >= 0)
        close(root);
    if (admission >= 0)
        close(admission);
    return root_ok && fstat(authority->session_fd, &session_now) == 0 &&
           S_ISREG(session_now.st_mode) &&
           epoch_same_stamp(&authority->stamp, &session_now) &&
           epoch_lookup_same(authority->session_parent_fd,
                             authority->session_leaf, &authority->stamp);
}

static bool epoch_names(const char *base, struct epoch_artifacts *artifacts)
{
    char stem[NAME_MAX + 1u];
    if (snprintf(stem, sizeof stem, "%s", base) >= (int)sizeof stem)
        return false;
    size_t n = strlen(stem);
    if (n >= 2u && strcmp(stem + n - 2u, ".o") == 0)
        stem[n - 2u] = '\0';
    return snprintf(artifacts->object_name, sizeof artifacts->object_name,
                    "%s", base) < (int)sizeof artifacts->object_name &&
           snprintf(artifacts->dep_name, sizeof artifacts->dep_name, "%s.d",
                    stem) < (int)sizeof artifacts->dep_name &&
           snprintf(artifacts->note_name, sizeof artifacts->note_name,
                    "%s.gcno", stem) < (int)sizeof artifacts->note_name &&
           snprintf(artifacts->record_name, sizeof artifacts->record_name,
                    "%s.gcno-path", stem) <
               (int)sizeof artifacts->record_name &&
           snprintf(artifacts->lock_name, sizeof artifacts->lock_name,
                    "%s.lock", base) < (int)sizeof artifacts->lock_name;
}

static bool epoch_artifact_path(const struct epoch_artifacts *artifacts,
                                const char *name, char path[PATH_MAX])
{
#if defined(__APPLE__)
    int fd = strcmp(name, artifacts->object_name) == 0
                 ? artifacts->object_fd
                 : strcmp(name, artifacts->dep_name) == 0
                       ? artifacts->dep_fd
                       : artifacts->note_fd;
    return fd >= 0 && snprintf(path, PATH_MAX, "/dev/fd/%d", fd) < PATH_MAX;
#else
    return platform_dirfd_child_path(path, PATH_MAX, artifacts->staging_fd,
                                     name);
#endif
}

static bool epoch_make_staging(struct epoch_artifacts *artifacts)
{
    for (unsigned int attempt = 0; attempt < 128u; attempt++) {
        if (snprintf(artifacts->staging_name, sizeof artifacts->staging_name,
                     ".zcc-epoch.%ld.%u", (long)getpid(), attempt) >=
            (int)sizeof artifacts->staging_name)
            return false;
        if (mkdirat(artifacts->parent_fd, artifacts->staging_name, 0700) == 0)
            break;
        if (errno != EEXIST || attempt == 127u)
            return false;
    }
    artifacts->staging_fd = openat(artifacts->parent_fd,
                                    artifacts->staging_name,
                                    O_RDONLY | O_DIRECTORY | O_NOFOLLOW);
    return artifacts->staging_fd >= 0 &&
           fstat(artifacts->staging_fd, &artifacts->staging_stamp) == 0;
}

static bool epoch_stage_prepare(const char *output,
                                const struct epoch_authority *authority,
                                struct epoch_artifacts *artifacts)
{
    memset(artifacts, 0, sizeof *artifacts);
    artifacts->parent_fd = artifacts->staging_fd = -1;
    artifacts->object_fd = artifacts->dep_fd = artifacts->note_fd = -1;
    size_t root_len = strlen(authority->epoch_path);
    const char *relative = output + root_len + 1u;
    char base[NAME_MAX + 1u];
    if (!epoch_split_relative(relative, artifacts->parent_relative, base) ||
        !epoch_names(base, artifacts))
        return false;
    artifacts->parent_fd = epoch_open_relative_dir(
        authority->epoch_fd, artifacts->parent_relative, true);
    if (artifacts->parent_fd < 0 || !epoch_make_staging(artifacts) ||
        fstat(artifacts->parent_fd, &artifacts->parent_stamp) != 0)
        return false;
#if defined(__APPLE__)
    artifacts->object_fd = openat(artifacts->staging_fd,
                                  artifacts->object_name,
                                  O_RDWR | O_CREAT | O_EXCL, 0600);
    artifacts->dep_fd = openat(artifacts->staging_fd, artifacts->dep_name,
                               O_RDWR | O_CREAT | O_EXCL, 0600);
    artifacts->note_fd = openat(artifacts->staging_fd, artifacts->note_name,
                                O_RDWR | O_CREAT | O_EXCL, 0600);
    if (artifacts->object_fd < 0 || artifacts->dep_fd < 0 ||
        artifacts->note_fd < 0)
        return false;
#endif
    const char *ignored_base = NULL;
    if (!epoch_split_output(output, artifacts->parent_path, &ignored_base) ||
        !epoch_artifact_path(artifacts, artifacts->dep_name,
                             artifacts->depfile) ||
        !epoch_artifact_path(artifacts, artifacts->object_name,
                             artifacts->object) ||
        !epoch_artifact_path(artifacts, artifacts->note_name,
                             artifacts->note))
        return false;
#if defined(__APPLE__)
    if (snprintf(artifacts->note_option, sizeof artifacts->note_option,
                 "-coverage-notes-file=%s", artifacts->note) >=
        (int)sizeof artifacts->note_option)
        return false;
#endif
    return true;
}

static int epoch_compiler_start(int argc, char **argv)
{
    if (argc < 14)
        return 12;
    struct stat self, wrapper;
    if (stat(argv[0], &self) != 0 || !S_ISREG(self.st_mode) ||
        stat(argv[12], &wrapper) != 0 || !S_ISREG(wrapper.st_mode))
        return 12;
    return self.st_dev == wrapper.st_dev && self.st_ino == wrapper.st_ino
               ? 13 : 12;
}

static char **epoch_compiler_argv(int argc, char **argv, const char *output,
                                  const char *source,
                                  const struct epoch_artifacts *artifacts,
                                  bool coverage,
                                  int *compiler_argc)
{
    int input_start = epoch_compiler_start(argc, argv);
    int input_argc = argc - input_start;
    char **cc = zcl_calloc((size_t)input_argc + 14u, sizeof *cc,
                           "zcc epoch compiler argv");
    if (!cc)
        return NULL;
    cc[0] = (char *)"zcc:epoch-compiler";
    for (int i = 0; i < input_argc; i++)
        cc[i + 1] = argv[i + input_start];
    int next = input_argc + 1;
    const char *extra[] = { "-MMD", "-MP", "-MF", artifacts->depfile,
                            "-MT", output, "-c", "-o", artifacts->object };
    for (size_t i = 0; i < sizeof extra / sizeof extra[0]; i++)
        cc[next++] = (char *)extra[i];
#if defined(__APPLE__)
    if (coverage) {
        cc[next++] = (char *)"-Xclang";
        cc[next++] = (char *)artifacts->note_option;
    }
#else
    (void)coverage;
#endif
    cc[next++] = (char *)source;
    *compiler_argc = next;
    return cc;
}

static bool epoch_compile_complete(int rc, bool coverage,
                                   const struct epoch_artifacts *artifacts)
{
    struct stat object_st, dep_st, note_st;
    bool object_ok = fstatat(artifacts->staging_fd, artifacts->object_name,
                             &object_st, AT_SYMLINK_NOFOLLOW) == 0 &&
                     S_ISREG(object_st.st_mode) && object_st.st_size > 0;
    bool dep_ok = fstatat(artifacts->staging_fd, artifacts->dep_name, &dep_st,
                          AT_SYMLINK_NOFOLLOW) == 0 &&
                  S_ISREG(dep_st.st_mode) && dep_st.st_size > 0;
    bool note_ok = !coverage ||
                   (fstatat(artifacts->staging_fd, artifacts->note_name,
                            &note_st, AT_SYMLINK_NOFOLLOW) == 0 &&
                    S_ISREG(note_st.st_mode) && note_st.st_size > 0);
    if (rc == 0 && object_ok && dep_ok && note_ok)
        return true;
    fprintf(stderr,
            "zcc --epoch-object: incomplete compiler output rc=%d "
            "object=%d dep=%d note=%d coverage=%d\n",
            rc, object_ok, dep_ok, note_ok, coverage);
    return false;
}

static bool epoch_stage_current(const struct epoch_authority *authority,
                                const struct epoch_artifacts *artifacts)
{
    struct stat parent_now, staging_now, named_staging;
    int parent = epoch_open_relative_dir(authority->epoch_fd,
                                         artifacts->parent_relative, false);
    bool ok = fstat(artifacts->parent_fd, &parent_now) == 0 &&
              epoch_same_identity(&artifacts->parent_stamp, &parent_now) &&
              parent >= 0 && fstat(parent, &parent_now) == 0 &&
              epoch_same_identity(&artifacts->parent_stamp, &parent_now) &&
              fstat(artifacts->staging_fd, &staging_now) == 0 &&
              epoch_same_identity(&artifacts->staging_stamp, &staging_now) &&
              fstatat(artifacts->parent_fd, artifacts->staging_name,
                      &named_staging, AT_SYMLINK_NOFOLLOW) == 0 &&
              S_ISDIR(named_staging.st_mode) &&
              epoch_same_identity(&artifacts->staging_stamp, &named_staging);
    if (parent >= 0)
        close(parent);
    return ok && epoch_authority_current(authority);
}

static int epoch_unverified_state(const struct epoch_authority *authority)
{
    struct stat st;
    if (fstatat(authority->epoch_fd, ".unverified", &st,
                AT_SYMLINK_NOFOLLOW) != 0)
        return errno == ENOENT ? 0 : -1;
    if (!S_ISREG(st.st_mode))
        return -1;
    int fd = openat(authority->epoch_fd, ".unverified",
                    O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
    struct buf text = { 0 };
    struct stat stamp;
    bool ok = fd >= 0 && epoch_read_fd(fd, &text, &stamp) &&
              text.len == authority->unverified_len &&
              memcmp(text.p, authority->unverified, text.len) == 0;
    if (fd >= 0)
        close(fd);
    buf_free(&text);
    return ok ? 1 : -1;
}

static bool epoch_write_unverified(const struct epoch_authority *authority)
{
    char temporary[NAME_MAX + 1u];
    int fd = -1;
    for (unsigned int attempt = 0; attempt < 128u; attempt++) {
        if (snprintf(temporary, sizeof temporary, ".unverified.%ld.%u",
                     (long)getpid(), attempt) >= (int)sizeof temporary)
            return false;
        fd = openat(authority->epoch_fd, temporary,
                    O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC,
                    0600);
        if (fd >= 0)
            break;
        if (errno != EEXIST)
            return false;
    }
    if (fd < 0)
        return false;
    bool ok = fd >= 0 &&
              write_all(fd, (const unsigned char *)authority->unverified,
                        authority->unverified_len) &&
              fsync(fd) == 0;
    if (fd >= 0 && close(fd) != 0)
        ok = false;
    if (ok)
        ok = renameat(authority->epoch_fd, temporary, authority->epoch_fd,
                      ".unverified") == 0;
    if (!ok)
        (void)unlinkat(authority->epoch_fd, temporary, 0);
    return ok;
}

static bool epoch_sync_unverified(const struct epoch_authority *authority)
{
    int fd = openat(authority->epoch_fd, ".unverified",
                    O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
    struct buf text = { 0 };
    struct stat stamp;
    bool ok = fd >= 0 && epoch_read_fd(fd, &text, &stamp) &&
              text.len == authority->unverified_len &&
              memcmp(text.p, authority->unverified, text.len) == 0 &&
              epoch_lookup_same(authority->epoch_fd, ".unverified", &stamp) &&
              fsync(fd) == 0;
    if (fd >= 0 && close(fd) != 0)
        ok = false;
    buf_free(&text);
    return ok;
}

static bool epoch_ensure_unverified(const struct epoch_authority *authority)
{
    int state = epoch_unverified_state(authority);
    if (state != 0)
        return state > 0;
    return epoch_write_unverified(authority) &&
           epoch_sync_unverified(authority) &&
           fsync(authority->epoch_fd) == 0;
}

static bool epoch_admission_lock_current(
    const struct epoch_authority *authority, int lock_fd)
{
    struct stat opened, named;
    return fstat(lock_fd, &opened) == 0 && S_ISREG(opened.st_mode) &&
           fstatat(authority->admission_dir_fd,
                   authority->admission_lock_name, &named,
                   AT_SYMLINK_NOFOLLOW) == 0 &&
           S_ISREG(named.st_mode) && epoch_same_identity(&opened, &named);
}

static int epoch_admission_acquire(
    const struct epoch_authority *authority,
    const struct epoch_artifacts *artifacts)
{
    int lock_fd = openat(authority->admission_dir_fd,
                         authority->admission_lock_name,
                         O_RDWR | O_CREAT | O_NOFOLLOW | O_CLOEXEC, 0600);
    struct stat lock_st;
    if (lock_fd < 0 || fstat(lock_fd, &lock_st) != 0 ||
        !S_ISREG(lock_st.st_mode) || flock(lock_fd, LOCK_EX) != 0 ||
        !epoch_admission_lock_current(authority, lock_fd) ||
        !epoch_stage_current(authority, artifacts) ||
        !epoch_ensure_unverified(authority) ||
        !epoch_stage_current(authority, artifacts)) {
        if (lock_fd >= 0)
            close(lock_fd);
        return -1;
    }
    return lock_fd;
}

static void epoch_remove_staging(struct epoch_artifacts *artifacts)
{
    if (artifacts->object_fd >= 0)
        close(artifacts->object_fd);
    if (artifacts->dep_fd >= 0)
        close(artifacts->dep_fd);
    if (artifacts->note_fd >= 0)
        close(artifacts->note_fd);
    artifacts->object_fd = artifacts->dep_fd = artifacts->note_fd = -1;
    if (artifacts->staging_fd >= 0) {
        (void)unlinkat(artifacts->staging_fd, artifacts->object_name, 0);
        (void)unlinkat(artifacts->staging_fd, artifacts->dep_name, 0);
        (void)unlinkat(artifacts->staging_fd, artifacts->note_name, 0);
        close(artifacts->staging_fd);
        artifacts->staging_fd = -1;
    }
    if (artifacts->parent_fd >= 0 && artifacts->staging_name[0])
        (void)unlinkat(artifacts->parent_fd, artifacts->staging_name,
                       AT_REMOVEDIR);
}

static void epoch_artifacts_close(struct epoch_artifacts *artifacts,
                                  bool remove_staging)
{
    if (remove_staging)
        epoch_remove_staging(artifacts);
    else {
        if (artifacts->object_fd >= 0)
            close(artifacts->object_fd);
        if (artifacts->dep_fd >= 0)
            close(artifacts->dep_fd);
        if (artifacts->note_fd >= 0)
            close(artifacts->note_fd);
        if (artifacts->staging_fd >= 0)
            close(artifacts->staging_fd);
    }
    if (artifacts->parent_fd >= 0)
        close(artifacts->parent_fd);
    artifacts->staging_fd = artifacts->parent_fd = -1;
    artifacts->object_fd = artifacts->dep_fd = artifacts->note_fd = -1;
}

static bool epoch_prepare_record(const struct epoch_artifacts *artifacts,
                                 char temporary[NAME_MAX + 1u])
{
    char line[PATH_MAX + NAME_MAX + 3u];
    if (snprintf(temporary, NAME_MAX + 1u, ".zcc-record.%ld",
                 (long)getpid()) >= NAME_MAX + 1 ||
        snprintf(line, sizeof line, "%s/%s/%s\n", artifacts->parent_path,
                 artifacts->staging_name, artifacts->note_name) >=
            (int)sizeof line)
        return false;
    int fd = openat(artifacts->parent_fd, temporary,
                    O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC,
                    0600);
    bool ok = fd >= 0 &&
              write_all(fd, (const unsigned char *)line, strlen(line));
    if (fd >= 0 && close(fd) != 0)
        ok = false;
    if (!ok)
        (void)unlinkat(artifacts->parent_fd, temporary, 0);
    return ok;
}

static bool epoch_publish(bool coverage,
                          const struct epoch_artifacts *artifacts)
{
    char record_tmp[NAME_MAX + 1u] = { 0 };
    bool ready = !coverage ||
                 (epoch_prepare_record(artifacts, record_tmp) &&
                  (unlinkat(artifacts->parent_fd, artifacts->record_name, 0) ==
                       0 ||
                   errno == ENOENT));
    bool published = ready &&
                     renameat(artifacts->staging_fd, artifacts->dep_name,
                              artifacts->parent_fd, artifacts->dep_name) == 0 &&
                     renameat(artifacts->staging_fd, artifacts->object_name,
                              artifacts->parent_fd,
                              artifacts->object_name) == 0 &&
                     (!coverage ||
                      renameat(artifacts->parent_fd, record_tmp,
                               artifacts->parent_fd,
                               artifacts->record_name) == 0);
    if (coverage && !published) {
        (void)unlinkat(artifacts->parent_fd, record_tmp, 0);
        (void)unlinkat(artifacts->parent_fd, artifacts->record_name, 0);
    }
    return published;
}

static void epoch_retract(bool coverage,
                          const struct epoch_artifacts *artifacts)
{
    (void)unlinkat(artifacts->parent_fd, artifacts->object_name, 0);
    (void)unlinkat(artifacts->parent_fd, artifacts->dep_name, 0);
    if (coverage)
        (void)unlinkat(artifacts->parent_fd, artifacts->record_name, 0);
}

static int zcc_dispatch(int argc, char **argv, bool replace_on_bypass);

/* ── Admitted verifier object (proof mode only) ─────────────────────────
 * A landing proof's driver -- the lander's pinned z23-dev, never this
 * candidate-built binary -- may admit one separate-account observation for
 * the fixed test-fast unit and name its private directory in ZCC_ADMITTED
 * (tools/dev/verify_receiver.h). zcc has no admission authority. It only
 * copies those bytes into this exact epoch target, and only when make's
 * compiler argv equals the driver's pinned-profile tokens exactly and its
 * cwd is the driver's generation root; the
 * depfile it writes is the driver's own, for this target. After make the
 * driver rehashes what was published. Every other case compiles for real
 * and logs why the admitted object was not used. */
#define ZCC_ADMITTED_SOURCE "platform/modules/base/src/result.c"
#define ZCC_ADMITTED_PREFIX "build/test-obj/epochs/"
#define ZCC_ADMITTED_SUFFIX "/platform/modules/base/src/result.o"
#define ZCC_ADMITTED_MAX (8u * 1024u * 1024u)

static void admitted_log(const char *disposition, const char *detail,
                         const char *output)
{
    const char *path = getenv("ZCC_LOG");
    if (!path || !path[0])
        return;
    int fd = open(path, O_WRONLY | O_CREAT | O_APPEND | O_CLOEXEC, 0600);
    if (fd < 0)
        return;
    char line[1024];
    int n = snprintf(line, sizeof line, "%-8s %-28s %s\n", disposition,
                     detail, output);
    if (n > 0 && (size_t)n < sizeof line)
        (void)!write(fd, line, (size_t)n);
    close(fd);
}

static bool admitted_target(const char *output)
{
    size_t a = sizeof ZCC_ADMITTED_PREFIX - 1u;
    size_t b = sizeof ZCC_ADMITTED_SUFFIX - 1u;
    if (strlen(output) != a + 64u + b ||
        strncmp(output, ZCC_ADMITTED_PREFIX, a) != 0 ||
        strcmp(output + a + 64u, ZCC_ADMITTED_SUFFIX) != 0)
        return false;
    for (size_t i = a; i < a + 64u; i++)
        if (!((output[i] >= '0' && output[i] <= '9') ||
              (output[i] >= 'a' && output[i] <= 'f')))
            return false;
    return true;
}

/* One regular, single-link member of the admitted directory, no link
 * followed, read whole and checked against its size. */
static bool admitted_read(int dir, const char *name, struct buf *out)
{
    int fd = openat(dir, name, O_RDONLY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC);
    struct stat st;
    bool ok = fd >= 0 && fstat(fd, &st) == 0 && S_ISREG(st.st_mode) &&
              st.st_nlink == 1 && st.st_size >= 0 &&
              (uint64_t)st.st_size <= ZCC_ADMITTED_MAX;
    unsigned char chunk[65536];
    while (ok) {
        ssize_t n = read(fd, chunk, sizeof chunk);
        if (n < 0 && errno == EINTR)
            continue;
        if (n <= 0) {
            ok = n == 0;
            break;
        }
        ok = buf_add(out, chunk, (size_t)n);
    }
    if (fd >= 0)
        close(fd);
    return ok && out->len == (size_t)st.st_size;
}

/* The driver's tokens are NUL-terminated, in order. */
static bool admitted_argv_equal(const struct buf *want, char **argv,
                                int from, int argc)
{
    size_t at = 0;
    for (int i = from; i < argc; i++) {
        size_t n = strlen(argv[i]) + 1u;
        if (n > want->len - at || memcmp(want->p + at, argv[i], n) != 0)
            return false;
        at += n;
    }
    return at == want->len;
}

static bool admitted_write(const char *path, const void *head, size_t head_len,
                           const struct buf *body)
{
    int fd = open(path, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC,
                  0600);
    bool ok = fd >= 0 && write_all(fd, head, head_len) &&
              write_all(fd, body->p, body->len);
    return fd >= 0 && close(fd) == 0 && ok;
}

struct admitted_bytes {
    struct buf want, object, tail, err, root;
};

/* The driver's physical generation root must be this process's cwd, so a
 * sub-make run with -C in another tree is never served. */
static bool admitted_cwd(const struct buf *root)
{
    char cwd[PATH_MAX];
    return getcwd(cwd, sizeof cwd) && root->len == strlen(cwd) &&
           memcmp(root->p, cwd, root->len) == 0;
}

static const char *admitted_load(const char *dir_path, int argc, char **argv,
                                 struct admitted_bytes *a)
{
    int dir = open(dir_path, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (dir < 0)
        return "directory_unreadable";
    bool read_ok = admitted_read(dir, "argv", &a->want) &&
                   admitted_read(dir, "object.o", &a->object) &&
                   admitted_read(dir, "depfile.tail", &a->tail) &&
                   admitted_read(dir, "stderr.bin", &a->err) &&
                   admitted_read(dir, "root", &a->root);
    close(dir);
    if (!read_ok)
        return "artifact_unreadable";
    if (a->object.len == 0 || a->tail.len == 0 || a->tail.p[0] != ':')
        return "artifact_malformed";
    if (!admitted_argv_equal(&a->want, argv, epoch_compiler_start(argc, argv),
                             argc))
        return "argv_mismatch";
    return admitted_cwd(&a->root) ? NULL : "cwd_mismatch";
}

/* NULL when the admitted object was served; "" when no admission applies to
 * this compile; otherwise the reason it was not used. */
static const char *admitted_serve(int argc, char **argv, const char *mode,
                                  const char *output, const char *source,
                                  const struct epoch_artifacts *artifacts)
{
#if defined(__linux__)
    const char *dir_path = getenv("ZCC_ADMITTED");
    if (!getenv("ZCC_VERIFIED") || !dir_path || !dir_path[0] ||
        strcmp(source, ZCC_ADMITTED_SOURCE) != 0)
        return "";
    if (strcmp(mode, "dep") != 0)
        return "coverage_mode";
    if (dir_path[0] != '/' || !admitted_target(output))
        return "target_invalid";
    struct admitted_bytes a = { 0 };
    const char *why = admitted_load(dir_path, argc, argv, &a);
    if (!why && (!admitted_write(artifacts->object, "", 0u, &a.object) ||
                 !admitted_write(artifacts->depfile, output, strlen(output),
                                 &a.tail))) {
        (void)unlink(artifacts->object);
        (void)unlink(artifacts->depfile);
        why = "write_failed";
    }
    if (!why && a.err.len > 0)
        (void)write_all(STDERR_FILENO, a.err.p, a.err.len);
    buf_free(&a.want);
    buf_free(&a.object);
    buf_free(&a.tail);
    buf_free(&a.err);
    buf_free(&a.root);
    return why;
#else
    (void)argc; (void)argv; (void)mode; (void)output; (void)source;
    (void)artifacts;
    return "";
#endif
}

static int epoch_compile_or_serve(int argc, char **argv, const char *mode,
                                  const char *output, const char *source,
                                  const struct epoch_artifacts *artifacts,
                                  int compiler_argc, char **cc)
{
    const char *why = admitted_serve(argc, argv, mode, output, source,
                                     artifacts);
    if (!why) {
        admitted_log("VERIFIED", "admitted:fixed_result.v2", output);
        return 0;
    }
    if (why[0]) {
        char detail[64];
        (void)snprintf(detail, sizeof detail, "admitted:%s", why);
        admitted_log("MISS", detail, output);
    }
    return zcc_dispatch(compiler_argc, cc, false);
}

static int epoch_compile_publish(int argc, char **argv, const char *mode,
                                 const char *output, const char *source,
                                 const struct epoch_authority *authority)
{
    struct epoch_artifacts artifacts = { 0 };
    int lock_fd = -1;
    if (!epoch_stage_prepare(output, authority, &artifacts)) {
        epoch_artifacts_close(&artifacts, true);
        return epoch_fail("could not create complete object staging paths");
    }
    bool coverage = strcmp(mode, "coverage") == 0;
    if (coverage) {
        lock_fd = openat(artifacts.parent_fd, artifacts.lock_name,
                         O_RDWR | O_CREAT | O_NOFOLLOW | O_CLOEXEC, 0600);
        if (lock_fd < 0 || flock(lock_fd, LOCK_EX) != 0 ||
            !epoch_stage_current(authority, &artifacts)) {
            if (lock_fd >= 0)
                close(lock_fd);
            epoch_artifacts_close(&artifacts, true);
            return epoch_fail("could not lock coverage object");
        }
    }
    int compiler_argc = 0;
    char **cc = epoch_compiler_argv(argc, argv, output, source, &artifacts,
                                    coverage, &compiler_argc);
    if (!cc) {
        epoch_artifacts_close(&artifacts, true);
        if (lock_fd >= 0)
            close(lock_fd);
        return epoch_fail("could not allocate compiler argv");
    }
    int rc = epoch_compile_or_serve(argc, argv, mode, output, source,
                                    &artifacts, compiler_argc, cc);
    free(cc);
    bool complete = epoch_compile_complete(rc, coverage, &artifacts);
    if (!complete || !epoch_stage_current(authority, &artifacts)) {
        epoch_artifacts_close(&artifacts, true);
        if (lock_fd >= 0)
            close(lock_fd);
        if (rc != 0)
            return rc;
        return epoch_fail(!complete ? "compiler did not create a complete object"
                                   : "compile authority changed during compilation");
    }
    int admission_fd = epoch_admission_acquire(authority, &artifacts);
    if (admission_fd < 0) {
        epoch_artifacts_close(&artifacts, true);
        if (lock_fd >= 0)
            close(lock_fd);
        return epoch_fail("could not acquire stable-publication admission");
    }
    bool published = epoch_publish(coverage, &artifacts);
    if (published &&
        (!epoch_admission_lock_current(authority, admission_fd) ||
         !epoch_stage_current(authority, &artifacts))) {
        epoch_retract(coverage, &artifacts);
        published = false;
    }
    epoch_artifacts_close(&artifacts, !coverage || !published);
    close(admission_fd);
    if (lock_fd >= 0)
        close(lock_fd);
    return published ? 0 : epoch_fail("atomic object publication failed");
}

static int cmd_epoch_object(int argc, char **argv)
{
    if (argc < 13 || strcmp(argv[11], "--") != 0)
        return epoch_fail("usage: zcc --epoch-object dep|coverage OUTPUT "
                          "SOURCE SOURCE_ID COMPLETE MUTATION EPOCH "
                          "COMPILER_ID SESSION -- COMPILER [ARG...]");
    const char *mode = argv[2], *output = argv[3], *source = argv[4];
    const char *source_id = argv[5], *complete = argv[6], *mutation = argv[7];
    const char *epoch = argv[8], *compiler_id = argv[9], *session = argv[10];
    if (strcmp(mode, "dep") != 0 && strcmp(mode, "coverage") != 0)
        return epoch_fail("unknown compile mode");
    if (!epoch_is_sha256(source_id) || !epoch_is_sha256(mutation) ||
        !epoch_is_sha256(epoch) || !epoch_is_sha256(compiler_id))
        return epoch_fail("authority field is not lowercase SHA-256");
    if (strcmp(complete, "1") != 0)
        return epoch_fail("source capture is incomplete");
    struct stat source_st;
    if (lstat(source, &source_st) != 0 || !S_ISREG(source_st.st_mode))
        return epoch_fail("source is not a regular file");
    if (!epoch_paths_contained(output, session, epoch))
        return epoch_fail("object and session paths do not share compile epoch");
    struct epoch_authority authority;
    if (!epoch_authority_open(output, session, source_id, complete, mutation,
                              compiler_id, epoch, &authority))
        return epoch_fail("compile-session stamp does not match object authority");
    int result = epoch_compile_publish(argc, argv, mode, output, source,
                                       &authority);
    epoch_authority_close(&authority);
    return result;
}

/* ── main ────────────────────────────────────────────────────────────── */

static int exec_direct(char **argv)
{
    execvp(argv[0], argv);
    fprintf(stderr, "zcc: cannot execute %s: %s\n", argv[0], strerror(errno));
    return 127;
}

static bool flight_revalidate(const struct cache *c, const struct plan *pl,
                               const char *key, struct deps *deps)
{
    char fresh_key[HEXLEN + 1u];
    deps_free(deps);
    return content_key(pl, c->tmp, c->root, deps, fresh_key) &&
           strcmp(key, fresh_key) == 0;
}

/* A nonnegative result owns the compile range; -2 already served the result;
 * -1 must compile without cache publication because coordination failed or
 * the caller's input key changed while it waited. */
static int flight_prepare(const struct cache *c, const struct plan *pl,
                           const char *key, struct deps *deps,
                           bool *have_deps)
{
    bool waited = false;
    int fd = flight_acquire(c, key, pl, &waited);
    if (fd < 0)
        return -1;
    if (waited) {
        if (!flight_revalidate(c, pl, key, deps)) {
            close(fd);
            return -1;
        }
        *have_deps = true;
    }
    if (!serve(c, key, pl))
        return fd;
    close(fd);
    bump(c, "hit");
    logline("HIT", "concurrent content", pl);
    return -2;
}

static void audit_compare(bool audit, bool had_cached, const char *key,
                           const struct plan *pl, const struct buf *cached)
{
    if (!audit || !had_cached)
        return;
    struct buf fresh = { 0 };
    if (read_file(pl->out_path, &fresh)) {
        bool same = fresh.len == cached->len &&
                    memcmp(fresh.p, cached->p, fresh.len) == 0;
        fprintf(stderr, "zcc: AUDIT %s %s (%s)\n",
                same ? "MATCH" : "DIVERGENCE", key, pl->out_path);
        if (!same)
            fprintf(stderr,
                    "zcc: AUDIT the cached artifact did NOT match a "
                    "fresh build — the fresh one was kept; report "
                    "this and run --zcc-clear\n");
    }
    buf_free(&fresh);
}

static bool manifest_store(const struct cache *c, const char *pkey,
                            const char *ckey, const struct deps *deps,
                            bool have_pkey, bool have_deps)
{
    return have_pkey && have_deps && manifest_write(c, pkey, ckey, deps);
}

static void record_compilation(const struct cache *c, const struct plan *pl,
                               const char *errfile, bool audit,
                               bool had_cached, const struct buf *cached,
                               const char *ckey, struct deps *deps,
                               const char *pkey, bool have_pkey,
                               int *flight_fd)
{
    audit_compare(audit, had_cached, ckey, pl, cached);
    /* The preprocessor ran before the compiler. A changed input forbids
     * publication under the earlier key even when compilation succeeded. */
    bool stable = flight_revalidate(c, pl, ckey, deps);
    if (stable)
        store(c, ckey, pl, errfile);
    if (*flight_fd >= 0) {
        close(*flight_fd);
        *flight_fd = -1;
    }
    if (stable)
        (void)manifest_store(c, pkey, ckey, deps, have_pkey, true);
    bump(c, "miss");
    logline("MISS", stable ? "compiled and stored" :
            "compiled; inputs changed during compilation", pl);
    maybe_trim(c, pl);
}

static int zcc_command_dispatch(int argc, char **argv)
{
    struct cache c;
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
    if (strcmp(argv[1], "--zcc-trim") == 0)
        return cmd_trim(&c, argc > 2 ? strtoll(argv[2], NULL, 10)
                                     : ceiling_mb());
    fprintf(stderr, "zcc: unknown option %s\n", argv[1]);
    return 2;
}

static int zcc_dispatch(int argc, char **argv, bool replace_on_bypass)
{
    if (argc < 2) {
        fprintf(stderr,
                "usage: zcc <compiler> [args...]\n"
                "       zcc --epoch-object dep|coverage OUTPUT SOURCE ...\n"
                "       zcc --zcc-stats | --zcc-clear | --zcc-trim [MB]\n");
        return 2;
    }

    if (strcmp(argv[1], "--epoch-object") == 0)
        return cmd_epoch_object(argc, argv);

    if (strncmp(argv[1], "--zcc-", 6) == 0)
        return zcc_command_dispatch(argc, argv);

    struct cache c;

    char **cc_argv = argv + 1;
    int cc_argc = argc - 1;

    struct plan pl = { 0 };
    plan_build(&pl, cc_argc, cc_argv);
    bool disabled = getenv("ZCC_DISABLE") != NULL;

    /* A proof may not consume this account's cache, even through the stat
     * manifest: candidate code can write both. Until a separately owned
     * verifier supplies an admitted object, compile from the real inputs.
     * This branch precedes cache_open and both cache-hit paths. The epoch
     * publisher reaches it through its nested zcc_dispatch call. */
    if (getenv("ZCC_VERIFIED") != NULL) {
        logline("MISS", "verified:no_verifier_key", &pl);
        plan_free(&pl);
        return replace_on_bypass ? exec_direct(cc_argv)
                                 : run_argv(cc_argv, NULL, NULL);
    }

    if (disabled || pl.bypass || !cache_open(&c)) {
        if (!disabled && pl.bypass && cache_open(&c)) {
            bump(&c, "bypass");
            logline("BYPASS", pl.bypass, &pl);
        }
        plan_free(&pl);
        return replace_on_bypass ? exec_direct(cc_argv)
                                 : run_argv(cc_argv, NULL, NULL);
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
    /* Source compiles recompute the content key. Parsed link-only inputs may
     * still use the probe shortcut. */
    bool have_pkey = probe_for_plan(&pl, c.root, strict, pkey);
    bool have_ckey = false;

    if (have_pkey && manifest_verify(&c, pkey, ckey))
        have_ckey = true;

    if (have_ckey && !audit && serve(&c, ckey, &pl)) {
        bump(&c, "hit");
        logline("HIT", "level 1 (probe manifest)", &pl);
        plan_free(&pl);
        return 0;
    }

    if (!have_ckey || audit) {
        if (!content_key(&pl, c.tmp, c.root, &deps, ckey)) {
            /* The -E probe did not work here. Run the real compiler, but say
             * so: an invocation that silently declines to be cached is a
             * performance bug nobody can see. A -MT value left unconsumed
             * once made EVERY node object take this path. */
            deps_free(&deps);
            bump(&c, "unkeyable");
            logline("UNKEY", "the -E probe failed", &pl);
            plan_free(&pl);
            return replace_on_bypass ? exec_direct(cc_argv)
                                     : run_argv(cc_argv, NULL, NULL);
        }
        have_deps = true;
        if (!audit && serve(&c, ckey, &pl)) {
            bool wrote = have_pkey && have_deps &&
                         manifest_write(&c, pkey, ckey, &deps);
            deps_free(&deps);
            bump(&c, "hit");
            logline("HIT", "level 2 (content)", &pl);
            /* A level-2 hit still ADDS a manifest, so it is one of the two
             * places bytes enter the cache and therefore one of the two that
             * has to check the bound. */
            if (wrote)
                maybe_trim(&c, &pl);
            plan_free(&pl);
            return 0;
        }
    }

    int flight_fd = -1;
    if (!audit) {
        flight_fd = flight_prepare(&c, &pl, ckey, &deps, &have_deps);
        if (flight_fd < 0) {
            if (flight_fd == -2) {
                if (manifest_store(&c, pkey, ckey, &deps,
                                   have_pkey, have_deps))
                    maybe_trim(&c, &pl);
                deps_free(&deps);
                plan_free(&pl);
                return 0;
            }
            deps_free(&deps);
            bump(&c, "bypass");
            logline("BYPASS", "content coordination unavailable or changed", &pl);
            plan_free(&pl);
            return replace_on_bypass ? exec_direct(cc_argv)
                                     : run_argv(cc_argv, NULL, NULL);
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
        record_compilation(&c, &pl, errfile, audit, had_cached,
                           &cached_before, ckey, &deps, pkey, have_pkey,
                           &flight_fd);
    }
    buf_free(&cached_before);
    flight_release(flight_fd);
    deps_free(&deps);
    unlink(errfile);
    plan_free(&pl);
    return rc;
}

int main(int argc, char **argv)
{
    return zcc_dispatch(argc, argv, true);
}
