/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * native_zcode_node_reproduce.c — the "produce bytes" half of
 * `z23 zcode node verify`, in process.
 *
 * It builds the node artifact ONCE on this machine and writes a
 * zcl.node_repro_receipt.v1 that names exactly what came out, and every
 * component it did NOT rebuild as an `unverified` row. It compares nothing:
 * the verdict belongs to vcs_node_reproduce_compare(). This is the in-process
 * replacement for the former node_reproduce.sh: the same receipt lines,
 * the same exit codes (0 written, 2 refusal, 1 build failure), the same make
 * environment and release flag profile. */

#include "command/native_zcode_node_reproduce.h"

#include "base/hex.h"
#include "platform/directory_compat.h"
#include "sha3/sha3.h"
#include "util/spawn.h"

#include <errno.h>
#include <limits.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#if defined(_WIN32)

static int nr_native_reproduce(const struct zcl_node_reproduce_request *req,
                              char *log, size_t log_cap)
{
    (void)req;
    if (log && log_cap > 0)
        log[0] = '\0';
    /* The rebuild runs POSIX make and POSIX process capture; refusing here
     * keeps a Windows host from ever reporting a receipt it did not make. */
    return 2;
}

#else

#include <dirent.h>
#include <sys/stat.h>
#include <unistd.h>

#define NR_ARTIFACT_REL "bin/z23"
#define NR_PATH_CAP ((size_t)PATH_MAX)
#define NR_ARGV_MAX 40u
#define NR_ARGV_TEXT 8192u
#define NR_FLAG_CAP 8192u
#define NR_CAPTURE_CAP 256u
#define NR_BUILD_OUT_CAP (256u * 1024u)
#define NR_RECEIPT_CAP (32u * 1024u)
#define NR_ARCHIVE_MAX 128u
#define NR_NAME_CAP 256u
#define NR_HASH_CHUNK 65536u
#define NR_MAX_TIMEOUT_S 43200
#define NR_PROBE_MS 60000

/* ── bounded text and argv builders ──────────────────────────────────── */

struct nr_text {
    char *buf;
    size_t cap;
    size_t len;
    bool overflow;
};

static void nr_text_add(struct nr_text *t, const char *fmt, ...)
{
    if (t->overflow)
        return;
    va_list ap;
    va_start(ap, fmt);
    int n = vsnprintf(t->buf + t->len, t->cap - t->len, fmt, ap);
    va_end(ap);
    if (n < 0 || (size_t)n >= t->cap - t->len)
        t->overflow = true;
    else
        t->len += (size_t)n;
}

static bool nr_fmt(char *dst, size_t cap, const char *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    int n = vsnprintf(dst, cap, fmt, ap);
    va_end(ap);
    return n >= 0 && (size_t)n < cap;
}

struct nr_argv {
    const char *v[NR_ARGV_MAX];
    char text[NR_ARGV_TEXT];
    size_t used;
    size_t n;
};

static void nr_argv_reset(struct nr_argv *a)
{
    a->n = 0;
    a->used = 0;
    a->v[0] = NULL;
}

static bool nr_argv_push(struct nr_argv *a, const char *s)
{
    size_t len = strlen(s);
    if (a->n + 1 >= NR_ARGV_MAX || len + 1 > NR_ARGV_TEXT - a->used)
        return false;
    char *at = a->text + a->used;
    memcpy(at, s, len + 1);
    a->v[a->n++] = at;
    a->used += len + 1;
    a->v[a->n] = NULL;
    return true;
}

/* Pushes "key=value" as one argv element, without a shell. */
static bool nr_argv_push_kv(struct nr_argv *a, const char *key,
                            const char *value)
{
    size_t kl = strlen(key), vl = strlen(value);
    if (a->n + 1 >= NR_ARGV_MAX || kl + vl + 2 > NR_ARGV_TEXT - a->used)
        return false;
    char *at = a->text + a->used;
    memcpy(at, key, kl);
    at[kl] = '=';
    memcpy(at + kl + 1, value, vl + 1);
    a->v[a->n++] = at;
    a->used += kl + vl + 2;
    a->v[a->n] = NULL;
    return true;
}

static bool nr_argv_push_list(struct nr_argv *a, const char *const *list)
{
    for (; *list; list++) {
        if (!nr_argv_push(a, *list))
            return false;
    }
    return true;
}

/* The environment the old script exported before every make: reproduction
 * consumes already-acquired inputs, so a cache miss must never reach the
 * network, and the build never uses ccache. */
static bool nr_argv_env(struct nr_argv *a, const char *epoch)
{
    static const char *const base[] = {
        "env", "LC_ALL=C", "TZ=UTC", "ZCL_VENDOR_OFFLINE=1",
        "ZCL_USE_CCACHE=0", NULL,
    };
    if (!nr_argv_push_list(a, base))
        return false;
    return !epoch || nr_argv_push_kv(a, "SOURCE_DATE_EPOCH", epoch);
}

/* ── small filesystem helpers ────────────────────────────────────────── */

static bool nr_is_regular(const char *path)
{
    struct stat st;
    return stat(path, &st) == 0 && S_ISREG(st.st_mode);
}

static bool nr_is_dir(const char *path)
{
    struct stat st;
    return stat(path, &st) == 0 && S_ISDIR(st.st_mode);
}

/* mkdir -p: every prefix is created, EEXIST is fine, the leaf must be a
 * directory afterwards. */
static bool nr_mkdirs(const char *dir)
{
    char buf[NR_PATH_CAP];
    if (!nr_fmt(buf, sizeof(buf), "%s", dir))
        return false;
    size_t n = strlen(buf);
    for (size_t i = 1; i <= n; i++) {
        if (buf[i] != '/' && buf[i] != '\0')
            continue;
        char saved = buf[i];
        buf[i] = '\0';
        if (mkdir(buf, 0777) != 0 && errno != EEXIST)
            return false;
        buf[i] = saved;
    }
    return nr_is_dir(dir);
}

static bool nr_write_file(const char *path, const char *data, size_t len)
{
    FILE *f = fopen(path, "wb");
    if (!f)
        return false;
    bool ok = fwrite(data, 1, len, f) == len;
    return fclose(f) == 0 && ok;
}

/* Reads a file, drops trailing newlines the way $(...) does, and refuses a
 * file that does not fit. */
static bool nr_read_trimmed(const char *path, char *out, size_t cap)
{
    FILE *f = fopen(path, "rb");
    if (!f)
        return false;
    size_t n = fread(out, 1, cap - 1, f);
    bool ok = !ferror(f) && !(n == cap - 1 && fgetc(f) != EOF);
    fclose(f);
    if (!ok)
        return false;
    out[n] = '\0';
    while (n > 0 && out[n - 1] == '\n')
        out[--n] = '\0';
    return true;
}

/* ── subprocess wrappers (no shell) ──────────────────────────────────── */

static int nr_spawn(const struct nr_argv *a, const char *cwd, char *out,
                    size_t cap, int timeout_ms)
{
    bool timed_out = false;
    return zcl_spawn_capture_in_dir_observed(a->v, cwd, out, cap, timeout_ms,
                                             &timed_out);
}

/* ── the plan: everything a build needs, resolved once ───────────────── */

struct nr_plan {
    char src[NR_PATH_CAP];
    char scratch[NR_PATH_CAP];
    char build[NR_PATH_CAP];
    char build_log[NR_PATH_CAP];
    char artifact[NR_PATH_CAP];
    char source_id[65];
    char epoch[32];
    char cflags[NR_FLAG_CAP];
    char ldflags[NR_FLAG_CAP];
    char desc[NR_FLAG_CAP];
    bool release;
    int jobs;
    int timeout_ms;
};

static bool nr_make_available(void)
{
    static const char *const probe[] = { "make", "--version", NULL };
    struct nr_argv a;
    nr_argv_reset(&a);
    char out[NR_CAPTURE_CAP];
    bool timed_out = false;
    return nr_argv_push_list(&a, probe) &&
           zcl_spawn_capture_observed(a.v, out, sizeof(out), NR_PROBE_MS,
                                      &timed_out) == 0;
}

/* Argument shape: every refusal here is a usage error (exit 2). */
static int nr_check_values(const struct zcl_node_reproduce_request *req)
{
    if (!req || !req->out_path || !req->out_path[0] || !req->source_dir ||
        !req->scratch_dir || !req->scratch_dir[0])
        return 2;
    if (!req->profile || (strcmp(req->profile, "default") != 0 &&
                          strcmp(req->profile, "release") != 0))
        return 2;
    if (req->jobs < 1 || req->timeout_s < 1 ||
        req->timeout_s > NR_MAX_TIMEOUT_S)
        return 2;
    return 0;
}

/* Filesystem and host prerequisites: a checkout with a Makefile and make. */
static int nr_check_tree(const struct zcl_node_reproduce_request *req,
                         struct nr_plan *p)
{
    if (!platform_directory_canonical_real(req->source_dir, p->src,
                                           sizeof(p->src)))
        return 2;
    char makefile[NR_PATH_CAP];
    if (!nr_fmt(makefile, sizeof(makefile), "%s/Makefile", p->src) ||
        !nr_is_regular(makefile))
        return 2;
    if (!nr_make_available())
        return 2;
    if (!nr_fmt(p->scratch, sizeof(p->scratch), "%s", req->scratch_dir))
        return 2;
    return 0;
}

static int nr_check_request(const struct zcl_node_reproduce_request *req,
                            struct nr_plan *p)
{
    int rc = nr_check_values(req);
    if (rc != 0)
        return rc;
    rc = nr_check_tree(req, p);
    if (rc != 0)
        return rc;
    p->release = strcmp(req->profile, "release") == 0;
    p->jobs = req->jobs;
    p->timeout_ms = req->timeout_s * 1000;
    return 0;
}

static bool nr_plan_paths(struct nr_plan *p)
{
    return nr_fmt(p->build, sizeof(p->build), "%s/build", p->scratch) &&
           nr_fmt(p->build_log, sizeof(p->build_log), "%s/build.log",
                  p->scratch) &&
           nr_fmt(p->artifact, sizeof(p->artifact), "%s/bin/z23", p->build);
}

/* ── release flag profile (the old repro_build_vars.sh, in C) ────────── */

/* make asks itself to expand one variable and writes it to a file, so the
 * value is what make resolves, never a parsed `$(VAR)` expression. */
static bool nr_make_var(const struct nr_plan *p, const char *name, char *out,
                        size_t cap)
{
    char path[NR_PATH_CAP];
    if (!nr_fmt(path, sizeof(path), "%s/repro-capture-%s.txt", p->scratch,
                name))
        return false;
    static const char *const head[] = {
        "make", "-s", "--no-print-directory",
        "--eval", ".PHONY: __zcl_repro_capture",
        "--eval",
        "__zcl_repro_capture: ; @$(file >$(ZCL_REPRO_CAPTURE_PATH),"
        "$($(ZCL_REPRO_CAPTURE_NAME)))true",
        "-C", NULL,
    };
    struct nr_argv a;
    nr_argv_reset(&a);
    char raw[NR_CAPTURE_CAP];
    bool ok = nr_argv_env(&a, NULL) &&
              nr_argv_push_kv(&a, "ZCL_REPRO_CAPTURE_NAME", name) &&
              nr_argv_push_kv(&a, "ZCL_REPRO_CAPTURE_PATH", path) &&
              nr_argv_push_list(&a, head) && nr_argv_push(&a, p->src) &&
              nr_argv_push(&a, "__zcl_repro_capture");
    bool got = ok && nr_spawn(&a, NULL, raw, sizeof(raw), p->timeout_ms) == 0 &&
               nr_read_trimmed(path, out, cap);
    (void)remove(path);
    return got;
}

/* Rewrites every -march=native to the portable v3 baseline, as the release
 * contract does. Fails closed if the result does not fit. */
static bool nr_march_rewrite(const char *in, char *out, size_t cap)
{
    static const char from[] = "-march=native";
    static const char to[] = "-march=x86-64-v3";
    size_t o = 0;
    const char *s = in;
    while (*s) {
        bool here = strncmp(s, from, sizeof(from) - 1) == 0;
        size_t take = here ? sizeof(from) - 1 : 1;
        const char *emit = here ? to : s;
        size_t width = here ? sizeof(to) - 1 : 1;
        if (o + width >= cap)
            return false;
        memcpy(out + o, emit, width);
        o += width;
        s += take;
    }
    out[o] = '\0';
    return true;
}

/* Drops trailing newlines from captured stdout, as $(...) does. */
static void nr_trim_newlines(char *s)
{
    size_t n = strlen(s);
    while (n > 0 && s[n - 1] == '\n')
        s[--n] = '\0';
}

static bool nr_git_epoch(const struct nr_plan *p, char *out, size_t cap)
{
    static const char *const git[] = { "git", "log", "-1", "--format=%ct",
                                       NULL };
    struct nr_argv a;
    nr_argv_reset(&a);
    char raw[64] = "";
    bool ran = nr_argv_push_list(&a, git) &&
               nr_spawn(&a, p->src, raw, sizeof(raw), p->timeout_ms) == 0;
    nr_trim_newlines(raw);
    return nr_fmt(out, cap, "%s", ran && raw[0] ? raw : "0");
}

static bool nr_resolve_epoch(struct nr_plan *p)
{
    const char *env = getenv("SOURCE_DATE_EPOCH");
    if (env && env[0])
        return nr_fmt(p->epoch, sizeof(p->epoch), "%s", env);
    return nr_git_epoch(p, p->epoch, sizeof(p->epoch));
}

static bool nr_resolve_release(struct nr_plan *p)
{
    char raw_cflags[NR_FLAG_CAP], raw_ldflags[NR_FLAG_CAP];
    if (!nr_resolve_epoch(p) ||
        !nr_make_var(p, "CFLAGS", raw_cflags, sizeof(raw_cflags)) ||
        !nr_make_var(p, "LDFLAGS", raw_ldflags, sizeof(raw_ldflags)))
        return false;
    if (!nr_march_rewrite(raw_cflags, p->cflags, sizeof(p->cflags)) ||
        !p->cflags[0])
        return false;
    return nr_fmt(p->ldflags, sizeof(p->ldflags),
                  "%s -Wl,--build-id=none", raw_ldflags) &&
           nr_fmt(p->desc, sizeof(p->desc),
                  "tools/release.sh release profile, SOURCE_DATE_EPOCH=%s",
                  p->epoch);
}

static void nr_default_desc(struct nr_plan *p)
{
    (void)nr_fmt(p->desc, sizeof(p->desc),
                 "make default profile (the same flags make z23 and make "
                 "repro-verify use)");
}

/* ── source identity (the one step still delegated) ──────────────────── */

/* Switches to the C23 source-identity binary when that lands; until then
 * this is the same shell capture the script ran. Optional: any output that
 * is not exactly 64 lowercase hex is treated as absent, never as an id. */
static void nr_capture_source_id(struct nr_plan *p)
{
    char tool[NR_PATH_CAP];
    p->source_id[0] = '\0';
    if (!nr_fmt(tool, sizeof(tool), "%s/tools/dev/source-identity.sh",
                p->src) || access(tool, X_OK) != 0)
        return;
    const char *argv[] = { tool, "capture", NULL };
    char out[256];
    bool timed_out = false;
    if (zcl_spawn_capture_in_dir_observed(argv, p->src, out, sizeof(out),
                                          p->timeout_ms, &timed_out) < 0)
        return;
    nr_trim_newlines(out);
    if (strlen(out) != 64)
        return;
    for (size_t i = 0; i < 64; i++) {
        if (!((out[i] >= '0' && out[i] <= '9') ||
              (out[i] >= 'a' && out[i] <= 'f')))
            return;
    }
    memcpy(p->source_id, out, 65);
}

/* ── build ───────────────────────────────────────────────────────────── */

static bool nr_build_argv(const struct nr_plan *p, struct nr_argv *a)
{
    char jobs[32];
    if (!nr_fmt(jobs, sizeof(jobs), "-j%d", p->jobs))
        return false;
    static const char *const make_head[] = { "make", "-C", NULL };
    if (!nr_argv_env(a, p->release ? p->epoch : NULL) ||
        !nr_argv_push_list(a, make_head) || !nr_argv_push(a, p->src) ||
        !nr_argv_push(a, jobs) || !nr_argv_push_kv(a, "BUILD_DIR", p->build))
        return false;
    if (p->release && (!nr_argv_push_kv(a, "CFLAGS", p->cflags) ||
                       !nr_argv_push_kv(a, "LDFLAGS", p->ldflags)))
        return false;
    return nr_argv_push(a, "z23");
}

/* Copies the last `log_cap - 1` bytes of the build output: the failure is
 * at the end, and that is what a reader needs. */
static void nr_copy_tail(char *log, size_t log_cap, const char *out, size_t n)
{
    if (!log || log_cap == 0)
        return;
    size_t keep = n < log_cap - 1 ? n : log_cap - 1;
    memcpy(log, out + (n - keep), keep);
    log[keep] = '\0';
}

static void nr_note(char *log, size_t log_cap, const char *msg)
{
    nr_copy_tail(log, log_cap, msg, strlen(msg));
}

static bool nr_run_build(const struct nr_plan *p, char *log, size_t log_cap)
{
    static char out[NR_BUILD_OUT_CAP];
    struct nr_argv a;
    nr_argv_reset(&a);
    if (!nr_build_argv(p, &a))
        return false;
    bool timed_out = false;
    int rc = zcl_spawn_capture_merged_observed(a.v, out, sizeof(out),
                                               p->timeout_ms, &timed_out);
    size_t n = strnlen(out, sizeof(out));
    (void)nr_write_file(p->build_log, out, n);
    if (rc != 0 || timed_out) {
        nr_copy_tail(log, log_cap, out, n);
        return false;
    }
    if (!nr_is_regular(p->artifact)) {
        nr_note(log, log_cap, "build produced no bin/z23");
        return false;
    }
    return true;
}

/* ── hashing and the unverified inventory ────────────────────────────── */

static bool nr_hash_file(const char *path, char hex[65], long long *size)
{
    struct stat st;
    if (stat(path, &st) != 0 || !S_ISREG(st.st_mode))
        return false;
    FILE *f = fopen(path, "rb");
    if (!f)
        return false;
    static unsigned char chunk[NR_HASH_CHUNK];
    struct sha3_256_ctx ctx;
    sha3_256_init(&ctx);
    size_t n;
    while ((n = fread(chunk, 1, sizeof(chunk), f)) > 0)
        sha3_256_write(&ctx, chunk, n);
    bool failed = ferror(f) != 0;
    fclose(f);
    if (failed)
        return false;
    unsigned char digest[SHA3_256_OUTPUT_SIZE];
    sha3_256_finalize(&ctx, digest);
    zcl_hex_encode(digest, sizeof(digest), hex);
    *size = (long long)st.st_size;
    return true;
}

struct nr_archives {
    char name[NR_ARCHIVE_MAX][NR_NAME_CAP];
    size_t n;
};

static int nr_name_cmp(const void *a, const void *b)
{
    return strcmp((const char *)a, (const char *)b);
}

/* The shell glob "*.a": a plain name ending in .a, never a dot-file. */
static bool nr_is_archive_name(const char *name)
{
    size_t len = strlen(name);
    return len > 2 && name[0] != '.' && strcmp(name + len - 2, ".a") == 0;
}

static bool nr_list_archives(const char *src, struct nr_archives *lib)
{
    lib->n = 0;
    char dir[NR_PATH_CAP];
    if (!nr_fmt(dir, sizeof(dir), "%s/vendor/lib", src))
        return false;
    DIR *d = opendir(dir);
    if (!d)
        return errno == ENOENT; /* the glob matches nothing */
    bool ok = true;
    struct dirent *e;
    while (ok && (e = readdir(d)) != NULL) {
        char path[NR_PATH_CAP];
        if (!nr_is_archive_name(e->d_name))
            continue;
        if (!nr_fmt(path, sizeof(path), "%s/%s", dir, e->d_name) ||
            !nr_is_regular(path))
            continue;
        if (lib->n >= NR_ARCHIVE_MAX || strlen(e->d_name) >= NR_NAME_CAP)
            ok = false;
        else
            (void)snprintf(lib->name[lib->n++], NR_NAME_CAP, "%s",
                           e->d_name);
    }
    closedir(d);
    if (ok)
        qsort(lib->name, lib->n, NR_NAME_CAP, nr_name_cmp);
    return ok;
}

/* One archive is a named gap: "prebuilt" when the source tree carries its
 * provenance manifest, otherwise "already present on this host". Either way
 * this run rebuilt none of it, so the verdict cannot cover it silently. */
static void nr_add_archive_row(const struct nr_plan *p, const char *name,
                               struct nr_text *t)
{
    char manifest[NR_PATH_CAP];
    size_t stem = strlen(name) - 2;
    bool have_manifest =
        nr_fmt(manifest, sizeof(manifest),
               "%s/vendor/provenance/%.*s.manifest", p->src, (int)stem,
               name) &&
        nr_is_regular(manifest);
    /* Reasons stay within the comparator's 160-byte reason field
     * (VCS_NODE_REPRO_TEXT_MAX); a longer one makes the decoder refuse the
     * whole receipt. */
    if (have_manifest)
        nr_text_add(t, "unverified vendor/lib/%s prebuilt archive committed "
                       "to the source tree; its manifest in vendor/provenance/ "
                       "records provenance this build did not re-derive\n",
                    name);
    else
        nr_text_add(t, "unverified vendor/lib/%s archive already present on "
                       "this host, linked as-is; this run rebuilt none of it "
                       "from vendored source\n", name);
}

static bool nr_render_receipt(const struct nr_plan *p,
                              const struct nr_archives *lib, const char *sha,
                              long long size, char *buf, size_t cap)
{
    struct nr_text t = { buf, cap, 0, false };
    nr_text_add(&t, "zcl.node_repro_receipt.v1\n");
    nr_text_add(&t, "producer local-rebuild\n");
    if (p->source_id[0])
        nr_text_add(&t, "source_id %s\n", p->source_id);
    nr_text_add(&t, "toolchain_desc %s\n", p->desc);
    nr_text_add(&t, "artifact %s %lld %s\n", sha, size, NR_ARTIFACT_REL);
    for (size_t i = 0; i < lib->n; i++)
        nr_add_archive_row(p, lib->name[i], &t);
    nr_text_add(&t, "unverified lto-intermediate-objects gcc LTO streams "
                    "absolute paths that -ffile-prefix-map cannot reach, so "
                    "per-unit objects are not byte-stable; only the linked "
                    "artifact is compared\n");
    nr_text_add(&t, "unverified host-toolchain compiler, assembler, linker and "
                    "archiver were not rebuilt; identity is read from the "
                    "artifact ELF .comment section, weaker than reproducing "
                    "them\n");
    return !t.overflow;
}

/* ── receipt write (temp file, then rename) ──────────────────────────── */

static bool nr_parent_dir(const char *path, char *dir, size_t cap)
{
    const char *slash = strrchr(path, '/');
    if (!slash)
        return nr_fmt(dir, cap, ".");
    if (slash == path)
        return nr_fmt(dir, cap, "/");
    return nr_fmt(dir, cap, "%.*s", (int)(slash - path), path);
}

static bool nr_write_receipt(const char *out_path, const char *text,
                             size_t len)
{
    char dir[NR_PATH_CAP], tmp[NR_PATH_CAP];
    if (!nr_parent_dir(out_path, dir, sizeof(dir)) || !nr_mkdirs(dir) ||
        !nr_fmt(tmp, sizeof(tmp), "%s.tmp", out_path))
        return false;
    if (!nr_write_file(tmp, text, len) || rename(tmp, out_path) != 0) {
        (void)remove(tmp);
        return false;
    }
    return true;
}

static bool nr_emit_receipt(const struct nr_plan *p, const char *sha,
                            long long size, const char *out_path)
{
    struct nr_archives lib;
    if (!nr_list_archives(p->src, &lib))
        return false;
    static char text[NR_RECEIPT_CAP];
    if (!nr_render_receipt(p, &lib, sha, size, text, sizeof(text)))
        return false;
    return nr_write_receipt(out_path, text, strlen(text));
}

/* ── entry point ─────────────────────────────────────────────────────── */

static int nr_prepare(const struct zcl_node_reproduce_request *req,
                      struct nr_plan *p)
{
    int rc = nr_check_request(req, p);
    if (rc != 0)
        return rc;
    if (!nr_plan_paths(p))
        return 2;
    /* The release capture writes into the scratch root, so it must exist. */
    if (!nr_mkdirs(p->scratch))
        return 1;
    if (p->release)
        return nr_resolve_release(p) ? 0 : 2;
    nr_default_desc(p);
    return 0;
}

static int nr_native_reproduce(const struct zcl_node_reproduce_request *req,
                              char *log, size_t log_cap)
{
    if (log && log_cap > 0)
        log[0] = '\0';
    struct nr_plan p;
    memset(&p, 0, sizeof(p));
    int rc = nr_prepare(req, &p);
    if (rc != 0)
        return rc;
    nr_capture_source_id(&p);
    if (!nr_run_build(&p, log, log_cap))
        return 1;
    char sha[65];
    long long size = 0;
    if (!nr_hash_file(p.artifact, sha, &size))
        return 1;
    return nr_emit_receipt(&p, sha, size, req->out_path) ? 0 : 1;
}

#endif /* !_WIN32 */

/* The one public entry: the arm above decides whether a rebuild can run. */
int zcl_native_node_reproduce(const struct zcl_node_reproduce_request *req,
                              char *log, size_t log_cap)
{
    return nr_native_reproduce(req, log, log_cap);
}
