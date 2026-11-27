/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * purpose: HOT_FORK shape admission (see devloop_hotfork_shape.h).
 *
 * The baseline is never a previous candidate. It is the resident's own
 * inputs: the dev build's objects for the capsule's TU set in the epoch
 * named by build/dev-obj/.current-epoch, bound to the running image by
 * three facts — the epoch's completed build session names the action plan's
 * compiler identity, no object is newer than the running image, and every
 * global the objects define is defined by the running image.
 *
 * Each object and depfile the running image was linked from is kept for
 * that image under build/hotswap-fast/resident/<image>/ (hard links, taken
 * while the epoch object is still no newer than the image). zcc republishes
 * a rebuilt object under a new inode, so a later dev build of the same TU
 * in the same epoch leaves the kept baseline intact; without a kept object
 * a newer epoch object is RESIDENT_STALE. The epoch object's ctime, read
 * before the link (link() moves it), is recorded beside the kept object as
 * its build time.
 *
 * The capsule's TUs are the owner, its siblings and every source the story
 * adapter itself includes (a view contract compiles its service .c).
 *
 * Shape, compared per capsule:
 *   ABI    defined GLOBAL/WEAK symbols (functions, objects, TLS, common)
 *   state  writable, thread-local and common objects of any binding, by
 *          name (a local static's ".N" suffix is dropped), size and the
 *          number of relocations inside the object (its initializer's
 *          pointers); .data.rel.ro is read-only after relocation and is not
 *          state
 *   init   .preinit_array, .init_array, .fini_array, .ctors, .dtors
 *   refs   every symbol the candidate leaves undefined is in the running
 *          image's dynamic symbol table or defined by a library the image
 *          names (DT_NEEDED) or its interpreter, as mapped in this process
 *   deps   every prerequisite of each resident object's depfile under the
 *          source root, except the edited owner and siblings, still exists
 *          and is not newer than that object: its mtime not newer than the
 *          object's and its ctime not newer than the object's recorded
 *          build time (no per-input digest is recorded for dev objects; an
 *          mtime can be set back, a ctime cannot), and every
 *          prerequisite under the source root the candidate compiled after
 *          the owner is one some resident object was built from. Paths
 *          outside the source root are the toolchain's, bound by the
 *          compiler identity; headers the adapter includes before the owner
 *          are the adapter's.
 *
 * Section totals (.data/.bss/.tdata) are not compared: the unity packs every
 * TU plus the adapter into one object, so its padding and the adapter's own
 * objects make totals differ for implementation-only edits. Per-object size
 * and relocation counts carry the same facts at object granularity.
 * LOCAL function symbols are not shape: a static function has internal
 * linkage, holds no state, cannot be bound from outside its TU, and appears
 * or disappears with inlining decisions. Adding, renaming or removing one is
 * an implementation-only edit.
 *
 * The unity also carries the story adapter. A candidate-only symbol belongs
 * to the adapter only when its name is a token of the adapter text and of
 * no other file in the candidate's dependency closure; a symbol an owner
 * edit introduces is always a token of the owner (or a header) and is
 * therefore refused.
 *
 * Every read failure refuses: an unreadable or malformed object, a missing
 * symbol table, a missing session, object or depfile, an unreadable binding
 * record.
 *
 * The running image's .symtab globals and its .dynsym plus mapped
 * libraries' names are parsed once per process and reused while the
 * image's and libraries' file identities are unchanged (shape_image_acquire).
 */
#include "devloop_hotfork_shape.h"

#include "hotfork_unity.h"

#include <stdio.h>
#include <string.h>

bool zcl_hotfork_shape_refused(const char *why)
{
    return why && strncmp(why, ZCL_HOTFORK_SHAPE_REASON,
                          sizeof(ZCL_HOTFORK_SHAPE_REASON) - 1) == 0;
}

static bool shape_refuse(char *why, size_t why_len, const char *reason,
                         const char *subject, const char *detail)
{
    if (why && why_len)
        (void)snprintf(why, why_len, "%s%s %s: %s; fallback=restart",
                       ZCL_HOTFORK_SHAPE_REASON, reason,
                       subject && subject[0] ? subject : "-", detail);
    return false;
}

#if defined(__linux__)

#include "base/hex.h"
#include "codeindex/codeindex.h"
#include "platform/os_proc.h"
#include "util/safe_alloc.h"
#include "sha3/sha3.h"

#include <dirent.h>
#include <elf.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <unistd.h>

/* Sibling rule: rr_overlay_object_safe() in devloop_restart_build.c refuses
 * the first three of these for restart overlays. A HOT_FORK candidate runs
 * its constructors at dlopen inside the resident's child, so the old-style
 * .ctors/.dtors spellings are refused as well. */
static const char *const k_shape_init_fini[] = {
    ".preinit_array", ".init_array", ".fini_array", ".ctors", ".dtors",
};

enum {
    SHAPE_SECTION_MAX = 64 << 20, /* bytes read from one ELF section */
    SHAPE_TEXT_MAX = 16 << 20,    /* bytes read from one closure file */
    SHAPE_ADAPTER_TU_MAX = 4,     /* sources one story adapter includes */
    SHAPE_TU_MAX = 1 + ZCL_HOTFORK_UNITY_SIBLING_MAX + SHAPE_ADAPTER_TU_MAX,
    SHAPE_DEPS_MAX = 4096,
    SHAPE_LIBS_MAX = 32,          /* DT_NEEDED entries of the image */
};

enum shape_kind { SHAPE_GLOBAL, SHAPE_DATA, SHAPE_TLS };
enum shape_read { SHAPE_READ_OK, SHAPE_READ_UNREADABLE, SHAPE_READ_NO_SYMTAB };

struct shape_elf {
    int fd;
    uint64_t size;
    Elf64_Ehdr eh;
    Elf64_Shdr *sh;
    char *shstr;
    size_t shstr_len;
    Elf64_Sym *sym;
    size_t nsym;
    char *str;
    size_t str_len;
    size_t strndx; /* section index of `str` */
};

struct shape_sym {
    const char *name; /* borrowed from the owning shape_elf string table */
    size_t len;       /* compared length */
    uint64_t size;
    enum shape_kind kind;
    uint64_t value;   /* offset in its section (state entries) */
    size_t shndx;     /* its section in the owning object (state entries) */
    uint32_t relocs;  /* relocations inside the object (state entries) */
};

struct shape_paths {
    char **items;
    size_t count;
    size_t cap;
};

struct shape_set {
    struct shape_sym *items;
    size_t count;
    size_t cap;
    char init_fini[64]; /* first init/fini section seen, "" when none */
};

struct shape_texts {
    bool adapter_tried;
    bool loaded;
    bool ok;
    char *files[SHAPE_DEPS_MAX];
    size_t count;
};

struct shape_run {
    const struct zcl_hotfork_shape *shape;
    const char *candidate;
    const char *depfile;
    struct shape_elf objects[SHAPE_TU_MAX];
    size_t object_count;
    struct shape_elf cand;
    struct shape_set base;
    struct shape_set next;
    struct shape_set undefined; /* the candidate's undefined references */
    struct shape_paths resident_deps; /* sorted, root-relative */
    char *deps_text;
    char *deps[SHAPE_DEPS_MAX];
    size_t dep_count;
    char closure[65];
    char story[ZCL_HOTFORK_UNITY_TU_MAX];
    char *adapter;
    char record[PATH_MAX];
    bool record_current;
    struct shape_texts texts;
};

/* ── small facts ─────────────────────────────────────────────────────── */

static void shape_hex_root(struct sha3_256_ctx *ctx, char out[65])
{
    unsigned char digest[SHA3_256_OUTPUT_SIZE];
    sha3_256_finalize(ctx, digest);
    zcl_hex_encode(digest, sizeof(digest), out);
}

static void shape_hash_text(struct sha3_256_ctx *ctx, const char *text)
{
    sha3_256_write(ctx, (const unsigned char *)text, strlen(text));
    sha3_256_write(ctx, (const unsigned char *)"\n", 1);
}

static void shape_hash_stat(struct sha3_256_ctx *ctx, const char *label,
                            const struct stat *st)
{
    char line[PATH_MAX + 160];
    int n = snprintf(line, sizeof(line), "%s=%llu:%llu:%lld:%lld.%09ld",
                     label, (unsigned long long)st->st_dev,
                     (unsigned long long)st->st_ino, (long long)st->st_size,
                     (long long)st->st_mtim.tv_sec, (long)st->st_mtim.tv_nsec);
    if (n > 0 && n < (int)sizeof(line))
        shape_hash_text(ctx, line);
}

static bool shape_hex64(const char *text)
{
    size_t n = 0;
    while (text[n] && ((text[n] >= '0' && text[n] <= '9') ||
                       (text[n] >= 'a' && text[n] <= 'f')))
        n++;
    return n == 64 && text[64] == 0;
}

static bool shape_newer(const struct stat *a, const struct stat *b)
{
    return a->st_mtim.tv_sec > b->st_mtim.tv_sec ||
           (a->st_mtim.tv_sec == b->st_mtim.tv_sec &&
            a->st_mtim.tv_nsec > b->st_mtim.tv_nsec);
}

static bool shape_regular(const char *path, struct stat *st)
{
    return stat(path, st) == 0 && S_ISREG(st->st_mode);
}

/* The running image's own file identity (device, inode, size, mtime),
 * read off the SAME descriptor os_proc_open_self_exe() pins to the kernel's
 * exe_file reference — never a resolved pathname re-looked-up by name,
 * which a later replace-at-that-path deploy could point at a different
 * file by the time of this call. */
static bool shape_resident_stat(struct stat *out)
{
    FILE *f = os_proc_open_self_exe();
    if (!f)
        return false;
    bool ok = fstat(fileno(f), out) == 0 && S_ISREG(out->st_mode);
    fclose(f);
    return ok;
}

/* Reads a small text file whole; NULL when absent, unreadable, too large or
 * holding a NUL byte (text searches must see every byte). */
static char *shape_slurp(const char *path, size_t max, size_t *len_out)
{
    FILE *f = fopen(path, "rb");
    char *buf = f ? zcl_malloc(max + 1, "HOT_FORK shape text") : NULL;
    size_t n = buf ? fread(buf, 1, max + 1, f) : 0;
    bool whole = buf && !ferror(f) && feof(f) && n <= max &&
                 !memchr(buf, 0, n);
    if (f)
        fclose(f);
    if (!whole) {
        free(buf);
        return NULL;
    }
    buf[n] = 0;
    if (len_out)
        *len_out = n;
    return buf;
}

/* ── the resident generation ─────────────────────────────────────────── */

static bool shape_unbound(struct zcl_hotfork_shape *shape, const char *reason,
                          const char *subject, const char *detail)
{
    return shape_refuse(shape->unbound, sizeof(shape->unbound), reason,
                        subject, detail);
}

static bool shape_read_epoch(struct zcl_hotfork_shape *shape)
{
    char path[PATH_MAX];
    char *text = snprintf(path, sizeof(path), "%s/build/dev-obj/.current-epoch",
                          shape->root) < (int)sizeof(path)
                     ? shape_slurp(path, 128, NULL) : NULL;
    bool ok = text && strlen(text) >= 64 &&
              (text[64] == 0 || strcmp(text + 64, "\n") == 0);
    if (ok) {
        memcpy(shape->epoch, text, 64);
        shape->epoch[64] = 0;
        ok = shape_hex64(shape->epoch);
    }
    free(text);
    return ok || shape_unbound(shape, "NO_BASELINE", "build/dev-obj/.current-epoch",
                               "no dev build epoch names the resident's objects");
}

static const char *shape_session_value(const char *text, const char *key,
                                       char out[65])
{
    size_t klen = strlen(key);
    for (const char *line = text; line && *line;) {
        const char *end = strchr(line, '\n');
        size_t len = end ? (size_t)(end - line) : strlen(line);
        if (len == klen + 1 + 64 && strncmp(line, key, klen) == 0 &&
            line[klen] == '=') {
            memcpy(out, line + klen + 1, 64);
            out[64] = 0;
            return shape_hex64(out) ? out : NULL;
        }
        line = end ? end + 1 : NULL;
    }
    return NULL;
}

/* The epoch's completed build session: its compiler identity must be the
 * action plan's, and it is part of the generation. */
static bool shape_read_session(struct zcl_hotfork_shape *shape,
                               struct sha3_256_ctx *ctx)
{
    char path[PATH_MAX], epoch[65], compiler[65], flags[65];
    char *text = snprintf(path, sizeof(path),
                          "%s/build/dev-obj/epochs/%s/.build-session",
                          shape->root, shape->epoch) < (int)sizeof(path)
                     ? shape_slurp(path, 4096, NULL) : NULL;
    bool ok = text && strstr(text, "complete=1\n") &&
              shape_session_value(text, "epoch", epoch) &&
              strcmp(epoch, shape->epoch) == 0 &&
              shape_session_value(text, "compiler_id", compiler) &&
              shape_session_value(text, "flags_sha256", flags);
    free(text);
    if (!ok)
        return shape_unbound(shape, "NO_BASELINE", shape->epoch,
                             "the resident epoch has no completed build session");
    if (!shape->compiler_id || strcmp(compiler, shape->compiler_id) != 0)
        return shape_unbound(shape, "TOOLCHAIN_CHANGED", compiler,
                             "the resident objects were built by another "
                             "compiler than the action plan names");
    shape_hash_text(ctx, epoch);
    shape_hash_text(ctx, compiler);
    shape_hash_text(ctx, flags);
    return true;
}

/* ── source paths ────────────────────────────────────────────────────── */

/* `path` relative to the source root, or NULL when it lies outside it. */
static const char *shape_in_root(const char *root, const char *path)
{
    size_t n = strlen(root);
    while (n > 1 && root[n - 1] == '/')
        n--;
    if (path[0] != '/')
        return path;
    return strncmp(path, root, n) == 0 && path[n] == '/' ? path + n + 1
                                                         : NULL;
}

/* Drops the last segment of out[0..*n). False when there is none. */
static bool shape_pop(char *out, size_t *n)
{
    if (*n == 0)
        return false;
    while (*n > 0 && out[*n - 1] != '/')
        (*n)--;
    if (*n > 0)
        (*n)--;
    return true;
}

/* Collapses "." and ".." segments of a relative path; false when it
 * escapes its base or does not fit. */
static bool shape_collapse(const char *p, char *out, size_t cap)
{
    size_t n = 0;
    while (*p) {
        size_t len = strcspn(p, "/");
        const char *seg = p;
        p += len + (p[len] == '/');
        bool dot = len == 1 && seg[0] == '.';
        bool up = len == 2 && seg[0] == '.' && seg[1] == '.';
        if (up && !shape_pop(out, &n))
            return false;
        if (len == 0 || dot || up)
            continue;
        if (n + 1 + len >= cap)
            return false;
        if (n)
            out[n++] = '/';
        memcpy(out + n, seg, len);
        n += len;
    }
    out[n] = 0;
    return n > 0;
}

/* `path` as a collapsed root-relative path; false when outside the root. */
static bool shape_normal(const char *root, const char *path, char *out,
                         size_t cap)
{
    const char *rel = shape_in_root(root, path);
    return rel && shape_collapse(rel, out, cap);
}

/* The epoch's current build object (`ext` ".o" or ".d") of `tu`. */
static bool shape_epoch_path(const struct zcl_hotfork_shape *shape,
                             const char *tu, const char *ext, char *out,
                             size_t cap)
{
    size_t n = strlen(tu);
    return n > 2 && strcmp(tu + n - 2, ".c") == 0 &&
           snprintf(out, cap, "%s/build/dev-obj/epochs/%s/%.*s%s",
                    shape->root, shape->epoch, (int)(n - 2), tu, ext) <
               (int)cap;
}

static bool shape_kept_dir(const struct zcl_hotfork_shape *shape, char *out,
                           size_t cap)
{
    return snprintf(out, cap, "%s/build/hotswap-fast/resident/%s", shape->root,
                    shape->image) < (int)cap;
}

/* The build object of `tu` the running image was linked from, as kept for
 * this image (see shape_bind_tu): one flat file per TU, '/' as '%'. */
static bool shape_object_path(const struct zcl_hotfork_shape *shape,
                              const char *tu, const char *ext, char *out,
                              size_t cap)
{
    char dir[PATH_MAX], flat[ZCL_HOTFORK_UNITY_TU_MAX];
    size_t n = strlen(tu);
    if (n <= 2 || n >= sizeof(flat) || strcmp(tu + n - 2, ".c") != 0 ||
        strchr(tu, '%') || !shape_kept_dir(shape, dir, sizeof(dir)))
        return false;
    for (size_t i = 0; i <= n; i++)
        flat[i] = tu[i] == '/' ? '%' : tu[i];
    return snprintf(out, cap, "%s/%.*s%s", dir, (int)(n - 2), flat, ext) <
           (int)cap;
}

static size_t shape_edit_tu_count(const struct zcl_hotfork_shape *shape)
{
    return 1 + zcl_hotfork_tu_list_count(shape->sibling_tus);
}

/* TU `index` of the capsule: the owner, each sibling, then each source the
 * story adapter includes. */
static bool shape_tu_at(const struct zcl_hotfork_shape *shape, size_t index,
                        char *out, size_t cap)
{
    size_t edits = shape_edit_tu_count(shape);
    if (index == 0)
        return snprintf(out, cap, "%s", shape->source_tu) < (int)cap;
    if (index < edits)
        return zcl_hotfork_tu_list_at(shape->sibling_tus, index - 1, out, cap);
    return zcl_hotfork_tu_list_at(shape->adapter_tus, index - edits, out, cap);
}

static size_t shape_tu_count(const struct zcl_hotfork_shape *shape)
{
    return shape_edit_tu_count(shape) +
           zcl_hotfork_tu_list_count(shape->adapter_tus);
}

/* True when `rel` is one of the capsule's first `limit` TUs. */
static bool shape_tu_among(const struct zcl_hotfork_shape *shape,
                           const char *rel, size_t limit)
{
    for (size_t i = 0; i < limit; i++) {
        char tu[ZCL_HOTFORK_UNITY_TU_MAX];
        if (shape_tu_at(shape, i, tu, sizeof(tu)) && strcmp(tu, rel) == 0)
            return true;
    }
    return false;
}

/* True for the owner and its siblings: the files the edit may touch. */
static bool shape_is_edit_tu(const struct zcl_hotfork_shape *shape,
                             const char *rel)
{
    return shape_tu_among(shape, rel, shape_edit_tu_count(shape));
}

/* Appends the adapter's `#include "<dir>/<len bytes>"` source. */
static bool shape_adapter_tu_add(struct zcl_hotfork_shape *shape,
                                 const char *story, const char *inc,
                                 size_t len)
{
    char joined[PATH_MAX], tu[ZCL_HOTFORK_UNITY_TU_MAX];
    const char *slash = strrchr(story, '/');
    size_t used = strlen(shape->adapter_tus);
    int dir = slash ? (int)(slash - story) : 0;
    if (zcl_hotfork_tu_list_count(shape->adapter_tus) >= SHAPE_ADAPTER_TU_MAX ||
        snprintf(joined, sizeof(joined), "%.*s%s%.*s", dir, story,
                 dir ? "/" : "", (int)len, inc) >= (int)sizeof(joined) ||
        !shape_collapse(joined, tu, sizeof(tu)))
        return false;
    return snprintf(shape->adapter_tus + used, sizeof(shape->adapter_tus) - used,
                    "%s%s", used ? "|" : "", tu) <
           (int)(sizeof(shape->adapter_tus) - used);
}

/* Every `#include "….c"` in the story adapter is a capsule TU too. */
static bool shape_adapter_tus(struct zcl_hotfork_shape *shape)
{
    static const char directive[] = "#include \"";
    char story[ZCL_HOTFORK_UNITY_TU_MAX], path[PATH_MAX];
    char *text = zcl_hotfork_story_path(shape->adapter_id, story,
                                        sizeof(story)) &&
                         snprintf(path, sizeof(path), "%s/%s", shape->root,
                                  story) < (int)sizeof(path)
                     ? shape_slurp(path, SHAPE_TEXT_MAX, NULL) : NULL;
    bool ok = text != NULL;
    for (const char *p = text; ok && (p = strstr(p, directive)) != NULL;) {
        p += sizeof(directive) - 1;
        size_t len = strcspn(p, "\"\n");
        if (len > 2 && p[len] == '"' && memcmp(p + len - 2, ".c", 2) == 0)
            ok = shape_adapter_tu_add(shape, story, p, len);
        p += len;
    }
    free(text);
    return ok || shape_unbound(shape, "NO_BASELINE",
                               shape->adapter_id ? shape->adapter_id : "-",
                               "the story adapter or a source it includes "
                               "does not resolve");
}

/* Removes the files of one kept-object directory, then the directory. */
static void shape_remove_kept(const char *dir)
{
    DIR *d = opendir(dir);
    for (struct dirent *e = d ? readdir(d) : NULL; e; e = readdir(d)) {
        char path[PATH_MAX];
        if (e->d_name[0] != '.' &&
            snprintf(path, sizeof(path), "%s/%s", dir, e->d_name) <
                (int)sizeof(path))
            (void)unlink(path);
    }
    if (d)
        closedir(d);
    (void)rmdir(dir);
}

/* Drops every kept-object directory under `parent` except `keep`'s. */
static void shape_kept_prune(const char *parent, const char *keep)
{
    DIR *d = opendir(parent);
    for (struct dirent *e = d ? readdir(d) : NULL; e; e = readdir(d)) {
        char other[PATH_MAX];
        if (e->d_name[0] != '.' && strcmp(e->d_name, keep) != 0 &&
            snprintf(other, sizeof(other), "%s/%s", parent, e->d_name) <
                (int)sizeof(other))
            shape_remove_kept(other);
    }
    if (d)
        closedir(d);
}

/* The kept-object directory of the running image exists; the first save
 * under a new image drops every other image's directory. */
static bool shape_kept_ready(struct zcl_hotfork_shape *shape)
{
    static const char *const levels[] = {"build", "build/hotswap-fast",
                                         "build/hotswap-fast/resident"};
    char path[PATH_MAX], dir[PATH_MAX];
    bool ok = shape_kept_dir(shape, dir, sizeof(dir));
    for (size_t i = 0; ok && i < sizeof(levels) / sizeof(levels[0]); i++)
        ok = snprintf(path, sizeof(path), "%s/%s", shape->root, levels[i]) <
                 (int)sizeof(path) &&
             (mkdir(path, 0700) == 0 || errno == EEXIST);
    bool created = ok && mkdir(dir, 0700) == 0;
    if (created)
        shape_kept_prune(path, shape->image);
    return created || (ok && errno == EEXIST) ||
           shape_unbound(shape, "RECORD_UNWRITABLE", "build/hotswap-fast/resident",
                         "the resident's build objects cannot be kept for "
                         "the running image");
}

/* `to` names the same file as `from`: a hard link, replaced atomically. */
static bool shape_link_current(const char *from, const char *to)
{
    static atomic_uint seq;
    struct stat a, b;
    char tmp[PATH_MAX];
    if (stat(from, &a) == 0 && stat(to, &b) == 0 && a.st_dev == b.st_dev &&
        a.st_ino == b.st_ino)
        return true;
    if (snprintf(tmp, sizeof(tmp), "%s.%ld.%u.tmp", to, (long)getpid(),
                 atomic_fetch_add(&seq, 1u)) >= (int)sizeof(tmp))
        return false;
    bool ok = link(from, tmp) == 0 && rename(tmp, to) == 0;
    if (!ok)
        (void)unlink(tmp);
    return ok;
}

static bool shape_ts_after(const struct timespec *a, const struct timespec *b)
{
    return a->tv_sec > b->tv_sec ||
           (a->tv_sec == b->tv_sec && a->tv_nsec > b->tv_nsec);
}

/* "<kept object>.built": the object's device, inode and build time. */
static bool shape_built_path(const char *kept, char *out, size_t cap)
{
    return snprintf(out, cap, "%s.built", kept) < (int)cap;
}

/* Records `st` (the epoch object, stated before it is linked) as the kept
 * object's build time: its ctime, which user space cannot set back. The
 * record is taken before the link because link() itself moves the ctime. */
static bool shape_record_built(const char *kept, const struct stat *st)
{
    static atomic_uint seq;
    char path[PATH_MAX], tmp[PATH_MAX], text[128];
    int n = snprintf(text, sizeof(text), "%llu %llu %lld %ld\n",
                     (unsigned long long)st->st_dev,
                     (unsigned long long)st->st_ino,
                     (long long)st->st_ctim.tv_sec, (long)st->st_ctim.tv_nsec);
    if (!shape_built_path(kept, path, sizeof(path)) ||
        snprintf(tmp, sizeof(tmp), "%s.%ld.%u.tmp", path, (long)getpid(),
                 atomic_fetch_add(&seq, 1u)) >= (int)sizeof(tmp))
        return false;
    FILE *f = fopen(tmp, "wb");
    bool ok = f && fwrite(text, 1, (size_t)n, f) == (size_t)n;
    if (f && fclose(f) != 0)
        ok = false;
    ok = ok && rename(tmp, path) == 0;
    if (!ok)
        (void)unlink(tmp);
    return ok;
}

static bool shape_built_numbers(char fields[4][128],
                                unsigned long long *dev,
                                unsigned long long *ino,
                                long long *sec, long *nsec)
{
    char *end;
    *dev = 0;
    *ino = 0;
    *sec = 0;
    *nsec = 0;
    if (fields[0][0] == '-' || fields[1][0] == '-') return false;
    errno = 0;
    *dev = strtoull(fields[0], &end, 10);
    if (errno == ERANGE || end == fields[0] || *end) return false;
    errno = 0;
    *ino = strtoull(fields[1], &end, 10);
    if (errno == ERANGE || end == fields[1] || *end) return false;
    errno = 0;
    *sec = strtoll(fields[2], &end, 10);
    if (errno == ERANGE || end == fields[2] || *end) return false;
    errno = 0;
    *nsec = strtol(fields[3], &end, 10);
    return errno != ERANGE && end != fields[3] && !*end;
}

/* The build time recorded for the kept object `kept` (stated as `st`);
 * false when there is no record or it names another file. */
static bool shape_read_built(const char *kept, const struct stat *st,
                             struct timespec *built)
{
    *built = (struct timespec){0};
    char path[PATH_MAX];
    unsigned long long dev = 0, ino = 0;
    long long sec = 0;
    long nsec = 0;
    size_t len = 0;
    int used = 0;
    char fields[4][128];
    char *text = shape_built_path(kept, path, sizeof(path))
                     ? shape_slurp(path, 128, &len) : NULL;
    bool ok = text && sscanf(text, "%127s %127s %127s %127s%n",
                             fields[0], fields[1], fields[2], fields[3],
                             &used) == 4 &&
              ((size_t)used == len ||
               ((size_t)used + 1 == len && text[used] == '\n')) &&
              shape_built_numbers(fields, &dev, &ino, &sec, &nsec) &&
              nsec >= 0 && nsec < 1000000000 && (long long)(time_t)sec == sec &&
              dev == (unsigned long long)st->st_dev &&
              ino == (unsigned long long)st->st_ino;
    free(text);
    if (ok)
        *built = (struct timespec){.tv_sec = (time_t)sec, .tv_nsec = nsec};
    return ok;
}

#if defined(ZCL_TESTING)
/* Exercise the stored timestamp reader without a running-image clock. */
bool zcl_hotfork_shape_test_read_built(const char *kept, const struct stat *st,
                                      struct timespec *built);
bool zcl_hotfork_shape_test_read_built(const char *kept, const struct stat *st,
                                      struct timespec *built)
{
    return shape_read_built(kept, st, built);
}
#endif

/* Keeps the epoch object (stated as `st`) and its depfile for the running
 * image, recording the object's build time first when it is newly kept. */
static bool shape_keep(const char *obj, const struct stat *st,
                       const char *kept, const char *dep,
                       const char *kept_dep)
{
    struct stat k;
    bool same = stat(kept, &k) == 0 && k.st_dev == st->st_dev &&
                k.st_ino == st->st_ino;
    return (same || (shape_record_built(kept, st) &&
                     shape_link_current(obj, kept))) &&
           shape_link_current(dep, kept_dep);
}

/* The resident object of one TU and its depfile. The epoch's object and
 * depfile must exist. While the object is no newer than the running image
 * it is the image's input and is kept for this image (hard links); zcc
 * republishes a rebuilt object under a new inode, so after the proof ladder
 * recompiles the TU the kept object is still the one the image was linked
 * from and stays the baseline. An object changed in place after the image
 * linked, or rebuilt before anything was kept, is stale. */
static bool shape_bind_tu(struct zcl_hotfork_shape *shape, const char *tu,
                          const struct stat *resident, struct sha3_256_ctx *ctx)
{
    char obj[PATH_MAX], dep[PATH_MAX], kept[PATH_MAX], kept_dep[PATH_MAX];
    struct stat st, dst;
    if (!shape_epoch_path(shape, tu, ".o", obj, sizeof(obj)) ||
        !shape_regular(obj, &st))
        return shape_unbound(shape, "NO_BASELINE", tu,
                             "the resident build object for this TU is missing");
    if (!shape_epoch_path(shape, tu, ".d", dep, sizeof(dep)) ||
        !shape_regular(dep, &dst))
        return shape_unbound(shape, "NO_BASELINE", tu,
                             "the resident build object's depfile is missing");
    if (!shape_object_path(shape, tu, ".o", kept, sizeof(kept)) ||
        !shape_object_path(shape, tu, ".d", kept_dep, sizeof(kept_dep)))
        return shape_unbound(shape, "NO_BASELINE", tu,
                             "the TU has no kept-object path");
    if (!shape_newer(&st, resident) &&
        !shape_keep(obj, &st, kept, dep, kept_dep))
        return shape_unbound(shape, "RECORD_UNWRITABLE", tu,
                             "the resident build object cannot be kept for "
                             "the running image");
    if (!shape_regular(kept, &st) || !shape_regular(kept_dep, &dst) ||
        shape_newer(&st, resident))
        return shape_unbound(shape, "RESIDENT_STALE", tu,
                             "the resident build object is newer than the "
                             "running image; restart the resident");
    shape_hash_stat(ctx, tu, &st);
    shape_hash_stat(ctx, kept_dep, &dst);
    return true;
}

static bool shape_bind_objects(struct zcl_hotfork_shape *shape,
                               const struct stat *resident,
                               struct sha3_256_ctx *ctx)
{
    size_t count = shape_tu_count(shape);
    for (size_t i = 0; i < count; i++) {
        char tu[ZCL_HOTFORK_UNITY_TU_MAX];
        if (!shape_tu_at(shape, i, tu, sizeof(tu)))
            return shape_unbound(shape, "NO_BASELINE", shape->source_tu,
                                 "a capsule TU does not resolve");
        if (!shape_bind_tu(shape, tu, resident, ctx))
            return false;
    }
    return true;
}

static void shape_toolchain(struct zcl_hotfork_shape *shape)
{
    struct sha3_256_ctx ctx;
    sha3_256_init(&ctx);
    shape_hash_text(&ctx, "zcl.hotfork_shape_toolchain.v1");
    shape_hash_text(&ctx, shape->cc ? shape->cc : "");
    shape_hash_text(&ctx, shape->compiler_id ? shape->compiler_id : "");
    shape_hash_text(&ctx, shape->cflags ? shape->cflags : "");
    shape_hex_root(&ctx, shape->toolchain);
}

static void shape_begin_linux(struct zcl_hotfork_shape *shape, const char *root,
                              const char *source_tu, const char *sibling_tus,
                              const char *adapter_id, const char *cc,
                              const char *compiler_id, const char *cflags)
{
    memset(shape, 0, sizeof(*shape));
    shape->root = root;
    shape->source_tu = source_tu;
    shape->sibling_tus = sibling_tus;
    shape->adapter_id = adapter_id;
    shape->cc = cc;
    shape->compiler_id = compiler_id;
    shape->cflags = cflags;
    (void)snprintf(shape->generation, sizeof(shape->generation), "unbound");
    shape_toolchain(shape);
    struct sha3_256_ctx ctx;
    struct stat resident;
    sha3_256_init(&ctx);
    shape_hash_text(&ctx, "zcl.hotfork_shape_generation.v1");
    if (!root || !source_tu) {
        (void)shape_unbound(shape, "NO_BASELINE", "-", "no capsule named");
        return;
    }
    if (!shape_resident_stat(&resident)) {
        (void)shape_unbound(shape, "RESIDENT_UNREADABLE", "running image",
                            "the running image cannot be identified");
        return;
    }
    shape_hash_stat(&ctx, "resident", &resident);
    (void)snprintf(shape->image, sizeof(shape->image), "%llx-%llx-%llx-%llx.%09ld",
                   (unsigned long long)resident.st_dev,
                   (unsigned long long)resident.st_ino,
                   (unsigned long long)resident.st_size,
                   (unsigned long long)resident.st_mtim.tv_sec,
                   (long)resident.st_mtim.tv_nsec);
    if (shape_read_epoch(shape) && shape_read_session(shape, &ctx) &&
        shape_adapter_tus(shape) && shape_kept_ready(shape) &&
        shape_bind_objects(shape, &resident, &ctx))
        shape_hex_root(&ctx, shape->generation);
}

/* ── ELF64 reader ────────────────────────────────────────────────────── */

static unsigned char shape_host_data(void)
{
    const uint16_t probe = 1;
    return *(const unsigned char *)&probe ? ELFDATA2LSB : ELFDATA2MSB;
}

static void *shape_pread(int fd, uint64_t off, uint64_t len, uint64_t size)
{
    if (len == 0 || len > SHAPE_SECTION_MAX || off > size || len > size - off)
        return NULL;
    unsigned char *buf = zcl_malloc((size_t)len + 1, "HOT_FORK shape ELF section");
    size_t got = 0;
    while (buf && got < len) {
        ssize_t n = pread(fd, buf + got, (size_t)(len - got),
                          (off_t)(off + got));
        if (n < 0 && errno == EINTR)
            continue;
        if (n <= 0) {
            free(buf);
            return NULL;
        }
        got += (size_t)n;
    }
    if (buf)
        buf[len] = 0;
    return buf;
}

static void shape_elf_close(struct shape_elf *e)
{
    if (e->fd >= 0)
        (void)close(e->fd);
    free(e->sh);
    free(e->shstr);
    free(e->sym);
    free(e->str);
    memset(e, 0, sizeof(*e));
    e->fd = -1;
}

static bool shape_ehdr_valid(const Elf64_Ehdr *eh, uint64_t size)
{
    return memcmp(eh->e_ident, ELFMAG, SELFMAG) == 0 &&
           eh->e_ident[EI_CLASS] == ELFCLASS64 &&
           eh->e_ident[EI_DATA] == shape_host_data() &&
           eh->e_ident[EI_VERSION] == EV_CURRENT &&
           eh->e_shentsize == sizeof(Elf64_Shdr) && eh->e_shoff <= size &&
           (uint64_t)eh->e_shnum * sizeof(Elf64_Shdr) <= size - eh->e_shoff &&
           (eh->e_shnum == 0 || eh->e_shstrndx < eh->e_shnum);
}

/* The one SHT_SYMTAB; NULL with *bad set when the table is malformed or
 * extended section indices are in use (not supported: refuse). */
static const Elf64_Shdr *shape_find_symtab(const struct shape_elf *e,
                                           unsigned type, bool *bad)
{
    const Elf64_Shdr *symtab = NULL;
    for (size_t i = 0; i < e->eh.e_shnum; i++) {
        if (e->sh[i].sh_type == SHT_SYMTAB_SHNDX ||
            (e->sh[i].sh_type == type && symtab))
            *bad = true;
        if (e->sh[i].sh_type == type)
            symtab = &e->sh[i];
    }
    return *bad ? NULL : symtab;
}

static bool shape_load_names(struct shape_elf *e)
{
    const Elf64_Shdr *names = &e->sh[e->eh.e_shstrndx];
    if (names->sh_type != SHT_STRTAB)
        return false;
    e->shstr = shape_pread(e->fd, names->sh_offset, names->sh_size, e->size);
    e->shstr_len = (size_t)names->sh_size;
    return e->shstr != NULL;
}

static enum shape_read shape_load_symtab(struct shape_elf *e, bool names,
                                        unsigned type)
{
    bool bad = false;
    const Elf64_Shdr *symtab = shape_find_symtab(e, type, &bad);
    if (bad)
        return SHAPE_READ_UNREADABLE;
    if (!symtab)
        return SHAPE_READ_NO_SYMTAB;
    if (symtab->sh_entsize != sizeof(Elf64_Sym) ||
        symtab->sh_size % sizeof(Elf64_Sym) != 0 ||
        symtab->sh_link >= e->eh.e_shnum ||
        e->sh[symtab->sh_link].sh_type != SHT_STRTAB)
        return SHAPE_READ_UNREADABLE;
    const Elf64_Shdr *strs = &e->sh[symtab->sh_link];
    e->strndx = symtab->sh_link;
    e->sym = shape_pread(e->fd, symtab->sh_offset, symtab->sh_size, e->size);
    e->nsym = (size_t)(symtab->sh_size / sizeof(Elf64_Sym));
    e->str = shape_pread(e->fd, strs->sh_offset, strs->sh_size, e->size);
    e->str_len = (size_t)strs->sh_size;
    bool ok = e->sym && e->str && (!names || shape_load_names(e));
    return ok ? SHAPE_READ_OK : SHAPE_READ_UNREADABLE;
}

/* Opens one ELF64 file of the host byte order with its `type` symbol table
 * (SHT_SYMTAB or SHT_DYNSYM). `names` also loads section names. */
static enum shape_read shape_elf_open_as(struct shape_elf *e, const char *path,
                                         bool names, unsigned type)
{
    struct stat st;
    memset(e, 0, sizeof(*e));
    e->fd = open(path, O_RDONLY | O_CLOEXEC);
    if (e->fd < 0 || fstat(e->fd, &st) != 0 || !S_ISREG(st.st_mode) ||
        st.st_size < (off_t)sizeof(Elf64_Ehdr))
        return SHAPE_READ_UNREADABLE;
    e->size = (uint64_t)st.st_size;
    if (pread(e->fd, &e->eh, sizeof(e->eh), 0) != (ssize_t)sizeof(e->eh) ||
        !shape_ehdr_valid(&e->eh, e->size))
        return SHAPE_READ_UNREADABLE;
    if (e->eh.e_shnum == 0)
        return SHAPE_READ_NO_SYMTAB;
    e->sh = shape_pread(e->fd, e->eh.e_shoff,
                        (uint64_t)e->eh.e_shnum * sizeof(Elf64_Shdr), e->size);
    return e->sh ? shape_load_symtab(e, names, type) : SHAPE_READ_UNREADABLE;
}

static enum shape_read shape_elf_open(struct shape_elf *e, const char *path,
                                      bool names)
{
    return shape_elf_open_as(e, path, names, SHT_SYMTAB);
}

static bool shape_open_refuse(enum shape_read got, const char *subject,
                              char *why, size_t why_len)
{
    if (got == SHAPE_READ_NO_SYMTAB)
        return shape_refuse(why, why_len, "SYMTAB_MISSING", subject,
                            "the ELF object has no symbol table");
    return shape_refuse(why, why_len, "OBJECT_UNREADABLE", subject,
                        "the ELF object cannot be read or parsed");
}

static const char *shape_sym_name(const struct shape_elf *e,
                                  const Elf64_Sym *s)
{
    return s->st_name < e->str_len ? e->str + s->st_name : NULL;
}

static const char *shape_section_name(const struct shape_elf *e,
                                      const Elf64_Shdr *sec)
{
    return e->shstr && sec->sh_name < e->shstr_len ? e->shstr + sec->sh_name
                                                   : NULL;
}

/* ── shape of one relocatable object ─────────────────────────────────── */

static bool shape_push(struct shape_set *set, struct shape_sym sym)
{
    if (set->count == set->cap) {
        size_t cap = set->cap ? set->cap * 2 : 256;
        struct shape_sym *grown =
            zcl_realloc(set->items, cap * sizeof(*grown), "HOT_FORK shape set");
        if (!grown)
            return false;
        set->items = grown;
        set->cap = cap;
    }
    set->items[set->count++] = sym;
    return true;
}

static bool shape_is_global(const Elf64_Sym *s)
{
    unsigned bind = ELF64_ST_BIND(s->st_info);
    unsigned type = ELF64_ST_TYPE(s->st_info);
    return (bind == STB_GLOBAL || bind == STB_WEAK || bind == STB_GNU_UNIQUE) &&
           s->st_shndx != SHN_UNDEF && type != STT_FILE &&
           type != STT_SECTION;
}

/* SHAPE_DATA / SHAPE_TLS for writable, thread-local or common objects;
 * SHAPE_GLOBAL (meaning "not state") otherwise. */
static enum shape_kind shape_state_kind(const struct shape_elf *e,
                                        const Elf64_Sym *s)
{
    unsigned type = ELF64_ST_TYPE(s->st_info);
    if (s->st_shndx == SHN_COMMON || type == STT_COMMON)
        return SHAPE_DATA;
    if ((type != STT_OBJECT && type != STT_TLS) ||
        s->st_shndx == SHN_UNDEF || s->st_shndx >= e->eh.e_shnum)
        return SHAPE_GLOBAL;
    const Elf64_Shdr *sec = &e->sh[s->st_shndx];
    if (sec->sh_flags & SHF_TLS)
        return SHAPE_TLS;
    if (!(sec->sh_flags & SHF_WRITE))
        return SHAPE_GLOBAL;
    const char *name = shape_section_name(e, sec);
    return name && strncmp(name, ".data.rel.ro", 12) == 0 ? SHAPE_GLOBAL
                                                         : SHAPE_DATA;
}

/* A local static's name without its compiler-numbered ".N" suffixes. */
static size_t shape_canonical_len(const char *name, bool local)
{
    size_t n = strlen(name);
    while (local) {
        size_t d = n;
        while (d > 0 && name[d - 1] >= '0' && name[d - 1] <= '9')
            d--;
        if (d == n || d < 2 || name[d - 1] != '.')
            break;
        n = d - 1;
    }
    return n;
}

static void shape_note_init_fini(const struct shape_elf *e,
                                 struct shape_set *set)
{
    for (size_t i = 0; i < e->eh.e_shnum && !set->init_fini[0]; i++) {
        const char *name = shape_section_name(e, &e->sh[i]);
        unsigned type = e->sh[i].sh_type;
        bool hit = type == SHT_INIT_ARRAY || type == SHT_FINI_ARRAY ||
                   type == SHT_PREINIT_ARRAY;
        for (size_t k = 0; !hit && name && k < sizeof(k_shape_init_fini) /
                                               sizeof(k_shape_init_fini[0]); k++)
            hit = strncmp(name, k_shape_init_fini[k],
                          strlen(k_shape_init_fini[k])) == 0;
        if (hit)
            (void)snprintf(set->init_fini, sizeof(set->init_fini), "%s",
                           name ? name : "(init/fini)");
    }
}

/* Counts one relocation at `at` in section `shndx` against the state entry
 * of this object that holds it; a relocation outside every state object
 * (padding, anonymous data) belongs to no entry. */
static void shape_attribute(struct shape_set *set, size_t first, size_t shndx,
                            uint64_t at)
{
    for (size_t j = first; j < set->count; j++) {
        struct shape_sym *s = &set->items[j];
        if (s->kind != SHAPE_GLOBAL && s->shndx == shndx && at >= s->value &&
            at - s->value < s->size) {
            s->relocs++;
            return;
        }
    }
}

static bool shape_section_relocs(const struct shape_elf *e,
                                 const Elf64_Shdr *rs, struct shape_set *set,
                                 size_t first)
{
    size_t entsize = rs->sh_type == SHT_RELA ? sizeof(Elf64_Rela)
                                             : sizeof(Elf64_Rel);
    if (rs->sh_entsize != entsize || rs->sh_size % entsize != 0)
        return false;
    if (rs->sh_size == 0)
        return true;
    unsigned char *raw = shape_pread(e->fd, rs->sh_offset, rs->sh_size, e->size);
    if (!raw)
        return false;
    for (uint64_t off = 0; off < rs->sh_size; off += entsize) {
        uint64_t at; /* r_offset leads both Elf64_Rel and Elf64_Rela */
        memcpy(&at, raw + off, sizeof(at));
        shape_attribute(set, first, rs->sh_info, at);
    }
    free(raw);
    return true;
}

/* Relocations applied inside writable or thread-local sections: the
 * pointers an object's initializer holds. */
static bool shape_count_relocs(const struct shape_elf *e,
                               struct shape_set *set, size_t first)
{
    for (size_t i = 0; i < e->eh.e_shnum; i++) {
        const Elf64_Shdr *rs = &e->sh[i];
        if ((rs->sh_type != SHT_RELA && rs->sh_type != SHT_REL) ||
            rs->sh_info >= e->eh.e_shnum ||
            !(e->sh[rs->sh_info].sh_flags & (SHF_WRITE | SHF_TLS)))
            continue;
        if (!shape_section_relocs(e, rs, set, first))
            return false;
    }
    return true;
}

static bool shape_collect(const struct shape_elf *e, struct shape_set *set)
{
    size_t first = set->count;
    for (size_t i = 1; i < e->nsym; i++) {
        const Elf64_Sym *s = &e->sym[i];
        const char *name = shape_sym_name(e, s);
        if (!name || !name[0])
            continue;
        enum shape_kind state = shape_state_kind(e, s);
        bool local = ELF64_ST_BIND(s->st_info) == STB_LOCAL;
        struct shape_sym sym = { .name = name, .len = strlen(name),
                                 .size = s->st_size, .kind = SHAPE_GLOBAL };
        if (shape_is_global(s) && !shape_push(set, sym))
            return false;
        sym.len = shape_canonical_len(name, local);
        sym.kind = state;
        sym.value = s->st_value;
        sym.shndx = s->st_shndx;
        if (state != SHAPE_GLOBAL && !shape_push(set, sym))
            return false;
    }
    shape_note_init_fini(e, set);
    return shape_count_relocs(e, set, first);
}

/* The candidate's undefined references, by name. */
static bool shape_collect_undefined(const struct shape_elf *e,
                                    struct shape_set *set)
{
    for (size_t i = 1; i < e->nsym; i++) {
        const Elf64_Sym *s = &e->sym[i];
        const char *name = shape_sym_name(e, s);
        unsigned bind = ELF64_ST_BIND(s->st_info);
        unsigned type = ELF64_ST_TYPE(s->st_info);
        if (!name || !name[0] || s->st_shndx != SHN_UNDEF ||
            (bind != STB_GLOBAL && bind != STB_WEAK) || type == STT_SECTION ||
            type == STT_FILE)
            continue;
        struct shape_sym sym = { .name = name, .len = strlen(name),
                                 .kind = SHAPE_GLOBAL };
        if (!shape_push(set, sym))
            return false;
    }
    return true;
}

static int shape_cmp(const void *pa, const void *pb)
{
    const struct shape_sym *a = pa, *b = pb;
    if (a->kind != b->kind)
        return a->kind < b->kind ? -1 : 1;
    int c = memcmp(a->name, b->name, a->len < b->len ? a->len : b->len);
    if (c != 0)
        return c;
    if (a->len != b->len)
        return a->len < b->len ? -1 : 1;
    if (a->kind == SHAPE_GLOBAL)
        return 0;
    if (a->size != b->size)
        return a->size < b->size ? -1 : 1;
    if (a->relocs != b->relocs)
        return a->relocs < b->relocs ? -1 : 1;
    return 0;
}

/* ── baseline objects and the running image ──────────────────────────── */

static bool shape_load_baseline(struct shape_run *run, char *why,
                                size_t why_len)
{
    size_t count = shape_tu_count(run->shape);
    for (size_t i = 0; i < count; i++) {
        char tu[ZCL_HOTFORK_UNITY_TU_MAX], path[PATH_MAX];
        if (!shape_tu_at(run->shape, i, tu, sizeof(tu)) ||
            !shape_object_path(run->shape, tu, ".o", path, sizeof(path)))
            return shape_refuse(why, why_len, "NO_BASELINE", tu,
                                "the resident build object path does not resolve");
        enum shape_read got = shape_elf_open(&run->objects[i], path, true);
        run->object_count = i + 1;
        if (got != SHAPE_READ_OK || run->objects[i].eh.e_type != ET_REL)
            return shape_open_refuse(got == SHAPE_READ_OK ? SHAPE_READ_UNREADABLE
                                                          : got,
                                     tu, why, why_len);
        if (!shape_collect(&run->objects[i], &run->base))
            return shape_refuse(why, why_len, "OBJECT_UNREADABLE", tu,
                                "the object's symbols or relocations cannot be read");
    }
    if (run->base.count > 1)
        qsort(run->base.items, run->base.count, sizeof(run->base.items[0]),
              shape_cmp);
    return true;
}

static uint64_t shape_fnv(const char *name, size_t len)
{
    uint64_t h = 1469598103934665603ull;
    for (size_t i = 0; i < len; i++)
        h = (h ^ (unsigned char)name[i]) * 1099511628211ull;
    return h;
}

/* ── dependency closure and the binding record ───────────────────────── */

/* Length of a backslash line continuation at `in`, 0 when there is none. */
static size_t shape_continuation(const char *in)
{
    if (in[0] != '\\')
        return 0;
    if (in[1] == '\n')
        return 2;
    return in[1] == '\r' && in[2] == '\n' ? 3 : 0;
}

static bool shape_depfile_index(char *text, const char *end, char **deps,
                                size_t *count, size_t max)
{
    size_t n = 0;
    for (char *t = text; t < end && n < max; t += strlen(t) + 1)
        if (*t)
            deps[n++] = t;
    *count = n;
    return n > 0 && n < max;
}

/* Splits the first rule of a make depfile into its prerequisite paths, in
 * place, one NUL between paths; the target and its ':' are dropped, a
 * backslash-newline is a separator, a backslash-space is a space inside a
 * path, and the rule ends at its first bare newline (any -MP phony rules
 * after it name no new prerequisite). */
static bool shape_depfile_split(char *text, char **deps, size_t *count,
                                size_t max)
{
    char *colon = text ? strchr(text, ':') : NULL;
    if (!colon)
        return false;
    char *out = text;
    for (const char *in = colon + 1; *in && *in != '\n'; in++) {
        size_t joined = shape_continuation(in);
        bool escaped = in[0] == '\\' && in[1] == ' ';
        in += joined ? joined - 1 : escaped;
        char c = joined || (!escaped && strchr(" \t\r", *in)) ? 0 : *in;
        if (c != 0 || (out > text && out[-1] != 0))
            *out++ = c;
    }
    *out = 0;
    return shape_depfile_index(text, out, deps, count, max);
}

/* Every prerequisite after the first (the generated unity, a fresh temp
 * path on each compile) names the closure. */
static void shape_closure_root(struct shape_run *run)
{
    struct sha3_256_ctx ctx;
    sha3_256_init(&ctx);
    shape_hash_text(&ctx, "zcl.hotfork_shape_closure.v1");
    for (size_t i = 1; i < run->dep_count; i++)
        shape_hash_text(&ctx, run->deps[i]);
    shape_hex_root(&ctx, run->closure);
}

static bool shape_record_path(struct shape_run *run)
{
    size_t n = strlen(run->depfile);
    return n > 2 && strcmp(run->depfile + n - 2, ".d") == 0 &&
           snprintf(run->record, sizeof(run->record), "%.*s.shape",
                    (int)(n - 2), run->depfile) < (int)sizeof(run->record);
}

static bool shape_record_field(const char *text, const char *key,
                               char out[65])
{
    char want[32];
    (void)snprintf(want, sizeof(want), "\n%s=", key);
    const char *at = strstr(text, want);
    if (!at)
        return false;
    at += strlen(want);
    if (strnlen(at, 65) < 65 || at[64] != '\n')
        return false;
    memcpy(out, at, 64);
    out[64] = 0;
    return shape_hex64(out);
}

static bool shape_candidate_deps(struct shape_run *run, char *why,
                                 size_t why_len)
{
    run->deps_text = shape_slurp(run->depfile, 1 << 20, NULL);
    if (!shape_depfile_split(run->deps_text, run->deps, &run->dep_count,
                             SHAPE_DEPS_MAX) ||
        !shape_record_path(run))
        return shape_refuse(why, why_len, "CLOSURE_UNREADABLE", run->depfile,
                            "the candidate's dependency closure cannot be read");
    shape_closure_root(run);
    return true;
}

static bool shape_record_check(struct shape_run *run, char *why,
                               size_t why_len)
{
    struct stat st;
    if (!shape_regular(run->record, &st))
        return true;
    char *text = shape_slurp(run->record, 4096, NULL);
    char generation[65], toolchain[65], closure[65];
    bool ok = text && strncmp(text, "zcl.hotfork_shape_record.v1\n", 28) == 0 &&
              shape_record_field(text, "generation", generation) &&
              shape_record_field(text, "toolchain", toolchain) &&
              shape_record_field(text, "closure", closure);
    free(text);
    if (!ok) {
        (void)unlink(run->record);
        return shape_refuse(why, why_len, "RECORD_UNREADABLE", run->record,
                            "the shape binding record is malformed and was "
                            "discarded");
    }
    if (strcmp(generation, run->shape->generation) != 0)
        return true;
    if (strcmp(toolchain, run->shape->toolchain) != 0)
        return shape_refuse(why, why_len, "TOOLCHAIN_CHANGED", toolchain,
                            "the baseline was bound under another compiler, "
                            "driver or flags than this candidate was built with");
    if (strcmp(closure, run->closure) != 0)
        return shape_refuse(why, why_len, "CLOSURE_CHANGED", closure,
                            "the baseline was bound to another dependency "
                            "closure than this candidate's");
    run->record_current = true;
    return true;
}

static bool shape_record_commit(struct shape_run *run, char *why,
                                size_t why_len)
{
    if (run->record_current)
        return true;
    char tmp[PATH_MAX + 32];
    FILE *f = snprintf(tmp, sizeof(tmp), "%s.%ld.tmp", run->record,
                       (long)getpid()) < (int)sizeof(tmp)
                  ? fopen(tmp, "wb") : NULL;
    bool ok = f && fprintf(f,
                           "zcl.hotfork_shape_record.v1\ngeneration=%s\n"
                           "toolchain=%s\nclosure=%s\n",
                           run->shape->generation, run->shape->toolchain,
                           run->closure) > 0;
    if (f && fclose(f) != 0)
        ok = false;
    ok = ok && rename(tmp, run->record) == 0;
    if (!ok) {
        if (f)
            (void)unlink(tmp);
        return shape_refuse(why, why_len, "RECORD_UNWRITABLE", run->record,
                            "the shape binding record could not be written");
    }
    return true;
}

/* ── header drift ────────────────────────────────────────────────────── */

static int shape_path_cmp(const void *pa, const void *pb)
{
    return strcmp(*(char *const *)pa, *(char *const *)pb);
}

static bool shape_paths_push(struct shape_paths *p, const char *s)
{
    if (p->count == p->cap) {
        size_t cap = p->cap ? p->cap * 2 : 64;
        char **grown = zcl_realloc(p->items, cap * sizeof(*grown),
                                   "HOT_FORK shape paths");
        if (!grown)
            return false;
        p->items = grown;
        p->cap = cap;
    }
    size_t n = strlen(s);
    char *copy = zcl_malloc(n + 1, "HOT_FORK shape path");
    if (!copy)
        return false;
    memcpy(copy, s, n + 1);
    p->items[p->count++] = copy;
    return true;
}

static bool shape_paths_has(const struct shape_paths *p, const char *s)
{
    return p->count &&
           bsearch(&s, p->items, p->count, sizeof(p->items[0]),
                   shape_path_cmp) != NULL;
}

static bool shape_drift(char *why, size_t why_len, const char *subject,
                        const char *detail)
{
    return shape_refuse(why, why_len, "HEADER_DRIFT", subject, detail);
}

/* One prerequisite of a resident object last written at `built`, built at
 * `built_at` (its recorded ctime). A prerequisite is fresh only when its
 * mtime is not newer than the object's and its ctime is not newer than
 * the object's build time: an mtime can be set back (cp -p, touch -d,
 * rsync -t, tar), a ctime cannot. */
static bool shape_resident_dep(struct shape_run *run, const char *dep,
                               const struct stat *built,
                               const struct timespec *built_at, char *why,
                               size_t why_len)
{
    char rel[PATH_MAX], path[PATH_MAX];
    struct stat st;
    if (!shape_normal(run->shape->root, dep, rel, sizeof(rel)))
        return true; /* the toolchain's, bound by the compiler identity */
    if (!shape_paths_push(&run->resident_deps, rel))
        return shape_refuse(why, why_len, "NO_BASELINE", rel,
                            "out of memory recording the resident's inputs");
    if (shape_is_edit_tu(run->shape, rel))
        return true;
    if (snprintf(path, sizeof(path), "%s/%s", run->shape->root, rel) >=
            (int)sizeof(path) ||
        !shape_regular(path, &st))
        return shape_drift(why, why_len, rel,
                           "an input the resident object was built from is gone");
    if (shape_newer(&st, built))
        return shape_drift(why, why_len, rel,
                           "changed after the resident object was built from it");
    return !shape_ts_after(&st.st_ctim, built_at) ||
           shape_drift(why, why_len, rel,
                       "replaced or re-dated after the resident object was "
                       "built from it (its ctime is newer)");
}

/* Every input one resident object's depfile names. */
static bool shape_resident_tu_deps(struct shape_run *run, const char *tu,
                                   char *why, size_t why_len)
{
    char obj[PATH_MAX], dep[PATH_MAX];
    struct stat built = {0};
    struct timespec built_at = {0};
    size_t count = 0;
    if (!shape_object_path(run->shape, tu, ".o", obj, sizeof(obj)) ||
        !shape_regular(obj, &built) ||
        !shape_read_built(obj, &built, &built_at))
        return shape_refuse(why, why_len, "NO_BASELINE", tu,
                            "the resident build object's build time is not "
                            "recorded");
    char **deps = zcl_calloc(SHAPE_DEPS_MAX, sizeof(*deps),
                             "HOT_FORK resident depfile");
    char *text = deps && shape_object_path(run->shape, tu, ".d", dep,
                                           sizeof(dep))
                     ? shape_slurp(dep, 1 << 20, NULL) : NULL;
    bool ok = shape_depfile_split(text, deps, &count, SHAPE_DEPS_MAX);
    if (!ok)
        (void)shape_refuse(why, why_len, "NO_BASELINE", tu,
                           "the resident build object's depfile cannot be read");
    for (size_t i = 0; ok && i < count; i++)
        ok = shape_resident_dep(run, deps[i], &built, &built_at, why, why_len);
    free(deps);
    free(text);
    return ok;
}

/* Every input under the source root the candidate compiled after the owner
 * is one some resident object was built from. Inputs before the owner are
 * the story adapter's phase-1 includes. */
static bool shape_candidate_added(struct shape_run *run, char *why,
                                  size_t why_len)
{
    bool after_owner = false;
    for (size_t i = 1; i < run->dep_count; i++) {
        char rel[PATH_MAX];
        if (!shape_normal(run->shape->root, run->deps[i], rel, sizeof(rel)))
            continue;
        if (!after_owner) {
            after_owner = strcmp(rel, run->shape->source_tu) == 0;
            continue;
        }
        if (!shape_paths_has(&run->resident_deps, rel))
            return shape_drift(why, why_len, rel,
                               "the candidate compiles an input no resident "
                               "object was built from");
    }
    return after_owner ||
           shape_refuse(why, why_len, "CLOSURE_UNREADABLE",
                        run->shape->source_tu,
                        "the owner is not in the candidate's dependency closure");
}

static bool shape_header_check(struct shape_run *run, char *why,
                               size_t why_len)
{
    size_t count = shape_tu_count(run->shape);
    for (size_t i = 0; i < count; i++) {
        char tu[ZCL_HOTFORK_UNITY_TU_MAX];
        if (!shape_tu_at(run->shape, i, tu, sizeof(tu)))
            return shape_refuse(why, why_len, "NO_BASELINE",
                                run->shape->source_tu,
                                "a capsule TU does not resolve");
        if (!shape_resident_tu_deps(run, tu, why, why_len))
            return false;
    }
    if (run->resident_deps.count)
        qsort(run->resident_deps.items, run->resident_deps.count,
              sizeof(run->resident_deps.items[0]), shape_path_cmp);
    return shape_candidate_added(run, why, why_len);
}

/* ── unresolved references ───────────────────────────────────────────── */

struct shape_libs {
    char needed[SHAPE_LIBS_MAX][NAME_MAX + 1]; /* DT_NEEDED basenames */
    size_t count;
    char interp[PATH_MAX];
};

static const char *shape_basename(const char *path)
{
    const char *slash = strrchr(path, '/');
    return slash ? slash + 1 : path;
}

static bool shape_dynamic_needed(const struct shape_elf *img,
                                 const Elf64_Shdr *sec, struct shape_libs *libs)
{
    if (sec->sh_link != img->strndx || sec->sh_entsize != sizeof(Elf64_Dyn))
        return false;
    unsigned char *raw = shape_pread(img->fd, sec->sh_offset, sec->sh_size,
                                     img->size);
    bool ok = raw != NULL;
    for (size_t k = 0; ok && k < sec->sh_size / sizeof(Elf64_Dyn); k++) {
        Elf64_Dyn d;
        memcpy(&d, raw + k * sizeof(d), sizeof(d));
        if (d.d_tag != DT_NEEDED)
            continue;
        ok = d.d_un.d_val < img->str_len && libs->count < SHAPE_LIBS_MAX &&
             snprintf(libs->needed[libs->count], sizeof(libs->needed[0]), "%s",
                      img->str + d.d_un.d_val) < (int)sizeof(libs->needed[0]);
        if (ok)
            libs->count++;
    }
    free(raw);
    return ok;
}

static bool shape_interp(const struct shape_elf *img, const Elf64_Shdr *sec,
                         struct shape_libs *libs)
{
    char *raw = shape_pread(img->fd, sec->sh_offset, sec->sh_size, img->size);
    bool ok = raw && snprintf(libs->interp, sizeof(libs->interp), "%s", raw) <
                         (int)sizeof(libs->interp);
    free(raw);
    return ok;
}

/* The image's DT_NEEDED names (in its dynamic string table) and its
 * program interpreter. */
static bool shape_image_libs(const struct shape_elf *img,
                             struct shape_libs *libs)
{
    bool ok = true;
    for (size_t i = 0; ok && i < img->eh.e_shnum; i++) {
        const Elf64_Shdr *sec = &img->sh[i];
        const char *name = shape_section_name(img, sec);
        if (sec->sh_type == SHT_DYNAMIC)
            ok = shape_dynamic_needed(img, sec, libs);
        else if (name && strcmp(name, ".interp") == 0)
            ok = shape_interp(img, sec, libs);
    }
    return ok;
}

static bool shape_lib_wanted(const struct shape_libs *libs, const char *path)
{
    const char *base = shape_basename(path);
    if (libs->interp[0] && strcmp(base, shape_basename(libs->interp)) == 0)
        return true;
    for (size_t i = 0; i < libs->count; i++)
        if (strcmp(base, libs->needed[i]) == 0)
            return true;
    return false;
}

/* ── the running image's defined names, parsed once per image ────────── */

/* A set of names: a string arena and an open-addressed index of offsets. */
struct shape_names {
    char *arena;
    size_t len;
    size_t cap;
    size_t *slots; /* 1 + arena offset; 0 is empty */
    size_t mask;
    size_t count;
};

static void shape_names_free(struct shape_names *n)
{
    free(n->arena);
    free(n->slots);
    memset(n, 0, sizeof(*n));
}

/* The slot holding `name` (`len` bytes), or the empty slot it would take. */
static size_t shape_names_slot(const size_t *slots, size_t mask,
                               const char *arena, const char *name, size_t len)
{
    size_t at = shape_fnv(name, len) & mask;
    for (; slots[at]; at = (at + 1) & mask) {
        const char *s = arena + slots[at] - 1;
        if (strncmp(s, name, len) == 0 && s[len] == 0)
            break;
    }
    return at;
}

static bool shape_names_has(const struct shape_names *n, const char *name,
                            size_t len)
{
    return n->slots &&
           n->slots[shape_names_slot(n->slots, n->mask, n->arena, name, len)];
}

/* Regrows the index to hold at least `want` names at half load. */
static bool shape_names_rehash(struct shape_names *n, size_t want)
{
    size_t cap = n->slots ? (n->mask + 1) * 2 : 1024;
    while (cap < want * 2)
        cap *= 2;
    size_t *slots = zcl_calloc(cap, sizeof(*slots), "HOT_FORK image names");
    for (size_t i = 0; slots && n->slots && i <= n->mask; i++) {
        if (!n->slots[i])
            continue;
        const char *s = n->arena + n->slots[i] - 1;
        slots[shape_names_slot(slots, cap - 1, n->arena, s, strlen(s))] =
            n->slots[i];
    }
    if (!slots)
        return false;
    free(n->slots);
    n->slots = slots;
    n->mask = cap - 1;
    return true;
}

static bool shape_names_add(struct shape_names *n, const char *name)
{
    size_t len = strlen(name);
    if ((!n->slots || (n->count + 1) * 2 > n->mask + 1) &&
        !shape_names_rehash(n, n->count + 1))
        return false;
    size_t at = shape_names_slot(n->slots, n->mask, n->arena, name, len);
    if (n->slots[at])
        return true;
    if (n->cap - n->len < len + 1) {
        size_t cap = n->cap ? n->cap : 1 << 16;
        while (cap - n->len < len + 1)
            cap *= 2;
        char *grown = zcl_realloc(n->arena, cap, "HOT_FORK image names");
        if (!grown)
            return false;
        n->arena = grown;
        n->cap = cap;
    }
    memcpy(n->arena + n->len, name, len + 1);
    n->slots[at] = n->len + 1;
    n->len += len + 1;
    n->count++;
    return true;
}

enum { SHAPE_IMAGE_SYMTAB, SHAPE_IMAGE_DYNAMIC, SHAPE_IMAGE_KINDS };

/* One image's defined names: SYMTAB its .symtab globals, DYNAMIC its
 * .dynsym plus every library it names as mapped in this process. */
struct shape_image {
    bool valid;
    char path[PATH_MAX];
    struct stat id;
    struct shape_libs libs;
    uint64_t libs_id; /* the mapped libraries' paths and file identities */
    struct shape_names names;
};

static pthread_mutex_t g_shape_image_mu = PTHREAD_MUTEX_INITIALIZER;
static struct shape_image g_shape_images[SHAPE_IMAGE_KINDS];
#ifdef ZCL_TESTING
static unsigned long g_shape_image_parses;
#endif

static uint64_t shape_fold(uint64_t h, const void *bytes, size_t len)
{
    const unsigned char *b = bytes;
    for (size_t i = 0; i < len; i++)
        h = (h ^ b[i]) * 1099511628211ull;
    return h;
}

/* Adds the names `e` defines: with `globals` its defined GLOBAL/WEAK
 * symbols, otherwise every symbol it does not leave undefined. */
static bool shape_add_defined(const struct shape_elf *e, bool globals,
                              struct shape_names *into)
{
    /* One index size for the whole table: no regrowth while adding. */
    bool ok = (into->slots && (into->count + e->nsym) * 2 <= into->mask + 1) ||
              shape_names_rehash(into, into->count + e->nsym);
    for (size_t i = 1; ok && i < e->nsym; i++) {
        const Elf64_Sym *s = &e->sym[i];
        const char *name = shape_sym_name(e, s);
        bool defines = globals ? shape_is_global(s) : s->st_shndx != SHN_UNDEF;
        if (name && name[0] && defines)
            ok = shape_names_add(into, name);
    }
    return ok;
}

/* Folds one mapped library's path and file identity into `*id`; with
 * `into`, also adds the names its dynamic symbol table defines. */
static bool shape_lib_scan(const char *path, struct shape_names *into,
                           uint64_t *id)
{
    struct stat st;
    if (stat(path, &st) != 0)
        return false;
    uint64_t facts[5] = {(uint64_t)st.st_dev, (uint64_t)st.st_ino,
                         (uint64_t)st.st_size, (uint64_t)st.st_mtim.tv_sec,
                         (uint64_t)st.st_mtim.tv_nsec};
    *id = shape_fold(shape_fold(*id, path, strlen(path) + 1), facts,
                     sizeof(facts));
    if (!into)
        return true;
    struct shape_elf lib;
    bool ok = shape_elf_open_as(&lib, path, false, SHT_DYNSYM) ==
                  SHAPE_READ_OK &&
              shape_add_defined(&lib, false, into);
    shape_elf_close(&lib);
    return ok;
}

/* Every library the image names, as this process mapped it (the reflex
 * runner execs the same image): each one's path and identity folds into
 * `*id`, and with `into` the names each defines are added. */
static bool shape_libs_scan(const struct shape_libs *libs,
                            struct shape_names *into, uint64_t *id)
{
    char *maps = os_proc_self_maps_read(4 << 20, NULL);
    const char *last = "";
    bool ok = maps != NULL;
    *id = 1469598103934665603ull;
    for (char *line = maps; ok && line && *line;) {
        char *end = strchr(line, '\n');
        if (end)
            *end = 0;
        const char *path = strchr(line, '/');
        if (path && strcmp(path, last) != 0 && !strstr(path, " (deleted)") &&
            shape_lib_wanted(libs, path)) {
            ok = shape_lib_scan(path, into, id);
            last = path;
        }
        line = end ? end + 1 : NULL;
    }
    free(maps);
    return ok;
}

static enum shape_read shape_image_parse(struct shape_image *im, unsigned kind)
{
    bool dynamic = kind == SHAPE_IMAGE_DYNAMIC;
    struct shape_elf img;
    enum shape_read got = shape_elf_open_as(&img, im->path, dynamic,
                                            dynamic ? SHT_DYNSYM : SHT_SYMTAB);
    bool ok = got == SHAPE_READ_OK &&
              shape_add_defined(&img, !dynamic, &im->names) &&
              (!dynamic || (shape_image_libs(&img, &im->libs) &&
                            shape_libs_scan(&im->libs, &im->names,
                                            &im->libs_id)));
    shape_elf_close(&img);
    if (got != SHAPE_READ_OK)
        return got;
    return ok ? SHAPE_READ_OK : SHAPE_READ_UNREADABLE;
}

static bool shape_same_file(const struct stat *a, const struct stat *b)
{
    return a->st_dev == b->st_dev && a->st_ino == b->st_ino &&
           a->st_size == b->st_size &&
           a->st_mtim.tv_sec == b->st_mtim.tv_sec &&
           a->st_mtim.tv_nsec == b->st_mtim.tv_nsec &&
           a->st_ctim.tv_sec == b->st_ctim.tv_sec &&
           a->st_ctim.tv_nsec == b->st_ctim.tv_nsec;
}

/* The kept parse still describes `path`: same path and file identity and,
 * for DYNAMIC, the same mapped libraries by path and file identity. */
static bool shape_image_current(const struct shape_image *im, unsigned kind,
                                 const char *path, const struct stat *st)
{
    uint64_t libs_id = 0;
    return im->valid && strcmp(im->path, path) == 0 &&
           shape_same_file(&im->id, st) &&
           (kind != SHAPE_IMAGE_DYNAMIC ||
            (shape_libs_scan(&im->libs, NULL, &libs_id) &&
             libs_id == im->libs_id));
}

static enum shape_read shape_image_load(struct shape_image *im, unsigned kind,
                                        const char *path,
                                        const struct stat *st)
{
    shape_names_free(&im->names);
    memset(&im->libs, 0, sizeof(im->libs));
    im->libs_id = 0;
    im->valid = false;
    if (snprintf(im->path, sizeof(im->path), "%s", path) >=
        (int)sizeof(im->path))
        return SHAPE_READ_UNREADABLE;
#ifdef ZCL_TESTING
    g_shape_image_parses++;
#endif
    enum shape_read got = shape_image_parse(im, kind);
    im->id = *st;
    im->valid = got == SHAPE_READ_OK;
    if (!im->valid)
        shape_names_free(&im->names);
    return got;
}

/* The names `path` defines as `kind`. A parse is kept for the process and
 * reused while the image's identity is unchanged: its path, device, inode,
 * size, mtime and ctime and, for DYNAMIC, each mapped library's path and
 * file identity. Any change re-parses; a failed parse is never kept, so a
 * missing fact is read again (and refused again) on the next call. On
 * SHAPE_READ_OK g_shape_image_mu is held until shape_image_release(); on
 * failure nothing is held. */
static enum shape_read shape_image_acquire(unsigned kind, const char *path,
                                           const struct shape_names **names)
{
    struct shape_image *im = &g_shape_images[kind];
    struct stat st;
    pthread_mutex_lock(&g_shape_image_mu);
    enum shape_read got = SHAPE_READ_UNREADABLE;
    if (stat(path, &st) == 0)
        got = shape_image_current(im, kind, path, &st)
                  ? SHAPE_READ_OK
                  : shape_image_load(im, kind, path, &st);
    if (got == SHAPE_READ_OK) {
        *names = &im->names;
        return got;
    }
    im->valid = false;
    pthread_mutex_unlock(&g_shape_image_mu);
    return got;
}

static void shape_image_release(void)
{
    pthread_mutex_unlock(&g_shape_image_mu);
}

/* Every global the resident objects define is defined by the running image:
 * the objects are the image's inputs, not a later or foreign build. */
static bool shape_resident_defines(const struct shape_set *base, char *why,
                                   size_t why_len)
{
    const struct shape_names *names = NULL;
    char exe[PATH_MAX];
    enum shape_read got = os_proc_self_exe_open_path(exe, sizeof(exe))
        ? shape_image_acquire(SHAPE_IMAGE_SYMTAB, exe, &names)
        : SHAPE_READ_UNREADABLE;
    if (got != SHAPE_READ_OK)
        return got == SHAPE_READ_NO_SYMTAB
                   ? shape_refuse(why, why_len, "SYMTAB_MISSING", "running image",
                                  "the running image has no symbol table")
                   : shape_refuse(why, why_len, "RESIDENT_UNREADABLE",
                                  "running image",
                                  "the running image cannot be read");
    const struct shape_sym *missing = NULL;
    for (size_t i = 0; !missing && i < base->count; i++)
        if (base->items[i].kind == SHAPE_GLOBAL &&
            !shape_names_has(names, base->items[i].name, base->items[i].len))
            missing = &base->items[i];
    shape_image_release();
    return !missing ||
           shape_refuse(why, why_len, "RESIDENT_MISMATCH", missing->name,
                        "defined by the resident build objects but not by the "
                        "running image; the objects are not its inputs");
}

/* Every symbol the candidate leaves undefined is defined by the running
 * image's dynamic symbol table or by a library it loads; the linker's own
 * _GLOBAL_OFFSET_TABLE_ is not a reference to anything. */
static bool shape_resolve(struct shape_run *run, char *why, size_t why_len)
{
    const struct shape_names *names = NULL;
    const struct shape_set *refs = &run->undefined;
    char exe[PATH_MAX];
    if (!os_proc_self_exe_open_path(exe, sizeof(exe)) ||
        shape_image_acquire(SHAPE_IMAGE_DYNAMIC, exe, &names) != SHAPE_READ_OK)
        return shape_refuse(why, why_len, "RESIDENT_UNREADABLE",
                            "running image",
                            "the running image's dynamic symbols or libraries "
                            "cannot be read");
    const struct shape_sym *missing = NULL;
    for (size_t i = 0; !missing && i < refs->count; i++)
        if (strcmp(refs->items[i].name, "_GLOBAL_OFFSET_TABLE_") != 0 &&
            !shape_names_has(names, refs->items[i].name, refs->items[i].len))
            missing = &refs->items[i];
    shape_image_release();
    char subject[512];
    if (missing)
        (void)snprintf(subject, sizeof(subject), "%s", missing->name);
    return !missing ||
           shape_refuse(why, why_len, "UNRESOLVED", subject,
                        "referenced by the candidate but defined neither by "
                        "the running image nor by a library it loads");
}

#if defined(ZCL_TESTING)
static int shape_test_image_defines_linux(const char *image, const char *name,
                                          bool dynamic, unsigned long *parses)
{
    const struct shape_names *names = NULL;
    unsigned kind = dynamic ? SHAPE_IMAGE_DYNAMIC : SHAPE_IMAGE_SYMTAB;
    int has = -1;
    if (shape_image_acquire(kind, image, &names) == SHAPE_READ_OK) {
        has = shape_names_has(names, name, strlen(name)) ? 1 : 0;
        shape_image_release();
    }
    pthread_mutex_lock(&g_shape_image_mu);
    if (parses)
        *parses = g_shape_image_parses;
    pthread_mutex_unlock(&g_shape_image_mu);
    return has;
}
#endif

/* ── adapter attribution ─────────────────────────────────────────────── */

static bool shape_is_ident(unsigned char c)
{
    return c == '_' || (c >= '0' && c <= '9') || (c >= 'a' && c <= 'z') ||
           (c >= 'A' && c <= 'Z');
}

static bool shape_has_token(const char *text, const char *name, size_t len)
{
    for (const char *p = text; (p = strstr(p, name)) != NULL; p++) {
        /* strstr matched the NUL-terminated prefix; the canonical length may
         * be shorter than the stored name, so recheck the boundary at len. */
        if ((p == text || !shape_is_ident((unsigned char)p[-1])) &&
            !shape_is_ident((unsigned char)p[len]))
            return true;
    }
    return false;
}

/* True when [p, p+n) holds the identifier token name[0..len). */
static bool shape_span_has(const char *p, size_t n, const char *name,
                           size_t len)
{
    size_t i = 0;
    while (i < n) {
        size_t start = i;
        while (i < n && shape_is_ident((unsigned char)p[i]))
            i++;
        if (i - start == len && memcmp(p + start, name, len) == 0)
            return true;
        i += i == start;
    }
    return false;
}

static bool shape_is_adapter_path(const struct shape_run *run,
                                  const char *path, const char *story)
{
    size_t root_len = strlen(run->shape->root);
    return strcmp(path, story) == 0 ||
           (strncmp(path, run->shape->root, root_len) == 0 &&
            path[root_len] == '/' && strcmp(path + root_len + 1, story) == 0);
}

static char *shape_read_dep(const struct shape_run *run, const char *dep)
{
    char path[PATH_MAX];
    if (dep[0] == '/')
        return shape_slurp(dep, SHAPE_TEXT_MAX, NULL);
    return snprintf(path, sizeof(path), "%s/%s", run->shape->root, dep) <
                   (int)sizeof(path)
               ? shape_slurp(path, SHAPE_TEXT_MAX, NULL)
               : NULL;
}

static const char *shape_adapter(struct shape_run *run)
{
    char path[PATH_MAX];
    if (!run->texts.adapter_tried) {
        run->texts.adapter_tried = true;
        if (zcl_hotfork_story_path(run->shape->adapter_id, run->story,
                                   sizeof(run->story)) &&
            snprintf(path, sizeof(path), "%s/%s", run->shape->root,
                     run->story) < (int)sizeof(path))
            run->adapter = shape_slurp(path, SHAPE_TEXT_MAX, NULL);
    }
    return run->adapter;
}

static void shape_texts_load(struct shape_run *run)
{
    struct shape_texts *t = &run->texts;
    t->loaded = true;
    t->ok = shape_adapter(run) != NULL;
    for (size_t i = 1; t->ok && i < run->dep_count; i++) {
        if (shape_is_adapter_path(run, run->deps[i], run->story))
            continue;
        t->files[t->count] = shape_read_dep(run, run->deps[i]);
        t->ok = t->files[t->count++] != NULL;
    }
}

/* A candidate-only symbol is the story adapter's when its name is a token
 * of the adapter and of no other file the candidate compiled. */
static bool shape_adapter_owns(struct shape_run *run,
                               const struct shape_sym *s)
{
    char name[512];
    if (s->len >= sizeof(name))
        return false;
    memcpy(name, s->name, s->len);
    name[s->len] = 0;
    if (!run->texts.loaded)
        shape_texts_load(run);
    if (!run->texts.ok || !shape_has_token(run->adapter, name, s->len))
        return false;
    for (size_t i = 0; i < run->texts.count; i++)
        if (shape_has_token(run->texts.files[i], name, s->len))
            return false;
    return true;
}

/* A resident global the candidate deliberately does not rebuild: the story
 * adapter names it on a "hotfork-resident-bound:" line (a capsule core
 * macro compiles that definition out, so the candidate's references bind the
 * resident's copy by design). Only resident-side globals are ever excused. */
static bool shape_resident_bound(struct shape_run *run,
                                 const struct shape_sym *s)
{
    static const char marker[] = "hotfork-resident-bound:";
    const char *text = shape_adapter(run);
    for (const char *p = text; p && (p = strstr(p, marker)) != NULL;) {
        p += sizeof(marker) - 1;
        if (shape_span_has(p, strcspn(p, "\n*"), s->name, s->len))
            return true;
    }
    return false;
}

/* ── the comparison ──────────────────────────────────────────────────── */

struct shape_diff {
    const struct shape_sym *removed; /* resident global, candidate lacks */
    const struct shape_sym *added;   /* candidate global, resident lacks */
    const struct shape_sym *state;   /* writable state present on one side */
    bool state_in_resident;
};

static void shape_note(struct shape_run *run, struct shape_diff *d,
                       const struct shape_sym *s, bool resident_side)
{
    if (resident_side ? s->kind == SHAPE_GLOBAL && shape_resident_bound(run, s)
                      : shape_adapter_owns(run, s))
        return;
    if (s->kind == SHAPE_GLOBAL) {
        const struct shape_sym **slot = resident_side ? &d->removed : &d->added;
        if (!*slot)
            *slot = s;
        return;
    }
    if (!d->state) {
        d->state = s;
        d->state_in_resident = resident_side;
    }
}

static void shape_walk(struct shape_run *run, struct shape_diff *d)
{
    size_t i = 0, j = 0;
    const struct shape_set *a = &run->base, *b = &run->next;
    while (i < a->count || j < b->count) {
        int c = i == a->count ? 1
              : j == b->count ? -1
                              : shape_cmp(&a->items[i], &b->items[j]);
        if (c == 0) {
            i++;
            j++;
        } else if (c < 0) {
            shape_note(run, d, &a->items[i++], true);
        } else {
            shape_note(run, d, &b->items[j++], false);
        }
    }
}

static bool shape_report(const struct shape_diff *d, char *why, size_t why_len)
{
    char subject[512];
    const struct shape_sym *s = d->removed ? d->removed
                              : d->added   ? d->added
                                           : d->state;
    if (!s)
        return true;
    (void)snprintf(subject, sizeof(subject), "%.*s", (int)s->len, s->name);
    if (d->removed)
        return shape_refuse(why, why_len, "ABI_REMOVED", subject,
                            "exported by the resident build of the capsule but "
                            "not defined by the candidate; its callers would "
                            "bind the resident's stale copy");
    if (d->added)
        return shape_refuse(why, why_len, "ABI_ADDED", subject,
                            "exported by the candidate but not by the resident "
                            "build of the capsule");
    return shape_refuse(why, why_len, "STATE_CHANGED", subject,
                        d->state_in_resident
                            ? "writable state of the resident build is absent, "
                              "resized or initialized with other relocations "
                              "in the candidate"
                            : "the candidate adds, resizes or re-relocates "
                              "writable state");
}

static bool shape_compare(struct shape_run *run, char *why, size_t why_len)
{
    enum shape_read got = shape_elf_open(&run->cand, run->candidate, true);
    if (got != SHAPE_READ_OK || run->cand.eh.e_type != ET_REL)
        return shape_open_refuse(got == SHAPE_READ_OK ? SHAPE_READ_UNREADABLE
                                                      : got,
                                 "candidate", why, why_len);
    if (!shape_collect(&run->cand, &run->next) ||
        !shape_collect_undefined(&run->cand, &run->undefined))
        return shape_refuse(why, why_len, "OBJECT_UNREADABLE", "candidate",
                            "the candidate's symbols or relocations cannot be read");
    if (run->next.init_fini[0])
        return shape_refuse(why, why_len, "INIT_FINI", run->next.init_fini,
                            "the candidate carries a constructor or destructor "
                            "section that would run at dlopen");
    if (run->next.count > 1)
        qsort(run->next.items, run->next.count, sizeof(run->next.items[0]),
              shape_cmp);
    struct shape_diff diff = {0};
    shape_walk(run, &diff);
    return shape_report(&diff, why, why_len);
}

/* ── the resident call closure ───────────────────────────────────────── */

/* The capsule compiles its TU set; every other function its story reaches
 * binds RTLD_LAZY to the running image's copy. The checks above bind the TU
 * set's own objects and headers to the image, but a body edit to a TU
 * OUTSIDE the set keeps every ABI fact they read, and the story would answer
 * from bytes the tree no longer holds. So the set's resident callees are
 * derived, never declared: every identifier in the current bytes of the TU
 * set and the story adapter that the code index places in-tree seeds a
 * forward call-and-include closure (codeindex_forward_closure). Each closure
 * TU the image was built from (it has an object in the resident epoch) must
 * still be the image's input: its object no newer than the image and every
 * input its depfile names no newer than that object, by mtime and by ctime.
 * No index, no placed seed or a truncated closure refuses: an unbounded
 * closure cannot vouch for the resident. A TU with no epoch object was not
 * linked into the image, so the image holds no copy of it to go stale. */

struct shape_closure {
    const struct zcl_hotfork_shape *shape;
    struct codeindex *ci;
    char (*rows)[256];
    struct shape_names seeds; /* identifiers already looked up */
    struct shape_names tus;   /* closure translation units */
    size_t placed;            /* seeds the index placed in-tree */
};

static bool shape_call_unknown(char *why, size_t why_len, const char *subject,
                               const char *detail)
{
    return shape_refuse(why, why_len, "CALL_CLOSURE_UNKNOWN", subject, detail);
}

static bool shape_closure_seed(struct shape_closure *c, const char *name,
                               char *why, size_t why_len)
{
    struct ci_symbol sym;
    bool found = false, truncated = false, root_found = false;
    if (shape_names_has(&c->seeds, name, strlen(name)))
        return true;
    if (!shape_names_add(&c->seeds, name) ||
        !codeindex_symbol(c->ci, name, &sym, &found))
        return shape_call_unknown(why, why_len, name,
                                  "the code index cannot answer for a "
                                  "symbol the capsule names");
    if (!found || !sym.def_path[0])
        return true; /* the toolchain's or a library's, not the tree's */
    int n = codeindex_forward_closure(c->ci, name, c->rows,
                                      CI_IMPACT_CLOSURE_MAX_FILES, &truncated,
                                      &root_found);
    if (n < 0 || truncated || !root_found)
        return shape_refuse(why, why_len, "CALL_CLOSURE_TRUNCATED", name,
                            "the forward call closure the story reaches "
                            "through this symbol is incomplete");
    c->placed++;
    for (int i = 0; i < n; i++)
        if (codeindex_path_is_translation_unit(c->rows[i]) &&
            !shape_names_add(&c->tus, c->rows[i]))
            return shape_call_unknown(why, why_len, c->rows[i],
                                      "out of memory recording the closure");
    return true;
}

/* Seeds the closure from every identifier token of `rel`'s current bytes. */
static bool shape_closure_text(struct shape_closure *c, const char *rel,
                               char *why, size_t why_len)
{
    char path[PATH_MAX], name[128];
    char *text = snprintf(path, sizeof(path), "%s/%s", c->shape->root, rel) <
                         (int)sizeof(path)
                     ? shape_slurp(path, SHAPE_TEXT_MAX, NULL) : NULL;
    bool ok = text != NULL ||
              shape_call_unknown(why, why_len, rel,
                                 "a capsule source cannot be read");
    for (const char *p = text; ok && *p;) {
        size_t n = 0;
        while (shape_is_ident((unsigned char)p[n]))
            n++;
        if (n > 0 && n < sizeof(name) && (unsigned char)(p[0] - '0') > 9) {
            memcpy(name, p, n);
            name[n] = 0;
            ok = shape_closure_seed(c, name, why, why_len);
        }
        p += n ? n : 1;
    }
    free(text);
    return ok;
}

static bool shape_closure_seed_all(struct shape_closure *c, char *why,
                                   size_t why_len)
{
    char story[ZCL_HOTFORK_UNITY_TU_MAX], tu[ZCL_HOTFORK_UNITY_TU_MAX];
    bool ok = zcl_hotfork_story_path(c->shape->adapter_id, story,
                                     sizeof(story)) &&
              shape_closure_text(c, story, why, why_len);
    size_t count = shape_tu_count(c->shape);
    for (size_t i = 0; ok && i < count; i++)
        ok = shape_tu_at(c->shape, i, tu, sizeof(tu)) &&
             shape_closure_text(c, tu, why, why_len);
    if (!ok)
        return why && why[0]
                   ? false
                   : shape_call_unknown(why, why_len, c->shape->source_tu,
                                        "the capsule's sources do not "
                                        "resolve");
    return c->placed > 0 ||
           shape_call_unknown(why, why_len, c->shape->source_tu,
                              "the code index places no symbol the capsule "
                              "or its story names");
}

static bool shape_call_stale(char *why, size_t why_len, const char *subject,
                             const char *detail)
{
    return shape_refuse(why, why_len, "CALL_CLOSURE_STALE", subject, detail);
}

/* One input of a closure TU's resident object `built`. */
static bool shape_closure_dep(const struct zcl_hotfork_shape *shape,
                              const char *dep, const struct stat *built,
                              char *why, size_t why_len)
{
    char rel[PATH_MAX], path[PATH_MAX];
    struct stat st;
    if (!shape_normal(shape->root, dep, rel, sizeof(rel)))
        return true; /* the toolchain's, bound by the compiler identity */
    if (snprintf(path, sizeof(path), "%s/%s", shape->root, rel) >=
            (int)sizeof(path) ||
        !shape_regular(path, &st))
        return shape_call_stale(why, why_len, rel,
                                "an input of a TU the story reaches through "
                                "the running image is gone; restart the "
                                "resident");
    return (!shape_newer(&st, built) &&
            !shape_ts_after(&st.st_ctim, &built->st_ctim)) ||
           shape_call_stale(why, why_len, rel,
                            "changed after the running image's copy of a TU "
                            "the story reaches was built, so the story would "
                            "run the stale copy; restart the resident");
}

static bool shape_closure_tu(const struct zcl_hotfork_shape *shape,
                             const char *tu, const struct stat *resident,
                             char *why, size_t why_len)
{
    char obj[PATH_MAX], dep[PATH_MAX];
    struct stat built;
    size_t count = 0;
    if (shape_tu_among(shape, tu, shape_tu_count(shape)) ||
        !shape_epoch_path(shape, tu, ".o", obj, sizeof(obj)) ||
        !shape_regular(obj, &built))
        return true;
    if (shape_newer(&built, resident))
        return shape_call_stale(why, why_len, tu,
                                "a TU the story reaches through the running "
                                "image was rebuilt after the image linked; "
                                "restart the resident");
    char **deps = zcl_calloc(SHAPE_DEPS_MAX, sizeof(*deps),
                             "HOT_FORK closure depfile");
    char *text = deps && shape_epoch_path(shape, tu, ".d", dep, sizeof(dep))
                     ? shape_slurp(dep, 1 << 20, NULL) : NULL;
    bool ok = shape_depfile_split(text, deps, &count, SHAPE_DEPS_MAX) ||
              shape_call_unknown(why, why_len, tu,
                                 "the resident depfile of a TU the story "
                                 "reaches cannot be read");
    for (size_t i = 0; ok && i < count; i++)
        ok = shape_closure_dep(shape, deps[i], &built, why, why_len);
    free(deps);
    free(text);
    return ok;
}

static bool shape_closure_check(const struct zcl_hotfork_shape *shape,
                                char *why, size_t why_len)
{
    struct stat resident;
    struct shape_closure c = { .shape = shape };
    if (why && why_len)
        why[0] = 0;
    if (!shape_resident_stat(&resident))
        return shape_refuse(why, why_len, "RESIDENT_UNREADABLE",
                            "running image",
                            "the running image cannot be identified");
    c.ci = codeindex_open_existing(shape->root);
    c.rows = zcl_malloc(sizeof(*c.rows) * CI_IMPACT_CLOSURE_MAX_FILES,
                        "HOT_FORK call closure");
    bool ok = (c.ci && c.rows) ||
              shape_call_unknown(why, why_len, shape->source_tu,
                                 "no code index answers for the source root, "
                                 "so the story's resident callees cannot be "
                                 "bounded");
    ok = ok && shape_closure_seed_all(&c, why, why_len);
    for (size_t off = 0; ok && off < c.tus.len;
         off += strlen(c.tus.arena + off) + 1)
        ok = shape_closure_tu(shape, c.tus.arena + off, &resident, why,
                              why_len);
    if (c.ci)
        codeindex_close(c.ci);
    free(c.rows);
    shape_names_free(&c.seeds);
    shape_names_free(&c.tus);
    return ok;
}

static bool shape_closure_admit_linux(const char *root, const char *source_tu,
                                      const char *sibling_tus,
                                      const char *adapter_id, char *why,
                                      size_t why_len)
{
    struct zcl_hotfork_shape shape;
    memset(&shape, 0, sizeof(shape));
    shape.root = root;
    shape.source_tu = source_tu;
    shape.sibling_tus = sibling_tus;
    shape.adapter_id = adapter_id;
    if (!root || !source_tu || !sibling_tus || !adapter_id)
        return shape_call_unknown(why, why_len, "-", "no capsule named");
    if (!shape_read_epoch(&shape) || !shape_adapter_tus(&shape)) {
        if (why && why_len)
            (void)snprintf(why, why_len, "%s", shape.unbound);
        return false;
    }
    return shape_closure_check(&shape, why, why_len);
}

static void shape_run_free(struct shape_run *run)
{
    for (size_t i = 0; i < run->object_count; i++)
        shape_elf_close(&run->objects[i]);
    shape_elf_close(&run->cand);
    free(run->base.items);
    free(run->next.items);
    free(run->undefined.items);
    for (size_t i = 0; i < run->resident_deps.count; i++)
        free(run->resident_deps.items[i]);
    free(run->resident_deps.items);
    free(run->deps_text);
    free(run->adapter);
    for (size_t i = 0; i < run->texts.count; i++)
        free(run->texts.files[i]);
}

static bool shape_still_bound(const struct zcl_hotfork_shape *shape,
                              char *why, size_t why_len)
{
    struct zcl_hotfork_shape now;
    shape_begin_linux(&now, shape->root, shape->source_tu,
                      shape->sibling_tus, shape->adapter_id, shape->cc,
                      shape->compiler_id, shape->cflags);
    if (now.unbound[0]) {
        if (why && why_len)
            (void)snprintf(why, why_len, "%s", now.unbound);
        return false;
    }
    return strcmp(now.generation, shape->generation) == 0 ||
           shape_refuse(why, why_len, "GENERATION_MOVED", shape->source_tu,
                        "the resident image or its build objects changed "
                        "while the candidate compiled");
}

/* Each check names the first fact it finds missing or contradicted. */
static bool shape_run_checks(struct shape_run *run, char *why, size_t why_len)
{
    return shape_still_bound(run->shape, why, why_len) &&
           shape_load_baseline(run, why, why_len) &&
           shape_resident_defines(&run->base, why, why_len) &&
           shape_candidate_deps(run, why, why_len) &&
           shape_header_check(run, why, why_len) &&
           shape_record_check(run, why, why_len) &&
           shape_compare(run, why, why_len) &&
           shape_resolve(run, why, why_len) &&
           shape_record_commit(run, why, why_len);
}

static bool shape_admit_linux(bool prior, const struct zcl_hotfork_shape *shape,
                              const char *candidate_object, const char *depfile,
                              char *why, size_t why_len)
{
    if (!prior)
        return false;
    if (!shape || !candidate_object || !depfile)
        return shape_refuse(why, why_len, "NO_BASELINE", "-",
                            "no shape facts were captured");
    struct shape_run *run = zcl_calloc(1, sizeof(*run), "HOT_FORK shape run");
    if (!run)
        return shape_refuse(why, why_len, "OBJECT_UNREADABLE", "-",
                            "out of memory");
    run->shape = shape;
    run->candidate = candidate_object;
    run->depfile = depfile;
    run->cand.fd = -1;
    bool ok = shape_run_checks(run, why, why_len);
    shape_run_free(run);
    free(run);
    return ok;
}

#endif /* __linux__ */

/* Per-arm bodies (shape_begin_linux etc., above) hold the real Linux/ELF
 * facts; every other platform refuses by name. One definition per public
 * entry point regardless of arm, so the two bodies never appear as
 * duplicate top-level definitions of the same symbol. */
void zcl_hotfork_shape_begin(struct zcl_hotfork_shape *shape, const char *root,
                             const char *source_tu, const char *sibling_tus,
                             const char *adapter_id, const char *cc,
                             const char *compiler_id, const char *cflags)
{
#if defined(__linux__)
    shape_begin_linux(shape, root, source_tu, sibling_tus, adapter_id, cc,
                      compiler_id, cflags);
#else
    memset(shape, 0, sizeof(*shape));
    shape->root = root;
    shape->source_tu = source_tu;
    shape->sibling_tus = sibling_tus;
    shape->adapter_id = adapter_id;
    shape->cc = cc;
    shape->compiler_id = compiler_id;
    shape->cflags = cflags;
    (void)snprintf(shape->generation, sizeof(shape->generation), "unbound");
    (void)shape_refuse(shape->unbound, sizeof(shape->unbound), "UNSUPPORTED",
                       source_tu, "ELF shape facts are read on Linux only");
#endif
}

bool zcl_hotfork_shape_admit(bool prior, const struct zcl_hotfork_shape *shape,
                             const char *candidate_object, const char *depfile,
                             char *why, size_t why_len)
{
#if defined(__linux__)
    return shape_admit_linux(prior, shape, candidate_object, depfile, why,
                             why_len);
#else
    (void)candidate_object;
    (void)depfile;
    (void)shape;
    if (!prior)
        return false;
    return shape_refuse(why, why_len, "UNSUPPORTED", "-",
                        "ELF shape facts are read on Linux only");
#endif
}

bool zcl_hotfork_shape_closure_admit(const char *root, const char *source_tu,
                                     const char *sibling_tus,
                                     const char *adapter_id, char *why,
                                     size_t why_len)
{
#if defined(__linux__)
    return shape_closure_admit_linux(root, source_tu, sibling_tus, adapter_id,
                                     why, why_len);
#else
    (void)root;
    (void)sibling_tus;
    (void)adapter_id;
    return shape_refuse(why, why_len, "UNSUPPORTED", source_tu,
                        "ELF shape facts are read on Linux only");
#endif
}

#if defined(ZCL_TESTING)
int zcl_hotfork_shape_test_image_defines(const char *image, const char *name,
                                         bool dynamic, unsigned long *parses)
{
#if defined(__linux__)
    return shape_test_image_defines_linux(image, name, dynamic, parses);
#else
    (void)image;
    (void)name;
    (void)dynamic;
    if (parses)
        *parses = 0;
    return -1;
#endif
}
#endif
