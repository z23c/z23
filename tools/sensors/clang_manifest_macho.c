/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: The Mach-O half of the object compiler's IDENTITY: the driver (an xcode-select shim followed to the real compiler), its transitive dylib closure read from the load commands, and the OS and dyld shared cache identity for the dylibs that live only in the cache. */
/* realpath() is declared only under _DEFAULT_SOURCE on glibc without the
 * fortify inline; set it before the first header pulls in <features.h>. */
#if !defined(_WIN32) && !defined(_DEFAULT_SOURCE)
#define _DEFAULT_SOURCE
#endif

#include "clang_manifest_core.h"

#if defined(__APPLE__)
#include "base/safe_alloc.h"
#include "base/serialize_le.h"
#include "sha3/sha3.h"

#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/sysctl.h>
#include <unistd.h>
#include <uuid/uuid.h>

/* Exported by libdyld; declared in dyld_priv.h, which the SDK does not ship. */
extern bool _dyld_get_shared_cache_uuid(uuid_t uuid);

#define CMM_MH_MAGIC_64 0xfeedfacfu
#define CMM_FAT_MAGIC 0xcafebabeu
#define CMM_MH_CMDS_CAP (1u << 20)
#define CMM_MAX_IMAGES 512u
#define CMM_MAX_DEPTH 16u
#define CMM_MAX_RPATHS 64u
#define CMM_LC_LAZY_LOAD_DYLIB 0x20u
#define CMM_LC_LOAD_WEAK_DYLIB 0x80000018u
#define CMM_LC_RPATH 0x8000001cu
#define CMM_LC_REEXPORT_DYLIB 0x8000001fu
#define CMM_LC_LOAD_UPWARD_DYLIB 0x80000023u
#define CMM_LC_LOAD_DYLIB 0x0cu

struct cmm_walk {
    struct sha3_256_ctx *ctx;
    char (*seen)[PATH_MAX]; /* realpaths already folded */
    char (*rp)[PATH_MAX];   /* expanded LC_RPATH entries, innermost last */
    size_t nseen, nrp;
    size_t seg[CMM_MAX_DEPTH + 2]; /* start of each image's LC_RPATH run */
    size_t nseg;
    char exec_dir[PATH_MAX];
};

enum cmm_where { CMM_ON_DISK, CMM_IN_CACHE, CMM_NOWHERE };

static bool cmm_is_file(const char *path)
{
    struct stat st;
    return stat(path, &st) == 0 && S_ISREG(st.st_mode);
}

static bool cmm_dir_of(const char *real, char out[PATH_MAX])
{
    const char *slash = strrchr(real, '/');
    size_t n = slash != NULL ? (size_t)(slash - real) : 0;
    if (slash == NULL || n >= PATH_MAX)
        return false;
    memcpy(out, real, n);
    out[n] = '\0';
    return true;
}

/* The bytes of `path` into ctx; false on any read error. */
static bool cmm_hash_file(const char *path, struct sha3_256_ctx *ctx)
{
    unsigned char buf[65536];
    size_t n;
    FILE *fp = fopen(path, "rb");
    bool ok;
    if (fp == NULL)
        return false;
    while ((n = fread(buf, 1, sizeof(buf), fp)) > 0)
        sha3_256_write(ctx, buf, n);
    ok = !ferror(fp);
    return fclose(fp) == 0 && ok;
}

/* The OS build, product version and shared cache UUID. */
static bool cmm_os_identity(struct sha3_256_ctx *ctx)
{
    static const char *const keys[] = {"kern.osversion", "kern.osproductversion"};
    uuid_t uuid;
    for (size_t k = 0; k < sizeof(keys) / sizeof(keys[0]); k++) {
        char val[128];
        size_t n = sizeof(val) - 1;
        if (sysctlbyname(keys[k], val, &n, NULL, 0) != 0 || n == 0)
            return false;
        val[n] = '\0';
        sha3_256_write(ctx, (const unsigned char *)keys[k], strlen(keys[k]) + 1);
        sha3_256_write(ctx, (const unsigned char *)val, strlen(val) + 1);
    }
    if (!_dyld_get_shared_cache_uuid(uuid))
        return false;
    sha3_256_write(ctx, uuid, sizeof(uuid));
    return true;
}

/* `s` with a leading @loader_path or @executable_path replaced; an absolute
 * path as is; anything else is not resolvable. */
static bool cmm_subst(const struct cmm_walk *w, const char *s,
                      const char *loader_dir, char out[PATH_MAX])
{
    static const char loader[] = "@loader_path", exec[] = "@executable_path";
    const char *base = NULL, *rest = NULL;
    int n;
    if (strncmp(s, loader, sizeof(loader) - 1) == 0) {
        base = loader_dir;
        rest = s + sizeof(loader) - 1;
    } else if (strncmp(s, exec, sizeof(exec) - 1) == 0) {
        base = w->exec_dir;
        rest = s + sizeof(exec) - 1;
    } else if (s[0] == '/') {
        base = "";
        rest = s;
    }
    if (base == NULL || (rest[0] != '\0' && rest[0] != '/'))
        return false;
    n = snprintf(out, PATH_MAX, "%s%s", base, rest);
    return n > 0 && (size_t)n < PATH_MAX;
}

/* Where the dylib `name` of an image in loader_dir is: a file reached by
 * @rpath, @loader_path, @executable_path or an absolute path, or (for a
 * system path with no file) the dyld shared cache. */
static enum cmm_where cmm_locate(const struct cmm_walk *w, const char *name,
                                 const char *loader_dir, char out[PATH_MAX])
{
    if (strncmp(name, "@rpath/", 7) == 0) {
        /* dyld's order: this image's entries, then its loader's, up to the
         * main executable; each image's entries in load-command order. */
        for (size_t s = w->nseg; s > 0; s--) {
            size_t end = s == w->nseg ? w->nrp : w->seg[s];
            for (size_t k = w->seg[s - 1]; k < end; k++) {
                int n = snprintf(out, PATH_MAX, "%s/%s", w->rp[k], name + 7);
                if (n > 0 && (size_t)n < PATH_MAX && cmm_is_file(out))
                    return CMM_ON_DISK;
            }
        }
        return CMM_NOWHERE;
    }
    if (!cmm_subst(w, name, loader_dir, out))
        return CMM_NOWHERE;
    if (cmm_is_file(out))
        return CMM_ON_DISK;
    return name[0] == '/' && (strncmp(name, "/usr/lib/", 9) == 0 ||
                              strncmp(name, "/System/", 8) == 0)
               ? CMM_IN_CACHE
               : CMM_NOWHERE;
}

/* One load command at `at`: its command, size and the string at +8. */
static bool cmm_next(const char *cmds, size_t len, size_t at, uint32_t *cmd,
                     uint32_t *size, const char **str)
{
    uint32_t off;
    if (len - at < 8)
        return false;
    memcpy(cmd, cmds + at, sizeof(*cmd));
    memcpy(size, cmds + at + 4, sizeof(*size));
    if (*size < 8 || *size > len - at)
        return false;
    *str = NULL;
    if (*size >= 12) {
        memcpy(&off, cmds + at + 8, sizeof(off));
        if (off >= 12 && off < *size &&
            memchr(cmds + at + off, '\0', *size - off) != NULL)
            *str = cmds + at + off;
    }
    return true;
}

static bool cmm_dylib_cmd(uint32_t cmd)
{
    return cmd == CMM_LC_LOAD_DYLIB || cmd == CMM_LC_LAZY_LOAD_DYLIB ||
           cmd == CMM_LC_LOAD_WEAK_DYLIB || cmd == CMM_LC_REEXPORT_DYLIB ||
           cmd == CMM_LC_LOAD_UPWARD_DYLIB;
}

/* Push this slice's LC_RPATH entries, expanded; false on a bad one. */
static bool cmm_push_rpaths(struct cmm_walk *w, const char *cmds, size_t len,
                            uint32_t ncmds, const char *loader_dir)
{
    size_t at = 0;
    for (uint32_t k = 0; k < ncmds; k++) {
        uint32_t cmd, size;
        const char *str;
        if (!cmm_next(cmds, len, at, &cmd, &size, &str))
            return false;
        if (cmd == CMM_LC_RPATH &&
            (str == NULL || w->nrp >= CMM_MAX_RPATHS ||
             !cmm_subst(w, str, loader_dir, w->rp[w->nrp++])))
            return false;
        at += size;
    }
    return true;
}

static bool cmm_visit(struct cmm_walk *w, const char *path, unsigned depth);

/* Fold one dylib dependency: a file is visited (recursively), a cache
 * resident one is bound by the OS identity already folded, and a weak
 * dependency that is nowhere is recorded as absent. */
static bool cmm_dependency(struct cmm_walk *w, uint32_t cmd, const char *name,
                           const char *loader_dir, unsigned depth)
{
    char path[PATH_MAX];
    enum cmm_where where = cmm_locate(w, name, loader_dir, path);
    if (where == CMM_NOWHERE && cmd != CMM_LC_LOAD_WEAK_DYLIB)
        return false;
    sha3_256_write(w->ctx, (const unsigned char *)name, strlen(name) + 1);
    sha3_256_write(w->ctx, (const unsigned char *)(where == CMM_ON_DISK ? "F" : where == CMM_IN_CACHE ? "C" : "A"),
                   2);
    return where != CMM_ON_DISK || cmm_visit(w, path, depth + 1);
}

/* Every dylib command of the slice. */
static bool cmm_dependencies(struct cmm_walk *w, const char *cmds, size_t len,
                             uint32_t ncmds, const char *loader_dir,
                             unsigned depth)
{
    size_t at = 0;
    for (uint32_t k = 0; k < ncmds; k++) {
        uint32_t cmd, size;
        const char *str;
        if (!cmm_next(cmds, len, at, &cmd, &size, &str))
            return false;
        if (cmm_dylib_cmd(cmd) &&
            (str == NULL || !cmm_dependency(w, cmd, str, loader_dir, depth)))
            return false;
        at += size;
    }
    return true;
}

/* The slice of fp at `base`: header, commands, then rpaths and dylibs. */
static bool cmm_slice(struct cmm_walk *w, FILE *fp, long base,
                      const char *loader_dir, unsigned depth)
{
    uint32_t h[8];
    char *cmds;
    size_t mark = w->nrp;
    bool ok;
    if (fseek(fp, base, SEEK_SET) != 0 || fread(h, sizeof(h), 1, fp) != 1 ||
        h[0] != CMM_MH_MAGIC_64 || h[5] > CMM_MH_CMDS_CAP)
        return false;
    cmds = zcl_malloc((size_t)h[5] + 1, "clang_manifest.macho_cmds");
    if (cmds == NULL)
        return false;
    if (w->nseg >= sizeof(w->seg) / sizeof(w->seg[0])) {
        free(cmds);
        return false;
    }
    w->seg[w->nseg++] = mark;
    ok = fread(cmds, 1, h[5], fp) == h[5] &&
         cmm_push_rpaths(w, cmds, h[5], h[4], loader_dir) &&
         cmm_dependencies(w, cmds, h[5], h[4], loader_dir, depth);
    free(cmds);
    w->nrp = mark;
    w->nseg--;
    return ok;
}

/* The slice offsets of a thin or fat image: base[0..n). */
static bool cmm_slices(FILE *fp, long base[16], uint32_t *n)
{
    unsigned char id[8], arch[20];
    if (fseek(fp, 0, SEEK_SET) != 0 || fread(id, sizeof(id), 1, fp) != 1)
        return false;
    if (zcl_read_u32_be(id) != CMM_FAT_MAGIC) {
        base[0] = 0;
        *n = 1;
        return true;
    }
    *n = zcl_read_u32_be(id + 4);
    if (*n < 1 || *n > 16)
        return false;
    for (uint32_t k = 0; k < *n; k++) {
        if (fseek(fp, 8 + (long)k * 20, SEEK_SET) != 0 ||
            fread(arch, sizeof(arch), 1, fp) != 1)
            return false;
        base[k] = (long)zcl_read_u32_be(arch + 8);
    }
    return true;
}

static bool cmm_seen(struct cmm_walk *w, const char *real, bool *fresh)
{
    for (size_t k = 0; k < w->nseen; k++)
        if (strcmp(w->seen[k], real) == 0) {
            *fresh = false;
            return true;
        }
    if (w->nseen >= CMM_MAX_IMAGES)
        return false;
    memcpy(w->seen[w->nseen++], real, strlen(real) + 1);
    *fresh = true;
    return true;
}

/* Fold the image at `path` (realpath, bytes) and walk its dylibs once. */
static bool cmm_visit(struct cmm_walk *w, const char *path, unsigned depth)
{
    char real[PATH_MAX], loader_dir[PATH_MAX];
    long base[16];
    uint32_t n = 0;
    bool fresh = false, ok;
    FILE *fp;
    if (depth > CMM_MAX_DEPTH || realpath(path, real) == NULL ||
        !cmm_seen(w, real, &fresh) || !cmm_dir_of(real, loader_dir))
        return false;
    if (!fresh)
        return true;
    sha3_256_write(w->ctx, (const unsigned char *)real, strlen(real) + 1);
    if (!cmm_hash_file(real, w->ctx) || (fp = fopen(real, "rb")) == NULL)
        return false;
    ok = cmm_slices(fp, base, &n);
    for (uint32_t k = 0; ok && k < n; k++)
        ok = cmm_slice(w, fp, base[k], loader_dir, depth);
    (void)fclose(fp);
    return ok;
}

/* A root driver: its @executable_path is its own directory. */
static bool cmm_root(struct cmm_walk *w, const char *path)
{
    char real[PATH_MAX];
    if (realpath(path, real) == NULL || !cmm_dir_of(real, w->exec_dir))
        return false;
    w->nrp = 0;
    w->nseg = 0;
    return cmm_visit(w, real, 0);
}

/* /usr/bin/cc and its kin are xcode-select shims that run the compiler of
 * the active developer directory (DEVELOPER_DIR, the xcode-select link, or
 * the Command Line Tools). The real driver, or false. */
static bool cmm_real_driver(const char *shim, char out[PATH_MAX])
{
    char dev[PATH_MAX], cand[PATH_MAX];
    const char *name = strrchr(shim, '/') + 1;
    const char *env = getenv("DEVELOPER_DIR");
    ssize_t n;
    static const char *const sub[] = {"usr/bin", "Toolchains/XcodeDefault.xctoolchain/usr/bin"};
    if (env != NULL && env[0] == '/') {
        n = (ssize_t)snprintf(dev, sizeof(dev), "%s", env);
    } else if ((n = readlink("/var/db/xcode_select_link", dev, sizeof(dev) - 1)) > 0) {
        dev[n] = '\0';
    } else {
        n = (ssize_t)snprintf(dev, sizeof(dev), "%s", "/Library/Developer/CommandLineTools");
    }
    if (n <= 0 || (size_t)n >= sizeof(dev))
        return false;
    for (size_t k = 0; k < sizeof(sub) / sizeof(sub[0]); k++) {
        int w = snprintf(cand, sizeof(cand), "%s/%s/%s", dev, sub[k], name);
        if (w > 0 && (size_t)w < sizeof(cand) && cmm_is_file(cand) &&
            realpath(cand, out) != NULL && strcmp(out, shim) != 0)
            return true;
    }
    return false;
}

static bool cmm_is_shim(const char *real)
{
    return strncmp(real, "/usr/bin/", 9) == 0 && strchr(real + 9, '/') == NULL;
}

bool cm_macho_closure(const char *exe, uint8_t d[32])
{
    struct sha3_256_ctx ctx;
    struct cmm_walk w = {.ctx = &ctx};
    char real[PATH_MAX], drv[PATH_MAX];
    bool ok;
    w.seen = zcl_calloc(CMM_MAX_IMAGES, PATH_MAX, "clang_manifest.macho_seen");
    w.rp = zcl_calloc(CMM_MAX_RPATHS, PATH_MAX, "clang_manifest.macho_rpaths");
    sha3_256_init(&ctx);
    ok = w.seen != NULL && w.rp != NULL && cmm_os_identity(&ctx) &&
         cmm_root(&w, exe);
    if (ok && realpath(exe, real) != NULL && cmm_is_shim(real))
        ok = cmm_real_driver(real, drv) && cmm_root(&w, drv);
    sha3_256_finalize(&ctx, d);
    free(w.seen);
    free(w.rp);
    return ok && w.nseen > 0;
}
#endif
