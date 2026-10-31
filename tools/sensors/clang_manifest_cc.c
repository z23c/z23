/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: The object compiler's IDENTITY text: the driver resolved through any compile-cache masquerade, its bytes, its loaded shared objects, and the build's toolchain identity. */
/* realpath() is declared only under _DEFAULT_SOURCE on glibc without the
 * fortify inline; set it before the first header pulls in <features.h>. */
#if !defined(_WIN32) && !defined(_DEFAULT_SOURCE)
#define _DEFAULT_SOURCE
#endif

#include "clang_manifest_core.h"

#include "base/safe_alloc.h"
#include "sha3/sha3.h"

#include <errno.h>
#include <fcntl.h>
#include <spawn.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

#if defined(__linux__)
#include <elf.h>
#endif

extern char **environ;

#define CM_TRACE_CAP (64u * 1024u)

static bool cm_exec_file(const char *path, char out[PATH_MAX])
{
    struct stat st;
    return access(path, X_OK) == 0 && stat(path, &st) == 0 &&
           S_ISREG(st.st_mode) && realpath(path, out) != NULL;
}

/* A compile cache that runs the compiler named after it, or (as a
 * masquerade link named like the compiler) the next one of that name on
 * PATH. Its bytes say nothing about the code generator. */
static bool cm_is_wrapper(const char *real)
{
    const char *base = strrchr(real, '/');
    base = base != NULL ? base + 1 : real;
    return strncmp(base, "ccache", 6) == 0 ||
           strncmp(base, "sccache", 7) == 0 || strcmp(base, "zcc") == 0;
}

/* The first executable file named `name` on PATH, skipping every candidate
 * that resolves to a compile-cache wrapper when `skip_wrappers`. */
static bool cm_path_lookup(const char *name, bool skip_wrappers,
                           char out[PATH_MAX])
{
    const char *path = getenv("PATH");
    for (const char *p = path; p != NULL;) {
        const char *colon = strchr(p, ':');
        size_t n = colon != NULL ? (size_t)(colon - p) : strlen(p);
        char candidate[PATH_MAX];
        int w = n == 0 ? snprintf(candidate, sizeof(candidate), "%s", name)
                       : snprintf(candidate, sizeof(candidate), "%.*s/%s",
                                  (int)n, p, name);
        if (w > 0 && (size_t)w < sizeof(candidate) &&
            cm_exec_file(candidate, out) && !(skip_wrappers && cm_is_wrapper(out)))
            return true;
        p = colon != NULL ? colon + 1 : NULL;
    }
    return false;
}

enum cm_cc_resolution cm_resolve_cc(const char *cc, char out[PATH_MAX])
{
    const char *base;
    if (cc == NULL || cc[0] == '\0')
        return CM_CC_NONE;
    if (strchr(cc, '/') != NULL ? !cm_exec_file(cc, out)
                                : !cm_path_lookup(cc, false, out))
        return CM_CC_NONE;
    if (!cm_is_wrapper(out))
        return CM_CC_FOUND;
    /* A masquerade link (/usr/lib/ccache/gcc -> ccache) runs the next
     * `gcc` on PATH that is not itself the cache, as ccache does. */
    base = strrchr(cc, '/');
    base = base != NULL ? base + 1 : cc;
    if (!cm_is_wrapper(base) && cm_path_lookup(base, true, out))
        return CM_CC_FOUND;
    out[0] = '\0';
    return CM_CC_WRAPPED;
}

bool cm_toolchain_id_ok(const char *id)
{
    bool nonzero = false;
    if (id == NULL || strlen(id) != 64)
        return false;
    for (size_t k = 0; k < 64; k++) {
        if (!((id[k] >= '0' && id[k] <= '9') || (id[k] >= 'a' && id[k] <= 'f')))
            return false;
        nonzero = nonzero || id[k] != '0';
    }
    return nonzero;
}

static bool cm_cc_sha3(const char *path, struct sha3_256_ctx *ctx)
{
    unsigned char buf[65536];
    size_t n;
    FILE *fp = fopen(path, "rb");
    if (fp == NULL)
        return false;
    while ((n = fread(buf, 1, sizeof(buf), fp)) > 0)
        sha3_256_write(ctx, buf, n);
    bool ok = !ferror(fp);
    if (fclose(fp) != 0)
        ok = false;
    return ok;
}

enum cm_image { CM_IMAGE_SCRIPT, CM_IMAGE_STATIC, CM_IMAGE_DYNAMIC,
                CM_IMAGE_MACHO, CM_IMAGE_UNKNOWN };

#if defined(__linux__)
/* The program header table of a native-endian ELF image: its offset, entry
 * count and entry size. False for another class or byte order. */
static bool cm_elf_phdrs(FILE *fp, const unsigned char *id, uint64_t *off,
                         unsigned *phnum, unsigned *phentsize)
{
    uint16_t one = 1;
    unsigned char host = *(unsigned char *)&one ? ELFDATA2LSB : ELFDATA2MSB;
    Elf64_Ehdr e64;
    Elf32_Ehdr e32;
    if (id[EI_DATA] != host || fseek(fp, 0, SEEK_SET) != 0)
        return false;
    if (id[EI_CLASS] == ELFCLASS64 && fread(&e64, sizeof(e64), 1, fp) == 1) {
        *off = e64.e_phoff;
        *phnum = e64.e_phnum;
        *phentsize = e64.e_phentsize;
        return *phentsize >= sizeof(Elf64_Phdr);
    }
    if (id[EI_CLASS] == ELFCLASS32 && fread(&e32, sizeof(e32), 1, fp) == 1) {
        *off = e32.e_phoff;
        *phnum = e32.e_phnum;
        *phentsize = e32.e_phentsize;
        return *phentsize >= sizeof(Elf32_Phdr);
    }
    return false;
}

/* PT_INTERP among the program headers of a native-endian ELF image. */
static enum cm_image cm_elf_image(FILE *fp, const unsigned char *id)
{
    uint64_t off = 0;
    unsigned phnum = 0, phentsize = 0;
    if (!cm_elf_phdrs(fp, id, &off, &phnum, &phentsize))
        return CM_IMAGE_UNKNOWN;
    for (unsigned k = 0; k < phnum; k++) {
        uint32_t type;
        if (fseek(fp, (long)(off + (uint64_t)k * phentsize), SEEK_SET) != 0 ||
            fread(&type, sizeof(type), 1, fp) != 1)
            return CM_IMAGE_UNKNOWN;
        if (type == PT_INTERP)
            return CM_IMAGE_DYNAMIC;
    }
    return CM_IMAGE_STATIC;
}
#endif

#if defined(__APPLE__)
/* A thin 64-bit little-endian Mach-O or a fat archive. */
static bool cm_is_macho(const unsigned char *id)
{
    static const unsigned char thin[4] = {0xcf, 0xfa, 0xed, 0xfe};
    static const unsigned char fat[4] = {0xca, 0xfe, 0xba, 0xbe};
    return memcmp(id, thin, 4) == 0 || memcmp(id, fat, 4) == 0;
}
#endif

/* What kind of executable the driver is. A script's bytes are all of it
 * that runs before the programs it names; an image format this sensor
 * cannot read the loaded objects of is unknown. */
static enum cm_image cm_image_of(const char *path)
{
    unsigned char id[16] = {0};
    enum cm_image kind = CM_IMAGE_UNKNOWN;
    FILE *fp = fopen(path, "rb");
    if (fp == NULL)
        return CM_IMAGE_UNKNOWN;
    size_t n = fread(id, 1, sizeof(id), fp);
    if (n >= 2 && id[0] == '#' && id[1] == '!')
        kind = CM_IMAGE_SCRIPT;
#if defined(__linux__)
    else if (n == sizeof(id) && memcmp(id, ELFMAG, SELFMAG) == 0)
        kind = cm_elf_image(fp, id);
#elif defined(__APPLE__)
    else if (n == sizeof(id) && cm_is_macho(id))
        kind = CM_IMAGE_MACHO;
#endif
    (void)fclose(fp);
    return kind;
}

/* Start `exe` under the loader's trace mode, its stdout on out_fd (closed
 * in the child along with in_fd) and its stderr discarded. */
static bool cm_trace_spawn(const char *exe, int in_fd, int out_fd, pid_t *pid)
{
    size_t nenv = 0;
    posix_spawn_file_actions_t fa;
    bool ok;
    while (environ != NULL && environ[nenv] != NULL)
        nenv++;
    char **envp = zcl_calloc(nenv + 2, sizeof(char *), "clang_manifest.trace_env");
    char *argv[] = {(char *)exe, NULL};
    if (envp == NULL || posix_spawn_file_actions_init(&fa) != 0) {
        free(envp);
        return false;
    }
    envp[0] = (char *)"LD_TRACE_LOADED_OBJECTS=1";
    for (size_t k = 0; k < nenv; k++)
        envp[k + 1] = environ[k];
    ok = posix_spawn_file_actions_adddup2(&fa, out_fd, STDOUT_FILENO) == 0 &&
         posix_spawn_file_actions_addopen(&fa, STDERR_FILENO, "/dev/null",
                                          O_WRONLY, 0) == 0 &&
         posix_spawn_file_actions_addclose(&fa, in_fd) == 0 &&
         posix_spawn(pid, exe, &fa, NULL, argv, envp) == 0;
    (void)posix_spawn_file_actions_destroy(&fa);
    free(envp);
    return ok;
}

/* Read fd to end of file into buf (NUL-terminated), draining past cap so
 * the writer never blocks on a full pipe; an overflow only fails. */
static bool cm_drain(int fd, char *buf, size_t cap)
{
    size_t got = 0;
    bool full = false;
    for (;;) {
        char sink[4096];
        bool room = got < cap - 1;
        ssize_t r = room ? read(fd, buf + got, cap - 1 - got)
                         : read(fd, sink, sizeof(sink));
        if (r < 0 && errno == EINTR)
            continue;
        if (r <= 0) {
            buf[got] = '\0';
            return r == 0 && !full;
        }
        if (room)
            got += (size_t)r;
        else
            full = true;
    }
}

/* Reap pid; true when it exited 0. */
static bool cm_reap(pid_t pid)
{
    int status = 0;
    pid_t w;
    while ((w = waitpid(pid, &status, 0)) < 0 && errno == EINTR)
        ;
    return w == pid && WIFEXITED(status) && WEXITSTATUS(status) == 0;
}

/* Run the dynamic loader in trace mode on `exe` (it lists the objects it
 * would map and exits without running the program) into buf. */
static bool cm_trace_run(const char *exe, char *buf, size_t cap)
{
    int fds[2];
    pid_t pid = -1;
    bool ok;
    if (pipe(fds) != 0)
        return false;
    ok = cm_trace_spawn(exe, fds[0], fds[1], &pid);
    (void)close(fds[1]);
    if (ok) {
        ok = cm_drain(fds[0], buf, cap);
        ok = cm_reap(pid) && ok;
    }
    (void)close(fds[0]);
    return ok;
}

/* Fold one loaded object (by realpath and bytes) into the closure. */
static bool cm_fold_object(struct sha3_256_ctx *ctx, const char *path,
                           size_t *count)
{
    char real[PATH_MAX];
    struct sha3_256_ctx one;
    uint8_t d[32];
    if (realpath(path, real) == NULL)
        return false;
    sha3_256_init(&one);
    if (!cm_cc_sha3(real, &one))
        return false;
    sha3_256_finalize(&one, d);
    sha3_256_write(ctx, (const unsigned char *)real, strlen(real) + 1);
    sha3_256_write(ctx, d, sizeof(d));
    (*count)++;
    return true;
}

/* One trace line: "name => /path (0x..)", "/path (0x..)" (the loader), or
 * a virtual object with no file ("linux-vdso.so.1 (0x..)"). */
static bool cm_fold_line(struct sha3_256_ctx *ctx, char *line, size_t *count)
{
    char *arrow = strstr(line, " => "), *path, *end;
    while (*line == ' ' || *line == '\t')
        line++;
    if (*line == '\0')
        return true;
    path = arrow != NULL ? arrow + 4 : line;
    if (*path != '/')
        return arrow == NULL && strchr(line, '/') == NULL &&
               strstr(line, " (0x") != NULL;
    end = strstr(path, " (0x");
    if (end == NULL)
        return false;
    *end = '\0';
    return cm_fold_object(ctx, path, count);
}

/* The SHA3-256 over every shared object the loader maps for `exe`. */
static bool cm_closure(const char *exe, uint8_t d[32])
{
    char *buf = zcl_malloc(CM_TRACE_CAP, "clang_manifest.trace");
    struct sha3_256_ctx ctx;
    size_t count = 0;
    char *save = NULL;
    bool ok = buf != NULL && cm_trace_run(exe, buf, CM_TRACE_CAP);
    sha3_256_init(&ctx);
    for (char *line = ok ? strtok_r(buf, "\n", &save) : NULL;
         ok && line != NULL; line = strtok_r(NULL, "\n", &save))
        ok = cm_fold_line(&ctx, line, &count);
    sha3_256_finalize(&ctx, d);
    free(buf);
    return ok && count > 0;
}

/* "libs none" for a script or static image, "libs sha3-256 <hex>" over a
 * dynamic image's loaded objects, false when they cannot be established. */
static bool cm_libs_text(const char *exe, char out[96])
{
    uint8_t d[32];
    char hex[65];
    switch (cm_image_of(exe)) {
    case CM_IMAGE_SCRIPT:
    case CM_IMAGE_STATIC:
        (void)snprintf(out, 96, "libs none");
        return true;
    case CM_IMAGE_MACHO:
#if defined(__APPLE__)
        if (!cm_macho_closure(exe, d))
            return false;
        cm_hex(d, hex);
        (void)snprintf(out, 96, "libs sha3-256 %s", hex);
        return true;
#else
        return false;
#endif
    case CM_IMAGE_DYNAMIC:
        if (!cm_closure(exe, d))
            return false;
        cm_hex(d, hex);
        (void)snprintf(out, 96, "libs sha3-256 %s", hex);
        return true;
    case CM_IMAGE_UNKNOWN:
    default:
        return false;
    }
}

char *cm_object_cc_text(struct cm_core *c)
{
    struct sha3_256_ctx ctx;
    uint8_t d[32];
    char hex[65], libs[96];
    char *spelled = NULL, *out;
    size_t n;
    if (c->object_cc == NULL || c->toolchain_id == NULL ||
        !cm_libs_text(c->object_cc, libs)) {
        out = cm_strdup("object-cc unknown");
        if (out == NULL)
            (void)cm_fail(c, "out of memory");
        return out;
    }
    sha3_256_init(&ctx);
    if (!cm_cc_sha3(c->object_cc, &ctx)) {
        (void)cm_fail(c, "cannot read the object compiler %s", c->object_cc);
        return NULL;
    }
    sha3_256_finalize(&ctx, d);
    cm_hex(d, hex);
    if (!cm_spell_real(c, c->object_cc, &spelled))
        return NULL;
    n = strlen(spelled) + strlen(libs) + strlen(c->toolchain_id) + 128;
    out = zcl_malloc(n, "clang_manifest.object_cc");
    if (out != NULL)
        (void)snprintf(out, n, "object-cc %s sha3-256 %s %s toolchain %s",
                       spelled, hex, libs, c->toolchain_id);
    else
        (void)cm_fail(c, "out of memory");
    free(spelled);
    return out;
}
