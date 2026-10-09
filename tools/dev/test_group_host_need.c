/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: Evaluate declared test-group host needs against an exact tree. */

#include "test_group_host_need.h"
#include "test_group_catalog.h"
#include "base/safe_alloc.h"

#include <limits.h>
#include <stdint.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#if !defined(_WIN32)
#include <fcntl.h>
#include <sys/wait.h>
#include <unistd.h>
#endif

#ifndef PATH_MAX
#define PATH_MAX 4096
#endif

static const struct zcl_test_group_host_need g_host_needs[] = {
#define ZCL_TEST_GROUP_NEED(full_id_, kind_, value_) \
    {kind_, full_id_, value_, NULL},
#define ZCL_TEST_GROUP_BUILD_NEED(full_id_, value_, target_) \
    {ZCL_HOST_NEED_BUILD, full_id_, value_, target_},
#include "test_group_host_needs.def"
#undef ZCL_TEST_GROUP_BUILD_NEED
#undef ZCL_TEST_GROUP_NEED
};

#define ZCL_HOST_NEED_COUNT \
    (sizeof(g_host_needs) / sizeof(g_host_needs[0]))

const char *
zcl_test_group_host_need_kind_name(enum zcl_test_group_host_need_kind kind)
{
    switch (kind) {
    case ZCL_HOST_NEED_NONE:
        return "none";
    case ZCL_HOST_NEED_FILE:
        return "file";
    case ZCL_HOST_NEED_ENV:
        return "env";
    case ZCL_HOST_NEED_C23_TOOLCHAIN:
        return "toolchain";
    case ZCL_HOST_NEED_BUILD:
        return "build";
    default:
        return NULL;
    }
}

/* A BUILD row names its Make target; no other kind carries one. */
static bool host_need_target_valid(const struct zcl_test_group_host_need *row)
{
    bool has_target = row->target && row->target[0];
    return (row->kind == ZCL_HOST_NEED_BUILD) == has_target &&
           (has_target || !row->target);
}

/* One row's own shape: a known non-NONE kind, a non-empty value naming a
 * registered group, and a target exactly when the kind is BUILD. A row that
 * fails this is a table error, not a host fact. */
static bool host_need_row_valid(size_t i)
{
    const struct zcl_test_group_host_need *row = &g_host_needs[i];
    if (!row->group || !row->group[0] || !row->value || !row->value[0] ||
        row->kind == ZCL_HOST_NEED_NONE ||
        !zcl_test_group_host_need_kind_name(row->kind) ||
        !host_need_target_valid(row)) {
        fprintf(stderr,
                "test_group_host_need: row %zu declares an unknown kind or an "
                "empty field\n", i);
        return false;
    }
    if (!zcl_test_group_catalog_contains(row->group)) {
        fprintf(stderr,
                "test_group_host_need: row %zu names unregistered group '%s'\n",
                i, row->group);
        return false;
    }
    return true;
}

/* A group may have one host gate plus distinct BUILD targets. The gate is
 * resolved before a BUILD row so universal selection cannot silently treat
 * a missing host capability as a buildable input. */
static bool host_need_pair_valid(size_t i, size_t j)
{
    const struct zcl_test_group_host_need *a = &g_host_needs[i];
    const struct zcl_test_group_host_need *b = &g_host_needs[j];
    if (strcmp(a->group, b->group) != 0)
        return true;
    if (a->kind == ZCL_HOST_NEED_BUILD && b->kind == ZCL_HOST_NEED_BUILD &&
        strcmp(a->target, b->target) != 0)
        return true;
    if ((a->kind == ZCL_HOST_NEED_BUILD) !=
        (b->kind == ZCL_HOST_NEED_BUILD))
        return true;
    fprintf(stderr,
            "test_group_host_need: group '%s' declares two needs that are "
            "not distinct BUILD targets\n", a->group);
    return false;
}

bool zcl_test_group_host_needs_valid(void)
{
    for (size_t i = 0; i < ZCL_HOST_NEED_COUNT; i++) {
        if (!host_need_row_valid(i))
            return false;
        for (size_t j = 0; j < i; j++)
            if (!host_need_pair_valid(i, j))
                return false;
    }
    return true;
}

/* Is `target` already one of the first `n` collected needs? */
static bool host_need_target_listed(const struct zcl_test_group_host_need *needs,
                                    size_t n, const char *target)
{
    for (size_t k = 0; k < n; k++)
        if (strcmp(needs[k].target, target) == 0)
            return true;
    return false;
}

bool zcl_test_group_build_needs_add(const char *group,
                                    struct zcl_test_group_host_need *needs,
                                    size_t cap, size_t *n)
{
    struct zcl_test_group_host_need gate;
    if (!needs || !n || *n > cap || !zcl_test_group_host_need(group, &gate))
        return false;
    for (size_t i = 0; i < ZCL_HOST_NEED_COUNT; i++) {
        const struct zcl_test_group_host_need *row = &g_host_needs[i];
        if (row->kind != ZCL_HOST_NEED_BUILD ||
            strcmp(row->group, group) != 0 ||
            host_need_target_listed(needs, *n, row->target))
            continue;
        if (*n >= cap) {
            fprintf(stderr,
                    "test_group_host_need: no room for '%s' build need '%s'\n",
                    group, row->target);
            return false;
        }
        needs[(*n)++] = *row;
    }
    return true;
}

bool zcl_test_group_host_need(const char *group,
                              struct zcl_test_group_host_need *out)
{
    if (!out)
        return false;
    out->kind = ZCL_HOST_NEED_NONE;
    out->group = NULL;
    out->value = NULL;
    out->target = NULL;
    if (!group || !group[0] || !zcl_test_group_catalog_contains(group)) {
        fprintf(stderr,
                "test_group_host_need: '%s' is not a registered test group\n",
                group ? group : "(null)");
        return false;
    }
    if (!zcl_test_group_host_needs_valid())
        return false;
    for (size_t i = 0; i < ZCL_HOST_NEED_COUNT; i++) {
        if (strcmp(g_host_needs[i].group, group) != 0)
            continue;
        if (g_host_needs[i].kind != ZCL_HOST_NEED_BUILD) {
            *out = g_host_needs[i];
            return true;
        }
        if (out->kind == ZCL_HOST_NEED_NONE)
            *out = g_host_needs[i];
    }
    return true;
}

#if defined(__linux__) && defined(__x86_64__)
/* A compiler probe is a host fact, not a passed test. Use only the root-owned
 * system compiler route whose libclang runtime the proof already binds.
 * stderr is discarded; the named host-gated row carries the refusal. */
static bool root_owned_regular_file(const char *path)
{
    struct stat st;
    return stat(path, &st) == 0 && st.st_uid == 0 &&
           S_ISREG(st.st_mode) && (st.st_mode & 022) == 0;
}

/* The C23 features test_semantic_facts_fuzz really feeds its compilers
 * (semantic_fuzz_templ.c / semantic_fuzz_repro.c): constexpr, static_assert
 * as a keyword, the ' digit separator, typeof, and for clang #embed with
 * __has_embed. clang 18 lacks constexpr and __has_embed, which fails the
 * group, so the probe must fail it too. gcc 14.2 has no __has_embed, and the
 * group never gives gcc an embed TU (semantic_fuzz_repro.c: "gcc 14 has
 * neither"), so gcc is probed with the common core only. /dev/null is the
 * embedded resource so the probe needs no file of its own. */
#define C23_PROBE_CORE                                                       \
    "constexpr int x = 1;\n"                                                 \
    "static_assert(x == 1, \"x\");\n"                                        \
    "static const int big = 1'0;\n"                                          \
    "typeof(x) y = 2;\n"
#define C23_PROBE_MAIN "int main(void) { return x + big + y; }\n"

static bool c23_compiler_accepts(const char *path, const char *source)
{
#if defined(__linux__) && defined(__x86_64__)
    if (!root_owned_regular_file(path))
        return false;
    int fd[2];
    if (pipe(fd) != 0)
        return false;
    size_t len = strlen(source);
    ssize_t wrote = write(fd[1], source, len);
    if (wrote != (ssize_t)len) {
        close(fd[0]); close(fd[1]);
        return false;
    }
    pid_t child = fork();
    if (child < 0) {
        close(fd[0]); close(fd[1]);
        return false;
    }
    if (child == 0) {
        int null_fd = open("/dev/null", O_WRONLY);
        if (null_fd < 0 || dup2(fd[0], STDIN_FILENO) < 0 ||
            dup2(null_fd, STDOUT_FILENO) < 0 ||
            dup2(null_fd, STDERR_FILENO) < 0)
            _exit(127);
        close(fd[0]); close(fd[1]); close(null_fd);
        char *const args[] = {(char *)path, "-std=c23", "-x", "c",
                              "-fsyntax-only", "-", NULL};
        execv(path, args);
        _exit(127);
    }
    close(fd[0]); close(fd[1]);
    int status = 0;
    pid_t waited;
    do {
        waited = waitpid(child, &status, 0);
    } while (waited < 0 && errno == EINTR);
    return waited == child && WIFEXITED(status) && WEXITSTATUS(status) == 0;
#else
    (void)path;
    (void)source;
    return false;
#endif
}

#endif /* Linux x86_64 compiler probes */

/* Mirrors the Makefile's CLANG_MANIFEST_LLVM_DIR: the first existing
 * /usr/lib/llvm-{20,21,19,18}/include/clang-c/Index.h, in that order. */
int zcl_c23_fuzz_select_llvm(const bool header[ZCL_C23_FUZZ_LLVM_N])
{
    for (int i = 0; i < ZCL_C23_FUZZ_LLVM_N; i++)
        if (header[i])
            return i;
    return -1;
}

bool zcl_c23_fuzz_toolchain_decide(const struct zcl_c23_fuzz_facts *f)
{
    if (!f || !f->gcc_c23)
        return false;
    /* A sensor that already exists runs the clang it was linked against, not
     * the one a rebuild would bind: a stale sensor makes the group fail. */
    if (f->sensor_present && !f->sensor_bound_matches_selection)
        return false;
    if (zcl_c23_fuzz_select_llvm(f->header) >= 0)
        return f->selected_clang_file && f->selected_clang_c23;
    return f->fallback_lib && f->fallback_clang_c23;
}

#if defined(__linux__) && defined(__x86_64__)
#define C23_FALLBACK_CLANG "/usr/lib/llvm-18/bin/clang"
#define C23_SENSOR_REL "build/bin/z23-clang-manifest"
#define ELF_MAX_SHNUM 1024u
#define ELF_MAX_DYN (64u * 1024u)

static const char k_probe_gcc[] = C23_PROBE_CORE C23_PROBE_MAIN;
static const char k_probe_clang[] =
    "#if __has_embed(\"/dev/null\") == __STDC_EMBED_NOT_FOUND__\n"
    "#error embed\n"
    "#endif\n"
    "static const unsigned char blob[] = {\n"
    "#embed \"/dev/null\" if_empty(0)\n"
    "};\n"
    C23_PROBE_CORE
    "int main(void) { return x + big + y + blob[0]; }\n";

static const char *const k_llvm_dirs[ZCL_C23_FUZZ_LLVM_N] = {
    "/usr/lib/llvm-20", "/usr/lib/llvm-21",
    "/usr/lib/llvm-19", "/usr/lib/llvm-18",
};

static bool elf_pread(int fd, void *buf, size_t n, uint64_t off)
{
    return pread(fd, buf, n, (off_t)off) == (ssize_t)n;
}

/* One heap block holds both tables, so a worker thread's stack stays small
 * and every path frees it once. */
struct elf_mem {
    uint8_t sh[ELF_MAX_SHNUM * 64];
    uint8_t dyn[ELF_MAX_DYN];
};

struct elf_ctx {
    int fd;
    uint64_t fsize;
    uint64_t soff, ssz; /* the dynamic section's string table */
};

/* What the dynamic section says: the string-table offset of the winning
 * runpath, and whether DT_NEEDED names exactly libclang-18.so.18. */
struct elf_dyn_info {
    bool has_runpath;
    uint64_t runpath_off;
    bool needs_clang18;
};

/* Is the NUL-terminated string at string-table offset `off` exactly `want`,
 * with its NUL inside the table? */
static bool strtab_equals(const struct elf_ctx *c, uint64_t off,
                          const char *want)
{
    char b[32];
    size_t n = strlen(want) + 1;
    return n <= sizeof(b) && off < c->ssz && c->ssz - off >= n &&
           elf_pread(c->fd, b, n, c->soff + off) && memcmp(b, want, n) == 0;
}

/* Scan the 16-byte dynamic entries. Like the test's reader, a later
 * DT_RUNPATH replaces any earlier one, and a DT_RPATH counts only when
 * nothing was found yet; the scan does not stop at DT_NULL. */
static void elf_dyn_scan(const struct elf_ctx *c, const uint8_t *dyn,
                         size_t n, struct elf_dyn_info *info)
{
    for (size_t q = 0; q < n / 16; q++) {
        uint64_t tag, val;
        memcpy(&tag, dyn + q * 16, 8);
        memcpy(&val, dyn + q * 16 + 8, 8);
        if (tag == 29 || (tag == 15 && !info->has_runpath)) {
            info->has_runpath = true;
            info->runpath_off = val;
        } else if (tag == 1 && !info->needs_clang18) {
            info->needs_clang18 = strtab_equals(c, val, "libclang-18.so.18");
        }
    }
}

/* Read the ELF64 x86-64 little-endian section header table into m->sh.
 * False on anything else. */
static bool elf_read_sections(int fd, uint64_t fsize, struct elf_mem *m,
                              size_t *shnum)
{
    uint8_t eh[64];
    uint64_t shoff;
    uint16_t machine, entsize, num;
    if (!elf_pread(fd, eh, sizeof(eh), 0) ||
        memcmp(eh, "\177ELF\2\1", 6) != 0)
        return false;
    memcpy(&machine, eh + 18, 2);
    memcpy(&shoff, eh + 40, 8);
    memcpy(&entsize, eh + 58, 2);
    memcpy(&num, eh + 60, 2);
    if (machine != 62 || entsize != 64 || num == 0 ||
        (unsigned)num > ELF_MAX_SHNUM || shoff > fsize ||
        (uint64_t)num * 64 > fsize - shoff)
        return false;
    *shnum = num;
    return elf_pread(fd, m->sh, (size_t)num * 64, shoff);
}

/* Load dynamic section sh[k] and scan it. Its linked section must be a
 * string table inside the file. */
static bool elf_dyn_section(struct elf_ctx *c, struct elf_mem *m,
                            size_t shnum, size_t k, struct elf_dyn_info *info)
{
    uint64_t doff, dsz;
    uint32_t link, stype;
    memcpy(&doff, m->sh + k * 64 + 24, 8);
    memcpy(&dsz, m->sh + k * 64 + 32, 8);
    memcpy(&link, m->sh + k * 64 + 40, 4);
    if (link >= shnum || dsz == 0 || dsz > ELF_MAX_DYN || dsz % 16 != 0 ||
        doff > c->fsize || dsz > c->fsize - doff)
        return false;
    memcpy(&stype, m->sh + (size_t)link * 64 + 4, 4);
    memcpy(&c->soff, m->sh + (size_t)link * 64 + 24, 8);
    memcpy(&c->ssz, m->sh + (size_t)link * 64 + 32, 8);
    if (stype != 3 || c->soff > c->fsize || c->ssz > c->fsize - c->soff ||
        !elf_pread(c->fd, m->dyn, dsz, doff))
        return false;
    elf_dyn_scan(c, m->dyn, dsz, info);
    return true;
}

/* The runpath string at string-table offset `off`: non-empty, with its NUL
 * inside the table and the whole string inside `cap`. */
static bool elf_runpath_string(const struct elf_ctx *c, uint64_t off,
                               char *out, size_t cap)
{
    if (off >= c->ssz || cap < 2)
        return false;
    uint64_t room = c->ssz - off;
    size_t take = room < cap ? (size_t)room : cap;
    return elf_pread(c->fd, out, take, c->soff + off) &&
           memchr(out, '\0', take) != NULL && out[0] != '\0';
}

/* The clang a RUNPATH string binds, by the test's find_clang rule: the first
 * entry ending "/lib" whose <dir>/../bin/clang is executable. */
static bool clang_from_runpath(char *rp, char *out, size_t cap)
{
    char *save = NULL;
    for (char *d = strtok_r(rp, ":", &save); d != NULL;
         d = strtok_r(NULL, ":", &save)) {
        size_t len = strlen(d);
        if (len < 4 || strcmp(d + len - 4, "/lib") != 0)
            continue;
        if ((size_t)snprintf(out, cap, "%.*s/bin/clang", (int)(len - 4), d) <
                cap &&
            access(out, X_OK) == 0)
            return true;
    }
    return false;
}

/* The dynamic info of the ELF at `fd`: no dynamic section is "nothing
 * found"; more than one is ambiguous and refused. */
static bool elf_dynamic_info(struct elf_ctx *c, struct elf_mem *m,
                             struct elf_dyn_info *info)
{
    size_t shnum = 0, dynamics = 0, at = 0;
    if (!elf_read_sections(c->fd, c->fsize, m, &shnum))
        return false;
    for (size_t k = 0; k < shnum; k++) {
        uint32_t type;
        memcpy(&type, m->sh + k * 64 + 4, 4);
        if (type == 6) {
            dynamics++;
            at = k;
        }
    }
    if (dynamics > 1)
        return false;
    return dynamics == 0 || elf_dyn_section(c, m, shnum, at, info);
}

/* The clang the sensor at `sensor` is bound to, by the test's find_clang
 * rule: the RUNPATH's clang, or with no RUNPATH the system llvm-18 clang when
 * the sensor needs exactly libclang-18.so.18. *present is false only when
 * the file is absent (ENOENT/ENOTDIR); any other failure is present and
 * unreadable, which the caller treats as not ready. Known differences from
 * the test (each can only cause the group to self-skip): no program-header
 * binding check, no root-ownership check of the fallback clang. */
static bool sensor_bound_clang(const char *sensor, char *out, size_t cap,
                               bool *present)
{
    struct stat st;
    *present = true;
    if (stat(sensor, &st) != 0) {
        *present = errno != ENOENT && errno != ENOTDIR;
        return false;
    }
    /* Not regular (FIFO, device): present and unbound. Tested before open()
     * so a FIFO cannot block the open forever. */
    if (!S_ISREG(st.st_mode))
        return false;
    struct elf_mem *m = zcl_malloc(sizeof(*m), "host_need.elf");
    int fd = open(sensor, O_RDONLY | O_CLOEXEC | O_NONBLOCK);
    struct elf_ctx c = {fd, (uint64_t)st.st_size, 0, 0};
    struct elf_dyn_info info = {0};
    char rp[PATH_MAX];
    bool ok = m != NULL && fd >= 0 && elf_dynamic_info(&c, m, &info);
    if (ok && info.has_runpath)
        ok = elf_runpath_string(&c, info.runpath_off, rp, sizeof(rp)) &&
             clang_from_runpath(rp, out, cap);
    else if (ok)
        ok = info.needs_clang18 &&
             (size_t)snprintf(out, cap, "%s", C23_FALLBACK_CLANG) < cap;
    if (fd >= 0)
        close(fd);
    free(m);
    return ok;
}

/* The facts that do not depend on the tree: which LLVM the build binds, and
 * the compilers. selected_path gets the bound clang path. */
static void c23_fuzz_gather_facts(struct zcl_c23_fuzz_facts *f,
                                  char *selected_path, size_t cap)
{
    char path[PATH_MAX];
    memset(f, 0, sizeof(*f));
    for (int i = 0; i < ZCL_C23_FUZZ_LLVM_N; i++) {
        (void)snprintf(path, sizeof(path), "%s/include/clang-c/Index.h",
                       k_llvm_dirs[i]);
        f->header[i] = access(path, F_OK) == 0;
    }
    int sel = zcl_c23_fuzz_select_llvm(f->header);
    if (sel >= 0) {
        (void)snprintf(selected_path, cap, "%s/bin/clang", k_llvm_dirs[sel]);
        f->selected_clang_file = root_owned_regular_file(selected_path);
        f->selected_clang_c23 = f->selected_clang_file &&
                                c23_compiler_accepts(selected_path,
                                                     k_probe_clang);
    } else {
        (void)snprintf(selected_path, cap, "%s", C23_FALLBACK_CLANG);
    }
    struct stat lib;
    f->fallback_lib =
        stat("/lib/x86_64-linux-gnu/libclang-18.so.18", &lib) == 0 &&
        S_ISREG(lib.st_mode) && lib.st_uid == 0 && (lib.st_mode & 022) == 0;
    f->fallback_clang_c23 = c23_compiler_accepts(C23_FALLBACK_CLANG,
                                                 k_probe_clang);
    f->gcc_c23 = c23_compiler_accepts("/usr/bin/gcc", k_probe_gcc);
}

/* The tree-dependent facts: the sensor build/bin/z23-clang-manifest under
 * `root`, the path the group execs. Without a root the sensor cannot be
 * located, so it is treated as absent. */
static void c23_fuzz_sensor_facts(const char *root, const char *selected,
                                  struct zcl_c23_fuzz_facts *f)
{
    char sensor[PATH_MAX], bound[PATH_MAX];
    if (!root || !root[0])
        return;
    /* A path that does not fit cannot be judged: present and unbound. */
    if ((size_t)snprintf(sensor, sizeof(sensor), "%s/" C23_SENSOR_REL, root) >=
        sizeof(sensor)) {
        f->sensor_present = true;
        return;
    }
    bool bound_ok = sensor_bound_clang(sensor, bound, sizeof(bound),
                                       &f->sensor_present);
    f->sensor_bound_matches_selection = bound_ok &&
                                        strcmp(bound, selected) == 0;
}
#endif

static bool c23_fuzz_toolchain_ready(const char *root)
{
#if defined(__linux__) && defined(__x86_64__)
    static bool have;
    static struct zcl_c23_fuzz_facts base;
    static char selected[PATH_MAX];
    if (!have) {
        c23_fuzz_gather_facts(&base, selected, sizeof(selected));
        have = true;
    }
    struct zcl_c23_fuzz_facts facts = base;
    c23_fuzz_sensor_facts(root, selected, &facts);
    return zcl_c23_fuzz_toolchain_decide(&facts);
#else
    (void)root;
    return false;
#endif
}

bool zcl_c23_fuzz_sensor_bound_clang_for_test(const char *sensor_path,
                                              char *out, size_t cap,
                                              bool *present)
{
    if (!present)
        return false;
    *present = false;
    if (!sensor_path || !out || cap == 0)
        return false;
#if defined(__linux__) && defined(__x86_64__)
    return sensor_bound_clang(sensor_path, out, cap, present);
#else
    return false; /* the whole need is unmet off Linux x86-64 */
#endif
}

/* Does `<root>/<value>` exist? Only existence is asked: a proof generation
 * either carries the artifact or it does not, and a deeper probe would make
 * selection depend on the artifact's content. */
static bool host_need_file_present(const char *root, const char *value)
{
    char path[PATH_MAX];
    struct stat st;
    int n = snprintf(path, sizeof(path), "%s/%s", root, value);
    if (n <= 0 || (size_t)n >= sizeof(path)) {
        fprintf(stderr,
                "test_group_host_need: file need path too long under '%s'\n",
                root);
        return false;
    }
    return stat(path, &st) == 0;
}

bool zcl_test_group_host_need_met(const char *root,
                                  const struct zcl_test_group_host_need *need)
{
    if (!need)
        return false;
    if (need->kind != ZCL_HOST_NEED_NONE && (!need->value || !need->value[0]))
        return false;
    switch (need->kind) {
    case ZCL_HOST_NEED_NONE:
        return true;
    case ZCL_HOST_NEED_FILE:
    case ZCL_HOST_NEED_BUILD: {
        if (!root || !root[0])
            return false;
        return host_need_file_present(root, need->value);
    }
    case ZCL_HOST_NEED_ENV: {
        const char *set = getenv(need->value);
        return set != NULL && set[0] != '\0';
    }
    case ZCL_HOST_NEED_C23_TOOLCHAIN:
        return strcmp(need->value, "bound-libclang18-full-c23") == 0 &&
               c23_fuzz_toolchain_ready(root);
    default:
        fprintf(stderr,
                "test_group_host_need: unknown need kind %d for '%s'\n",
                (int)need->kind, need->group ? need->group : "(null)");
        return false;
    }
}

bool zcl_test_group_host_need_selectable(
    const char *root, const struct zcl_test_group_host_need *need)
{
    if (!need)
        return false;
    if (need->kind == ZCL_HOST_NEED_NONE || need->kind == ZCL_HOST_NEED_BUILD)
        return true;
    return zcl_test_group_host_need_met(root, need);
}
