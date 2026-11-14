/* Copyright 2026 Rhett Creighton; SPDX-License-Identifier: Apache-2.0.
 * purpose: Builds the three fixed-result verifier images (tool, source,
 *          check) as root layouts with fixed modes and sorted entries,
 *          discovers the host GCC driver's closure of the pinned test-fast
 *          result.c compile, and proves without root that the tool image
 *          is complete. It signs and authorizes nothing: every root it
 *          prints is an input for review and for root's pins file. */
#ifndef ZCL_VERIFY_FIXED_RESULT_IMAGE_H
#define ZCL_VERIFY_FIXED_RESULT_IMAGE_H

#include "verify/fixed_result_contract.h"

#include <limits.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <sys/types.h>

/* Refusal tokens. Each is printed as fixed_result_image_refuse=<token>
 * followed by the offending path. */
#define ZCL_FRI_WHY_ARGS "image_arguments_invalid"
#define ZCL_FRI_WHY_ROOT_EXISTS "image_root_exists"
#define ZCL_FRI_WHY_ROOT_UNSAFE "image_root_unsafe"
#define ZCL_FRI_WHY_MISSING "input_missing"
#define ZCL_FRI_WHY_UNREADABLE "input_unreadable"
#define ZCL_FRI_WHY_SPECIAL "input_special"
#define ZCL_FRI_WHY_NOT_DIR "input_not_directory"
#define ZCL_FRI_WHY_ESCAPES "input_symlink_escapes"
#define ZCL_FRI_WHY_LOOP "input_symlink_loop"
#define ZCL_FRI_WHY_CHANGED "input_changed"
#define ZCL_FRI_WHY_PIN "input_pin_mismatch"
#define ZCL_FRI_WHY_LIMIT "image_limit"
#define ZCL_FRI_WHY_CONFLICT "image_conflict"
#define ZCL_FRI_WHY_WRITE "image_write_failed"
#define ZCL_FRI_WHY_IMAGE_CHANGED "image_changed"
#define ZCL_FRI_WHY_EXTRA "image_extra_entry"
#define ZCL_FRI_WHY_ALLOC "image_allocation_failed"
#define ZCL_FRI_WHY_ELF "elf_unsupported"
#define ZCL_FRI_WHY_ELF_SEARCH "elf_search_path_unsupported"
#define ZCL_FRI_WHY_ELF_NEEDED "elf_needed_missing"
#define ZCL_FRI_WHY_PROFILE "profile_mismatch"
#define ZCL_FRI_WHY_SPAWN "compiler_spawn_failed"
#define ZCL_FRI_WHY_COMPILE "compile_failed"
#define ZCL_FRI_WHY_TRACE "trace_unparsed"
#define ZCL_FRI_WHY_TRACE_WRITE "trace_write_outside_scratch"
#define ZCL_FRI_WHY_TRACE_ERRNO "trace_unexpected_error"
#define ZCL_FRI_WHY_STRACE "strace_unavailable"
#define ZCL_FRI_WHY_NAME "check_name_invalid"

#define ZCL_FRI_MAX_ENTRIES 4096u
#define ZCL_FRI_MAX_FILE (512ULL * 1024ULL * 1024ULL)
#define ZCL_FRI_MAX_BYTES (4ULL * 1024ULL * 1024ULL * 1024ULL)
#define ZCL_FRI_PROFILE_ARGS ZCL_FR_PROFILE_ARGC
#define ZCL_FRI_TARGET \
    "build/test-obj/epochs/" \
    "0000000000000000000000000000000000000000000000000000000000000000" \
    "/platform/modules/base/src/result.o"

struct zcl_fri_entry {
    char *path;      /* image-relative, no leading slash */
    char kind;       /* 'D', 'F' or 'L' */
    unsigned mode;   /* fixed image mode */
    char *target;    /* 'L': stored relative target */
    char *source;    /* 'F': host path the bytes came from, or NULL */
    uint64_t size;
    uint8_t sha3[32];
};

struct zcl_fri_image;
typedef void (*zcl_fri_copy_hook)(void *ctx, const char *host_path);

struct zcl_fri_image {
    char root[PATH_MAX];      /* absolute image directory */
    char host_root[PATH_MAX]; /* "" is the real "/"; fixtures use a dir */
    struct zcl_fri_entry *entries;
    size_t count, cap;
    uint64_t bytes;
    const char *why;
    char why_path[PATH_MAX];
    zcl_fri_copy_hook after_copy; /* fixtures change an input mid-build */
    void *hook_ctx;
};

struct zcl_fri_roots {
    uint8_t tree_sha3[32];      /* measured, owner-bound */
    uint8_t content_sha3[32];   /* owner-independent */
    uint8_t root_tree_sha3[32]; /* the same bytes owned by UID 0 */
    uid_t owner;
    unsigned entries;
    uint64_t bytes;
};

/* ── image core (fixed_result_image.c) ─────────────────────────────── */

/* Creates `root` (absolute, must not exist; its parent must). host_root is
 * NULL or "" for the real filesystem. */
bool zcl_fri_image_begin(struct zcl_fri_image *img, const char *root,
                         const char *host_root);
void zcl_fri_image_free(struct zcl_fri_image *img);

/* Materializes an absolute host path at the same absolute path in the image:
 * every directory on the way, every symlink hop (absolute targets rewritten
 * relative, so they resolve inside the image) and the final file or
 * directory. `physical` receives the resolved host path. */
bool zcl_fri_add_host_path(struct zcl_fri_image *img, const char *host_path,
                           char physical[PATH_MAX]);
/* Copies one regular host file to an arbitrary image path. */
bool zcl_fri_add_copy(struct zcl_fri_image *img, const char *rel,
                      const char *host_file);
/* A directory (and its parents) that exists only in the image. */
bool zcl_fri_add_dir(struct zcl_fri_image *img, const char *rel);
/* An empty regular file: a bind-mount target. */
bool zcl_fri_add_empty(struct zcl_fri_image *img, const char *rel,
                       unsigned mode);
const struct zcl_fri_entry *zcl_fri_find(const struct zcl_fri_image *img,
                                         const char *rel);

/* Re-hashes every host input and every image file against what was copied,
 * then hashes the tree three ways. The tree walk must see exactly the
 * recorded entries plus the root. */
bool zcl_fri_image_finish(struct zcl_fri_image *img,
                          struct zcl_fri_roots *roots);
bool zcl_fri_manifest_write(const struct zcl_fri_image *img, const char *kind,
                            const struct zcl_fri_roots *roots, FILE *out);
/* Emulates a chroot lookup of an absolute path inside the finished image,
 * following the image's own links. Returns 'D', 'F', 'L' (dangling), or 0
 * when absent; `rel` receives the physical image-relative path. */
char zcl_fri_image_lookup(const char *image_root, const char *path,
                          char rel[PATH_MAX]);
bool zcl_fri_sha3_file(const char *path, uint8_t out[32], uint64_t *size);

/* ── ELF closure (fixed_result_image_elf.c) ────────────────────────── */

/* Adds an executable, its PT_INTERP and its DT_NEEDED closure, resolved
 * in the loader's default x86-64 directories. RPATH/RUNPATH refuses. */
typedef bool (*zcl_fri_path_fn)(void *ctx, const char *physical);
/* `seen`, when non-NULL, receives the physical path of every object. */
bool zcl_fri_add_elf_closure(struct zcl_fri_image *img, const char *host_path,
                             zcl_fri_path_fn seen, void *ctx);
/* The same closure for a file that is not itself placed in the image. */
bool zcl_fri_add_elf_deps(struct zcl_fri_image *img, const char *host_file);
/* The program interpreter named by an ELF file, "" when it has none. */
bool zcl_fri_elf_interp(const char *path, char interp[PATH_MAX],
                        const char **why);

/* ── the three images (fixed_result_image_build.c) ─────────────────── */

struct zcl_fri_discovery {
    bool traced;             /* strace observed the compile */
    unsigned trace_present;  /* tool paths the compile found */
    unsigned trace_absent;   /* tool paths the compile probed and missed */
    unsigned static_files;   /* regular files the static walk named */
    unsigned static_only;    /* static files the trace never opened */
    unsigned trace_only;     /* traced files the static walk never named */
    bool specs_builtin;      /* no specs file: GCC used its built-in specs */
    char static_only_first[PATH_MAX];
    char trace_only_first[PATH_MAX];
};

/* The profile as the worker runs it: the pinned lines with @CWD@ expanded
 * once, then the worker's exact -MMD/-MP/-MF/-MT/-c|-E/-o tail. */
struct zcl_fri_argv {
    char *bytes;
    char *argv[ZCL_FRI_PROFILE_ARGS + 24u];
    size_t argc;
    char expanded[PATH_MAX * 2];
};
const char *zcl_fri_argv_make(struct zcl_fri_argv *a, const char *profile,
                              const char *cwd, const char *target,
                              const char *out, const char *dep,
                              bool preprocess);
void zcl_fri_argv_free(struct zcl_fri_argv *a);

/* Source image: the three pinned files at their repository paths and the
 * profile's ordered -I directories, empty. `repo` is the absolute root the
 * pinned files are copied from; each file's SHA3 must equal its pin. */
bool zcl_fri_build_source(struct zcl_fri_image *img, const char *repo,
                          const char *profile);
/* Tool image: traces (when strace exists and `allow_trace`) and statically
 * walks both worker compiles in a fresh source image built from `repo`
 * under `scratch`, then materializes the union plus the jail's mount points and
 * the pinned profile at /etc/z23verify/fixed_result_fast.args. */
bool zcl_fri_build_tool(struct zcl_fri_image *img, const char *profile,
                        const char *repo, const char *scratch,
                        bool allow_trace, struct zcl_fri_discovery *d);
/* Check image: each NAME=PATH executable at /usr/local/libexec/NAME plus
 * its ELF closure. */
bool zcl_fri_build_check(struct zcl_fri_image *img, char *const *specs,
                         size_t count);

/* ── process and trace plumbing (fixed_result_image_run.c) ─────────── */

struct zcl_fri_run {
    char *const *argv;
    char *const *envp;
    const char *path;     /* executable */
    const char *cwd;
    const char *out_path; /* stdout file, or NULL for /dev/null */
    const char *err_path; /* stderr file, or NULL for /dev/null */
};
bool zcl_fri_run_wait(const struct zcl_fri_run *r, int *exit_code);
bool zcl_fri_strace_available(void);

enum zcl_fri_state { ZCL_FRI_PRESENT = 1, ZCL_FRI_ABSENT = 2 };
struct zcl_fri_access {
    char *path;   /* absolute, as the process spelled it (cwd joined) */
    int state;    /* zcl_fri_state */
    bool write;   /* creates, truncates, renames or removes */
};
struct zcl_fri_trace {
    struct zcl_fri_access *v;
    size_t count, cap;
    const char *why;
    char why_line[256];
};
/* Parses every per-process strace file under `dir` (strace -ff -o dir/t). */
bool zcl_fri_trace_parse_dir(struct zcl_fri_trace *t, const char *dir,
                             const char *cwd);
bool zcl_fri_trace_parse_line(struct zcl_fri_trace *t, const char *line,
                              const char *cwd, char pending[512]);
void zcl_fri_trace_free(struct zcl_fri_trace *t);
/* Runs argv under strace -f -ff into `trace_dir` with the given env. */
bool zcl_fri_trace_run(const struct zcl_fri_run *r, const char *trace_dir,
                       int *exit_code);

/* Where one traced path lies. The image, snapshot and scratch directories
 * are compared after lexical normalization; everything else is the tool
 * namespace the jail replaces with the tool image. */
enum zcl_fri_class {
    ZCL_FRI_C_TOOL, ZCL_FRI_C_IMAGE, ZCL_FRI_C_SNAPSHOT, ZCL_FRI_C_SCRATCH,
    ZCL_FRI_C_TMP, ZCL_FRI_C_DEV_NULL, ZCL_FRI_C_PROC_SELF,
    ZCL_FRI_C_LOADER_CACHE, ZCL_FRI_C_ANCESTOR
};
struct zcl_fri_zones {
    const char *image;    /* NULL outside the proof */
    const char *snapshot; /* the compile's cwd */
    const char *scratch;  /* outputs and traces */
};
enum zcl_fri_class zcl_fri_classify(const struct zcl_fri_zones *z,
                                    const char *path);

/* ── no-root completeness proof (fixed_result_image_proof.c) ───────── */

#define ZCL_FRI_NAMED 8u
struct zcl_fri_proof {
    uint8_t reference_object[32];
    uint8_t image_object[32];
    uint64_t object_size;
    bool object_equal, dep_equal, stderr_equal;
    bool traced;
    unsigned leaks, ancestors, absent_outside, image_reads;
    char leak[ZCL_FRI_NAMED][PATH_MAX];
    char absent[ZCL_FRI_NAMED][PATH_MAX];
    unsigned eq_present, eq_absent, eq_mismatch;
    char mismatch[ZCL_FRI_NAMED][PATH_MAX];
    const char *why;
    char why_path[PATH_MAX];
};
/* Compiles the pinned argv twice from a fresh source image of `repo` under
 * `scratch`: once with the host's /usr/bin/cc (the cold reference) and once
 * entirely from the tool image through its own loader, with the loader
 * cache inhibited, the library path, GCC_EXEC_PREFIX, COMPILER_PATH and
 * --sysroot confined to the image, and -ffile-prefix-map folding the image
 * prefix away. Traces the image run and names every path outside the image,
 * snapshot and scratch; traces the host run and checks that the image
 * presents each path it found and hides each path it missed. */
bool zcl_fri_prove(const char *tool_image, const char *repo,
                   const char *profile, const char *scratch,
                   struct zcl_fri_proof *p);

#endif
