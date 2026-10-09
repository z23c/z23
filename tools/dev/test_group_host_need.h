/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: Resolve the declared host input an exact test group needs. */

#ifndef ZCL_TEST_GROUP_HOST_NEED_H
#define ZCL_TEST_GROUP_HOST_NEED_H

#include <stdbool.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/* What a group's host must already carry. NONE is the normal case: the group
 * needs nothing beyond the tree every runner already has. */
enum zcl_test_group_host_need_kind {
    ZCL_HOST_NEED_NONE = 0,
    /* `value` is a path relative to the tree the runner execs in. */
    ZCL_HOST_NEED_FILE,
    /* `value` is an environment variable name. */
    ZCL_HOST_NEED_ENV,
    /* Exact root-owned Clang/GCC pair must parse the C23 fuzz syntax. */
    ZCL_HOST_NEED_C23_TOOLCHAIN,
    /* `value` is a path relative to the tree the runner execs in, and
     * `target` the Make target that builds it there from that tree's own
     * sources. A proof whose selection carries the group builds `target` in
     * its generation before the test dimension and fails, by name, when it
     * cannot; the group is never left to self-skip. */
    ZCL_HOST_NEED_BUILD,
};

struct zcl_test_group_host_need {
    enum zcl_test_group_host_need_kind kind;
    const char *group; /* canonical full catalog id, or NULL for NONE */
    const char *value; /* path or environment name, or NULL for NONE */
    const char *target; /* BUILD only: the Make target; NULL otherwise */
};

/* Every declared row names a registered catalog group with a known kind and
 * a non-empty value. A group declares at most one host gate and may also
 * declare distinct BUILD targets. A violation is named on stderr and
 * returns false; no caller may proceed on a false. */
bool zcl_test_group_host_needs_valid(void);

/* Resolve `group`'s gating need: its FILE/ENV/TOOLCHAIN row, or first BUILD row
 * (which never gates), or NONE. Returns false — and names why — when the
 * table is invalid or `group` is not a registered catalog id; that is a
 * refusal, not an answer. Returns true with out->kind == ZCL_HOST_NEED_NONE
 * for a registered group that declares no need. */
bool zcl_test_group_host_need(const char *group,
                              struct zcl_test_group_host_need *out);

/* Append to needs[0..*n) every BUILD row `group` declares whose target is
 * not already listed, in table order, advancing *n. Collecting over a whole
 * selection therefore names each Make target once. The one resolver both the
 * proof's test-needs step and the local runner's --list-build-needs read, so
 * a local run and a landing proof build the same tools for the same groups.
 * Refuses an unregistered group, an invalid table, and a full array -- a
 * dropped need would leave its group to fail on a missing tool. */
bool zcl_test_group_build_needs_add(const char *group,
                                    struct zcl_test_group_host_need *needs,
                                    size_t cap, size_t *n);

/* Facts behind the C23 fuzz toolchain need (test_semantic_facts_fuzz). The
 * header flags follow the Makefile's CLANG_MANIFEST_LLVM_DIR order: llvm-20,
 * llvm-21, llvm-19, llvm-18 clang-c/Index.h. The first present one is the
 * LLVM the build binds, and only that LLVM's clang is judged; with none
 * present the system libclang-18 fallback facts decide. */
#define ZCL_C23_FUZZ_LLVM_N 4
struct zcl_c23_fuzz_facts {
    bool header[ZCL_C23_FUZZ_LLVM_N]; /* llvm-20, -21, -19, -18 Index.h */
    bool selected_clang_file;  /* selected <llvm>/bin/clang: root-owned file */
    bool selected_clang_c23;   /* selected clang accepts the C23 probe */
    bool fallback_lib;         /* system libclang-18 is root-owned, regular */
    bool fallback_clang_c23;   /* /usr/lib/llvm-18/bin/clang accepts */
    bool gcc_c23;              /* /usr/bin/gcc accepts */
    bool sensor_present;       /* build/bin/z23-clang-manifest exists */
    bool sensor_bound_matches_selection; /* the clang it is bound to is the
                                            selected one (stale sensor: no) */
};

/* Index of the LLVM the build binds (first present header), or -1. */
int zcl_c23_fuzz_select_llvm(const bool header[ZCL_C23_FUZZ_LLVM_N]);

/* Pure decision: is the toolchain the group would really run able to run
 * it? Exposed so tests can drive it without the host. */
bool zcl_c23_fuzz_toolchain_decide(const struct zcl_c23_fuzz_facts *f);

/* Test-visible: the clang the sensor ELF at sensor_path is bound to (its
 * RUNPATH's <dir>/bin/clang, or the system llvm-18 clang for a sensor with no
 * RUNPATH that needs libclang-18.so.18) written to out. *present is false
 * only when the file is absent (ENOENT/ENOTDIR); any other failure is
 * present, unbound. False on every malformation. */
bool zcl_c23_fuzz_sensor_bound_clang_for_test(const char *sensor_path,
                                              char *out, size_t cap,
                                              bool *present);

/* Is the need satisfied by the tree at `root` and this process's environment?
 * FILE and BUILD resolve `<root>/<value>`, so they answer for the tree a
 * runner will exec in and never for the caller's own checkout. NONE is always
 * met; an unknown kind or a missing argument is refused as unmet. */
bool zcl_test_group_host_need_met(const char *root,
                                  const struct zcl_test_group_host_need *need);

/* May a selector carry the group in the tree at `root`? NONE and BUILD
 * always -- a BUILD need is the proof's own to satisfy, and the proof fails
 * when it cannot -- FILE and ENV only when met. The universal selector and
 * its shadow reference ask this one question, so they cannot disagree. */
bool zcl_test_group_host_need_selectable(
    const char *root, const struct zcl_test_group_host_need *need);

/* Stable lowercase token for a kind, for logs. NULL on an unknown kind. */
const char *
zcl_test_group_host_need_kind_name(enum zcl_test_group_host_need_kind kind);

#ifdef __cplusplus
}
#endif

#endif /* ZCL_TEST_GROUP_HOST_NEED_H */
