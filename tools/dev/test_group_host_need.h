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
};

struct zcl_test_group_host_need {
    enum zcl_test_group_host_need_kind kind;
    const char *group; /* canonical full catalog id, or NULL for NONE */
    const char *value; /* path or environment name, or NULL for NONE */
};

/* Every declared row names a registered catalog group exactly once, with a
 * known kind and a non-empty value. A violation is named on the diagnostic
 * stream and returns false; no caller may proceed on a false. */
bool zcl_test_group_host_needs_valid(void);

/* Resolve `group`'s declared need. Returns false — and names why — when the
 * table is invalid or `group` is not a registered catalog id; that is a
 * refusal, not an answer. Returns true with out->kind == ZCL_HOST_NEED_NONE
 * for a registered group that declares no need. */
bool zcl_test_group_host_need(const char *group,
                              struct zcl_test_group_host_need *out);

/* Is the need satisfied by the tree at `root` and this process's environment?
 * FILE resolves `<root>/<value>`, so it answers for the tree a runner will
 * exec in and never for the caller's own checkout. NONE is always met; an
 * unknown kind or a missing argument is refused as unmet. */
bool zcl_test_group_host_need_met(const char *root,
                                  const struct zcl_test_group_host_need *need);

/* Stable lowercase token for a kind, for logs. NULL on an unknown kind. */
const char *
zcl_test_group_host_need_kind_name(enum zcl_test_group_host_need_kind kind);

#ifdef __cplusplus
}
#endif

#endif /* ZCL_TEST_GROUP_HOST_NEED_H */
