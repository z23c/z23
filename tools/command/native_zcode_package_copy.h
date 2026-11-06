/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: shared reader for personal package copies made by
 * zcode.package.fork — the fork record, the verified version chain, the
 * persisted release lookup and the plan/confirm helpers the fork, version and
 * share leaves use. No new record: a copy is an ordinary ZVCS repository
 * whose first commit has phase "fork" and task_ref "zcode.fork:<release>". */

#ifndef ZCL_NATIVE_ZCODE_PACKAGE_COPY_H
#define ZCL_NATIVE_ZCODE_PACKAGE_COPY_H

#include "command/native_command.h"
#include "json/json.h"
#include "vcs/package_release.h"
#include "vcs/vcs.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define ZCL_PACKAGE_COPY_FORK_PHASE "fork"
#define ZCL_PACKAGE_COPY_FORK_PREFIX "zcode.fork:"

struct zcl_package_copy {
    struct vcs_repo *repo;
    size_t versions;
    uint8_t head_version[32];
    uint8_t head_tree[32];
    uint8_t fork_version[32];
    uint8_t fork_tree[32];
    uint8_t parent_release[32];
};

enum zcl_package_copy_lookup {
    ZCL_PACKAGE_COPY_FOUND = 0,
    ZCL_PACKAGE_COPY_UNKNOWN,
    ZCL_PACKAGE_COPY_AMBIGUOUS,
    ZCL_PACKAGE_COPY_IO,
};

/* Fail the reply with one named refusal. */
void zcl_package_copy_fail(struct zcl_command_reply *reply, const char *code,
                           bool mutated, const char *message,
                           const char *evidence);

/* The non-empty string at key, or NULL. */
const char *zcl_package_copy_str(const struct json_value *input,
                                 const char *key);

/* Input datadir, else the operator datadir; fails the reply when neither. */
const char *zcl_package_copy_datadir(const struct json_value *input,
                                     struct zcl_command_reply *reply,
                                     const char *command);

/* True only for a JSON boolean confirm:true. */
bool zcl_package_copy_confirmed(const struct json_value *input);

/* The commit half: input plan_id must decode and equal want. Fails the reply
 * with PLAN_ID_REQUIRED or PLAN_MISMATCH otherwise. */
bool zcl_package_copy_plan_matches(const struct json_value *input,
                                   const uint8_t want[32],
                                   struct zcl_command_reply *reply,
                                   const char *command);

void zcl_package_copy_push_root(struct json_value *obj, const char *key,
                                const uint8_t root[32]);

/* Open dir's EXISTING ZVCS history (never creating one), walk it newest
 * first, require an unbroken parent chain that ends at a root commit with the
 * fork record, and fill copy. On refusal the reply names NOT_A_PACKAGE_COPY
 * or COPY_HISTORY_INVALID and nothing stays open. */
bool zcl_package_copy_open(const char *dir, struct zcl_package_copy *copy,
                           struct zcl_command_reply *reply,
                           const char *command);
void zcl_package_copy_close(struct zcl_package_copy *copy);

/* Count working-tree changes against the saved head. */
bool zcl_package_copy_unsaved(struct zcl_package_copy *copy, size_t *changes);

/* Find the persisted release under <datadir>/zcode/releases whose release id
 * equals root, or else the single release whose package root equals root. */
enum zcl_package_copy_lookup zcl_package_copy_find_release(
    const char *datadir, const uint8_t root[32],
    struct vcs_package_release *release_out, uint8_t release_id_out[32]);

/* zcode.commons.lineage support: append `releases` rows (release, name,
 * semver, sequence, parent release and parent package root) for every
 * persisted release of package_root under datadir. */
bool zcl_package_copy_lineage_releases(const char *datadir,
                                       const uint8_t package_root[32],
                                       struct json_value *data);

#endif
