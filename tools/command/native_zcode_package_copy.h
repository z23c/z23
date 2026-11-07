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
/* The only phases a copy's own leaves write after the fork record:
 * zcode.package.version.save and the source-only vcs_revert of
 * zcode.package.version.restore. Any other phase after the fork record is a
 * FOREIGN commit: a later leaf that fetches or merges someone else's work
 * into a copy must write its own phase, never one of these. */
#define ZCL_PACKAGE_COPY_SAVE_PHASE "save"
#define ZCL_PACKAGE_COPY_RESTORE_PHASE "revert"

struct zcl_package_copy {
    struct vcs_repo *repo;
    size_t versions;
    /* Commits after the fork record whose phase is not a local one. */
    size_t foreign_versions;
    uint8_t head_version[32];
    uint8_t head_tree[32];
    uint8_t selected_version[32];
    uint8_t selected_tree[32];
    uint8_t fork_version[32];
    uint8_t fork_tree[32];
    uint8_t parent_release[32];
};

/* How a copy's history is opened. */
enum zcl_package_copy_access {
    /* History reads only (vcs_open_readonly): nothing under the copy is
     * created, changed or removed, and a damaged log is refused untouched.
     * version.list, the copies list and the adoption check. */
    ZCL_PACKAGE_COPY_READ = 0,
    /* The READ verification first, then the full open a status scan needs:
     * a damaged log is refused before anything opens it for writing. Plan
     * halves and share. */
    ZCL_PACKAGE_COPY_CHECKED,
    /* The recovering open (a torn tail is truncated before the walk):
     * confirmed version.save and version.restore only. */
    ZCL_PACKAGE_COPY_RECOVER,
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

/* Open dir's EXISTING ZVCS history (never creating one) as `access` says,
 * walk it newest first, require an unbroken parent chain that ends at a root
 * commit with the fork record, and fill copy. On refusal the reply names
 * NOT_A_PACKAGE_COPY or COPY_HISTORY_INVALID and nothing stays open. */
bool zcl_package_copy_open_as(const char *dir,
                              enum zcl_package_copy_access access,
                              struct zcl_package_copy *copy,
                              struct zcl_command_reply *reply,
                              const char *command);
/* zcl_package_copy_open_as(..., ZCL_PACKAGE_COPY_CHECKED, ...). */
bool zcl_package_copy_open(const char *dir, struct zcl_package_copy *copy,
                           struct zcl_command_reply *reply,
                           const char *command);
/* CHECKED open; NULL selects HEAD, otherwise require an exact version in
 * the fully validated history or refuse VERSION_UNKNOWN. */
bool zcl_package_copy_open_selected(const char *dir, struct zcl_package_copy *copy,
    struct zcl_command_reply *reply, const char *command, const char *version);
void zcl_package_copy_close(struct zcl_package_copy *copy);
/* Exact selection with explicit access; READ never creates or recovers
 * history/index state. Full chain and fork validation still precedes success. */
bool zcl_package_copy_open_selected_as(const char *dir,
    enum zcl_package_copy_access access, struct zcl_package_copy *copy,
    struct zcl_command_reply *reply, const char *command, const char *version);

/* Resolve input `root` (a persisted release id, or a package root carried by
 * exactly one persisted release) under datadir and verify the envelope.
 * Fails the reply with BAD_ROOT, FORK_ROOT_UNKNOWN, FORK_ROOT_AMBIGUOUS,
 * RELEASES_UNREADABLE or FORK_PARENT_INVALID. */
bool zcl_package_copy_resolve_release(const struct json_value *input,
                                      const char *datadir,
                                      struct vcs_package_release *release,
                                      uint8_t release_id[32],
                                      struct zcl_command_reply *reply,
                                      const char *command);

struct vcs_package_checkout_metrics;

/* Reconstruct `release` beneath the absent `destination` through the verified
 * package checkout, then write the fork record as the copy's first commit;
 * `session` (NULL for none) is bound into that commit. On success `version`
 * is the fork record's commit id. */
bool zcl_package_copy_make(const char *datadir,
                           const struct vcs_package_release *release,
                           const uint8_t release_id[32],
                           const char *destination, const char *session,
                           uint8_t version[32],
                           struct vcs_package_checkout_metrics *metrics,
                           struct zcl_command_reply *reply);

/* Count working-tree changes against the saved head. */
bool zcl_package_copy_unsaved(struct zcl_package_copy *copy, size_t *changes);

/* Find the persisted release under <datadir>/zcode/releases whose release id
 * equals root, or else the single release whose package root equals root. */
enum zcl_package_copy_lookup zcl_package_copy_find_release(
    const char *datadir, const uint8_t root[32],
    struct vcs_package_release *release_out, uint8_t release_id_out[32]);

/* The owner's publisher key file, ~/.z23/zcode_publisher.key (the release
 * key format plugin publish --release-key reads), created 0600 on first
 * use; *created says whether this call made it. Only its public key is
 * read: signing stays inside plugin_dist_release_key_sign. Fails the reply
 * PUBLISHER_KEY_UNAVAILABLE (no absolute HOME) or PUBLISHER_KEY_REFUSED. */
bool zcl_package_copy_owner_key(
    char *key_path, size_t key_path_cap,
    uint8_t pubkey[VCS_PACKAGE_RELEASE_PUBKEY_BYTES], bool *created,
    struct zcl_command_reply *reply, const char *command);

/* The publisher sequence pubkey's next release under datadir takes (1 for
 * a publisher with none). Fails the reply RELEASES_UNREADABLE. */
bool zcl_package_copy_next_sequence(
    const char *datadir, const uint8_t pubkey[VCS_PACKAGE_RELEASE_PUBKEY_BYTES],
    uint64_t *sequence, struct zcl_command_reply *reply);

/* zcode.commons.lineage support: append `releases` rows (release, name,
 * semver, sequence, parent release and parent package root) for every
 * persisted release of package_root under datadir. */
bool zcl_package_copy_lineage_releases(const char *datadir,
                                       const uint8_t package_root[32],
                                       struct json_value *data);

/* ── adoption (zcode.package.adopt) ─────────────────────────────────────
 *
 * The owner's decision to keep and run one release as their own copy. The
 * adopt record lives in the DATADIR, never in the copy, at
 * <datadir>/zcode/adopted/<key hex>.adopt with key = SHA3-256(
 * "zcl.package_adopt.key.v1" 0x00 || copy root commit || release id). The
 * copy itself lives at <datadir>/copies/<name>. Adoption covers the copy's
 * later LOCAL commits (save and restore) that descend from that root; any
 * other commit after the root needs a new adopt. */

#define ZCL_PACKAGE_ADOPT_NAME_MAX 32u
#define ZCL_PACKAGE_ADOPT_PUBKEY_BYTES 33u
/* The base of a copy name; "-<n>" (n up to 999) follows it. */
#define ZCL_PACKAGE_COPY_BASE_MAX 24u

/* The base of a release's copy names: the last segment of its name, lowered
 * to [a-z0-9._-] ("skycombat/skycombat" gives "skycombat"). */
void zcl_package_copy_name_base(const char *release_name,
                                char base[ZCL_PACKAGE_COPY_BASE_MAX + 1u]);

/* The first absent <datadir>/copies/<base>-<n> for this release name: name
 * gets "<base>-<n>" and dir the path. COPIES_FULL otherwise. */
bool zcl_package_copy_pick_name(const char *datadir, const char *release_name,
                                char name[ZCL_PACKAGE_ADOPT_NAME_MAX + 1u],
                                char *dir, size_t cap,
                                struct zcl_command_reply *reply);

struct zcl_package_adopt_record {
    uint8_t root_commit[32];   /* the copy's fork record commit */
    uint8_t release_id[32];
    uint8_t package_root[32];
    uint8_t parent_release[32]; /* zero when the release has no parent */
    uint8_t publisher_pubkey[ZCL_PACKAGE_ADOPT_PUBKEY_BYTES];
    uint64_t adopted_at;
    char name[ZCL_PACKAGE_ADOPT_NAME_MAX + 1u]; /* copies/<name> */
};

enum zcl_package_copy_adoption {
    ZCL_PACKAGE_COPY_ADOPTED = 0,
    ZCL_PACKAGE_COPY_NOT_ADOPTED,
    ZCL_PACKAGE_COPY_FOREIGN_COMMITS,
    ZCL_PACKAGE_COPY_ADOPTION_UNREADABLE,
    /* No adopt record, but the owner confirmed this received copy's
     * publisher and root once at zcode.package.bundle.receive (owner
     * decision 11-06): it may be built and opened like an adopted copy. */
    ZCL_PACKAGE_COPY_RECEIVED_TRUSTED,
};

/* "adopted", "not_adopted", "foreign_commits", "received_trusted" or
 * "adoption_unreadable". */
const char *zcl_package_copy_adoption_name(enum zcl_package_copy_adoption a);

/* Validate, encode and durably write the record (tmp, fsync, rename, fsync
 * dir) under <datadir>/zcode/adopted. */
bool zcl_package_adopt_record_save(const char *datadir,
                                   const struct zcl_package_adopt_record *rec);

/* Load the record for (root_commit, release_id). *found false with true is
 * no record; a present record that is malformed or names other inputs
 * returns false. */
bool zcl_package_adopt_record_load(const char *datadir,
                                   const uint8_t root_commit[32],
                                   const uint8_t release_id[32],
                                   struct zcl_package_adopt_record *out,
                                   bool *found);

/* Is this open copy adopted? ADOPTED needs a datadir record for (the copy's
 * fork record commit, its parent release), the copy to be the directory
 * <datadir>/copies/<record name> itself, and every later commit to be a
 * local save or restore; FOREIGN_COMMITS when the record and place hold but
 * a later commit is not local. A hand-written or copied commit log is never
 * adoption. `record` (optional) receives the record when one was found.
 * With no adopt record, a received copy is RECEIVED_TRUSTED when the
 * datadir holds the owner's receive trust record for (its fork record
 * commit, its parent release), that release is persisted here with the
 * trusted package root, and every later commit is local (else
 * FOREIGN_COMMITS). One check serves adopted and received copies. */
enum zcl_package_copy_adoption zcl_package_copy_adopted(
    const char *datadir, const struct zcl_package_copy *copy,
    struct zcl_package_adopt_record *record);

#endif
