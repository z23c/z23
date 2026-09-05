/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * mind — the per-NODE resident that owns rebuilding this box's code indexes,
 * and the state every reader of it shares.
 *
 * WHY A NODE AND NOT A CHECKOUT. zcl-devd@.service is instanced per checkout
 * and says so in its own description; a box with five worktrees runs five
 * devd instances. An index owner cannot work that way: the whole point is
 * that exactly ONE process rebuilds, so `mind` is one unit per node reading
 * its checkout list from a state file, not one unit per directory.
 *
 * WHAT IT OWNS. For every registered checkout the resident holds the
 * codeindex owner claim (codeindex_owner_claim), watches the source tree, and
 * is the only process that calls codeindex_rebuild for it. Everything else
 * asks, and a stale answer is refused rather than served — see docs/MIND.md.
 *
 * WHAT IT IS NOT. It is not an authority. It answers where a symbol is, who
 * owns a territory, and which tests route; it decides nothing. No gate reads
 * it, no verdict cites it.
 */

#ifndef ZCL_TOOLS_MIND_H
#define ZCL_TOOLS_MIND_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

struct json_value;

#define ZCL_MIND_PATH_MAX 1024
#define ZCL_MIND_CHECKOUTS_MAX 8
#define ZCL_MIND_GROUPS_MAX 12
#define ZCL_MIND_NAME_MAX 64

/* The state file that registers a checkout. Removing it retires the
 * resident: a mind with nothing to own must not keep a claim alive. */
#define ZCL_MIND_REGISTRY_MAGIC "zcl.mind_registry.v1"
#define ZCL_MIND_CHECKOUT_MAGIC "zcl.mind_checkout.v1"
#define ZCL_MIND_HEARTBEAT_SCHEMA "zcl.mind_heartbeat.v1"
#define ZCL_MIND_CAPSULE_SCHEMA "zcl.mind_capsule.v1"

/* One group row, as the mind saw it and as it travels to a peer. `lines` is
 * deliberately absent: the index stores no per-group line count, and a mind
 * that invented one would be a mind that lies cheaply. Adding it is a
 * codeindex schema change, which belongs to the shard lane, not here. */
struct zcl_mind_group_row {
    char      name[ZCL_MIND_NAME_MAX];
    long long files;
};

/* Per-checkout state, as the resident last observed it. `index_age_s` and
 * `stale` are facts about the generation on disk, never a promise about the
 * source tree. */
struct zcl_mind_checkout {
    char      root[ZCL_MIND_PATH_MAX];
    char      index_root[65];
    long long index_age_s;
    long long last_rebuild_ms;
    long long last_rebuild_unix;
    long long rebuilds;
    bool      indexed;
    bool      stale;
    /* What the generation HOLDS, read from the store itself when the mind
     * published it. Files and symbols are different facts: a file the
     * scanner admitted but could not parse contributes a file row and no
     * symbols, so one number for both would claim coverage the index does
     * not have. build_cold_* is the store's own receipt for the last FULL
     * build, which an incremental refresh never rewrites. */
    long long files;
    long long symbols;
    long long includes;
    long long refs;
    long long index_bytes;
    long long build_cold_ms;
    long long build_cold_files;
    /* What the mind actually SAW, recorded when it published the generation.
     * Recomputing these on a peer's request would put a database open on the
     * mesh status responder's latency path; a heartbeat read is a file. */
    size_t    group_count;
    struct zcl_mind_group_row groups[ZCL_MIND_GROUPS_MAX];
};

struct zcl_mind_heartbeat {
    long long pid;
    long long started_unix;
    long long beat_unix;
    long long last_rebuild_ms;
    size_t    checkout_count;
    struct zcl_mind_checkout checkouts[ZCL_MIND_CHECKOUTS_MAX];
};

struct zcl_mind_registry {
    size_t count;
    char roots[ZCL_MIND_CHECKOUTS_MAX][ZCL_MIND_PATH_MAX];
};


/* What one paired node says about its own mind. Decoded from the `mind`
 * member of a signed, expiring mesh-status capsule; `expires_unix` is the
 * receipt's, because the capsule never carries its own lifetime. */
struct zcl_mind_peer {
    char      index_root[65];
    long long index_age_s;
    long long checkouts;
    size_t    group_count;
    struct zcl_mind_group_row groups[ZCL_MIND_GROUPS_MAX];
};

/* ── paths ── */
bool zcl_mind_state_dir(char *out, size_t cap);
bool zcl_mind_lock_path(char *out, size_t cap);
bool zcl_mind_heartbeat_path(char *out, size_t cap);
bool zcl_mind_registry_path(char *out, size_t cap);

/* ── the registry ── */
/* False when the file is absent or unparseable. Absent is the retire signal
 * and is NOT logged as an error by the reader. */
bool zcl_mind_registry_load(struct zcl_mind_registry *out);
bool zcl_mind_registry_write(const struct zcl_mind_registry *reg);

/* ── the heartbeat ── */
bool zcl_mind_heartbeat_write(const struct zcl_mind_heartbeat *beat);
bool zcl_mind_heartbeat_read(struct zcl_mind_heartbeat *out);

/* ── the peer capsule ── */
/* Render this node's `mind` capsule member from its own heartbeat. False
 * when no heartbeat exists — a node with no mind says nothing rather than
 * claiming an empty one. */
bool zcl_mind_capsule_render(struct json_value *out);
/* Read a peer's `mind` member out of a decoded capsule object. */
bool zcl_mind_capsule_parse(const struct json_value *capsule,
                            struct zcl_mind_peer *out);

/* ── the resident ── */
/* Run until the registry file is removed or `stop` returns true. Returns 0 on
 * a clean retirement, 1 when the singleton lock is already held or the state
 * is unusable. */
typedef bool (*zcl_mind_stop_predicate)(void *opaque);
int zcl_mind_serve(zcl_mind_stop_predicate stop, void *stop_opaque,
                   long long max_cycles);

#endif /* ZCL_TOOLS_MIND_H */
