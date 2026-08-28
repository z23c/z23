/* Copyright 2026 Rhett Creighton - Apache License 2.0 */

#ifndef ZCL_TOOLS_DEV_ACTIVATION_INTERNAL_H
#define ZCL_TOOLS_DEV_ACTIVATION_INTERNAL_H

/*
 * Shared internals for the dev-lane activation engine. Split across
 * dev_activation.c (confinement / staging / orchestration / deploy-state) and
 * dev_activation_verify.c (verify / quarantine / rollback). NOT a public
 * surface — the stable contract is dev_activation.h.
 *
 * The whole engine compiles only when a dev OR test build is in effect
 * (ZCL_DEV_BUILD or ZCL_TESTING); the release binary sees an empty TU so the
 * entry-point symbols are absent by construction.
 */

#if defined(ZCL_DEV_BUILD) || defined(ZCL_TESTING)

#include "dev_activation.h"
#include "platform/process_lock.h"

#include <limits.h>
#include <stdbool.h>
#include <stddef.h>
#include <sys/types.h>

#ifndef PATH_MAX
#define PATH_MAX 4096
#endif

/* Generation ids are "gen-<64hex>" / "legacy-<64hex>" => 71 bytes + NUL. */
#define DEV_GEN_ID_MAX 80

/*
 * Bounded timeouts. The stop/start process window must OUTLIVE the dev unit's
 * TimeoutStopSec=300: killing `systemctl stop` earlier leaves systemd still
 * deactivating the unit and races the following start/probe. Keep 30 seconds
 * of control-plane headroom. A full dev datadir under the production 3 GiB
 * cgroup has now exceeded ten minutes from start to RPC readiness after an
 * unclean shutdown: integrity recovery, prover self-test, wallet rescan, and
 * index publication all completed, but the 600 s verifier killed the
 * candidate before RPC opened. Give every full-generation boot a twenty-minute
 * bounded window. Exact process identity and the readiness probe still reject
 * bad images; this only prevents a healthy, visibly-progressing boot from
 * being rolled back early.
 */
#define DEV_ACTIVATION_STOP_START_TIMEOUT_S 330
#define DEV_ACTIVATION_VERIFY_TIMEOUT_S 1200
#define DEV_ACTIVATION_RECOVERY_VERIFY_TIMEOUT_S 1200
#define DEV_ACTIVATION_VERIFY_INTERVAL_MS 250

/*
 * Live transaction state threaded through the engine. Working buffers here are
 * copied into the caller's dev_activation_result as the transaction advances.
 */
struct dev_activation_txn {
    const struct dev_activation_request *req;
    const struct dev_activation_ops *ops;
    struct dev_activation_result *result;

    /* Resolved HOME and derived lane paths. */
    char home[PATH_MAX];
    char gen_root[PATH_MAX];
    char current_link[PATH_MAX];
    char last_good_link[PATH_MAX];
    char staged_link[PATH_MAX];
    char rejected_dir[PATH_MAX];
    char lock_path[PATH_MAX];
    char inprogress_path[PATH_MAX]; /* crash-recovery marker for a live flip */
    char compat_bin[PATH_MAX];    /* ~/.local/bin/zclassic23-dev symlink */
    char build_id_dropin[PATH_MAX];
    char deploy_state[PATH_MAX];

    /* Candidate identity. */
    char candidate_sha_hex[65];
    char candidate_generation[DEV_GEN_ID_MAX];
    char candidate_dir[PATH_MAX];
    char candidate_bin[PATH_MAX];

    /* Generation cursors. */
    char previous_generation[DEV_GEN_ID_MAX];
    char current_generation[DEV_GEN_ID_MAX];
    char last_good_generation[DEV_GEN_ID_MAX];

    struct platform_process_lock lock;
    bool lock_held;
    bool activation_in_progress;
    bool recovery_boot;
};

/* ── shared low-level helpers (dev_activation.c) ─────────────────────── */

/* snprintf "%s/%s" of (a,b) into out; false on overflow. */
bool dev_activation_join(char *out, size_t out_sz, const char *a,
                         const char *b);
/* mkdir -p `path` (0755). */
bool dev_activation_mkdir_p(const char *path);
/* ISO-8601 UTC "now" into out[32]. */
void dev_activation_iso_utc_now(char out[32]);
/* Escape `in` for a JSON double-quoted value into out. */
void dev_activation_json_escape(const char *in, char *out, size_t out_sz);
/* First "key":"value" string field of a JSON blob into out; false if absent. */
bool dev_activation_json_first_string(const char *blob, const char *key,
                                      char *out, size_t out_sz);
/* Copy `src` -> `dst` with mode `mode`. */
bool dev_activation_install_file(const char *src, const char *dst, mode_t mode);

/* ── staging + deploy-state (dev_activation_stage.c) ─────────────────── */

/* Stage the candidate artifact as an immutable gen-<sha> generation. Sets the
 * txn/result candidate_* fields. Returns an enum dev_activation_status. */
int dev_activation_stage_candidate(struct dev_activation_txn *txn);
/* Import a pre-existing plain compat binary as a legacy rollback generation
 * when no current generation exists. */
void dev_activation_ensure_rollback(struct dev_activation_txn *txn);

/* ── path helpers (dev_activation.c) ─────────────────────────────────── */

/* Lexically canonicalize `in` (collapse //, ., ..; strip trailing /) into
 * `out`. Mirrors `readlink -m` for the symlink-free paths confinement checks.
 * Returns false on overflow / empty input. */
bool dev_activation_canon(const char *in, char *out, size_t out_sz);

/* Hex-encode 32 bytes into out[65] (lowercase, NUL-terminated). */
void dev_activation_hex32(const uint8_t in[32], char out[65]);

/* SHA-256 of the file at `path`, lowercase hex into out[65]. */
bool dev_activation_sha256_file(const char *path, char out[65]);

/* Read the generation id a `current`/`last-good`/`staged` symlink points to
 * (validated: gen-/legacy- prefix, no slash, backing binary executable) into
 * out[DEV_GEN_ID_MAX]. Returns false when the link is absent/invalid. */
bool dev_activation_read_gen_link(const struct dev_activation_txn *txn,
                                  const char *link, char *out, size_t out_sz);

/* Refresh current_generation / last_good_generation from the on-disk links. */
void dev_activation_refresh_gen_state(struct dev_activation_txn *txn);

/* Atomic symlink flip: gen_root/<name> -> `generation` (tmp symlink+rename).
 * Validates the generation id and that its backing binary is executable. */
bool dev_activation_link_generation(const struct dev_activation_txn *txn,
                                    const char *name, const char *generation);

/* Refresh the ~/.local/bin/zclassic23-dev compat symlink to current. */
bool dev_activation_refresh_compat_link(const struct dev_activation_txn *txn);

/* Write authoritative ZCL_AGENT_EXPECT_SOURCE_ID plus optional display-only
 * Git trace metadata for `generation`. */
bool dev_activation_write_build_identity(const struct dev_activation_txn *txn,
                                         const char *generation);

/* True iff `s` is an exact lowercase 64-hex SHA-256 identity. */
bool dev_activation_source_id_valid(const char *s);

/* Read the authoritative manifest source_id_sha256 of `generation` into out
 * (out[0]=0 if absent or malformed). */
void dev_activation_generation_source_id(
    const struct dev_activation_txn *txn, const char *generation,
    char out[65]);

/* Read optional display-only manifest build_commit metadata. */
void dev_activation_generation_commit(const struct dev_activation_txn *txn,
                                      const char *generation,
                                      char *out, size_t out_sz);

/* Write the byte-compatible zcl.agent_dev_deploy.v1 state file. */
bool dev_activation_write_deploy_state(struct dev_activation_txn *txn);

/* Remove the crash-recovery in-progress marker (best-effort). Called wherever
 * the transaction concludes (success OR rollback) so a live flip that finished
 * leaves no stale marker behind. Safe to call when no marker exists. */
void dev_activation_clear_in_progress(const struct dev_activation_txn *txn);

/* ── verify / rollback / quarantine (dev_activation_verify.c) ─────────── */

/* Bounded post-restart verification of `expected` generation: service active,
 * /proc exe identity matches the generation binary, and activation_probe
 * passes with the expected authoritative source ID. Sets
 * result->running_generation on success. Returns true on success. */
bool dev_activation_verify_running(struct dev_activation_txn *txn,
                                   const char *expected);

/* Select the normal or explicitly-authorized recovery readiness window,
 * honoring the bounded test/operator override when present. */
long dev_activation_verify_timeout_seconds(bool recovery_boot);

/* Quarantine the candidate: write rejected/<gen>.json with `reason`. */
void dev_activation_quarantine(const struct dev_activation_txn *txn,
                               const char *reason);

/* Roll the `current` link back to previous_generation, restart, and verify.
 * Sets result->rollback_status / failure_capsule. Returns true on a verified
 * recovery. Clears activation_in_progress. */
bool dev_activation_rollback_previous(struct dev_activation_txn *txn,
                                      const char *reason);

#endif /* ZCL_DEV_BUILD || ZCL_TESTING */

#endif /* ZCL_TOOLS_DEV_ACTIVATION_INTERNAL_H */
