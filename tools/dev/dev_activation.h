/* Copyright 2026 Rhett Creighton - Apache License 2.0 */

#ifndef ZCL_TOOLS_DEV_ACTIVATION_H
#define ZCL_TOOLS_DEV_ACTIVATION_H

/*
 * Native transactional dev-lane activation engine.
 *
 * This is the C port of the proven shell transaction in
 * tools/dev/deploy-dev-lane.sh: it stages a prebuilt candidate binary into an
 * immutable content-addressed generation, preflights it while the running
 * process is untouched, then performs a single atomic `current` symlink flip,
 * verifies the exact /proc executable identity of the restarted service, and
 * on any failure quarantines the candidate and rolls back to the previous
 * generation. It writes a byte-compatible zcl.agent_dev_deploy.v1 state file
 * to <datadir>/agent-deploy.json — the same contract read by
 * devloop_cycle.c:read_reload_generation(), `dev generation current/history`,
 * and recover-dev-lane.sh.
 *
 * All service actions go through the `struct dev_activation_ops` vtable so the
 * transaction logic is exercisable with a fake, in-memory ops implementation.
 * The real implementation (dev_activation_default_ops) execs `systemctl --user
 * ...` and reads /proc/<pid>/exe through the fixed-argv runner
 * zcl_devloop_process_run(); every process exec is confined to ZCL_DEV_BUILD.
 *
 * The three extern entry points (dev_activation_run,
 * dev_activation_activate_generation, dev_activation_default_ops) are compiled
 * out of the release binary and their absence is proven by the lint gate
 * the lint gate check-release-no-dev-symbols (tools/lint/lintc/gate_release_no_dev_symbols.c).
 */

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Result classification returned by dev_activation_run() /
 * dev_activation_activate_generation() and mirrored into result->status.
 * DEV_ACTIVATION_E_LOCK_BUSY keeps the shell's distinct exit-75 value so the
 * "another activation owns the lock" case stays a separate, recognizable code. */
enum dev_activation_status {
    DEV_ACTIVATION_OK = 0,            /* activated (or staged) and verified */
    DEV_ACTIVATION_E_CONFINEMENT = 2, /* refused: not the isolated dev lane */
    DEV_ACTIVATION_E_STAGE = 3,       /* candidate staging / lookup failed */
    DEV_ACTIVATION_E_PREFLIGHT = 4,   /* preflight rejected; nothing touched */
    DEV_ACTIVATION_E_ACTIVATE = 5,    /* stop/start/verify failed (rolled back) */
    DEV_ACTIVATION_E_INTERNAL = 6,    /* unexpected internal error */
    /* Refused before the lock: a pending crash-only auto-reindex request is on
     * disk (<datadir>/auto_reindex_request) and this deploy would stop/restart
     * the lane, silently consuming a bounded reindex attempt before RPC comes
     * up. Mirrors deploy-dev-lane.sh:guard_pending_auto_reindex(). Override with
     * ZCL_DEV_ALLOW_AUTO_REINDEX_DEPLOY=1. */
    DEV_ACTIVATION_E_AUTO_REINDEX_PENDING = 7,
    /* Refused under the lock: a prior activation crashed mid-transaction and
     * left a stale <gen_root>/activation.in_progress marker. The lane may be in
     * a mixed state; the operator must run `make agent-dev-recover` to
     * reconcile. We never auto-roll-back another run's half-finished state. */
    DEV_ACTIVATION_E_STALE_IN_PROGRESS = 8,
    DEV_ACTIVATION_E_LOCK_BUSY = 75,  /* another activation holds the lock */
};

/* Activation mode. ACTIVATE performs the full stop/flip/start/verify
 * transaction; STAGE_ONLY builds the immutable generation and preflights it
 * but never stops or restarts the running service. */
enum dev_activation_mode {
    DEV_ACTIVATION_MODE_ACTIVATE = 0,
    DEV_ACTIVATION_MODE_STAGE_ONLY = 1,
};

/*
 * Service-action vtable. Each function returns 0 on success and non-zero on
 * failure. `ctx` is passed opaquely to every callback. These mirror the
 * ZCL_DEV_*_COMMAND seams of the shell script one-for-one.
 */
struct dev_activation_ops {
    /* Install/update the exact source-controlled unit before the first
     * service action. This makes an owner-approved activation sufficient on a
     * fresh host instead of depending on an older deploy path having run. */
    int (*service_prepare)(void *ctx);

    /* Stop / start / reload the unit. */
    int (*service_stop)(void *ctx);
    int (*service_start)(void *ctx);
    int (*service_daemon_reload)(void *ctx);
    int (*service_reset_failed)(void *ctx);

    /* 0 iff the unit is currently active. */
    int (*service_active)(void *ctx);

    /* Write the unit MainPID into *pid_out (0 or negative => not running). */
    int (*service_main_pid)(void *ctx, long *pid_out);

    /* Resolve the executable backing `pid` (readlink of /proc/<pid>/exe) into
     * `out`. Returns 0 on success. */
    int (*running_exe)(void *ctx, long pid, char *out, size_t out_sz);

    /* Preflight the staged candidate binary at `cand_bin` against the baked
     * 64-hex SHA-256 source identity. Git build_commit is trace metadata and
     * is deliberately not an activation decision input. */
    int (*preflight)(void *ctx, const char *cand_bin,
                     const char *source_id_sha256);

    /* Final source-epoch compare-and-swap after candidate preflight and
     * immediately before staging publication or service stop. Optional for
     * hermetic fake ops; the real default op fails closed without a bound
     * request source identity. */
    int (*source_epoch_cas)(void *ctx);

    /* Post-restart readiness probe for the activated generation `gen_id`.
     * `expected_source_id_sha256` is the generation manifest's authoritative
     * baked source identity. */
    int (*activation_probe)(void *ctx, const char *gen_id,
                            const char *expected_source_id_sha256);

    void *ctx;
};

/*
 * Activation request. All paths are caller-owned strings that must outlive the
 * call. `artifact_path` is a prebuilt, executable node binary (this engine
 * never builds). `source_identity` is the authoritative SHA-256 identity
 * recorded in the generation manifest and required of the candidate at
 * preflight. `build_commit` is optional display/GitHub trace metadata only.
 */
struct dev_activation_request {
    const char *repo_root;      /* absolute repository root */
    const char *artifact_path;  /* prebuilt candidate binary (executable) */
    const char *build_commit;   /* optional display-only Git trace */
    const char *build_type;     /* "fast" | "strict" | ... (state file field) */
    const char *source_identity;/* authoritative 64-hex SHA-256 source id */
    /* Optional ABA mutation token captured with source_identity.  Real ops
     * verify both fields atomically immediately before publication.  Legacy
     * internal callers may leave this NULL and retain source-content CAS. */
    const char *source_mutation;
    /* Optional resident-generation compare-and-swap.  When non-NULL, the
     * activation lock requires `current` to still equal this exact generation
     * (the empty string means no current generation). */
    const char *expected_current_generation;
    const char *gen_root;       /* content-addressed generation store root */
    const char *datadir;        /* must resolve to ~/.zclassic-c23-dev */
    const char *unit;           /* must be "zcl23-dev.service" */
    int rpcport;                /* must be 18252 */
    enum dev_activation_mode mode;
};

#ifdef ZCL_TESTING
/* One-shot staging race hook after the source artifact is initially hashed and
 * before it is copied into the immutable generation. */
void dev_activation_stage_test_set_after_hash_hook(void (*hook)(void *),
                                                   void *ctx);
#endif

/*
 * Activation result. All string fields are NUL-terminated. `status` mirrors
 * the enum dev_activation_status return value.
 */
struct dev_activation_result {
    int status;
    char activation_status[32]; /* preparing|staged|active|rolled_back|failed */
    char rollback_status[40];   /* not_needed|verified|unavailable|... */
    char verify_status[32];     /* ready|staged|preflight_failed|... */
    char candidate_generation[80];
    char running_generation[80];
    char candidate_sha256[65];
    char verify_detail[256];
    char failure_capsule[256];
};

/*
 * Run the full activation transaction described by `req`. When `ops` is NULL
 * the real systemctl/proc implementation (dev_activation_default_ops) is used.
 * Returns an enum dev_activation_status value (0 on success). `result` is
 * always fully populated (even on failure) so the caller can render the
 * deploy-state contract.
 */
int dev_activation_run(const struct dev_activation_request *req,
                       const struct dev_activation_ops *ops,
                       struct dev_activation_result *result);

/*
 * Activate an already-staged generation identified by its 32-byte binary
 * SHA-256 (the Wave 3.3 revert hook). No build and no re-staging occurs: the
 * generation directory gen-<hex> must already exist under req->gen_root with a
 * matching binary. Otherwise identical semantics to dev_activation_run() in
 * ACTIVATE mode (preflight, atomic flip, verify, rollback-on-failure).
 */
int dev_activation_activate_generation(const uint8_t gen_sha256[32],
                                       const struct dev_activation_request *req,
                                       const struct dev_activation_ops *ops,
                                       struct dev_activation_result *result);

/*
 * Fill *out with the real service-action implementation (execs `systemctl
 * --user ...` via the fixed-argv runner, reads /proc/<pid>/exe). `ctx` is
 * bound to `req`, which must outlive any use of the returned ops. Present only
 * in dev builds; absent from the release binary by construction.
 */
void dev_activation_default_ops(const struct dev_activation_request *req,
                                struct dev_activation_ops *out);

#ifdef __cplusplus
}
#endif

#endif /* ZCL_TOOLS_DEV_ACTIVATION_H */
