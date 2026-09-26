/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Clean-zygote reflex runner.
 *
 * The resident watcher never forks itself to execute candidate bytes. On first
 * need it spawns ONE runner by exec of its own image (argv = {"z23-dev",
 * "__reflex-runner"}, empty environment, stdio on /dev/null, exactly one extra
 * descriptor: a SOCK_SEQPACKET control socket at ZCL_REFLEX_RUNNER_CONTROL_FD)
 * and keeps it warm. The runner therefore starts from a fresh address space:
 * no resident heap, keys, environment or descriptors exist in it.
 *
 * Per candidate the resident verifies the artifact digest, copies it into a
 * sealed memfd and sends a fixed-size versioned request plus that memfd. The
 * runner forks a disposable child which closes every other descriptor, lowers
 * rlimits, enters Landlock deny-all and the seccomp session deny-list, re-hashes
 * the memfd, and only then maps it (dlopen of /proc/self/fd/N). A second
 * seccomp layer denies PROT_EXEC mmap/mprotect before the story or frozen KAT
 * runs. The child reports in two fixed frames on one pipe: a pre-load frame
 * of its confinement, re-hash and census facts written BEFORE the candidate
 * is mapped, and one observation frame after the story. The runner adds what
 * it saw itself (exit status or signal, deadline, the leaf's final seccomp
 * layer count), kills the child at the deadline, and survives crashes.
 *
 * Everything fails closed: an unavailable runner or a failed confinement step
 * is a named red/unavailable story, never an unconfined fallback.
 */
#ifndef ZCL_TOOLS_DEV_DEVLOOP_REFLEX_RUNNER_H
#define ZCL_TOOLS_DEV_DEVLOOP_REFLEX_RUNNER_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "hotswap/hotfork_capsule.h"
#include "hotswap/hotswap_service.h"

#define ZCL_REFLEX_RUNNER_ARGV1 "__reflex-runner"
#define ZCL_REFLEX_RUNNER_ARGV0 "z23-dev"
#define ZCL_REFLEX_RUNNER_CONTROL_FD 3

enum zcl_reflex_runner_mode {
    ZCL_REFLEX_MODE_HOT_FORK = 1,
    ZCL_REFLEX_MODE_HOT_SHADOW = 2,
};

/* What the resident asks for. Every string is copied into the fixed-size
 * request; an overlong field is refused rather than truncated. */
struct zcl_reflex_runner_spec {
    enum zcl_reflex_runner_mode mode;
    const char *artifact_path;
    const char *artifact_sha256;        /* lower-hex, 64 chars */
    const char *owner_id;               /* HOT_FORK descriptor owner */
    const char *source_tu;              /* owner key for last-green state */
    const char *candidate_object_root;  /* HOT_FORK descriptor binding */
    const char *story_id;
    const char *story_root;
    const char *story_fixture_root;
    uint32_t timeout_ms;
    /* Test-only; a production caller must leave this false. Reaches the
     * already-exec'd runner as a wire request flag (see
     * ZCL_REFLEX_TESTING_DISABLE_CLOSE_RANGE), never an environment
     * variable, because the runner execs with an empty environment. */
    bool testing_disable_close_range;
};

/* The resident's validated view of one leaf. Environment facts (hash,
 * sandbox, census, canary, confine timing) come only from the pre-load
 * frame; wx_installed is the runner's own observation; story_ok,
 * descriptor_valid, candidate_executed, the post-load timings, observation
 * and service come from the observation frame and are candidate-influenced
 * data. Every string here was checked for termination before it was copied. */
struct zcl_reflex_child_report {
    bool hash_verified;
    bool descriptor_valid;
    bool sandboxed;
    bool wx_installed;
    bool candidate_executed;
    bool story_ok;
    uint32_t env_count;
    uint32_t inherited_fd_count;
    uint64_t resident_canary_seen;
    int64_t start_us;
    int64_t confine_us;
    int64_t dlopen_us;
    int64_t story_us;
    char runtime_module_sha256[65];
    char stage[32];
    char error[160];
    struct zcl_hotfork_observation_v1 observation;
    struct zcl_hotswap_service_report service;
};

struct zcl_reflex_runner_outcome {
    bool available;          /* a runner reply was obtained */
    bool green;              /* every confinement + story check held */
    bool runner_warm;        /* the runner already existed before this call */
    bool timed_out;
    bool cancelled;
    bool report_complete;
    bool seals_verified;     /* runner saw WRITE|SHRINK|GROW seals */
    bool address_space_fresh;
    int child_exit_code;     /* -1 when not exited normally */
    int child_signal;
    int runner_pid;
    uint32_t env_inherited_count;
    uint32_t inherited_fd_count;
    uint32_t runner_env_count;
    uint32_t runner_fd_count;
    uint32_t runner_deny_probes; /* startup kernel-surface probes killed */
    int64_t spawn_us;        /* 0 when warm */
    int64_t seal_us;         /* resident memfd copy + hash */
    int64_t fork_us;
    int64_t confine_us;
    int64_t dlopen_us;
    int64_t story_us;
    int64_t runner_total_us;
    char runner_sha256[65];  /* runner-measured digest of the sealed image */
    char reason[192];
    struct zcl_reflex_child_report report;
};

/* Exact-argv dispatch for any image that can host a resident: returns true
 * (and sets *rc) only for argv == {<any>, "__reflex-runner"}. Linux dev/test
 * images run the runner loop; other hosts return rc=2 without running. */
bool zcl_reflex_runner_dispatch(int argc, char **argv, int *rc);

/* Branch-free form for a host main(): exits the process with the runner's
 * status when argv selects the runner; otherwise returns and does nothing. */
void zcl_reflex_runner_exit_if_requested(int argc, char **argv);

/* Run one candidate in a fresh confined child of the warm runner. Returns
 * true when a runner reply was obtained (out->available); false with
 * out->reason on any spawn/transport/verification failure. Never executes
 * candidate bytes in the calling process. */
bool zcl_reflex_runner_run(const struct zcl_reflex_runner_spec *spec,
                           struct zcl_reflex_runner_outcome *out);

/* Artifact root of the last green candidate recorded for `source_tu`.
 * Red candidates never replace it. Returns false when none exists. */
bool zcl_reflex_runner_last_green(const char *source_tu, char out[65]);

/* Stop and reap the warm runner (next run respawns it). */
void zcl_reflex_runner_shutdown(void);

/* Resident-owned canary: the resident writes a nonzero value before it spawns
 * the runner; a fresh address space observes zero. Exported so a proof
 * fixture can try to read it from candidate code. */
extern volatile uint64_t zcl_reflex_resident_canary;

#endif /* ZCL_TOOLS_DEV_DEVLOOP_REFLEX_RUNNER_H */
