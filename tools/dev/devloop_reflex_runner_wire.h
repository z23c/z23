/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Private fixed-size frames between the resident client and the clean-zygote
 * reflex runner. Both ends are the same image, but every frame still carries
 * magic, ABI version, kind and size so a stale or foreign peer is refused by
 * name instead of being reinterpreted. SOCK_SEQPACKET preserves boundaries,
 * so one frame is exactly one datagram.
 */
#ifndef ZCL_TOOLS_DEV_DEVLOOP_REFLEX_RUNNER_WIRE_H
#define ZCL_TOOLS_DEV_DEVLOOP_REFLEX_RUNNER_WIRE_H

#include "devloop_reflex_runner.h"

#include <sys/types.h>

#define ZCL_REFLEX_WIRE_MAGIC UINT32_C(0x5a524e31)   /* "ZRN1" */
#define ZCL_REFLEX_REPORT_MAGIC UINT32_C(0x5a524352) /* "ZRCR" */
#define ZCL_REFLEX_WIRE_ABI 2u
/* Kernel-surface probes the runner must see killed (SIGSYS) under the leaf
 * filters before it may serve: io_uring_setup, pidfd_open, kill. */
#define ZCL_REFLEX_DENY_PROBES 3u

enum zcl_reflex_frame_kind {
    ZCL_REFLEX_FRAME_HELLO = 1,
    ZCL_REFLEX_FRAME_REQUEST = 2,
    ZCL_REFLEX_FRAME_REPLY = 3,
    ZCL_REFLEX_FRAME_CANCEL = 4,
};

struct zcl_reflex_frame_head {
    uint32_t magic;
    uint32_t abi;
    uint32_t kind;
    uint32_t size;
    uint64_t sequence;
};

struct zcl_reflex_hello {
    struct zcl_reflex_frame_head head;
    int32_t pid;
    uint32_t env_count;
    uint32_t fd_count;
    uint64_t resident_canary_seen;
    uint32_t deny_probes_killed; /* of ZCL_REFLEX_DENY_PROBES */
};

struct zcl_reflex_request {
    struct zcl_reflex_frame_head head;
    uint32_t mode;
    uint32_t timeout_ms;
    char expected_sha256[65];
    char owner_id[128];
    char source_tu[256];
    char candidate_object_root[65];
    char story_id[128];
    char story_root[65];
    char story_fixture_root[65];
};

struct zcl_reflex_reply {
    struct zcl_reflex_frame_head head;
    bool report_complete;
    bool timed_out;
    bool cancelled;
    bool seals_verified;
    int32_t child_exit_code;
    int32_t child_signal;
    int64_t fork_us;
    int64_t total_us;
    char runner_sha256[65];
    char error[160];
    struct zcl_reflex_child_report report;
};

/* ── leaf report frames (report pipe, leaf -> runner) ─────────────────────
 *
 * The pipe is a byte stream, so each frame carries its own head. The leaf
 * writes exactly two, in order:
 *   PRELOAD      before the candidate image is mapped: the leaf's own
 *                confinement, re-hash and census facts (trusted);
 *   OBSERVATION  after the story: the story bit and its observation data
 *                (candidate-influenced; never describes the environment).
 * Flags are bytes, not bool, because the observation frame is written by
 * candidate-controlled memory and every byte is validated before use. */
enum zcl_reflex_report_kind {
    ZCL_REFLEX_REPORT_PRELOAD = 1,
    ZCL_REFLEX_REPORT_OBSERVATION = 2,
};

struct zcl_reflex_report_head {
    uint32_t magic;
    uint32_t abi;
    uint32_t kind;
    uint32_t size;
};

struct zcl_reflex_preload_frame {
    struct zcl_reflex_report_head head;
    uint8_t hash_verified;
    uint8_t sandboxed;
    uint8_t reserved[2];
    uint32_t env_count;
    uint32_t inherited_fd_count;
    uint64_t resident_canary_seen;
    int64_t start_us;
    int64_t confine_us;
    char runtime_module_sha256[65];
    char stage[32];
    char error[160];
};

struct zcl_reflex_observation_frame {
    struct zcl_reflex_report_head head;
    uint8_t story_ok;
    uint8_t descriptor_valid;
    uint8_t candidate_executed;
    uint8_t reserved;
    int64_t dlopen_us;
    int64_t story_us;
    char stage[32];
    char error[160];
    struct zcl_hotfork_observation_v1 observation;
    struct zcl_hotswap_service_report service;
};

enum zcl_reflex_frames_status {
    ZCL_REFLEX_FRAMES_OK = 0,
    ZCL_REFLEX_FRAMES_PRELOAD_MISSING,
    ZCL_REFLEX_FRAMES_OBSERVATION_MISSING,
    ZCL_REFLEX_FRAMES_TRUNCATED,
    ZCL_REFLEX_FRAMES_BAD_MAGIC,
    ZCL_REFLEX_FRAMES_BAD_ABI,
    ZCL_REFLEX_FRAMES_UNKNOWN_KIND,
    ZCL_REFLEX_FRAMES_WRONG_SIZE,
    ZCL_REFLEX_FRAMES_OUT_OF_ORDER,
    ZCL_REFLEX_FRAMES_DUPLICATE,
    ZCL_REFLEX_FRAMES_TRAILING,
};

struct zcl_reflex_frames {
    bool preload_present;
    bool observation_present;
    uint32_t status; /* enum zcl_reflex_frames_status */
    struct zcl_reflex_preload_frame preload;
    struct zcl_reflex_observation_frame observation;
};

/* Parse the complete byte sequence the leaf wrote. A frame is copied out only
 * when its head and size are exact and it arrives in its slot; the status
 * names the first defect. PRELOAD may be present while the status is not OK
 * (e.g. OBSERVATION_MISSING after a crash). */
enum zcl_reflex_frames_status zcl_reflex_frames_parse(
    const uint8_t *bytes, size_t len, struct zcl_reflex_frames *out);

/* Stable, named reason for a frames status ("" for OK). */
const char *zcl_reflex_frames_reason(enum zcl_reflex_frames_status status);

/* String/flag validation before any use. Each returns NULL when every
 * fixed-size string is NUL-terminated inside its array, every digest field is
 * empty-or-64-lowercase-hex as its contract allows, and every flag byte is 0
 * or 1; otherwise a named reason. */
const char *zcl_reflex_preload_invalid(const struct zcl_reflex_preload_frame *f);
const char *zcl_reflex_observation_invalid(
    const struct zcl_reflex_observation_frame *f);

/* Runner-observed end of one leaf. */
struct zcl_reflex_reap {
    bool reaped;
    bool killed_at_deadline; /* still alive at the deadline: SIGKILLed */
    bool filters_read;       /* Seccomp_filters read before the reap */
    int exit_code;           /* -1 unless it exited normally */
    int signal;
    uint32_t seccomp_filters;
};

/* Wait for `child` until `deadline_us` (monotonic); past it, SIGKILL and
 * reap. Reads the exited leaf's /proc/<pid>/status Seccomp_filters before
 * reaping it. Never waits without bound for a child that is alive. */
void zcl_reflex_reap_bounded(pid_t child, int64_t deadline_us,
                             struct zcl_reflex_reap *out);

#if defined(ZCL_TESTING)
/* Test seams: disable close_range so the enumeration fallback runs, and
 * point the enumeration at another directory (NULL restores /proc/self/fd). */
void zcl_reflex_testing_use_close_range(bool enabled);
void zcl_reflex_testing_set_fd_dir(const char *path);
#endif

/* Runner-side child: confine, verify, load by descriptor, run, report. Never
 * returns; exits with 0 after a complete report write, 125 otherwise. */
[[noreturn]] void zcl_reflex_runner_child_main(
    const struct zcl_reflex_request *request, int image_fd, int report_fd,
    int runner_pid);

/* Close every descriptor except the listed ones (at most 8): close_range
 * where the kernel has it, otherwise a full allocation-free /proc/self/fd
 * enumeration. False (a refusal) when neither is possible. Async-signal-safe. */
bool zcl_reflex_close_all_except(const int *keep, size_t keep_count);

/* Count every open descriptor not in `keep` by full /proc/self/fd
 * enumeration; UINT32_MAX when the enumeration is impossible. */
uint32_t zcl_reflex_count_fds_except(const int *keep, size_t keep_count);

/* Same census through an already-open fd directory (not itself counted),
 * for a caller that can no longer open paths. */
uint32_t zcl_reflex_count_fds_in(int dir_fd, const int *keep,
                                 size_t keep_count);

/* Number of entries in this process's environment. */
uint32_t zcl_reflex_env_count(void);

/* Lower-hex SHA-256 of an fd's full contents from offset 0. */
bool zcl_reflex_sha256_fd(int fd, char out[65]);

#endif /* ZCL_TOOLS_DEV_DEVLOOP_REFLEX_RUNNER_WIRE_H */
