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

#define ZCL_REFLEX_WIRE_MAGIC UINT32_C(0x5a524e31)   /* "ZRN1" */
#define ZCL_REFLEX_REPORT_MAGIC UINT32_C(0x5a524352) /* "ZRCR" */
#define ZCL_REFLEX_WIRE_ABI 1u

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

/* Runner-side child: confine, verify, load by descriptor, run, report. Never
 * returns; exits with 0 after a complete report write, 125 otherwise. */
[[noreturn]] void zcl_reflex_runner_child_main(
    const struct zcl_reflex_request *request, int image_fd, int report_fd,
    int runner_pid);

/* Close every descriptor except the listed ones (close_range where the
 * kernel has it, a bounded loop otherwise). */
bool zcl_reflex_close_all_except(const int *keep, size_t keep_count);

/* Count open descriptors in [0, 1024) not in `keep`. */
uint32_t zcl_reflex_count_fds_except(const int *keep, size_t keep_count);

/* Number of entries in this process's environment. */
uint32_t zcl_reflex_env_count(void);

/* Lower-hex SHA-256 of an fd's full contents from offset 0. */
bool zcl_reflex_sha256_fd(int fd, char out[65]);

#endif /* ZCL_TOOLS_DEV_DEVLOOP_REFLEX_RUNNER_WIRE_H */
