/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: shell-free, headless child process lifecycle capabilities. */
#ifndef ZCL_PLATFORM_PROCESS_LIFECYCLE_H
#define ZCL_PLATFORM_PROCESS_LIFECYCLE_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#if defined(_WIN32)
#include <wchar.h>
/* Conventional CRT/CommandLineToArgvW encoding of UTF-8 argv. Caller supplies
 * bounded, NULL-terminated input (the encoder does not impose an argc bound).
 * Heap-owned result (free), NULL on invalid UTF-8 or capacity failure.
 * Caller enforces CreateProcess's 32767-unit limit including NUL. */
wchar_t *platform_process_windows_command_line(const char *const *argv);
#endif

struct platform_process {
    uintptr_t native;
    uintptr_t containment; /* Windows kill-on-close Job Object, else unused. */
    uint64_t pid;
};

struct platform_process_options {
    const char *image;          /* UTF-8 absolute executable path. */
    const char *const *argv;    /* NULL-terminated; argv[0] is explicit. */
    const char *cwd;            /* UTF-8 absolute directory, or NULL. */
    const char *const *env;     /* Required NULL-terminated KEY=VALUE list. */
    const uintptr_t *inherited; /* Explicit native handle/fd allowlist. */
    size_t inherited_count;
};

struct platform_process_capture_result {
    uint32_t exit_code;
    bool timed_out;
    bool output_truncated;
};

#define PLATFORM_PROCESS_EVIDENCE_TAIL 512u
struct platform_process_evidence {
    unsigned char stdout_tail[PLATFORM_PROCESS_EVIDENCE_TAIL];
    unsigned char stderr_tail[PLATFORM_PROCESS_EVIDENCE_TAIL];
    size_t stdout_len, stderr_len;
    uint64_t stdout_observed, stderr_observed;
    bool stdout_complete, stderr_complete;
};

enum platform_process_wait_result {
    PLATFORM_PROCESS_WAIT_EXITED = 0,
    PLATFORM_PROCESS_WAIT_RUNNING,
    PLATFORM_PROCESS_WAIT_FAILED
};

void platform_process_init(struct platform_process *process);
/* Call at child entry before performing work. Suppresses OS crash/error UI. */
void platform_process_child_prepare_headless(void);
bool platform_process_start_hidden(struct platform_process *process,
                                   const struct platform_process_options *options);
/* Run one operator-approved host tool and capture stdout only. The executable
 * must be an absolute, trusted host path supplied in options->image; this is
 * not a package-execution sandbox and must never run fetched source or an
 * executable selected by package input. Windows uses the same hidden,
 * explicit-environment, explicit-handle-list and kill-on-close Job Object
 * boundary as platform_process_start_hidden(). timeout_ms must be nonzero.
 * `out` is NUL-terminated on every return when out_size is nonzero. A timeout
 * is a successful observation reported in result->timed_out; launch, wait, or
 * pipe failures return false. Native capture is currently Windows-only. */
bool platform_process_capture_stdout(
    const struct platform_process_options *options, char *out, size_t out_size,
    uint32_t timeout_ms, struct platform_process_capture_result *result);

/* Same trusted capture and stdout contract, with separate bounded byte tails
 * from the same child. The result qualifies timeout and stdout truncation. */
bool platform_process_capture_evidence(
    const struct platform_process_options *options, char *out, size_t out_size,
    uint32_t timeout_ms, struct platform_process_capture_result *result,
    struct platform_process_evidence *evidence);

/* Trusted Windows host-test capture with a private file as stdin. This is not
 * package/agent execution qualification. stdin_path must be a drive-absolute
 * regular file (no final reparse point/device/directory), at most 64 KiB, opened
 * read-only with writers/deletion excluded for the capture lifetime. The
 * existing explicit environment, handle allowlist, timeout, output limit and
 * Job Object cleanup apply unchanged. NULL/missing/oversized input refuses
 * before launch; empty input is valid. This validates the opened object, not
 * ancestor containment or a local-only filesystem. The trusted caller owns
 * the fixture. Non-Windows currently refuses. */
#define PLATFORM_PROCESS_CAPTURE_STDIN_MAX (64u * 1024u)
bool platform_process_capture_stdout_file_input(
    const struct platform_process_options *options, const char *stdin_path,
    char *out, size_t out_size, uint32_t timeout_ms,
    struct platform_process_capture_result *result);
bool platform_process_open_existing(struct platform_process *process,
                                    uint64_t pid,
                                    const char *expected_image);
enum platform_process_wait_result platform_process_wait(
    struct platform_process *process, uint32_t timeout_ms, uint32_t *exit_code);
bool platform_process_terminate(struct platform_process *process,
                                uint32_t exit_code);
/* Transfer containment to a persistent child and release the caller's handles.
 * On Windows the child retains the Job Object, so its descendants are reaped
 * when the persistent child exits. */
bool platform_process_detach(struct platform_process *process);
/* Closing an owned Windows process also closes its kill-on-close Job Object,
 * so descendants cannot outlive the bounded caller. */
void platform_process_close(struct platform_process *process);

#endif
