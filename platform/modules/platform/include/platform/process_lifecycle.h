/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: shell-free, headless child process lifecycle capabilities. */
#ifndef ZCL_PLATFORM_PROCESS_LIFECYCLE_H
#define ZCL_PLATFORM_PROCESS_LIFECYCLE_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

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
