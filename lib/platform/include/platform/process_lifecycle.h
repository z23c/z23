/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: shell-free, headless child process lifecycle capabilities. */
#ifndef ZCL_PLATFORM_PROCESS_LIFECYCLE_H
#define ZCL_PLATFORM_PROCESS_LIFECYCLE_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

struct platform_process { uintptr_t native; uint64_t pid; };

struct platform_process_options {
    const char *image;          /* UTF-8 absolute executable path. */
    const char *const *argv;    /* NULL-terminated; argv[0] is explicit. */
    const char *cwd;            /* UTF-8 absolute directory, or NULL. */
    const char *const *env;     /* NULL-terminated KEY=VALUE entries. */
    bool inherit_environment;   /* false creates only the supplied env. */
};

enum platform_process_wait_result {
    PLATFORM_PROCESS_WAIT_EXITED = 0,
    PLATFORM_PROCESS_WAIT_RUNNING,
    PLATFORM_PROCESS_WAIT_FAILED
};

void platform_process_init(struct platform_process *process);
bool platform_process_start_hidden(struct platform_process *process,
                                   const struct platform_process_options *options);
enum platform_process_wait_result platform_process_wait(
    struct platform_process *process, uint32_t timeout_ms, uint32_t *exit_code);
bool platform_process_terminate(struct platform_process *process,
                                uint32_t exit_code);
void platform_process_close(struct platform_process *process);

#endif
