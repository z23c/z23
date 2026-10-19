/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * purpose: Windows arm of the host build queue. The queue uses flock(2),
 *          fork and systemd user scopes, so a Windows node reports it as
 *          unavailable; the POSIX bodies live in build_admit.c,
 *          build_run.c, build_status.c and native_ops_host_build.c.
 */

#ifdef _WIN32

#include "command/build_admit.h"
#include "command/native_command.h"

#include <stdio.h>

void ba_request_stop(int signo) { (void)signo; }
int ba_stop_signal(void) { return 0; }

int ba_admit(const struct ba_config *cfg, struct ba_slot *slot)
{
    (void)cfg;
    (void)slot;
    return BA_EXIT_DEFERRED;
}

void ba_slot_release(struct ba_slot *slot) { (void)slot; }

bool ba_cpu_plan_parse(const char *text, char *list, size_t cap,
                       unsigned *workers)
{
    (void)text;
    (void)list;
    (void)cap;
    (void)workers;
    return false;
}

int ba_run(const struct ba_config *cfg, const char *const *argv, int argc)
{
    (void)cfg;
    (void)argv;
    (void)argc;
    return BA_EXIT_DEFERRED;
}

unsigned ba_reserve_gib_from_env(void) { return BA_DEFAULT_RESERVE_GIB; }

bool ba_list_names(const char *dir, char (**names)[BA_NAME_MAX], size_t *count)
{
    (void)dir;
    *names = NULL;
    *count = 0;
    return true;
}

bool ba_status(const char *state_dir, struct json_value *out)
{
    (void)state_dir;
    (void)out;
    return false;
}

bool zcl_native_ops_host_build_try_run(const char *const *words, size_t count,
                                       size_t consumed, int *rc)
{
    (void)words;
    (void)count;
    (void)consumed;
    (void)fprintf(stderr, "devbuild: the build queue needs a POSIX host\n");
    *rc = BA_EXIT_USAGE;
    return true;
}

#else

/* POSIX hosts build the real queue; ISO C forbids an empty translation unit. */
typedef int ba_windows_stub_unused;

#endif /* _WIN32 */
