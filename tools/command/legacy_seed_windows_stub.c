/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * purpose: Windows arm of the legacy seed. The seed relies on openat,
 *          flock, fcntl locks and renameat2, so a Windows node reports it as
 *          unavailable; the POSIX bodies live in legacy_seed.c,
 *          legacy_seed_walk.c and legacy_seed_copy.c.
 */

#ifdef _WIN32

#include "command/legacy_seed.h"

#include <stdio.h>
#include <string.h>

static struct lseed_hooks g_hooks;

struct lseed_hooks *lseed_hooks(void) { return &g_hooks; }
const char *lseed_refusal_name(enum lseed_refusal code)
{
    (void)code;
    return "unsupported";
}
void lseed_request_defaults(struct lseed_request *req)
{
    memset(req, 0, sizeof(*req));
}
void lseed_plan_id(const struct lseed_request *req, char out[65])
{
    (void)req;
    memset(out, '0', 64);
    out[64] = '\0';
}
bool lseed_datadir_in_use(const char *datadir, long *pid_out)
{
    (void)datadir;
    (void)pid_out;
    return false;
}

static enum lseed_refusal unsupported(char *why, size_t cap)
{
    (void)snprintf(why, cap, "legacy seed is not available on Windows");
    return LSEED_BAD_INPUT;
}

enum lseed_refusal lseed_preflight(const struct lseed_request *req,
                                   bool require_stopped,
                                   struct lseed_plan *plan, char *why,
                                   size_t why_cap)
{
    (void)req;
    (void)require_stopped;
    memset(plan, 0, sizeof(*plan));
    return unsupported(why, why_cap);
}

enum lseed_refusal lseed_stage(const struct lseed_request *req,
                               struct lseed_result *res, char *why,
                               size_t why_cap)
{
    (void)req;
    memset(res, 0, sizeof(*res));
    return unsupported(why, why_cap);
}

enum lseed_refusal lseed_finish(const struct lseed_request *req,
                                struct lseed_result *res, char *why,
                                size_t why_cap)
{
    (void)req;
    memset(res, 0, sizeof(*res));
    return unsupported(why, why_cap);
}

#else

typedef int lseed_windows_stub_unused; /* ISO C forbids an empty translation unit */

#endif /* _WIN32 */
