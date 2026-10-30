/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * purpose: the child-process policy of check-reproducible-build, as pure
 * functions. rpb_child_env() builds the environment every child build sees
 * from a caller environment (no setenv, no process state): the forced entries
 * replace any caller entry with the same key, and nothing else is removed. The
 * forced set is the one the shell gate pinned (offline, no compiler cache,
 * C locale, UTC, the fixed PATH and HOME). rpb_resolve() finds a program on
 * the forced PATH, because posix_spawnp would search the caller's PATH.
 */
#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#endif
#include <string.h>
#include <unistd.h>
#include "lintc.h"
#include "gate_reproducible_build_priv.h"

static const char *const rpb_forced[] = {
    "ZCL_VENDOR_OFFLINE=1", "ZCL_USE_CCACHE=0", "LC_ALL=C", "TZ=UTC",
    "PATH=" RPB_PATH, "HOME=/nonexistent", NULL };

/* The shell gate unset nothing; the list stays empty so a caller variable is
 * only ever overridden by a forced key, never silently dropped. */
static const char *const rpb_unset[] = { NULL };

static size_t rpb_key_len(const char *entry)
{
    const char *eq = strchr(entry, '=');
    return eq ? (size_t)(eq - entry) : strlen(entry);
}

static int rpb_same_key(const char *entry, const char *forced)
{
    size_t kl = rpb_key_len(forced);
    return rpb_key_len(entry) == kl && strncmp(entry, forced, kl) == 0;
}

static int rpb_is_forced(const char *entry)
{
    for (size_t i = 0; rpb_forced[i]; i++) {
        if (rpb_same_key(entry, rpb_forced[i]))
            return 1;
    }
    for (size_t i = 0; rpb_unset[i]; i++) {
        if (rpb_same_key(entry, rpb_unset[i]))
            return 1;
    }
    return 0;
}

static int rpb_forced_count(void)
{
    int n = 0;
    while (rpb_forced[n])
        n++;
    return n;
}

/* Caller entries are kept as pointers into src (they outlive the call); only
 * the pinned entries are copied into e->forced. */
int rpb_child_env(char *const src[], struct rpb_env *e)
{
    int n = 0;
    int nf = rpb_forced_count();
    memset(e, 0, sizeof *e);
    if (nf > (int)(sizeof e->forced / sizeof e->forced[0]))
        return 2;
    for (size_t i = 0; src && src[i]; i++) {
        if (rpb_is_forced(src[i]))
            continue;
        if (n >= RP_ENVN - nf)
            return 2;
        e->ptr[n++] = src[i];
    }
    for (int k = 0; k < nf; k++) {
        if (ovf(snprintf(e->forced[k], RP_ENVL, "%s", rpb_forced[k]), RP_ENVL))
            return 2;
        e->ptr[n++] = e->forced[k];
    }
    e->ptr[n] = NULL;
    return 0;
}

/* 0 with the single value in out, 1 when the key is absent, 2 when it is
 * present more than once or does not fit. */
int rpb_env_get(const struct rpb_env *e, const char *key, char *out, size_t cap)
{
    int found = 0;
    const char *value = NULL;
    for (size_t i = 0; e->ptr[i]; i++) {
        if (!strchr(e->ptr[i], '=') || strlen(key) != rpb_key_len(e->ptr[i]) ||
            strncmp(e->ptr[i], key, strlen(key)) != 0)
            continue;
        found++;
        value = strchr(e->ptr[i], '=') + 1;
    }
    if (found > 1)
        return 2;
    if (found == 0)
        return 1;
    return ovf(snprintf(out, cap, "%s", value), cap) ? 2 : 0;
}

/* A program name is looked up in each RPB_PATH directory; a name with a slash
 * is used as given. 0 with the path in out, 1 when not found, 2 on overflow. */
int rpb_resolve(const char *prog, char *out, size_t cap)
{
    if (strchr(prog, '/'))
        return ovf(snprintf(out, cap, "%s", prog), cap) ? 2 : 0;
    char dirs[sizeof RPB_PATH];
    memcpy(dirs, RPB_PATH, sizeof RPB_PATH);
    char *p = dirs;
    while (p && *p) {
        char *colon = strchr(p, ':');
        if (colon)
            *colon = '\0';
        if (ovf(snprintf(out, cap, "%s/%s", p, prog), cap))
            return 2;
        if (access(out, X_OK) == 0)
            return 0;
        p = colon ? colon + 1 : NULL;
    }
    return 1;
}
