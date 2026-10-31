/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * The hot-swap activation flag and the gate that decides whether this
 * process may activate a module. Moved out of hotswap_activate.c unchanged;
 * hotswap_activate.c reads hotswap_env_opt_in() for its telemetry. */

#define _GNU_SOURCE

#include "hotswap/hotswap.h"
#include "hotswap/hotswap_module.h"
#include "hotswap_activate_internal.h"

#include <limits.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* ── activation flag + gate (pure; compiled in every build) ─────────────── */
static _Atomic bool g_activate_flag = false;

void hotswap_set_activate_flag(bool enabled)
{
    atomic_store_explicit(&g_activate_flag, enabled, memory_order_release);
}

bool hotswap_activate_flag(void)
{
    return atomic_load_explicit(&g_activate_flag, memory_order_acquire);
}

bool hotswap_env_opt_in(void)
{
    const char *v = getenv("ZCL_HOTSWAP_ACTIVATE");
    return v && strcmp(v, "1") == 0;
}

static bool dir_equals(const char *a, const char *b)
{
    if (!a || !a[0] || !b || !b[0])
        return false;
#if defined(_WIN32)
    /* Native activation is refused below before this comparison can grant
     * authority. Do not approximate canonical identity with string folding. */
    return false;
#else
    char ra[PATH_MAX], rb[PATH_MAX];
    const char *pa = realpath(a, ra) ? ra : a;
    const char *pb = realpath(b, rb) ? rb : b;
    size_t la = strlen(pa), lb = strlen(pb);
    if (la && pa[la - 1] == '/') la--;
    if (lb && pb[lb - 1] == '/') lb--;
    return la == lb && strncmp(pa, pb, la) == 0;
#endif
}

static bool datadir_is_canonical(const char *datadir)
{
    if (!datadir || !datadir[0])
        return false;
    const char *home = getenv("HOME");
    if (!home || home[0] != '/')
        return false;
    char canonical[PATH_MAX];
    snprintf(canonical, sizeof(canonical), "%s/.zclassic-c23", home);
    return dir_equals(datadir, canonical);
}

bool hotswap_activation_authorized(const char *resolved_datadir,
                                   char *why, size_t why_sz)
{
    if (why && why_sz)
        why[0] = '\0';
#if defined(_WIN32)
    (void)resolved_datadir;
    if (why && why_sz)
        snprintf(why, why_sz,
                 "activation refused: native Windows module loading awaits "
                 "PE import validation and immutable directory staging");
    return false;
#endif
    if (!hotswap_activate_flag()) {
        if (why) snprintf(why, why_sz,
            "activation refused: -hotswap-activate flag is not set");
        return false;
    }
    if (!hotswap_env_opt_in()) {
        if (why) snprintf(why, why_sz,
            "activation refused: ZCL_HOTSWAP_ACTIVATE=1 is not set");
        return false;
    }
    if (datadir_is_canonical(resolved_datadir)) {
        if (why) snprintf(why, why_sz,
            "activation refused on the canonical datadir ~/.zclassic-c23 "
            "(canonical activation stays behind the owner's Phase-3 ritual)");
        return false;
    }
    if (!hotswap_datadir_is_dev(resolved_datadir)) {
        if (why) snprintf(why, why_sz,
            "activation requires the exact dev datadir ~/.zclassic-c23-dev, got '%s'",
            resolved_datadir ? resolved_datadir : "");
        return false;
    }
    return true;
}
