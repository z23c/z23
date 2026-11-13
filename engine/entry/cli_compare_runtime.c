/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0
 * Purpose: bracket standalone comparisons with checked signal ownership. */
#include "cli_compare_runtime.h"
#include "command/native_command.h"
#include <string.h>

#if !defined(_WIN32)
static volatile sig_atomic_t cli_compare_cancelled;
static bool cli_compare_scope_active;
static const int cli_compare_signal_numbers[2] = {SIGINT, SIGTERM};
static void cli_compare_on_signal(int number)
{
    (void)number; cli_compare_cancelled = 1;
}
#endif

bool cli_compare_scope_begin(void *context)
{
#if !defined(_WIN32)
    if (!context || cli_compare_scope_active) return false;
    struct cli_compare_signals *s = context;
    memset(s, 0, sizeof(*s));
    cli_compare_scope_active = true; s->acquired = true;
    sigemptyset(&s->owned); sigaddset(&s->owned, SIGINT); sigaddset(&s->owned, SIGTERM);
    if (sigprocmask(SIG_BLOCK, &s->owned, &s->original) != 0) return false;
    s->mask_saved = true;
    if (sigismember(&s->original, SIGINT) != 0 || sigismember(&s->original, SIGTERM) != 0)
        return false;
    cli_compare_cancelled = 0;
    struct sigaction action; memset(&action, 0, sizeof(action));
    action.sa_handler = cli_compare_on_signal; sigemptyset(&action.sa_mask);
    for (unsigned i = 0; i < 2; i++) {
        if (sigaction(cli_compare_signal_numbers[i], &action, &s->previous[i]) != 0) return false;
        s->installed++;
    }
    return sigprocmask(SIG_SETMASK, &s->original, NULL) == 0;
#else
    if (context) memset(context, 0, sizeof(struct cli_compare_signals));
    return false;
#endif
}

bool cli_compare_scope_end(void *context)
{
#if !defined(_WIN32)
    struct cli_compare_signals *s = context;
    if (!s->acquired) return true;
    bool ok = true;
    if (s->mask_saved) {
        if (sigprocmask(SIG_BLOCK, &s->owned, NULL) != 0) ok = false;
        sigset_t pending;
        if (sigpending(&pending) != 0) ok = false;
        else if (sigismember(&pending, SIGINT) == 1 || sigismember(&pending, SIGTERM) == 1)
            cli_compare_cancelled = 1;
        for (unsigned i = 0; i < s->installed; i++)
            if (sigaction(cli_compare_signal_numbers[i], &s->previous[i], NULL) != 0) ok = false;
        if (sigprocmask(SIG_SETMASK, &s->original, NULL) != 0) ok = false;
    }
    s->acquired = false; cli_compare_scope_active = false;
    return ok;
#else
    (void)context; return false;
#endif
}

bool cli_compare_reserve(void *context, unsigned count,
                                struct zcl_command_cleanup_slot **slots)
{
#if !defined(_WIN32)
    struct cli_compare_signals *s = context;
    if (!slots) return false;
    *slots = NULL;
    if (!s->acquired || s->reserved || count != ZCL_COMMAND_CLEANUP_SLOTS_MAX) return false;
    s->reserved = true; *slots = s->slots; return true;
#else
    (void)context; (void)count;
    if (slots) *slots = NULL;
    return false;
#endif
}

bool cli_compare_cleanup(void *context)
{
#if !defined(_WIN32)
    struct cli_compare_signals *s = context; bool ok = true;
    for (unsigned i = 0; i < ZCL_COMMAND_CLEANUP_SLOTS_MAX; i++) {
        struct zcl_command_cleanup_slot *slot = &s->slots[i];
        if (slot->owner) {
            bool released = slot->release && slot->release(&slot->owner);
            if (!released || slot->owner) slot->release_failed = true;
        }
        if (slot->release_failed || slot->owner) ok = false;
    }
    return ok;
#else
    (void)context; return false;
#endif
}

bool cli_compare_scope_cancelled(void *context)
{
#if !defined(_WIN32)
    (void)context; return cli_compare_cancelled != 0;
#else
    (void)context; return true;
#endif
}

/* Own a fresh single-invocation runtime only on the standalone POSIX entry. */
int cli_native_registry_dispatch(const char *method,
    const char *const *params_storage, int nparams, const char *datadir,
    int cli_port, bool regtest_set, bool testnet_set, bool datadir_set)
{
#if !defined(_WIN32)
        struct cli_compare_signals signals = {0};
        const struct zcl_native_standalone_runtime runtime = {
            .one_shot_process = true, .begin = cli_compare_scope_begin, .end = cli_compare_scope_end,
            .cancelled = cli_compare_scope_cancelled, .reserve_cleanup = cli_compare_reserve,
            .cleanup = cli_compare_cleanup, .context = &signals
        };
        return zcl_native_command_main_standalone(method,
            (const char *const *)params_storage, nparams, datadir, cli_port,
            regtest_set ? CHAIN_REGTEST : testnet_set ? CHAIN_TESTNET : CHAIN_MAIN,
            datadir_set, &runtime);
#else
        return zcl_native_command_main(method,
                                       (const char *const *)params_storage,
                                       nparams, datadir, cli_port,
                                       regtest_set ? CHAIN_REGTEST :
                                       testnet_set ? CHAIN_TESTNET : CHAIN_MAIN,
                                       datadir_set);

#endif
}
