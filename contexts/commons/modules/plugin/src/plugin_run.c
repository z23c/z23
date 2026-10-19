/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: restart policy for a supervised plugin: nonce-bound health pings,
 * exponential backoff, and one restore of the last-good generation after a
 * crash loop. The confined child itself is plugin_run_spawn.c. */

#include "plugin_run_internal.h"

#include "base/safe_alloc.h"
#include "platform/os_sandbox.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#define PRR_NS_PER_MS UINT64_C(1000000)
/* ABI 3 handles LANDLOCK_ACCESS_FS_TRUNCATE; below it a plugin could truncate
 * any file it can open for writing outside its data directory. */
#define PRR_LANDLOCK_ABI_MIN 3

static const struct {
    const char *code;
    const char *next_action;
} prr_status_text[] = {
    {"", ""},
    {"PLUGIN_RUN_ARGUMENT",
     "Run z23 plugin run NAME with an installed plugin name."},
    {"PLUGIN_RUN_PLATFORM",
     "Run plugins on Linux; confined plugin processes are not available here."},
    {"PLUGIN_RUN_STORE",
     "Fix the plugin store refusal named in the evidence, then run again."},
    {"PLUGIN_RUN_CAPABILITY",
     "Install a plugin build that asks only for fs.read, fs.write and clock."},
    {"PLUGIN_RUN_SPAWN",
     "Check the evidence line; the kernel must support Landlock and seccomp."},
    {"PLUGIN_RUN_FAILED",
     "Read the evidence line, fix the plugin, then run z23 plugin run again."},
    {"PLUGIN_RUN_SANDBOX",
     "Run on a Linux kernel 6.2 or newer with Landlock (ABI 3) and seccomp enabled."},
};

const char *plugin_run_status_code(enum plugin_run_status status)
{
    size_t n = sizeof(prr_status_text) / sizeof(prr_status_text[0]);
    return (size_t)status < n ? prr_status_text[status].code : "PLUGIN_RUN_FAILED";
}

const char *plugin_run_status_next_action(enum plugin_run_status status)
{
    size_t n = sizeof(prr_status_text) / sizeof(prr_status_text[0]);
    return (size_t)status < n ? prr_status_text[status].next_action : "";
}

#if defined(__linux__)
static uint32_t prr_default(uint32_t value, uint32_t fallback)
{
    return value ? value : fallback;
}

static void prr_options(struct plugin_run *run, const struct plugin_run_options *o)
{
    run->opt = *o;
    run->opt.ping_interval_ms = prr_default(o->ping_interval_ms, 1000);
    run->opt.ping_deadline_ms = prr_default(o->ping_deadline_ms, 2000);
    run->opt.ping_miss_limit = prr_default(o->ping_miss_limit, 2);
    run->opt.backoff_initial_ms = prr_default(o->backoff_initial_ms, 250);
    run->opt.backoff_max_ms = prr_default(o->backoff_max_ms, 30000);
    run->opt.stable_ms = prr_default(o->stable_ms, 10000);
    run->opt.crash_limit = prr_default(o->crash_limit, 3);
    if (run->opt.backoff_max_ms < run->opt.backoff_initial_ms)
        run->opt.backoff_max_ms = run->opt.backoff_initial_ms;
}
#endif

static void prr_reset_backoff(struct plugin_run *run)
{
    run->info.crashes = 0;
    run->info.backoff_ms = run->opt.backoff_initial_ms;
}

enum plugin_run_status plugin_run_open(const struct plugin_run_options *options,
                                       struct plugin_run **out,
                                       enum plugin_status *store)
{
    if (store)
        *store = PLUGIN_OK;
    if (!options || !out || !options->root || !plugin_name_valid(options->name))
        return PLUGIN_RUN_ERR_ARGUMENT;
#if !defined(__linux__)
    return PLUGIN_RUN_ERR_PLATFORM;
#else
    if (os_sandbox_landlock_abi() < PRR_LANDLOCK_ABI_MIN || !os_sandbox_seccomp_supported())
        return PLUGIN_RUN_ERR_SANDBOX;
    struct plugin_run *run = zcl_calloc(1, sizeof(*run), "plugin-run");
    if (!run)
        return PLUGIN_RUN_ERR_ARGUMENT;
    prr_options(run, options);
    run->log_fd = -1;
    resident_launch_init(&run->launch);
    snprintf(run->info.detail, sizeof(run->info.detail), "not started");
    enum plugin_run_status st = PLUGIN_RUN_ERR_ARGUMENT;
    if (plugin_join(run->plugdir, sizeof(run->plugdir), options->root,
                    options->name, NULL, NULL))
        st = prs_resolve(run);
    if (st != PLUGIN_RUN_OK) {
        if (store)
            *store = run->store;
        free(run);
        return st;
    }
    prr_reset_backoff(run);
    *out = run;
    return PLUGIN_RUN_OK;
#endif
}

/* After a crash loop, restore last-good once; otherwise keep retrying. */
static void prr_fallback(struct plugin_run *run, uint64_t now)
{
    char last_good[PLUGIN_HEX_SHA3_512 + 1], restored[PLUGIN_HEX_SHA3_512 + 1];
    if (run->info.fell_back ||
        !plugin_link_generation(run->plugdir, "last-good", last_good) ||
        strcmp(last_good, run->info.generation) == 0)
        return;
    if (plugin_store_rollback(run->opt.root, run->opt.name, restored) != PLUGIN_OK)
        return;
    run->info.fell_back = true;
    prr_reset_backoff(run);
    run->next_ns = now;
    snprintf(run->info.detail, sizeof(run->info.detail),
             "crash loop: restored last-good generation");
}

static void prr_schedule(struct plugin_run *run, uint64_t now)
{
    uint32_t delay = run->info.backoff_ms;
    run->info.state = PLUGIN_RUN_STATE_BACKOFF;
    run->next_ns = now + (uint64_t)delay * PRR_NS_PER_MS;
    uint64_t doubled = (uint64_t)delay * 2;
    run->info.backoff_ms = doubled > run->opt.backoff_max_ms
                               ? run->opt.backoff_max_ms : (uint32_t)doubled;
}

/* The child is gone without being asked to stop. */
static void prr_crashed(struct plugin_run *run, uint64_t now)
{
    run->info.pid = 0;
    run->info.crashes++;
    prr_schedule(run, now);
    if (run->info.crashes >= run->opt.crash_limit)
        prr_fallback(run, now);
}

/* Start the child for the generation prs_resolve or prs_check_target left resolved. */
static enum plugin_run_status prr_launch(struct plugin_run *run, uint64_t now)
{
    enum plugin_run_status st = prs_child_start(run);
    if (st == PLUGIN_RUN_ERR_SPAWN && run->started_once) {
        prr_crashed(run, now);
        return PLUGIN_RUN_OK;
    }
    if (st != PLUGIN_RUN_OK) {
        run->info.state = PLUGIN_RUN_STATE_FAILED;
        return st;
    }
    if (run->started_once)
        run->info.restarts++;
    run->started_once = true;
    run->info.state = PLUGIN_RUN_STATE_RUNNING;
    run->info.pid = run->launch.pid;
    run->started_ns = now;
    run->next_ping_ns = now;
    run->ping_pending = false;
    run->misses = 0;
    run->run_pings = 0;
    return PLUGIN_RUN_OK;
}

static enum plugin_run_status prr_start(struct plugin_run *run, uint64_t now)
{
    enum plugin_run_status st = prs_resolve(run);
    if (st == PLUGIN_RUN_OK)
        return prr_launch(run, now);
    run->info.state = PLUGIN_RUN_STATE_FAILED;
    return st;
}

static void prr_kill(struct plugin_run *run, uint64_t now, const char *why)
{
    prs_child_stop(run);
    run->info.last_exit_code = -1;
    run->info.last_exit_signal = 9;
    snprintf(run->info.detail, sizeof(run->info.detail), "%s", why);
    prr_crashed(run, now);
}

static void prr_stable(struct plugin_run *run, uint64_t now)
{
    uint64_t window = (uint64_t)run->opt.stable_ms * PRR_NS_PER_MS;
    if (run->run_pings > 0 && now - run->started_ns >= window &&
        (run->info.crashes != 0 || run->info.backoff_ms != run->opt.backoff_initial_ms))
        prr_reset_backoff(run);
}

static void prr_ping_miss(struct plugin_run *run, uint64_t now)
{
    run->ping_pending = false;
    run->misses++;
    run->next_ping_ns = now;
    if (run->misses >= run->opt.ping_miss_limit)
        prr_kill(run, now, "missed health pings");
}

static void prr_ping(struct plugin_run *run, uint64_t now)
{
    if (!run->ping_pending) {
        if (now >= run->next_ping_ns)
            prs_ping_send(run, now);
        return;
    }
    enum prs_ping got = prs_ping_collect(run);
    if (got == PRS_PING_OK) {
        run->ping_pending = false;
        run->misses = 0;
        run->run_pings++;
        run->info.pings_ok++;
        run->next_ping_ns = now + (uint64_t)run->opt.ping_interval_ms * PRR_NS_PER_MS;
    } else if (got == PRS_PING_BAD) {
        prr_kill(run, now, "invalid reply on the control descriptor");
    } else if (now - run->ping_sent_ns >=
               (uint64_t)run->opt.ping_deadline_ms * PRR_NS_PER_MS) {
        prr_ping_miss(run, now);
    }
}

static void prr_supervise(struct plugin_run *run, uint64_t now)
{
    prs_log_drain(run, false);
    if (prs_child_reaped(run)) {
        prr_crashed(run, now);
        return;
    }
    prr_ping(run, now);
    if (run->info.state == PLUGIN_RUN_STATE_RUNNING)
        prr_stable(run, now);
}

enum plugin_run_status plugin_run_poll(struct plugin_run *run)
{
    if (!run)
        return PLUGIN_RUN_ERR_ARGUMENT;
    uint64_t now = prs_now_ns();
    switch (run->info.state) {
    case PLUGIN_RUN_STATE_BACKOFF:
        return now >= run->next_ns ? prr_start(run, now) : PLUGIN_RUN_OK;
    case PLUGIN_RUN_STATE_RUNNING:
        prr_supervise(run, now);
        return PLUGIN_RUN_OK;
    case PLUGIN_RUN_STATE_FAILED:
        return PLUGIN_RUN_ERR_FAILED;
    default:
        return PLUGIN_RUN_OK;
    }
}

enum plugin_run_status plugin_run_reload(struct plugin_run *run)
{
    if (!run)
        return PLUGIN_RUN_ERR_ARGUMENT;
    /* A running child is only replaced by a target that already verified: a
     * refused reload leaves it, its pid and its state as they were. */
    if (run->info.state != PLUGIN_RUN_STATE_RUNNING) {
        run->info.pid = 0;
        run->info.fell_back = false;
        prr_reset_backoff(run);
        return prr_start(run, prs_now_ns());
    }
    enum plugin_run_status st = prs_check_target(run);
    if (st != PLUGIN_RUN_OK)
        return st;
    prs_child_stop(run);
    run->info.pid = 0;
    run->info.fell_back = false;
    prr_reset_backoff(run);
    return prr_launch(run, prs_now_ns());
}

void plugin_run_info_get(const struct plugin_run *run, struct plugin_run_info *out)
{
    if (run && out)
        *out = run->info;
}

enum plugin_run_status plugin_run_loop(struct plugin_run *run,
                                       volatile const sig_atomic_t *stop,
                                       volatile sig_atomic_t *reload,
                                       uint32_t max_ms)
{
    const struct timespec nap = {0, 20 * 1000 * 1000};
    uint64_t end = prs_now_ns() + (uint64_t)max_ms * PRR_NS_PER_MS;
    while (!*stop && (max_ms == 0 || prs_now_ns() < end)) {
        enum plugin_run_status st = PLUGIN_RUN_OK;
        if (reload && *reload) {
            *reload = 0;
            st = plugin_run_reload(run);
            /* a refused reload keeps the old child supervised; only a lost child ends the loop */
            if (st != PLUGIN_RUN_OK && run->info.state == PLUGIN_RUN_STATE_RUNNING)
                st = PLUGIN_RUN_OK;
        }
        if (st == PLUGIN_RUN_OK)
            st = plugin_run_poll(run);
        if (st != PLUGIN_RUN_OK)
            return st;
        nanosleep(&nap, NULL);
    }
    return PLUGIN_RUN_OK;
}

void plugin_run_close(struct plugin_run *run)
{
    if (!run)
        return;
    if (run->info.state == PLUGIN_RUN_STATE_RUNNING)
        prs_child_stop(run);
    free(run);
}
