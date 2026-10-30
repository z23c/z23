/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * node_pace - process-wide pace (see jobs/node_pace.h). */

#include "jobs/node_pace.h"

#include "platform/time_compat.h"
#include "util/log_macros.h"

#include <pthread.h>
#include <stdatomic.h>
#include <stdio.h>
#include <string.h>

#define NODE_PACE_POLL_US 1000000
#define NODE_PACE_GENTLE_SLEEP_MAX_MS 250
#define NODE_PACE_RESUME_GRACE_US 120000000

static _Atomic int g_pace = NODE_PACE_NORMAL;
static _Atomic int64_t g_next_poll_us;
static _Atomic int64_t g_resume_until_us;
static pthread_mutex_t g_path_mu = PTHREAD_MUTEX_INITIALIZER;
static char g_path[1024];

static const char *const k_names[] = { "normal", "gentle", "pause" };

const char *node_pace_name(enum node_pace pace)
{
    return (unsigned)pace < 3u ? k_names[pace] : "normal";
}

bool node_pace_parse(const char *word, enum node_pace *out)
{
    if (!word || !out)
        return false;
    for (int i = 0; i < 3; i++) {
        size_t n = strlen(k_names[i]);
        if (strncmp(word, k_names[i], n) == 0 &&
            (word[n] == 0 || word[n] == 0x0a || word[n] == 0x0d ||
             word[n] == 0x20)) {
            *out = (enum node_pace)i;
            return true;
        }
    }
    return false;
}

enum node_pace node_pace_get(void)
{
    return (enum node_pace)atomic_load_explicit(&g_pace,
                                                memory_order_relaxed);
}

void node_pace_set(enum node_pace pace)
{
    int prev = atomic_exchange(&g_pace, (int)pace);
    if (prev == (int)NODE_PACE_PAUSE && pace != NODE_PACE_PAUSE)
        atomic_store(&g_resume_until_us,
                     platform_time_monotonic_us() + NODE_PACE_RESUME_GRACE_US);
    if (prev != (int)pace)
        LOG_INFO("node_pace", "[node_pace] pace %s -> %s",
                 node_pace_name((enum node_pace)prev), node_pace_name(pace));
}

void node_pace_set_datadir(const char *datadir)
{
    pthread_mutex_lock(&g_path_mu);
    if (datadir && datadir[0] &&
        snprintf(g_path, sizeof(g_path), "%s/pace", datadir) <
            (int)sizeof(g_path)) {
        atomic_store(&g_next_poll_us, 0);
    } else {
        g_path[0] = 0;
    }
    pthread_mutex_unlock(&g_path_mu);
}

/* Requested pace from the file; normal when it is absent or unreadable. */
static enum node_pace node_pace_read_file(const char *path)
{
    char word[32] = {0};
    enum node_pace pace = NODE_PACE_NORMAL;
    FILE *f = fopen(path, "r");
    if (!f)
        return pace;
    if (fgets(word, sizeof(word), f))
        (void)node_pace_parse(word, &pace);
    fclose(f);
    return pace;
}

void node_pace_poll(void)
{
    int64_t now = platform_time_monotonic_us();
    int64_t due = atomic_load_explicit(&g_next_poll_us, memory_order_relaxed);
    if (now < due ||
        !atomic_compare_exchange_strong(&g_next_poll_us, &due,
                                        now + NODE_PACE_POLL_US))
        return;
    char path[sizeof(g_path)];
    pthread_mutex_lock(&g_path_mu);
    memcpy(path, g_path, sizeof(path));
    pthread_mutex_unlock(&g_path_mu);
    if (path[0])
        node_pace_set(node_pace_read_file(path));
}

bool node_pace_hold_recovery(void)
{
    return node_pace_get() == NODE_PACE_PAUSE ||
           platform_time_monotonic_us() <
               atomic_load_explicit(&g_resume_until_us, memory_order_relaxed);
}

#ifdef ZCL_TESTING
void node_pace_test_end_resume_grace(void)
{
    atomic_store(&g_resume_until_us, 0);
}
#endif

int node_pace_gentle_sleep_ms(int64_t round_us)
{
    if (node_pace_get() != NODE_PACE_GENTLE || round_us <= 0)
        return 0;
    int64_t ms = round_us / 1000;
    if (ms < 1)
        ms = 1;
    return ms > NODE_PACE_GENTLE_SLEEP_MAX_MS ? NODE_PACE_GENTLE_SLEEP_MAX_MS
                                              : (int)ms;
}
