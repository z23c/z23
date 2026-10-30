/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0 */
#include "nodelog.h"
#include <assert.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

static pthread_mutex_t lock = PTHREAD_MUTEX_INITIALIZER;
static char seen[64][ZAPP_NODELOG_LINE_MAX + 1];
static int levels[64];
static int count;
static void sink(void *arg, int level, const char *text)
{
    (void)arg;
    pthread_mutex_lock(&lock);
    if (count < 64) { snprintf(seen[count], sizeof(seen[0]), "%s", text); levels[count++] = level; }
    pthread_mutex_unlock(&lock);
}
static int forwarded(void)
{
    pthread_mutex_lock(&lock);
    int n = count;
    pthread_mutex_unlock(&lock);
    return n;
}

/* Line shapes from a node console log. */
static const char *const sample[] = {
    "[boot-stage] init -> datadir_locked\n",
    "2026-10-29T10:00:01Z INFO  [boot] block index rebuilt from projection: 3301698 entries in 812ms\n",
    "[boot]   blkidx.flat_parse_insert        4120ms\n",
    "2026-10-29T10:00:02Z INFO  [db] src/db.c:88 db_open(): opened coins.db size=4096\n",
    "[boot-stage] datadir_locked -> crypto_ready\n",
    "2026-10-29T10:00:03Z WARN  [net] src/connman.c:412 dial(): connect timed out peer=203.0.113.9:8033\n",
    "Tor: bootstrapping...\n",
    "2026-10-29T10:00:04Z INFO  [tor] bootstrap 45%% (loading relay descriptors)\n",
    "2026-10-29T10:00:05Z INFO  [net] handshake complete peer=203.0.113.9:8033 version=170012 height=3301698\n",
    "2026-10-29T10:00:06Z ERROR [wallet] src/wallet.c:9 load(): wallet unreadable\n",
    "2026-10-29T10:00:07Z INFO  [wallet] imported spending key for address zs1abc\n",
    "2026-10-29T10:00:07Z INFO  [wallet] mnemonic words loaded FAIL-safe\n",
    "2026-10-29T10:00:08Z INFO  [boot] active tip seeded from durable finalized cursor\n",
    "2026-10-29T10:00:09Z INFO  [net] addr relay: 3 peers\n",
    "[boot-stage] crypto_ready -> db_open\n",
};

static void filter_cases(void)
{
    struct zapp_nodelog l;
    zapp_nodelog_init(&l, sink, NULL);
    assert(!strcmp(zapp_nodelog_stage(&l), "starting the node"));
    for (size_t i = 0; i < sizeof(sample) / sizeof(sample[0]); i++) zapp_nodelog_line(&l, sample[i], (int64_t)i);
    /* Boot stages, boot timings, warnings, errors, Tor progress and handshakes pass; ordinary
     * information, spending keys, mnemonics and seeds do not. */
    assert(forwarded() == 10);
    assert(!strcmp(seen[0], "[boot-stage] init -> datadir_locked"));
    assert(strstr(seen[1], "[boot] block index rebuilt") && levels[1] == 0);
    assert(strstr(seen[4], "WARN") && levels[4] == 1);
    assert(strstr(seen[5], "Tor: bootstrapping"));
    assert(strstr(seen[6], "bootstrap 45%"));
    assert(strstr(seen[7], "handshake complete") && levels[7] == 0);
    assert(strstr(seen[8], "ERROR") && levels[8] == 1);
    assert(!strstr(seen[9], "seeded") && strstr(seen[9], "db_open"));
    for (int i = 0; i < count; i++) assert(!strstr(seen[i], "spending key") && !strstr(seen[i], "mnemonic"));
    assert(!strcmp(zapp_nodelog_stage(&l), "loading the wallet"));
    zapp_nodelog_line(&l, "[boot-stage] ready -> shutdown_requested (shutdown from ready)\n", 100);
    assert(!strcmp(zapp_nodelog_stage(&l), "saving data and stopping"));
    zapp_nodelog_line(&l, "[boot-stage] FATAL misorder: cannot move BACKWARD ready -> init. See X.\n", 100);
    assert(!strcmp(zapp_nodelog_stage(&l), "saving data and stopping"));
    zapp_nodelog_line(&l, "[boot-stage] a -> not_a_stage\n", 100);
    assert(!strcmp(zapp_nodelog_stage(&l), "saving data and stopping"));
}

static void limit_cases(void)
{
    struct zapp_nodelog l;
    count = 0;
    zapp_nodelog_init(&l, sink, NULL);
    for (int i = 0; i < 30; i++) zapp_nodelog_line(&l, "WARN [net] peer timed out", 5000 + i);
    assert(count == ZAPP_NODELOG_PER_SECOND);
    zapp_nodelog_line(&l, "WARN [net] peer timed out", 5999);
    assert(count == ZAPP_NODELOG_PER_SECOND);
    zapp_nodelog_line(&l, "WARN [net] peer timed out", 6000);
    assert(count == ZAPP_NODELOG_PER_SECOND + 1);
    /* A dropped line still records its boot stage. */
    for (int i = 0; i < 25; i++) zapp_nodelog_line(&l, "WARN [net] peer timed out", 7000);
    zapp_nodelog_line(&l, "[boot-stage] network_ready -> services_running", 7000);
    assert(!strcmp(zapp_nodelog_stage(&l), "finishing startup"));
    /* Forwarded text is capped. */
    char big[2000];
    memset(big, 'x', sizeof(big));
    memcpy(big, "ERROR ", 6);
    big[sizeof(big) - 1] = 0;
    count = 0;
    zapp_nodelog_line(&l, big, 9000);
    assert(count == 1 && strlen(seen[0]) == ZAPP_NODELOG_LINE_MAX);
}

static void tail_cases(const char *dir)
{
    char file[512];
    assert(snprintf(file, sizeof(file), "%s/app-console.log", dir) > 0);
    FILE *f = fopen(file, "w");
    assert(f && fputs("WARN [old] from an earlier run\n", f) >= 0);
    long offset = ftell(f);
    assert(fputs("[boot-stage] init -> datadir_locked\nINFO ordinary\n", f) >= 0 && fflush(f) == 0);
    struct zapp_nodelog l;
    count = 0;
    zapp_nodelog_init(&l, sink, NULL);
    assert(zapp_nodelog_start(&l, file, offset, getpid()));
    for (int i = 0; i < 40 && forwarded() < 1; i++) { struct timespec p = {.tv_nsec = 100000000}; nanosleep(&p, NULL); }
    assert(fputs("ERROR [boot] db failed\n", f) >= 0 && fclose(f) == 0);
    for (int i = 0; i < 40 && forwarded() < 2; i++) { struct timespec p = {.tv_nsec = 100000000}; nanosleep(&p, NULL); }
    zapp_nodelog_stop(&l);
    assert(count == 2 && strstr(seen[0], "datadir_locked") && strstr(seen[1], "db failed"));
    assert(!strcmp(zapp_nodelog_stage(&l), "preparing cryptography"));
    assert(unlink(file) == 0);
}

int main(int argc, char **argv)
{
    assert(argc == 2);
    filter_cases();
    limit_cases();
    tail_cases(argv[1]);
    puts("nodelog tests passed");
    return 0;
}
