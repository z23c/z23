/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0 */
#include "nodelog.h"
#include <assert.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
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
    assert(!strcmp(seen[4], "WARN [net] dial()") && levels[4] == 1);
    assert(strstr(seen[5], "Tor: bootstrapping"));
    assert(strstr(seen[6], "bootstrap 45%"));
    assert(strstr(seen[7], "handshake complete") && levels[7] == 0);
    assert(!strcmp(seen[8], "ERROR [wallet] load()") && levels[8] == 1);
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

/* A warning or error that matched only its level word reaches logcat as the level, the domain and the function, never its text. */
static void level_lines_hide_their_text(void)
{
    static const char *const sensitive[] = {
        "2026-11-02T00:16:08Z ERROR [native.wallet] contexts/wallet/send.c:88 wnh_send(): failed paying zs1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq",
        "2026-11-02T00:16:08Z WARN  [native.wallet] contexts/wallet/tx.c:12 note_scan(): txid 0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef not found",
        "2026-11-02T00:16:08Z FAIL  [wallet.spend] contexts/wallet/spend.c:7 spend_check(): amount 12.34567890 ZCL to t1abcdefghijklmnopqrstuvwxyz1234567 refused",
        "2026-11-02T00:16:08Z FATAL [db] src/db.c:5 db_open_all(): cannot read t1abcdefghijklmnopqrstuvwxyz1234567",
    };
    static const char *const expected[] = {"ERROR [native.wallet] wnh_send()", "WARN [native.wallet] note_scan()", "FAIL [wallet.spend] spend_check()", "FATAL [db] db_open_all()"};
    struct zapp_nodelog l;
    count = 0;
    zapp_nodelog_init(&l, sink, NULL);
    for (size_t i = 0; i < sizeof(sensitive) / sizeof(sensitive[0]); i++) {
        zapp_nodelog_line(&l, sensitive[i], (int64_t)i * 1000);
        assert(count == (int)i + 1 && !strcmp(seen[i], expected[i]) && levels[i] == 1);
        assert(!strstr(seen[i], "zs1") && !strstr(seen[i], "t1abc") && !strstr(seen[i], "0123") && !strstr(seen[i], "12.3"));
    }
    /* Without a readable domain or function only the level is forwarded. */
    count = 0;
    zapp_nodelog_line(&l, "ERROR spent 5.5 ZCL for zs1abcdef", 9000);
    zapp_nodelog_line(&l, "WARN [bad domain] spent 5.5 ZCL", 9001);
    zapp_nodelog_line(&l, "ERROR [x] file.c:1 f(): zs1abc", 9002);
    assert(count == 3 && !strcmp(seen[0], "ERROR") && !strcmp(seen[1], "WARN") && !strcmp(seen[2], "ERROR [x] f()"));
}

/* Progress words in the text of a warning do not carry the text out, and a header that says INFO is information whatever its text holds. */
static void progress_words_do_not_leak(void)
{
    struct zapp_nodelog l;
    count = 0;
    zapp_nodelog_init(&l, sink, NULL);
    zapp_nodelog_line(&l, "2026-11-02T00:16:08Z ERROR [native.wallet] send.c:88 wnh_send(): paying zs1qqqq failed after handshake", 0);
    zapp_nodelog_line(&l, "2026-11-02T00:16:08Z WARN [wallet] w.c:2 f(): tor bootstrap of zs1qqqq restore", 1);
    zapp_nodelog_line(&l, "2026-11-02T00:16:08Z FAIL [boot] b.c:3 g(): [boot] zs1qqqq", 2);
    assert(count == 3 && !strcmp(seen[0], "ERROR [native.wallet] wnh_send()") && !strcmp(seen[1], "WARN [wallet] f()") &&
           !strcmp(seen[2], "FAIL [boot] g()"));
    count = 0;
    zapp_nodelog_line(&l, "2026-11-02T00:16:08Z INFO [wallet] w.c:1 f(): FAILED [zs1qqqq]", 3000);
    zapp_nodelog_line(&l, "2026-11-02T00:16:08Z INFO [wallet] w.c:1 f(): ERROR zs1qqqq", 3001);
    assert(count == 0);
    /* A line that does not begin with a header still reaches logcat as its level and nothing else. */
    zapp_nodelog_line(&l, "wallet.c:5 FATAL: could not open zs1qqqq", 3001);
    assert(count == 1 && !strcmp(seen[0], "FATAL") && levels[0] == 1);
    count = 0;
    /* A word that only contains a level is not a level. */
    zapp_nodelog_line(&l, "2026-11-02T00:16:08Z INFO [wallet] w.c:1 f(): WARNING ERRORS FAILED zs1qqqq", 3002);
    assert(count == 0);
    /* Tor progress needs the Tor domain or prefix; a wallet line with "restore" and "bootstrap" in a word is not it. */
    zapp_nodelog_line(&l, "2026-11-02T00:16:08Z INFO [wallet] w.c:1 f(): restore bootstrap data", 3003);
    assert(count == 0);
    /* A handshake is progress only from the net domain or the node's own peer lines. */
    zapp_nodelog_line(&l, "2026-11-02T00:16:08Z INFO [wallet] w.c:1 f(): paid zs1qqqq after handshake", 3009);
    zapp_nodelog_line(&l, "error: paying zs1qqqq failed after handshake", 3010);
    assert(count == 0);
    zapp_nodelog_line(&l, "Peer 203.0.113.9:8033 handshake complete", 3011);
    zapp_nodelog_line(&l, "Addnode 203.0.113.9:8033 handshake complete", 3012);
    assert(count == 2 && !strncmp(seen[0], "Peer ", 5) && !strncmp(seen[1], "Addnode ", 8));
    count = 0;
    /* Level and progress words match whole words only, and the Tor domain alone is not progress. */
    zapp_nodelog_line(&l, "ERRORS zs1qqqq", 3005);
    zapp_nodelog_line(&l, "x.c:1 WARNED about zs1qqqq", 3006);
    zapp_nodelog_line(&l, "NOERROR zs1qqqq", 3006);
    zapp_nodelog_line(&l, "2026-11-02T00:16:08Z INFO [net] w.c:1 f(): handshakes zs1qqqq", 3007);
    zapp_nodelog_line(&l, "2026-11-02T00:16:08Z INFO [tor] circuit built", 3008);
    assert(count == 0);
    zapp_nodelog_line(&l, "2026-11-02T00:16:08Z INFO [tor] bootstrap 90%", 3004);
    assert(count == 1 && strstr(seen[0], "bootstrap 90%"));
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
    memcpy(big, "[boot] ", 7);
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
    assert(zapp_nodelog_start(&l, file, offset, getpid(), ZAPP_CONSOLE_CAP));
    for (int i = 0; i < 40 && forwarded() < 1; i++) { struct timespec p = {.tv_nsec = 100000000}; nanosleep(&p, NULL); }
    assert(fputs("ERROR [boot] db failed\n", f) >= 0 && fclose(f) == 0);
    for (int i = 0; i < 40 && forwarded() < 2; i++) { struct timespec p = {.tv_nsec = 100000000}; nanosleep(&p, NULL); }
    zapp_nodelog_stop(&l);
    assert(count == 2 && strstr(seen[0], "datadir_locked") && !strcmp(seen[1], "ERROR [boot]"));
    assert(!strcmp(zapp_nodelog_stage(&l), "preparing cryptography"));
    assert(unlink(file) == 0);
}

static long file_size(const char *file)
{
    struct stat st;
    return stat(file, &st) == 0 ? (long)st.st_size : -1;
}
static void pause_briefly(void)
{
    struct timespec p = {.tv_nsec = 100000000};
    nanosleep(&p, NULL);
}

/* With a 256-byte cap, the reader forwards the unread oversize line, truncates the file to 0 and forwards the line written
 * after that. */
static void cap_truncates_and_resumes(const char *dir)
{
    char file[512], pad[300];
    assert(snprintf(file, sizeof(file), "%s/cap-console.log", dir) > 0);
    memset(pad, 'x', sizeof(pad) - 1);
    pad[sizeof(pad) - 1] = 0;
    FILE *f = fopen(file, "w");
    /* Written before the reader starts, so the line is unread tail when the reader first checks the cap. */
    assert(f && fprintf(f, "2026-11-02T00:16:08Z WARN [net] src/a.c:1 before(): %s\n", pad) > 256 && fclose(f) == 0);
    struct zapp_nodelog l;
    count = 0;
    zapp_nodelog_init(&l, sink, NULL);
    assert(zapp_nodelog_start(&l, file, 0, getpid(), 256));
    for (int i = 0; i < 40 && file_size(file) != 0; i++) pause_briefly();
    assert(file_size(file) == 0);
    /* Appended as the node appends: the file is opened in append mode, so the line lands at the new end. */
    f = fopen(file, "a");
    assert(f && fputs("2026-11-02T00:16:09Z WARN [net] src/b.c:2 after(): restarted\n", f) >= 0 && fclose(f) == 0);
    for (int i = 0; i < 40 && forwarded() < 2; i++) pause_briefly();
    zapp_nodelog_stop(&l);
    assert(count == 2 && !strcmp(seen[0], "WARN [net] before()") && !strcmp(seen[1], "WARN [net] after()"));
    assert(unlink(file) == 0);
}

/* A file under the cap is not touched. */
static void under_cap_left_alone(const char *dir)
{
    char file[512];
    assert(snprintf(file, sizeof(file), "%s/under-console.log", dir) > 0);
    const char *small = "2026-11-02T00:16:10Z WARN [net] src/c.c:3 under(): small\n";
    FILE *f = fopen(file, "w");
    assert(f && fputs(small, f) >= 0 && fclose(f) == 0);
    count = 0;
    struct zapp_nodelog l;
    zapp_nodelog_init(&l, sink, NULL);
    assert(zapp_nodelog_start(&l, file, 0, getpid(), 256));
    for (int i = 0; i < 40 && forwarded() < 1; i++) pause_briefly();
    for (int i = 0; i < 3; i++) pause_briefly();
    zapp_nodelog_stop(&l);
    assert(count == 1 && !strcmp(seen[0], "WARN [net] under()") && file_size(file) == (long)strlen(small));
    assert(unlink(file) == 0);
}

static void cap_cases(const char *dir)
{
    cap_truncates_and_resumes(dir);
    under_cap_left_alone(dir);
}

static void redacted(const char *in, const char *want)
{
    char out[ZAPP_NODELOG_LINE_MAX + 1];
    zapp_nodelog_redact(in, out, sizeof(out));
    if (strcmp(out, want)) { fprintf(stderr, "redact: got [%s] want [%s]\n", out, want); assert(0); }
}
/* Peer names never reach the sink; the rest of a progress line does. */
static void peer_names_are_redacted(void)
{
    redacted("Addnode abcdefghijklmnop.onion: protocol failure before handshake (eof)", "Addnode <peer>: protocol failure before handshake (eof)");
    redacted("Addnode ABCDEFGH.ONION:8033 handshake complete", "Addnode <peer> handshake complete");
    redacted("Peer 203.0.113.9 handshake complete", "Peer <peer> handshake complete");
    redacted("Peer 203.0.113.9:8033 handshake complete.", "Peer <peer> handshake complete.");
    redacted("Peer 2001:db8::1 handshake complete", "Peer <peer> handshake complete");
    redacted("Peer [2001:db8::1]:8033 handshake complete", "Peer <peer> handshake complete");
    redacted("Peer [::1]:8033, then ::ffff:203.0.113.9.", "Peer <peer>, then <peer>.");
    redacted("Peer 2001:db8:0:0:0:0:0:1 handshake complete", "Peer <peer> handshake complete");
    redacted("peer=203.0.113.9:8033 and peer=x.onion", "peer=<peer> and peer=<peer>");
    redacted("Peer a.onion b.onion handshake", "Peer <peer> <peer> handshake");
    redacted("Addnode:203.0.113.9 failed", "Addnode:<peer> failed");
    redacted("peer-203.0.113.9:8033 closed", "peer-<peer> closed");
    redacted("connect to:2001:db8::1 failed", "connect to:<peer> failed");
    redacted("dial:[2001:db8::1]:8033 failed", "dial:<peer> failed");
    redacted("Addnode:2001:db8::1", "Addnode:<peer>");
    /* Lines with no address are unchanged. */
    redacted("2026-10-29T10:00:05Z INFO  [net] handshake complete version=170012 height=3301698", "2026-10-29T10:00:05Z INFO  [net] handshake complete version=170012 height=3301698");
    redacted("[boot-stage] crypto_ready -> db_open 10:00:01 v1.2.3 onion service", "[boot-stage] crypto_ready -> db_open 10:00:01 v1.2.3 onion service");
    char tiny[8];
    zapp_nodelog_redact("Peer 203.0.113.9 handshake", tiny, sizeof(tiny));
    assert(!strcmp(tiny, "Peer <p"));
}
static void sink_lines_carry_no_peer(void)
{
    struct zapp_nodelog l;
    int before = count;
    zapp_nodelog_init(&l, sink, NULL);
    zapp_nodelog_line(&l, "Addnode abcdefghijklmnop.onion: protocol failure before handshake (eof)", 9000);
    zapp_nodelog_line(&l, "2026-10-29T10:00:05Z INFO  [net] handshake complete peer=203.0.113.9:8033 version=1", 9001);
    assert(count == before + 2);
    assert(!strcmp(seen[before], "Addnode <peer>: protocol failure before handshake (eof)"));
    assert(!strcmp(seen[before + 1], "2026-10-29T10:00:05Z INFO  [net] handshake complete peer=<peer> version=1"));
}

static void shutdown_timing_cases(void)
{
    static const char *const names[] = {"emergency-coins-flush", "diagnostics-drain",
        "frontend-stop", "network-quiesce", "worker-drain", "runtime-persist",
        "fast-restart-persist", "release-resources", "offline-worker-drain", "offline-persist"};
    struct zapp_nodelog l; char line[512], expected[128];
    count = 0; zapp_nodelog_init(&l, sink, NULL);
    for (size_t i = 0; i < sizeof(names) / sizeof(names[0]); i++) {
        snprintf(line, sizeof(line), "2026-11-05T07:00:00Z INFO [shutdown] stage.c:1 close_current_stage(): stage '%s' took 123ms (durability-critical)", names[i]);
        snprintf(expected, sizeof(expected), "shutdown stage=%s elapsed_ms=123", names[i]);
        zapp_nodelog_line(&l, line, (int64_t)i * 1000);
        assert(count == (int)i + 1 && !strcmp(seen[i], expected));
    }
    static const char *const bad[] = {
        "INFO [shutdown] s.c:1 close_current_stage(): stage 'wallet-secret' took 4ms",
        "INFO [shutdown] s.c:1 close_current_stage(): stage 'worker-drain' took -1ms",
        "INFO [shutdown] s.c:1 close_current_stage(): stage 'worker-drain' took 1234567890ms",
        "INFO [shutdown] s.c:1 close_current_stage(): stage 'worker-drain' took 1ms address=zs1secret",
        "INFO [wallet] s.c:1 close_current_stage(): stage 'worker-drain' took 1ms",
        "INFO [shutdown] s.c:1 other(): stage 'worker-drain' took 1ms",
        "INFO [shutdown] s.c:1 close_current_stage(): stage 'worker-drain' took 1ms mnemonic",
        "INFO [shutdown] s.c:1 close_current_stage(): stage 'worker-drain' took ms",
    };
    for (size_t i = 0; i < sizeof(bad) / sizeof(bad[0]); i++)
        zapp_nodelog_line(&l, bad[i], 20000 + (int64_t)i * 1000);
    assert(count == (int)(sizeof(names) / sizeof(names[0])));
}
static void shutdown_substep_cases(void)
{
    static const char *const input[] = {
        "[shutdown]   shutdown.projection_catch_up 12ms",
        "[shutdown]   shutdown.flat_save           33ms path=incremental rewritten_bytes=123",
        "[shutdown]   shutdown.flat_bind           44ms rows=10 checked=9 rows/s=2 threads=1",
        "[shutdown]   shutdown.wal_passive         0ms",
        "[shutdown]   shutdown.flat_save           1ms path=full rewritten_bytes=18446744073709551615",
        "[shutdown]   shutdown.flat_save           2ms"
    };
    static const char *const expected[] = {
        "shutdown substep=projection_catch_up elapsed_ms=12",
        "shutdown substep=flat_save elapsed_ms=33 mode=incremental rewritten_bytes=123",
        "shutdown substep=flat_bind elapsed_ms=44",
        "shutdown substep=wal_passive elapsed_ms=0",
        "shutdown substep=flat_save elapsed_ms=1 mode=full rewritten_bytes=18446744073709551615",
        "shutdown substep=flat_save elapsed_ms=2"
    };
    static const char *const bad[] = {
        "[shutdown]   shutdown.secret 1ms", "[shutdown]   shutdown.wal_passive -1ms",
        "[shutdown]   shutdown.wal_passive 1234567890ms", "[shutdown]   shutdown.wal_passive 1ms address=secret",
        "[shutdown]   shutdown.flat_save 1ms path=other rewritten_bytes=1",
        "[shutdown]   shutdown.flat_save 1ms path=full rewritten_bytes=18446744073709551616",
        "[shutdown]   shutdown.flat_bind 1ms rows=1 checked=2 rows/s=3 threads=4 extra=x",
        "[shutdown]   shutdown.flat_bind 1ms rows=1 checked=2 rows/s=3 threads=-1"
    };
    struct zapp_nodelog l; count = 0; zapp_nodelog_init(&l, sink, NULL);
    for (size_t i = 0; i < sizeof(input) / sizeof(input[0]); ++i) {
        zapp_nodelog_line(&l, input[i], (int64_t)i * 1000);
        assert(count == (int)i + 1 && !strcmp(seen[i], expected[i]));
    }
    for (size_t i = 0; i < sizeof(bad) / sizeof(bad[0]); ++i)
        zapp_nodelog_line(&l, bad[i], 10000 + (int64_t)i * 1000);
    assert(count == (int)(sizeof(input) / sizeof(input[0])));
}
int main(int argc, char **argv)
{
    assert(argc == 2);
    filter_cases();
    shutdown_timing_cases();
    shutdown_substep_cases();
    level_lines_hide_their_text();
    progress_words_do_not_leak();
    peer_names_are_redacted();
    sink_lines_carry_no_peer();
    limit_cases();
    tail_cases(argv[1]);
    cap_cases(argv[1]);
    puts("nodelog tests passed");
    return 0;
}
