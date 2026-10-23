/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Unit tests for the append-only event log primitive
 * (engine/modules/storage/src/event_log.c).
 *
 * Coverage: append/read round-trip, in-order streaming, fingerprint
 * determinism and sensitivity, targeted recovery plus an opt-in kill-9 fuzz
 * harness, opt-in throughput benchmark (ZCL_EVENT_LOG_BENCH=1), empty and
 * large payloads, corrupt tail detection, the verified-prefix receipt (fast
 * reopen, stale fallbacks, off-boot prefix audit). Default CI uses small counts;
 * ZCL_EVENT_LOG_EXHAUSTIVE=1 runs the larger matrices.
 * Tmpdirs live under ./test-tmp/event_log_<pid>_<tag>/. */

#include "test/test_core.h"

#include "platform/time_compat.h"
#include "crypto/sha3.h"
#include "services/reducer_ingest_service.h"
#include "storage/event_log.h"
#include "storage/event_log_singleton.h"

#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#if !defined(_WIN32)
#include <sys/wait.h>
#endif
#include <time.h>
#include <unistd.h>
#if !defined(_WIN32)

/* Sleep for `us` microseconds via nanosleep (POSIX.1-2001). */
static void sleep_us(uint64_t us)
{
    struct timespec ts;
    ts.tv_sec  = (time_t)(us / 1000000u);
    ts.tv_nsec = (long)((us % 1000000u) * 1000u);
    nanosleep(&ts, NULL);
}

#define EL_CHECK(name, expr) do { \
    printf("event_log: %s... ", (name)); \
    if ((expr)) printf("OK\n"); \
    else { printf("FAIL\n"); failures++; } \
} while (0)

static int el_mkdir_p(const char *p)
{
    if (mkdir(p, 0700) == 0) return 0;
    if (errno == EEXIST) return 0;
    return -1;
}

/* Ensure ./test-tmp/ exists (parent of all our scratch dirs). */
static void el_ensure_root(void)
{
    el_mkdir_p("./test-tmp");
}

static double mono_sec(void)
{
    struct timespec ts;
    platform_time_monotonic_timespec(&ts);
    return (double)ts.tv_sec + (double)ts.tv_nsec / 1e9;
}

static bool event_log_exhaustive_enabled(void)
{
    return getenv("ZCL_EVENT_LOG_EXHAUSTIVE") != NULL;
}

/* ── Task 2: append + read round-trip ──────────────────────────────── */

static int run_append_read_roundtrip(int *failures_out)
{
    int failures = 0;
    char dir[256];
    test_fmt_tmpdir(dir, sizeof(dir), "event_log", "rt");
    el_mkdir_p(dir);
    char path[512];
    snprintf(path, sizeof(path), "%s/events.log", dir);

    event_log_t *log = event_log_open(path);
    EL_CHECK("open fresh log", log != NULL);
    if (!log) goto done;
    event_log_set_deferred_sync(log, true);

    const int N = event_log_exhaustive_enabled() ? 1000 : 64;
    uint64_t offsets[1000];
    event_log_test_reset_append_stats();
    /* Variable-size payloads so we exercise different lengths. */
    for (int i = 0; i < N; i++) {
        uint8_t buf[200];
        size_t len = (size_t)((i * 7) % 200);
        for (size_t k = 0; k < len; k++)
            buf[k] = (uint8_t)((i + k) * 31 + 5);
        offsets[i] = event_log_append(log,
                        (enum event_log_type)(EV_BLOCK_HEADER + (i % 11)),
                        buf, len);
    }
    bool all_ok = true;
    for (int i = 0; i < N; i++)
        if (offsets[i] == UINT64_MAX) { all_ok = false; break; }
    EL_CHECK("append/read: all selected appends succeed", all_ok);

    uint64_t barrier = 0, deferred = 0, barrier_us = 0;
    event_log_append_stats(&barrier, &deferred, &barrier_us);
    EL_CHECK("append/read: bulk fixture takes no per-event barriers",
             barrier == 0 && deferred == (uint64_t)N);
    EL_CHECK("append/read: publish bulk fixture once",
             event_log_flush(log));

    /* Round-trip every event. */
    bool rt_ok = true;
    for (int i = 0; i < N && rt_ok; i++) {
        uint8_t expect[200];
        size_t exp_len = (size_t)((i * 7) % 200);
        for (size_t k = 0; k < exp_len; k++)
            expect[k] = (uint8_t)((i + k) * 31 + 5);

        uint8_t got[200] = {0};
        enum event_log_type t = 0;
        size_t got_len = 0;
        int r = event_log_read(log, offsets[i], &t, got,
                               sizeof(got), &got_len);
        if (r != 0) { rt_ok = false; break; }
        if (got_len != exp_len) { rt_ok = false; break; }
        if ((uint32_t)t != (uint32_t)(EV_BLOCK_HEADER + (i % 11))) {
            rt_ok = false; break;
        }
        if (memcmp(got, expect, exp_len) != 0) {
            rt_ok = false; break;
        }
    }
    EL_CHECK("append/read: selected events round-trip via event_log_read",
             rt_ok);

    event_log_close(log);
    test_cleanup_tmpdir(dir);
done:
    event_log_test_reset_append_stats();
    *failures_out += failures;
    return failures;
}

/* ── Task 3: stream callback ───────────────────────────────────────── */

struct stream_ctx {
    int count;
    bool ordered;
    uint64_t last_offset;
    int max;
    int stop_at;  /* if > 0, stop after this many */
};

static bool stream_cb(uint64_t offset, enum event_log_type type,
                      const void *payload, size_t len, void *user)
{
    (void)type; (void)payload; (void)len;
    struct stream_ctx *c = (struct stream_ctx *)user;
    if (c->count > 0 && offset <= c->last_offset)
        c->ordered = false;
    c->last_offset = offset;
    c->count++;
    if (c->stop_at > 0 && c->count >= c->stop_at) return false;
    return true;
}

static int run_stream(int *failures_out)
{
    int failures = 0;
    char dir[256];
    test_fmt_tmpdir(dir, sizeof(dir), "event_log", "stream");
    el_mkdir_p(dir);
    char path[512];
    snprintf(path, sizeof(path), "%s/events.log", dir);

    event_log_t *log = event_log_open(path);
    EL_CHECK("stream: open OK", log != NULL);
    if (!log) goto done;
    event_log_set_deferred_sync(log, true);
    event_log_test_reset_append_stats();

    const int N = event_log_exhaustive_enabled() ? 1000 : 64;
    for (int i = 0; i < N; i++) {
        uint8_t buf[64];
        memset(buf, (int)(i & 0xFF), sizeof(buf));
        event_log_append(log, EV_BLOCK_BODY, buf, sizeof(buf));
    }
    uint64_t barrier = 0, deferred = 0, barrier_us = 0;
    event_log_append_stats(&barrier, &deferred, &barrier_us);
    EL_CHECK("stream: bulk fixture takes no per-event barriers",
             barrier == 0 && deferred == (uint64_t)N);
    EL_CHECK("stream: publish bulk fixture once", event_log_flush(log));
    struct stream_ctx c = {0};
    c.ordered = true;
    c.max = N;
    int r = event_log_stream(log, 0, stream_cb, &c);
    EL_CHECK("stream returns 0", r == 0);
    EL_CHECK("stream visits exactly N events", c.count == N);
    EL_CHECK("stream visits in offset-monotonic order", c.ordered);

    /* Early-termination via callback. */
    struct stream_ctx c2 = {0};
    c2.ordered = true;
    c2.stop_at = 5;
    r = event_log_stream(log, 0, stream_cb, &c2);
    EL_CHECK("stream early-terminate returns 0", r == 0);
    EL_CHECK("stream early-terminate honours cb stop", c2.count == 5);

    event_log_close(log);
    test_cleanup_tmpdir(dir);
done:
    event_log_test_reset_append_stats();
    *failures_out += failures;
    return failures;
}

/* ── Task 4: fingerprint ───────────────────────────────────────────── */

static int run_fingerprint(int *failures_out)
{
    int failures = 0;
    char dir1[256], dir2[256];
    test_fmt_tmpdir(dir1, sizeof(dir1), "event_log", "fp1");
    test_fmt_tmpdir(dir2, sizeof(dir2), "event_log", "fp2");
    el_mkdir_p(dir1);
    el_mkdir_p(dir2);
    char p1[512], p2[512];
    snprintf(p1, sizeof(p1), "%s/events.log", dir1);
    snprintf(p2, sizeof(p2), "%s/events.log", dir2);

    event_log_t *a = event_log_open(p1);
    event_log_t *b = event_log_open(p2);
    EL_CHECK("fp: open a", a != NULL);
    EL_CHECK("fp: open b", b != NULL);
    if (!a || !b) goto done;
    event_log_set_deferred_sync(a, true);
    event_log_set_deferred_sync(b, true);
    event_log_test_reset_append_stats();

    const int N = event_log_exhaustive_enabled() ? 256 : 32;
    for (int i = 0; i < N; i++) {
        uint8_t buf[33];
        for (size_t k = 0; k < sizeof(buf); k++)
            buf[k] = (uint8_t)(i + k);
        event_log_append(a, EV_UTXO_ADD, buf, sizeof(buf));
        event_log_append(b, EV_UTXO_ADD, buf, sizeof(buf));
    }
    uint64_t barrier = 0, deferred = 0, barrier_us = 0;
    event_log_append_stats(&barrier, &deferred, &barrier_us);
    EL_CHECK("fp: bulk fixtures take no per-event barriers",
             barrier == 0 && deferred == (uint64_t)(2 * N));
    EL_CHECK("fp: publish fixture a once", event_log_flush(a));
    EL_CHECK("fp: publish fixture b once", event_log_flush(b));
    uint8_t ha[32], hb[32];
    EL_CHECK("fp(a)", event_log_fingerprint(a, ha) == 0);
    EL_CHECK("fp(b)", event_log_fingerprint(b, hb) == 0);
    EL_CHECK("identical content → identical fingerprint",
             memcmp(ha, hb, 32) == 0);

    /* Append one more event to b — fingerprints must differ. */
    uint8_t extra[1] = {0xFF};
    event_log_append(b, EV_UTXO_ADD, extra, 1);
    EL_CHECK("fp: publish mutation once", event_log_flush(b));
    EL_CHECK("fp(b) after extra append", event_log_fingerprint(b, hb) == 0);
    EL_CHECK("one-byte change → different fingerprint",
             memcmp(ha, hb, 32) != 0);

    /* fingerprint over empty log is deterministic (SHA3-256 of empty). */
    char dir3[256];
    test_fmt_tmpdir(dir3, sizeof(dir3), "event_log", "fp3");
    el_mkdir_p(dir3);
    char p3[512];
    snprintf(p3, sizeof(p3), "%s/events.log", dir3);
    event_log_t *c = event_log_open(p3);
    EL_CHECK("fp: open empty c", c != NULL);
    uint8_t hc[32];
    EL_CHECK("fp(empty)", event_log_fingerprint(c, hc) == 0);
    /* SHA3-256("") = a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a */
    static const uint8_t empty_sha3[32] = {
        0xa7,0xff,0xc6,0xf8,0xbf,0x1e,0xd7,0x66,
        0x51,0xc1,0x47,0x56,0xa0,0x61,0xd6,0x62,
        0xf5,0x80,0xff,0x4d,0xe4,0x3b,0x49,0xfa,
        0x82,0xd8,0x0a,0x4b,0x80,0xf8,0x43,0x4a,
    };
    EL_CHECK("fp(empty) == SHA3-256(\"\")",
             memcmp(hc, empty_sha3, 32) == 0);

    event_log_close(a);
    event_log_close(b);
    event_log_close(c);
    test_cleanup_tmpdir(dir1);
    test_cleanup_tmpdir(dir2);
    test_cleanup_tmpdir(dir3);
done:
    event_log_test_reset_append_stats();
    *failures_out += failures;
    return failures;
}

/* ── Task 5: kill-9 fuzz harness (LOAD-BEARING) ────────────────────── */

/* The child appends until killed; payload i is the 4-byte LE integer i plus
 * a fixed pattern. After the kill the parent reopens (recovery + tail
 * truncation) and asserts every event has a valid CRC + sentinel. */

#define FUZZ_PAYLOAD_LEN  64

static void child_appender(const char *path)
{
    /* Direct stderr away so the kill doesn't leave dangling messages. */
 TEST_DISCARD(freopen("/dev/null", "w", stderr));
    event_log_t *log = event_log_open(path);
    if (!log) _exit(2);
    uint32_t i = 0;
    while (1) {
        uint8_t buf[FUZZ_PAYLOAD_LEN];
        buf[0] = (uint8_t)(i & 0xFF);
        buf[1] = (uint8_t)((i >> 8) & 0xFF);
        buf[2] = (uint8_t)((i >> 16) & 0xFF);
        buf[3] = (uint8_t)((i >> 24) & 0xFF);
        for (int k = 4; k < FUZZ_PAYLOAD_LEN; k++)
            buf[k] = (uint8_t)(0xA5 ^ k);
        if (event_log_append(log, EV_BLOCK_HEADER,
                             buf, sizeof(buf)) == UINT64_MAX) {
            _exit(3);
        }
        i++;
    }
}

/* Deferred-mode variant: per-append fsync skipped, one fdatasync every
 * FLUSH_EVERY events. A SIGKILL mid-batch loses un-synced whole events; the
 * tail scan must recover a consistent prefix. Same payload scheme as
 * child_appender. */
#define DEFERRED_FLUSH_EVERY 8
static void child_appender_deferred(const char *path)
{
 TEST_DISCARD(freopen("/dev/null", "w", stderr));
    event_log_t *log = event_log_open(path);
    if (!log) _exit(2);
    event_log_set_deferred_sync(log, true);
    uint32_t i = 0;
    while (1) {
        uint8_t buf[FUZZ_PAYLOAD_LEN];
        buf[0] = (uint8_t)(i & 0xFF);
        buf[1] = (uint8_t)((i >> 8) & 0xFF);
        buf[2] = (uint8_t)((i >> 16) & 0xFF);
        buf[3] = (uint8_t)((i >> 24) & 0xFF);
        for (int k = 4; k < FUZZ_PAYLOAD_LEN; k++)
            buf[k] = (uint8_t)(0xA5 ^ k);
        if (event_log_append(log, EV_BLOCK_HEADER,
                             buf, sizeof(buf)) == UINT64_MAX) {
            _exit(3);
        }
        if ((++i % DEFERRED_FLUSH_EVERY) == 0) {
            if (!event_log_flush(log)) _exit(4);
        }
    }
}

struct fuzz_count_ctx {
    int count;
    bool ok;
    uint32_t expected_next;
};

static bool fuzz_count_cb(uint64_t offset, enum event_log_type type,
                          const void *payload, size_t len, void *user)
{
    (void)offset;
    struct fuzz_count_ctx *c = (struct fuzz_count_ctx *)user;
    if (type != EV_BLOCK_HEADER || len != FUZZ_PAYLOAD_LEN) {
        c->ok = false;
        return false;
    }
    const uint8_t *p = (const uint8_t *)payload;
    uint32_t got = (uint32_t)p[0]
        | ((uint32_t)p[1] << 8)
        | ((uint32_t)p[2] << 16)
        | ((uint32_t)p[3] << 24);
    if (got != c->expected_next) {
        c->ok = false;
        return false;
    }
    for (int k = 4; k < FUZZ_PAYLOAD_LEN; k++) {
        if (p[k] != (uint8_t)(0xA5 ^ k)) {
            c->ok = false;
            return false;
        }
    }
    c->count++;
    c->expected_next++;
    return true;
}

/* One kill-9 trial. The parent waits `delay_us` before SIGKILL. */
static bool run_one_kill9_trial(const char *path, uint64_t delay_us,
                                bool deferred)
{
    /* Wipe any prior log for clean state. */
    unlink(path);

    pid_t pid = fork();
    if (pid < 0) return false;
    if (pid == 0) {
        if (deferred) child_appender_deferred(path);
        else          child_appender(path);
        _exit(0);
    }
    sleep_us(delay_us);
    if (kill(pid, SIGKILL) != 0) {
        /* Process already exited (e.g., appender error). */
    }
    int status = 0;
    waitpid(pid, &status, 0);

    /* Reopen (triggers tail recovery) and stream. */
    event_log_t *log = event_log_open(path);
    if (!log) return false;

    struct fuzz_count_ctx c = { .count = 0, .ok = true,
                                .expected_next = 0 };
    int r = event_log_stream(log, 0, fuzz_count_cb, &c);
    if (r != 0 || !c.ok) {
        event_log_close(log);
        return false;
    }
    /* Reopen again: recovery is idempotent (size equals the well-formed
     * prefix), checked via the fingerprint computed twice. */
    uint8_t fp1[32], fp2[32];
    if (event_log_fingerprint(log, fp1) != 0) {
        event_log_close(log);
        return false;
    }
    event_log_close(log);

    log = event_log_open(path);
    if (!log) return false;
    if (event_log_fingerprint(log, fp2) != 0) {
        event_log_close(log);
        return false;
    }
    bool stable = memcmp(fp1, fp2, 32) == 0;
    event_log_close(log);
    return stable;
}

static int run_kill9_fuzz(int *failures_out)
{
    int failures = 0;
    if (getenv("ZCL_EVENT_LOG_KILL9_FUZZ") == NULL) {
        printf("event_log: kill9 fuzz SKIP "
               "(set ZCL_EVENT_LOG_KILL9_FUZZ=1 for the background lane)\n");
        return 0;
    }

    char dir[256];
    test_fmt_tmpdir(dir, sizeof(dir), "event_log", "kill9");
    el_mkdir_p(dir);
    char path[512];
    snprintf(path, sizeof(path), "%s/events.log", dir);

    /* Spread of delays from very short (likely to interrupt mid-header
     * or mid-payload) to longer (many complete events landed). */
    static const uint64_t delays[] = {
        100,     /* 0.1 ms */
        500,     /* 0.5 ms */
        1000,    /* 1 ms */
        2000,    /* 2 ms */
        5000,    /* 5 ms */
        10000,   /* 10 ms */
        20000,   /* 20 ms */
        50000,   /* 50 ms */
    };
    const int trials_per_delay = 3;
    bool all_ok = true;
    int total = 0, good = 0;
    /* Both durability modes (per-append fsync, deferred batch-flush) recover
     * to a consistent prefix identically. */
    for (int mode = 0; mode < 2; mode++) {
        bool deferred = (mode == 1);
        for (size_t i = 0; i < sizeof(delays) / sizeof(delays[0]); i++) {
            for (int t = 0; t < trials_per_delay; t++) {
                total++;
                if (run_one_kill9_trial(path, delays[i], deferred)) good++;
                else all_ok = false;
            }
        }
    }
    printf("event_log: kill9 trials passed: %d/%d (per-append + deferred)\n",
           good, total);
    EL_CHECK("all kill9 trials recover to a valid log", all_ok);

    test_cleanup_tmpdir(dir);
    *failures_out += failures;
    return failures;
}

/* Targeted recovery: corrupt the tail (mid-sentinel, mid-payload,
 * mid-header) and verify open() recovers. */
static int run_targeted_recovery(int *failures_out)
{
    int failures = 0;
    char dir[256];
    test_fmt_tmpdir(dir, sizeof(dir), "event_log", "recov");
    el_mkdir_p(dir);
    char path[512];
    snprintf(path, sizeof(path), "%s/events.log", dir);

    /* Build a log with a few events; record the size after each. */
    event_log_t *log = event_log_open(path);
    EL_CHECK("recov: open", log != NULL);
    if (!log) goto done;

    const int event_count = event_log_exhaustive_enabled() ? 5 : 3;
    uint64_t sizes[5];
    for (int i = 0; i < event_count; i++) {
        uint8_t buf[32];
        memset(buf, (int)(0x10 + i), sizeof(buf));
        event_log_append(log, EV_BLOCK_HEADER, buf, sizeof(buf));
        sizes[i] = event_log_size(log);
    }
    event_log_close(log);

    /* For each kind of corruption, truncate the file to (size_prefix +
     * partial_bytes) and verify reopen rolls back to size_prefix. */
    for (int i = 0; i < event_count; i++) {
        uint64_t prefix = (i == 0) ? 0 : sizes[i - 1];
        /* Try truncations at +1, +halfway, +size-1 of event i. */
        uint64_t evt_len = sizes[i] - prefix;
        uint64_t tries[3] = {
            prefix + 1,
            prefix + (evt_len / 2),
            sizes[i] - 1,
        };
        for (int j = 0; j < 3; j++) {
            int fd = open(path, O_WRONLY);
            if (fd < 0) { failures++; continue; }
             TEST_DISCARD(ftruncate(fd, (off_t)tries[j]));
            fsync(fd);
            close(fd);

            event_log_t *l2 = event_log_open(path);
            if (!l2) { failures++; continue; }
            EL_CHECK("recov: tail truncated to last-good prefix",
                     event_log_size(l2) == prefix);
            /* Streaming must visit exactly i events. */
            struct stream_ctx sc = {0};
            sc.ordered = true;
            event_log_stream(l2, 0, stream_cb, &sc);
            EL_CHECK("recov: stream visits exactly the good events",
                     sc.count == i);
            event_log_close(l2);

            /* Restore the full log for the next iteration by re-appending
             * event i with the original payload. */
            l2 = event_log_open(path);
            if (l2) {
                /* Re-append events i..end so sizes[] stays accurate. */
                for (int kk = i; kk < event_count; kk++) {
                    uint8_t buf[32];
                    memset(buf, (int)(0x10 + kk), sizeof(buf));
                    event_log_append(l2, EV_BLOCK_HEADER,
                                     buf, sizeof(buf));
                    sizes[kk] = event_log_size(l2);
                }
                event_log_close(l2);
            }
        }
    }

    test_cleanup_tmpdir(dir);
done:
    *failures_out += failures;
    return failures;
}

/* ── Task 6: benchmark ─────────────────────────────────────────────── */

struct bench_readback {
    uint64_t count;
    uint64_t bytes;
    bool valid;
};

static bool bench_readback_cb(uint64_t offset, enum event_log_type type,
                              const void *payload, size_t len, void *user)
{
    struct bench_readback *c = user;
    uint8_t expected[128];
    memset(expected, 0xC3, sizeof(expected));
    if (c->count >= 136u || type != EV_BLOCK_HEADER || len != sizeof(expected)) {
        c->valid = false;
        return false;
    }
    c->valid = c->valid && memcmp(payload, expected, sizeof(expected)) == 0;
    c->valid = c->valid && offset == c->bytes;
    c->count++;
    c->bytes += EVENT_LOG_FRAME_OVERHEAD + sizeof(expected);
    return c->valid;
}

static int bench_check_readback(const char *path, uint64_t expected_count)
{
    int failures = 0;
    event_log_t *log = event_log_open(path);
    EL_CHECK("bench proof: reopen", log != NULL);
    if (!log) return failures;
    struct bench_readback c = {.valid = true};
    int rc = event_log_stream(log, 0, bench_readback_cb, &c);
    EL_CHECK("bench proof: read-back count", c.count == expected_count);
    EL_CHECK("bench proof: read-back bytes and payloads",
             rc == 0 && c.valid &&
             c.bytes == expected_count * (EVENT_LOG_FRAME_OVERHEAD + 128u) &&
             event_log_size(log) == c.bytes);
    event_log_close(log);
    return failures;
}

static bool bench_proof_append(event_log_t *log, int count, bool deferred,
                               unsigned *flushes_out)
{
    *flushes_out = 0;
    uint8_t pay[128];
    memset(pay, 0xC3, sizeof(pay));
    bool ok = true;
    for (int i = 0; i < count; i++) {
        if (event_log_append(log, EV_BLOCK_HEADER, pay, sizeof(pay)) == UINT64_MAX)
            ok = false;
        if (deferred && ((i + 1) % 64) == 0) {
            ++*flushes_out;
            if (!event_log_flush(log)) ok = false;
        }
    }
    if (deferred) {
        ++*flushes_out;
        if (!event_log_flush(log)) ok = false;
    }
    return ok;
}

static int bench_proof_mode(const char *path, int count, int warmup,
                            bool deferred)
{
    int failures = 0;
    event_log_t *log = event_log_open(path);
    EL_CHECK("bench proof: open", log != NULL);
    if (!log) return failures;
    event_log_set_deferred_sync(log, deferred);
    unsigned flushes = 0;
    EL_CHECK("bench proof: warm-up appends succeed",
             bench_proof_append(log, warmup, false, &flushes));
    bool ok = bench_proof_append(log, count, deferred, &flushes);
    printf("event_log: bounded push proof %s — %d requested events\n",
           deferred ? "DEFERRED(flush/64)" : "PER-APPEND-fsync", count);
    EL_CHECK("bench proof: all appends and flushes succeed", ok);
    unsigned expected_flushes = deferred ? (unsigned)count / 64u + 1u : 0u;
    EL_CHECK("bench proof: explicit flush count", flushes == expected_flushes);
    event_log_close(log);
    failures += bench_check_readback(path, (uint64_t)(count + warmup));
    return failures;
}

static int run_benchmark_proof(void)
{
    char dir[4096], path[4128];
    int failures = 0;
    char *created = test_mkdtemp(dir, sizeof(dir), "event_log_bench_proof");
    EL_CHECK("bench proof: fixture creation succeeds", created != NULL);
    if (!created) return failures;
    event_log_test_set_force_per_append(0);
    snprintf(path, sizeof(path), "%s/events.log", dir);
    failures += bench_proof_mode(path, 128, 8, false);
    snprintf(path, sizeof(path), "%s/ab_0.log", dir);
    failures += bench_proof_mode(path, 64, 0, false);
    snprintf(path, sizeof(path), "%s/ab_1.log", dir);
    failures += bench_proof_mode(path, 64, 0, true);
    event_log_test_set_force_per_append(-1);
    EL_CHECK("bench proof: fixture cleanup succeeds",
             test_rm_rf_recursive(dir) == 0);
    if (failures == 0)
        printf("event_log: bounded push proof completed: counts=136,64,64 flushes=0,0,2\n");
    return failures;
}

static int run_benchmark_ab(const char *dir, const uint8_t pay[128])
{
    int failures = 0;
    /* A/B on fresh logs: per-append fsync (mode A) vs deferred batch-flush
     * (mode B); flush_every mirrors the reducer drain-batch size. */
    {
        /* Small N: the per-append-fsync leg pays a disk barrier per event. */
        const int Nab = 4000;
        const int flush_every = 64;
        for (int mode = 0; mode < 2; mode++) {
            char abpath[544];
            snprintf(abpath, sizeof(abpath), "%s/ab_%d.log", dir, mode);
            unlink(abpath);
            event_log_t *l = event_log_open(abpath);
            if (!l) { EL_CHECK("bench: A/B open", false); continue; }
            bool deferred = (mode == 1);
            event_log_set_deferred_sync(l, deferred);
            double a0 = mono_sec();
            for (int i = 0; i < Nab; i++) {
                event_log_append(l, EV_BLOCK_HEADER, pay, 128u);
                if (deferred && ((i + 1) % flush_every) == 0)
                    event_log_flush(l);
            }
            if (deferred) event_log_flush(l);
            double a1 = mono_sec();
            double s = a1 - a0;
            double r = s > 0 ? (double)Nab / s : 0;
            printf("event_log: A/B %s — %d events in %.3f s = %.0f ev/s "
                   "(%.1f us/event)\n",
                   deferred ? "DEFERRED(flush/64)" : "PER-APPEND-fsync",
                   Nab, s, r, s * 1e6 / (double)Nab);
            event_log_close(l);
            unlink(abpath);
        }
    }

    return failures;
}

/* Measures append throughput and prints events/sec. The 50K/sec target is
 * reported, not asserted: parallel groups contend on fsync. Opt-in via
 * ZCL_EVENT_LOG_BENCH=1, run in isolation for the real number. */
static int run_benchmark(int *failures_out)
{
    int failures = 0;
    bool full_benchmark = getenv("ZCL_EVENT_LOG_BENCH") != NULL;
    bool push_proof = !full_benchmark &&
                      getenv("ZCL_EVENT_LOG_BENCH_PROOF") != NULL;
    if (push_proof) {
        int result = run_benchmark_proof();
        *failures_out += result;
        return result;
    }
    if (!full_benchmark) {
        printf("event_log: benchmark SKIP "
               "(set ZCL_EVENT_LOG_BENCH=1 for standalone measurement or "
               "use the push-proof runner contract)\n");
        return 0;
    }

    char dir[256];
    test_fmt_tmpdir(dir, sizeof(dir), "event_log", "bench");
    el_mkdir_p(dir);
    char path[512];
    snprintf(path, sizeof(path), "%s/events.log", dir);

    event_log_t *log = event_log_open(path);
    EL_CHECK("bench: open", log != NULL);
    if (!log) goto done;

    /* Warm-up. */
    uint8_t pay[128];
    memset(pay, 0xC3, sizeof(pay));
    int warmup_count = 50;
    for (int i = 0; i < warmup_count; i++)
        event_log_append(log, EV_BLOCK_HEADER, pay, sizeof(pay));

    int N = 50000;

    double t0 = mono_sec();
    for (int i = 0; i < N; i++)
        event_log_append(log, EV_BLOCK_HEADER, pay, sizeof(pay));
    double t1 = mono_sec();
    double sec = t1 - t0;
    double rate = sec > 0 ? (double)N / sec : 0;
    printf("event_log: benchmark — %d events in %.3f s = %.0f events/sec "
           "(%s)\n",
           N, sec, rate, "standalone");
    if (rate >= 50000.0)
        printf("event_log: benchmark — MEETS 50K/sec target\n");
    else
        printf("event_log: benchmark — below 50K/sec target "
               "(run ZCL_EVENT_LOG_BENCH=1 on an idle lane for the real number)\n");
    /* Sanity floor, permissive so concurrent fsync load cannot fail it. */
    EL_CHECK("bench: rate > 10 events/sec (sanity)", rate > 10.0);
    event_log_close(log);

    failures += run_benchmark_ab(dir, pay);

    test_cleanup_tmpdir(dir);
done:
    *failures_out += failures;
    return failures;
}

/* ── empty payload + large payload ─────────────────────────────────── */

static int run_edge_cases(int *failures_out)
{
    int failures = 0;
    char dir[256];
    test_fmt_tmpdir(dir, sizeof(dir), "event_log", "edge");
    el_mkdir_p(dir);
    char path[512];
    snprintf(path, sizeof(path), "%s/events.log", dir);

    event_log_t *log = event_log_open(path);
    EL_CHECK("edge: open", log != NULL);
    if (!log) goto done;

    /* Empty payload. */
    uint64_t off = event_log_append(log, EV_PEER_OBSERVED, NULL, 0);
    EL_CHECK("edge: empty append succeeds", off != UINT64_MAX);
    enum event_log_type t = 0;
    uint8_t buf[16] = {0};
    size_t got = 999;
    int r = event_log_read(log, off, &t, buf, sizeof(buf), &got);
    EL_CHECK("edge: empty read returns 0", r == 0);
    EL_CHECK("edge: empty payload length is 0", got == 0);
    EL_CHECK("edge: empty type round-trips",
             (uint32_t)t == (uint32_t)EV_PEER_OBSERVED);

    /* 1 MiB payload. */
    const size_t big_len = 1u << 20;
    uint8_t *big = malloc(big_len);  // raw-alloc-ok:test-scratch
    EL_CHECK("edge: alloc 1MiB", big != NULL);
    if (big) {
        for (size_t k = 0; k < big_len; k++)
            big[k] = (uint8_t)(k * 13 + 7);
        off = event_log_append(log, EV_BLOCK_BODY, big, big_len);
        EL_CHECK("edge: 1MiB append succeeds", off != UINT64_MAX);
        uint8_t *out = malloc(big_len);  // raw-alloc-ok:test-scratch
        EL_CHECK("edge: alloc 1MiB out", out != NULL);
        if (out) {
            got = 0;
            r = event_log_read(log, off, &t, out, big_len, &got);
            EL_CHECK("edge: 1MiB read returns 0", r == 0);
            EL_CHECK("edge: 1MiB length matches", got == big_len);
            EL_CHECK("edge: 1MiB bytes match",
                     memcmp(big, out, big_len) == 0);
            free(out);
        }
        free(big);
    }

    /* NULL input rejected. */
    EL_CHECK("edge: append on NULL log returns sentinel",
             event_log_append(NULL, EV_BLOCK_HEADER, "x", 1) == UINT64_MAX);
    EL_CHECK("edge: read on NULL log returns -1",
             event_log_read(NULL, 0, &t, buf, sizeof(buf), &got) == -1);
    EL_CHECK("edge: open(NULL) returns NULL",
             event_log_open(NULL) == NULL);
    EL_CHECK("edge: open(\"\") returns NULL",
             event_log_open("") == NULL);
    EL_CHECK("edge: close(NULL) is safe",
             (event_log_close(NULL), true));

    event_log_close(log);
    test_cleanup_tmpdir(dir);
done:
    *failures_out += failures;
    return failures;
}

/* ── persistence across close + reopen ─────────────────────────────── */

static int run_persistence(int *failures_out)
{
    int failures = 0;
    char dir[256];
    test_fmt_tmpdir(dir, sizeof(dir), "event_log", "persist");
    el_mkdir_p(dir);
    char path[512];
    snprintf(path, sizeof(path), "%s/events.log", dir);

    event_log_t *log = event_log_open(path);
    EL_CHECK("persist: open #1", log != NULL);
    if (!log) goto done;

    const int N = event_log_exhaustive_enabled() ? 50 : 8;
    uint64_t offsets[50];
    for (int i = 0; i < N; i++) {
        uint8_t buf[33];
        memset(buf, (int)(i + 1), sizeof(buf));
        offsets[i] = event_log_append(log, EV_UTXO_ADD, buf, sizeof(buf));
    }
    uint8_t fp_before[32];
    event_log_fingerprint(log, fp_before);
    event_log_close(log);

    /* Reopen and verify. */
    log = event_log_open(path);
    EL_CHECK("persist: open #2", log != NULL);
    if (!log) goto done;

    uint8_t fp_after[32];
    EL_CHECK("persist: fingerprint after reopen",
             event_log_fingerprint(log, fp_after) == 0);
    EL_CHECK("persist: fingerprint unchanged across reopen",
             memcmp(fp_before, fp_after, 32) == 0);

    /* Each event still readable. */
    bool all_ok = true;
    for (int i = 0; i < N; i++) {
        uint8_t got[33] = {0};
        enum event_log_type t = 0;
        size_t got_len = 0;
        if (event_log_read(log, offsets[i], &t, got,
                           sizeof(got), &got_len) != 0) {
            all_ok = false; break;
        }
        for (size_t k = 0; k < sizeof(got); k++)
            if (got[k] != (uint8_t)(i + 1)) { all_ok = false; break; }
    }
    EL_CHECK("persist: all events readable after reopen", all_ok);

    event_log_close(log);
    test_cleanup_tmpdir(dir);
done:
    *failures_out += failures;
    return failures;
}

/* ── CRC32C implementation dispatch ───────────────────────────────── */

static int run_crc32c_dispatch(int *failures_out)
{
    int failures = 0;
    enum { LEN = 1u << 20 };
    uint8_t *buf = malloc(LEN);  // raw-alloc-ok:test-scratch
    EL_CHECK("crc32c: alloc bench buffer", buf != NULL);
    if (!buf) {
        *failures_out += failures;
        return failures;
    }
    for (size_t i = 0; i < LEN; i++)
        buf[i] = (uint8_t)(i * 19u + i / 7u + 3u);

    uint32_t sw = event_log_crc32c_test_sw(buf, LEN);
    uint32_t active = event_log_crc32c_test_active(buf, LEN);
    EL_CHECK("crc32c: active matches software reference", active == sw);

    bool standalone = getenv("ZCL_EVENT_LOG_BENCH") != NULL;
    int loops = standalone ? 512 : 16;
    volatile uint32_t sink = 0;
    double t0 = mono_sec();
    for (int i = 0; i < loops; i++)
        sink ^= event_log_crc32c_test_sw(buf, LEN);
    double t1 = mono_sec();
    for (int i = 0; i < loops; i++)
        sink ^= event_log_crc32c_test_active(buf, LEN);
    double t2 = mono_sec();
    double sw_sec = t1 - t0;
    double active_sec = t2 - t1;
    double bytes = (double)LEN * (double)loops;
    double sw_gbs = sw_sec > 0 ? bytes / sw_sec / 1e9 : 0.0;
    double active_gbs = active_sec > 0 ? bytes / active_sec / 1e9 : 0.0;
    printf("event_log: crc32c — impl=%s sw=%.2f GB/s active=%.2f GB/s "
           "(sink=%u)\n",
           event_log_crc32c_impl(), sw_gbs, active_gbs, (unsigned)sink);
    if (event_log_crc32c_hw_available()) {
#if defined(__aarch64__)
        const char *expected_impl = "hardware-armv8-crc32";
#else
        const char *expected_impl = "hardware-sse4.2";
#endif
        EL_CHECK("crc32c: hardware path selected after self-check",
                 strcmp(event_log_crc32c_impl(), expected_impl) == 0);
    } else {
        EL_CHECK("crc32c: software fallback selected",
                 strcmp(event_log_crc32c_impl(), "software-table") == 0);
    }

    free(buf);
    *failures_out += failures;
    return failures;
}

/* ── Append-path attribution: barrier vs deferred ──────────────────────
 * event_log_append_stats() splits appends by path; barrier time is charged
 * only to the barrier path. */
static int run_append_path_attribution(int *failures_out)
{
    int failures = 0;
    char dir[256];
    test_fmt_tmpdir(dir, sizeof(dir), "event_log", "attrib");
    el_mkdir_p(dir);
    char path[512];
    snprintf(path, sizeof(path), "%s/events.log", dir);

    event_log_test_set_force_per_append(0);
    event_log_test_reset_append_stats();

    uint64_t barrier = 0, deferred = 0, barrier_us = 0;
    event_log_append_stats(&barrier, &deferred, &barrier_us);
    EL_CHECK("attrib: reset zeroes all three counters",
             barrier == 0 && deferred == 0 && barrier_us == 0);

    event_log_t *log = event_log_open(path);
    EL_CHECK("attrib: open", log != NULL);
    if (!log) goto done;

    uint8_t buf[32];
    memset(buf, 0x44, sizeof(buf));

    /* Per-append mode (the at-tip / non-reducer default): each append takes
     * the two-barrier path and nothing lands on the deferred counter. */
    const int PER_APPEND = 3;
    for (int i = 0; i < PER_APPEND; i++)
        EL_CHECK("attrib: per-append append succeeds",
                 event_log_append(log, EV_BLOCK_HEADER, buf, sizeof(buf))
                     != UINT64_MAX);
    event_log_append_stats(&barrier, &deferred, &barrier_us);
    EL_CHECK("attrib: per-append appends counted as barrier appends",
             barrier == (uint64_t)PER_APPEND);
    EL_CHECK("attrib: per-append appends are not counted as deferred",
             deferred == 0);

    /* Deferred mode only copies into the pending buffer, so the barrier
     * counters must not move. */
    uint64_t barrier_at_switch = barrier;
    uint64_t barrier_us_at_switch = barrier_us;
    event_log_set_deferred_sync(log, true);
    const int DEFERRED = 5;
    for (int i = 0; i < DEFERRED; i++)
        EL_CHECK("attrib: deferred append succeeds",
                 event_log_append(log, EV_BLOCK_HEADER, buf, sizeof(buf))
                     != UINT64_MAX);
    event_log_append_stats(&barrier, &deferred, &barrier_us);
    EL_CHECK("attrib: deferred appends counted as deferred",
             deferred == (uint64_t)DEFERRED);
    EL_CHECK("attrib: deferred appends add no barrier appends",
             barrier == barrier_at_switch);
    EL_CHECK("attrib: deferred appends add no barrier time",
             barrier_us == barrier_us_at_switch);

    /* event_log_flush() is a different barrier with its own timer and must
     * not be charged here. */
    EL_CHECK("attrib: flush succeeds", event_log_flush(log));
    event_log_append_stats(&barrier, &deferred, &barrier_us);
    EL_CHECK("attrib: batched flush is not charged to the append counters",
             barrier == barrier_at_switch &&
             barrier_us == barrier_us_at_switch &&
             deferred == (uint64_t)DEFERRED);

    /* The kill switch pushes a deferred-flagged handle back onto the barrier
     * path — the A/B lever, so it must be visible in the attribution. */
    event_log_test_set_force_per_append(1);
    EL_CHECK("attrib: forced append succeeds",
             event_log_append(log, EV_BLOCK_HEADER, buf, sizeof(buf))
                 != UINT64_MAX);
    event_log_append_stats(&barrier, &deferred, &barrier_us);
    EL_CHECK("attrib: kill switch moves the append back to the barrier path",
             barrier == barrier_at_switch + 1 &&
             deferred == (uint64_t)DEFERRED);
    event_log_test_set_force_per_append(0);

    /* Every event is still readable: attribution must not have changed the
     * bytes on disk. */
    event_log_close(log);
    log = event_log_open(path);
    EL_CHECK("attrib: reopen after mixed-mode appends", log != NULL);
    if (log) {
        struct stream_ctx sc = {0};
        sc.ordered = true;
        event_log_stream(log, 0, stream_cb, &sc);
        EL_CHECK("attrib: every append is durable and streamable",
                 sc.count == PER_APPEND + DEFERRED + 1);
        event_log_close(log);
    }
    test_cleanup_tmpdir(dir);
done:
    event_log_test_set_force_per_append(-1);
    event_log_test_reset_append_stats();
    *failures_out += failures;
    return failures;
}

/* ── Deferred durability mode: batched fdatasync ───────────────────────
 * No per-append fsync in deferred mode; flush syncs once and clears dirty;
 * events are durable after flush + reopen; ZCL_EVENTLOG_SYNC_PER_APPEND
 * forces per-append sync; a flush failure returns false (commit veto). */
static int run_deferred_sync(int *failures_out)
{
    /* Local counter: EL_CHECK increments `failures`. */
    int failures = 0;
    char dir[256];
    test_fmt_tmpdir(dir, sizeof(dir), "event_log", "defer");
    el_mkdir_p(dir);
    char path[512];
    snprintf(path, sizeof(path), "%s/events.log", dir);

    /* Force the kill switch OFF so deferred mode is genuinely deferred. */
    event_log_test_set_force_per_append(0);

    event_log_t *log = event_log_open(path);
    EL_CHECK("defer: open", log != NULL);
    if (!log) goto done;

    /* Baseline: deferred off — an append must NOT leave the log dirty. */
    EL_CHECK("defer: default mode is not deferred",
             !event_log_deferred_sync_enabled(log));
    uint8_t buf[32];
    memset(buf, 0x11, sizeof(buf));
    event_log_append(log, EV_BLOCK_HEADER, buf, sizeof(buf));
    EL_CHECK("defer: per-append mode leaves nothing dirty",
             !event_log_test_dirty(log));

    /* Turn deferred mode on: N appends should NOT fsync (dirty accumulates),
     * and no flush happens implicitly. */
    event_log_set_deferred_sync(log, true);
    EL_CHECK("defer: enabled after set", event_log_deferred_sync_enabled(log));
    uint64_t visible_before = event_log_size(log);
    const int N = 20;
    for (int i = 0; i < N; i++) {
        memset(buf, (int)(0x20 + i), sizeof(buf));
        event_log_append(log, EV_BLOCK_HEADER, buf, sizeof(buf));
    }
    EL_CHECK("defer: appends left the log dirty (no per-append fsync)",
             event_log_test_dirty(log));
    EL_CHECK("defer: unflushed batch is not reader-visible",
             event_log_size(log) == visible_before);

    /* Flush: one fdatasync, dirty cleared. A second flush is a no-op true. */
    EL_CHECK("defer: flush succeeds", event_log_flush(log));
    EL_CHECK("defer: flush clears dirty", !event_log_test_dirty(log));
    EL_CHECK("defer: flush publishes the complete batch",
             event_log_size(log) > visible_before);
    EL_CHECK("defer: flush is idempotent when clean", event_log_flush(log));

    /* All 1 (baseline) + N events must survive a close + reopen. */
    uint64_t size_before = event_log_size(log);
    event_log_close(log);
    log = event_log_open(path);
    EL_CHECK("defer: reopen after flush", log != NULL);
    if (!log) goto done;
    EL_CHECK("defer: no tail truncation after flush",
             event_log_size(log) == size_before);
    /* A reopened handle starts in per-append mode (the flag is not
     * persisted); re-enable deferred mode for the checks below. */
    EL_CHECK("defer: reopened handle defaults to per-append",
             !event_log_deferred_sync_enabled(log));

    /* A nested reducer kick arms a late-wired handle rather than assuming
     * the outermost entry did. */
    event_log_set_singleton(NULL);
    reducer_enter_batched_body_sync();
    event_log_set_singleton(log);
    reducer_enter_batched_body_sync();
    unsigned scope_depth = 0;
    bool singleton_deferred = false;
    reducer_body_fsync_scope_snapshot(&scope_depth, &singleton_deferred);
    EL_CHECK("defer: nested entry arms singleton wired mid-scope",
             scope_depth == 2 && singleton_deferred);
    reducer_exit_batched_body_sync();
    reducer_body_fsync_scope_snapshot(&scope_depth, &singleton_deferred);
    EL_CHECK("defer: inner exit preserves outer deferred scope",
             scope_depth == 1 && singleton_deferred);
    reducer_exit_batched_body_sync();
    reducer_body_fsync_scope_snapshot(&scope_depth, &singleton_deferred);
    EL_CHECK("defer: outer exit flushes and disables late singleton",
             scope_depth == 0 && !singleton_deferred);
    event_log_set_singleton(NULL);

    struct stream_ctx sc = {0};
    sc.ordered = true;
    event_log_stream(log, 0, stream_cb, &sc);
    EL_CHECK("defer: all events durable after flush + reopen",
             sc.count == N + 1);

    /* Kill switch: force per-append sync ON — a deferred-flagged append must
     * still fsync inline and leave nothing dirty. */
    event_log_set_deferred_sync(log, true);
    event_log_test_set_force_per_append(1);
    EL_CHECK("defer: still flagged deferred (flag is orthogonal to switch)",
             event_log_deferred_sync_enabled(log));
    memset(buf, 0x7E, sizeof(buf));
    event_log_append(log, EV_BLOCK_HEADER, buf, sizeof(buf));
    EL_CHECK("defer: kill switch forces per-append sync (not dirty)",
             !event_log_test_dirty(log));
    event_log_test_set_force_per_append(0);

    /* Flush failure: a bad fd makes fdatasync fail; flush returns false and
     * KEEPS dirty (the pre-commit veto contract). */
    memset(buf, 0x33, sizeof(buf));
    event_log_append(log, EV_BLOCK_HEADER, buf, sizeof(buf));
    EL_CHECK("defer: append pending before fault", event_log_test_dirty(log));
    int real_fd = event_log_test_fd(log);
    event_log_test_set_fd(log, -1);
    EL_CHECK("defer: flush failure returns false (vetoes commit)",
             !event_log_flush(log));
    EL_CHECK("defer: dirty KEPT after failed flush (retryable)",
             event_log_test_dirty(log));
    event_log_test_set_fd(log, real_fd);
    EL_CHECK("defer: flush succeeds once fd restored", event_log_flush(log));
    EL_CHECK("defer: dirty cleared after successful retry",
             !event_log_test_dirty(log));

    event_log_close(log);
    test_cleanup_tmpdir(dir);
done:
    event_log_test_set_force_per_append(-1);   /* restore env-driven default */
    *failures_out += failures;
    return failures;
}

/* ── verified-prefix receipt ───────────────────────────────────────── */

#define RCPT_EVENTS 24

static void rc_sidecar(char *out, size_t cap, const char *path)
{
    snprintf(out, cap, "%s.verified", path);
}

static bool rc_exists(const char *p)
{
    struct stat st;
    return stat(p, &st) == 0;
}

/* Fresh log of RCPT_EVENTS events (payloads >= 8 bytes so offset 16 is always
 * payload), cleanly closed. *last_off is the start of the last event. */
static uint64_t rc_make_log(const char *path, uint64_t *last_off)
{
    unlink(path);
    char side[600];
    rc_sidecar(side, sizeof(side), path);
    unlink(side);
    event_log_t *log = event_log_open(path);
    if (!log) return 0;
    for (int i = 0; i < RCPT_EVENTS; i++) {
        uint8_t buf[200];
        size_t len = 8u + (size_t)i * 3u;
        memset(buf, 0x20 + i, sizeof(buf));
        uint64_t off = event_log_append(log, EV_BLOCK_HEADER, buf, len);
        if (last_off) *last_off = off;
    }
    uint64_t size = event_log_size(log);
    event_log_close(log);
    return size;
}

static bool rc_flip_byte(const char *path, uint64_t off)
{
    int fd = open(path, O_RDWR);
    if (fd < 0) return false;
    uint8_t b = 0;
    bool ok = pread(fd, &b, 1, (off_t)off) == 1;
    b ^= 0xFF;
    ok = ok && pwrite(fd, &b, 1, (off_t)off) == 1;
    fsync(fd);
    close(fd);
    return ok;
}

static bool rc_append_raw(const char *path, const void *data, size_t n)
{
    int fd = open(path, O_WRONLY | O_APPEND);
    if (fd < 0) return false;
    bool ok = write(fd, data, n) == (ssize_t)n;
    fsync(fd);
    close(fd);
    return ok;
}

/* Open, report (size, walked bytes, receipt used), close. */
struct rc_open_info { bool opened, used; uint64_t size, walked; };

static struct rc_open_info rc_reopen(const char *path)
{
    struct rc_open_info i = {0};
    event_log_t *log = event_log_open(path);
    if (!log) return i;
    i.opened = true;
    i.size = event_log_size(log);
    i.walked = event_log_test_last_open_walked_bytes();
    i.used = event_log_test_last_open_used_receipt();
    event_log_close(log);
    return i;
}

static bool rc_stream_count_is(const char *path, int want)
{
    event_log_t *log = event_log_open(path);
    if (!log) return false;
    struct stream_ctx sc = {0};
    sc.ordered = true;
    event_log_stream(log, 0, stream_cb, &sc);
    event_log_close(log);
    return sc.count == want;
}

/* Rewrite a sidecar field and (optionally) re-seal its checksum, so identity
 * and checksum rejection can be told apart. */
static bool rc_patch_sidecar(const char *side, size_t off, uint8_t delta,
                             bool reseal)
{
    uint8_t raw[96];
    FILE *f = fopen(side, "rb");
    if (!f) return false;
    bool ok = fread(raw, 1, sizeof(raw), f) == sizeof(raw);
    fclose(f);
    if (!ok) return false;
    raw[off] = (uint8_t)(raw[off] + delta);
    if (reseal) {
        struct sha3_256_ctx h;
        sha3_256_init(&h);
        sha3_256_write(&h, raw, 64);
        sha3_256_finalize(&h, raw + 64);
    }
    f = fopen(side, "wb");
    if (!f) return false;
    ok = fwrite(raw, 1, sizeof(raw), f) == sizeof(raw);
    fclose(f);
    return ok;
}

struct rc_ctx {
    char path[512];
    char side[600];
    char copy[600];
    char copy_side[700];
    int failures;
};

static void rc_copy_file(const char *src, const char *dst)
{
    FILE *in = fopen(src, "rb");
    FILE *out = fopen(dst, "wb");
    char buf[4096];
    size_t n;
    while (in && out && (n = fread(buf, 1, sizeof(buf), in)) > 0)
        fwrite(buf, 1, n, out);
    if (in) fclose(in);
    if (out) fclose(out);
}

static void rc_truncate_to(const char *path, uint64_t size)
{
    int fd = open(path, O_WRONLY);
    if (fd < 0) return;
    TEST_DISCARD(ftruncate(fd, (off_t)size));
    fsync(fd);
    close(fd);
}

static uint64_t rc_file_size(const char *path)
{
    struct stat st;
    return stat(path, &st) == 0 ? (uint64_t)st.st_size : 0;
}

/* Open the log, append `n` fixed events, close cleanly. */
static void rc_append_session(const char *path, int n, size_t len)
{
    event_log_t *l = event_log_open(path);
    uint8_t b[64];
    memset(b, 0x7A, sizeof(b));
    for (int i = 0; l && i < n; i++)
        event_log_append(l, EV_BLOCK_HEADER, b, len);
    if (l) event_log_close(l);
}

static bool rc_fell_back(struct rc_open_info oi, uint64_t walked)
{
    return oi.opened && !oi.used && oi.walked == walked;
}

/* 1. A clean close leaves a receipt; reopen takes the fast path. */
static void rc_case_fast_path(struct rc_ctx *c)
{
    int failures = 0;
    uint64_t size = rc_make_log(c->path, NULL);
    EL_CHECK("receipt: clean close writes the sidecar",
             size > 0 && rc_exists(c->side));
    struct rc_open_info oi = rc_reopen(c->path);
    EL_CHECK("receipt: reopen uses the receipt",
             oi.opened && oi.used && oi.size == size);
    EL_CHECK("receipt: fast path walks zero bytes", oi.walked == 0);
    EL_CHECK("receipt: stream still sees every event",
             rc_stream_count_is(c->path, RCPT_EVENTS));
    rc_append_session(c->path, 3, 16);
    oi = rc_reopen(c->path);
    EL_CHECK("receipt: receipt advances across sessions",
             oi.used && oi.walked == 0 && oi.size > size);
    EL_CHECK("receipt: count after second session",
             rc_stream_count_is(c->path, RCPT_EVENTS + 3));
    c->failures += failures;
}

/* 2. A torn tail past the receipt truncates exactly as the full walk does. */
static void rc_case_torn_tail(struct rc_ctx *c)
{
    int failures = 0;
    uint64_t s1_size = rc_make_log(c->path, NULL);
    uint8_t s1[96];
    FILE *f = fopen(c->side, "rb");
    bool got = f && fread(s1, 1, sizeof(s1), f) == sizeof(s1);
    if (f) fclose(f);
    EL_CHECK("receipt: captured sidecar for the stale-ahead case", got);
    rc_append_session(c->path, 2, 40);
    uint64_t s2_size = rc_file_size(c->path);
    /* Put the OLDER receipt back and tear the final event: the receipt is
     * valid (identity, size, last record) but trails the real tail. */
    f = fopen(c->side, "wb");
    if (f) { fwrite(s1, 1, sizeof(s1), f); fclose(f); }
    rc_truncate_to(c->path, s2_size - 5);
    rc_copy_file(c->path, c->copy);       /* reference: no receipt, full walk */
    unlink(c->copy_side);
    struct rc_open_info full = rc_reopen(c->copy);
    struct rc_open_info oi = rc_reopen(c->path);
    EL_CHECK("receipt: torn tail uses the receipt",
             oi.used && oi.walked > 0 && oi.walked < s2_size - s1_size);
    EL_CHECK("receipt: torn tail truncates exactly like the full walk",
             !full.used && oi.size == full.size &&
             oi.size > s1_size && oi.size < s2_size);
    EL_CHECK("receipt: torn tail keeps the whole events before it",
             rc_stream_count_is(c->path, RCPT_EVENTS + 1));
    c->failures += failures;
}

/* 3. A truncate removes the sidecar before it shrinks the file. */
static void rc_case_truncate_drops_sidecar(struct rc_ctx *c)
{
    int failures = 0;
    uint64_t size = rc_make_log(c->path, NULL);
    EL_CHECK("receipt: sidecar present before the tear", rc_exists(c->side));
    EL_CHECK("receipt: garbage tail appended",
             rc_append_raw(c->path, "\x05\x00\x00\x00torn", 8));
    event_log_t *l = event_log_open(c->path);
    EL_CHECK("receipt: truncating open succeeds",
             l && event_log_size(l) == size);
    EL_CHECK("receipt: truncate path removed the sidecar",
             !rc_exists(c->side));
    if (l) event_log_close(l);
    EL_CHECK("receipt: clean close recreates it", rc_exists(c->side));
    c->failures += failures;
}

/* 4a. A replaced file or a shorter file invalidates the receipt. */
static void rc_case_stale_file(struct rc_ctx *c)
{
    int failures = 0;
    uint64_t size = rc_make_log(c->path, NULL);
    TEST_DISCARD(rename(c->path, c->copy));     /* new inode, same bytes */
    rc_copy_file(c->copy, c->path);
    unlink(c->copy);
    struct rc_open_info oi = rc_reopen(c->path);
    EL_CHECK("receipt: replaced file rejects the receipt",
             rc_fell_back(oi, size) && oi.size == size);

    size = rc_make_log(c->path, NULL);
    rc_truncate_to(c->path, size - 3);
    oi = rc_reopen(c->path);
    EL_CHECK("receipt: file shorter than verified_end rejects the receipt",
             oi.opened && !oi.used && oi.size < size);
    c->failures += failures;
}

/* 4b. A damaged or mismatching sidecar is ignored. */
static void rc_case_bad_sidecar(struct rc_ctx *c)
{
    int failures = 0;
    uint64_t size = rc_make_log(c->path, NULL);
    EL_CHECK("receipt: identity patched (checksum resealed)",
             rc_patch_sidecar(c->side, 40, 1, true));
    EL_CHECK("receipt: identity mismatch rejects the receipt",
             rc_fell_back(rc_reopen(c->path), size));

    size = rc_make_log(c->path, NULL);
    EL_CHECK("receipt: checksum left stale",
             rc_patch_sidecar(c->side, 16, 1, false));
    struct rc_open_info oi = rc_reopen(c->path);
    EL_CHECK("receipt: bad sidecar checksum rejects the receipt",
             rc_fell_back(oi, size) && oi.size == size);

    size = rc_make_log(c->path, NULL);
    FILE *f = fopen(c->side, "wb");
    if (f) { fwrite("ZCLEVRCP", 1, 8, f); fclose(f); }
    EL_CHECK("receipt: short sidecar rejects the receipt",
             rc_fell_back(rc_reopen(c->path), size));
    c->failures += failures;
}

/* 4c. The one record the receipt re-verifies is corrupt. */
static void rc_case_corrupt_last_record(struct rc_ctx *c)
{
    int failures = 0;
    uint64_t last_off = 0;
    rc_make_log(c->path, &last_off);
    EL_CHECK("receipt: last verified record corrupted",
             rc_flip_byte(c->path, last_off + 16));
    struct rc_open_info oi = rc_reopen(c->path);
    EL_CHECK("receipt: corrupt last record rejects the receipt and truncates it",
             oi.opened && !oi.used && oi.size == last_off);
    c->failures += failures;
}

/* 5. The off-boot audit catches damage inside the vouched prefix. */
static void rc_case_audit(struct rc_ctx *c)
{
    int failures = 0;
    uint64_t size = rc_make_log(c->path, NULL);
    event_log_t *l = event_log_open(c->path);
    uint64_t audited = 0;
    EL_CHECK("receipt: audit of an intact prefix passes",
             l && event_log_audit_prefix(l, NULL, &audited) == 0 &&
             audited == size);
    if (l) event_log_close(l);

    EL_CHECK("receipt: flipped byte inside the prefix",
             rc_flip_byte(c->path, 16 + 2));    /* payload of event 0 */
    l = event_log_open(c->path);
    EL_CHECK("receipt: open still takes the fast path",
             l && event_log_test_last_open_used_receipt() &&
             event_log_size(l) == size);
    EL_CHECK("receipt: audit detects the flipped byte",
             l && event_log_audit_prefix(l, NULL, &audited) == -1);
    EL_CHECK("receipt: failed audit removed the sidecar", !rc_exists(c->side));
    if (l) event_log_close(l);
    EL_CHECK("receipt: close does not re-vouch for a damaged prefix",
             !rc_exists(c->side));
    struct rc_open_info oi = rc_reopen(c->path);
    EL_CHECK("receipt: next open does the full walk and truncates",
             oi.opened && !oi.used && oi.size == 0);
    c->failures += failures;
}

static int run_receipt(int *failures_out)
{
    char dir[256];
    test_fmt_tmpdir(dir, sizeof(dir), "event_log", "receipt");
    el_mkdir_p(dir);
    struct rc_ctx c = {0};
    snprintf(c.path, sizeof(c.path), "%s/events.log", dir);
    rc_sidecar(c.side, sizeof(c.side), c.path);
    snprintf(c.copy, sizeof(c.copy), "%s/copy.log", dir);
    rc_sidecar(c.copy_side, sizeof(c.copy_side), c.copy);

    rc_case_fast_path(&c);
    rc_case_torn_tail(&c);
    rc_case_truncate_drops_sidecar(&c);
    rc_case_stale_file(&c);
    rc_case_bad_sidecar(&c);
    rc_case_corrupt_last_record(&c);
    rc_case_audit(&c);

    test_cleanup_tmpdir(dir);
    *failures_out += c.failures;
    return c.failures;
}

static int test_event_log_platform_arm(void)
{
    printf("\n=== event_log tests ===\n");
    int failures = 0;
    el_ensure_root();

    run_append_read_roundtrip(&failures);
    run_stream(&failures);
    run_fingerprint(&failures);
    run_edge_cases(&failures);
    run_persistence(&failures);
    run_deferred_sync(&failures);
    run_append_path_attribution(&failures);
    run_targeted_recovery(&failures);
    run_receipt(&failures);
    run_crc32c_dispatch(&failures);

    printf("event_log: %d failures\n", failures);
    return failures;
}

static int test_event_log_kill9_platform_arm(void)
{
    int failures = 0;
    printf("\n=== event_log kill9 integration proof ===\n");
    run_kill9_fuzz(&failures);
    return failures;
}

static int test_event_log_benchmark_platform_arm(void)
{
    int failures = 0;
    printf("\n=== event_log benchmark integration proof ===\n");
    run_benchmark(&failures);
    return failures;
}
#else  /* _WIN32 */
/* Windows has no fork()/waitpid process model; this group's fork+SIGKILL event-log kill9-trial lane
 * cannot run here. Skipped loudly rather than faked. */
static int test_event_log_platform_arm(void)
{
    printf("event_log: SKIP (Windows): fork+SIGKILL event-log kill9-trial lane\n");
    return 0;
}

static int test_event_log_kill9_platform_arm(void)
{
    printf("event_log_kill9: SKIP (Windows): fork+SIGKILL event-log "
           "kill9-trial lane\n");
    return 0;
}

static int test_event_log_benchmark_platform_arm(void)
{
    printf("event_log_benchmark: SKIP (Windows): fork+SIGKILL event-log "
           "kill9-trial lane\n");
    return 0;
}
#endif

int test_event_log(void)
{
    return test_event_log_platform_arm();
}

int test_event_log_benchmark(void)
{
    return test_event_log_benchmark_platform_arm();
}

int test_event_log_kill9(void)
{
    return test_event_log_kill9_platform_arm();
}
