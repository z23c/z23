/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Unit tests for the mailbox primitive (platform/modules/util/src/mailbox.c).
 *
 * Coverage:
 *   - create/destroy: input validation, capacity & msg_size accessors
 *   - SPSC: 1000 sends → 1000 recvs, deterministic order preserved
 *   - overflow: try_send returns false at capacity; drop_count
 *     increments
 *   - close: try_send returns false post-close; drain still works
 *   - MPSC: 4 producer threads × 256 messages, single consumer drains
 *     all 1024 with no loss */

#include "test/test_core.h"
#include "util/mailbox.h"

#include <pthread.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#define MBX_CHECK(name, expr) do { \
    printf("mailbox: %s... ", (name)); \
    if ((expr)) printf("OK\n"); \
    else { printf("FAIL\n"); failures++; } \
} while (0)

struct producer_args {
    mailbox_t    *m;
    int           tid;
    int           count;
    _Atomic bool *abort_flag;  /* consumer gave up — stop, don't wedge */
    _Atomic int   sent;        /* what this producer actually got in */
};

static void *producer_thread(void *arg)
{
    struct producer_args *a = arg;
    /* Encode (tid, seq) in a uint64 so the consumer can verify no loss. */
    for (int i = 0; i < a->count; i++) {
        uint64_t msg = ((uint64_t)a->tid << 32) | (uint64_t)i;
        /* Spin-retry on overflow so the test never silently drops — but honour
         * the consumer's abort flag. The ring holds 64 and the producers offer
         * 1024, so a consumer that stops draining leaves every producer parked
         * in this loop forever; without the flag the pthread_join below would
         * never return and the whole GROUP would hang until the runner's
         * per-group timeout SIGKILLed it. A wedge must fail an assertion and
         * say why, not stop the clock. */
        while (!mailbox_try_send(a->m, &msg)) {
            if (atomic_load(a->abort_flag)) return NULL;
            sched_yield();
        }
        atomic_fetch_add(&a->sent, 1);
    }
    return NULL;
}

/* Monotonic milliseconds — bounds how long the consumer is willing to wait for
 * producers. Never asserted on. */
static long mbx_now_ms(void)
{
    struct timespec ts;
    if (clock_gettime(CLOCK_MONOTONIC, &ts) != 0) return 0;  // platform-ok:test-wedge-deadline-bounds-a-wait-never-an-assertion
    return (long)ts.tv_sec * 1000L + ts.tv_nsec / 1000000L;
}

/* Widen the consumer's patience on a knowingly-loaded runner without changing
 * what is being waited for. Same knob test_wallet_backup.c uses. */
static long mbx_timeout_scale(void)
{
    const char *env = getenv("ZCL_TEST_TIMEOUT_SCALE");
    long v = env ? strtol(env, NULL, 10) : 1;
    return (v >= 1 && v <= 100) ? v : 1;
}

int test_mailbox(void)
{
    printf("\n=== mailbox tests ===\n");
    int failures = 0;

    /* ── create / destroy / validation ──────────────────────────── */
    {
        mailbox_t *m = mailbox_create(16, sizeof(int));
        MBX_CHECK("create OK", m != NULL);
        MBX_CHECK("capacity matches", mailbox_capacity(m) == 16);
        MBX_CHECK("depth starts 0", mailbox_depth(m) == 0);
        MBX_CHECK("not closed at create", !mailbox_is_closed(m));
        mailbox_destroy(m);

        MBX_CHECK("zero capacity → NULL",
                  mailbox_create(0, sizeof(int)) == NULL);
        MBX_CHECK("zero msg_size → NULL",
                  mailbox_create(16, 0) == NULL);
        mailbox_destroy(NULL);  /* must not crash */
    }

    /* ── SPSC: 1000 messages preserve FIFO order ────────────────── */
    {
        mailbox_t *m = mailbox_create(1000, sizeof(int));
        for (int i = 0; i < 1000; i++) {
            int v = i;
            if (!mailbox_try_send(m, &v)) {
                printf("send %d failed\n", i);
                failures++;
                break;
            }
        }
        MBX_CHECK("depth=1000 after 1000 sends",
                  mailbox_depth(m) == 1000);
        MBX_CHECK("sent_count=1000",
                  mailbox_sent_count(m) == 1000);

        int got;
        bool fifo_ok = true;
        for (int i = 0; i < 1000; i++) {
            if (!mailbox_try_recv(m, &got) || got != i) {
                fifo_ok = false;
                break;
            }
        }
        MBX_CHECK("FIFO order preserved", fifo_ok);
        MBX_CHECK("depth=0 after drain", mailbox_depth(m) == 0);
        MBX_CHECK("recv on empty returns false",
                  !mailbox_try_recv(m, &got));
        MBX_CHECK("recv_count=1000",
                  mailbox_recv_count(m) == 1000);
        mailbox_destroy(m);
    }

    /* ── overflow: ring full ─────────────────────────────────── */
    {
        mailbox_t *m = mailbox_create(4, sizeof(int));
        int v = 0;
        for (int i = 0; i < 4; i++) {
            v = i;
            MBX_CHECK("fill OK", mailbox_try_send(m, &v));
        }
        v = 99;
        MBX_CHECK("5th send returns false",
                  !mailbox_try_send(m, &v));
        MBX_CHECK("drop_count=1", mailbox_drop_count(m) == 1);
        MBX_CHECK("depth still capacity",
                  mailbox_depth(m) == mailbox_capacity(m));

        /* Drain one, send one — should succeed. */
        int got;
        mailbox_try_recv(m, &got);
        v = 100;
        MBX_CHECK("send after drain OK",
                  mailbox_try_send(m, &v));
        mailbox_destroy(m);
    }

    /* ── close: send fails, drain still works ────────────────── */
    {
        mailbox_t *m = mailbox_create(8, sizeof(int));
        int v = 42;
        mailbox_try_send(m, &v);
        mailbox_try_send(m, &v);
        MBX_CHECK("close transitions", mailbox_close(m));
        MBX_CHECK("close idempotent (returns false 2nd)",
                  !mailbox_close(m));
        MBX_CHECK("is_closed reflects state",
                  mailbox_is_closed(m));
        MBX_CHECK("send-after-close returns false",
                  !mailbox_try_send(m, &v));
        int got = 0;
        MBX_CHECK("recv-after-close drains 1",
                  mailbox_try_recv(m, &got) && got == 42);
        MBX_CHECK("recv-after-close drains 2",
                  mailbox_try_recv(m, &got) && got == 42);
        MBX_CHECK("recv after drained empty",
                  !mailbox_try_recv(m, &got));
        mailbox_destroy(m);
    }

    /* ── Single-threaded MPSC shape: same accounting, no scheduler ─────
     * The 4-producer case below can only ever prove the counters agree once
     * the producers are joined. This case proves the SAME accounting with the
     * threads removed entirely, so if the concurrent case ever degenerates
     * (producers aborted, ring never filled) the group still has a case that
     * genuinely exercises interleaved send/recv across a wrapping ring. */
    {
        const int N_PROD = 4;
        const int PER    = 256;
        const int target = N_PROD * PER;
        mailbox_t *m = mailbox_create(64, sizeof(uint64_t));

        int seen[4][256] = {{0}};
        int drained = 0;
        int next[4] = {0, 0, 0, 0};
        int done_prod = 0;
        /* Round-robin the four "producers" by hand, draining whenever the ring
         * fills — the exact wrap-around/interleave pattern the threaded case
         * hits, made deterministic. */
        while (done_prod < N_PROD || mailbox_depth(m) > 0) {
            /* Fill the ring to capacity before draining, so this case really
             * does wrap it (16 times over) rather than tiptoeing along an
             * always-near-empty buffer. */
            bool progressed = true;
            while (progressed) {
                progressed = false;
                for (int t = 0; t < N_PROD; t++) {
                    if (next[t] >= PER) continue;
                    uint64_t msg = ((uint64_t)t << 32) | (uint64_t)next[t];
                    if (mailbox_try_send(m, &msg)) {
                        progressed = true;
                        if (++next[t] == PER) done_prod++;
                    }
                }
            }
            uint64_t got;
            while (mailbox_try_recv(m, &got)) {
                int tid = (int)(got >> 32);
                int seq = (int)(got & 0xffffffffu);
                if (tid >= 0 && tid < N_PROD && seq >= 0 && seq < PER)
                    seen[tid][seq]++;
                drained++;
            }
        }

        MBX_CHECK("MPSC (single-threaded) drained every message",
                  drained == target);
        bool no_dup_no_miss = true;
        for (int t = 0; t < N_PROD && no_dup_no_miss; t++)
            for (int s = 0; s < PER; s++)
                if (seen[t][s] != 1) { no_dup_no_miss = false; break; }
        MBX_CHECK("MPSC (single-threaded) no duplicates / no misses",
                  no_dup_no_miss);
        MBX_CHECK("MPSC (single-threaded) sent_count=target",
                  mailbox_sent_count(m) == (size_t)target);
        MBX_CHECK("MPSC (single-threaded) recv_count=target",
                  mailbox_recv_count(m) == (size_t)target);
        mailbox_destroy(m);
    }

    /* ── MPSC: 4 producers × 256 = 1024 messages, no loss ──────
     * Every assertion here is made AFTER the producers are joined and the ring
     * is drained, so none of them depends on which thread won any particular
     * race — only on the totals, which are forced once the producers have
     * finished. The consumer loop below is bounded by real elapsed time (not a
     * spin count) and tells the producers to give up when it expires, so a
     * genuine wedge fails an assertion instead of hanging the suite. */
    {
        const int N_PROD = 4;
        const int PER    = 256;
        mailbox_t *m = mailbox_create(64, sizeof(uint64_t));

        _Atomic bool abort_flag = false;
        pthread_t threads[4];
        struct producer_args args[4];
        int started = 0;
        for (int i = 0; i < N_PROD; i++) {
            args[i].m = m;
            args[i].tid = i;
            args[i].count = PER;
            args[i].abort_flag = &abort_flag;
            atomic_store(&args[i].sent, 0);
            if (pthread_create(&threads[i], NULL, producer_thread,
                               &args[i]) == 0)
                started++;
        }
        MBX_CHECK("MPSC all producers started", started == N_PROD);

        /* Consumer drains 1024 messages, tracking what's seen. */
        int seen[4][256] = {{0}};
        int drained = 0;
        const int target = N_PROD * PER;

        /* 30s baseline. Draining 1024 messages takes microseconds; this is a
         * wedge detector, not a schedule the producers have to keep. */
        const long deadline = mbx_now_ms() + 30000L * mbx_timeout_scale();
        bool timed_out = false;
        while (drained < target) {
            uint64_t msg;
            if (mailbox_try_recv(m, &msg)) {
                int tid = (int)(msg >> 32);
                int seq = (int)(msg & 0xffffffffu);
                if (tid >= 0 && tid < N_PROD && seq >= 0 && seq < PER) {
                    seen[tid][seq]++;
                }
                drained++;
            } else {
                if (mbx_now_ms() > deadline) { timed_out = true; break; }
                sched_yield();
            }
        }
        MBX_CHECK("MPSC consumer drained without hitting the wedge deadline",
                  !timed_out);

        atomic_store(&abort_flag, true);  /* releases any parked producer */
        for (int i = 0; i < started; i++) pthread_join(threads[i], NULL);

        /* Drain any stragglers post-join. */
        uint64_t leftover;
        while (mailbox_try_recv(m, &leftover)) {
            int tid = (int)(leftover >> 32);
            int seq = (int)(leftover & 0xffffffffu);
            if (tid >= 0 && tid < N_PROD && seq >= 0 && seq < PER) {
                seen[tid][seq]++;
            }
            drained++;
        }

        /* Post-join: every producer has returned, so these totals are fixed
         * and no longer depend on the scheduler. */
        int offered = 0;
        for (int i = 0; i < started; i++) offered += atomic_load(&args[i].sent);
        MBX_CHECK("MPSC every producer offered its full run", offered == target);
        MBX_CHECK("MPSC drained 1024", drained == target);
        bool no_dup_no_miss = true;
        for (int t = 0; t < N_PROD; t++) {
            for (int s = 0; s < PER; s++) {
                if (seen[t][s] != 1) { no_dup_no_miss = false; break; }
            }
            if (!no_dup_no_miss) break;
        }
        MBX_CHECK("MPSC no duplicates / no misses", no_dup_no_miss);
        MBX_CHECK("MPSC sent_count=target",
                  mailbox_sent_count(m) == (size_t)target);
        MBX_CHECK("MPSC recv_count=target",
                  mailbox_recv_count(m) == (size_t)target);
        mailbox_destroy(m);
    }

    if (failures == 0) {
        printf("=== mailbox tests: ALL PASS ===\n\n");
    } else {
        printf("=== mailbox tests: %d FAILURE(S) ===\n\n", failures);
    }
    return failures;
}
