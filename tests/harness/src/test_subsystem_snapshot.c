/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * test_subsystem_snapshot — the seqlock publish envelope (util/subsystem_snapshot.h).
 * Proves the two contract properties the diagnostic snapshot plane relies on:
 *
 *   1. Multi-field coherence: a reader bracket that completes (read_ok == true)
 *      NEVER observes a torn multi-field snapshot; when it cannot get a coherent
 *      read it falls back to the LAST published (still-coherent) values labeled
 *      stale — never an empty body.
 *   2. The uniform staleness label reports {stale, age_us, last_publish_height,
 *      generation, warning_reason} correctly for never-published, fresh, and
 *      torn reads.
 *
 * Assertion discipline — read this before adding a check here. Which SIDE of
 * the race wins is a scheduler decision and this group runs under a 32-worker
 * suite, so no assertion may depend on it. Two measured failure modes come from
 * ignoring that:
 *
 *   - The writer thread was never scheduled during the racing reads, so every
 *     read was uncontended (writes=0, torn=0). The coherence assertions passed
 *     over a reader with no competition at all: the group reported success while
 *     proving nothing.
 *   - The writer was scheduled and hammered without pause. A reader bracket
 *     retries at most ZCL_SNAPSHOT_READ_MAX_RETRIES (8) times, which is not
 *     enough to beat an uninterrupted publisher — or to outlast a writer
 *     preempted mid-publish, which parks the seq odd for a whole timeslice — so
 *     every read fell back (coherent=0, torn=200000) and a "some reads
 *     completed" assertion failed.
 *
 * So: the racing phase asserts SAFETY only (nothing a completed read observes is
 * ever inconsistent), which holds no matter who wins or whether either side runs
 * at all. Everything that needs a definite outcome is asserted where the outcome
 * is forced — against a writer that has acknowledged it is idle, or after the
 * writer thread is joined. The torn window itself is exercised deterministically
 * on one thread in case_torn_window_deterministic, so the group cannot go
 * vacuous when the scheduler declines to interleave.
 */

#include "test/test_core.h"

#include "json/json.h"
#include "platform/time_compat.h"
#include "util/subsystem_snapshot.h"

#include <pthread.h>
#include <sched.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#define SS_CHECK(name, expr) do {                     \
    printf("subsystem_snapshot: %s... ", (name));     \
    if (expr) { printf("OK\n"); }                     \
    else { printf("FAIL\n"); failures++; }            \
} while (0)

/* Hang guard for the two handshakes below. It is NOT a tuned delay: the waits
 * need microseconds of scheduler fairness, and this bound is four orders of
 * magnitude past that. It exists so a wedged writer thread FAILS this group
 * instead of hanging the whole suite. */
#define SS_HANDSHAKE_GUARD_US (30 * 1000 * 1000)

/* A two-field payload the writer keeps EQUAL (a == b) at all times; a coherent
 * read must therefore always see a == b. A torn read (writer mid-publish) would
 * see a != b — which the seqlock bracket must reject. */
struct hammer_payload {
    struct zcl_snapshot_env env;
    _Atomic int64_t a;
    _Atomic int64_t b;
};

/* Writer duty cycle. RUN publishes continuously; QUIESCE stops publishing and
 * acknowledges, which is what lets the main thread assert a definite outcome
 * against a writer that is provably not in flight. The mode only ever moves
 * RUN -> QUIESCE, so once the acknowledgement is visible no further publish can
 * start. */
enum hammer_mode { HAMMER_RUN = 0, HAMMER_QUIESCE = 1 };

struct hammer_ctl {
    struct hammer_payload *p;
    _Atomic int stop;
    _Atomic int mode;
    _Atomic int quiesced;        /* writer is outside a window and will not open one */
    _Atomic uint64_t writes;
};

static void *hammer_writer(void *arg)
{
    struct hammer_ctl *c = arg;
    int64_t v = 0;
    while (!atomic_load_explicit(&c->stop, memory_order_acquire)) {
        if (atomic_load_explicit(&c->mode, memory_order_acquire) ==
            HAMMER_QUIESCE) {
            /* Publish window is closed here, and the mode never returns to RUN,
             * so it stays closed. Announce that and idle. */
            atomic_store_explicit(&c->quiesced, 1, memory_order_release);
            sched_yield();
            continue;
        }
        v++;
        zcl_snapshot_publish_begin(&c->p->env);
        atomic_store_explicit(&c->p->a, v, memory_order_relaxed);
        /* A deliberate gap between the two field stores widens the torn window
         * a naive (non-seqlock) reader would fall into. */
        for (volatile int spin = 0; spin < 8; spin++) { }
        atomic_store_explicit(&c->p->b, v, memory_order_relaxed);
        zcl_snapshot_publish_end(&c->p->env, v);
        atomic_fetch_add_explicit(&c->writes, 1, memory_order_relaxed);
        /* Gap BETWEEN publishes. Without it the reader's 8-retry bracket can
         * never win and a scheduled writer drives the racing phase to 100%
         * fallback, which exercises only one of the two outcomes. This is a
         * bounded spin rather than a sleep, and no assertion depends on its
         * length — it only shifts how often each outcome is observed. */
        for (volatile int spin = 0; spin < 512; spin++) { }
    }
    return NULL;
}

/* One reader bracket (<= ZCL_SNAPSHOT_READ_MAX_RETRIES). On success the out
 * params hold a coherent pair; on failure they hold the last-attempt (possibly
 * torn) values and the caller must fall back to last-known. True iff coherent. */
static bool read_pair(struct hammer_payload *p, int64_t *a, int64_t *b)
{
    for (int i = 0; i < ZCL_SNAPSHOT_READ_MAX_RETRIES; i++) {
        uint64_t seq;
        if (!zcl_snapshot_read_try(&p->env, &seq))
            continue;  /* writer active — retry */
        *a = atomic_load_explicit(&p->a, memory_order_relaxed);
        *b = atomic_load_explicit(&p->b, memory_order_relaxed);
        if (zcl_snapshot_read_ok(&p->env, seq))
            return true;
    }
    return false;
}

/* Wait for a counter the writer thread must eventually bump. Yields rather than
 * busy-spinning so it makes progress on a fully subscribed box. */
static bool wait_until_u64_at_least(const _Atomic uint64_t *v, uint64_t least)
{
    int64_t deadline = platform_time_monotonic_us() + SS_HANDSHAKE_GUARD_US;
    for (;;) {
        if (atomic_load_explicit(v, memory_order_acquire) >= least)
            return true;
        if (platform_time_monotonic_us() >= deadline)
            return false;
        sched_yield();
    }
}

static bool wait_until_int_eq(const _Atomic int *v, int want)
{
    int64_t deadline = platform_time_monotonic_us() + SS_HANDSHAKE_GUARD_US;
    for (;;) {
        if (atomic_load_explicit(v, memory_order_acquire) == want)
            return true;
        if (platform_time_monotonic_us() >= deadline)
            return false;
        sched_yield();
    }
}

/* The torn window, made deterministic. One thread opens a publish window and
 * writes only the FIRST of the two fields, so the payload is genuinely
 * inconsistent at a point we choose. This case proves the bracket rejects that
 * state without involving the scheduler at all — it is the part of the group
 * that cannot go vacuous, and it is what fails if the seqlock is broken. */
static int case_torn_window_deterministic(void)
{
    int failures = 0;
    struct hammer_payload p;
    memset(&p, 0, sizeof(p));
    struct zcl_snapshot_env init = ZCL_SNAPSHOT_ENV_INIT;
    p.env = init;

    zcl_snapshot_publish_begin(&p.env);
    atomic_store_explicit(&p.a, 1, memory_order_relaxed);
    atomic_store_explicit(&p.b, 1, memory_order_relaxed);
    zcl_snapshot_publish_end(&p.env, 1);

    int64_t a = -1, b = -2;
    SS_CHECK("torn-window: a read outside any publish window completes",
             read_pair(&p, &a, &b) && a == 1 && b == 1);

    /* Open a window and update only field a: the pair is now inconsistent. */
    zcl_snapshot_publish_begin(&p.env);
    atomic_store_explicit(&p.a, 2, memory_order_relaxed);

    SS_CHECK("torn-window: the payload really is inconsistent here (a != b)",
             atomic_load_explicit(&p.a, memory_order_relaxed) !=
             atomic_load_explicit(&p.b, memory_order_relaxed));

    int64_t ta = -1, tb = -2;
    SS_CHECK("torn-window: the bracket REFUSES to complete a read",
             !read_pair(&p, &ta, &tb));

    uint64_t torn_before =
        atomic_load_explicit(&p.env.torn_reads_total, memory_order_relaxed);
    zcl_snapshot_note_torn(&p.env);
    SS_CHECK("torn-window: the fallback is accounted",
             atomic_load_explicit(&p.env.torn_reads_total,
                                  memory_order_relaxed) == torn_before + 1);
    /* The whole point of the fallback: last-known values are still there to
     * serve, labeled stale, rather than an empty body. */
    SS_CHECK("torn-window: last-known values survive the window (never empty)",
             atomic_load_explicit(&p.env.generation, memory_order_relaxed) > 0 &&
             atomic_load_explicit(&p.env.last_height, memory_order_relaxed) == 1);

    atomic_store_explicit(&p.b, 2, memory_order_relaxed);
    zcl_snapshot_publish_end(&p.env, 2);

    a = -1; b = -2;
    SS_CHECK("torn-window: once the window closes the read completes with the new pair",
             read_pair(&p, &a, &b) && a == 2 && b == 2);

    return failures;
}

#define SS_RACING_READS 200000
#define SS_QUIET_READS  1000
/* How many writer publishes must land DURING the racing reads for the racing
 * phase to count as having raced anything. Small on purpose: this is a
 * "did the other thread run at all" floor, not a throughput target. */
#define SS_MIN_RACING_WRITES 64

static int case_concurrent_coherence(void)
{
    int failures = 0;
    struct hammer_payload p;
    memset(&p, 0, sizeof(p));
    struct zcl_snapshot_env init = ZCL_SNAPSHOT_ENV_INIT;
    p.env = init;

    /* Seed one coherent publish so the fallback always has last-known values. */
    zcl_snapshot_publish_begin(&p.env);
    atomic_store_explicit(&p.a, 0, memory_order_relaxed);
    atomic_store_explicit(&p.b, 0, memory_order_relaxed);
    zcl_snapshot_publish_end(&p.env, 0);

    struct hammer_ctl ctl = { .p = &p };
    atomic_store(&ctl.stop, 0);
    atomic_store(&ctl.mode, HAMMER_RUN);
    atomic_store(&ctl.quiesced, 0);
    atomic_store(&ctl.writes, 0);

    pthread_t th;
    int rc = pthread_create(&th, NULL, hammer_writer, &ctl);
    SS_CHECK("concurrent: writer thread starts", rc == 0);
    if (rc != 0)
        return failures;

    /* ── Phase 1: race ─────────────────────────────────────────────────────
     * Wait for one completed publish first, so the reads below race a writer
     * that has demonstrably run — otherwise a run where the writer never got
     * scheduled would assert coherence over an uncontended reader and call that
     * a pass. Nothing here asserts WHICH side wins. */
    bool writer_ran = wait_until_u64_at_least(&ctl.writes, 1);
    SS_CHECK("concurrent: writer published before the racing reads begin",
             writer_ran);
    uint64_t writes_before_race =
        atomic_load_explicit(&ctl.writes, memory_order_acquire);

    int64_t coherent_reads = 0, torn_fallbacks = 0;
    int64_t last_a = 0, last_b = 0;  /* last-known-good fallback */
    /* This is also the weak-memory regression: without read_ok's trailing
     * acquire fence, ARM64 may validate seq first and observe these relaxed
     * payload loads afterwards, accepting a pair from two generations. */
    bool ever_incoherent = false;    /* a completed read that saw a != b */
    bool fallback_ever_incoherent = false;
    bool fallback_ever_empty = false; /* fallback with nothing published to serve */

    for (int i = 0; i < SS_RACING_READS; i++) {
        int64_t a = -1, b = -2;
        if (read_pair(&p, &a, &b)) {
            coherent_reads++;
            if (a != b)
                ever_incoherent = true;   /* MUST never happen */
            last_a = a;
            last_b = b;                   /* update last-known-good */
        } else {
            torn_fallbacks++;
            zcl_snapshot_note_torn(&p.env);
            /* Fallback path: serve last-known-good — which is always coherent,
             * and always present (generation > 0 means there is something to
             * serve, so the dumper never emits an empty body). */
            if (last_a != last_b)
                fallback_ever_incoherent = true;
            if (atomic_load_explicit(&p.env.generation,
                                     memory_order_relaxed) == 0)
                fallback_ever_empty = true;
        }
    }

    /* Coverage, established by CONSTRUCTION rather than hoped for.
     *
     * Waiting for one publish before the loop proves the writer had run at
     * some point; it does not prove the writer ran DURING the 200k reads. On a
     * saturated box the writer can sit off-CPU for that whole window, in which
     * case every assertion above is being made about an UNCONTENDED reader and
     * passes without exercising the seqlock at all — the failure mode this
     * group was found in previously. So: keep reading until the writer has
     * demonstrably raced us, bounded by the same guard the other handshakes
     * use. If the writer never advances, that is a real problem and it fails
     * here with a name instead of passing vacuously. */
    {
        int64_t guard = platform_time_monotonic_us() + SS_HANDSHAKE_GUARD_US;
        while (atomic_load_explicit(&ctl.writes, memory_order_acquire) <
                   writes_before_race + SS_MIN_RACING_WRITES &&
               platform_time_monotonic_us() < guard) {
            int64_t a = -1, b = -2;
            if (read_pair(&p, &a, &b)) {
                coherent_reads++;
                if (a != b) ever_incoherent = true;
                last_a = a; last_b = b;
            } else {
                torn_fallbacks++;
                zcl_snapshot_note_torn(&p.env);
                if (last_a != last_b) fallback_ever_incoherent = true;
                if (atomic_load_explicit(&p.env.generation,
                                         memory_order_relaxed) == 0)
                    fallback_ever_empty = true;
            }
        }
    }
    uint64_t raced_writes =
        atomic_load_explicit(&ctl.writes, memory_order_acquire) -
        writes_before_race;
    SS_CHECK("racing: the writer published concurrently with the reads "
             "(the racing phase actually raced)",
             raced_writes >= SS_MIN_RACING_WRITES);

    SS_CHECK("racing: NO completed read ever saw a torn (a!=b) pair",
             !ever_incoherent);
    SS_CHECK("racing: the fallback value is always coherent",
             !fallback_ever_incoherent);
    SS_CHECK("racing: the fallback always has published values to serve",
             !fallback_ever_empty);
    SS_CHECK("racing: torn_reads_total accounts every fallback",
             atomic_load_explicit(&p.env.torn_reads_total,
                                  memory_order_relaxed) ==
             (uint64_t)torn_fallbacks);

    /* ── Phase 2: writer parked ────────────────────────────────────────────
     * Ask the writer to stop publishing and wait for its acknowledgement. After
     * that no publish window can open, so "a reader completes" is forced, not
     * hoped for. This is where the coverage assertion belongs. */
    atomic_store_explicit(&ctl.mode, HAMMER_QUIESCE, memory_order_release);
    bool quiesced = wait_until_int_eq(&ctl.quiesced, 1);
    SS_CHECK("parked: writer acknowledges it stopped publishing", quiesced);

    if (quiesced) {
        uint64_t torn_before =
            atomic_load_explicit(&p.env.torn_reads_total, memory_order_relaxed);
        uint64_t writes_at_park =
            atomic_load_explicit(&ctl.writes, memory_order_acquire);
        int64_t quiet_coherent = 0;
        bool quiet_wrong_value = false;
        for (int i = 0; i < SS_QUIET_READS; i++) {
            int64_t a = -1, b = -2;
            if (read_pair(&p, &a, &b)) {
                quiet_coherent++;
                /* The writer's counter starts at 0 and pre-increments, so after
                 * N publishes the pair is exactly (N, N). */
                if (a != b || a != (int64_t)writes_at_park)
                    quiet_wrong_value = true;
            }
        }
        SS_CHECK("parked: every read completes (no writer in flight)",
                 quiet_coherent == SS_QUIET_READS);
        SS_CHECK("parked: every read returns the last published pair",
                 !quiet_wrong_value);
        SS_CHECK("parked: no read fell back",
                 atomic_load_explicit(&p.env.torn_reads_total,
                                      memory_order_relaxed) == torn_before);
        SS_CHECK("parked: last_publish_height is the last value published",
                 atomic_load_explicit(&p.env.last_height,
                                      memory_order_relaxed) ==
                 (int64_t)writes_at_park);
        SS_CHECK("parked: generation counts the seed publish plus every write",
                 atomic_load_explicit(&p.env.generation, memory_order_relaxed) ==
                 writes_at_park + 1);
    }

    atomic_store_explicit(&ctl.stop, 1, memory_order_release);
    pthread_join(th, NULL);

    /* ── Phase 3: writer joined ────────────────────────────────────────────*/
    uint64_t writes = atomic_load_explicit(&ctl.writes, memory_order_relaxed);
    SS_CHECK("joined: the writer actually published", writes > 0);
    int64_t a = -1, b = -2;
    SS_CHECK("joined: a read completes and returns the final pair",
             read_pair(&p, &a, &b) && a == b && a == (int64_t)writes);

    printf("subsystem_snapshot: racing stats completed=%lld fell_back=%lld writes=%llu\n",
           (long long)coherent_reads, (long long)torn_fallbacks,
           (unsigned long long)writes);
    return failures;
}

/* Deterministic torn detection: leaving the env mid-publish (begin without end)
 * makes read_try report the writer is active; read_ok on a stale even seq is
 * false. */
static int case_deterministic_bracket(void)
{
    int failures = 0;
    struct zcl_snapshot_env env = ZCL_SNAPSHOT_ENV_INIT;
    uint64_t seq = 0;

    SS_CHECK("bracket: fresh env read_try succeeds (even seq)",
             zcl_snapshot_read_try(&env, &seq) && (seq & 1U) == 0);

    zcl_snapshot_publish_begin(&env);
    SS_CHECK("bracket: mid-publish read_try fails (odd seq)",
             !zcl_snapshot_read_try(&env, &seq));
    zcl_snapshot_publish_end(&env, 123);

    SS_CHECK("bracket: after publish read_try succeeds",
             zcl_snapshot_read_try(&env, &seq));
    SS_CHECK("bracket: read_ok true when no writer intervened",
             zcl_snapshot_read_ok(&env, seq));

    /* A publish between read_try and read_ok invalidates the sample. */
    uint64_t seq2 = 0;
    SS_CHECK("bracket: read_try before an intervening publish",
             zcl_snapshot_read_try(&env, &seq2));
    zcl_snapshot_publish_begin(&env);
    zcl_snapshot_publish_end(&env, 456);
    SS_CHECK("bracket: read_ok false after an intervening publish",
             !zcl_snapshot_read_ok(&env, seq2));

    return failures;
}

static const char *label_reason(const struct json_value *label)
{
    const struct json_value *wr = json_get(label, "warning_reason");
    return wr ? json_get_str(wr) : NULL;
}

static int case_label(void)
{
    int failures = 0;
    int64_t now = platform_time_monotonic_us();

    /* Never published: stale, warning_reason never_published, age -1, gen 0. */
    struct zcl_snapshot_env env = ZCL_SNAPSHOT_ENV_INIT;
    struct json_value label;
    json_init(&label);
    json_set_object(&label);
    zcl_snapshot_emit_label(&label, &env, /*torn=*/false, now);
    SS_CHECK("label(never): stale true",
             json_get_bool(json_get(&label, "stale")));
    SS_CHECK("label(never): generation 0",
             json_get_int(json_get(&label, "generation")) == 0);
    SS_CHECK("label(never): age_us -1",
             json_get_int(json_get(&label, "age_us")) == -1);
    { const char *r = label_reason(&label);
      SS_CHECK("label(never): warning_reason never_published",
               r && strcmp(r, "never_published") == 0); }
    json_free(&label);

    /* Fresh publish: not stale, ok, generation 1, last_publish_height records. */
    zcl_snapshot_publish_begin(&env);
    zcl_snapshot_publish_end(&env, 987654);
    json_init(&label);
    json_set_object(&label);
    zcl_snapshot_emit_label(&label, &env, /*torn=*/false,
                            platform_time_monotonic_us());
    SS_CHECK("label(fresh): stale false",
             !json_get_bool(json_get(&label, "stale")));
    SS_CHECK("label(fresh): generation 1",
             json_get_int(json_get(&label, "generation")) == 1);
    SS_CHECK("label(fresh): last_publish_height 987654",
             json_get_int(json_get(&label, "last_publish_height")) == 987654);
    { const char *r = label_reason(&label);
      SS_CHECK("label(fresh): warning_reason ok", r && strcmp(r, "ok") == 0); }
    json_free(&label);

    /* Torn read: even on a published env, torn=true labels the fallback stale. */
    json_init(&label);
    json_set_object(&label);
    zcl_snapshot_emit_label(&label, &env, /*torn=*/true,
                            platform_time_monotonic_us());
    SS_CHECK("label(torn): stale true",
             json_get_bool(json_get(&label, "stale")));
    { const char *r = label_reason(&label);
      SS_CHECK("label(torn): warning_reason snapshot_torn_read",
               r && strcmp(r, "snapshot_torn_read") == 0); }
    /* The fallback still carries the LAST published values, never empty. */
    SS_CHECK("label(torn): last_publish_height still 987654 (not empty)",
             json_get_int(json_get(&label, "last_publish_height")) == 987654);
    json_free(&label);

    return failures;
}

int test_subsystem_snapshot(void)
{
    int failures = 0;
    failures += case_deterministic_bracket();
    failures += case_torn_window_deterministic();
    failures += case_label();
    failures += case_concurrent_coherence();
    if (failures == 0)
        printf("test_subsystem_snapshot: ALL PASSED\n");
    else
        printf("test_subsystem_snapshot: %d FAILURE(S)\n", failures);
    return failures;
}
