/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Unit tests for the seed_tape primitive (engine/modules/sim/src/seed_tape.c).
 *
 * Coverage (11 cases from the assignment spec):
 *   1.  open_close_clean
 *   2.  rng_deterministic
 *   3.  rng_different_seeds_diverge
 *   4.  install_hooks_rng
 *   5.  install_hooks_clock
 *   6.  advance_clock
 *   7.  inject_event
 *   8.  save_load_roundtrip
 *   9.  replay_rejects_writes
 *  10.  corruption_detected
 *  11.  memory_codec_roundtrip
 */

#include "test/test_core.h"
#include "sim/seed_tape.h"
#include "platform/rng.h"
#include "platform/clock.h"

#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define TAPE_CHECK(name, expr) do { \
    printf("seed_tape: %s... ", (name)); \
    if ((expr)) printf("OK\n"); \
    else { printf("FAIL\n"); failures++; } \
} while (0)

static char g_tmp_path[256];

static void make_tmp_path(const char *suffix)
{
    snprintf(g_tmp_path, sizeof(g_tmp_path),
             "/tmp/zcl_seed_tape_test_%d_%s.bin",
             (int)getpid(), suffix);
    /* Best-effort wipe from a prior run. */
    unlink(g_tmp_path);
}

int test_seed_tape(void)
{
    printf("\n=== seed_tape tests ===\n");
    int failures = 0;

    /* ── 1. open_close_clean ──────────────────────────────────── */
    {
        seed_tape_t *t = seed_tape_open(0xCAFEBABE12345678ULL, 1700000000);
        TAPE_CHECK("open returns non-NULL", t != NULL);
        TAPE_CHECK("rng_count starts at 0", seed_tape_rng_count(t) == 0);
        TAPE_CHECK("advance_count starts at 0", seed_tape_clock_advance_count(t) == 0);
        TAPE_CHECK("inject_count starts at 0", seed_tape_inject_count(t) == 0);
        seed_tape_close(t);
        /* Close of NULL is a no-op (doesn't crash). */
        seed_tape_close(NULL);
        TAPE_CHECK("close(NULL) is safe (no crash)", true);
    }

    /* ── 2. rng_deterministic ─────────────────────────────────── */
    {
        seed_tape_t *a = seed_tape_open(0xDEADBEEFULL, 0);
        seed_tape_t *b = seed_tape_open(0xDEADBEEFULL, 0);
        TAPE_CHECK("two tapes open", a != NULL && b != NULL);

        bool all_equal = true;
        seed_tape_install(a);
        uint64_t draws_a[1000];
        for (int i = 0; i < 1000; i++) draws_a[i] = rng_u64();
        seed_tape_uninstall();

        seed_tape_install(b);
        for (int i = 0; i < 1000; i++) {
            uint64_t v = rng_u64();
            if (v != draws_a[i]) { all_equal = false; break; }
        }
        seed_tape_uninstall();

        TAPE_CHECK("same seed -> identical 1000 draws", all_equal);
        TAPE_CHECK("rng_count == 1000 on tape a",
                   seed_tape_rng_count(a) == 1000);
        TAPE_CHECK("rng_count == 1000 on tape b",
                   seed_tape_rng_count(b) == 1000);
        seed_tape_close(a);
        seed_tape_close(b);
    }

    /* ── 3. rng_different_seeds_diverge ───────────────────────── */
    {
        seed_tape_t *a = seed_tape_open(1, 0);
        seed_tape_t *b = seed_tape_open(2, 0);
        bool diverged = false;

        seed_tape_install(a);
        uint64_t draws_a[10];
        for (int i = 0; i < 10; i++) draws_a[i] = rng_u64();
        seed_tape_uninstall();

        seed_tape_install(b);
        for (int i = 0; i < 10; i++) {
            if (rng_u64() != draws_a[i]) { diverged = true; break; }
        }
        seed_tape_uninstall();

        TAPE_CHECK("different seeds diverge within first 10 draws",
                   diverged);
        seed_tape_close(a);
        seed_tape_close(b);
    }

    /* ── 4. install_hooks_rng ─────────────────────────────────── */
    {
        seed_tape_t *t = seed_tape_open(42, 0);
        seed_tape_install(t);

        /* The value must come from the tape (xoshiro from seed=42),
         * not /dev/urandom. Two consecutive draws will be the
         * fixed xoshiro sequence; we just verify rng_u64 reads
         * through to the tape (count goes up). */
        uint64_t v1 = rng_u64();
        uint64_t v2 = rng_u64();
        uint64_t cnt_installed = seed_tape_rng_count(t);
        TAPE_CHECK("rng_count == 2 after 2 draws while installed",
                   cnt_installed == 2);

        seed_tape_uninstall();

        /* After uninstall, rng_u64 should now be system source —
         * we can't predict the exact value, but the tape's count
         * must NOT increase. */
        uint64_t v3 = rng_u64();
        uint64_t v4 = rng_u64();
        TAPE_CHECK("rng_count unchanged after uninstall",
                   seed_tape_rng_count(t) == cnt_installed);
        (void)v1; (void)v2; (void)v3; (void)v4;

        seed_tape_close(t);
    }

    /* ── 5. install_hooks_clock ───────────────────────────────── */
    {
        seed_tape_t *t = seed_tape_open(0, 1700000000);
        seed_tape_install(t);

        int64_t mono = clock_now_monotonic_ns();
        int64_t wall_ms = clock_now_wall_ms();

        /* Tape monotonic starts at 0 us -> 0 ns. */
        TAPE_CHECK("clock_now_monotonic_ns == 0 at start",
                   mono == 0);
        /* Wall: 1700000000 unix seconds = 1700000000000 ms. */
        TAPE_CHECK("clock_now_wall_ms == start_wall * 1000",
                   wall_ms == 1700000000LL * 1000LL);

        /* Advance by 1.5 s; both clocks should reflect. */
        int rc = seed_tape_advance(t, 1500000);
        TAPE_CHECK("advance returns 0", rc == 0);

        mono = clock_now_monotonic_ns();
        wall_ms = clock_now_wall_ms();
        TAPE_CHECK("monotonic_ns == 1.5e9 after +1.5s advance",
                   mono == 1500000LL * 1000LL);
        /* Wall is unix seconds * 1000 = (1700000000 + 1) * 1000
         * because 1500000 us = 1 whole second + 500000 us. */
        TAPE_CHECK("wall_ms == (start + 1) * 1000 after +1.5s",
                   wall_ms == (1700000000LL + 1LL) * 1000LL);

        seed_tape_uninstall();
        seed_tape_close(t);
    }

    /* ── 6. advance_clock ─────────────────────────────────────── */
    {
        seed_tape_t *t = seed_tape_open(0, 0);
        seed_tape_install(t);

        seed_tape_advance(t, 1000);
        seed_tape_advance(t, 2000);

        int64_t mono = clock_now_monotonic_ns();
        TAPE_CHECK("two advances accumulate (1000+2000 us = 3 us total)",
                   mono == 3000LL * 1000LL);
        TAPE_CHECK("advance_count == 2",
                   seed_tape_clock_advance_count(t) == 2);

        seed_tape_uninstall();
        seed_tape_close(t);
    }

    /* ── 7. inject_event ─────────────────────────────────────── */
    {
        seed_tape_t *t = seed_tape_open(0, 0);
        uint8_t p1[3] = { 0xAA, 0xBB, 0xCC };
        uint8_t p2[1] = { 0x55 };

        TAPE_CHECK("inject #1 ok",
                   seed_tape_inject(t, 1, p1, sizeof(p1)) == 0);
        TAPE_CHECK("inject #2 ok",
                   seed_tape_inject(t, 2, p2, sizeof(p2)) == 0);
        TAPE_CHECK("inject #3 (empty payload) ok",
                   seed_tape_inject(t, 3, NULL, 0) == 0);
        TAPE_CHECK("inject_count == 3",
                   seed_tape_inject_count(t) == 3);

        /* NULL payload + nonzero len -> EINVAL. */
        TAPE_CHECK("inject(NULL, len>0) rejected",
                   seed_tape_inject(t, 4, NULL, 5) == -EINVAL);

        seed_tape_close(t);
    }

    /* ── 8. save_load_roundtrip ──────────────────────────────── */
    {
        make_tmp_path("roundtrip");

        seed_tape_t *rec = seed_tape_open(0xABCDEF0123456789ULL, 1234567890);

        /* Build a mixed action log: 5 advances + 3 injects. */
        seed_tape_advance(rec, 100);
        seed_tape_advance(rec, 200);
        uint8_t pa[4] = { 1, 2, 3, 4 };
        seed_tape_inject(rec, 10, pa, sizeof(pa));
        seed_tape_advance(rec, 300);
        seed_tape_inject(rec, 11, NULL, 0);
        seed_tape_advance(rec, 400);
        uint8_t pb[8] = { 'h','e','l','l','o','!','!','!' };
        seed_tape_inject(rec, 12, pb, sizeof(pb));
        seed_tape_advance(rec, 500);

        /* Make some RNG draws BEFORE saving so the stored state
         * is mid-stream — replay should resume from there. */
        seed_tape_install(rec);
        uint64_t pre_save_draws[5];
        for (int i = 0; i < 5; i++) pre_save_draws[i] = rng_u64();
        seed_tape_uninstall();

        int rc = seed_tape_save(rec, g_tmp_path);
        TAPE_CHECK("save returns 0", rc == 0);

        /* Capture the next-N draws on `rec` AFTER save so we know
         * what replay must reproduce. */
        seed_tape_install(rec);
        uint64_t expected_post_draws[10];
        for (int i = 0; i < 10; i++) expected_post_draws[i] = rng_u64();
        seed_tape_uninstall();

        /* Load and verify replay matches. */
        seed_tape_t *rep = seed_tape_load(g_tmp_path);
        TAPE_CHECK("load returns non-NULL", rep != NULL);
        if (rep) {
            TAPE_CHECK("loaded advance_count == 5",
                       seed_tape_clock_advance_count(rep) == 5);
            TAPE_CHECK("loaded inject_count == 3",
                       seed_tape_inject_count(rep) == 3);

            seed_tape_install(rep);
            bool draws_match = true;
            for (int i = 0; i < 10; i++) {
                uint64_t v = rng_u64();
                if (v != expected_post_draws[i]) {
                    draws_match = false; break;
                }
            }
            seed_tape_uninstall();
            TAPE_CHECK("replay RNG matches post-save draws",
                       draws_match);

            /* Replay events: 3 injects, in order. */
            uint8_t type = 0;
            uint8_t buf[64];
            size_t len = 0;
            int e1 = seed_tape_next_event(rep, &type, buf, sizeof(buf), &len);
            TAPE_CHECK("event #1 returns 0", e1 == 0);
            TAPE_CHECK("event #1 type == 10", type == 10);
            TAPE_CHECK("event #1 len == 4", len == 4);
            TAPE_CHECK("event #1 payload matches",
                       e1 == 0 && memcmp(buf, pa, 4) == 0);

            int e2 = seed_tape_next_event(rep, &type, buf, sizeof(buf), &len);
            TAPE_CHECK("event #2 returns 0", e2 == 0);
            TAPE_CHECK("event #2 type == 11", type == 11);
            TAPE_CHECK("event #2 len == 0", len == 0);

            int e3 = seed_tape_next_event(rep, &type, buf, sizeof(buf), &len);
            TAPE_CHECK("event #3 returns 0", e3 == 0);
            TAPE_CHECK("event #3 type == 12", type == 12);
            TAPE_CHECK("event #3 len == 8", len == 8);
            TAPE_CHECK("event #3 payload matches",
                       e3 == 0 && memcmp(buf, pb, 8) == 0);

            int e4 = seed_tape_next_event(rep, &type, buf, sizeof(buf), &len);
            TAPE_CHECK("next_event returns -ENOENT after exhaustion",
                       e4 == -ENOENT);

            seed_tape_close(rep);
        }
        (void)pre_save_draws;
        seed_tape_close(rec);
        unlink(g_tmp_path);
    }

    /* ── 9. replay_rejects_writes ────────────────────────────── */
    {
        make_tmp_path("ro");
        seed_tape_t *rec = seed_tape_open(99, 0);
        seed_tape_advance(rec, 1);
        seed_tape_inject(rec, 1, NULL, 0);
        int rc = seed_tape_save(rec, g_tmp_path);
        TAPE_CHECK("save (for ro test) ok", rc == 0);
        seed_tape_close(rec);

        seed_tape_t *rep = seed_tape_load(g_tmp_path);
        TAPE_CHECK("load (for ro test) ok", rep != NULL);
        if (rep) {
            int adv_rc = seed_tape_advance(rep, 1);
            int inj_rc = seed_tape_inject(rep, 1, NULL, 0);
            TAPE_CHECK("advance on replay tape -> -EROFS",
                       adv_rc == -EROFS);
            TAPE_CHECK("inject on replay tape -> -EROFS",
                       inj_rc == -EROFS);
            seed_tape_close(rep);
        }
        unlink(g_tmp_path);
    }

    /* ── 10. corruption_detected ─────────────────────────────── */
    {
        make_tmp_path("corrupt");
        seed_tape_t *rec = seed_tape_open(7, 0);
        seed_tape_advance(rec, 12345);
        seed_tape_inject(rec, 5, (const uint8_t *)"abc", 3);
        int rc = seed_tape_save(rec, g_tmp_path);
        TAPE_CHECK("save (for corrupt test) ok", rc == 0);
        seed_tape_close(rec);

        /* Verify load works before corrupting. */
        seed_tape_t *ok = seed_tape_load(g_tmp_path);
        TAPE_CHECK("pre-corrupt load ok", ok != NULL);
        if (ok) seed_tape_close(ok);

        /* Flip a byte in the middle of the file (after magic, before
         * CRC). Read, mutate, write back. */
        FILE *fp = fopen(g_tmp_path, "r+b");
        TAPE_CHECK("reopen tape for corruption", fp != NULL);
        if (fp) {
            /* Seek into the records area (~mid-file). */
            fseek(fp, 0, SEEK_END);
            long fsize = ftell(fp);
            long off = fsize / 2;
            fseek(fp, off, SEEK_SET);
            int orig = fgetc(fp);
            int corrupt = orig ^ 0xFF;
            fseek(fp, off, SEEK_SET);
            fputc(corrupt, fp);
            fclose(fp);

            seed_tape_t *bad = seed_tape_load(g_tmp_path);
            TAPE_CHECK("load(corrupted) returns NULL", bad == NULL);
            if (bad) seed_tape_close(bad);
        }
        unlink(g_tmp_path);
    }

    /* ── 11. memory_codec_roundtrip ──────────────────────────── */
    {
        seed_tape_t *rec = seed_tape_open(0x5152535455565758ULL, 42);
        TAPE_CHECK("memory codec tape open", rec != NULL);
        if (rec) {
            seed_tape_advance(rec, 777);
            uint8_t payload[5] = { 'm', 'e', 'm', 'o', 'k' };
            seed_tape_inject(rec, 33, payload, sizeof(payload));

            seed_tape_install(rec);
            uint64_t before_save = rng_u64();
            seed_tape_uninstall();
            (void)before_save;

            size_t need = seed_tape_size_bytes(rec);
            uint8_t small[8];
            size_t written = 0;
            TAPE_CHECK("save_to_memory reports required size",
                       seed_tape_save_to_memory(rec, small, sizeof(small),
                                                &written) == -ENOSPC &&
                       written == need);

            uint8_t *buf = (uint8_t *)malloc(need);
            TAPE_CHECK("malloc memory codec buffer", buf != NULL);
            if (buf) {
                TAPE_CHECK("save_to_memory succeeds",
                           seed_tape_save_to_memory(rec, buf, need,
                                                    &written) == 0 &&
                           written == need);

                seed_tape_install(rec);
                uint64_t expected = rng_u64();
                seed_tape_uninstall();

                seed_tape_t *rep = seed_tape_load_from_memory(buf, written);
                TAPE_CHECK("load_from_memory returns non-NULL", rep != NULL);
                if (rep) {
                    seed_tape_install(rep);
                    uint64_t got = rng_u64();
                    seed_tape_uninstall();
                    TAPE_CHECK("memory replay RNG resumes",
                               got == expected);

                    uint8_t type = 0;
                    uint8_t out[8];
                    size_t out_len = 0;
                    int ev = seed_tape_next_event(rep, &type, out,
                                                  sizeof(out), &out_len);
                    TAPE_CHECK("memory replay event returns 0", ev == 0);
                    TAPE_CHECK("memory replay event payload matches",
                               ev == 0 && type == 33 &&
                               out_len == sizeof(payload) &&
                               memcmp(out, payload, sizeof(payload)) == 0);
                    seed_tape_close(rep);
                }

                buf[written - 1] ^= 0xff;
                seed_tape_t *bad = seed_tape_load_from_memory(buf, written);
                TAPE_CHECK("load_from_memory rejects corruption", bad == NULL);
                if (bad) seed_tape_close(bad);
                free(buf);
            }
            seed_tape_close(rec);
        }
    }

    /* Always restore default sources at the end. */
    seed_tape_uninstall();

    if (failures == 0) {
        printf("=== seed_tape tests: ALL PASS ===\n\n");
    } else {
        printf("=== seed_tape tests: %d FAILURE(S) ===\n\n", failures);
    }
    return failures;
}
