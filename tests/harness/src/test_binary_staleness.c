/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Tests for the binary_staleness service.
 *
 * The real test binary never changes out from under itself mid-run, so
 * the mismatch/edge-trigger paths are exercised via the ZCL_TESTING hooks
 * (`binary_staleness_test_force_boot_stamp` / `_test_force_probe`), which
 * let us fake both stamps directly with no real file IO — exactly the
 * seam the header documents for this purpose. The real-filesystem code
 * path (`binary_staleness_capture_boot_stamp()` against the actual
 * /proc/self/exe of the test binary) is exercised separately in test 1
 * and in the start/stop lifecycle test, so both the real and faked paths
 * get coverage.
 */

#include "test/test_core.h"
#include "services/binary_staleness_service.h"
#include "util/blocker.h"
#include "json/json.h"

#include <stdio.h>
#include <string.h>

#define BS_CHECK(name, expr) do { \
    printf("bs: %s... ", (name)); \
    if ((expr)) printf("OK\n"); \
    else { printf("FAIL\n"); failures++; } \
} while (0)

/* 64 lowercase hex chars = a well-formed (fake) SHA3-256 digest. */
#define DIGEST_A "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
#define DIGEST_B "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"

int test_binary_staleness(void)
{
    printf("\n=== binary_staleness tests ===\n");
    int failures = 0;

    blocker_module_init();

    /* ── 1. Real capture against this test binary's own image ───── */
    {
        binary_staleness_reset_for_testing();
        bool captured = binary_staleness_capture_boot_stamp();
        struct binary_staleness_status st;
        binary_staleness_status_snapshot(&st);
        BS_CHECK("real capture_boot_stamp succeeds against /proc/self/exe",
                 captured && st.boot_captured);
        BS_CHECK("real capture records a 64-char hex digest",
                 strlen(st.boot_digest_hex) == 64);
        BS_CHECK("real capture resolves a non-empty exe_path",
                 st.exe_path[0] != '\0');
        BS_CHECK("real capture is not stale immediately after boot",
                 !st.stale && !binary_staleness_is_stale());
        BS_CHECK("no blocker raised right after boot capture",
                 !blocker_exists(BINARY_STALENESS_BLOCKER_ID));
    }

    /* ── 2. Forced boot stamp + matching probe: no edge, no blocker ── */
    {
        binary_staleness_reset_for_testing();
        binary_staleness_test_force_boot_stamp(DIGEST_A, 1000, 4096,
                                               "/fake/zclassic23");
        binary_staleness_test_force_probe(DIGEST_A, 1000, 4096);
        bool stale = binary_staleness_check_now();
        BS_CHECK("matching probe (same mtime/size as boot) reports not stale",
                 !stale && !binary_staleness_is_stale());
        BS_CHECK("no blocker raised when content matches",
                 !blocker_exists(BINARY_STALENESS_BLOCKER_ID));

        struct binary_staleness_status st;
        binary_staleness_status_snapshot(&st);
        BS_CHECK("unchanged stamp does not count as a rehash",
                 st.rehash_count == 0);
    }

    /* ── 3. Forced mismatch: raises ops.binary_stale exactly once ─── */
    {
        binary_staleness_reset_for_testing();
        binary_staleness_test_force_boot_stamp(DIGEST_A, 1000, 4096,
                                               "/fake/zclassic23");
        binary_staleness_test_force_probe(DIGEST_A, 1000, 4096);
        binary_staleness_check_now(); /* baseline tick: not stale */

        binary_staleness_test_force_probe(DIGEST_B, 2000, 8192);
        bool stale = binary_staleness_check_now();
        BS_CHECK("mismatched probe (different mtime/size + digest) reports stale",
                 stale && binary_staleness_is_stale());
        BS_CHECK("ops.binary_stale blocker is raised on the ok->stale edge",
                 blocker_exists(BINARY_STALENESS_BLOCKER_ID));

        struct binary_staleness_status st;
        binary_staleness_status_snapshot(&st);
        BS_CHECK("stale_transitions incremented exactly once",
                 st.stale_transitions == 1);
        /* rehash_count only counts REAL bs_hash_path() calls — the forced
         * probe override supplies the digest directly (digest_known=true
         * in check_now()), deliberately skipping the hash step (and its
         * counter) so a test never touches the filesystem. See test 1 for
         * coverage of the real (non-overridden) hashing path. */
        BS_CHECK("rehash_count stays 0 under a forced probe override",
                 st.rehash_count == 0);
        BS_CHECK("last_disk_digest_hex reflects the new probe digest",
                 strcmp(st.last_disk_digest_hex, DIGEST_B) == 0);

        /* Re-checking with the SAME mismatched stamp (no stat() delta)
         * must not re-fire the edge (still-stale, not a new transition). */
        bool still_stale = binary_staleness_check_now();
        binary_staleness_status_snapshot(&st);
        BS_CHECK("re-check with unchanged mismatched stamp stays stale, no re-fire",
                 still_stale && st.stale_transitions == 1);
    }

    /* ── 4. Recovery: on-disk content matches the running image again ── */
    {
        /* Continues from test 3's raised state (still stale, blocker set). */
        binary_staleness_test_force_probe(DIGEST_A, 1000, 4096);
        bool stale = binary_staleness_check_now();
        BS_CHECK("probe reverting to the boot digest clears staleness",
                 !stale && !binary_staleness_is_stale());
        BS_CHECK("ops.binary_stale blocker is cleared on the stale->ok edge",
                 !blocker_exists(BINARY_STALENESS_BLOCKER_ID));

        struct binary_staleness_status st;
        binary_staleness_status_snapshot(&st);
        BS_CHECK("stale_transitions is not incremented on a clearing edge",
                 st.stale_transitions == 1);

        binary_staleness_test_clear_probe_override();
    }

    /* ── 5. check_now() before a boot stamp is a no-op ───────────── */
    {
        binary_staleness_reset_for_testing();
        bool stale = binary_staleness_check_now();
        BS_CHECK("check_now() with no boot stamp captured returns false",
                 !stale);
        struct binary_staleness_status st;
        binary_staleness_status_snapshot(&st);
        BS_CHECK("check_now() with no boot stamp does not bump check_count",
                 st.check_count == 0);
    }

    /* ── 6. dump_state_json exposes the documented keys ──────────── */
    {
        binary_staleness_reset_for_testing();
        binary_staleness_test_force_boot_stamp(DIGEST_A, 1000, 4096,
                                               "/fake/zclassic23");
        struct json_value out;
        json_init(&out);
        bool ok = binary_staleness_dump_state_json(&out, NULL);
        BS_CHECK("dump_state_json returns true", ok);
        const struct json_value *boot_captured = json_get(&out, "boot_captured");
        const struct json_value *stale = json_get(&out, "stale");
        const struct json_value *digest = json_get(&out, "boot_digest_hex");
        BS_CHECK("dump_state_json includes boot_captured=true",
                 boot_captured && json_get_bool(boot_captured));
        BS_CHECK("dump_state_json includes stale=false",
                 stale && !json_get_bool(stale));
        BS_CHECK("dump_state_json includes the forced boot_digest_hex",
                 digest && strcmp(json_get_str(digest), DIGEST_A) == 0);
        json_free(&out);
    }

    /* ── 7. start()/stop() lifecycle against the real binary ─────── */
    {
        binary_staleness_reset_for_testing();
        struct binary_staleness_config cfg;
        binary_staleness_config_defaults(&cfg);
        cfg.poll_seconds = 3600; /* keep the background tick from firing
                                  * mid-test; the synchronous first check
                                  * inside start() is what we assert on */
        struct zcl_result r = binary_staleness_start(&cfg);
        BS_CHECK("start() succeeds against the real running binary", r.ok);

        struct binary_staleness_status st;
        binary_staleness_status_snapshot(&st);
        BS_CHECK("status snapshot shows running after start()", st.running);
        BS_CHECK("status snapshot shows boot_captured after start()",
                 st.boot_captured);
        BS_CHECK("a freshly started monitor against its own binary is not stale",
                 !st.stale);

        struct zcl_result r2 = binary_staleness_start(&cfg);
        BS_CHECK("start() rejects a second concurrent start", !r2.ok);

        binary_staleness_stop();
        binary_staleness_status_snapshot(&st);
        BS_CHECK("status snapshot shows not running after stop()", !st.running);

        binary_staleness_stop(); /* must be a safe no-op */
        BS_CHECK("stop() is a safe no-op when already stopped", true);
    }

    binary_staleness_reset_for_testing();
    return failures;
}
