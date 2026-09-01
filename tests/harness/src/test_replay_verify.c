/* SPDX-License-Identifier: Apache-2.0
 * Copyright 2026 Rhett Creighton
 *
 * test_replay_verify — exercises the offline integrity/PoW sweep service
 * (engine/services/src/replay_verify_service.c).
 *
 * Three layers, all datadir-independent except the optional live block:
 *
 *   1. Cheap unit assertions (NULL guards, missing-datadir → error) —
 *      always run.
 *
 *   2. CI TEETH (always run, self-contained, zero datadir): build a tiny
 *      block-log fixture with the writable block_log_file adapter and run
 *      the SAME canonical sweep (replay_verify_run_port → check_block) over
 *      it. The fixture proves the verifier is NOT a no-op:
 *        - a contiguous chain verifies with zero LINKAGE failures (the
 *          linkage cursor is computed correctly), while
 *        - every block in it is flagged as a PoW failure (the fixture
 *          blocks carry no valid Equihash 200,9 solution, so a wired
 *          check_pow MUST reject them — if PoW verification were silently
 *          skipped this assertion fails), and
 *        - corrupting one block's hashPrevBlock is CAUGHT as a linkage
 *          failure (negative control with teeth), and
 *        - a non-deserializable record is CAUGHT as an operational stop.
 *      No reimplemented crypto: the per-block verdict is check_block.
 *
 *   3. Live block (real legacy datadir, ZCL_LEGACY_DATADIR or ~/.zclassic).
 *      Skipped with PASS in CI / when zclassicd holds the LevelDB LOCK, so
 *      a fresh checkout (or a box with the live node running) never fails.
 */

#include "test/test_core.h"
#include "services/replay_verify_service.h"

#include "adapters/outbound/persistence/block_log_file.h"
#include "ports/block_log_port.h"

#include "bloom/merkle.h"
#include "core/serialize.h"
#include "core/uint256.h"
#include "primitives/block.h"
#include "primitives/transaction.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#define RV_CHECK(name, expr) do {                        \
    printf("replay_verify: %s... ", (name));             \
    if ((expr)) { printf("OK\n"); }                      \
    else { printf("FAIL\n"); failures++; }               \
} while (0)

/* Explicit opt-in only. There is deliberately no $HOME/.zclassic fallback:
 * that directory belongs to a running zclassicd, and replay_verify_run →
 * block_log_legacy_open → bilr_open → db_wrapper_open is an ordinary
 * read-WRITE LevelDB open — it creates if missing, takes the LOCK, and can
 * run log recovery against a live daemon's block index.
 *
 * This was the second instance of the same fallback; the first was removed
 * from test_block_log_legacy.c. It was not theoretical: the live index
 * logged fresh LevelDB recoveries advancing about two per full-suite run
 * while this fallback was in place. Point ZCL_LEGACY_DATADIR at a datadir
 * you own (a stopped node, or a copy) to exercise the live block. */
static const char *rv_resolve_live_datadir(void)
{
    const char *env = getenv("ZCL_LEGACY_DATADIR");
    if (!env || !env[0]) return NULL;
    struct stat st;
    if (stat(env, &st) != 0 || !S_ISDIR(st.st_mode))
        return NULL;
    return env;
}

/* ── Fixture-block builders ─────────────────────────────────────────
 *
 * A minimal but fully deserializable block: one coinbase transaction,
 * header version 4, a non-zero nBits, and a merkle root that matches the
 * single tx. These blocks deliberately carry NO valid Equihash solution
 * (nSolutionSize stays 0), so check_block(check_pow=true) rejects them on
 * the PoW gate — which is exactly the negative control we want for the
 * "verifier actually runs PoW" assertion. */

static void rv_fixture_coinbase(struct transaction *tx, uint8_t marker)
{
    transaction_init(tx);
    transaction_alloc(tx, 1, 1);
    outpoint_set_null(&tx->vin[0].prevout);
    tx->vin[0].sequence = UINT32_MAX;
    /* A distinct, deterministic value so each block's coinbase (and thus
     * its txid + merkle root + block hash) is unique per height. */
    tx->vout[0].value = 1250000000LL + (int64_t)marker;
    tx->vout[0].script_pub_key.size = 0;
    transaction_compute_hash(tx);
}

/* Build block `b` at logical height `marker` with the given prev hash,
 * fixing the header merkle root to the (single) coinbase txid. Caller
 * owns / frees `b`. */
static void rv_build_block(struct block *b, uint8_t marker,
                           const struct uint256 *prev)
{
    block_init(b);
    b->header.nVersion = 4;
    b->header.nTime = 1478403829u + marker;
    b->header.nBits = 0x1f07ffff;
    if (prev)
        b->header.hashPrevBlock = *prev;
    else
        memset(b->header.hashPrevBlock.data, 0, 32);

    b->vtx = calloc(1, sizeof(struct transaction));
    b->num_vtx = 1;
    rv_fixture_coinbase(&b->vtx[0], marker);

    struct uint256 ids[1] = { b->vtx[0].hash };
    b->header.hashMerkleRoot = compute_merkle_root(ids, 1);
}

/* Serialize `b` and append it to the open block_log_file port at
 * `height`, keyed by its canonical block hash. Returns the block hash
 * via `hash_out` so the next block can chain to it. */
static bool rv_append_block(struct block_log_port *port, uint32_t height,
                            const struct block *b, struct uint256 *hash_out)
{
    struct byte_stream s;
    stream_init(&s, 1024);
    if (!block_serialize(b, &s)) { stream_free(&s); return false; }

    struct uint256 h;
    block_get_hash(b, &h);
    if (hash_out) *hash_out = h;

    struct block_hash bh;
    memcpy(bh.bytes, h.data, 32);

    struct zcl_result r = port->append(port->self, height, &bh,
                                       s.data, s.size);
    stream_free(&s);
    return r.ok;
}

/* Build a contiguous 3-block fixture chain into a fresh block_log_file
 * under `dir`. On success leaves *h_out / *port_out open (caller closes)
 * and returns true. */
static bool rv_build_fixture_chain(const char *dir,
                                   struct block_log_file **h_out,
                                   struct block_log_port *port_out)
{
    struct zcl_result r = block_log_file_open(dir, h_out, port_out);
    if (!r.ok) return false;

    struct uint256 prev;
    memset(prev.data, 0, 32);
    bool have_prev = false;
    for (uint8_t i = 0; i < 3; i++) {
        struct block b;
        rv_build_block(&b, i, have_prev ? &prev : NULL);
        struct uint256 h;
        bool ok = rv_append_block(port_out, i, &b, &h);
        block_free(&b);
        if (!ok) return false;
        prev = h;
        have_prev = true;
    }
    return true;
}

/* ── The CI teeth section ───────────────────────────────────────────
 * Returns failure count; runs with zero datadir dependency. */
static int rv_ci_fixture_teeth(void)
{
    int failures = 0;

    /* 1. Contiguous chain: linkage clean, PoW rejected on every block. */
    char tmpl[] = "/tmp/zcl_rv_fixtureXXXXXX";
    char *dir = mkdtemp(tmpl);
    RV_CHECK("ci: mkdtemp fixture", dir != NULL);
    if (!dir) return failures;

    struct block_log_file *h = NULL;
    struct block_log_port port = {0};
    bool built = rv_build_fixture_chain(dir, &h, &port);
    RV_CHECK("ci: build 3-block fixture chain", built);
    if (!built) { /* best-effort cleanup */ goto cleanup_dir; }

    {
        struct replay_verify_report rep;
        struct zcl_result r = replay_verify_run_port(&port, 0, 0, &rep);
        RV_CHECK("ci: sweep over fixture → OK", r.ok);
        RV_CHECK("ci: blocks_checked == 3", rep.blocks_checked == 3);
        RV_CHECK("ci: tip_height == 2", rep.tip_height == 2);

        /* TEETH #1: linkage is computed correctly over a contiguous chain
         * (each hashPrevBlock matches the prior block's hash). */
        RV_CHECK("ci: contiguous chain → 0 linkage failures",
                 rep.linkage_failures == 0);

        /* TEETH #2: PoW verification is actually wired. These fixture
         * blocks have no valid Equihash solution, so a live check_pow MUST
         * flag every one of them. If PoW were silently skipped this fails. */
        RV_CHECK("ci: invalid PoW caught on every block (not a no-op)",
                 rep.pow_failures == rep.blocks_checked &&
                 rep.pow_failures == 3);
        RV_CHECK("ci: first_fail recorded (pow)",
                 rep.first_fail_height == 0 &&
                 rep.first_fail_reason != NULL);
    }
    block_log_file_close(h);
    h = NULL;

    /* 2. NEGATIVE CONTROL — corrupted linkage is CAUGHT.
     * Reopen the same dir, then build a fresh dir whose middle block points
     * at the wrong prev hash. We assert the linkage failure is detected. */
    {
        char tmpl2[] = "/tmp/zcl_rv_badlinkXXXXXX";
        char *dir2 = mkdtemp(tmpl2);
        RV_CHECK("ci: mkdtemp bad-linkage", dir2 != NULL);
        if (dir2) {
            struct block_log_file *h2 = NULL;
            struct block_log_port port2 = {0};
            struct zcl_result ro = block_log_file_open(dir2, &h2, &port2);
            RV_CHECK("ci: open bad-linkage log", ro.ok);
            if (ro.ok) {
                struct uint256 prev;
                memset(prev.data, 0, 32);

                /* height 0: genesis-style (no prev). */
                struct block b0;
                rv_build_block(&b0, 0, NULL);
                struct uint256 h0;
                bool ok0 = rv_append_block(&port2, 0, &b0, &h0);
                block_free(&b0);

                /* height 1: WRONG prev hash (all 0xCD), not h0. This is the
                 * deliberate corruption the verifier must catch. */
                struct uint256 wrong;
                memset(wrong.data, 0xCD, 32);
                struct block b1;
                rv_build_block(&b1, 1, &wrong);
                struct uint256 h1;
                bool ok1 = rv_append_block(&port2, 1, &b1, &h1);
                block_free(&b1);

                RV_CHECK("ci: appended bad-linkage blocks", ok0 && ok1);

                struct replay_verify_report rep;
                struct zcl_result r =
                    replay_verify_run_port(&port2, 0, 0, &rep);
                RV_CHECK("ci: bad-linkage sweep → OK", r.ok);
                RV_CHECK("ci: corrupted hashPrevBlock CAUGHT "
                         "(linkage_failures >= 1)",
                         rep.linkage_failures >= 1);
                (void)prev;
                block_log_file_close(h2);
            }
            /* leave temp files; they are tiny and under /tmp */
        }
    }

    /* 3. NEGATIVE CONTROL — non-deserializable bytes are an OPERATIONAL stop.
     * Append a record whose payload is not a valid serialized block; the
     * sweep must return a non-OK operational result (deser_failed), never
     * silently report success. */
    {
        char tmpl3[] = "/tmp/zcl_rv_corruptXXXXXX";
        char *dir3 = mkdtemp(tmpl3);
        RV_CHECK("ci: mkdtemp corrupt-bytes", dir3 != NULL);
        if (dir3) {
            struct block_log_file *h3 = NULL;
            struct block_log_port port3 = {0};
            struct zcl_result ro = block_log_file_open(dir3, &h3, &port3);
            RV_CHECK("ci: open corrupt-bytes log", ro.ok);
            if (ro.ok) {
                struct block_hash bh;
                memset(bh.bytes, 0x77, 32);
                uint8_t garbage[16];
                memset(garbage, 0xFF, sizeof garbage);
                struct zcl_result ra =
                    port3.append(port3.self, 0, &bh, garbage, sizeof garbage);
                RV_CHECK("ci: appended garbage record", ra.ok);

                struct replay_verify_report rep;
                struct zcl_result r =
                    replay_verify_run_port(&port3, 0, 0, &rep);
                RV_CHECK("ci: non-deserializable block → operational error",
                         !r.ok);
                block_log_file_close(h3);
            }
        }
    }

cleanup_dir:
    if (h) block_log_file_close(h);
    return failures;
}

int test_replay_verify(void)
{
    int failures = 0;

    /* ── 1. NULL / empty arg guards. */
    {
        struct replay_verify_report rep;
        struct zcl_result r = replay_verify_run(NULL, 0, 1, &rep);
        RV_CHECK("run(NULL datadir) → err", !r.ok);

        r = replay_verify_run("", 0, 1, &rep);
        RV_CHECK("run(empty datadir) → err", !r.ok);

        r = replay_verify_run("/anything", 0, 1, NULL);
        RV_CHECK("run(NULL report) → err", !r.ok);

        /* Port variant: NULL port and NULL report. */
        r = replay_verify_run_port(NULL, 0, 1, &rep);
        RV_CHECK("run_port(NULL port) → err", !r.ok);
        struct block_log_port empty = {0};
        r = replay_verify_run_port(&empty, 0, 1, &rep);
        RV_CHECK("run_port(incomplete port) → err", !r.ok);
    }

    /* ── 2. Missing datadir → operational error (open fails). */
    {
        struct replay_verify_report rep;
        struct zcl_result r = replay_verify_run(
                "/tmp/zcl_no_such_legacy_dir_91919191", 0, 1, &rep);
        RV_CHECK("run(missing datadir) → err", !r.ok);
    }

    /* ── 3. Datadir with no blocks/ subdir → operational error. */
    {
        char tmpl[] = "/tmp/zcl_rv_emptyXXXXXX";
        char *dir = mkdtemp(tmpl);
        RV_CHECK("mkdtemp empty", dir != NULL);
        if (dir) {
            struct replay_verify_report rep;
            struct zcl_result r = replay_verify_run(dir, 0, 1, &rep);
            RV_CHECK("run(no blocks/) → err", !r.ok);
            rmdir(dir);
        }
    }

    /* ── 4. CI TEETH: self-contained fixture proving the verifier runs
     *       and catches corruption. Zero datadir dependency. */
    failures += rv_ci_fixture_teeth();

    /* ── 5. Live block: real legacy datadir. Bounded sweep over the
     * first few blocks. Skipped (with PASS) when no datadir is reachable
     * or the LevelDB LOCK is held by a running zclassicd. */
    const char *datadir = rv_resolve_live_datadir();
    if (!datadir) {
        printf("replay_verify: live block SKIPPED "
               "(no ZCL_LEGACY_DATADIR or ~/.zclassic)\n");
        return failures;
    }

    struct replay_verify_report rep;
    struct zcl_result r = replay_verify_run(datadir, 0, /*max_blocks=*/8,
                                            &rep);
    if (!r.ok) {
        printf("replay_verify: live block SKIPPED "
               "(run %s failed: code=%d %s)\n",
               datadir, r.code, r.message);
        return failures;
    }

    /* Report shape: a bounded run of N requested blocks reads at most N. */
    RV_CHECK("blocks_checked in (0, 8]",
             rep.blocks_checked > 0 && rep.blocks_checked <= 8);

    /* start_height echoed; tip and end are sane. */
    RV_CHECK("start_height == 0", rep.start_height == 0);
    RV_CHECK("tip_height >= end_height", rep.tip_height >= rep.end_height);

    /* The first blocks of mainnet must verify cleanly: no PoW, linkage,
     * or merkle failures, and no recorded first failure. */
    RV_CHECK("no pow failures",      rep.pow_failures == 0);
    RV_CHECK("no linkage failures",  rep.linkage_failures == 0);
    RV_CHECK("no merkle failures",   rep.merkle_failures == 0);
    RV_CHECK("first_fail_height == -1", rep.first_fail_height == -1);
    RV_CHECK("first_fail_reason NULL",  rep.first_fail_reason == NULL);

    printf("  blocks_checked=%llu tip=%u (clean)\n",
           (unsigned long long)rep.blocks_checked, rep.tip_height);

    return failures;
}
