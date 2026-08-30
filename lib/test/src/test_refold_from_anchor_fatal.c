/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Deterministic fault-injection test for the -refold-from-anchor hard-assert:
 * boot_refold_from_anchor_reset (config/src/boot_refold_staged.c:274-437) FATALs
 * via _exit(EXIT_FAILURE) (after EV_BOOT_VALIDATION_FAILED) whenever the
 * re-seeded coins_kv does NOT reproduce the compiled checkpoint
 * (commitment != cp->sha3_hash OR count != cp->utxo_count) — the `anchor_proven`
 * check at boot_refold_staged.c:332-354. This is the "never boots on a bad
 * foundation; FATALs with a NAMED blocker" invariant.
 *
 * Because that path ends in _exit, it CANNOT be asserted in-process — each fault
 * is driven in a FORKED CHILD whose exit status is asserted (the proven idiom in
 * test_util_signal_handler.c: fflush; fork; child redirects stderr to a temp
 * file, runs the reset, then _exit(99) if it survives; parent waitpid()s and
 * asserts WIFEXITED && WEXITSTATUS==EXIT_FAILURE).
 *
 * Three fault sub-cases (each its own forked child), corrupting the anchor
 * SOURCES the reset reads (it prefers the MINTED snapshot via ZCL_MINT_ANCHOR_OUT
 * and falls back to the node.db `utxos` reseed; the hard-assert guards BOTH):
 *   A: wrong-SHA3 snapshot (tampered body) + EMPTY node.db utxos -> both sources
 *      fail -> coins_kv ends wrong -> FATAL.
 *   B: wrong-COUNT snapshot (clean SHA3 but cp->utxo_count = snap.count+1) ->
 *      snapshot count guard rejects -> node.db fallback (empty) -> FATAL.
 *   C: truncated snapshot (header short read) -> uss_open NULL -> fallback -> FATAL.
 *
 * Plus a POSITIVE control (in-process, no fork): a MATCHING snapshot makes the
 * reset return normally and coins_kv become the proven authority at anchor+1.
 *
 * Negative control (flip the fault children GREEN -> test RED): in
 * config/src/boot_refold_staged.c weaken the hard-assert at line 338 from
 *     if (!anchor_proven) {
 * to
 *     if (false) {
 * (equivalently delete the _exit(EXIT_FAILURE) at line 353, or set
 * `bool anchor_proven = true;`). The child no longer FATALs on a bad anchor set:
 * it arms the cursors over an UNPROVEN coins_kv and returns normally, reaching
 * _exit(99) -> parent sees WEXITSTATUS==99 (not 1) and the banner is absent ->
 * all three sub-cases FAIL. This is the "boots on a bad foundation" regression.
 *
 * Scratch files live under ./test-tmp/<name>_<pid>/.
 */

#define _GNU_SOURCE
#include "test/test_core.h"

#include "chain/checkpoints.h"
#include "config/boot.h"
#include "crypto/sha3.h"
#include "models/database.h"
#include "storage/coins_kv.h"
#include "storage/progress_store.h"

#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#if !defined(_WIN32)
#include <sys/wait.h>
#endif
#include <unistd.h>
#if !defined(_WIN32)

#define RFA_CHECK(name, expr) do {                            \
    printf("refold_from_anchor_fatal: %s... ", (name));       \
    if (expr) printf("OK\n");                                 \
    else { printf("FAIL\n"); failures++; }                    \
} while (0)

static void rfa_wle32(uint8_t *p, uint32_t v)
{ p[0]=(uint8_t)v; p[1]=(uint8_t)(v>>8); p[2]=(uint8_t)(v>>16); p[3]=(uint8_t)(v>>24); }
static void rfa_wle64(uint8_t *p, uint64_t v)
{ for (int i=0;i<8;i++) p[i]=(uint8_t)(v>>(8*i)); }

/* Build a tiny but valid USS snapshot body (3 records); fill body_sha3, count,
 * total. `tamper` flips one body byte AFTER hashing so the on-disk body SHA3 no
 * longer matches the header root (modeling a corrupted/forged artifact). Mirrors
 * lv_build_snapshot (test_load_verify_boot.c). */
struct rfa_built {
    uint8_t  file[8192];
    size_t   file_len;
    uint8_t  body_sha3[32];
    uint64_t count;
    int64_t  total;
};
static void rfa_build_snapshot(struct rfa_built *b, bool tamper)
{
    uint8_t body[4096] = {0};
    size_t off = 0;
    uint8_t txid[32];
    for (int i = 0; i < 32; i++) txid[i] = (uint8_t)(0x40 + i);

    struct rec { uint32_t vout; int64_t value; uint8_t s[5]; uint32_t sl;
                 uint32_t height; uint8_t cb; };
    struct rec recs[3] = {
        { 0, 11111, {0x76,0xa9,0x14,0,0}, 3, 10, 1 },
        { 1, 22222, {0x6a,0,0,0,0},       1, 20, 0 },
        { 2, 33333, {0x21,0x02,0x03,0x04,0x05}, 5, 30, 0 },
    };
    int64_t total = 0;
    for (int i = 0; i < 3; i++) {
        memcpy(body + off, txid, 32); off += 32;
        rfa_wle32(body + off, recs[i].vout); off += 4;
        rfa_wle64(body + off, (uint64_t)recs[i].value); off += 8;
        rfa_wle32(body + off, recs[i].sl); off += 4;
        memcpy(body + off, recs[i].s, recs[i].sl); off += recs[i].sl;
        rfa_wle32(body + off, recs[i].height); off += 4;
        body[off++] = recs[i].cb;
        total += recs[i].value;
    }
    size_t body_len = off;
    b->count = 3;
    b->total = total;

    struct sha3_256_ctx ctx;
    sha3_256_init(&ctx);
    sha3_256_write(&ctx, body, body_len);
    sha3_256_finalize(&ctx, b->body_sha3);

    if (tamper) body[20] ^= 0xff;

    uint8_t header[104] = {0};
    memcpy(header, "ZCLUTXO\x00", 8);
    rfa_wle32(header + 8, 1);                 /* version */
    rfa_wle32(header + 16, 1234);             /* height */
    rfa_wle64(header + 24, b->count);
    rfa_wle64(header + 32, (uint64_t)b->total);
    /* anchor block hash header+40 left zero */
    memcpy(header + 72, b->body_sha3, 32);    /* claimed root = CLEAN body sha3 */

    memcpy(b->file, header, 104);
    memcpy(b->file + 104, body, body_len);
    b->file_len = 104 + body_len;
}

/* Write `len` bytes of the assembled file to `path` (len < file_len => truncated). */
static bool rfa_write_n(const char *path, const struct rfa_built *b, size_t len)
{
    FILE *f = fopen(path, "wb");
    if (!f) return false;
    size_t w = fwrite(b->file, 1, len, f);
    fclose(f);
    return w == len;
}

enum rfa_fault { RFA_WRONG_SHA3, RFA_WRONG_COUNT, RFA_TRUNCATED };

/* Run boot_refold_from_anchor_reset in a forked child against a fault-specific
 * anchor source, redirecting the child's stderr to `stderr_path`. The child
 * _exit(99)s if it SURVIVES the (expected) FATAL. Returns the child's wait
 * status via *out_status; returns false on a fork/wait failure. */
static bool rfa_run_child(const char *dir, const char *snap_path,
                          const char *stderr_path, enum rfa_fault fault,
                          const struct rfa_built *snap,
                          const struct sha3_utxo_checkpoint *cp_ovr,
                          int *out_status)
{
    /* Write the fault-specific snapshot bytes. */
    bool wrote;
    switch (fault) {
    case RFA_WRONG_SHA3:  wrote = rfa_write_n(snap_path, snap, snap->file_len); break;
    case RFA_WRONG_COUNT: wrote = rfa_write_n(snap_path, snap, snap->file_len); break;
    case RFA_TRUNCATED:   wrote = rfa_write_n(snap_path, snap, 60); break;  /* header short read */
    default: wrote = false; break;
    }
    if (!wrote)
        return false;

    fflush(stdout);
    fflush(stderr);
    pid_t pid = fork();
    if (pid < 0)
        return false;

    if (pid == 0) {
        /* CHILD. Redirect stderr to the temp file before the FATAL banner. */
        int fd = open(stderr_path, O_WRONLY | O_CREAT | O_TRUNC, 0600);
        if (fd < 0) _exit(42);
        dup2(fd, STDERR_FILENO);
        close(fd);
        int dn = open("/dev/null", O_WRONLY);
        if (dn >= 0) { dup2(dn, STDOUT_FILENO); close(dn); }

        /* Install the checkpoint override in THIS process image. */
        checkpoints_set_sha3_override_for_test(cp_ovr);

        /* Open the stores post-fork on this dir. */
        if (!progress_store_open(dir)) _exit(40);
        sqlite3 *pk = progress_store_db();
        if (!pk || !coins_kv_ensure_schema(pk)) _exit(41);

        /* node.db with an EMPTY `utxos` table so the node.db fallback cannot
         * reproduce the checkpoint (coins_kv_count==0 != cp->utxo_count). */
        char dbpath[400];
        snprintf(dbpath, sizeof(dbpath), "%s/node.db", dir);
        struct node_db ndb;
        if (!node_db_open(&ndb, dbpath)) _exit(43);
        if (!node_db_exec(&ndb,
                "CREATE TABLE IF NOT EXISTS utxos(txid BLOB, vout INTEGER,"
                " value INTEGER, height INTEGER, is_coinbase INTEGER,"
                " script BLOB)"))
            _exit(44);

        /* DRIVE the reset. On a correct FATAL this _exit(EXIT_FAILURE)s and the
         * next line is unreachable. */
        boot_refold_from_anchor_reset(&ndb);

        /* If we reach here the hard-assert did NOT fire (a regression): a
         * distinct exit code the parent surfaces clearly. */
        _exit(99);
    }

    int status = 0;
    if (waitpid(pid, &status, 0) != pid)
        return false;
    *out_status = status;
    return true;
}

/* Slurp up to cap-1 bytes of a file (NUL-terminated). -1 if unopenable. */
static long rfa_slurp(const char *path, char *buf, size_t cap)
{
    FILE *f = fopen(path, "rb");
    if (!f) return -1;
    size_t n = fread(buf, 1, cap - 1, f);
    fclose(f);
    buf[n] = '\0';
    return (long)n;
}

static int test_refold_from_anchor_fatal_platform_arm(void);
static int test_refold_from_anchor_fatal_platform_arm(void)
{
    printf("\n=== refold_from_anchor_fatal tests ===\n");
    int failures = 0;

    char dir[256];
    test_make_tmpdir(dir, sizeof(dir), "refold_from_anchor_fatal", "main");

    /* Build the synthetic anchor snapshot (clean) -> deterministic body SHA3. */
    struct rfa_built snap;
    rfa_build_snapshot(&snap, /*tamper=*/false);

    /* ── FAULT A: wrong-SHA3 snapshot (tampered body) + empty node.db. ─────── */
    {
        char fdir[300], snap_path[400], errlog[460];
        snprintf(fdir, sizeof(fdir), "%s/faultA", dir);
        mkdir(fdir, 0755);
        snprintf(snap_path, sizeof(snap_path), "%s/utxo-anchor.snapshot", fdir);
        snprintf(errlog, sizeof(errlog), "%s/child_stderr.log", fdir);
        /* Each child derives the snapshot path the same way the reset does:
         * point ZCL_MINT_ANCHOR_OUT at THIS fault's snapshot. The child
         * inherits this env across fork. */
        setenv("ZCL_MINT_ANCHOR_OUT", snap_path, 1);

        struct rfa_built bad = snap;
        rfa_build_snapshot(&bad, /*tamper=*/true);  /* on-disk body != header root */

        struct sha3_utxo_checkpoint cp;
        memset(&cp, 0, sizeof(cp));
        cp.height = 1234;
        memcpy(cp.sha3_hash, bad.body_sha3, 32);  /* header root == checkpoint */
        cp.utxo_count = bad.count;
        cp.total_supply = bad.total;

        int status = 0;
        bool ran = rfa_run_child(fdir, snap_path, errlog, RFA_WRONG_SHA3,
                                 &bad, &cp, &status);
        RFA_CHECK("A: child ran", ran);
        RFA_CHECK("A: child FATALed (WIFEXITED && WEXITSTATUS==EXIT_FAILURE)",
                  ran && WIFEXITED(status) && WEXITSTATUS(status) == EXIT_FAILURE);
        char buf[8192];
        long n = rfa_slurp(errlog, buf, sizeof(buf));
        RFA_CHECK("A: NAMED banner on stderr (SHA3/count check failed)",
                  n > 0 &&
                  strstr(buf, "re-seeded anchor set FAILED the "
                              "SHA3/count check") != NULL &&
                  strstr(buf, "refusing to fold from an unproven anchor") != NULL);
    }

    /* ── FAULT B: wrong-COUNT snapshot (clean SHA3, cp->utxo_count mismatched). */
    {
        char fdir[300], snap_path[400], errlog[460];
        snprintf(fdir, sizeof(fdir), "%s/faultB", dir);
        mkdir(fdir, 0755);
        snprintf(snap_path, sizeof(snap_path), "%s/utxo-anchor.snapshot", fdir);
        snprintf(errlog, sizeof(errlog), "%s/child_stderr.log", fdir);
        setenv("ZCL_MINT_ANCHOR_OUT", snap_path, 1);

        struct sha3_utxo_checkpoint cp;
        memset(&cp, 0, sizeof(cp));
        cp.height = 1234;
        memcpy(cp.sha3_hash, snap.body_sha3, 32);
        cp.utxo_count = snap.count + 1;   /* count guard rejects the snapshot */
        cp.total_supply = snap.total;

        int status = 0;
        bool ran = rfa_run_child(fdir, snap_path, errlog, RFA_WRONG_COUNT,
                                 &snap, &cp, &status);
        RFA_CHECK("B: child ran", ran);
        RFA_CHECK("B: child FATALed (count mismatch)",
                  ran && WIFEXITED(status) && WEXITSTATUS(status) == EXIT_FAILURE);
        char buf[8192];
        long n = rfa_slurp(errlog, buf, sizeof(buf));
        RFA_CHECK("B: NAMED banner on stderr",
                  n > 0 && strstr(buf, "re-seeded anchor set FAILED the "
                                       "SHA3/count check") != NULL);
    }

    /* ── FAULT C: truncated snapshot (header short read). ──────────────────── */
    {
        char fdir[300], snap_path[400], errlog[460];
        snprintf(fdir, sizeof(fdir), "%s/faultC", dir);
        mkdir(fdir, 0755);
        snprintf(snap_path, sizeof(snap_path), "%s/utxo-anchor.snapshot", fdir);
        snprintf(errlog, sizeof(errlog), "%s/child_stderr.log", fdir);
        setenv("ZCL_MINT_ANCHOR_OUT", snap_path, 1);

        struct sha3_utxo_checkpoint cp;
        memset(&cp, 0, sizeof(cp));
        cp.height = 1234;
        memcpy(cp.sha3_hash, snap.body_sha3, 32);
        cp.utxo_count = snap.count;
        cp.total_supply = snap.total;

        int status = 0;
        bool ran = rfa_run_child(fdir, snap_path, errlog, RFA_TRUNCATED,
                                 &snap, &cp, &status);
        RFA_CHECK("C: child ran", ran);
        RFA_CHECK("C: child FATALed (truncated snapshot)",
                  ran && WIFEXITED(status) && WEXITSTATUS(status) == EXIT_FAILURE);
        char buf[8192];
        long n = rfa_slurp(errlog, buf, sizeof(buf));
        RFA_CHECK("C: NAMED banner on stderr",
                  n > 0 && strstr(buf, "re-seeded anchor set FAILED the "
                                       "SHA3/count check") != NULL);
    }

    /* ── POSITIVE control (in-process, no fork): a MATCHING snapshot makes the
     * reset return normally and coins_kv become the proven authority at anchor+1.
     * Proves the gate is reachable + advances ONLY on a proven set. */
    {
        char pdir[300];
        snprintf(pdir, sizeof(pdir), "%s/pos", dir);
        mkdir(pdir, 0755);
        char psnap[400];
        snprintf(psnap, sizeof(psnap), "%s/utxo-anchor.snapshot", pdir);
        setenv("ZCL_MINT_ANCHOR_OUT", psnap, 1);
        RFA_CHECK("pos: matching snapshot written",
                  rfa_write_n(psnap, &snap, snap.file_len));

        struct sha3_utxo_checkpoint cp;
        memset(&cp, 0, sizeof(cp));
        cp.height = 1234;
        memcpy(cp.sha3_hash, snap.body_sha3, 32);
        cp.utxo_count = snap.count;
        cp.total_supply = snap.total;
        checkpoints_set_sha3_override_for_test(&cp);

        progress_store_close();
        RFA_CHECK("pos: progress store opens", progress_store_open(pdir));
        sqlite3 *pk = progress_store_db();
        RFA_CHECK("pos: coins_kv schema", pk && coins_kv_ensure_schema(pk));

        char pdbpath[420];
        snprintf(pdbpath, sizeof(pdbpath), "%s/node.db", pdir);
        struct node_db ndb;
        RFA_CHECK("pos: node_db opens", node_db_open(&ndb, pdbpath));

        boot_refold_from_anchor_reset(&ndb);

        int32_t applied = -1;
        RFA_CHECK("pos: coins_kv is proven authority after a clean reset",
                  pk && coins_kv_is_proven_authority(pk, &applied));
        RFA_CHECK("pos: applied frontier == anchor+1 (advanced only on proven set)",
                  applied == cp.height + 1);
        RFA_CHECK("pos: self-folded provenance marker set",
                  coins_kv_contains_refold_marker(pk));
        {
            char reason[96] = {0};
            RFA_CHECK("pos: tip is self-derived after minted snapshot reset",
                      coins_kv_tip_is_self_derived(pk, cp.height, reason,
                                                    sizeof(reason)));
        }

        checkpoints_reset_sha3_override_for_test();
        node_db_close(&ndb);
        progress_store_close();
    }

    /* ── teardown ──────────────────────────────────────────────────────────── */
    unsetenv("ZCL_MINT_ANCHOR_OUT");
    test_cleanup_tmpdir(dir);
    return failures;
}
#else  /* _WIN32 */
/* Windows has no fork()/waitpid process model; this group's fork crash-window refold lane
 * cannot run here. Skipped loudly rather than faked. */
static int test_refold_from_anchor_fatal_platform_arm(void)
{
    printf("refold_from_anchor_fatal: SKIP (Windows): fork crash-window refold lane\n");
    return 0;
}
#endif

int test_refold_from_anchor_fatal(void)
{
    return test_refold_from_anchor_fatal_platform_arm();
}
