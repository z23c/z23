/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * test_anchor_selfmint — the in-fold SELF-MINT snapshot-reachability gate.
 *
 * The load-bearing property: when the staged fold first lands the compiled SHA3
 * UTXO checkpoint height, the self-mint hook PERSISTS the live coins_kv set to
 * <datadir>/utxo-anchor.snapshot — and ONLY a snapshot whose recomputed body
 * SHA3 EQUALS the compiled checkpoint is left on disk. After the hook fires the
 * artifact is VERIFIED-REACHABLE: uss_open(verify_full_sha3, expected_sha3 =
 * cp->sha3_hash) opens it and its count matches the checkpoint — exactly what the
 * torn-import self-heal (boot_anchor_seed_from_snapshot) needs to re-seed from.
 *
 *   (1) BELOW the anchor (next_cursor != cp->height) → NO file written (the hook
 *       only mints at the exact anchor crossing).
 *   (2) AT the anchor (next_cursor == cp->height) → a SHA3-verified snapshot is
 *       written; uss_open(.,expected=cp) opens it and count == checkpoint.
 *   (3) IDEMPOTENT: a second call at the anchor leaves the same file untouched
 *       (same mtime/size) — no needless rewrite.
 *   (4) MISMATCH: if the live set does NOT reproduce the checkpoint (wrong
 *       override root), the hook writes then HARD-VERIFY UNLINKS it → no
 *       unverified artifact is ever left for a later -refold-from-anchor to load.
 *
 * The fixture lowers the compiled anchor via the test override and seeds a tiny
 * coins_kv whose REAL commitment IS the override root, so the production hook
 * runs identically at a handful of rows instead of 1.35 M.
 */

#include "test/test_core.h"

#include "config/boot_snapshot_install.h"
#include "services/anchor_selfmint.h"
#include "storage/progress_store.h"
#include "storage/coins_kv.h"
#include "storage/snapshot_shielded.h"
#include "chain/checkpoints.h"
#include "chain/utxo_snapshot_loader.h"

#include <sqlite3.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#define SM_CHECK(name, expr) do {                                          \
    if (expr) { printf("  anchor_selfmint: %s... OK\n", (name)); }          \
    else { printf("  anchor_selfmint: %s... FAIL\n", (name)); failures++; } \
} while (0)

#define TEST_ANCHOR ((int32_t)777)

/* Seed a few deterministic coins into coins_kv. */
static bool sm_seed_coins(sqlite3 *db)
{
    for (int i = 0; i < 5; i++) {
        uint8_t txid[32];
        for (int j = 0; j < 32; j++) txid[j] = (uint8_t)(0x10 + i * 7 + j);
        uint8_t script[5] = { 0x76, 0xa9, 0x14, (uint8_t)i, 0x88 };
        if (!coins_kv_add(db, txid, /*vout=*/(uint32_t)i,
                          /*value=*/100000 + i, /*height=*/i + 1,
                          /*is_coinbase=*/i == 0, script, sizeof(script)))
            return false;
    }
    return true;
}

static bool sm_file_present(const char *path)
{
    struct stat st;
    return stat(path, &st) == 0;
}

/* Open the progress store, install the coins_kv schema and seed the fixture
 * rows. */
static int sm_open_store_and_seed_coins(const char *dir, sqlite3 **pdb_out)
{
    int failures = 0;
    SM_CHECK("progress_store opens", progress_store_open(dir));
    sqlite3 *pdb = progress_store_db();
    SM_CHECK("pdb handle", pdb != NULL);
    SM_CHECK("coins_kv schema", coins_kv_ensure_schema(pdb));
    /* Seed coins_kv and compute its REAL commitment — the override checkpoint
     * will carry exactly this root + count + the test anchor height. */
    SM_CHECK("seed coins", sm_seed_coins(pdb));
    *pdb_out = pdb;
    return failures;
}

/* Compute the seeded set's REAL commitment and install it — with the test
 * anchor height — as the compiled-checkpoint override. */
static int sm_install_override_checkpoint(
    sqlite3 *pdb, struct sha3_utxo_checkpoint *cp_ovr)
{
    int failures = 0;
    uint8_t real_root[32] = {0};
    SM_CHECK("commitment computed", coins_kv_commitment(pdb, real_root) == 0);
    int64_t num_txs = 0, real_count = 0, supply = 0;
    SM_CHECK("setinfo", coins_kv_setinfo(pdb, &num_txs, &real_count, &supply));

    memset(cp_ovr, 0, sizeof(*cp_ovr));
    cp_ovr->height = TEST_ANCHOR;
    memcpy(cp_ovr->sha3_hash, real_root, 32);
    cp_ovr->utxo_count = (uint64_t)real_count;
    cp_ovr->total_supply = supply;
    checkpoints_set_sha3_override_for_test(cp_ovr);
    return failures;
}

/* Sanity: the resolver returns the env path. */
static int sm_check_resolve_path_honors_env(const char *snap_path)
{
    int failures = 0;
    char resolved[400];
    bool ok = anchor_selfmint_resolve_path(NULL, resolved, sizeof(resolved));
    SM_CHECK("resolve_path honors env",
             ok && strcmp(resolved, snap_path) == 0);
    return failures;
}

/* (1) BELOW the anchor → no mint. */
static int sm_check_below_anchor_no_mint(sqlite3 *pdb, const char *dir,
                                         const char *snap_path)
{
    int failures = 0;
    anchor_selfmint_hook_in_tx(pdb, dir, TEST_ANCHOR - 1);
    SM_CHECK("(1) below anchor → no snapshot", !sm_file_present(snap_path));
    {
        struct anchor_snapshot_status st;
        bool ok = anchor_selfmint_snapshot_status(dir, &st);
        SM_CHECK("(1) status reports missing candidate",
                 ok && !st.verified && st.path_resolved &&
                 strcmp(st.path, snap_path) == 0 &&
                 strcmp(st.verification, "missing") == 0);
    }
    return failures;
}

/* (2) AT the anchor → a SHA3-verified snapshot is written + reachable. */
static int sm_check_at_anchor_mints_verified_snapshot(
    sqlite3 *pdb, const char *dir, const char *snap_path)
{
    int failures = 0;
    anchor_selfmint_hook_in_tx(pdb, dir, TEST_ANCHOR);
    SM_CHECK("(2) at anchor → snapshot written", sm_file_present(snap_path));
    {
        char err[128] = {0};
        struct uss_header hdr;
        const struct sha3_utxo_checkpoint *cp = get_sha3_utxo_checkpoint();
        struct uss_handle *h = uss_open(snap_path, /*verify_full_sha3=*/true,
                                        cp->sha3_hash, &hdr, err, sizeof(err));
        SM_CHECK("(2) uss_open verifies vs checkpoint root", h != NULL);
        if (h) {
            SM_CHECK("(2) snapshot count == checkpoint",
                     hdr.count == cp->utxo_count);
            SM_CHECK("(2) snapshot height == anchor",
                     (int32_t)hdr.height == cp->height);
            uss_close(h);
        }
    }
    return failures;
}

/* (2, cont.) the status predicate reports the snapshot as refold-ready. */
static int sm_check_at_anchor_status_verified(const char *dir)
{
    int failures = 0;
    struct anchor_snapshot_status st;
    bool ok = anchor_selfmint_snapshot_status(dir, &st);
    SM_CHECK("(2) status verifies snapshot readiness",
             ok && st.verified && st.header_read &&
             st.checkpoint_height == TEST_ANCHOR &&
             (int32_t)st.snapshot_height == TEST_ANCHOR &&
             st.count_match && st.sha3_match &&
             strcmp(st.verification, "verified") == 0 &&
             strstr(st.next_action, "-refold-from-anchor") != NULL);
    return failures;
}

/* (3) IDEMPOTENT: a second call at the anchor does NOT rewrite the file. */
static int sm_check_second_hook_call_is_idempotent(
    sqlite3 *pdb, const char *dir, const char *snap_path)
{
    int failures = 0;
    struct stat before, after;
    bool sb = stat(snap_path, &before) == 0;
    /* Bump mtime granularity isn't guaranteed; assert size + inode stable +
     * still verified. The hook short-circuits on verified_snapshot_present
     * BEFORE any write, so the file is byte-identical. */
    anchor_selfmint_hook_in_tx(pdb, dir, TEST_ANCHOR);
    bool sa = stat(snap_path, &after) == 0;
    SM_CHECK("(3) idempotent: file still present",
             sb && sa && before.st_size == after.st_size &&
             before.st_ino == after.st_ino);
    return failures;
}

/* Write the seeded coins plus a shielded section. One nullifier record forces
 * the v3 on-disk format (nf_count > 0). */
static bool sm_write_v3_sha3(sqlite3 *pdb, const char *path,
                             const struct sha3_utxo_checkpoint *cp,
                             uint8_t got_sha3[32])
{
    uint8_t nf[32];
    for (int j = 0; j < 32; j++) nf[j] = (uint8_t)(0xA0 + j);
    uint8_t nf_rec[SNAPSHOT_NF_RECORD_BYTES];
    snapshot_shielded_pack_nf(nf_rec, /*pool=*/0, nf, /*height=*/1);
    struct snapshot_shielded sh;
    memset(&sh, 0, sizeof(sh));
    sh.nf_records = nf_rec;
    sh.nf_count = 1;

    uint64_t got_count = 0;
    int64_t got_supply = 0;
    return coins_kv_snapshot_write(pdb, path, cp->height, cp->block_hash, &sh,
                                   got_sha3, &got_count, &got_supply);
}

static bool sm_write_v3(sqlite3 *pdb, const char *path,
                        const struct sha3_utxo_checkpoint *cp)
{
    uint8_t got_sha3[32] = {0};
    return sm_write_v3_sha3(pdb, path, cp, got_sha3);
}

/* (5) v3 ACCEPTANCE: a valid v3 artifact carries the same coins set as
 * the checkpoint plus a shielded section, so its full-body header SHA3
 * (coins+shielded) never equals the coins-only checkpoint hash. Admission
 * must recompute the COINS-ONLY component and bind THAT to the
 * checkpoint. The override is still the correct root here (step 4 changes
 * it below). */
static int sm_check_v3_artifact_written(sqlite3 *pdb, const char *dir,
                                        char *v3_path, size_t v3_path_size)
{
    int failures = 0;
    snprintf(v3_path, v3_path_size, "%s/utxo-anchor-v3.snapshot", dir);
    setenv("ZCL_MINT_ANCHOR_OUT", v3_path, 1);
    unlink(v3_path);

    const struct sha3_utxo_checkpoint *cp = get_sha3_utxo_checkpoint();
    uint8_t got_sha3[32] = {0};
    bool wrote = sm_write_v3_sha3(pdb, v3_path, cp, got_sha3);
    SM_CHECK("(5) v3 artifact written", wrote && sm_file_present(v3_path));
    SM_CHECK("(5) v3 body sha3 != coins-only checkpoint",
             memcmp(got_sha3, cp->sha3_hash, 32) != 0);
    return failures;
}

/* (5, cont.) admission of the valid v3 artifact must bind the recomputed
 * coins-only SHA3 to the checkpoint, not the full-body header hash. */
static int sm_check_v3_admission_binds_coins_only(const char *dir,
                                                  const char *v3_path,
                                                  const char *snap_path)
{
    int failures = 0;
    const struct sha3_utxo_checkpoint *cp = get_sha3_utxo_checkpoint();

    /* Comparing uss_open(expected_sha3 = coins-only cp) would reject the
     * valid v3 artifact; admission must not use that predicate. */
    {
        char err[128] = {0};
        struct uss_header vh;
        struct uss_handle *bad =
            uss_open(v3_path, /*verify_full_sha3=*/true, cp->sha3_hash, &vh,
                     err, sizeof(err));
        SM_CHECK("(5) old expected=cp predicate rejects v3", bad == NULL);
        if (bad) uss_close(bad);
    }

    /* The CORRECTED status predicate ACCEPTS the valid v3 artifact. */
    {
        struct anchor_snapshot_status st;
        bool ok = anchor_selfmint_snapshot_status(dir, &st);
        SM_CHECK("(5) status ACCEPTS valid v3 artifact",
                 ok && st.verified && st.sha3_match && st.count_match &&
                 (int32_t)st.snapshot_height == TEST_ANCHOR &&
                 strcmp(st.verification, "verified") == 0);
    }

    unlink(v3_path);
    /* Restore the coins-only env path for the mismatch step below. */
    setenv("ZCL_MINT_ANCHOR_OUT", snap_path, 1);
    return failures;
}

/* (4) MISMATCH: install a WRONG checkpoint root (same anchor height so the
 * hook still fires). The hook writes the real coins set, HARD-VERIFY finds
 * SHA3 != the (wrong) checkpoint, and UNLINKS — no unverified artifact left. */
static int sm_check_mismatch_unlinks_artifact(
    sqlite3 *pdb, const char *dir, const char *snap_path,
    const struct sha3_utxo_checkpoint *cp_ovr)
{
    int failures = 0;
    unlink(snap_path);
    struct sha3_utxo_checkpoint cp_wrong = *cp_ovr;
    cp_wrong.sha3_hash[0] ^= 0xff;   /* now coins_kv root != checkpoint root */
    checkpoints_set_sha3_override_for_test(&cp_wrong);
    anchor_selfmint_hook_in_tx(pdb, dir, TEST_ANCHOR);
    SM_CHECK("(4) mismatch → no artifact left (write+unlink)",
             !sm_file_present(snap_path));
    return failures;
}


/* ------------------------------------------------------------------------
 * Mutation-gap cases. The hook decides what state a node may trust, so these
 * pin: when a mint is refused, which values the status binds to, and what the
 * status reports for missing or inconsistent input.
 * ------------------------------------------------------------------------ */

#define SM_ENV "ZCL_MINT_ANCHOR_OUT"

struct sm_fix {
    sqlite3 *pdb;
    const char *dir;
    char path[400];
    struct sha3_utxo_checkpoint cp;
};

static void sm_hex(const uint8_t *in, char out[65])
{
    for (int i = 0; i < 32; i++)
        snprintf(out + 2 * i, 3, "%02x", in[i]);
}

static bool sm_hex_is(const char *got, const uint8_t *bytes)
{
    char want[65];
    sm_hex(bytes, want);
    return strlen(got) == 64 && strcmp(got, want) == 0;
}

static bool sm_resolve(const char *datadir, size_t cap, char *buf)
{
    return anchor_selfmint_resolve_path(datadir, buf, cap);
}

static bool sm_write_bytes(const char *path, const char *data, size_t n)
{
    FILE *f = fopen(path, "wb");
    if (!f)
        return false;
    bool ok = n == 0 || fwrite(data, 1, n, f) == n;
    return fclose(f) == 0 && ok;
}

static bool sm_flip_last_byte(const char *path)
{
    FILE *f = fopen(path, "r+b");
    if (!f)
        return false;
    int c = 0;
    bool ok = fseek(f, -1, SEEK_END) == 0 && (c = fgetc(f)) != EOF &&
              fseek(f, -1, SEEK_END) == 0 && fputc(c ^ 0xff, f) != EOF;
    return fclose(f) == 0 && ok;
}

/* The resolver, env path: the buffer must hold the path plus its NUL. */
static int sm_case_resolve_env_bounds(void)
{
    int failures = 0;
    char buf[64];
    setenv(SM_ENV, "x", 1);
    SM_CHECK("resolve: 1-char env path fits cap 2",
             sm_resolve("ignored", 2, buf) && strcmp(buf, "x") == 0);
    memset(buf, 'S', sizeof(buf));
    SM_CHECK("resolve: env path length == cap is refused",
             !sm_resolve("ignored", 1, buf) && buf[0] == '\0');
    setenv(SM_ENV, "xy", 1);
    SM_CHECK("resolve: 2-char env path fits cap 3",
             sm_resolve("ignored", 3, buf) && strcmp(buf, "xy") == 0);
    SM_CHECK("resolve: 2-char env path refused at cap 2",
             !sm_resolve("ignored", 2, buf));
    memset(buf, 'S', sizeof(buf));
    SM_CHECK("resolve: cap 0 refused, buffer untouched",
             !sm_resolve("ignored", 0, buf) && buf[0] == 'S');
    SM_CHECK("resolve: NULL buffer refused", !sm_resolve("d", 16, NULL));
    return failures;
}

/* The resolver, datadir path (env unset or empty). */
static int sm_case_resolve_datadir_bounds(void)
{
    int failures = 0;
    char buf[64];
    const char *want = "d/utxo-anchor.snapshot";
    size_t len = strlen(want);
    unsetenv(SM_ENV);
    SM_CHECK("resolve: 1-char datadir fits at cap len+1",
             sm_resolve("d", len + 1, buf) && strcmp(buf, want) == 0);
    SM_CHECK("resolve: datadir path length == cap is refused",
             !sm_resolve("d", len, buf));
    SM_CHECK("resolve: NULL datadir means the current directory",
             sm_resolve(NULL, sizeof(buf), buf) &&
             strcmp(buf, "./utxo-anchor.snapshot") == 0);
    SM_CHECK("resolve: empty datadir means the current directory",
             sm_resolve("", sizeof(buf), buf) &&
             strcmp(buf, "./utxo-anchor.snapshot") == 0);
    setenv(SM_ENV, "", 1);
    SM_CHECK("resolve: empty env falls back to the datadir",
             sm_resolve("d", sizeof(buf), buf) && strcmp(buf, want) == 0);
    return failures;
}

/* An unresolvable path is reported, not an error return. */
static int sm_case_status_unresolved(void)
{
    int failures = 0;
    static char longp[1300];
    memset(longp, 'a', 1200);
    longp[0] = '/';
    longp[1200] = '\0';
    setenv(SM_ENV, longp, 1);
    struct anchor_snapshot_status st;
    SM_CHECK("status: unresolvable path still returns true",
             anchor_selfmint_snapshot_status("unused", &st));
    SM_CHECK("status: unresolvable path is classified",
             !st.path_resolved && !st.verified && !st.checkpoint_present &&
             strcmp(st.verification, "path_unresolved") == 0);
    SM_CHECK("status: unresolvable path error text",
             strcmp(st.error, "could not resolve anchor snapshot path") == 0);
    SM_CHECK("status: unresolvable path next action",
             strcmp(st.next_action,
                    "fix datadir or ZCL_MINT_ANCHOR_OUT path") == 0);
    SM_CHECK("status: path source names the env var",
             strcmp(st.path_source, SM_ENV) == 0);
    SM_CHECK("status: NULL out is refused",
             !anchor_selfmint_snapshot_status("unused", NULL));
    return failures;
}

/* path_source: env var only when it is set and non-empty. */
static int sm_case_status_path_source(const char *dir)
{
    int failures = 0;
    char sub[300];
    snprintf(sub, sizeof(sub), "%s/empty", dir);
    SM_CHECK("path_source: scratch dir", mkdir(sub, 0700) == 0);
    struct anchor_snapshot_status st;
    unsetenv(SM_ENV);
    SM_CHECK("path_source: unset env reports datadir",
             anchor_selfmint_snapshot_status(sub, &st) &&
             strcmp(st.path_source, "datadir") == 0);
    char want[400];
    snprintf(want, sizeof(want), "%s/utxo-anchor.snapshot", sub);
    SM_CHECK("path_source: datadir path is derived from the datadir",
             strcmp(st.path, want) == 0 && st.path_resolved);
    setenv(SM_ENV, "", 1);
    SM_CHECK("path_source: empty env reports datadir",
             anchor_selfmint_snapshot_status(sub, &st) &&
             strcmp(st.path_source, "datadir") == 0);
    setenv(SM_ENV, "x", 1);
    SM_CHECK("path_source: 1-char env reports the env var",
             anchor_selfmint_snapshot_status(sub, &st) &&
             strcmp(st.path_source, SM_ENV) == 0);
    rmdir(sub);
    return failures;
}

static bool sm_cp_fields_match(const struct anchor_snapshot_status *st,
                               const struct sha3_utxo_checkpoint *cp)
{
    return st->checkpoint_present && st->checkpoint_height == cp->height &&
           st->checkpoint_utxo_count == cp->utxo_count &&
           st->checkpoint_total_supply == cp->total_supply &&
           sm_hex_is(st->checkpoint_sha3_hex, cp->sha3_hash) &&
           sm_hex_is(st->checkpoint_block_hash_hex, cp->block_hash);
}

static bool sm_status_is(const struct anchor_snapshot_status *st,
                         const char *verification, bool present, int64_t size)
{
    return !st->verified && !st->header_read &&
           st->stat_present == present && st->stat_size == size &&
           strcmp(st->verification, verification) == 0;
}

static bool sm_next_is(const struct anchor_snapshot_status *st,
                       const char *fmt, const char *path)
{
    char want[300];
    snprintf(want, sizeof(want), fmt, path);
    return strcmp(st->next_action, want) == 0;
}

/* A candidate that is absent, empty or not a regular file is "missing" and
 * is never reported as present. */
static int sm_case_status_absent_forms(struct sm_fix *f)
{
    int failures = 0;
    struct anchor_snapshot_status st;
    setenv(SM_ENV, f->path, 1);
    unlink(f->path);
    SM_CHECK("absent: status returns true",
             anchor_selfmint_snapshot_status(f->dir, &st));
    SM_CHECK("absent: classified missing, checkpoint reported",
             sm_status_is(&st, "missing", false, 0) &&
             sm_cp_fields_match(&st, &f->cp));
    SM_CHECK("absent: error and next action",
             strcmp(st.error, "anchor snapshot candidate is absent") == 0 &&
             sm_next_is(&st, "mint or stage %.180s, then run refold copy proof",
                        f->path));
    SM_CHECK("absent: empty file is missing, not present",
             sm_write_bytes(f->path, "", 0) &&
             anchor_selfmint_snapshot_status(f->dir, &st) &&
             sm_status_is(&st, "missing", false, 0));
    unlink(f->path);
    SM_CHECK("absent: a directory is missing, not present",
             mkdir(f->path, 0700) == 0 &&
             anchor_selfmint_snapshot_status(f->dir, &st) &&
             sm_status_is(&st, "missing", false, 0));
    rmdir(f->path);
    return failures;
}

/* A file too short to carry a header is present but unreadable. */
static int sm_case_status_header_unreadable(struct sm_fix *f)
{
    int failures = 0;
    struct anchor_snapshot_status st;
    setenv(SM_ENV, f->path, 1);
    SM_CHECK("unreadable: 1-byte file written",
             sm_write_bytes(f->path, "x", 1));
    SM_CHECK("unreadable: status returns true and is not verified",
             anchor_selfmint_snapshot_status(f->dir, &st) &&
             sm_status_is(&st, "header_unreadable", true, 1));
    SM_CHECK("unreadable: error names a cause, next action names the path",
             st.error[0] != '\0' &&
             sm_next_is(&st, "replace %.180s with a minted checkpoint snapshot",
                        f->path));
    unlink(f->path);
    return failures;
}

static void sm_mint(struct sm_fix *f)
{
    setenv(SM_ENV, f->path, 1);
    unlink(f->path);
    anchor_selfmint_hook_in_tx(f->pdb, f->dir, f->cp.height);
}

/* The predicate every boot path applies before it loads an anchor artifact. */
static bool sm_boot_gate_accepts(const struct sm_fix *f)
{
    char err[128] = {0};
    struct uss_header hdr;
    struct uss_handle *h = uss_open(f->path, /*verify_full_sha3=*/true,
                                    /*expected_sha3=*/NULL, &hdr, err,
                                    sizeof(err));
    if (!h)
        return false;
    bool ok = boot_legacy_uss_matches_checkpoint(h, &hdr, &f->cp, err,
                                                 sizeof(err));
    uss_close(h);
    return ok;
}

/* A refusal names its cause and tells the operator to replace the file. It must
 * not point at -refold-from-anchor. */
static bool sm_refused_as(const struct anchor_snapshot_status *st,
                          const struct sm_fix *f, const char *verification,
                          const char *error)
{
    char want[300];
    snprintf(want, sizeof(want),
             "replace %.170s with a snapshot minted at checkpoint height %d",
             f->path, f->cp.height);
    return !st->verified && strcmp(st->verification, verification) == 0 &&
           strcmp(st->error, error) == 0 &&
           strcmp(st->next_action, want) == 0;
}

static bool sm_header_fields_match(const struct anchor_snapshot_status *st,
                                   const struct sha3_utxo_checkpoint *cp)
{
    return st->header_read && st->snapshot_height == (uint32_t)cp->height &&
           st->snapshot_count == cp->utxo_count &&
           st->snapshot_total_supply == cp->total_supply &&
           sm_hex_is(st->snapshot_sha3_hex, cp->sha3_hash) &&
           sm_hex_is(st->snapshot_block_hash_hex, cp->block_hash);
}

static bool sm_all_bound(const struct anchor_snapshot_status *st)
{
    return st->height_match && st->count_match && st->sha3_match &&
           st->block_hash_match && st->verified;
}

/* A minted snapshot is bound to the checkpoint on every axis. */
static int sm_case_status_minted_fields(struct sm_fix *f)
{
    int failures = 0;
    struct anchor_snapshot_status st;
    struct stat sb;
    sm_mint(f);
    SM_CHECK("minted: file stat succeeds", stat(f->path, &sb) == 0);
    SM_CHECK("minted: status returns true",
             anchor_selfmint_snapshot_status(f->dir, &st));
    SM_CHECK("minted: header and checkpoint fields are reported",
             sm_header_fields_match(&st, &f->cp) &&
             sm_cp_fields_match(&st, &f->cp));
    SM_CHECK("minted: every binding matches and the file is verified",
             sm_all_bound(&st) && st.stat_present &&
             st.stat_size == (int64_t)sb.st_size);
    SM_CHECK("minted: the boot gate accepts what the status verified",
             sm_boot_gate_accepts(f));
    return failures;
}

/* A checkpoint whose block hash differs only in its last byte. */
static int sm_case_variant_block_hash(struct sm_fix *f)
{
    int failures = 0;
    struct anchor_snapshot_status st;
    f->cp.block_hash[31] ^= 0x01;
    bool ok = anchor_selfmint_snapshot_status(f->dir, &st);
    SM_CHECK("variant block hash: only the block-hash binding fails",
             ok && !st.block_hash_match && st.height_match &&
             st.count_match && st.sha3_match);
    SM_CHECK("variant block hash: hex fields show both hashes",
             sm_hex_is(st.checkpoint_block_hash_hex, f->cp.block_hash) &&
             strcmp(st.checkpoint_block_hash_hex,
                    st.snapshot_block_hash_hex) != 0);
    SM_CHECK("variant block hash: refused, not ready for a refold",
             sm_refused_as(&st, f, "block_hash_mismatch",
                           "snapshot block hash does not match checkpoint"));
    SM_CHECK("variant block hash: the boot gate refuses it too",
             !sm_boot_gate_accepts(f));
    f->cp.block_hash[31] ^= 0x01;
    return failures;
}

/* A checkpoint at another height than the snapshot header. */
static int sm_case_variant_height(struct sm_fix *f)
{
    int failures = 0;
    struct anchor_snapshot_status st;
    f->cp.height += 1;
    bool ok = anchor_selfmint_snapshot_status(f->dir, &st);
    SM_CHECK("variant height: height binding fails, others hold",
             ok && !st.height_match && st.count_match && st.sha3_match &&
             st.block_hash_match);
    SM_CHECK("variant height: both heights are reported",
             st.checkpoint_height == TEST_ANCHOR + 1 &&
             st.snapshot_height == (uint32_t)TEST_ANCHOR);
    SM_CHECK("variant height: refused, not ready for a refold",
             sm_refused_as(&st, f, "height_mismatch",
                           "snapshot height does not match checkpoint"));
    SM_CHECK("variant height: the boot gate refuses it too",
             !sm_boot_gate_accepts(f));
    f->cp.height -= 1;
    return failures;
}

/* The coins-only commitment matches but the count differs by one. */
static int sm_case_variant_count(struct sm_fix *f)
{
    int failures = 0;
    struct anchor_snapshot_status st;
    f->cp.utxo_count += 1;
    bool ok = anchor_selfmint_snapshot_status(f->dir, &st);
    SM_CHECK("variant count: count fails, sha3 holds, not verified",
             ok && !st.count_match && st.sha3_match && !st.verified &&
             strcmp(st.verification, "count_mismatch") == 0);
    SM_CHECK("variant count: error text",
             strcmp(st.error, "snapshot count does not match checkpoint") == 0);
    char want[300];
    snprintf(want, sizeof(want),
             "replace %.170s with a snapshot minted at checkpoint height %d",
             f->path, f->cp.height);
    SM_CHECK("variant count: next action", strcmp(st.next_action, want) == 0);
    f->cp.utxo_count -= 1;
    return failures;
}

/* The count matches but the commitment differs in its LAST byte only. */
static int sm_case_variant_sha3(struct sm_fix *f)
{
    int failures = 0;
    struct anchor_snapshot_status st;
    f->cp.sha3_hash[31] ^= 0x01;
    bool ok = anchor_selfmint_snapshot_status(f->dir, &st);
    SM_CHECK("variant sha3: sha3 fails, count holds, not verified",
             ok && !st.sha3_match && st.count_match && !st.verified &&
             strcmp(st.verification, "sha3_mismatch") == 0);
    SM_CHECK("variant sha3: error text",
             strcmp(st.error,
                    "coins-only commitment does not match checkpoint") == 0);
    char want[300];
    snprintf(want, sizeof(want),
             "replace %.170s with a snapshot minted at checkpoint height %d",
             f->path, f->cp.height);
    SM_CHECK("variant sha3: next action", strcmp(st.next_action, want) == 0);
    f->cp.sha3_hash[31] ^= 0x01;
    return failures;
}

/* A snapshot whose body was altered after minting: the header still reads,
 * but the artifact is refused as failing full verification. */
static int sm_case_status_corrupt_body(struct sm_fix *f)
{
    int failures = 0;
    struct anchor_snapshot_status st;
    SM_CHECK("corrupt: last byte flipped", sm_flip_last_byte(f->path));
    bool ok = anchor_selfmint_snapshot_status(f->dir, &st);
    SM_CHECK("corrupt: header read but the artifact is not verified",
             ok && st.header_read && !st.verified &&
             strcmp(st.verification, "sha3_or_format_mismatch") == 0);
    SM_CHECK("corrupt: an unverified body claims no count or sha3 match",
             !st.count_match && !st.sha3_match);
    SM_CHECK("corrupt: the header-only flags still report the header",
             st.height_match && st.block_hash_match);
    SM_CHECK("corrupt: error names a cause",
             st.error[0] != '\0');
    SM_CHECK("corrupt: next action",
             sm_next_is(&st,
                        "replace %.180s with a SHA3/count-verified minted "
                        "snapshot", f->path));
    return failures;
}

/* A refused mint leaves no artifact: above the anchor, and when the folded
 * set disagrees with the checkpoint in the last hash byte or in the count. */
static int sm_case_hook_refusals(struct sm_fix *f)
{
    int failures = 0;
    setenv(SM_ENV, f->path, 1);
    unlink(f->path);
    anchor_selfmint_hook_in_tx(f->pdb, f->dir, f->cp.height + 1);
    SM_CHECK("refusal: above the anchor writes nothing",
             !sm_file_present(f->path));
    f->cp.sha3_hash[31] ^= 0x01;
    anchor_selfmint_hook_in_tx(f->pdb, f->dir, f->cp.height);
    SM_CHECK("refusal: last-byte sha3 mismatch leaves no artifact",
             !sm_file_present(f->path));
    f->cp.sha3_hash[31] ^= 0x01;
    f->cp.utxo_count += 1;
    anchor_selfmint_hook_in_tx(f->pdb, f->dir, f->cp.height);
    SM_CHECK("refusal: count mismatch leaves no artifact",
             !sm_file_present(f->path));
    f->cp.utxo_count -= 1;
    return failures;
}

/* A valid snapshot already on disk is later judged against a checkpoint with
 * another count: it must not survive as a verified artifact. */
static int sm_case_hook_removes_stale_valid(struct sm_fix *f)
{
    int failures = 0;
    sm_mint(f);
    SM_CHECK("stale: valid snapshot minted", sm_file_present(f->path));
    f->cp.utxo_count += 1;
    anchor_selfmint_hook_in_tx(f->pdb, f->dir, f->cp.height);
    SM_CHECK("stale: checkpoint count changed, artifact removed",
             !sm_file_present(f->path));
    f->cp.utxo_count -= 1;
    return failures;
}

/* A corrupt file at the path is not "already verified": the hook replaces it
 * with a snapshot that opens under full verification against the checkpoint. */
static int sm_case_hook_replaces_corrupt(struct sm_fix *f)
{
    int failures = 0;
    sm_mint(f);
    SM_CHECK("replace: corrupt the minted file", sm_flip_last_byte(f->path));
    anchor_selfmint_hook_in_tx(f->pdb, f->dir, f->cp.height);
    char err[128] = {0};
    struct uss_header hdr;
    struct uss_handle *h = uss_open(f->path, /*verify_full_sha3=*/true,
                                    f->cp.sha3_hash, &hdr, err, sizeof(err));
    SM_CHECK("replace: file verifies against the checkpoint again", h != NULL);
    if (h)
        uss_close(h);
    unlink(f->path);
    return failures;
}

/* The right coins under another block hash: no boot path will load this file,
 * so the hook must not leave it in place as "already verified". */
static int sm_case_hook_remints_wrong_block_hash(struct sm_fix *f)
{
    int failures = 0;
    struct anchor_snapshot_status st;
    sm_mint(f);
    SM_CHECK("re-mint hash: valid snapshot minted", sm_file_present(f->path));
    if (!sm_file_present(f->path))
        return failures;
    f->cp.block_hash[31] ^= 0x01;
    anchor_selfmint_hook_in_tx(f->pdb, f->dir, f->cp.height);
    bool ok = anchor_selfmint_snapshot_status(f->dir, &st);
    SM_CHECK("re-mint hash: the file now carries the checkpoint hash",
             ok && st.verified &&
             sm_hex_is(st.snapshot_block_hash_hex, f->cp.block_hash));
    SM_CHECK("re-mint hash: the boot gate accepts the replacement",
             sm_boot_gate_accepts(f));
    f->cp.block_hash[31] ^= 0x01;
    unlink(f->path);
    return failures;
}

/* The right coins under another height: same reasoning as the block hash. */
static int sm_case_hook_remints_wrong_height(struct sm_fix *f)
{
    int failures = 0;
    struct anchor_snapshot_status st;
    sm_mint(f);
    SM_CHECK("re-mint height: valid snapshot minted", sm_file_present(f->path));
    if (!sm_file_present(f->path))
        return failures;
    f->cp.height += 1;
    anchor_selfmint_hook_in_tx(f->pdb, f->dir, f->cp.height);
    bool ok = anchor_selfmint_snapshot_status(f->dir, &st);
    SM_CHECK("re-mint height: the file now carries the checkpoint height",
             ok && st.verified && st.snapshot_height == (uint32_t)f->cp.height);
    SM_CHECK("re-mint height: the boot gate accepts the replacement",
             sm_boot_gate_accepts(f));
    f->cp.height -= 1;
    unlink(f->path);
    return failures;
}

/* A valid v3 artifact from -mint-anchor carries a shielded section the hook's
 * coins-only rewrite cannot reproduce. Its full-body hash never equals the
 * coins-only checkpoint, and that must not read as "absent". */
static int sm_case_hook_keeps_valid_v3(struct sm_fix *f)
{
    int failures = 0;
    setenv(SM_ENV, f->path, 1);
    unlink(f->path);
    bool wrote = sm_write_v3(f->pdb, f->path, &f->cp);
    SM_CHECK("keep v3: artifact written", wrote);
    if (!wrote)
        return failures;
    SM_CHECK("keep v3: the boot gate accepts it", sm_boot_gate_accepts(f));
    struct stat before, after;
    bool sb = stat(f->path, &before) == 0;
    anchor_selfmint_hook_in_tx(f->pdb, f->dir, f->cp.height);
    bool sa = stat(f->path, &after) == 0;
    SM_CHECK("keep v3: the hook left the file in place",
             sb && sa && before.st_ino == after.st_ino &&
             before.st_size == after.st_size);
    unlink(f->path);
    return failures;
}

static int sm_status_variant_cases(struct sm_fix *f)
{
    int failures = 0;
    failures += sm_case_variant_block_hash(f);
    failures += sm_case_variant_height(f);
    failures += sm_case_variant_count(f);
    failures += sm_case_variant_sha3(f);
    return failures;
}

static int sm_gap_cases(sqlite3 *pdb, const char *dir, const char *snap_path,
                        const struct sha3_utxo_checkpoint *cp_base,
                        struct sm_fix *f)
{
    int failures = 0;
    f->pdb = pdb;
    f->dir = dir;
    snprintf(f->path, sizeof(f->path), "%s", snap_path);
    f->cp = *cp_base;
    for (int j = 0; j < 32; j++)
        f->cp.block_hash[j] = (uint8_t)(0x40 + 3 * j);
    checkpoints_set_sha3_override_for_test(&f->cp);

    failures += sm_case_resolve_env_bounds();
    failures += sm_case_resolve_datadir_bounds();
    failures += sm_case_status_unresolved();
    failures += sm_case_status_path_source(dir);
    failures += sm_case_status_absent_forms(f);
    failures += sm_case_status_header_unreadable(f);
    failures += sm_case_status_minted_fields(f);
    failures += sm_status_variant_cases(f);
    failures += sm_case_status_corrupt_body(f);
    failures += sm_case_hook_refusals(f);
    failures += sm_case_hook_removes_stale_valid(f);
    failures += sm_case_hook_replaces_corrupt(f);
    failures += sm_case_hook_remints_wrong_block_hash(f);
    failures += sm_case_hook_remints_wrong_height(f);
    failures += sm_case_hook_keeps_valid_v3(f);
    setenv(SM_ENV, snap_path, 1);
    return failures;
}

int test_anchor_selfmint(void);
int test_anchor_selfmint(void)
{
    int failures = 0;
    char dir[256];
    test_make_tmpdir(dir, sizeof(dir), "anchor_selfmint", "main");

    sqlite3 *pdb = NULL;
    failures += sm_open_store_and_seed_coins(dir, &pdb);
    struct sha3_utxo_checkpoint cp_ovr;
    failures += sm_install_override_checkpoint(pdb, &cp_ovr);

    /* Resolve the target path the SAME way production does, via the env override
     * the path-derivation honors (keeps the test off any real datadir). */
    char snap_path[400];
    snprintf(snap_path, sizeof(snap_path), "%s/utxo-anchor.snapshot", dir);
    setenv("ZCL_MINT_ANCHOR_OUT", snap_path, 1);
    unlink(snap_path);

    failures += sm_check_resolve_path_honors_env(snap_path);
    failures += sm_check_below_anchor_no_mint(pdb, dir, snap_path);
    failures += sm_check_at_anchor_mints_verified_snapshot(pdb, dir,
                                                           snap_path);
    failures += sm_check_at_anchor_status_verified(dir);
    failures += sm_check_second_hook_call_is_idempotent(pdb, dir, snap_path);

    char v3_path[400];
    failures += sm_check_v3_artifact_written(pdb, dir, v3_path,
                                             sizeof(v3_path));
    failures += sm_check_v3_admission_binds_coins_only(dir, v3_path,
                                                       snap_path);
    failures += sm_check_mismatch_unlinks_artifact(pdb, dir, snap_path,
                                                   &cp_ovr);

    struct sm_fix fix;
    memset(&fix, 0, sizeof(fix));
    failures += sm_gap_cases(pdb, dir, snap_path, &cp_ovr, &fix);

    /* Teardown. */
    checkpoints_set_sha3_override_for_test(NULL);
    unsetenv("ZCL_MINT_ANCHOR_OUT");
    unlink(snap_path);
    progress_store_close();
    return failures;
}
