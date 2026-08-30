/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * THE RECOVERY COMMAND MUST NOT COST YOU THE WALLET YOU STILL HAVE.
 *
 * `core wallet recovery restore` is the command a person types after
 * something has already gone wrong. Three separate defects made it
 * dangerous in exactly that state, and this file is the proof for each.
 *
 *   1. IT RESET A DAMAGED DATABASE AND CALLED IT SUCCESS.
 *      The commit path opened the target with node_db_open() — the datadir
 *      BOOT CEREMONY: READWRITE|CREATE, then PRAGMA quick_check and, on
 *      failure, db_quarantine_files(), which rename()s node.db, node.db-wal
 *      and node.db-shm aside to node.db.corrupt-<ts> and installs a fresh
 *      empty database. The "this datadir already holds a wallet" refusal
 *      then read the NEW EMPTY database, counted zero keys, and recovered
 *      over the top, answering ok:true / keys_before:0 /
 *      wallet_already_present:false with no mention of the rename. And the
 *      leaf's `datadir` input DEFAULTED TO THE OPERATOR'S LIVE DATADIR. A
 *      damaged node.db is exactly the state in which somebody reaches for a
 *      recovery command.
 *      ASSERTED: a garbage node.db is refused by name, is still there
 *      byte-for-byte under its own name, no node.db.corrupt-* appears, and
 *      the leaf with no datadir at all writes nothing and says why.
 *
 *   2. TWO CONCURRENT RESTORES BOTH SUCCEEDED.
 *      The lock in wallet_restore_datadir_free() takes flock and drops it
 *      immediately, so two restores both read "no wallet here" and both
 *      wrote: 480 keys from two different seeds under one seed row —
 *      verbatim the state the refusal text says it exists to prevent.
 *      ASSERTED: two real concurrent processes, two different valid
 *      phrases, one datadir. Exactly one succeeds, and the keys left behind
 *      all descend from that one's seed and not the other's.
 *
 *   3. IT WROTE PLAINTEXT SPENDING KEYS AND THE MASTER SEED, MODE 0644.
 *      BOOT refuses to mint a wallet whose private keys land on disk in the
 *      clear without an explicit operator decision
 *      (wallet_at_rest_boot_decision). This command installed the whole
 *      wallet — every spending key AND the seed they all descend from —
 *      with no passphrase, no opt-in, and no warning. One command in the
 *      tree enforcing the policy and another ignoring it means the policy
 *      is decoration.
 *      ASSERTED: with neither ZCL_WALLET_PASSPHRASE nor
 *      ZCL_ALLOW_PLAINTEXT_WALLET the run is refused and NOTHING is
 *      written; with a passphrase it succeeds, the seed at rest is
 *      ENCRYPTED (not merely present), and node.db is not group- or
 *      world-readable.
 *
 * Every case runs against a fixture datadir under ./test-tmp. Nothing here
 * reads, writes or dials a live node.
 */

#define _POSIX_C_SOURCE 200809L

#include "test/test_core.h"

#include "chain/chainparams.h"
#include "command/native_command.h"   /* the restore leaf's handler */
#include "json/json.h"
#include "kernel/command_registry.h"
#include "models/database.h"
#include "models/wallet_key.h"
#include "services/wallet_recovery_service.h"
#include "support/cleanse.h"
#include "wallet/mnemonic.h"
#include "wallet/wallet.h"
#include "wallet/wallet_lock.h"
#include "wallet/wallet_sqlite.h"

#include <dirent.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#if !defined(_WIN32)
#include <sys/wait.h>
#endif
#include <unistd.h>

#if defined(_WIN32)
#include "platform/time_compat.h"   /* platform_sleep_ms for the go-token poll */
#endif

#define WRS_CHECK(name, expr) do {                                     \
    printf("wallet_recovery_safety: %s... ", (name));                  \
    if (expr) { printf("OK\n"); }                                      \
    else { printf("FAIL\n"); failures++; }                             \
} while (0)

/* Two different, genuinely valid BIP39 phrases (standard test vectors).
 * They must be different seeds, and case 2 asserts that rather than
 * assuming it. */
#define WRS_PHRASE_A \
    "abandon abandon abandon abandon abandon abandon " \
    "abandon abandon abandon abandon abandon about"
#define WRS_PHRASE_B \
    "legal winner thank year wave sausage worth useful legal winner " \
    "thank yellow"

/* ── fixture + observation helpers ─────────────────────────────────── */

static void wrs_mkfixture(char *dir, size_t n, const char *tag)
{
    test_fmt_tmpdir(dir, n, "wallet_recovery_safety", tag);
    mkdir("./test-tmp", 0700);
    test_rm_rf(dir);
    mkdir(dir, 0700);
}

/* FNV-1a over the whole file, and its length. Returns 0 when the file
 * could not be read — never confused with a real hash, because a failed
 * observation must not read as a match. */
static uint64_t wrs_file_hash(const char *path, int64_t *size_out)
{
    if (size_out)
        *size_out = -1;
    FILE *f = fopen(path, "rb");
    if (!f)
        return 0;
    uint64_t h = 1469598103934665603ULL;
    int64_t total = 0;
    unsigned char buf[65536];
    size_t got;
    while ((got = fread(buf, 1, sizeof(buf), f)) > 0) {
        total += (int64_t)got;
        for (size_t i = 0; i < got; i++) {
            h ^= buf[i];
            h *= 1099511628211ULL;
        }
    }
    fclose(f);
    if (size_out)
        *size_out = total;
    return h ? h : 1;
}

/* Directory entries whose name starts with `prefix`; -1 when the directory
 * cannot be read. */
static int wrs_count_entries(const char *dir, const char *prefix)
{
    DIR *d = opendir(dir);
    if (!d)
        return -1;
    int n = 0;
    size_t plen = strlen(prefix);
    struct dirent *e;
    while ((e = readdir(d)) != NULL) {
        if (strcmp(e->d_name, ".") == 0 || strcmp(e->d_name, "..") == 0)
            continue;
        if (plen == 0 || strncmp(e->d_name, prefix, plen) == 0)
            n++;
    }
    closedir(d);
    return n;
}

static void wrs_list_dir(const char *tag, const char *dir)
{
    DIR *d = opendir(dir);
    if (!d) {
        printf("    [%s] %s: unreadable\n", tag, dir);
        return;
    }
    struct dirent *e;
    while ((e = readdir(d)) != NULL) {
        if (strcmp(e->d_name, ".") == 0 || strcmp(e->d_name, "..") == 0)
            continue;
        char p[1200];
        snprintf(p, sizeof(p), "%s/%s", dir, e->d_name);
        struct stat st;
        if (stat(p, &st) == 0)
            printf("    [%s] %s (%lld bytes, mode %04o)\n", tag, e->d_name,
                   (long long)st.st_size, (unsigned)(st.st_mode & 07777));
        else
            printf("    [%s] %s\n", tag, e->d_name);
    }
    closedir(d);
}

/* The at-rest environment, set explicitly per case so no case inherits
 * another's decision (or the developer's shell). */
static void wrs_set_at_rest(const char *passphrase, const char *plaintext_optin)
{
    if (passphrase) setenv("ZCL_WALLET_PASSPHRASE", passphrase, 1);
    else            unsetenv("ZCL_WALLET_PASSPHRASE");
    if (plaintext_optin) setenv("ZCL_ALLOW_PLAINTEXT_WALLET", plaintext_optin, 1);
    else                 unsetenv("ZCL_ALLOW_PLAINTEXT_WALLET");
}

/* Commit a recovery of `phrase` into `dir`. */
static struct zcl_result wrs_restore(const char *dir, const char *phrase,
                                     struct wallet_recovery_report *rep)
{
    struct wallet_recovery_request req = {
        .phrase = phrase, .datadir = dir, .dry_run = false,
    };
    return wallet_recovery_run(&req, rep);
}

/* ── case 1: a damaged node.db is refused, never quarantined ───────── */

static int t_damaged_db_is_refused_not_reset(void)
{
    int failures = 0;
    char dir[256];
    wrs_mkfixture(dir, sizeof(dir), "damaged");

    char db_path[1200];
    snprintf(db_path, sizeof(db_path), "%s/node.db", dir);

    /* Not a SQLite file at all — the shape node_db_open()'s quick_check
     * rejects, and therefore the shape it renames aside. */
    static const char *const junk =
        "this is not a database. it is the operator's node.db after a bad "
        "disk, which is exactly when somebody types 'recovery restore'.\n";
    FILE *f = fopen(db_path, "wb");
    bool wrote = f && fwrite(junk, 1, strlen(junk), f) == strlen(junk);
    if (f) fclose(f);
    WRS_CHECK("fixture: a damaged node.db was written", wrote);
    if (!wrote) { test_rm_rf(dir); return failures; }

    int64_t size_before = -1;
    uint64_t hash_before = wrs_file_hash(db_path, &size_before);
    WRS_CHECK("fixture: the damaged node.db is readable by this test",
              hash_before != 0 && size_before > 0);

    /* A passphrase is set so the at-rest gate (case 3) cannot be what
     * refuses this run — the refusal under test is the database one. */
    wrs_set_at_rest("case1-passphrase", NULL);

    struct wallet_recovery_report rep;
    struct zcl_result r = wrs_restore(dir, WRS_PHRASE_A, &rep);
    printf("    result ok=%d code=%d msg=%.220s\n", (int)r.ok, r.code,
           r.message);
    wrs_list_dir("after", dir);

    WRS_CHECK("recovering over a damaged node.db is REFUSED", !r.ok);
    WRS_CHECK("the refusal is the unreadable-target one (-66), not a "
              "generic failure", r.code == -66);
    WRS_CHECK("the refusal never claims a wallet was recovered",
              !rep.seed_installed);

    int64_t size_after = -1;
    uint64_t hash_after = wrs_file_hash(db_path, &size_after);
    WRS_CHECK("the damaged node.db is still there, under its own name",
              hash_after != 0);
    WRS_CHECK("it is byte-for-byte what it was",
              hash_after == hash_before && size_after == size_before);
    /* THE HEADLINE. The old path renamed it to node.db.corrupt-<ts> and
     * put a fresh empty database in its place. */
    WRS_CHECK("nothing was quarantined to node.db.corrupt-*",
              wrs_count_entries(dir, "node.db.corrupt-") == 0);
    WRS_CHECK("no -wal/-shm sidecar was created beside it",
              wrs_count_entries(dir, "node.db-") == 0);

    test_rm_rf(dir);
    return failures;
}

/* ── case 1b: the leaf will not guess a datadir ────────────────────── */

static int t_restore_leaf_requires_an_explicit_datadir(void)
{
    int failures = 0;

    /* No `datadir` key at all — the invocation whose default used to be
     * the operator's live datadir. */
    struct json_value input;
    json_init(&input);
    json_set_object(&input);
    (void)json_push_kv_str(&input, "phrase", WRS_PHRASE_A);
    (void)json_push_kv_bool(&input, "confirm", true);

    struct zcl_command_request request = { .input = &input };
    struct zcl_command_reply reply;
    zcl_command_reply_init(&reply, "zcl.wallet_recovery_restore.v1");
    zcl_native_handle_wallet_recovery_restore(&request, &reply);

    printf("    exit=%d code=%s\n", (int)reply.exit_code,
           reply.error.code[0] ? reply.error.code : "-");

    bool refused = reply.exit_code != 0 && reply.error.code[0] != '\0';
    WRS_CHECK("restore with no datadir is REFUSED", refused);
    WRS_CHECK("and refused BY NAME, so the caller can act on it",
              strcmp(reply.error.code, "MISSING_DATADIR") == 0);
    WRS_CHECK("the refusal never reports a mutation",
              !reply.error.mutated);

    zcl_command_reply_free(&reply);
    json_free(&input);
    return failures;
}

/* ── case 2: two concurrent restores — exactly one may win ─────────── */

/* One child: wait on the barrier, then commit `phrase` into `dir`.
 * _exit(0) on success, _exit(1) on any refusal. Never returns.
 * Windows has no fork()/pipe-fd inheritance; the child lane there is the
 * re-exec'd role body in test_wallet_recovery_safety() below, which polls a
 * go-token file instead of this barrier pipe. */
#if !defined(_WIN32)
static void wrs_child_restore(int barrier_fd, const char *dir,
                              const char *phrase)
{
    char go = 0;
    /* Block until the parent releases both children at once, so the two
     * runs genuinely overlap instead of queueing. */
    while (read(barrier_fd, &go, 1) < 0)
        ;
    close(barrier_fd);
    wrs_set_at_rest("case2-passphrase", NULL);
    struct wallet_recovery_report rep;
    struct zcl_result r = wrs_restore(dir, phrase, &rep);
    fflush(stdout);
    fflush(stderr);
    _exit(r.ok ? 0 : 1);
}
#endif

static int t_two_concurrent_restores_leave_one_wallet(void)
{
    int failures = 0;
    char dir[256];
    wrs_mkfixture(dir, sizeof(dir), "concurrent");

    /* Anti-vacuous: the whole case rests on the two phrases naming two
     * different wallets. */
    uint8_t seed_a[32], seed_b[32];
    bool seeds_ok = mnemonic_to_wallet_seed(WRS_PHRASE_A, NULL, seed_a) &&
                    mnemonic_to_wallet_seed(WRS_PHRASE_B, NULL, seed_b);
    WRS_CHECK("the two test phrases derive two DIFFERENT seeds",
              seeds_ok && memcmp(seed_a, seed_b, 32) != 0);
    if (!seeds_ok) { test_rm_rf(dir); return failures; }

#if defined(_WIN32)
    /* The barrier pipe cannot cross CreateProcess, so the release signal is
     * a go-token file both children poll for (bounded, 60 s). */
    char go_path[300];
    snprintf(go_path, sizeof(go_path), "%s.go-token", dir);
    unlink(go_path);
    char log_a[300], log_b[300];
    snprintf(log_a, sizeof(log_a), "%s.case2_a.log", dir);
    snprintf(log_b, sizeof(log_b), "%s.case2_b.log", dir);
    void *ha = NULL, *hb = NULL;
    bool spawned = false;
    fflush(stdout);
    fflush(stderr);
    if (_putenv_s("ZCL_WRS_DIR", dir) == 0 &&
        _putenv_s("ZCL_WRS_GO", go_path) == 0) {
        ha = test_spawn_self_with_role("test_wallet_recovery_safety",
                                       "case2_a", log_a);
        hb = test_spawn_self_with_role("test_wallet_recovery_safety",
                                       "case2_b", log_b);
        spawned = ha != NULL && hb != NULL;
    }
    WRS_CHECK("two concurrent recovery processes started", spawned);
    if (!spawned) {
        if (ha) { test_self_child_kill(ha); test_self_child_wait(ha); }
        if (hb) { test_self_child_kill(hb); test_self_child_wait(hb); }
        _putenv_s("ZCL_WRS_DIR", "");
        _putenv_s("ZCL_WRS_GO", "");
        test_rm_rf(dir);
        return failures;
    }

    /* Release both at once. */
    FILE *gof = fopen(go_path, "w");
    if (gof) fclose(gof);
    WRS_CHECK("both processes were released together", gof != NULL);

    int sa = test_self_child_wait(ha);
    int sb = test_self_child_wait(hb);
    _putenv_s("ZCL_WRS_DIR", "");
    _putenv_s("ZCL_WRS_GO", "");
    bool ok_a = (sa == 0);
    bool ok_b = (sb == 0);
#else
    int barrier[2];
    if (pipe(barrier) != 0) {
        WRS_CHECK("barrier pipe created", false);
        test_rm_rf(dir);
        return failures;
    }

    fflush(stdout);
    fflush(stderr);
    pid_t pa = fork();
    if (pa == 0) { close(barrier[1]); wrs_child_restore(barrier[0], dir, WRS_PHRASE_A); }
    pid_t pb = fork();
    if (pb == 0) { close(barrier[1]); wrs_child_restore(barrier[0], dir, WRS_PHRASE_B); }
    close(barrier[0]);

    bool forked = pa > 0 && pb > 0;
    WRS_CHECK("two concurrent recovery processes started", forked);
    if (!forked) {
        close(barrier[1]);
        if (pa > 0) waitpid(pa, NULL, 0);
        if (pb > 0) waitpid(pb, NULL, 0);
        test_rm_rf(dir);
        return failures;
    }

    /* Release both at once. */
    ssize_t released = write(barrier[1], "gg", 2);
    close(barrier[1]);
    WRS_CHECK("both processes were released together", released == 2);

    int sa = -1, sb = -1;
    waitpid(pa, &sa, 0);
    waitpid(pb, &sb, 0);
    bool ok_a = WIFEXITED(sa) && WEXITSTATUS(sa) == 0;
    bool ok_b = WIFEXITED(sb) && WEXITSTATUS(sb) == 0;
#endif
    printf("    phrase A ok=%d, phrase B ok=%d\n", (int)ok_a, (int)ok_b);
    wrs_list_dir("after", dir);

    /* THE HEADLINE. Both used to succeed. */
    WRS_CHECK("EXACTLY ONE of the two concurrent restores succeeded",
              ok_a != ok_b);
    WRS_CHECK("at least one of them succeeded (the lock must serialize, "
              "not deadlock both)", ok_a || ok_b);

    /* And the datadir holds ONE seed's wallet, not a mixture. */
    struct node_db ndb;
    memset(&ndb, 0, sizeof(ndb));
    char db_path[1200];
    snprintf(db_path, sizeof(db_path), "%s/node.db", dir);
    bool opened = node_db_open(&ndb, db_path) && ndb.open;
    WRS_CHECK("the resulting node.db opens", opened);
    if (opened) {
        wallet_lock_reset_for_test();
        struct zcl_result ur = wallet_lock_unlock(
            NULL, NULL, "case2-passphrase");
        WRS_CHECK("the restored wallet explicitly unlocks for inspection",
                  ur.ok);
        struct wallet_sqlite ws;
        struct zcl_result wr = wallet_sqlite_open_r(&ws, ndb.db);
        WRS_CHECK("its wallet tables open", wr.ok);
        if (wr.ok) {
            uint8_t on_disk[32];
            memset(on_disk, 0, sizeof(on_disk));
            enum wallet_seed_state st =
                wallet_sqlite_sapling_seed_state(&ws, on_disk);
            bool readable = (st == WALLET_SEED_PLAINTEXT ||
                             st == WALLET_SEED_UNLOCKED);
            WRS_CHECK("exactly one seed row is stored, and it is readable",
                      readable);
            bool is_a = readable && memcmp(on_disk, seed_a, 32) == 0;
            bool is_b = readable && memcmp(on_disk, seed_b, 32) == 0;
            WRS_CHECK("the stored seed is one of the two, not a third thing",
                      is_a || is_b);
            /* The defect's fingerprint was keys from BOTH seeds under a
             * single seed row. Ask by derivation, exactly as boot does. */
            struct wallet *w = calloc(1, sizeof(*w));
            if (w) {
                wallet_init(w);
                struct zcl_result kr = wallet_sqlite_read_keys_r(&ws, w);
                WRS_CHECK("its keys read back", kr.ok);
                if (kr.ok) {
                    printf("    keys on disk: %zu\n", w->keystore.num_keys);
                    WRS_CHECK("the wallet is not empty", w->keystore.num_keys > 0);
                    bool gov_a = wallet_hd_adopt_seed(w, seed_a);
                    bool gov_b = wallet_hd_adopt_seed(w, seed_b);
                    printf("    governed by A=%d B=%d\n", (int)gov_a, (int)gov_b);
                    WRS_CHECK("every key on disk descends from ONE of the two "
                              "seeds, never a mixture of both",
                              gov_a != gov_b);
                    WRS_CHECK("and it is the seed that is actually stored",
                              (gov_a && is_a) || (gov_b && is_b));
                }
                wallet_free(w);
                free(w);
            }
            memory_cleanse(on_disk, sizeof(on_disk));
            wallet_sqlite_close(&ws);
        }
        node_db_close(&ndb);
        wallet_lock_reset_for_test();
    }

    memory_cleanse(seed_a, sizeof(seed_a));
    memory_cleanse(seed_b, sizeof(seed_b));
    test_rm_rf(dir);
    return failures;
}

/* ── case 3: the at-rest policy, and the file mode ─────────────────── */

static int t_at_rest_policy_is_obeyed(void)
{
    int failures = 0;

    /* 3a. Neither a passphrase nor an opt-in: BOOT would refuse to mint a
     * plaintext wallet here, so this must too — and must write nothing. */
    {
        char dir[256];
        wrs_mkfixture(dir, sizeof(dir), "atrest_refuse");
        wrs_set_at_rest(NULL, NULL);

        struct wallet_recovery_report rep;
        struct zcl_result r = wrs_restore(dir, WRS_PHRASE_A, &rep);
        printf("    undecided: ok=%d code=%d msg=%.200s\n", (int)r.ok, r.code,
               r.message);
        wrs_list_dir("after", dir);

        WRS_CHECK("with no at-rest decision the recovery is REFUSED", !r.ok);
        WRS_CHECK("and refused by its own code (-67), not a generic failure",
                  r.code == -67);
        WRS_CHECK("NOTHING was written: no node.db at all",
                  wrs_count_entries(dir, "node.db") == 0);
        WRS_CHECK("and no key was installed", !rep.seed_installed);
        test_rm_rf(dir);
    }

    /* 3b. With a passphrase it proceeds, the seed at rest is ENCRYPTED,
     * and the file holding the keys is not readable by anyone else. */
    {
        char dir[256];
        wrs_mkfixture(dir, sizeof(dir), "atrest_encrypted");
        wrs_set_at_rest("case3-passphrase", NULL);

        struct wallet_recovery_report rep;
        struct zcl_result r = wrs_restore(dir, WRS_PHRASE_A, &rep);
        printf("    encrypted: ok=%d code=%d msg=%.200s\n", (int)r.ok, r.code,
               r.message);
        wrs_list_dir("after", dir);

        WRS_CHECK("with ZCL_WALLET_PASSPHRASE set the recovery succeeds",
                  r.ok);
        WRS_CHECK("and it installed the phrase's seed", r.ok &&
                  rep.seed_installed);

        char db_path[1200];
        snprintf(db_path, sizeof(db_path), "%s/node.db", dir);
        struct stat st;
        bool stat_ok = stat(db_path, &st) == 0;
        WRS_CHECK("node.db exists after the recovery", stat_ok);
        if (stat_ok)
            printf("    node.db mode = %04o\n", (unsigned)(st.st_mode & 07777));
        /* It holds spending keys. 0644 is what SQLite creates by default
         * and is what this used to leave behind. */
        WRS_CHECK("node.db is not group- or world-readable",
                  stat_ok && (st.st_mode & (S_IRWXG | S_IRWXO)) == 0);

        /* The seed row must be ENCRYPTED, not merely present: UNLOCKED
         * means "there was an envelope and the passphrase opened it",
         * PLAINTEXT means the raw 32 bytes are sitting in the file. */
        struct node_db ndb;
        memset(&ndb, 0, sizeof(ndb));
        bool opened = node_db_open(&ndb, db_path) && ndb.open;
        WRS_CHECK("the recovered node.db opens", opened);
        if (opened) {
            wallet_lock_reset_for_test();
            struct zcl_result ur = wallet_lock_unlock(
                NULL, NULL, "case3-passphrase");
            WRS_CHECK("the recovered wallet explicitly unlocks for inspection",
                      ur.ok);
            struct wallet_sqlite ws;
            struct zcl_result wr = wallet_sqlite_open_r(&ws, ndb.db);
            if (wr.ok) {
                enum wallet_seed_state s =
                    wallet_sqlite_sapling_seed_state(&ws, NULL);
                printf("    seed_state = %d\n", (int)s);
                WRS_CHECK("the master seed is stored ENCRYPTED at rest, not "
                          "as raw bytes", s == WALLET_SEED_UNLOCKED);
                WRS_CHECK("some keys were actually written (an empty wallet "
                          "would make the mode check vacuous)",
                          db_wallet_key_count(&ndb) > 0);
                wallet_sqlite_close(&ws);
            } else {
                WRS_CHECK("the recovered wallet tables open", false);
            }
            node_db_close(&ndb);
            wallet_lock_reset_for_test();
        }
        test_rm_rf(dir);
    }

    /* 3c. The explicit plaintext opt-in still works — the gate is a
     * decision, not a ban. Without this the 3a assertion would also pass
     * over a command that simply refuses everything. */
    {
        char dir[256];
        wrs_mkfixture(dir, sizeof(dir), "atrest_optin");
        wrs_set_at_rest(NULL, "1");

        struct wallet_recovery_report rep;
        struct zcl_result r = wrs_restore(dir, WRS_PHRASE_A, &rep);
        printf("    plaintext opt-in: ok=%d code=%d msg=%.200s\n", (int)r.ok,
               r.code, r.message);
        WRS_CHECK("ZCL_ALLOW_PLAINTEXT_WALLET=1 lets the recovery proceed",
                  r.ok && rep.seed_installed);

        char db_path[1200];
        snprintf(db_path, sizeof(db_path), "%s/node.db", dir);
        struct stat st;
        bool stat_ok = stat(db_path, &st) == 0;
        WRS_CHECK("even the opted-in plaintext wallet is not world-readable",
                  stat_ok && (st.st_mode & (S_IRWXG | S_IRWXO)) == 0);
        test_rm_rf(dir);
    }

    wrs_set_at_rest(NULL, NULL);
    return failures;
}

int test_wallet_recovery_safety(void);
int test_wallet_recovery_safety(void)
{
#if defined(_WIN32)
    /* Windows has no fork(): case 2's concurrent restorers are this same
     * binary re-exec'd with a role (see test_spawn_self_with_role). The
     * go-token file replaces the barrier pipe, which cannot be inherited
     * across CreateProcess. Returns 0 when the restore succeeded — the exit
     * code is the parent's assertion input. */
    const char *fork_role = getenv("ZCL_TEST_FORK_ROLE");
    if (fork_role && fork_role[0]) {
        const char *phrase = NULL;
        if (strcmp(fork_role, "case2_a") == 0)
            phrase = WRS_PHRASE_A;
        else if (strcmp(fork_role, "case2_b") == 0)
            phrase = WRS_PHRASE_B;
        const char *dir = getenv("ZCL_WRS_DIR");
        const char *go = getenv("ZCL_WRS_GO");
        if (!phrase || !dir || !dir[0] || !go || !go[0]) {
            fprintf(stderr, "wallet_recovery_safety role '%s': "
                    "ZCL_WRS_DIR/ZCL_WRS_GO unset\n", fork_role);
            return 1;
        }
        int waited_ms = 0;
        while (access(go, 0) != 0 && waited_ms < 60000) {
            platform_sleep_ms(2);
            waited_ms += 2;
        }
        if (access(go, 0) != 0) {
            fprintf(stderr, "wallet_recovery_safety role '%s': go token "
                    "never appeared\n", fork_role);
            return 1;
        }
        wrs_set_at_rest("case2-passphrase", NULL);
        struct wallet_recovery_report rep;
        struct zcl_result r = wrs_restore(dir, phrase, &rep);
        return r.ok ? 0 : 1;
    }
#endif
    printf("\n=== recovery restore must not cost you the wallet you have ===\n");
    int failures = 0;

    /* Address encoding reads chain_params_get(), which aborts if nothing
     * ever selected a network. */
    chain_params_select(CHAIN_MAIN);
    /* Keep the full 240-key encryption path real but within the group budget.
     * 10k is the production-accepted minimum, not a disabled KDF. */
    setenv("ZCL_WALLET_KDF_ITERS", "10000", 1);
    wallet_lock_reset_for_test();

    failures += t_damaged_db_is_refused_not_reset();
    failures += t_restore_leaf_requires_an_explicit_datadir();
    failures += t_two_concurrent_restores_leave_one_wallet();
    failures += t_at_rest_policy_is_obeyed();

    wallet_lock_reset_for_test();
    unsetenv("ZCL_WALLET_KDF_ITERS");
    return failures;
}
