/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * `core wallet create` MAKES A WALLET AND NEVER DAMAGES ONE.
 *
 * The command draws a 24-word phrase, shows it once, and writes a wallet that
 * is encrypted from its first byte. This group is the proof of the rules that
 * make that safe, each driven through the real CLI path (standard input in,
 * one JSON document out) against isolated fixture datadirs:
 *
 *   1. The phrase restores: the same words, restored in a second datadir,
 *      open the same first shielded address. No transparent key is made.
 *   2. It never overwrites or merges: a datadir holding a transparent key, a
 *      lone seed, a lone Sapling key or a lone note is refused by name and its
 *      node.db is byte-identical afterwards.
 *   3. The phrase and the passphrase appear in no file of the datadir and in
 *      nothing the process wrote to stderr; the reply carries the phrase once.
 *   4. The seed is encrypted at rest: its raw bytes are in no file, it reads
 *      back as LOCKED without the passphrase and as the phrase's seed with it.
 *   5. The active tip (height and hash, never a reorganised-away row) is the
 *      birthday; only the first scan of the wallet starts below it, and only
 *      while its block is still active. No other scan range is raised.
 *   6. An empty, short or missing passphrase is refused and nothing is made.
 *   7. An agent-ceiling caller is refused before the handler, and a caller
 *      that did not use standard input is refused by the handler.
 *   8. Standard output is one JSON document; log lines go to stderr.
 *   9. Core dumps are off. 10. A wallet/ directory refuses create.
 *  11. Boot reads seed and Sapling rows, so it never mints or imports over a
 *      created wallet; a closed store mints nothing.
 *  12. A wrong passphrase is refused and a payment is found while locked
 *      (these two depend on the wallet-lock work).
 */

#define _POSIX_C_SOURCE 200809L

#include "test/test_core.h"

#include "chain/chainparams.h"
#include "config/boot_internal.h"
#include "config/boot_wallet_phrase.h"
#include "command/native_command.h"
#include "config/command_catalog.h"
#include "controllers/wallet_scan.h"
#include "json/json.h"
#include "kernel/command_registry.h"
#include "models/database.h"
#include "models/wallet_key.h"
#include "services/wallet_create_service.h"
#include "services/wallet_recovery_service.h"
#include "support/cleanse.h"
#include "validation/chainstate.h"
#include "sapling/constants.h"
#include "sapling/note_encryption.h"
#include "sapling/sapling.h"
#include "primitives/transaction.h"
#include "wallet/mnemonic.h"
#include "wallet/sapling_keys.h"
#include "wallet/wallet.h"
#include "wallet/wallet_lock.h"
#include "wallet/wallet_sqlite.h"

#include <dirent.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/resource.h>
#ifdef __linux__
#include <sys/prctl.h>
#endif
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#define WCR_CHECK(name, expr) do {                                     \
    printf("wallet_create: %s... ", (name));                           \
    if (expr) { printf("OK\n"); }                                      \
    else { printf("FAIL\n"); failures++; }                             \
} while (0)

#define WCR_PASS "fixture-passphrase-0001"
#define WCR_WIRE_CAP 16384

struct wcr_run {
    char wire[WCR_WIRE_CAP];    /* stdout: the one JSON document */
    char err[WCR_WIRE_CAP];     /* stderr: everything logged */
    int  rc;
};

/* ── fixtures and observation ──────────────────────────────────────── */

static void wcr_fixture(char *dir, size_t n, const char *tag)
{
    test_fmt_tmpdir(dir, n, "wallet_create", tag);
    mkdir("./test-tmp", 0700);
    test_rm_rf(dir);
    mkdir(dir, 0700);
}

static bool wcr_restore_fd(int saved, FILE *stream)
{
    if (saved < 0)
        return false;
    bool ok = dup2(saved, fileno(stream)) >= 0;
    ok &= close(saved) == 0;
    clearerr(stream);
    return ok;
}

static bool wcr_slurp(FILE *f, char *out, size_t cap)
{
    if (fflush(f) != 0 || fseek(f, 0, SEEK_SET) != 0)
        return false;
    size_t n = fread(out, 1, cap - 1, f);
    out[n] = '\0';
    return !ferror(f) && n < cap - 1;
}

/* One redirected standard stream: a temp file stands in for it, and the
 * original descriptor is kept to put it back. */
struct wcr_cap {
    FILE *stream;
    FILE *tmp;
    int   saved;
};

static bool wcr_cap_begin(struct wcr_cap *c, FILE *stream, const char *feed)
{
    c->stream = stream;
    c->tmp = tmpfile();
    c->saved = dup(fileno(stream));
    bool ok = c->tmp && c->saved >= 0 && fflush(stream) == 0;
    if (ok && feed)
        ok = fputs(feed, c->tmp) >= 0 && fflush(c->tmp) == 0 &&
             fseek(c->tmp, 0, SEEK_SET) == 0;
    if (ok)
        ok = dup2(fileno(c->tmp), fileno(stream)) >= 0;
    clearerr(stream);
    return ok;
}

/* Put the stream back and, when `out` is given, read what was written. */
static bool wcr_cap_end(struct wcr_cap *c, char *out, size_t cap)
{
    fflush(c->stream);
    bool ok = wcr_restore_fd(c->saved, c->stream);
    if (ok && out)
        ok = wcr_slurp(c->tmp, out, cap);
    if (c->tmp)
        fclose(c->tmp);
    return ok;
}

/* Run `z23 core <args>` in process with `stdin_text` on standard input,
 * capturing stdout and stderr. */
static bool wcr_cli_args(const char *const *args, int nargs,
                         const char *stdin_text, struct wcr_run *run)
{
    struct wcr_cap in, out, err;
    bool ok = wcr_cap_begin(&in, stdin, stdin_text);
    ok = wcr_cap_begin(&out, stdout, NULL) && ok;
    ok = wcr_cap_begin(&err, stderr, NULL) && ok;
    if (ok) {
        run->rc = zcl_native_command_main("core", args, nargs, "", 0,
                                          CHAIN_MAIN, false);
    }
    ok = wcr_cap_end(&in, NULL, 0) && ok;
    ok = wcr_cap_end(&out, run->wire, sizeof(run->wire)) && ok;
    ok = wcr_cap_end(&err, run->err, sizeof(run->err)) && ok;
    return ok;
}

/* Run `z23 core wallet create --input=-` with `stdin_text` on standard input. */
static bool wcr_cli(const char *stdin_text, struct wcr_run *run)
{
    const char *args[] = {"wallet", "create", "--input=-", "--format=json"};
    return wcr_cli_args(args, 4, stdin_text, run);
}

static bool wcr_create(const char *datadir, const char *pass,
                       struct wcr_run *run)
{
    char text[2048];
    if (pass)
        snprintf(text, sizeof(text),
                 "{\"datadir\":\"%s\",\"passphrase\":\"%s\"}", datadir, pass);
    else
        snprintf(text, sizeof(text), "{\"datadir\":\"%s\"}", datadir);
    return wcr_cli(text, run);
}

/* The reply document is the whole of stdout: no log line precedes it. */
static const char *wcr_doc(const struct wcr_run *run)
{
    return run->wire;
}

/* Copy a string field of the reply's data object. */
static bool wcr_field(const struct wcr_run *run, const char *key, char *out,
                      size_t cap)
{
    struct json_value v;
    json_init(&v);
    bool ok = json_read(&v, wcr_doc(run), strlen(wcr_doc(run)));
    const char *s = ok ? json_get_str(json_get(json_get(&v, "data"), key))
                       : NULL;
    ok = s && s[0] && strlen(s) < cap;
    if (ok)
        snprintf(out, cap, "%s", s);
    json_free(&v);
    return ok;
}

static bool wcr_error_is(const struct wcr_run *run, const char *code)
{
    char needle[96];
    snprintf(needle, sizeof(needle), "\"code\":\"%s\"", code);
    return strstr(run->wire, needle) != NULL;
}

static size_t wcr_count(const char *hay, size_t hay_len, const char *needle,
                        size_t nlen)
{
    size_t n = 0;
    if (nlen == 0 || hay_len < nlen)
        return 0;
    for (size_t i = 0; i + nlen <= hay_len; i++)
        if (hay[i] == needle[0] && memcmp(hay + i, needle, nlen) == 0)
            n++;
    return n;
}

/* Occurrences of `needle` in every regular file under `dir`. */
static size_t wcr_count_in_tree(const char *dir, const char *needle,
                                size_t nlen)
{
    size_t total = 0;
    DIR *d = opendir(dir);
    struct dirent *e;
    while (d && (e = readdir(d)) != NULL) {
        if (!strcmp(e->d_name, ".") || !strcmp(e->d_name, ".."))
            continue;
        char path[1400];
        snprintf(path, sizeof(path), "%s/%s", dir, e->d_name);
        struct stat st;
        if (lstat(path, &st) != 0)
            continue;
        if (S_ISDIR(st.st_mode)) {
            total += wcr_count_in_tree(path, needle, nlen);
            continue;
        }
        FILE *f = S_ISREG(st.st_mode) ? fopen(path, "rb") : NULL;
        char *buf = f ? malloc((size_t)st.st_size + 1) : NULL;
        if (buf && fread(buf, 1, (size_t)st.st_size, f) == (size_t)st.st_size)
            total += wcr_count(buf, (size_t)st.st_size, needle, nlen);
        free(buf);
        if (f) fclose(f);
    }
    if (d) closedir(d);
    return total;
}

static uint64_t wcr_file_hash(const char *path)
{
    FILE *f = fopen(path, "rb");
    if (!f)
        return 0;
    uint64_t h = 1469598103934665603ULL;
    unsigned char buf[65536];
    size_t got;
    while ((got = fread(buf, 1, sizeof(buf), f)) > 0)
        for (size_t i = 0; i < got; i++) {
            h ^= buf[i];
            h *= 1099511628211ULL;
        }
    fclose(f);
    return h ? h : 1;
}

static bool wcr_exists(const char *dir, const char *name)
{
    char p[1400];
    snprintf(p, sizeof(p), "%s/%s", dir, name);
    return access(p, F_OK) == 0;
}

/* Open <dir>/node.db for the fixture helpers below. */
static bool wcr_open(struct node_db *ndb, const char *dir)
{
    char p[1400];
    memset(ndb, 0, sizeof(*ndb));
    snprintf(p, sizeof(p), "%s/node.db", dir);
    return node_db_open(ndb, p);
}

static bool wcr_sql(const char *dir, const char *sql)
{
    struct node_db ndb;
    bool ok = wcr_open(&ndb, dir) &&
              sqlite3_exec(ndb.db, sql, NULL, NULL, NULL) == SQLITE_OK;
    if (ndb.open)
        node_db_close(&ndb);
    return ok;
}

/* Restore `phrase` into `dir` through the recovery service, plaintext. */
static bool wcr_restore(const char *dir, const char *phrase,
                        struct wallet_recovery_report *rep)
{
    /* An earlier create in this process left the lock module force-locked. */
    wallet_lock_reset_for_test();
    setenv("ZCL_ALLOW_PLAINTEXT_WALLET", "1", 1);
    struct wallet_recovery_request rq = { .phrase = phrase, .datadir = dir };
    struct zcl_result r = wallet_recovery_run(&rq, rep);
    unsetenv("ZCL_ALLOW_PLAINTEXT_WALLET");
    if (!r.ok)
        printf("    restore refused: %s\n", r.message);
    return r.ok;
}

static void wcr_phrase_seed(const char *phrase, uint8_t seed[32])
{
    memset(seed, 0, 32);
    (void)mnemonic_to_wallet_seed(phrase, NULL, seed);
}

/* ── case 1: the phrase restores the same wallet ───────────────────── */

static int t_round_trip(void)
{
    int failures = 0;
    char a[1024], b[1024], phrase[600], addr[200];
    wcr_fixture(a, sizeof(a), "rt_a");
    wcr_fixture(b, sizeof(b), "rt_b");

    struct wcr_run run;
    memset(&run, 0, sizeof(run));
    bool ran = wcr_create(a, WCR_PASS, &run);
    bool got = ran && wcr_field(&run, "phrase", phrase, sizeof(phrase)) &&
               wcr_field(&run, "first_shielded_address", addr, sizeof(addr));
    WCR_CHECK("create succeeds and returns a phrase and an address",
              got && run.rc == 0);
    if (!got)
        return failures + 1;

    int words = 1;
    for (const char *p = phrase; *p; p++)
        words += *p == ' ';
    WCR_CHECK("the phrase is 24 valid BIP39 words",
              words == 24 && mnemonic_validate(phrase));

    struct wallet_recovery_report rep;
    bool restored = wcr_restore(b, phrase, &rep);
    WCR_CHECK("the phrase restores in a second datadir", restored);
    WCR_CHECK("the first shielded address matches the restored one",
              restored && strcmp(addr, rep.first_shielded_address) == 0);

    struct node_db ndb;
    bool open = wcr_open(&ndb, a);
    WCR_CHECK("the created wallet has no transparent key",
              open && db_wallet_key_count(&ndb) == 0);
    WCR_CHECK("the created wallet has Sapling keys",
              open && db_sapling_key_count(&ndb) > 0);
    if (open)
        node_db_close(&ndb);

    char again[600];
    memset(&run, 0, sizeof(run));
    WCR_CHECK("a second create in the same datadir is refused",
              wcr_create(a, WCR_PASS, &run) &&
              wcr_error_is(&run, "WALLET_ALREADY_PRESENT") &&
              !wcr_field(&run, "phrase", again, sizeof(again)));
    memory_cleanse(phrase, sizeof(phrase));
    return failures;
}

/* ── case 2: never overwrite or merge ──────────────────────────────── */

static int refuse_case(const char *tag, const char *sql, bool via_restore)
{
    int failures = 0;
    char dir[1024], label[160], p[1400], dummy[600];
    wcr_fixture(dir, sizeof(dir), tag);
    bool seeded = true;
    if (via_restore) {
        struct wallet_recovery_report rep;
        seeded = wcr_restore(dir, "abandon abandon abandon abandon abandon "
                             "abandon abandon abandon abandon abandon "
                             "abandon about", &rep);
    } else {
        seeded = wcr_sql(dir, sql);
    }
    snprintf(p, sizeof(p), "%s/node.db", dir);
    uint64_t before = wcr_file_hash(p);

    struct wcr_run run;
    memset(&run, 0, sizeof(run));
    bool ran = wcr_create(dir, WCR_PASS, &run);
    snprintf(label, sizeof(label), "%s: seeded, refused by name, no phrase "
             "returned", tag);
    WCR_CHECK(label, seeded && ran && run.rc != 0 &&
              wcr_error_is(&run, "WALLET_ALREADY_PRESENT") &&
              !wcr_field(&run, "phrase", dummy, sizeof(dummy)));
    snprintf(label, sizeof(label), "%s: node.db is byte-identical", tag);
    WCR_CHECK(label, before != 0 && wcr_file_hash(p) == before);
    return failures;
}

static int t_refusals(void)
{
    int failures = 0;
    failures += refuse_case("with_keys", NULL, true);
    failures += refuse_case("seed_only",
        "INSERT INTO wallet_seed(id,seed) VALUES(1,zeroblob(32))", false);
    failures += refuse_case("sapling_key_only",
        "INSERT INTO wallet_sapling_keys(ivk,xsk,xfvk,diversifier,pk_d,"
        "child_index) VALUES(zeroblob(32),zeroblob(169),zeroblob(169),"
        "zeroblob(11),zeroblob(32),0)", false);
    failures += refuse_case("note_only",
        "INSERT INTO wallet_sapling_notes(txid,output_index,value,rcm,ivk,"
        "diversifier,pk_d,cm,nullifier) VALUES(zeroblob(32),0,1,zeroblob(32),"
        "zeroblob(32),zeroblob(11),zeroblob(32),zeroblob(32),zeroblob(32))",
        false);
    return failures;
}

/* The first `n` words of `phrase`, space separated. */
static size_t wcr_first_words(const char *phrase, int n, char *out, size_t cap)
{
    size_t len = 0;
    int spaces = 0;
    for (const char *p = phrase; *p && len + 1 < cap; p++) {
        if (*p == ' ' && ++spaces == n)
            break;
        out[len++] = *p;
    }
    out[len] = '\0';
    return len;
}

/* ── cases 3 and 4: nothing leaks, the seed is encrypted ───────────── */

static int t_phrase_not_captured_and_encrypted(void)
{
    int failures = 0;
    char dir[1024], phrase[600];
    wcr_fixture(dir, sizeof(dir), "leak");
    struct wcr_run run;
    memset(&run, 0, sizeof(run));
    bool got = wcr_create(dir, WCR_PASS, &run) &&
               wcr_field(&run, "phrase", phrase, sizeof(phrase));
    WCR_CHECK("create succeeds", got);
    if (!got)
        return failures + 1;
    size_t plen = strlen(phrase);

    WCR_CHECK("the reply carries the phrase exactly once",
              wcr_count(run.wire, strlen(run.wire), phrase, plen) == 1);
    WCR_CHECK("stderr (every log line) has no phrase and no passphrase",
              wcr_count(run.err, strlen(run.err), phrase, plen) == 0 &&
              wcr_count(run.err, strlen(run.err), WCR_PASS,
                        strlen(WCR_PASS)) == 0);
    WCR_CHECK("no file in the datadir holds the phrase",
              wcr_count_in_tree(dir, phrase, plen) == 0);
    char four[256];
    size_t fn = wcr_first_words(phrase, 4, four, sizeof(four));
    WCR_CHECK("no file in the datadir holds the first four words",
              fn > 0 && wcr_count_in_tree(dir, four, fn) == 0);
    WCR_CHECK("no file in the datadir holds the passphrase",
              wcr_count_in_tree(dir, WCR_PASS, strlen(WCR_PASS)) == 0);

    uint8_t seed[32];
    wcr_phrase_seed(phrase, seed);
    WCR_CHECK("the raw seed is in no file of the datadir",
              wcr_count_in_tree(dir, (const char *)seed, 32) == 0);

    struct node_db ndb;
    struct wallet_sqlite ws;
    bool open = wcr_open(&ndb, dir) &&
                wallet_sqlite_open_r(&ws, ndb.db).ok;
    uint8_t got_seed[32] = {0};
    WCR_CHECK("without the passphrase the stored seed is LOCKED",
              open && wallet_sqlite_sapling_seed_state(&ws, got_seed) ==
                          WALLET_SEED_LOCKED);
    bool unlocked = open && wallet_lock_unlock(NULL, NULL, WCR_PASS).ok;
    WCR_CHECK("with the passphrase it decrypts to the phrase's seed",
              unlocked &&
              wallet_sqlite_sapling_seed_state(&ws, got_seed) ==
                  WALLET_SEED_UNLOCKED && memcmp(got_seed, seed, 32) == 0);
    wallet_lock_lock(NULL);
    if (open) {
        wallet_sqlite_close(&ws);
        node_db_close(&ndb);
    }
    memory_cleanse(phrase, sizeof(phrase));
    memory_cleanse(seed, sizeof(seed));
    memory_cleanse(got_seed, sizeof(got_seed));
    return failures;
}

/* ── case 5: the birthday is stored, verified and used by the first scan ── */

#define WCR_BLOCK_INSERT                                                    \
    "INSERT INTO blocks(hash,height,prev_hash,version,merkle_root,time,"    \
    "bits,nonce,solution,chain_work,status) VALUES(X'%s',%d,zeroblob(32),4,"\
    "zeroblob(32),0,0,zeroblob(32),zeroblob(1),zeroblob(32),%d)"

/* A block whose 32-byte hash is `fill` repeated. */
static bool wcr_block(const char *dir, uint8_t fill, int height, int status)
{
    char hex[65], sql[512];
    for (int i = 0; i < 32; i++)
        snprintf(hex + 2 * i, 3, "%02x", fill);
    snprintf(sql, sizeof(sql), WCR_BLOCK_INSERT, hex, height, status);
    return wcr_sql(dir, sql);
}

/* An in-memory active chain of heights 0..n-1. Every block hashes to 0x01
 * repeated except the one at `special`, which hashes to `fill` repeated. */
struct wcr_chain {
    struct active_chain chain;
    struct block_index *idx;
    struct block_index **ptr;
};

static bool wcr_chain_make(struct wcr_chain *k, int n, int special,
                           uint8_t fill)
{
    active_chain_init(&k->chain);
    k->idx = calloc((size_t)n, sizeof(*k->idx));
    k->ptr = calloc((size_t)n, sizeof(*k->ptr));
    if (!k->idx || !k->ptr)
        return false;
    for (int i = 0; i < n; i++) {
        block_index_init(&k->idx[i]);
        k->idx[i].nHeight = i;
        memset(k->idx[i].hashBlock.data, i == special ? fill : 1, 32);
        k->idx[i].phashBlock = &k->idx[i].hashBlock;
        k->ptr[i] = &k->idx[i];
    }
    free(k->chain.chain);
    k->chain.chain = k->ptr;
    k->chain.height = n - 1;
    k->chain.capacity = n;
    return true;
}

static void wcr_chain_free(struct wcr_chain *k)
{
    k->chain.chain = NULL;
    k->chain.capacity = 0;
    k->chain.height = 0;
    active_chain_free(&k->chain);
    free(k->idx);
    free(k->ptr);
}

/* A scan of 0..500 must be asked for its whole range, whatever the birthday:
 * a transparent scan, a rescan and the full scan an imported key triggers
 * cover every block, because a key imported later can own a coin from before
 * the wallet was made. The scanner reaches its no-keys path (and not the
 * empty-range one a raised start of 900 would hit) only when the start stays
 * 0, so the chain given holds the birthday's floor block. */
static bool scan_is_not_raised(struct node_db *ndb, struct wcr_chain *k)
{
    struct wallet *w = calloc(1, sizeof(*w));
    struct wcr_cap cap;
    bool ok = w && wcr_cap_begin(&cap, stdout, NULL);
    if (ok)
        (void)wallet_scan_blocks(ndb, &k->chain, w, "/nonexistent", 0, 500);
    char log[4096] = {0};
    ok = wcr_cap_end(&cap, log, sizeof(log)) && ok;
    free(w);
    return ok && strstr(log, "range empty") == NULL &&
           strstr(log, "no wallet keys") != NULL;
}

/* What boot_wallet_boot_catch_up does to a wallet that has `best` scanned,
 * against `k`. The chains here reach past 1000 blocks, so the catch-up defers
 * and the wallet is the observation. */
static struct wallet *wcr_boot_wallet(struct node_db *ndb,
                                      struct wcr_chain *k, int best)
{
    struct wallet *w = calloc(1, sizeof(*w));
    if (!w)
        return NULL;
    wallet_init(w);
    w->best_block_height = best;
    w->initial_scan_floor = -1;
    (void)boot_wallet_boot_catch_up(w, &k->chain, "/nonexistent", ndb);
    return w;
}

static bool wcr_marked_unread(const struct wallet *w)
{
    return w && w->scan_retry.pending && w->scan_retry.from == 0 &&
           strcmp(w->scan_retry.blocker, "WALLET_BIRTHDAY_CHAIN_CHANGED") == 0 &&
           wallet_scanned_through_height(w) < 0;
}

static int birthday_stored(const char *dir, const struct wcr_run *run)
{
    int failures = 0;
    struct json_value v;
    json_init(&v);
    bool parsed = json_read(&v, wcr_doc(run), strlen(wcr_doc(run)));
    const struct json_value *data = json_get(&v, "data");
    WCR_CHECK("the reply names the birthday: the connected tip at 1000",
              parsed && json_get_bool_or(data, "birthday_recorded", false) &&
              json_get_int(json_get(data, "birthday_height")) == 1000);
    json_free(&v);

    struct node_db ndb;
    int64_t b = 0;
    uint8_t hash[32], want[32];
    memset(want, 0x09, sizeof(want));
    bool open = wcr_open(&ndb, dir);
    WCR_CHECK("the stored birthday is the tip height",
              open && db_wallet_birthday_get(&ndb, &b, hash) && b == 1000);
    WCR_CHECK("it stores the hash of the block 100 below the tip, not the tip",
              open && memcmp(hash, want, 32) == 0);
    struct wcr_chain k;
    bool made = open && wcr_chain_make(&k, 1002, 900, 0x09);
    WCR_CHECK("wallet_scan_blocks never raises a start: a key imported later "
              "scans its whole range", made && scan_is_not_raised(&ndb, &k));
    if (made)
        wcr_chain_free(&k);
    if (open)
        node_db_close(&ndb);
    return failures;
}

/* What boot does with a wallet that has `best` scanned, per chain. */
static int birthday_boot_wallets(struct node_db *ndb, struct wcr_chain *same,
                                 struct wcr_chain *other)
{
    int failures = 0;
    struct wallet *a = wcr_boot_wallet(ndb, same, 0);
    WCR_CHECK("boot gives the first catch-up of a valid birthday the floor",
              a && a->initial_scan_floor == 900 && !wcr_marked_unread(a));
    struct wallet *b = wcr_boot_wallet(ndb, other, 0);
    WCR_CHECK("a replaced birthday block marks the whole chain unread: the "
              "catch-up defers on a long chain and records it",
              b && b->initial_scan_floor == 0 && wcr_marked_unread(b));
    struct wallet *c = wcr_boot_wallet(ndb, other, 7);
    WCR_CHECK("a wallet that has already scanned is left to its scan height",
              c && c->initial_scan_floor == 0 && !wcr_marked_unread(c));
    struct wallet *all[] = { a, b, c };
    for (size_t i = 0; i < 3; i++)
        if (all[i]) {
            wallet_free(all[i]);
            free(all[i]);
        }
    return failures;
}

/* The active chain against the stored birthday of the datadir `dir` (tip 1000,
 * floor block 900 hashing to 0x09). */
static int birthday_chain_checks(const char *dir)
{
    int failures = 0;
    struct node_db ndb;
    struct wcr_chain same, other, shorter;
    bool open = wcr_open(&ndb, dir);
    bool made = open && wcr_chain_make(&same, 1002, 900, 0x09) &&
                wcr_chain_make(&other, 1002, 900, 0x77) &&
                wcr_chain_make(&shorter, 800, 700, 0x09);
    int floor = -1;
    WCR_CHECK("a chain holding the floor block makes the birthday valid at 900",
              made && wallet_birthday_check(&ndb, &same.chain, &floor) ==
                          WALLET_BIRTHDAY_VALID && floor == 900);
    WCR_CHECK("a chain with another block at 900 changes the birthday",
              made && wallet_birthday_check(&ndb, &other.chain, &floor) ==
                          WALLET_BIRTHDAY_CHANGED);
    WCR_CHECK("a chain shorter than the floor changes the birthday",
              made && wallet_birthday_check(&ndb, &shorter.chain, &floor) ==
                          WALLET_BIRTHDAY_CHANGED);
    if (made) {
        failures += birthday_boot_wallets(&ndb, &same, &other);
        wcr_chain_free(&same);
        wcr_chain_free(&other);
        wcr_chain_free(&shorter);
    }
    if (open)
        node_db_close(&ndb);
    return failures;
}

/* The datadir held connected rows above a rewound tip: 4900 and 5000 are both
 * status 3 (the demotion path never touches them), the active chain is back at
 * 3000. The birthday records 5000 and the floor block 4900; the chain does
 * not hold it, so the wallet scans everything. A chain that does hold the
 * block makes the same birthday valid: every block up to it was in the
 * datadir before the wallet. */
static int birthday_rewound_chains(struct node_db *ndb)
{
    int failures = 0;
    struct wcr_chain rewound, regrown;
    bool made = wcr_chain_make(&rewound, 3001, -1, 0) &&
                wcr_chain_make(&regrown, 5002, 4900, 0x49);
    struct wallet *w = made ? wcr_boot_wallet(ndb, &rewound, 0) : NULL;
    WCR_CHECK("a chain rewound to 3000 does not hold the floor block: the "
              "blocks 3001..4899 are not skipped",
              w && w->initial_scan_floor == 0 && wcr_marked_unread(w));
    int floor = 0;
    WCR_CHECK("a chain that holds block 4900 makes it valid",
              made && wallet_birthday_check(ndb, &regrown.chain, &floor) ==
                          WALLET_BIRTHDAY_VALID && floor == 4900);
    if (w) {
        wallet_free(w);
        free(w);
    }
    if (made) {
        wcr_chain_free(&rewound);
        wcr_chain_free(&regrown);
    }
    return failures;
}

static int birthday_rewound(void)
{
    int failures = 0;
    char dir[1024];
    wcr_fixture(dir, sizeof(dir), "birthday_rewound");
    bool seeded = wcr_block(dir, 0x49, 4900, 3) && wcr_block(dir, 0x50, 5000, 3);
    struct wcr_run run;
    memset(&run, 0, sizeof(run));
    bool created = seeded && wcr_create(dir, WCR_PASS, &run) && run.rc == 0;
    struct node_db ndb;
    int64_t b = 0;
    uint8_t hash[32];
    bool open = created && wcr_open(&ndb, dir);
    WCR_CHECK("a rewound datadir records its highest connected row as the tip",
              open && db_wallet_birthday_get(&ndb, &b, hash) && b == 5000);
    if (open) {
        failures += birthday_rewound_chains(&ndb);
        node_db_close(&ndb);
    }
    return failures;
}

/* The scan state a datadir persisted, read the way boot reads it. */
static bool wcr_scan_marker(const char *dir, struct wallet *w)
{
    struct node_db ndb;
    struct wallet_sqlite ws;
    bool ok = wcr_open(&ndb, dir) && wallet_sqlite_open_r(&ws, ndb.db).ok;
    if (ok) {
        wallet_init(w);
        ok = wallet_sqlite_read_scan_state(&ws, w);
        wallet_sqlite_close(&ws);
    }
    if (ndb.open)
        node_db_close(&ndb);
    return ok;
}

/* A restored wallet has read none of the chain, and boot defers a long
 * range, so it persists a pending retry from height 0 and reads incomplete.
 * A created wallet has its birthday and carries no marker. */
static int restored_marker(const char *created_dir)
{
    int failures = 0;
    char dir[1024];
    wcr_fixture(dir, sizeof(dir), "restored_marker");
    struct wallet_recovery_report rep;
    bool restored = wcr_restore(dir, "abandon abandon abandon abandon abandon "
                                "abandon abandon abandon abandon abandon "
                                "abandon about", &rep);
    struct wallet *w = calloc(1, sizeof(*w));
    bool read = restored && w && wcr_scan_marker(dir, w);
    WCR_CHECK("a restored wallet persists a pending retry from height 0",
              read && w->scan_retry.pending && w->scan_retry.from == 0 &&
              strcmp(w->scan_retry.blocker, "WALLET_RESTORE_UNREAD") == 0);
    WCR_CHECK("and claims no scanned-through height, so it reads incomplete",
              read && wallet_scanned_through_height(w) < 0);
    if (read)
        wallet_free(w);
    memset(w, 0, w ? sizeof(*w) : 0);
    bool again = w && wcr_scan_marker(created_dir, w);
    WCR_CHECK("a created wallet carries no such marker",
              again && !w->scan_retry.pending);
    if (again)
        wallet_free(w);
    free(w);
    return failures;
}

static int birthday_absent_when_restored(void)
{
    int failures = 0;
    char dir[1024];
    wcr_fixture(dir, sizeof(dir), "birthday_restored");
    struct wallet_recovery_report rep;
    bool r = wcr_restore(dir, "abandon abandon abandon abandon abandon "
                         "abandon abandon abandon abandon abandon abandon "
                         "about", &rep);
    struct node_db ndb;
    int64_t b = 0;
    uint8_t hash[32];
    struct wcr_chain k;
    bool open = r && wcr_open(&ndb, dir);
    bool made = open && wcr_chain_make(&k, 1002, -1, 0);
    int floor = 0;
    WCR_CHECK("a restored wallet has no birthday and scans from 0",
              made && !db_wallet_birthday_get(&ndb, &b, hash) &&
              wallet_birthday_check(&ndb, &k.chain, &floor) ==
                  WALLET_BIRTHDAY_NONE);
    if (made)
        wcr_chain_free(&k);
    if (open)
        node_db_close(&ndb);
    return failures;
}

static bool wcr_marked_deferred(const struct wallet *w, int from)
{
    return w && w->scan_retry.pending && w->scan_retry.from == from &&
           strcmp(w->scan_retry.blocker, "WALLET_CATCH_UP_DEFERRED") == 0 &&
           wallet_scanned_through_height(w) < from;
}

/* A wallet that has scanned nothing and holds no valid birthday must not read
 * complete after boot defers its first catch-up. Created with no chain in the
 * datadir (the lost-reply route), it has no birthday; a seed chain above 1000
 * blocks arrives, and boot defers. The same holds for a valid floor whose gap
 * to the tip is 50000 blocks or more. */
static int birthday_deferred_marker(void)
{
    int failures = 0;
    char dir[1024];
    wcr_fixture(dir, sizeof(dir), "birthday_deferred");
    struct wcr_run run;
    memset(&run, 0, sizeof(run));
    bool created = wcr_create(dir, WCR_PASS, &run) && run.rc == 0;
    struct node_db ndb;
    struct wcr_chain k, far;
    bool open = created && wcr_open(&ndb, dir);
    bool made = open && wcr_chain_make(&k, 1002, -1, 0);
    int64_t b = 0;
    uint8_t hash[32];
    WCR_CHECK("a wallet created with no chain records no birthday",
              open && !db_wallet_birthday_get(&ndb, &b, hash));
    struct wallet *w = made ? wcr_boot_wallet(&ndb, &k, 0) : NULL;
    WCR_CHECK("boot on a seed chain above 1000 blocks marks it unread from 0, "
              "so it reads incomplete", wcr_marked_deferred(w, 0));
    if (w) {
        wallet_free(w);
        free(w);
    }
    if (made)
        wcr_chain_free(&k);
    if (open)
        node_db_close(&ndb);

    char dir2[1024];
    wcr_fixture(dir2, sizeof(dir2), "birthday_gap");
    bool seeded = wcr_block(dir2, 0x09, 100, 3) && wcr_block(dir2, 0x0a, 200, 3);
    struct wcr_run made_run;
    memset(&made_run, 0, sizeof(made_run));
    seeded = seeded && wcr_create(dir2, WCR_PASS, &made_run) &&
             made_run.rc == 0;
    bool open2 = seeded && wcr_open(&ndb, dir2);
    bool made2 = open2 && wcr_chain_make(&far, 52000, 100, 0x09);
    struct wallet *g = made2 ? wcr_boot_wallet(&ndb, &far, 0) : NULL;
    WCR_CHECK("a valid floor 50000 or more blocks below the tip marks the "
              "range unread from the floor", wcr_marked_deferred(g, 100));
    struct wallet *s = made2 ? wcr_boot_wallet(&ndb, &far, 7) : NULL;
    WCR_CHECK("a wallet that has scanned is not marked by the deferral",
              s && !s->scan_retry.pending);
    if (g) {
        wallet_free(g);
        free(g);
    }
    if (s) {
        wallet_free(s);
        free(s);
    }
    if (made2)
        wcr_chain_free(&far);
    if (open2)
        node_db_close(&ndb);
    return failures;
}

static int t_birthday(void)
{
    int failures = 0;
    char dir[1024];
    wcr_fixture(dir, sizeof(dir), "birthday");
    bool seeded = wcr_block(dir, 0x09, 900, 3) && wcr_block(dir, 0x0a, 1000, 3);
    struct wcr_run run;
    memset(&run, 0, sizeof(run));
    WCR_CHECK("a datadir with a connected tip at 1000 creates a wallet",
              seeded && wcr_create(dir, WCR_PASS, &run) && run.rc == 0);
    failures += birthday_stored(dir, &run);
    failures += birthday_chain_checks(dir);
    failures += birthday_rewound();
    failures += restored_marker(dir);
    failures += birthday_absent_when_restored();
    failures += birthday_deferred_marker();
    return failures;
}

/* ── case 6: weak passphrases ──────────────────────────────────────── */

static int weak_case(const char *tag, const char *pass, const char *code)
{
    int failures = 0;
    char dir[1024], label[160], dummy[600];
    wcr_fixture(dir, sizeof(dir), tag);
    struct wcr_run run;
    memset(&run, 0, sizeof(run));
    bool ran = wcr_create(dir, pass, &run);
    snprintf(label, sizeof(label), "%s passphrase is refused, nothing made",
             tag);
    WCR_CHECK(label, ran && run.rc != 0 &&
              (wcr_error_is(&run, code) ||
               ((!pass || !pass[0]) &&
                wcr_error_is(&run, "INVALID_INPUT"))) &&
              !wcr_field(&run, "phrase", dummy, sizeof(dummy)) &&
              !wcr_exists(dir, "node.db"));
    return failures;
}

static int t_weak_passphrases(void)
{
    int failures = 0;
    failures += weak_case("empty", "", "PASSPHRASE_TOO_SHORT");
    failures += weak_case("short", "elevenbytes", "PASSPHRASE_TOO_SHORT");
    failures += weak_case("missing", NULL, "PASSPHRASE_TOO_SHORT");
    return failures;
}

/* ── case 7: agents and argument transport are refused ─────────────── */

static int t_authority(void)
{
    int failures = 0;
    char dir[1024];
    wcr_fixture(dir, sizeof(dir), "authority");
    const struct zcl_command_registry *reg = zcl_command_catalog();
    const struct zcl_command_spec *spec = NULL;
    for (size_t i = 0; i < reg->count && !spec; i++)
        if (!strcmp(reg->commands[i].path, "core.wallet.create"))
            spec = &reg->commands[i];
    WCR_CHECK("the command is registered OWNER, wallet risk, local",
              spec && spec->authority == ZCL_COMMAND_AUTH_OWNER &&
              spec->scope == ZCL_COMMAND_SCOPE_LOCAL &&
              spec->risk == ZCL_COMMAND_RISK_WALLET);
    if (!spec)
        return failures + 1;

    struct json_value input;
    json_init(&input);
    json_set_object(&input);
    (void)json_push_kv_str(&input, "datadir", dir);
    (void)json_push_kv_str(&input, "passphrase", WCR_PASS);

    static char out[ZCL_COMMAND_RESULT_BUDGET + 1];
    enum zcl_command_exit code = ZCL_COMMAND_EXIT_OK;
    struct zcl_command_context agent = {
        .registry = reg, .granted_capabilities = ~(uint64_t)0,
        .authority_ceiling = ZCL_COMMAND_AUTH_OPERATOR,
    };
    (void)zcl_command_registry_execute_json(reg, spec, &agent, &input, false,
        spec->path, "normal", 0, 0, NULL, out, sizeof(out), &code);
    WCR_CHECK("a caller below owner authority is denied",
              code == ZCL_COMMAND_EXIT_DENIED &&
              strstr(out, "AUTHORITY_DENIED") != NULL &&
              strstr(out, "\"phrase\"") == NULL);
    WCR_CHECK("and nothing was created", !wcr_exists(dir, "node.db"));

    struct zcl_command_context owner = agent;
    owner.authority_ceiling = ZCL_COMMAND_AUTH_OWNER;
    (void)zcl_command_registry_execute_json(reg, spec, &owner, &input, false,
        spec->path, "normal", 0, 0, NULL, out, sizeof(out), &code);
    WCR_CHECK("an owner that did not use standard input is refused",
              strstr(out, "STDIN_REQUIRED") != NULL &&
              strstr(out, WCR_PASS) == NULL &&
              !wcr_exists(dir, "node.db"));
    json_free(&input);
    return failures;
}

/* ── case 8: standard output is the document and nothing else ─────────── */

/* A strict parser reads the whole of stdout. Log lines ahead of the document
 * would fail it after the wallet was committed, and the phrase would be lost:
 * the shown-once phrase cannot be fetched again and a retry is refused. */
static bool wcr_wire_is_one_document(const struct wcr_run *run)
{
    struct json_value v;
    json_init(&v);
    size_t len = strlen(run->wire);
    while (len > 0 && (run->wire[len - 1] == '\n' || run->wire[len - 1] == ' '))
        len--;
    bool ok = run->wire[0] == '{' && json_read(&v, run->wire, len);
    json_free(&v);
    return ok;
}

static int t_stdout_is_the_document(void)
{
    int failures = 0;
    char dir[1024], phrase[600];
    wcr_fixture(dir, sizeof(dir), "stdout");
    struct wcr_run run;
    memset(&run, 0, sizeof(run));
    bool got = wcr_create(dir, WCR_PASS, &run) &&
               wcr_field(&run, "phrase", phrase, sizeof(phrase));
    WCR_CHECK("create succeeds", got);
    WCR_CHECK("stdout is exactly one JSON document, no log line before it",
              got && wcr_wire_is_one_document(&run));
    WCR_CHECK("the log lines of opening the datadir went to stderr",
              got && run.err[0] != '\0');
    memory_cleanse(phrase, sizeof(phrase));

    struct wcr_run again;
    memset(&again, 0, sizeof(again));
    WCR_CHECK("a refusal is also exactly one document",
              wcr_create(dir, WCR_PASS, &again) && again.rc != 0 &&
              wcr_wire_is_one_document(&again) &&
              strstr(again.wire, "no command can show that phrase again"));
    return failures + !got;
}

/* ── case 9: core dumps are off once the handler runs ──────────────────── */

static int t_core_dumps_disabled(void)
{
    int failures = 0;
    struct rlimit saved, now;
    bool have_limit = getrlimit(RLIMIT_CORE, &saved) == 0;
    if (have_limit) {
        struct rlimit raised = { saved.rlim_max < 1048576 ? saved.rlim_max
                                                          : 1048576,
                                 saved.rlim_max };
        (void)setrlimit(RLIMIT_CORE, &raised);
    }
#ifdef __linux__
    (void)prctl(PR_SET_DUMPABLE, 1, 0, 0, 0);
#endif
    char dir[1024];
    wcr_fixture(dir, sizeof(dir), "core");
    struct wcr_run run;
    memset(&run, 0, sizeof(run));
    bool ran = wcr_create(dir, WCR_PASS, &run);
#ifdef __linux__
    WCR_CHECK("the handler makes the process undumpable",
              ran && prctl(PR_GET_DUMPABLE, 0, 0, 0, 0) == 0);
#endif
    /* A host whose hard limit is already zero cannot tell the two apart. */
    WCR_CHECK("the handler sets the core dump limit to zero",
              ran && getrlimit(RLIMIT_CORE, &now) == 0 && now.rlim_cur == 0);
    if (have_limit)
        (void)setrlimit(RLIMIT_CORE, &saved);
    return failures;
}

/* ── case 10: a legacy wallet directory is not an empty datadir ────────── */

static int t_legacy_wallet_directory(void)
{
    int failures = 0;
    char dir[1024], legacy[1100], dummy[600];
    wcr_fixture(dir, sizeof(dir), "legacy");
    snprintf(legacy, sizeof(legacy), "%s/wallet", dir);
    bool made = mkdir(legacy, 0700) == 0;
    struct wcr_run run;
    memset(&run, 0, sizeof(run));
    WCR_CHECK("a datadir holding a wallet/ directory is refused by name and "
              "nothing is made",
              made && wcr_create(dir, WCR_PASS, &run) && run.rc != 0 &&
              wcr_error_is(&run, "WALLET_ALREADY_PRESENT") &&
              !wcr_field(&run, "phrase", dummy, sizeof(dummy)) &&
              !wcr_exists(dir, "node.db"));
    return failures;
}

/* ── case 11: boot never mints or imports over a created wallet ───────── */

/* A created wallet holds a seed and Sapling keys and no transparent key. The
 * boot decisions below read those rows; a count of transparent keys alone
 * calls the wallet empty and draws a second seed over it, or lets a legacy
 * import replace it. */
/* A table that does not exist holds nothing; one that cannot be read is a row
 * at risk, never an empty answer. */
static int t_unreadable_rows(void)
{
    int failures = 0;
    char gone[1024], broken[1024];
    wcr_fixture(gone, sizeof(gone), "rows_gone");
    wcr_fixture(broken, sizeof(broken), "rows_broken");
    struct node_db n1, n2;
    memset(&n1, 0, sizeof(n1));
    memset(&n2, 0, sizeof(n2));
    /* Opening a datadir creates its schema, so the tables go after the open. */
    bool o1 = wcr_open(&n1, gone) &&
              sqlite3_exec(n1.db, "DROP TABLE wallet_seed; "
                           "DROP TABLE wallet_sapling_keys",
                           NULL, NULL, NULL) == SQLITE_OK;
    bool o2 = wcr_open(&n2, broken) &&
              sqlite3_exec(n2.db, "DROP TABLE wallet_seed; CREATE VIEW "
                           "wallet_seed AS SELECT * FROM nowhere",
                           NULL, NULL, NULL) == SQLITE_OK;
    WCR_CHECK("wallet tables that do not exist hold no rows at risk",
              o1 && boot_wallet_rows_at_risk(&n1, 0) == 0);
    WCR_CHECK("a wallet table that cannot be read is a row at risk",
              o2 && boot_wallet_rows_at_risk(&n2, 0) >= 1);
    if (n1.open)
        node_db_close(&n1);
    if (n2.open)
        node_db_close(&n2);
    return failures;
}

static int guard_case(const char *dir, const char *name, bool first_run)
{
    int failures = 0;
    struct node_db ndb;
    struct wallet_sqlite ws;
    char label[200];
    bool open = wcr_open(&ndb, dir) && wallet_sqlite_open_r(&ws, ndb.db).ok;
    snprintf(label, sizeof(label), "%s: first run is %s, the legacy import "
             "and the mint agree", name, first_run ? "yes" : "no");
    WCR_CHECK(label, open && boot_wallet_is_first_run(&ws, 0) == first_run &&
              boot_wallet_may_mint(&ws, 0) == first_run);
    snprintf(label, sizeof(label), "%s: any transparent key is not a first "
             "run", name);
    WCR_CHECK(label, open && !boot_wallet_is_first_run(&ws, 3) &&
              !boot_wallet_may_mint(&ws, 3));
    snprintf(label, sizeof(label), "%s: the rows at risk %s", name,
             first_run ? "are none" : "are counted");
    WCR_CHECK(label, open &&
              (boot_wallet_rows_at_risk(&ndb, 0) == 0) == first_run);
    if (open) {
        wallet_sqlite_close(&ws);
        node_db_close(&ndb);
    }
    return failures;
}

static int t_boot_guards(void)
{
    int failures = 0;
    char made[1024], fresh[1024], seed_only[1024], sapling_only[1024];
    wcr_fixture(made, sizeof(made), "guard_made");
    wcr_fixture(fresh, sizeof(fresh), "guard_fresh");
    wcr_fixture(seed_only, sizeof(seed_only), "guard_seed");
    wcr_fixture(sapling_only, sizeof(sapling_only), "guard_sapling");
    struct wcr_run run;
    memset(&run, 0, sizeof(run));
    bool created = wcr_create(made, WCR_PASS, &run) && run.rc == 0;
    bool seeded = wcr_sql(seed_only,
        "INSERT INTO wallet_seed(id,seed) VALUES(1,zeroblob(32))");
    bool keyed = wcr_sql(sapling_only,
        "INSERT INTO wallet_sapling_keys(ivk,xsk,xfvk,diversifier,pk_d,"
        "child_index) VALUES(zeroblob(32),zeroblob(169),zeroblob(169),"
        "zeroblob(11),zeroblob(32),0)");
    WCR_CHECK("fixtures: a created wallet, a lone seed, a lone Sapling key",
              created && seeded && keyed);

    failures += guard_case(fresh, "an empty datadir", true);
    failures += guard_case(made, "a created wallet (seed and Sapling keys, "
                           "no transparent key)", false);
    failures += guard_case(seed_only, "a lone seed row", false);
    failures += guard_case(sapling_only, "a lone Sapling key", false);

    struct wallet_sqlite closed;
    memset(&closed, 0, sizeof(closed));
    WCR_CHECK("a closed persistence layer mints nothing", 
              !boot_wallet_may_mint(&closed, 0) &&
              !boot_wallet_is_first_run(&closed, 0));
    struct node_db ndb;
    bool open = wcr_open(&ndb, made);
    WCR_CHECK("a transparent key count is added to the rows at risk",
              open && boot_wallet_rows_at_risk(&ndb, 3) >= 5);
    if (open)
        node_db_close(&ndb);
    failures += t_unreadable_rows();
    return failures;
}

/* ── case 12: dependent on the wallet-lock worker ──────────────────────── */

/* A payment to a created wallet, built by the production payer path. */
static bool wcr_payment_tx(struct transaction *tx, const char *address,
                           uint64_t value)
{
    uint8_t d[ZC_DIVERSIFIER_SIZE], pk_d[32], ovk[32];
    uint8_t cv[32] = {0}, cm[32] = {0}, epk[32] = {0};
    uint8_t enc[ZC_SAPLING_ENCCIPHERTEXT_SIZE] = {0};
    uint8_t out[ZC_SAPLING_OUTCIPHERTEXT_SIZE] = {0};
    uint8_t proof[GROTH_PROOF_SIZE] = {0};
    memset(ovk, 0x5a, sizeof(ovk));
    if (!sapling_decode_payment_address(address, d, pk_d) ||
        !sapling_build_output_description(ovk, d, pk_d, value, NULL, cv, cm,
                                          epk, enc, out, proof, NULL))
        return false;
    transaction_init(tx);
    tx->version = 4;
    tx->overwintered = true;
    tx->value_balance = -(int64_t)value;
    tx->v_shielded_output = calloc(1, sizeof(struct output_description));
    if (!tx->v_shielded_output) {
        transaction_free(tx);
        return false;
    }
    tx->num_shielded_output = 1;
    struct output_description *od = &tx->v_shielded_output[0];
    memcpy(od->cv.data, cv, 32);
    memcpy(od->cm.data, cm, 32);
    memcpy(od->ephemeral_key.data, epk, 32);
    memcpy(od->enc_ciphertext, enc, sizeof(enc));
    memcpy(od->out_ciphertext, out, sizeof(out));
    memcpy(od->zkproof, proof, sizeof(proof));
    return true;
}

/* A payment to the created address, read by a wallet that was loaded without
 * its passphrase. */
static bool wcr_locked_payment_found(struct wallet *w, struct wallet_sqlite *ws,
                                     const char *address)
{
    bool read = wallet_sqlite_read_sapling_keys(ws, w);
    struct transaction tx;
    bool built = wcr_payment_tx(&tx, address, 125000000ULL);
    struct uint256 txid;
    memset(&txid, 0, sizeof(txid));
    txid.data[0] = 0xC7;
    int found = built ? wallet_try_sapling_decrypt(w, &tx, &txid) : 0;
    printf("    locked-payment facts: keys_read=%d built=%d unlocked=%d "
           "keystore_keys=%zu found=%d\n", read, built,
           wallet_lock_is_unlocked(), w->sapling_keys.num_keys, found);
    if (built)
        transaction_free(&tx);
    return read && built && !wallet_lock_is_unlocked() && found == 1 &&
           w->num_sapling_notes == 1;
}

/* DEPENDS ON THE WALLET-LOCK WORK (lane claude-app-status: wallet_lock.c and
 * wallet_sqlite.c). Until it lands the two checks named "needs wallet-lock"
 * fail: they assert behaviour of the lock layer on a created wallet, not of
 * the create command, and nothing here edits that layer. */
static int t_locked_wallet(void)
{
    int failures = 0;
    char dir[1024], address[200];
    wcr_fixture(dir, sizeof(dir), "locked");
    struct wcr_run run;
    memset(&run, 0, sizeof(run));
    bool created = wcr_create(dir, WCR_PASS, &run) && run.rc == 0 &&
                   wcr_field(&run, "first_shielded_address", address,
                             sizeof(address));
    WCR_CHECK("create succeeds", created);
    if (!created)
        return failures + 1;

    wallet_lock_reset_for_test();
    struct node_db ndb;
    struct wallet_sqlite ws;
    bool open = wcr_open(&ndb, dir) && wallet_sqlite_open_r(&ws, ndb.db).ok;
    struct wallet *w = open ? calloc(1, sizeof(*w)) : NULL;
    if (w)
        wallet_init(w);
    WCR_CHECK("the created wallet opens", open && w);
    if (!w) {
        if (open) {
            wallet_sqlite_close(&ws);
            node_db_close(&ndb);
        }
        return failures + 1;
    }

    struct zcl_result bad = wallet_lock_unlock(w, &ws, "not-the-passphrase-0");
    WCR_CHECK("needs wallet-lock: a wrong passphrase is refused for a created "
              "wallet", !bad.ok);
    wallet_lock_lock(w);
    WCR_CHECK("needs wallet-lock: a payment to the created address is found "
              "while the wallet is locked",
              wcr_locked_payment_found(w, &ws, address));
    wallet_lock_lock(w);
    wallet_free(w);
    free(w);
    wallet_sqlite_close(&ws);
    node_db_close(&ndb);
    return failures;
}

int test_wallet_create(void);
int test_wallet_create(void)
{
    int failures = 0;
    chain_params_select(CHAIN_MAIN);
    failures += t_round_trip();
    failures += t_refusals();
    failures += t_phrase_not_captured_and_encrypted();
    failures += t_birthday();
    failures += t_weak_passphrases();
    failures += t_authority();
    failures += t_stdout_is_the_document();
    failures += t_core_dumps_disabled();
    failures += t_legacy_wallet_directory();
    failures += t_boot_guards();
    failures += t_locked_wallet();
    if (failures == 0)
        printf("wallet_create: OK (all wallet creation gates pass)\n");
    else
        printf("=== wallet_create: %d failure(s) ===\n", failures);
    return failures;
}
