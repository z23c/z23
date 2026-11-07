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
 *   5. The birthday is never above the highest height the datadir or the
 *      release proves (connected tip, shipped anchor, best header); only the
 *      first scan of the wallet starts below it, once the chain reaches its
 *      floor block and only while that block is still active. No other scan
 *      range is raised.
 *   6. An empty, short or missing passphrase is refused and nothing is made.
 *   7. An agent-ceiling caller is refused before the handler, and a caller
 *      that did not use standard input is refused by the handler.
 *   8. Standard output is one JSON document; log lines go to stderr.
 *   9. Core dumps are off. 10. A wallet/ directory refuses create.
 *  11. Boot reads seed and Sapling rows, so it never mints or imports over a
 *      created wallet; a closed store mints nothing.
 *  12. A wrong passphrase is refused and a payment is found while locked
 *      (these two depend on the wallet-lock work).
 *  13. The restore inputs the phone flow needs: a passphrase on standard
 *      input, shielded_only, a verified birthday and birthday_at_local_tip.
 *  14. A node whose blocks are behind still creates: the birthday comes from
 *      its shipped anchor or best header, never above either, and boot waits
 *      for the chain to reach its floor without marking anything unread. A
 *      node whose blocks are well past the anchor takes its own tip and never
 *      opens block_index.bin.
 */

#define _POSIX_C_SOURCE 200809L

#include "test/test_core.h"

#include "chain/chain.h"
#include "chain/chainparams.h"
#include "chain/checkpoints.h"
#include "chain/pow.h"
#include "config/boot_internal.h"
#include "config/boot_wallet_phrase.h"
#include "command/native_command.h"
#include "config/command_catalog.h"
#include "controllers/wallet_native_handlers.h"
#include "controllers/wallet_scan.h"
#include "core/arith_uint256.h"
#include "json/json.h"
#include "zjsonp/zjsonp.h"
#include "kernel/command_registry.h"
#include "keys/key.h"
#include "keys/pubkey.h"
#include "models/database.h"
#include "models/wallet_key.h"
#include "services/block_index_loader.h"
#include "services/wallet_create_service.h"
#include "services/wallet_recovery_service.h"
#include "support/cleanse.h"
#include "validation/chainstate.h"
#include "validation/main_state.h"
#include "sapling/constants.h"
#include "sapling/note_encryption.h"
#include "sapling/sapling.h"
#include "primitives/transaction.h"
#include "wallet/bip44.h"
#include "wallet/mnemonic.h"
#include "wallet/sapling_keys.h"
#include "wallet/wallet.h"
#include "wallet/wallet_lock.h"
#include "wallet/wallet_sqlite.h"

#include <dirent.h>
#include <errno.h>
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
#include <sys/wait.h>
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
    size_t wire_len;
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

static bool wcr_slurp(FILE *f, char *out, size_t cap, size_t *length)
{
    if (fflush(f) != 0 || fseek(f, 0, SEEK_SET) != 0)
        return false;
    size_t n = fread(out, 1, cap - 1, f);
    out[n] = '\0';
    if (length)
        *length = n;
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
static bool wcr_cap_end(struct wcr_cap *c, char *out, size_t cap, size_t *length)
{
    fflush(c->stream);
    bool ok = wcr_restore_fd(c->saved, c->stream);
    if (ok && out)
        ok = wcr_slurp(c->tmp, out, cap, length);
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
    ok = wcr_cap_end(&in, NULL, 0, NULL) && ok;
    ok = wcr_cap_end(&out, run->wire, sizeof(run->wire), &run->wire_len) && ok;
    ok = wcr_cap_end(&err, run->err, sizeof(run->err), NULL) && ok;
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

/* Occurrences of `needle` in every regular file under `dir`. Directories and
 * files that cannot be read, entries that are not regular files or
 * directories, and a failed directory read are counted in `*unreadable`,
 * apart from the matches. */
static size_t wcr_scan_tree(const char *dir, const char *needle, size_t nlen,
                            size_t *unreadable)
{
    size_t total = 0;
    DIR *d = opendir(dir);
    if (!d) {
        (*unreadable)++;
        return 0;
    }
    struct dirent *e;
    for (;;) {
        errno = 0;
        e = readdir(d);
        if (!e)
            break;
        if (!strcmp(e->d_name, ".") || !strcmp(e->d_name, ".."))
            continue;
        char path[1400];
        snprintf(path, sizeof(path), "%s/%s", dir, e->d_name);
        struct stat st;
        if (lstat(path, &st) != 0) {
            (*unreadable)++;
            continue;
        }
        if (S_ISDIR(st.st_mode)) {
            total += wcr_scan_tree(path, needle, nlen, unreadable);
            continue;
        }
        if (!S_ISREG(st.st_mode)) {
            (*unreadable)++;
            continue;
        }
        FILE *f = fopen(path, "rb");
        char *buf = f ? malloc((size_t)st.st_size + 1) : NULL;
        if (buf && fread(buf, 1, (size_t)st.st_size, f) == (size_t)st.st_size)
            total += wcr_count(buf, (size_t)st.st_size, needle, nlen);
        else
            (*unreadable)++;
        free(buf);
        if (f) fclose(f);
    }
    if (errno != 0)
        (*unreadable)++;
    closedir(d);
    return total;
}

/* Matches plus one when anything was unreadable: a scan that skipped a file
 * would call it clean, and every caller asserting absence expects zero. */
static size_t wcr_count_in_tree(const char *dir, const char *needle,
                                size_t nlen)
{
    size_t unreadable = 0;
    size_t matches = wcr_scan_tree(dir, needle, nlen, &unreadable);
    return matches + (unreadable ? 1 : 0);
}

/* True when the scan read every file and found `seed` in at least one. */
static bool wcr_scan_proves_seed(const char *dir, const uint8_t seed[32])
{
    size_t unreadable = 0;
    size_t matches = wcr_scan_tree(dir, (const char *)seed, 32, &unreadable);
    return unreadable == 0 && matches > 0;
}

/* Occurrences of the spending key scalars the phrase's seed derives, in every
 * file under `dir`. An unreadable file counts, as above. */
static bool wcr_spending_key_scan(const char *dir, const uint8_t seed[32],
                                  size_t *matches)
{
    struct sapling_keystore sks;
    uint8_t div[ZC_DIVERSIFIER_SIZE], pk_d[32];
    sapling_keystore_init(&sks);
    size_t unreadable = 0;
    *matches = 0;
    bool derived = sapling_keystore_set_seed(&sks, seed) &&
                   sapling_keystore_new_address(&sks, div, pk_d);
    if (derived) {
        const struct zip32_expsk *k = &sks.keys[0].xsk.expsk;
        *matches = wcr_scan_tree(dir, (const char *)k->ask, 32, &unreadable) +
                   wcr_scan_tree(dir, (const char *)k->nsk, 32, &unreadable);
    }
    sapling_keystore_free(&sks);
    return derived && unreadable == 0;
}

/* For checks that assert absence: a failed derivation or an unreadable file
 * counts as a hit, so the check cannot pass without having searched. */
static size_t wcr_spending_key_in_tree(const char *dir, const uint8_t seed[32])
{
    size_t matches;
    return wcr_spending_key_scan(dir, seed, &matches) ? matches : matches + 1;
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
    WCR_CHECK("the Sapling spending key scalars are in no file of the datadir",
              wcr_spending_key_in_tree(dir, seed) == 0);

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
    ok = wcr_cap_end(&cap, log, sizeof(log), NULL) && ok;
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

static int birthday_pending(struct node_db *ndb, struct wcr_chain *other)
{
    int failures = 0;
    struct wallet *pending = calloc(1, sizeof(*pending));
    if (pending) {
        wallet_init(pending);
        pending->best_block_height = 1002;
        pending->scan_retry.pending = true;
        pending->scan_retry.from = 100;
        pending->scan_retry.since = 123;
        snprintf(pending->scan_retry.blocker, sizeof(pending->scan_retry.blocker),
                 "%s", "OTHER_UNREAD");
        (void)boot_wallet_boot_catch_up(pending, &other->chain, "/nonexistent", ndb);
    }
    WCR_CHECK("a changed birthday lowers existing unread coverage to genesis",
              pending && pending->scan_retry.pending &&
              pending->scan_retry.from == 0 && pending->scan_retry.since == 123);
    if (pending) { wallet_free(pending); free(pending); }
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
    WCR_CHECK("a scanned wallet on a changed chain is marked unread",
              c && c->initial_scan_floor == 0 && c->scan_retry.pending &&
              c->scan_retry.from == 0 && wallet_scanned_through_height(c) < 0);
    failures += birthday_pending(ndb, other);
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
static int birthday_sparse_chain(struct node_db *ndb, struct wcr_chain *same)
{
    int failures = 0, floor = -1;
    struct block_index *saved = same->chain.chain[900];
    same->chain.chain[900] = NULL;
    WCR_CHECK("missing birthday slot is unavailable, not changed",
              wallet_birthday_check(ndb, &same->chain, &floor) ==
              WALLET_BIRTHDAY_UNAVAILABLE && floor == 900);
    struct wallet *w = wcr_boot_wallet(ndb, same, 0);
    WCR_CHECK("sparse birthday keeps the first scan pending",
              w && w->initial_scan_floor == 900 && w->scan_retry.pending &&
              w->scan_retry.from == 0 &&
              strcmp(w->scan_retry.blocker, WALLET_BIRTHDAY_PENDING) == 0);
    if (w) {
        wallet_birthday_reconcile(w, ndb, &same->chain, active_chain_tip(&same->chain));
        WCR_CHECK("tip notification cannot reject a missing birthday slot",
                  w->initial_scan_floor == 900 && w->scan_retry.from == 0 &&
                  strcmp(w->scan_retry.blocker, WALLET_BIRTHDAY_PENDING) == 0);
    }
    same->chain.chain[900] = saved;
    if (w) {
        wallet_birthday_reconcile(w, ndb, &same->chain, active_chain_tip(&same->chain));
        WCR_CHECK("available matching birthday starts its bounded scan",
                  w->initial_scan_floor == 900 && w->scan_retry.pending &&
                  w->scan_retry.from == 900 &&
                  strcmp(w->scan_retry.blocker, WALLET_BIRTHDAY_SCAN_PENDING) == 0);
        w->initial_scan_floor = 900;
        w->scan_retry.from = 0;
        snprintf(w->scan_retry.blocker, sizeof(w->scan_retry.blocker), "%s", WALLET_BIRTHDAY_PENDING);
        WCR_CHECK("changed persisted birthday fixture",
                  db_wallet_birthday_set(ndb, 901 + WALLET_BIRTHDAY_MARGIN, saved->phashBlock->data));
        wallet_birthday_reconcile(w, ndb, &same->chain, active_chain_tip(&same->chain));
        WCR_CHECK("changed stored birthday does not wait as sparse history",
                  w->initial_scan_floor == 0 && w->scan_retry.from == 0 &&
                  strcmp(w->scan_retry.blocker, WALLET_BIRTHDAY_CHANGED_BLOCKER) == 0);
        WCR_CHECK("restore persisted birthday fixture",
                  db_wallet_birthday_set(ndb, 900 + WALLET_BIRTHDAY_MARGIN, saved->phashBlock->data));
        wallet_free(w); free(w);
    }
    return failures;
}

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
    WCR_CHECK("a chain that has not reached the floor waits for it at 900",
              made && wallet_birthday_check(&ndb, &shorter.chain, &floor) ==
                          WALLET_BIRTHDAY_AHEAD && floor == 900);
    if (made) {
        failures += birthday_sparse_chain(&ndb, &same);
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
 * 3000. The birthday records 5000 and the floor block 4900. The chain has not
 * reached it, so coverage stays unread while the first scan waits. A chain
 * that holds the block makes the same birthday valid: every
 * block up to it was in the datadir before the wallet. A chain that reaches
 * 4900 with another block there scans everything. */
static int birthday_rewound_at_floor(struct node_db *ndb, struct wcr_chain *regrown, struct wallet *w);

static int birthday_rewound_floor(struct node_db *ndb, struct wcr_chain *regrown, struct wallet *w, bool made)
{
    int failures = 0;
    WCR_CHECK("a chain rewound to 3000 keeps the floor for when it reaches "
              "4900, runs no catch-up and remains unread",
              w && w->initial_scan_floor == 4900 && w->scan_retry.pending &&
              wallet_scanned_through_height(w) < 0);
    int floor = 0;
    WCR_CHECK("a chain that holds block 4900 makes it valid",
              made && wallet_birthday_check(ndb, &regrown->chain, &floor) ==
                          WALLET_BIRTHDAY_VALID && floor == 4900);
    if (w)
        wallet_birthday_reconcile(w, ndb, &regrown->chain, &regrown->idx[4899]);
    WCR_CHECK("before floor the running wallet remains unread",
              w && w->scan_retry.pending && wallet_scanned_through_height(w) < 0);
    failures += birthday_rewound_at_floor(ndb, regrown, w);
    return failures;
}

static int birthday_rewound_at_floor(struct node_db *ndb, struct wcr_chain *regrown, struct wallet *w)
{
    int failures = 0;
    if (w)
        wallet_birthday_reconcile(w, ndb, &regrown->chain, &regrown->idx[4900]);
    WCR_CHECK("matching floor requires a scan from the verified floor",
              w && w->scan_retry.pending && w->scan_retry.from == 4900 &&
              w->initial_scan_floor == 4900 &&
              strcmp(w->scan_retry.blocker, WALLET_BIRTHDAY_SCAN_PENDING) == 0);
    return failures;
}

static int birthday_rewound_restart(struct node_db *ndb, struct wcr_chain *regrown, struct wallet *w, bool made)
{
    int failures = 0;
    struct wallet *restarted = made ? wcr_boot_wallet(ndb, regrown, 5001) : NULL;
    WCR_CHECK("restart restores the verified floor",
              restarted && restarted->initial_scan_floor == 4900 &&
              !restarted->scan_retry.pending);
    if (restarted)
        (void)wallet_rewind_confirmations(restarted, 4899);
    WCR_CHECK("restart then rewind below floor marks the prefix unread",
              restarted && restarted->initial_scan_floor == 0 &&
              wcr_marked_unread(restarted));
    if (restarted) { wallet_free(restarted); free(restarted); }
    if (w) {
        w->best_block_height = 4900;
        (void)wallet_rewind_confirmations(w, 4899);
    }
    WCR_CHECK("rewind below verified floor marks the prefix unread",
              w && w->initial_scan_floor == 0 && wcr_marked_unread(w));
    return failures;
}

static int birthday_rewound_replaced(struct node_db *ndb, struct wcr_chain *rewound, struct wcr_chain *replaced, struct wallet *w, bool made)
{
    int failures = 0;
    struct wallet *live = made ? wcr_boot_wallet(ndb, rewound, 0) : NULL;
    if (live)
        wallet_birthday_reconcile(live, ndb, &replaced->chain, &replaced->idx[4900]);
    WCR_CHECK("different floor keeps the running wallet unread",
              live && live->initial_scan_floor == 0 && wcr_marked_unread(live));
    if (live) { wallet_free(live); free(live); }
    struct wallet *r = made ? wcr_boot_wallet(ndb, replaced, 0) : NULL;
    WCR_CHECK("a chain with another block at 4900 marks the whole chain unread",
              r && r->initial_scan_floor == 0 && wcr_marked_unread(r));
    if (w) { wallet_free(w); free(w); }
    if (r) { wallet_free(r); free(r); }
    return failures;
}

static int birthday_rewound_chains(struct node_db *ndb)
{
    int failures = 0;
    struct wcr_chain rewound, regrown, replaced;
    bool made = wcr_chain_make(&rewound, 3001, -1, 0) &&
                wcr_chain_make(&regrown, 5002, 4900, 0x49) &&
                wcr_chain_make(&replaced, 5002, 4900, 0x77);
    struct wallet *w = made ? wcr_boot_wallet(ndb, &rewound, 0) : NULL;
    failures += birthday_rewound_floor(ndb, &regrown, w, made);
    failures += birthday_rewound_restart(ndb, &regrown, w, made);
    failures += birthday_rewound_replaced(ndb, &rewound, &replaced, w, made);
    if (made) {
        wcr_chain_free(&rewound);
        wcr_chain_free(&regrown);
        wcr_chain_free(&replaced);
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
    uint8_t proof_hash[32], proof_identity[32]; int64_t proof_height = 0;
    WCR_CHECK("local creation binds its birthday to scan identity", open &&
        db_wallet_birthday_proof_get(&ndb, &proof_height, proof_hash, proof_identity) == WALLET_BIRTHDAY_PROOF_FOUND &&
        proof_height == b && !memcmp(proof_hash, hash, 32));
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
 * blocks arrives, and boot defers. */
static int birthday_deferred_no_chain(void)
{
    int failures = 0;
    char dir[1024];
    wcr_fixture(dir, sizeof(dir), "birthday_deferred");
    struct wcr_run run;
    memset(&run, 0, sizeof(run));
    bool created = wcr_create(dir, WCR_PASS, &run) && run.rc == 0;
    struct node_db ndb;
    struct wcr_chain k;
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
    return failures;
}

/* The same holds for a valid floor whose gap to the tip is 50000 blocks or
 * more, and a wallet that has already scanned is not marked. */
static int birthday_deferred_gap(void)
{
    int failures = 0;
    struct node_db ndb;
    struct wcr_chain far;
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
    failures += birthday_deferred_no_chain();
    failures += birthday_deferred_gap();
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
    transaction_init(tx);
    if (!sapling_decode_payment_address(address, d, pk_d) ||
        !sapling_build_output_description(ovk, d, pk_d, value, NULL, cv, cm,
                                          epk, enc, out, proof, NULL))
        return false;
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

/* ── case 13: the restore inputs the phone flow needs ──────────────── */

#define WCR_RESTORE_PHRASE                                                 \
    "abandon abandon abandon abandon abandon abandon abandon abandon "     \
    "abandon abandon abandon about"
#define WCR_HASH_09 "0909090909090909090909090909090909090909090909090909090909090909"
#define WCR_HASH_77 "7777777777777777777777777777777777777777777777777777777777777777"

static bool wcr_data_bool(const struct wcr_run *run, const char *key)
{
    struct json_value v;
    json_init(&v);
    bool ok = json_read(&v, run->wire, strlen(run->wire)) &&
              json_get_bool_or(json_get(&v, "data"), key, false);
    json_free(&v);
    return ok;
}

static int64_t wcr_data_int(const struct wcr_run *run, const char *key)
{
    struct json_value v;
    json_init(&v);
    int64_t n = json_read(&v, run->wire, strlen(run->wire))
                    ? json_get_int(json_get(json_get(&v, "data"), key)) : -1;
    json_free(&v);
    return n;
}

/* A datadir that holds a chain: connected blocks at 900 (hash 0x09) and 1000.
 * Seeded from a snapshot it holds nothing below 900; from genesis it also
 * holds block 0. */
static bool wcr_seeded_chain(char *dir, size_t cap, const char *tag,
                             bool from_genesis)
{
    wcr_fixture(dir, cap, tag);
    return wcr_block(dir, 0x09, 900, 3) && wcr_block(dir, 0x0a, 1000, 3) &&
           (!from_genesis || wcr_block(dir, 0x01, 0, 3));
}

/* Set by a test that stands for a process serving a wallet: the helper below
 * resets the lock module for each one-shot run and then marks it again. */
static bool wcr_process_serves_wallet;

/* `z23 core wallet recovery restore` on the production path. `extra` is the
 * rest of the input object (leading comma included), `via_stdin` selects
 * --input=- over --input=<json>. */
static bool wcr_restore_phrase_cli(const char *dir, const char *phrase,
                                    const char *extra, bool via_stdin,
                                    struct wcr_run *run)
{
    char text[2048], arg[2100];
    snprintf(text, sizeof(text),
             "{\"datadir\":\"%s\",\"phrase\":\"%s\",\"confirm\":true%s}", dir,
             phrase, extra);
    wallet_lock_reset_for_test();
    if (wcr_process_serves_wallet)
        wallet_lock_note_live_wallet();
    memset(run, 0, sizeof(*run));
    /* Without a passphrase the at-rest policy needs the plaintext opt-in. */
    if (!strstr(extra, "passphrase"))
        setenv("ZCL_ALLOW_PLAINTEXT_WALLET", "1", 1);
    snprintf(arg, sizeof(arg), "--input=%s", text);
    const char *by_stdin[] = {"wallet", "recovery", "restore", "--input=-",
                              "--format=json"};
    const char *by_argv[] = {"wallet", "recovery", "restore", arg,
                             "--format=json"};
    bool ok = via_stdin ? wcr_cli_args(by_stdin, 5, text, run)
                        : wcr_cli_args(by_argv, 5, "", run);
    unsetenv("ZCL_ALLOW_PLAINTEXT_WALLET");
    if (run->rc != 0)
        printf("    restore reply: %.500s\n", run->wire);
    return ok;
}

static bool wcr_restore_cli(const char *dir, const char *extra,
                            bool via_stdin, struct wcr_run *run)
{
    return wcr_restore_phrase_cli(dir, WCR_RESTORE_PHRASE, extra, via_stdin,
                                  run);
}

/* Find the persisted first account after each keystore load. */
static struct sapling_key_entry *wcr_child_zero(struct wallet *w)
{
    for (size_t i = 0; i < w->sapling_keys.num_keys; ++i)
        if (w->sapling_keys.keys[i].used && w->sapling_keys.keys[i].child_index == 0)
            return &w->sapling_keys.keys[i];
    return NULL;
}
/* Compare reopened spending scalars with the phrase-derived first account. */
static bool wcr_first_spending_matches(const struct sapling_key_entry *entry)
{
    uint8_t seed[32], div[ZC_DIVERSIFIER_SIZE], pk_d[32];
    struct sapling_keystore *expected = calloc(1, sizeof(*expected));
    if (!expected) return false;
    sapling_keystore_init(expected);
    bool ok = mnemonic_to_wallet_seed(WCR_RESTORE_PHRASE, NULL, seed) &&
        sapling_keystore_set_seed(expected, seed) &&
        sapling_keystore_new_address(expected, div, pk_d) && entry && !entry->secret_wiped &&
        !memcmp(entry->xsk.expsk.ask, expected->keys[0].xsk.expsk.ask, 32) &&
        !memcmp(entry->xsk.expsk.nsk, expected->keys[0].xsk.expsk.nsk, 32);
    memory_cleanse(seed, sizeof(seed)); sapling_keystore_free(expected); free(expected);
    return ok;
}

/* The successful restore reply names the persisted account-0 receiving key. */
static int restore_address_reopens(void)
{
    int failures = 0;
    char dir[1024], address[200], encoded[200];
    struct wcr_run run;
    wcr_fixture(dir, sizeof(dir), "restore_address_reopens");
    bool ran = wcr_restore_cli(dir, ",\"passphrase\":\"" WCR_PASS "\",\"shielded_only\":true", true, &run);
    bool got = ran && run.rc == 0 && wcr_data_bool(&run, "committed") &&
               wcr_data_bool(&run, "encrypted_at_rest") &&
               wcr_field(&run, "first_shielded_address", address, sizeof(address));
    WCR_CHECK("encrypted restore commits and returns its first address", got);
    if (!got) { test_rm_rf(dir); return failures + 1; }

    wallet_lock_reset_for_test();
    struct node_db ndb;
    bool db_open = wcr_open(&ndb, dir);
    struct wallet_sqlite ws;
    bool ws_open = db_open && wallet_sqlite_open_r(&ws, ndb.db).ok;
    struct wallet *w = ws_open ? calloc(1, sizeof(*w)) : NULL;
    WCR_CHECK("restored wallet reopens", w != NULL);
    if (!w) {
        if (ws_open) wallet_sqlite_close(&ws);
        if (db_open) node_db_close(&ndb);
        test_rm_rf(dir);
        return failures + 1;
    }
    wallet_init(w);
    bool found = wcr_locked_payment_found(w, &ws, address);
    WCR_CHECK("reopened locked wallet detects payment to restore address", found);
    struct sapling_key_entry *first = wcr_child_zero(w);
    const struct chain_params *cp = chain_params_get();
    bool matches = first && sapling_encode_payment_address(first->diversifier, first->pk_d,
        cp->bech32HRPs[BECH32_SAPLING_PAYMENT_ADDRESS], encoded, sizeof(encoded)) &&
        strcmp(encoded, address) == 0;
    WCR_CHECK("reopened child zero encodes to the committed reply address", matches);
    struct zcl_result unlocked = wallet_lock_unlock(w, &ws, WCR_PASS);
    first = wcr_child_zero(w);
    WCR_CHECK("restored wallet unlocks its child zero spending key",
              unlocked.ok && wcr_first_spending_matches(first));
    wallet_lock_lock(w);
    wallet_free(w); free(w);
    wallet_sqlite_close(&ws); node_db_close(&ndb);
    test_rm_rf(dir);
    return failures;
}
static bool wcr_wallet_rows_exist(const char *dir)
{
    struct node_db ndb;
    bool open = wcr_open(&ndb, dir);
    bool any = open && (db_wallet_key_count(&ndb) > 0 ||
                        db_sapling_key_count(&ndb) > 0);
    if (open)
        node_db_close(&ndb);
    return any;
}

/* The passphrase decides how the wallet is written. */
static int restore_passphrase_cases(void)
{
    int failures = 0;
    char dir[1024];
    struct wcr_run run;
    WCR_CHECK("setup: a seeded datadir",
              wcr_seeded_chain(dir, sizeof(dir), "rs_pass", false));
    uint8_t seed[32];
    wcr_phrase_seed(WCR_RESTORE_PHRASE, seed);
    bool ran = wcr_restore_cli(dir, ",\"passphrase\":\"" WCR_PASS "\"", true,
                               &run);
    WCR_CHECK("a restore with a passphrase on standard input succeeds",
              ran && run.rc == 0 && wcr_data_bool(&run, "committed"));
    WCR_CHECK("the reply says the keys are encrypted at rest",
              wcr_data_bool(&run, "encrypted_at_rest"));
    WCR_CHECK("the raw seed is in no file of the datadir",
              wcr_count_in_tree(dir, (const char *)seed, 32) == 0);
    WCR_CHECK("the Sapling spending key scalars are in no file of the datadir",
              wcr_spending_key_in_tree(dir, seed) == 0);
    WCR_CHECK("neither the phrase nor the passphrase is in any file",
              wcr_count_in_tree(dir, WCR_RESTORE_PHRASE,
                                strlen(WCR_RESTORE_PHRASE)) == 0 &&
              wcr_count_in_tree(dir, WCR_PASS, strlen(WCR_PASS)) == 0);
    struct node_db ndb;
    struct wallet_sqlite ws;
    bool open = wcr_open(&ndb, dir) && wallet_sqlite_open_r(&ws, ndb.db).ok;
    uint8_t got[32] = {0};
    WCR_CHECK("without the passphrase the stored seed is locked",
              open && wallet_sqlite_sapling_seed_state(&ws, got) ==
                          WALLET_SEED_LOCKED);
    bool unlocked = open && wallet_lock_unlock(NULL, NULL, WCR_PASS).ok;
    WCR_CHECK("with the passphrase it decrypts to the phrase's seed",
              unlocked &&
              wallet_sqlite_sapling_seed_state(&ws, got) ==
                  WALLET_SEED_UNLOCKED && memcmp(got, seed, 32) == 0);
    wallet_lock_lock(NULL);
    if (open) {
        wallet_sqlite_close(&ws);
        node_db_close(&ndb);
    }
    memory_cleanse(seed, sizeof(seed));
    memory_cleanse(got, sizeof(got));
    return failures;
}

/* A passphrase that cannot be used writes nothing. */
static int restore_passphrase_refusals(void)
{
    int failures = 0;
    char dir[1024];
    struct wcr_run run;
    WCR_CHECK("setup: a second seeded datadir",
              wcr_seeded_chain(dir, sizeof(dir), "rs_argv", false));
    bool ran = wcr_restore_cli(dir, ",\"passphrase\":\"" WCR_PASS "\"", false,
                          &run);
    WCR_CHECK("a passphrase in argv is refused and nothing is written",
              ran && wcr_error_is(&run, "STDIN_REQUIRED") &&
              !wcr_wallet_rows_exist(dir));
    ran = wcr_restore_cli(dir, ",\"passphrase\":\"short\"", true, &run);
    WCR_CHECK("a passphrase under 12 bytes is refused and nothing is written",
              ran && wcr_error_is(&run, "PASSPHRASE_TOO_SHORT") &&
              !wcr_wallet_rows_exist(dir));
    ran = wcr_restore_cli(dir, ",\"passphrase\":\"\"", true, &run);
    WCR_CHECK("an empty passphrase is refused, not read as none",
              ran && run.rc != 0 && wcr_error_is(&run, "INVALID_INPUT") &&
              !wcr_wallet_rows_exist(dir));
    return failures;
}

/* shielded_only mints no transparent key. */
static int restore_shielded_only_case(void)
{
    int failures = 0;
    char dir[1024], plain[1024];
    struct wcr_run run;
    WCR_CHECK("setup: seeded datadirs",
              wcr_seeded_chain(dir, sizeof(dir), "rs_shielded", true) &&
              wcr_seeded_chain(plain, sizeof(plain), "rs_both", true));
    bool ran = wcr_restore_cli(dir, ",\"passphrase\":\"" WCR_PASS "\","
                               "\"shielded_only\":true", true, &run);
    struct node_db ndb;
    bool open = ran && run.rc == 0 && wcr_open(&ndb, dir);
    WCR_CHECK("shielded_only restores Sapling keys and no transparent key",
              open && db_wallet_key_count(&ndb) == 0 &&
              db_sapling_key_count(&ndb) > 0);
    if (open)
        node_db_close(&ndb);
    ran = wcr_restore_cli(plain, ",\"passphrase\":\"" WCR_PASS "\"", true,
                          &run);
    open = ran && run.rc == 0 && wcr_open(&ndb, plain);
    WCR_CHECK("without it the same phrase restores transparent keys too",
              open && db_wallet_key_count(&ndb) > 0);
    if (open)
        node_db_close(&ndb);
    return failures;
}

/* The persisted scan marker of `dir`, or false when none is pending. */
static bool wcr_unread_blocker(const char *dir, const char *blocker)
{
    struct wallet *w = calloc(1, sizeof(*w));
    bool read = w && wcr_scan_marker(dir, w);
    bool unread = read && w->scan_retry.pending && w->scan_retry.from == 0 &&
                  strcmp(w->scan_retry.blocker, blocker) == 0;
    if (read)
        wallet_free(w);
    free(w);
    return unread;
}

static bool wcr_unread_from_zero(const char *dir)
{
    return wcr_unread_blocker(dir, WALLET_RESTORE_BLOCKER_UNREAD);
}

/* A birthday counts only when this datadir holds its block. */
static int restore_birthday_cases(void)
{
    int failures = 0;
    char dir[1024];
    struct wcr_run run;
    const char *good = ",\"birthday\":{\"height\":1000,\"hash\":\""
                       WCR_HASH_09 "\"}";
    WCR_CHECK("setup: a seeded datadir",
              wcr_seeded_chain(dir, sizeof(dir), "rs_bday_ok", false));
    bool ran = wcr_restore_cli(dir, good, true, &run);
    struct node_db ndb;
    int64_t b = 0;
    uint8_t hash[32];
    bool open = ran && run.rc == 0 && wcr_open(&ndb, dir);
    WCR_CHECK("a birthday this datadir holds is stored",
              open && db_wallet_birthday_get(&ndb, &b, hash) && b == 1000 &&
              hash[0] == 0x09 && hash[31] == 0x09);
    if (open)
        node_db_close(&ndb);
    WCR_CHECK("and the wallet carries no unread marker",
              ran && !wcr_unread_from_zero(dir));
    WCR_CHECK("the reply reports the birthday and nothing hidden below the seed",
              wcr_data_bool(&run, "birthday_recorded") &&
              !wcr_data_bool(&run, "birthday_rejected") &&
              !wcr_data_bool(&run, "history_below_seed_hidden"));

    return failures;
}

/* A birthday this datadir cannot verify falls back to the marker from 0. */
static int restore_birthday_rejected(void)
{
    int failures = 0;
    char dir[1024];
    struct wcr_run run;
    struct node_db ndb;
    int64_t b = 0;
    uint8_t hash[32];
    WCR_CHECK("setup: a datadir for a wrong hash",
              wcr_seeded_chain(dir, sizeof(dir), "rs_bday_bad", false));
    bool ran = wcr_restore_cli(dir, ",\"birthday\":{\"height\":1000,\"hash\":\""
                          WCR_HASH_77 "\"}", true, &run);
    bool open = ran && run.rc == 0 && wcr_open(&ndb, dir);
    WCR_CHECK("a wrong birthday hash stores no birthday",
              open && !db_wallet_birthday_get(&ndb, &b, hash));
    if (open)
        node_db_close(&ndb);
    WCR_CHECK("it falls back to a marker from height 0",
              ran && wcr_unread_from_zero(dir));
    WCR_CHECK("and the reply says it was rejected",
              wcr_data_bool(&run, "birthday_rejected") &&
              !wcr_data_bool(&run, "birthday_recorded"));

    ran = wcr_restore_cli(dir, ",\"birthday\":{\"height\":50}", true, &run);
    WCR_CHECK("a malformed birthday is refused before anything is written",
              ran && wcr_error_is(&run, "BAD_BIRTHDAY"));
    return failures;
}

/* A phrase with no birthday on a seeded node cannot show older funds, and the
 * reply says so in a field the app can read. */
static int restore_below_seed_cases(void)
{
    int failures = 0;
    char dir[1024];
    struct wcr_run run;
    WCR_CHECK("setup: a seeded datadir",
              wcr_seeded_chain(dir, sizeof(dir), "rs_seed", false));
    bool ran = wcr_restore_cli(dir, "", false, &run);
    WCR_CHECK("a restore with no birthday on a seeded node reports history "
              "below the seed hidden, with the seed height",
              ran && run.rc == 0 &&
              wcr_data_bool(&run, "history_below_seed_hidden") &&
              wcr_data_int(&run, "seed_floor_height") == 900 &&
              strstr(run.wire, "history_warning") != NULL);
    WCR_CHECK("setup: a datadir seeded from genesis",
              wcr_seeded_chain(dir, sizeof(dir), "rs_genesis", true));
    ran = wcr_restore_cli(dir, "", false, &run);
    WCR_CHECK("a datadir with no seed floor hides nothing",
              ran && run.rc == 0 &&
              !wcr_data_bool(&run, "history_below_seed_hidden") &&
              wcr_data_int(&run, "seed_floor_height") == 0);
    ran = wcr_restore_cli(dir, "", false, &run);
    WCR_CHECK("a second restore into that datadir is still refused",
              ran && wcr_error_is(&run, "WALLET_ALREADY_PRESENT"));
    return failures;
}

static int t_restore_inputs(void)
{
    int failures = 0;
    failures += restore_passphrase_cases();
    failures += restore_passphrase_refusals();
    failures += restore_shielded_only_case();
    failures += restore_birthday_cases();
    failures += restore_birthday_rejected();
    failures += restore_below_seed_cases();
    return failures;
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

/* A scan that cannot read a file must not call it clean. */
static int t_unreadable_file_fails_scan(void)
{
    int failures = 0;
    char dir[1024], path[1100];
    wcr_fixture(dir, sizeof(dir), "unreadable");
    snprintf(path, sizeof(path), "%s/hidden.bin", dir);
    FILE *f = fopen(path, "wb");
    bool wrote = f && fwrite("abcdefgh", 1, 8, f) == 8;
    if (f)
        fclose(f);
    WCR_CHECK("setup: a readable file without the needle scans clean",
              wrote && wcr_count_in_tree(dir, "zzzz", 4) == 0);
    WCR_CHECK("a readable file with the needle is counted",
              wcr_count_in_tree(dir, "cdef", 4) == 1);
    if (geteuid() == 0) {
        printf("wallet_create: an unreadable file is not scanned clean... "
               "not exercised: root reads any file\n");
        return failures;
    }
    bool locked = wrote && chmod(path, 0) == 0;
    WCR_CHECK("an unreadable file fails the scan",
              locked && wcr_count_in_tree(dir, "zzzz", 4) != 0);
    (void)chmod(path, 0600);
    return failures;
}

/* The seed scan proves nothing when it could not read everything: an
 * unreadable file or a non-regular entry beside a datadir without the seed, or
 * beside one with it, withholds the proof. */
static int t_seed_proof_needs_a_full_read(void)
{
    int failures = 0;
    uint8_t seed[32];
    memset(seed, 0x6b, sizeof(seed));
    char dir[1024], path[1100], fifo[1100], other[1100];
    wcr_fixture(dir, sizeof(dir), "seedproof");
    snprintf(path, sizeof(path), "%s/hidden.bin", dir);
    snprintf(fifo, sizeof(fifo), "%s/pipe", dir);
    snprintf(other, sizeof(other), "%s/seed.bin", dir);
    FILE *f = fopen(path, "wb");
    bool wrote = f && fwrite("abcdefgh", 1, 8, f) == 8;
    if (f)
        fclose(f);
    WCR_CHECK("setup: a datadir without the seed does not prove it",
              wrote && !wcr_scan_proves_seed(dir, seed));
    f = fopen(other, "wb");
    bool seeded = f && fwrite(seed, 1, sizeof(seed), f) == sizeof(seed);
    if (f)
        fclose(f);
    WCR_CHECK("setup: a fully readable datadir with the seed proves it",
              seeded && wcr_scan_proves_seed(dir, seed));
    bool piped = mkfifo(fifo, 0600) == 0;
    WCR_CHECK("a non-regular entry withholds the seed proof",
              piped && !wcr_scan_proves_seed(dir, seed));
    (void)unlink(fifo);
    if (geteuid() == 0) {
        printf("wallet_create: an unreadable file withholds the seed proof... "
               "not exercised: root reads any file\n");
        return failures;
    }
    bool locked = wrote && chmod(path, 0) == 0;
    WCR_CHECK("an unreadable file withholds the seed proof",
              locked && !wcr_scan_proves_seed(dir, seed));
    (void)chmod(path, 0600);
    return failures;
}

/* wallet_free wipes the Sapling seed and spending keys the wallet holds. The
 * keystore lives inside the caller's struct, so its bytes are read before the
 * struct itself is released. */
static bool wcr_all_zero(const void *p, size_t n)
{
    const uint8_t *b = p;
    for (size_t i = 0; i < n; i++)
        if (b[i])
            return false;
    return true;
}

bool wallet_add_sapling_note(struct wallet *w,
                             const struct sapling_received_note *note);

/* What the note-buffer observer saw: one entry per release, in order. */
static struct {
    unsigned calls;
    size_t bytes[4];
    bool zero[4];
} wcr_released;

static void wcr_note_buffer_released(const void *buf, size_t bytes)
{
    unsigned i = wcr_released.calls++;
    if (i >= 4)
        return;
    wcr_released.bytes[i] = bytes;
    wcr_released.zero[i] = wcr_all_zero(buf, bytes);
}

/* A wallet holding a Sapling seed and spending key, and a BIP32 master key. */
static bool wcr_make_keyed_wallet(struct wallet *w, const uint8_t seed[32])
{
    uint8_t div[ZC_DIVERSIFIER_SIZE], pk_d[32];
    wallet_init(w);
    return sapling_keystore_set_seed(&w->sapling_keys, seed) &&
           sapling_keystore_new_address(&w->sapling_keys, div, pk_d) &&
           wallet_init_hd(w, seed, 32);
}

/* 65 notes with a memo, randomness and ivk: the append that crosses 64 grows
 * the buffer. */
static bool wcr_add_notes(struct wallet *w)
{
    bool noted = true;
    for (uint32_t i = 0; noted && i < 65; i++) {
        struct sapling_received_note n;
        memset(&n, 0x5a, sizeof(n));
        memset(&n.txid, 0, sizeof(n.txid));
        n.txid.data[0] = (uint8_t)(i + 1);
        n.output_index = i;
        noted = wallet_add_sapling_note(w, &n);
    }
    return noted;
}

/* What a wallet holds before it is freed. */
static int wcr_held_before_free(const struct wallet *w, bool made, bool noted)
{
    int failures = 0;
    WCR_CHECK("setup: a wallet holds a Sapling seed, a spending key and a BIP32 master key",
              made && w->has_master_key &&
              !wcr_all_zero(&w->master_key, sizeof(w->master_key)) &&
              !wcr_all_zero(w->sapling_keys.seed, 32) &&
              !wcr_all_zero(&w->sapling_keys.keys[0].xsk.expsk,
                            sizeof(w->sapling_keys.keys[0].xsk.expsk)));
    WCR_CHECK("setup: the wallet holds 65 notes and a full viewing key",
              noted && w->num_sapling_notes == 65 &&
              !wcr_all_zero(&w->sapling_keys.keys[0].xfvk,
                            sizeof(w->sapling_keys.keys[0].xfvk)) &&
              !wcr_all_zero(w->sapling_keys.keys[0].ivk, 32));
    WCR_CHECK("growing the note buffer cleanses the old one before freeing it",
              wcr_released.calls == 1 && wcr_released.zero[0] &&
              wcr_released.bytes[0] == 64 * sizeof(struct sapling_received_note));
    return failures;
}

/* What the freed wallet's struct still holds. */
static int wcr_held_after_free(const struct wallet *w, bool made)
{
    int failures = 0;
    WCR_CHECK("wallet_free cleanses the note buffer before freeing it",
              wcr_released.calls == 2 && wcr_released.zero[1] &&
              wcr_released.bytes[1] == 128 * sizeof(struct sapling_received_note));
    WCR_CHECK("wallet_free leaves no full viewing key in the struct",
              made && wcr_all_zero(&w->sapling_keys.keys[0].xfvk,
                                   sizeof(w->sapling_keys.keys[0].xfvk)));
    WCR_CHECK("wallet_free leaves no ivk in the struct",
              made && wcr_all_zero(w->sapling_keys.keys[0].ivk, 32));
    WCR_CHECK("wallet_free leaves no Sapling seed in the struct",
              made && wcr_all_zero(w->sapling_keys.seed, 32));
    WCR_CHECK("wallet_free leaves no master key in the struct",
              made && wcr_all_zero(&w->sapling_keys.master_xsk,
                                   sizeof(w->sapling_keys.master_xsk)));
    WCR_CHECK("wallet_free leaves no BIP32 master key in the struct",
              made && wcr_all_zero(&w->master_key, sizeof(w->master_key)));
    WCR_CHECK("and no longer claims one", made && !w->has_master_key);
    WCR_CHECK("wallet_free leaves no spending key in the struct",
              made && wcr_all_zero(&w->sapling_keys.keys[0].xsk,
                                   sizeof(w->sapling_keys.keys[0].xsk)));
    return failures;
}

static int t_wallet_free_wipes_sapling_keys(void)
{
    int failures = 0;
    struct wallet *w = calloc(1, sizeof(*w));
    uint8_t seed[32];
    memset(seed, 0x5a, sizeof(seed));
    memset(&wcr_released, 0, sizeof(wcr_released));
    wallet_set_note_buffer_observer_for_test(wcr_note_buffer_released);
    bool made = w != NULL && wcr_make_keyed_wallet(w, seed);
    bool noted = made && wcr_add_notes(w);
    failures += wcr_held_before_free(w, made, noted);
    if (made)
        wallet_free(w);
    wallet_set_note_buffer_observer_for_test(NULL);
    failures += wcr_held_after_free(w, made);
    memory_cleanse(seed, sizeof(seed));
    free(w);
    return failures;
}

/* Create and restore unlock, then force-lock, the process-wide lock. A process
 * that serves a wallet refuses both before anything is read or written. */
static int t_live_wallet_refused(void)
{
    int failures = 0;
    char dir[1024], plan[1024];
    struct wcr_run run;
    wcr_fixture(dir, sizeof(dir), "live_create");
    wallet_lock_reset_for_test();
    wallet_lock_note_live_wallet();
    wcr_process_serves_wallet = true;
    bool ran = wcr_create(dir, WCR_PASS, &run);
    WCR_CHECK("create in a process that serves a wallet is refused by name",
              ran && run.rc != 0 &&
              wcr_error_is(&run, "WALLET_LIVE_IN_PROCESS"));
    WCR_CHECK("and writes nothing", !wcr_exists(dir, "node.db"));
    WCR_CHECK("and leaves the process lock state alone",
              wallet_lock_effective_passphrase() == NULL &&
              !wallet_lock_encrypted_at_rest());
    WCR_CHECK("setup: a seeded datadir for a restore",
              wcr_seeded_chain(plan, sizeof(plan), "live_restore", false));
    ran = wcr_restore_cli(plan, ",\"passphrase\":\"" WCR_PASS "\"", true,
                          &run);
    WCR_CHECK("restore in that process is refused by name",
              ran && wcr_error_is(&run, "WALLET_LIVE_IN_PROCESS") &&
              !wcr_wallet_rows_exist(plan));
    char text[2048];
    snprintf(text, sizeof(text), "{\"datadir\":\"%s\",\"phrase\":\"%s\"}",
             plan, WCR_RESTORE_PHRASE);
    const char *plan_args[] = {"wallet", "recovery", "restore", "--input=-",
                               "--format=json"};
    memset(&run, 0, sizeof(run));
    ran = wcr_cli_args(plan_args, 5, text, &run);
    WCR_CHECK("a plan, which locks nothing, is still answered",
              ran && run.rc == 0 && !wcr_wallet_rows_exist(plan));
    wcr_process_serves_wallet = false;
    wallet_lock_reset_for_test();
    return failures;
}

/* The reply code a service code maps to. -69 stays the phrase-draw and
 * report failure the create service documents; the live-process refusal has a
 * code of its own and is checked before the request is read. */
static int t_create_failure_codes(void)
{
    int failures = 0;
    enum zcl_command_exit ex = ZCL_COMMAND_EXIT_BLOCKED;
    const char *code = wrp_create_failure_code(-69, &ex);
    WCR_CHECK("a phrase-draw failure (-69) still reports CREATE_FAILED",
              !strcmp(code, "CREATE_FAILED") && ex == ZCL_COMMAND_EXIT_FAILED);
    struct wallet_create_request req = {.datadir = "/nonexistent-create-test",
                                        .passphrase = WCR_PASS};
    struct zcl_result null_report = wallet_create_run(&req, NULL);
    code = wrp_create_failure_code(null_report.code, &ex);
    WCR_CHECK("the service's own -69 (no report) maps to CREATE_FAILED",
              null_report.code == -69 && !strcmp(code, "CREATE_FAILED"));
    code = wrp_create_failure_code(-70, &ex);
    WCR_CHECK("the live-process refusal (-70) reports WALLET_LIVE_IN_PROCESS",
              !strcmp(code, "WALLET_LIVE_IN_PROCESS") &&
              ex == ZCL_COMMAND_EXIT_BLOCKED);
    wallet_lock_reset_for_test();
    wallet_lock_note_live_wallet();
    struct wallet_create_request empty = {.datadir = "", .passphrase = ""};
    struct wallet_create_report rep;
    struct zcl_result r = wallet_create_run(&empty, &rep);
    WCR_CHECK("create checks the live process before it reads the request",
              r.code == -70);
    wallet_lock_reset_for_test();
    return failures;
}

/* `core wallet recovery new` draws a phrase and touches nothing else. */
static bool wcr_recovery_new(struct wcr_run *run)
{
    const char *args[] = {"wallet", "recovery", "new", "--format=json"};
    memset(run, 0, sizeof(*run));
    return wcr_cli_args(args, 4, "", run);
}

/* Inspect every decoded member name, including nested/duplicate members.
 * Phrase values may contain BIP39's "seed"; captured bytes must form one object. */
static bool wcr_reply_has_no_secret_fields(const char *wire, size_t length)
{
    zjsonp parser;
    zjsonp_event event;
    zjsonp_init(&parser, wire, length);
    if (zjsonp_next(&parser, &event) != ZJRP_OK || event.kind != ZJRP_OBJ_OPEN)
        return false;
    zjsonp_status status;
    while ((status = zjsonp_next(&parser, &event)) == ZJRP_OK) {
        if (event.kind != ZJRP_KEY)
            continue;
        char key[7];
        size_t decoded = zjsonp_str_decode(wire, &event, key, sizeof(key));
        if (decoded == SIZE_MAX ||
            (decoded == 4 && memcmp(key, "seed", 4) == 0) ||
            (decoded == 7 && memcmp(key, "entropy", 7) == 0))
            return false;
    }
    return status == ZJRP_DONE;
}

static int t_recovery_reply_capture(void)
{
    int failures = 0;
    static const char nul_suffix[] = "{}\0{\"seed\":null}";
    WCR_CHECK("physical NUL cannot hide additional reply bytes",
              !wcr_reply_has_no_secret_fields(nul_suffix, sizeof(nul_suffix) - 1));
    FILE *capture = tmpfile();
    char captured[64];
    size_t captured_len = 0;
    bool read = capture &&
        fwrite(nul_suffix, 1, sizeof(nul_suffix) - 1, capture) == sizeof(nul_suffix) - 1 &&
        wcr_slurp(capture, captured, sizeof(captured), &captured_len);
    if (capture)
        read = fclose(capture) == 0 && read;
    WCR_CHECK("stdout capture retains the physical length past a NUL",
              read && captured_len == sizeof(nul_suffix) - 1 &&
              !wcr_reply_has_no_secret_fields(captured, captured_len));
    return failures;
}

static int t_recovery_reply_fields(void)
{
    int failures = 0;
    uint8_t entropy[32] = {0};
    char phrase[MNEMONIC_MAX_PHRASE_SIZE] = "", wire[1024];
    int seed_index = mnemonic_wordlist_find("seed");
    bool made = seed_index >= 0 && seed_index < BIP39_WORDLIST_SIZE;
    if (made) {
        /* The first eleven entropy bits select the first BIP39 word. */
        entropy[0] = (uint8_t)(seed_index >> 3);
        entropy[1] = (uint8_t)((seed_index & 7) << 5);
        made = mnemonic_from_entropy(entropy, sizeof(entropy), phrase, sizeof(phrase));
    }
    WCR_CHECK("deterministic recovery fixture is a valid phrase beginning with seed",
              made && mnemonic_validate(phrase) && strncmp(phrase, "seed ", 5) == 0);
    int size = snprintf(wire, sizeof(wire), "{\"data\":{\"phrase\":\"%s\",\"words\":24}}", phrase);
    WCR_CHECK("a valid recovery phrase containing seed is not a secret field",
              made && size > 0 && (size_t)size < sizeof(wire) &&
              wcr_reply_has_no_secret_fields(wire, (size_t)size));
    static const char *const allowed[] = {
        "{}", "{\"data\":{\"phrase\":\"seed entropy\"}}",
        "{\"seedling\":null,\"entropy_hint\":false}",
        "{\"data\":[\"seed\",{\"message\":\"entropy\"}]}\n",
        "{\"seed\\u0000suffix\":null}"
    };
    for (size_t i = 0; i < sizeof(allowed) / sizeof(allowed[0]); i++)
        WCR_CHECK("values and distinct decoded member names remain allowed",
                  wcr_reply_has_no_secret_fields(allowed[i], strlen(allowed[i])));
    static const char *const refused[] = {
        "{\"seed\":null}", "{\"entropy\":null}",
        "{\"data\":{\"seed\":\"bytes\"}}",
        "{\"data\":[{\"entropy\":false}]}",
        "{\"s\\u0065ed\":null}", "{\"\\u0065ntropy\":null}",
        "{\"data\":{},\"data\":{\"seed\":null}}",
        "", "null", "[]", "{\"data\":", "{\"data\":{}} trailing",
        "{} {}", "{\"data\":\"\\uZZZZ\"}", "{\"data\":\"\xff\"}"
    };
    for (size_t i = 0; i < sizeof(refused) / sizeof(refused[0]); i++)
        WCR_CHECK("forbidden members or incomplete reply documents refuse",
                  !wcr_reply_has_no_secret_fields(refused[i], strlen(refused[i])));
    failures += t_recovery_reply_capture();
    memory_cleanse(entropy, sizeof(entropy));
    memory_cleanse(phrase, sizeof(phrase));
    memory_cleanse(wire, sizeof(wire));
    return failures;
}

static int t_recovery_new(void)
{
    int failures = 0;
    struct wcr_run a, b;
    char p1[MNEMONIC_MAX_PHRASE_SIZE] = "", p2[MNEMONIC_MAX_PHRASE_SIZE] = "";
    bool ran = wcr_recovery_new(&a) && wcr_recovery_new(&b);
    WCR_CHECK("the new leaf answers ok with a phrase and no datadir",
              ran && a.rc == 0 && wcr_field(&a, "phrase", p1, sizeof(p1)) &&
              b.rc == 0 && wcr_field(&b, "phrase", p2, sizeof(p2)));
    WCR_CHECK("the phrase is 24 valid BIP39 words and the reply counts them",
              mnemonic_validate(p1) && wcr_data_int(&a, "words") == 24 &&
              strlen(p1) > 24 * 3);
    WCR_CHECK("two calls give different phrases", strcmp(p1, p2) != 0);
    WCR_CHECK("the reply carries no seed or entropy field",
              ran && wcr_reply_has_no_secret_fields(a.wire, a.wire_len) &&
              wcr_reply_has_no_secret_fields(b.wire, b.wire_len));
    WCR_CHECK("the phrase is in the reply once and never on standard error",
              wcr_count(a.wire, strlen(a.wire), p1, strlen(p1)) == 1 &&
              strstr(a.err, p1) == NULL);

    char dir[1024];
    wcr_fixture(dir, sizeof(dir), "new_restore");
    WCR_CHECK("setup: a seeded datadir",
              wcr_block(dir, 0x09, 900, 3) && wcr_block(dir, 0x0a, 1000, 3));
    struct wcr_run r;
    bool restored = wcr_restore_phrase_cli(dir, p1, "", true, &r);
    WCR_CHECK("restore accepts the phrase the new leaf drew",
              restored && r.rc == 0 && wcr_data_bool(&r, "committed") &&
              wcr_data_bool(&r, "recovered"));
    memory_cleanse(p1, sizeof(p1));
    memory_cleanse(p2, sizeof(p2));
    return failures;
}

/* A datadir holding blocks only at the given heights (status connected). */
static bool wcr_chain_at(char *dir, size_t cap, const char *tag,
                         const int *heights, size_t n)
{
    wcr_fixture(dir, cap, tag);
    for (size_t i = 0; i < n; i++)
        if (!wcr_block(dir, (uint8_t)(0x10 + i), heights[i], 3))
            return false;
    return true;
}

static int restore_tip_recorded(void)
{
    int failures = 0;
    char dir[1024];
    struct wcr_run run;
    struct node_db ndb;
    int64_t b = 0;
    uint8_t hash[32];
    WCR_CHECK("setup: a seeded datadir",
              wcr_seeded_chain(dir, sizeof(dir), "tip_ok", false));
    bool ran = wcr_restore_cli(dir, ",\"birthday_at_local_tip\":true", true,
                               &run);
    bool open = ran && run.rc == 0 && wcr_open(&ndb, dir);
    WCR_CHECK("without a release anchor mutable rows cannot set the birthday",
              open && !db_wallet_birthday_get(&ndb, &b, hash));
    if (open)
        node_db_close(&ndb);
    WCR_CHECK("the wallet remains unread until coverage is verified",
              ran && wcr_unread_blocker(dir,
                  wcr_data_bool(&run, "birthday_recorded")
                      ? WALLET_BIRTHDAY_PENDING : WALLET_RESTORE_BLOCKER_UNREAD));
    WCR_CHECK("the reply reports no birthday without a release anchor",
              !wcr_data_bool(&run, "birthday_recorded") &&
              !wcr_data_bool(&run, "birthday_rejected") &&
              !wcr_data_bool(&run, "history_below_seed_hidden"));
    return failures;
}

static int restore_tip_edge(void)
{
    int failures = 0;
    char dir[1024];
    struct wcr_run run;
    struct node_db ndb;
    int64_t b = 0;
    uint8_t hash[32];
    /* One block past the margin is the shortest usable chain. */
    const int edge[] = {1, 101};
    WCR_CHECK("setup: a chain of exactly margin + 1",
              wcr_chain_at(dir, sizeof(dir), "tip_edge", edge, 2));
    bool ran = wcr_restore_cli(dir, ",\"birthday_at_local_tip\":true", true, &run);
    bool open = ran && run.rc == 0 && wcr_open(&ndb, dir);
    WCR_CHECK("a short chain saves without claiming a mutable birthday",
              open && !db_wallet_birthday_get(&ndb, &b, hash) &&
              wcr_unread_from_zero(dir));
    if (open)
        node_db_close(&ndb);
    return failures;
}

/* A phrase made now saves on a chain too short for a floor block, with no
 * anchor and no headers: no birthday is stored and nothing is refused, so its
 * first scan starts at genesis. */
static int restore_tip_short(void)
{
    int failures = 0;
    char dir[1024];
    struct wcr_run run;
    struct node_db ndb;
    int64_t b = 0;
    uint8_t hash[32];
    const int low[] = {1, 100};
    WCR_CHECK("setup: a chain exactly at the margin",
              wcr_chain_at(dir, sizeof(dir), "tip_low", low, 2));
    bool ran = wcr_restore_cli(dir, ",\"birthday_at_local_tip\":true", true,
                               &run);
    bool open = ran && run.rc == 0 && wcr_open(&ndb, dir);
    WCR_CHECK("a tip at the margin saves the wallet with no birthday",
              open && !db_wallet_birthday_get(&ndb, &b, hash) &&
              wcr_data_bool(&run, "committed") &&
              !wcr_data_bool(&run, "birthday_recorded"));
    if (open)
        node_db_close(&ndb);
    WCR_CHECK("and its rows are written", wcr_wallet_rows_exist(dir));
    wcr_fixture(dir, sizeof(dir), "tip_none");
    ran = wcr_restore_cli(dir, ",\"birthday_at_local_tip\":true", true, &run);
    WCR_CHECK("an empty datadir saves the same way",
              ran && run.rc == 0 && wcr_wallet_rows_exist(dir) &&
              !wcr_data_bool(&run, "birthday_recorded"));
    WCR_CHECK("setup: a seeded datadir for the conflict",
              wcr_seeded_chain(dir, sizeof(dir), "tip_conflict", false));
    ran = wcr_restore_cli(dir, ",\"birthday_at_local_tip\":true,"
                          "\"birthday\":{\"height\":1000,\"hash\":\""
                          WCR_HASH_09 "\"}", true, &run);
    WCR_CHECK("an explicit birthday plus the flag is refused",
              ran && run.rc != 0 && wcr_error_is(&run, "BIRTHDAY_CONFLICT"));
    WCR_CHECK("and nothing was written",
              !wcr_wallet_rows_exist(dir));
    return failures;
}

/* `core wallet recovery restore` as a plan: the same input as a commit with
 * confirm false. */
static bool wcr_restore_plan(const char *dir, const char *extra,
                             struct wcr_run *run)
{
    char text[2048];
    snprintf(text, sizeof(text),
             "{\"datadir\":\"%s\",\"phrase\":\"%s\",\"confirm\":false%s}", dir,
             WCR_RESTORE_PHRASE, extra);
    const char *by_stdin[] = {"wallet", "recovery", "restore", "--input=-",
                              "--format=json"};
    memset(run, 0, sizeof(*run));
    wallet_lock_reset_for_test();
    setenv("ZCL_ALLOW_PLAINTEXT_WALLET", "1", 1);
    bool ok = wcr_cli_args(by_stdin, 5, text, run);
    unsetenv("ZCL_ALLOW_PLAINTEXT_WALLET");
    return ok;
}

/* Run the commit input a plan returned, with the phrase typed back in as the
 * plan asks. */
static bool wcr_commit_plan(const struct wcr_run *plan, struct wcr_run *run)
{
    char commit[2048], text[2300];
    const char *marker = "<your words>";
    if (!wcr_field(plan, "commit_input", commit, sizeof(commit)))
        return false;
    char *at = strstr(commit, marker);
    if (!at)
        return false;
    *at = '\0';
    snprintf(text, sizeof(text), "%s%s%s", commit, WCR_RESTORE_PHRASE,
             at + strlen(marker));
    const char *by_stdin[] = {"wallet", "recovery", "restore", "--input=-",
                              "--format=json"};
    memset(run, 0, sizeof(*run));
    wallet_lock_reset_for_test();
    setenv("ZCL_ALLOW_PLAINTEXT_WALLET", "1", 1);
    bool ok = wcr_cli_args(by_stdin, 5, text, run);
    unsetenv("ZCL_ALLOW_PLAINTEXT_WALLET");
    return ok;
}

/* The plan keeps the flag; no release anchor means full genesis coverage. */
static int restore_tip_plan_then_commit(void)
{
    int failures = 0;
    char dir[1024];
    struct wcr_run plan, run;
    struct node_db ndb;
    int64_t b = 0;
    uint8_t hash[32];
    WCR_CHECK("setup: a seeded datadir for a plan",
              wcr_seeded_chain(dir, sizeof(dir), "tip_plan", false));
    bool planned = wcr_restore_plan(dir, ",\"birthday_at_local_tip\":true",
                                    &plan);
    WCR_CHECK("a plan with the flag writes nothing and names the flag in its "
              "commit input",
              planned && plan.rc == 0 && !wcr_data_bool(&plan, "committed") &&
              !wcr_wallet_rows_exist(dir) &&
              strstr(plan.wire, "birthday_at_local_tip") != NULL);
    bool ran = wcr_commit_plan(&plan, &run);
    bool open = ran && run.rc == 0 && wcr_open(&ndb, dir);
    WCR_CHECK("the commit preserves genesis coverage without a release anchor",
              open && !db_wallet_birthday_get(&ndb, &b, hash) &&
              wcr_unread_from_zero(dir));
    if (open)
        node_db_close(&ndb);
    return failures;
}

/* A plan on a chain too short for a floor block is not refused either, and
 * writes nothing. */
static int restore_tip_plan_short(void)
{
    int failures = 0;
    char dir[1024];
    struct wcr_run run;
    const int low[] = {1, 100};
    WCR_CHECK("setup: a chain exactly at the margin for a plan",
              wcr_chain_at(dir, sizeof(dir), "tip_plan_low", low, 2));
    bool ran = wcr_restore_plan(dir, ",\"birthday_at_local_tip\":true", &run);
    WCR_CHECK("a plan on a short chain succeeds and writes nothing",
              ran && run.rc == 0 && !wcr_data_bool(&run, "committed") &&
              !wcr_wallet_rows_exist(dir));
    wcr_fixture(dir, sizeof(dir), "tip_plan_none");
    ran = wcr_restore_plan(dir, ",\"birthday_at_local_tip\":true", &run);
    WCR_CHECK("a plan on an empty datadir succeeds and creates no node.db",
              ran && run.rc == 0 && !wcr_exists(dir, "node.db"));
    return failures;
}

/* Without the flag nothing is recorded and the wallet reads unread from 0. */
static int restore_default_no_birthday(void)
{
    int failures = 0;
    char dir[1024];
    struct wcr_run run;
    struct node_db ndb;
    int64_t b = 0;
    uint8_t hash[32];
    WCR_CHECK("setup: a seeded datadir without the flag",
              wcr_seeded_chain(dir, sizeof(dir), "tip_default", false));
    bool ran = wcr_restore_cli(dir, "", true, &run);
    bool open = ran && run.rc == 0 && wcr_open(&ndb, dir);
    WCR_CHECK("a restore without the flag records no birthday",
              open && !db_wallet_birthday_get(&ndb, &b, hash) &&
              !wcr_data_bool(&run, "birthday_recorded"));
    if (open)
        node_db_close(&ndb);
    WCR_CHECK("and keeps the unread-from-0 marker", ran &&
              wcr_unread_from_zero(dir));
    return failures;
}

/* A refused restore prints neither the phrase on standard output nor on
 * standard error. */
static int restore_refusal_keeps_phrase_out(void)
{
    int failures = 0;
    char dir[1024];
    struct wcr_run run;
    WCR_CHECK("setup: an empty datadir",
              (wcr_fixture(dir, sizeof(dir), "tip_quiet"), true));
    bool ran = wcr_restore_cli(dir, ",\"birthday_at_local_tip\":true,"
                               "\"birthday\":{\"height\":1000,\"hash\":\""
                               WCR_HASH_09 "\"}", true, &run);
    WCR_CHECK("a refused restore echoes the phrase on neither stream",
              ran && run.rc != 0 && wcr_error_is(&run, "BIRTHDAY_CONFLICT") &&
              strstr(run.wire, WCR_RESTORE_PHRASE) == NULL &&
              strstr(run.err, WCR_RESTORE_PHRASE) == NULL &&
              strstr(run.err, "abandon abandon abandon") == NULL);
    return failures;
}

/* The new leaf makes no wallet state anywhere it could look: its home is an
 * empty directory and stays one. */
static int recovery_new_makes_no_state(void)
{
    int failures = 0;
    char dir[1024];
    struct wcr_run run;
    wcr_fixture(dir, sizeof(dir), "new_nostate");
    const char *home = getenv("HOME");
    char saved[1024] = "";
    if (home)
        snprintf(saved, sizeof(saved), "%s", home);
    setenv("HOME", dir, 1);
    bool ran = wcr_recovery_new(&run);
    if (home)
        setenv("HOME", saved, 1);
    else
        unsetenv("HOME");
    size_t entries = 0;
    DIR *d = opendir(dir);
    for (struct dirent *e = d ? readdir(d) : NULL; e; e = readdir(d))
        entries += strcmp(e->d_name, ".") && strcmp(e->d_name, "..");
    if (d)
        closedir(d);
    WCR_CHECK("the new leaf answers ok", ran && run.rc == 0);
    WCR_CHECK("it leaves its home directory empty: no node.db, wallet or file",
              d && entries == 0 && !wcr_exists(dir, "node.db") &&
              !wcr_exists(dir, ".zclassic-c23"));
    return failures;
}

/* ── a phrase made just now reads no address history ───────────────── */

/* The receiving index the history fixture marks used: past the floor's last
 * gap, so a scan that asks the chain derives more keys than one that does
 * not. */
#define WCR_USED_INDEX 110u

/* Statements asking whether an address has history on this chain (the gap
 * scan's two probes and the populated-index check), counted on every
 * connection the process opens while the trace is armed. */
static int wcr_history_asks;

static int wcr_history_trace(unsigned type, void *ctx, void *stmt, void *sql)
{
    (void)ctx;
    (void)stmt;
    const char *text = sql;
    if (type == SQLITE_TRACE_STMT && text &&
        (strstr(text, "FROM utxos WHERE address_hash") ||
         strstr(text, "FROM tx_outputs WHERE address_hash")))
        wcr_history_asks++;
    return 0;
}

static int wcr_history_trace_arm(sqlite3 *db, char **err,
                                 const struct sqlite3_api_routines *api)
{
    (void)err;
    (void)api;
    return sqlite3_trace_v2(db, SQLITE_TRACE_STMT, wcr_history_trace, NULL);
}

/* Restore the test phrase into `dir` with the request flags in `shape`,
 * plaintext, counting the history statements it runs into *asks. */
static bool wcr_restore_counted(const char *dir,
                                const struct wallet_recovery_request *shape,
                                struct wallet_recovery_report *rep, int *asks)
{
    struct wallet_recovery_request rq = *shape;
    rq.phrase = WCR_RESTORE_PHRASE;
    rq.datadir = dir;
    wallet_lock_reset_for_test();
    setenv("ZCL_ALLOW_PLAINTEXT_WALLET", "1", 1);
    wcr_history_asks = 0;
    void (*arm)(void) = (void (*)(void))wcr_history_trace_arm;
    bool armed = sqlite3_auto_extension(arm) == SQLITE_OK;
    struct zcl_result r = wallet_recovery_run(&rq, rep);
    if (armed)
        (void)sqlite3_cancel_auto_extension(arm);
    unsetenv("ZCL_ALLOW_PLAINTEXT_WALLET");
    *asks = wcr_history_asks;
    if (!r.ok)
        printf("    restore refused: %s\n", r.message);
    return armed && r.ok;
}

/* The hash160 of receiving key `index` of `phrase`, as hex: the key the gap
 * scan derives at that index and asks the chain about. */
static bool wcr_receiving_hash(const char *phrase, uint32_t index,
                               char hex[41])
{
    struct wallet *w = calloc(1, sizeof(*w));
    struct pubkey pk;
    if (!w)
        return false;
    wallet_lock_reset_for_test();
    wallet_init(w);
    w->sapling_keys.follows_wallet_lock = false;
    bool ok = ecc_start_once() && wallet_init_from_recovery_phrase(w, phrase);
    for (uint32_t i = 0; ok && i <= index; i++)
        ok = wallet_mint_next_hd_key(w, BIP44_EXTERNAL, &pk);
    if (ok) {
        struct key_id id = pubkey_get_id(&pk);
        for (int i = 0; i < 20; i++)
            snprintf(hex + 2 * i, 3, "%02x", id.id.data[i]);
    }
    wallet_free(w);
    free(w);
    return ok;
}

/* A seeded chain whose address index holds receiving key WCR_USED_INDEX. */
static bool wcr_history_chain(char *dir, size_t cap, const char *tag)
{
    char hex[41], sql[512];
    if (!wcr_receiving_hash(WCR_RESTORE_PHRASE, WCR_USED_INDEX, hex) ||
        !wcr_seeded_chain(dir, cap, tag, false))
        return false;
    snprintf(sql, sizeof(sql),
             "INSERT INTO tx_outputs(txid,vout,value,script_type,address_hash,"
             "block_height) VALUES(zeroblob(32),0,1000,1,X'%s',950)", hex);
    return wcr_sql(dir, sql);
}

struct wcr_digest {
    uint64_t hash;
    int64_t rows;
};

static int wcr_digest_row(void *ctx, int ncol, char **val, char **name)
{
    struct wcr_digest *d = ctx;
    (void)name;
    for (const char *p = ncol > 0 && val[0] ? val[0] : ""; *p; p++) {
        d->hash ^= (unsigned char)*p;
        d->hash *= 1099511628211ULL;
    }
    d->rows++;
    return 0;
}

/* The transparent public keys of `dir`'s wallet, in pubkey_hash order. */
static bool wcr_key_digest(const char *dir, struct wcr_digest *d)
{
    struct node_db ndb;
    d->hash = 1469598103934665603ULL;
    d->rows = 0;
    bool ok = wcr_open(&ndb, dir) &&
              sqlite3_exec(ndb.db, "SELECT hex(pubkey) FROM wallet_keys "
                           "ORDER BY pubkey_hash", wcr_digest_row, d,
                           NULL) == SQLITE_OK;
    if (ndb.open)
        node_db_close(&ndb);
    return ok;
}

/* An at-tip restore of a transparent wallet asks the chain nothing, even
 * where history for its phrase exists, and its keys are exactly the floor
 * keys a restore with no chain derives. */
static int restore_tip_reads_no_history(void)
{
    int failures = 0;
    char dir[1024], bare[1024];
    struct wallet_recovery_report rep, bare_rep;
    struct wcr_digest keys, floor_keys;
    int asks = -1, bare_asks = -1;
    const struct wallet_recovery_request at_tip = {
        .birthday_at_local_tip = true,
    };
    const struct wallet_recovery_request plain = { .dry_run = false };
    WCR_CHECK("setup: a chain whose address index holds a used key",
              wcr_history_chain(dir, sizeof(dir), "tip_nohist"));
    bool ran = wcr_restore_counted(dir, &at_tip, &rep, &asks);
    WCR_CHECK("an at-tip restore asks the chain nothing and says so",
              ran && asks == 0 && !rep.chain_history_consulted &&
              rep.history_skip == WALLET_RECOVERY_HISTORY_NEW_PHRASE &&
              rep.receiving_keys_used == 0 && !rep.birthday_recorded &&
              wcr_unread_from_zero(dir));
    wcr_fixture(bare, sizeof(bare), "tip_floor");
    bool floored = wcr_restore_counted(bare, &plain, &bare_rep, &bare_asks);
    WCR_CHECK("its keys are the floor keys a restore with no chain derives",
              ran && floored && wcr_key_digest(dir, &keys) &&
              wcr_key_digest(bare, &floor_keys) &&
              keys.rows == 2 * WALLET_RECOVERY_MIN_LOOKAHEAD &&
              keys.rows == floor_keys.rows && keys.hash == floor_keys.hash &&
              rep.receiving_keys == bare_rep.receiving_keys &&
              rep.change_keys == bare_rep.change_keys);
    return failures;
}

/* The app's create (shielded only, birthday at the tip) runs no history
 * statement at all, not even the populated-index check. */
static int restore_tip_shielded_reads_nothing(void)
{
    int failures = 0;
    char dir[1024];
    struct wallet_recovery_report rep;
    int asks = -1;
    const struct wallet_recovery_request app = {
        .shielded_only = true,
        .birthday_at_local_tip = true,
    };
    WCR_CHECK("setup: a chain with history for the app's create",
              wcr_history_chain(dir, sizeof(dir), "tip_nohist_z"));
    bool ran = wcr_restore_counted(dir, &app, &rep, &asks);
    WCR_CHECK("the app's shielded at-tip create runs no history statement",
              ran && asks == 0 && !rep.chain_history_consulted &&
              rep.history_skip == WALLET_RECOVERY_HISTORY_SHIELDED_ONLY &&
              rep.receiving_keys == 0 && !rep.birthday_recorded &&
              wcr_unread_from_zero(dir));
    return failures;
}

/* Every other restore still asks the chain and rebuilds past the floor to
 * the used key: one with no birthday and one with a verified birthday. */
static int restore_other_birthdays_read_history(void)
{
    int failures = 0;
    char dir[1024];
    struct wallet_recovery_report rep;
    int asks = -1;
    struct wallet_recovery_request named = {
        .has_birthday = true,
        .birthday_height = 1000,
    };
    memset(named.birthday_hash, 0x09, sizeof(named.birthday_hash));
    const struct wallet_recovery_request plain = { .dry_run = false };
    const uint32_t reach = WCR_USED_INDEX + 1 + WALLET_GAP_LIMIT;
    WCR_CHECK("setup: a chain with history for a restore without a birthday",
              wcr_history_chain(dir, sizeof(dir), "hist_plain"));
    bool ran = wcr_restore_counted(dir, &plain, &rep, &asks);
    WCR_CHECK("a restore without a birthday asks the chain and finds the key",
              ran && asks > 0 && rep.chain_history_consulted &&
              rep.receiving_keys_used == 1 && rep.receiving_keys == reach);
    WCR_CHECK("setup: a chain with history for a named birthday",
              wcr_history_chain(dir, sizeof(dir), "hist_named"));
    ran = wcr_restore_counted(dir, &named, &rep, &asks);
    WCR_CHECK("a restore with a verified birthday asks the chain as well",
              ran && asks > 0 && rep.chain_history_consulted &&
              rep.birthday_recorded && rep.receiving_keys == reach);
    return failures;
}

/* Words from each address_coverage line, one per reason the chain was not
 * read. */
#define WCR_SAYS_NO_CHAIN "has no chain to check against"
#define WCR_SAYS_NEW_PHRASE "requires a phrase generated after this release"
#define WCR_SAYS_SHIELDED "shielded_only derives no transparent address"

/* The reply reports the chain unread with the coverage line that contains
 * `says`, and claims no missing chain unless that is the line expected. */
static bool wcr_unread_because(const struct wcr_run *run, const char *says)
{
    char cov[1024];
    bool unread = run->rc == 0 &&
                  strstr(run->wire, "\"chain_history_consulted\":false") &&
                  wcr_field(run, "address_coverage", cov, sizeof(cov)) &&
                  strstr(cov, says) != NULL;
    return unread && (strcmp(says, WCR_SAYS_NO_CHAIN) == 0 ||
                      strstr(cov, WCR_SAYS_NO_CHAIN) == NULL);
}

/* The reply says why the chain was not read. On a datadir that holds history,
 * an at-tip plan and its commit name the phrase as new and the app's
 * shielded at-tip create names the missing transparent side; only a datadir
 * with no chain says it has none. */
static int restore_tip_reply_names_reason(void)
{
    int failures = 0;
    char dir[1024];
    struct wcr_run plan, run;
    const char *tip = ",\"birthday_at_local_tip\":true";
    WCR_CHECK("setup: a chain with history for the at-tip reply",
              wcr_history_chain(dir, sizeof(dir), "tip_reply"));
    bool planned = wcr_restore_plan(dir, tip, &plan);
    WCR_CHECK("an at-tip plan says the phrase is new, not that there is no "
              "chain",
              planned && wcr_unread_because(&plan, WCR_SAYS_NEW_PHRASE));
    bool ran = wcr_restore_cli(dir, tip, true, &run);
    WCR_CHECK("and so does its commit",
              ran && wcr_unread_because(&run, WCR_SAYS_NEW_PHRASE));
    WCR_CHECK("setup: a chain with history for the app's create reply",
              wcr_history_chain(dir, sizeof(dir), "tip_reply_z"));
    ran = wcr_restore_cli(dir, ",\"shielded_only\":true,"
                               "\"birthday_at_local_tip\":true", true, &run);
    WCR_CHECK("the app's create says it had no transparent address to look up",
              ran && wcr_unread_because(&run, WCR_SAYS_SHIELDED));
    wcr_fixture(dir, sizeof(dir), "reply_nochain");
    ran = wcr_restore_cli(dir, "", true, &run);
    WCR_CHECK("a restore into a datadir with no chain still says it has none",
              ran && wcr_unread_because(&run, WCR_SAYS_NO_CHAIN));
    return failures;
}

static int t_restore_at_local_tip(void)
{
    return restore_tip_recorded() + restore_tip_edge() +
           restore_tip_short() + restore_tip_plan_then_commit() +
           restore_tip_plan_short() + restore_default_no_birthday() +
           restore_refusal_keeps_phrase_out() + recovery_new_makes_no_state() +
           restore_tip_reads_no_history() +
           restore_tip_shielded_reads_nothing() +
           restore_other_birthdays_read_history() +
           restore_tip_reply_names_reason();
}

/* The key scans can find what they look for: a plaintext datadir holds the raw
 * seed, and the spending-key search finds it when it is stored. */
static int t_scan_positive_control(void)
{
    int failures = 0;
    char dir[1024];
    struct wcr_run run;
    uint8_t seed[32];
    wcr_phrase_seed(WCR_RESTORE_PHRASE, seed);
    WCR_CHECK("setup: a seeded datadir",
              wcr_seeded_chain(dir, sizeof(dir), "rs_plain", false));
    bool ran = wcr_restore_cli(dir, "", true, &run);
    WCR_CHECK("setup: a plaintext restore commits",
              ran && run.rc == 0 && wcr_data_bool(&run, "committed"));
    WCR_CHECK("the seed scan reads every file and finds the seed in a "
              "plaintext wallet",
              wcr_scan_proves_seed(dir, seed));
    size_t key_matches = 0;
    bool key_scanned = wcr_spending_key_scan(dir, seed, &key_matches);
    WCR_CHECK("the spending-key scan derives the key and reads every file",
              key_scanned);
    WCR_CHECK("the spending-key scan finds the key in a plaintext wallet",
              key_scanned && key_matches > 0);
    memory_cleanse(seed, sizeof(seed));
    return failures;
}

/* ── case 14: a node whose blocks are behind still creates ─────────────── */

/* The anchor the rest of this group runs with: none, so its fixtures keep the
 * birthdays their connected rows give. The cases below install a scaled-down
 * one, or the anchor this release ships. */
static const struct sha3_utxo_checkpoint wcr_no_anchor = { .height = 0 };
static struct sha3_utxo_checkpoint wcr_anchor;

static void wcr_anchor_at(int height, uint8_t fill)
{
    memset(&wcr_anchor, 0, sizeof(wcr_anchor));
    wcr_anchor.height = height;
    memset(wcr_anchor.block_hash, fill, sizeof(wcr_anchor.block_hash));
    checkpoints_set_sha3_override_for_test(&wcr_anchor);
}

static struct uint256 wcr_header_hash(int h, uint8_t branch)
{
    struct uint256 x;
    memset(&x, 0, sizeof(x));
    x.data[0] = (uint8_t)h;
    x.data[1] = (uint8_t)(h >> 8);
    x.data[2] = (uint8_t)(h >> 16);
    x.data[3] = (uint8_t)(0xb0 | branch);
    return x;
}

static struct block_index *wcr_header(struct main_state *ms,
                                      struct block_index *prev, int h,
                                      uint8_t branch, uint32_t bits,
                                      uint32_t status)
{
    struct uint256 hash = wcr_header_hash(h, branch);
    struct block_index *pi =
        chainstate_insert_block_index((struct chainstate *)ms, &hash);
    if (!pi)
        return NULL;
    pi->nHeight = h;
    pi->nBits = bits;
    pi->nTime = 1000000 + (uint32_t)h * 150;
    pi->nVersion = 4;
    pi->nStatus = status;
    pi->pprev = prev;
    struct arith_uint256 proof = GetBlockProof(pi);
    if (prev)
        arith_uint256_add(&pi->nChainWork, &prev->nChainWork, &proof);
    else
        pi->nChainWork = proof;
    return pi;
}

/* block_index.bin holding headers 0..n-1 the node accepted and holds no body
 * for. With `forks`, beside them a fork from 1101 to 1250 with a 256-fold
 * easier target, so longer and lighter, and a failed child of the last
 * header: the best header stays n-1, by chain work. */
static bool wcr_header_chain(const char *dir, int n, bool forks)
{
    struct main_state ms;
    main_state_init(&ms);
    struct block_index *prev = NULL, *base = NULL;
    bool ok = true;
    for (int h = 0; ok && h < n; h++) {
        prev = wcr_header(&ms, prev, h, 0, 0x1f07ffff, BLOCK_VALID_TREE);
        ok = prev != NULL;
        if (h == 1100)
            base = prev;
    }
    if (ok && forks) {
        ok = base != NULL &&
             wcr_header(&ms, prev, n, 2, 0x1f07ffff,
                        BLOCK_VALID_TREE | BLOCK_FAILED_VALID) != NULL;
        for (int h = 1101; ok && h <= 1250; h++)
            ok = (base = wcr_header(&ms, base, h, 1, 0x2007ffff,
                                    BLOCK_VALID_TREE)) != NULL;
    }
    ok = ok && save_block_index_flat_identity(dir, &ms, NULL).ok;
    main_state_free(&ms);
    return ok;
}

static bool wcr_birthday_of(const char *dir, int64_t *height,
                            uint8_t hash[32])
{
    struct node_db ndb;
    bool open = wcr_open(&ndb, dir);
    bool got = open && db_wallet_birthday_get(&ndb, height, hash);
    if (open)
        node_db_close(&ndb);
    printf("    birthday %lld\n", got ? (long long)*height : -1LL);
    return got;
}

/* Headers to 1199, an anchor at 1000, no block row: the best header wins and
 * its ancestor 100 below is the floor block. */
static int unsynced_headers(void)
{
    int failures = 0;
    char dir[1024];
    struct wcr_run run;
    int64_t b = 0;
    uint8_t hash[32];
    struct uint256 want = wcr_header_hash(1099, 0);
    wcr_fixture(dir, sizeof(dir), "unsynced_headers");
    wcr_anchor_at(1000, 0xa0);
    WCR_CHECK("setup: no block rows, an anchor at 1000, headers to 1199, a "
              "longer lighter fork and a failed child",
              wcr_header_chain(dir, 1200, true));
    memset(&run, 0, sizeof(run));
    uint64_t opens = block_index_flat_cursor_opens_for_testing();
    bool created = wcr_create(dir, WCR_PASS, &run) && run.rc == 0;
    WCR_CHECK("a node with headers and no blocks creates a wallet, opening "
              "block_index.bin once",
              created && block_index_flat_cursor_opens_for_testing() ==
                             opens + 1);
    WCR_CHECK("the birthday is the best header 1199, not the fork's 1250, "
              "with the hash of its ancestor at 1099",
              created && wcr_birthday_of(dir, &b, hash) && b == 1199 &&
              memcmp(hash, want.data, 32) == 0 &&
              wcr_data_int(&run, "birthday_height") == 1199);
    return failures;
}

/* Exposed new words use the release anchor even when saved headers lag. */
static int unsynced_short_headers(void)
{
    int failures = 0;
    char dir[1024];
    struct wcr_run run;
    int64_t b = 0;
    uint8_t hash[32];
    uint8_t want[32];
    memset(want, 0xa0, sizeof(want));
    wcr_fixture(dir, sizeof(dir), "unsynced_short");
    wcr_anchor_at(1000, 0xa0);
    WCR_CHECK("setup: headers to 299 under an anchor at 1000",
              wcr_header_chain(dir, 300, false));
    bool ran = wcr_restore_cli(dir, ",\"birthday_at_local_tip\":true", true,
                               &run);
    WCR_CHECK("the saved phrase keeps the release anchor despite short headers",
              ran && run.rc == 0 && wcr_birthday_of(dir, &b, hash) &&
              b == 1100 && memcmp(hash, want, 32) == 0 &&
              wcr_unread_blocker(dir, WALLET_BIRTHDAY_PENDING));
    struct node_db proof_db; uint8_t ph[32], pi[32]; int64_t pb = 0;
    bool proof_open = ran && run.rc == 0 && wcr_open(&proof_db, dir);
    WCR_CHECK("restore opt-in never creates local-origin proof", proof_open &&
        db_wallet_birthday_proof_get(&proof_db, &pb, ph, pi) == WALLET_BIRTHDAY_PROOF_ABSENT);
    if (proof_open) node_db_close(&proof_db);
    return failures;
}

/* A save delayed while the node advances cannot skip payments received
 * after phrase exposure. The release anchor stays below that whole range. */
static int unsynced_sparse_row(void)
{
    int failures = 0;
    char dir[1024];
    struct wcr_run run;
    int64_t b = 0;
    uint8_t hash[32], want[32];
    memset(want, 0xa0, sizeof(want));
    wcr_fixture(dir, sizeof(dir), "unsynced_sparse");
    wcr_anchor_at(1000, 0xa0);
    WCR_CHECK("setup: after words are exposed at anchor 1000, the chain advances",
              wcr_block(dir, 0x11, 1001, 3) &&
              wcr_block(dir, 0x12, 4900, 3) &&
              wcr_block(dir, 0x13, 5000, 3));
    bool ran = wcr_restore_cli(dir, ",\"birthday_at_local_tip\":true", true,
                               &run);
    WCR_CHECK("delayed save still scans payment height 1001 after tip reaches 5000",
              ran && run.rc == 0 && wcr_birthday_of(dir, &b, hash) &&
              b == 1100 && b - WALLET_BIRTHDAY_MARGIN < 1001 &&
              memcmp(hash, want, 32) == 0 &&
              wcr_unread_blocker(dir, WALLET_BIRTHDAY_PENDING));
    return failures;
}

/* Connected rows well past the anchor: the birthday is the node's own tip
 * and block_index.bin, whose open hashes the whole file, is never opened,
 * even though it holds headers past that tip. */
static int synced_reads_no_headers(void)
{
    int failures = 0;
    char dir[1024];
    struct wcr_run run;
    int64_t b = 0;
    uint8_t hash[32];
    wcr_fixture(dir, sizeof(dir), "synced_no_headers");
    wcr_anchor_at(1000, 0xa0);
    WCR_CHECK("setup: connected rows at 1900 and 2000, an anchor at 1000 and "
              "headers to 2499",
              wcr_block(dir, 0x19, 1900, 3) && wcr_block(dir, 0x20, 2000, 3) &&
              wcr_header_chain(dir, 2500, false));
    memset(&run, 0, sizeof(run));
    uint64_t opens = block_index_flat_cursor_opens_for_testing();
    bool created = wcr_create(dir, WCR_PASS, &run) && run.rc == 0;
    WCR_CHECK("a synced node creates a wallet without opening block_index.bin",
              created && block_index_flat_cursor_opens_for_testing() == opens);
    WCR_CHECK("the birthday is its tip 2000 on the row at 1900",
              created && wcr_birthday_of(dir, &b, hash) && b == 2000 &&
              hash[0] == 0x19 && hash[31] == 0x19 &&
              wcr_data_int(&run, "birthday_height") == 2000);
    return failures;
}

/* What boot then does with the wallet on a chain still at 1001. */
static int unsynced_boot(const char *dir, int floor_height)
{
    int failures = 0;
    struct node_db ndb;
    struct wcr_chain k;
    bool open = wcr_open(&ndb, dir);
    bool made = open && wcr_chain_make(&k, 1002, -1, 0);
    int floor = 0;
    WCR_CHECK("a chain at 1001 has not reached the floor: AHEAD",
              made && wallet_birthday_check(&ndb, &k.chain, &floor) ==
                          WALLET_BIRTHDAY_AHEAD && floor == floor_height);
    struct wallet *w = made ? wcr_boot_wallet(&ndb, &k, 0) : NULL;
    WCR_CHECK("boot keeps the floor but remains unread until it is verified",
              w && w->initial_scan_floor == floor_height &&
              w->scan_retry.pending && wallet_scanned_through_height(w) < 0);
    if (w) {
        wallet_free(w);
        free(w);
    }
    if (made)
        wcr_chain_free(&k);
    if (open)
        node_db_close(&ndb);
    return failures;
}

/* A fresh node stores the release anchor and remains unread until the
 * active chain verifies that floor and a scan covers the remaining blocks. */
static int unsynced_release_anchor(void)
{
    int failures = 0;
    char dir[1024];
    struct wcr_run run;
    int64_t b = 0;
    uint8_t hash[32];
    struct uint256 want;
    checkpoints_reset_sha3_override_for_test();
    const struct sha3_utxo_checkpoint *cp = get_sha3_utxo_checkpoint();
    int anchor = cp ? cp->height : 0;
    int floor = anchor;
    if (cp) memcpy(want.data, cp->block_hash, sizeof(want.data));
    WCR_CHECK("setup: the release ships an anchor above a checkpoint",
              anchor > 0 && floor > 0);
    wcr_fixture(dir, sizeof(dir), "unsynced_fresh");
    bool ran = wcr_restore_cli(dir, ",\"birthday_at_local_tip\":true", true,
                               &run);
    WCR_CHECK("an empty datadir saves a phrase made now",
              ran && run.rc == 0 && wcr_data_bool(&run, "committed"));
    WCR_CHECK("its birthday retains the release anchor as the scan floor",
              ran && wcr_birthday_of(dir, &b, hash) &&
              b == floor + WALLET_BIRTHDAY_MARGIN &&
              memcmp(hash, want.data, 32) == 0);
    WCR_CHECK("the wallet remains unread until coverage is verified",
              ran && wcr_unread_blocker(dir,
                  wcr_data_bool(&run, "birthday_recorded")
                      ? WALLET_BIRTHDAY_PENDING : WALLET_RESTORE_BLOCKER_UNREAD));
    failures += unsynced_boot(dir, floor);
    checkpoints_set_sha3_override_for_test(&wcr_no_anchor);
    return failures;
}

/* An older phrase restored on the same unsynced node is unchanged: no
 * birthday from headers or the anchor, and a named one counts only when the
 * datadir holds its block. */
static int unsynced_older_phrase(void)
{
    int failures = 0;
    char dir[1024], extra[256], hex[65];
    struct wcr_run run;
    int64_t b = 0;
    uint8_t hash[32];
    wcr_fixture(dir, sizeof(dir), "unsynced_older");
    wcr_anchor_at(1000, 0xa0);
    WCR_CHECK("setup: headers to 1199 under an anchor at 1000",
              wcr_header_chain(dir, 1200, false));
    bool ran = wcr_restore_cli(dir, "", true, &run);
    WCR_CHECK("a restore without a birthday stores none and reads unread "
              "from 0", ran && run.rc == 0 && !wcr_birthday_of(dir, &b, hash) &&
              wcr_unread_from_zero(dir));
    struct uint256 header = wcr_header_hash(1099, 0);
    for (int i = 0; i < 32; i++)
        snprintf(hex + 2 * i, 3, "%02x", header.data[i]);
    wcr_fixture(dir, sizeof(dir), "unsynced_named");
    snprintf(extra, sizeof(extra),
             ",\"birthday\":{\"height\":1199,\"hash\":\"%s\"}", hex);
    ran = wcr_header_chain(dir, 1200, false) &&
          wcr_restore_cli(dir, extra, true, &run);
    WCR_CHECK("a named birthday only a header holds is rejected and the "
              "wallet reads unread from 0",
              ran && run.rc == 0 && wcr_data_bool(&run, "birthday_rejected") &&
              !wcr_birthday_of(dir, &b, hash) && wcr_unread_from_zero(dir));
    checkpoints_set_sha3_override_for_test(&wcr_no_anchor);
    return failures;
}

static int t_unsynced_create(void)
{
    int failures = unsynced_headers() + unsynced_short_headers() +
                   unsynced_sparse_row() + synced_reads_no_headers();
    checkpoints_set_sha3_override_for_test(&wcr_no_anchor);
    return failures + unsynced_release_anchor() + unsynced_older_phrase();
}

static int birthday_deny_insert(void *ctx, int action, const char *a, const char *b,
                                const char *c, const char *d)
{
    (void)ctx; (void)a; (void)b; (void)c; (void)d;
    return action == SQLITE_INSERT ? SQLITE_DENY : SQLITE_OK;
}

static int birthday_identity_change(void)
{
    int failures = 0;
    struct wallet *w = calloc(1, sizeof(*w));
    if (!w) return 1;
    wallet_init(w);
    uint8_t before[32], after[32];
    struct key_id watch = {0}; watch.id.data[0] = 7;
    bool ok = wallet_scan_identity(w, before) && keystore_add_watch_only_id(&w->keystore, &watch) &&
        wallet_scan_identity(w, after) && memcmp(before, after, 32) != 0;
    WCR_CHECK("watch-only import changes bound scan identity", ok);
    struct privkey key; privkey_init(&key); privkey_make_new(&key, true);
    memcpy(before, after, 32);
    ok = ok && keystore_add_key(&w->keystore, &key) && wallet_scan_identity(w, after) && memcmp(before, after, 32) != 0;
    WCR_CHECK("private-key import changes bound scan identity", ok);
    memory_cleanse(key.vch, sizeof(key.vch));
    wallet_free(w); free(w);
    return failures;
}


static int birthday_proof_atomic(void)
{
    int failures = 0;
    struct node_db db = {0};
    bool opened = node_db_open(&db, ":memory:");
    uint8_t hash[32] = {1}, identity[32] = {2}, got_hash[32], got_identity[32];
    int64_t height = 0;
    WCR_CHECK("birthday proof fixture opens", opened);
    if (!opened) return failures;
    WCR_CHECK("birthday proof starts absent", db_wallet_birthday_proof_get(&db, &height, got_hash, got_identity) == WALLET_BIRTHDAY_PROOF_ABSENT);
    WCR_CHECK("birthday and identity bind", db_wallet_birthday_set_created(&db, 200, hash, identity) &&
        db_wallet_birthday_proof_get(&db, &height, got_hash, got_identity) == WALLET_BIRTHDAY_PROOF_FOUND &&
        height == 200 && !memcmp(hash, got_hash, 32) && !memcmp(identity, got_identity, 32));
    WCR_CHECK("birthday proof rolls back with outer transaction", node_db_begin(&db) &&
        db_wallet_birthday_set(&db, 300, hash) && node_db_rollback(&db) &&
        db_wallet_birthday_proof_get(&db, &height, got_hash, got_identity) == WALLET_BIRTHDAY_PROOF_FOUND && height == 200);
    WCR_CHECK("birthday fault injector installs", sqlite3_set_authorizer(db.db, birthday_deny_insert, NULL) == SQLITE_OK);
    bool refused = !db_wallet_birthday_set_created(&db, 400, hash, identity);
    sqlite3_set_authorizer(db.db, NULL, NULL);
    WCR_CHECK("failed write rolls back prior proof", refused &&
        db_wallet_birthday_proof_get(&db, &height, got_hash, got_identity) == WALLET_BIRTHDAY_PROOF_FOUND && height == 200);
    WCR_CHECK("legacy birthday rewrite invalidates proof", db_wallet_birthday_set(&db, 300, hash) &&
        db_wallet_birthday_proof_get(&db, &height, got_hash, got_identity) == WALLET_BIRTHDAY_PROOF_ABSENT);
    WCR_CHECK("malformed proof refuses", node_db_state_set(&db, "wallet_birthday_scan_identity", hash, 1) &&
        db_wallet_birthday_proof_get(&db, &height, got_hash, got_identity) == WALLET_BIRTHDAY_PROOF_MALFORMED);
    node_db_close(&db);
    return failures;
}


static int birthday_fresh_ignores_supplied_phrase(void)
{
    int failures = 0;
    char dir[1024], phrase[MNEMONIC_MAX_PHRASE_SIZE];
    wcr_fixture(dir, sizeof(dir), "fresh_override");
    struct wallet_recovery_request req = {.datadir = dir, .phrase = WCR_RESTORE_PHRASE,
        .passphrase = WCR_PASS, .shielded_only = true, .dry_run = true,
        .birthday_at_local_tip = true, .has_birthday = true};
    struct wallet_recovery_report report;
    wallet_lock_reset_for_test();
    struct zcl_result result = wallet_recovery_create_fresh(&req, &report, phrase, sizeof(phrase));
    WCR_CHECK("fresh entry replaces supplied phrase and conflicting birthday flags",
        result.ok && phrase[0] && strcmp(phrase, WCR_RESTORE_PHRASE) != 0);
    memory_cleanse(phrase, sizeof(phrase));
    return failures;
}


static bool creation_reservation(const char *dir, const char *words, bool issue,
                                 uint8_t d[11], uint8_t pk[32])
{
    struct node_db db;
    if (!wcr_open(&db, dir)) return false;
    struct wallet_sqlite ws = {0};
    bool ok = wallet_sqlite_open_r(&ws, db.db).ok;
    struct wallet *w = calloc(1, sizeof(*w));
    struct sapling_key_entry acct = {0};
    uint8_t initial_d[11], initial_pk[32];
    if (w) {
        wallet_init(w);
        w->sapling_keys.follows_wallet_lock = false;
        ok = ok && wallet_init_from_recovery_phrase(w, words) &&
            sapling_keystore_new_address(&w->sapling_keys, initial_d, initial_pk) &&
            sapling_keystore_copy_receive_account(&w->sapling_keys, &acct);
        if (ok) {
            if (issue) ok = wallet_sqlite_diversifier_reserve(&ws, &acct, d, pk);
            else ok = wallet_sqlite_diversifier_current(&ws, &acct, d, pk) == WALLET_DIVERSIFIER_PRESENT;
        }
        wallet_free(w);
        free(w);
    } else ok = false;
    memory_cleanse(&acct, sizeof(acct));
    if (ws.open) wallet_sqlite_close(&ws);
    node_db_close(&db);
    return ok;
}

static int creation_data_version(sqlite3 *db)
{
    sqlite3_stmt *s = NULL;
    if (!db || sqlite3_prepare_v2(db, "PRAGMA data_version", -1, &s, NULL) != SQLITE_OK)
        return -1;
    int version = sqlite3_step(s) == SQLITE_ROW ? sqlite3_column_int(s, 0) : -1;
    if (sqlite3_finalize(s) != SQLITE_OK) return -1;
    return version;
}

static int creation_reserved_retry_fixture(const char *dir, const char *words,
                                            const uint8_t nonce[32])
{
    int failures = 0;
    uint8_t before_d[11], before_pk[32], after_d[11], after_pk[32];
    bool reserved = creation_reservation(dir, words, true, before_d, before_pk);
    WCR_CHECK("new receive address reserved", reserved);
    char path[1400];
    snprintf(path, sizeof(path), "%s/node.db", dir);
    sqlite3 *observer = NULL;
    bool observed = sqlite3_open_v2(path, &observer, SQLITE_OPEN_READONLY, NULL) == SQLITE_OK;
    int version = observed ? creation_data_version(observer) : -1;
    struct wallet_recovery_report report = {0};
    bool retry = wallet_creation_commit(dir, words, nonce, WCR_PASS, &report).ok;
    int after_version = observed ? creation_data_version(observer) : -1;
    if (observer) sqlite3_close(observer);
    WCR_CHECK("committed retry does not change wallet database", version >= 0 && version == after_version);
    WCR_CHECK("committed retry succeeds after new address without writing",
              reserved && retry && report.creation_replayed);
    bool read = creation_reservation(dir, words, false, after_d, after_pk);
    WCR_CHECK("committed retry preserves current receive address",
              read && reserved && !memcmp(before_d, after_d, sizeof(before_d)) &&
              !memcmp(before_pk, after_pk, sizeof(before_pk)));
    return failures;
}

static int creation_committed_fixture(const char *dir, const char *words, const uint8_t nonce[32])
{
    int failures = 0;
    struct node_db db; struct wallet_create_pending p = {0};
    bool opened = wcr_open(&db, dir);
    WCR_CHECK("committed receipt survives reopen", opened &&
        db_wallet_create_pending_get(&db, &p) == WALLET_BIRTHDAY_PROOF_FOUND && p.committed);
    bool extra = opened && sqlite3_exec(db.db, "INSERT INTO wallet_watch_only(address_hash,address,created_at) VALUES(x'01','test',0)", NULL, NULL, NULL) == SQLITE_OK;
    if (opened) node_db_close(&db);
    WCR_CHECK("committed retry preserves later watch-only entry", extra && wallet_creation_commit(dir, words, nonce, WCR_PASS, NULL).ok);
    WCR_CHECK("committed retry rejects wrong passphrase", !wallet_creation_commit(dir, words, nonce, "wrong-passphrase", NULL).ok);
    opened = wcr_open(&db, dir);
    bool damaged_key = opened && sqlite3_exec(db.db, "UPDATE wallet_sapling_keys SET xsk=zeroblob(length(xsk)) WHERE child_index=0", NULL, NULL, NULL) == SQLITE_OK;
    if (opened) node_db_close(&db);
    WCR_CHECK("committed retry rejects mismatched spending key", damaged_key && !wallet_creation_commit(dir, words, nonce, WCR_PASS, NULL).ok);
    opened = wcr_open(&db, dir);
    bool damaged = opened && sqlite3_exec(db.db, "UPDATE wallet_seed SET seed=x'01' WHERE id=1", NULL, NULL, NULL) == SQLITE_OK;
    if (opened) node_db_close(&db);
    WCR_CHECK("committed retry rejects malformed seed", damaged && !wallet_creation_commit(dir, words, nonce, WCR_PASS, NULL).ok);
    return failures;
}

static int creation_prepare_fixture(void)
{
    int failures = 0;
    char dir[1024], words[MNEMONIC_MAX_PHRASE_SIZE] = {0};
    uint8_t nonce[32] = {0}, retry_nonce[32];
    wcr_fixture(dir, sizeof(dir), "creation_prepare");
    wallet_lock_reset_for_test();
    struct zcl_result first = wallet_creation_prepare(dir, words, sizeof(words), nonce);
    WCR_CHECK("creation prepare returns new words after durable record", first.ok && mnemonic_validate(words));
    struct node_db db;
    bool opened = first.ok && wcr_open(&db, dir);
    struct wallet_create_pending p = {0};
    WCR_CHECK("creation prepare survives database reopen", opened &&
        db_wallet_create_pending_get(&db, &p) == WALLET_BIRTHDAY_PROOF_FOUND && !memcmp(nonce, p.nonce, 32));
    if (opened) node_db_close(&db);
    char retry[MNEMONIC_MAX_PHRASE_SIZE]; memset(retry, 0x55, sizeof(retry));
    memset(retry_nonce, 0x55, sizeof(retry_nonce));
    struct zcl_result second = wallet_creation_prepare(dir, retry, sizeof(retry), retry_nonce);
    const uint8_t zero[32] = {0};
    WCR_CHECK("second prepare refuses and clears outputs", !second.ok && retry[0] == 0 && !memcmp(retry_nonce, zero, 32));
    uint8_t wrong_nonce[32]; memcpy(wrong_nonce, nonce, 32); wrong_nonce[0] ^= 1;
    WCR_CHECK("wrong nonce refuses commit", !wallet_creation_commit(dir, words, wrong_nonce, WCR_PASS, NULL).ok);
    WCR_CHECK("wrong phrase refuses commit", !wallet_creation_commit(dir, WCR_RESTORE_PHRASE, nonce, WCR_PASS, NULL).ok);
    struct wallet_recovery_report receipt = {0};
    WCR_CHECK("prepared phrase commits", wallet_creation_commit(dir, words, nonce, WCR_PASS, &receipt).ok && !receipt.creation_replayed);
    WCR_CHECK("repeated commit is idempotent", wallet_creation_commit(dir, words, nonce, WCR_PASS, &receipt).ok && receipt.creation_replayed);
    failures += creation_reserved_retry_fixture(dir, words, nonce);
    failures += creation_committed_fixture(dir, words, nonce);
    memory_cleanse(words, sizeof(words)); memory_cleanse(retry, sizeof(retry));
    return failures;
}


static int creation_cancel_fixture(void)
{
    int failures = 0;
    char dir[1024], words[MNEMONIC_MAX_PHRASE_SIZE] = {0};
    uint8_t nonce[32] = {0}, wrong[32];
    wcr_fixture(dir, sizeof(dir), "creation_cancel");
    wallet_lock_reset_for_test();
    struct zcl_result prepared = wallet_creation_prepare(dir, words, sizeof(words), nonce);
    WCR_CHECK("cancel fixture prepared", prepared.ok);
    memcpy(wrong, nonce, 32); wrong[0] ^= 1;
    WCR_CHECK("wrong nonce cannot cancel", !wallet_creation_cancel(dir, wrong).ok);
    struct node_db db;
    bool opened = wcr_open(&db, dir);
    bool inserted = opened && sqlite3_exec(db.db, "INSERT INTO wallet_key_encryption(id,wrapped_dek) VALUES(1,x'01')", NULL, NULL, NULL) == SQLITE_OK;
    WCR_CHECK("orphaned DEK fixture inserted", inserted);
    if (opened) node_db_close(&db);
    WCR_CHECK("cancel refuses retained DEK", inserted && !wallet_creation_cancel(dir, nonce).ok);
    opened = wcr_open(&db, dir);
    struct wallet_create_pending p = {0};
    WCR_CHECK("refusal preserves pending preparation", opened && db_wallet_create_pending_get(&db, &p) == WALLET_BIRTHDAY_PROOF_FOUND && !p.committed);
    bool removed = opened && sqlite3_exec(db.db, "DELETE FROM wallet_key_encryption", NULL, NULL, NULL) == SQLITE_OK;
    if (opened) node_db_close(&db);
    WCR_CHECK("matching wallet-free preparation cancels", removed && wallet_creation_cancel(dir, nonce).ok);
    memory_cleanse(words, sizeof(words));
    return failures;
}

static bool creation_fixture_seed_absent(sqlite3 *db)
{
    sqlite3_stmt *s = NULL;
    if (sqlite3_prepare_v2(db, "SELECT count(*) FROM wallet_seed", -1, &s, NULL) != SQLITE_OK) return false;
    bool absent = sqlite3_step(s) == SQLITE_ROW && sqlite3_column_int64(s, 0) == 0 && sqlite3_step(s) == SQLITE_DONE;
    return sqlite3_finalize(s) == SQLITE_OK && absent;
}

static int creation_atomic_failure_fixture(void)
{
    int failures = 0;
    char dir[1024], words[MNEMONIC_MAX_PHRASE_SIZE] = {0};
    uint8_t nonce[32] = {0};
    wcr_fixture(dir, sizeof(dir), "creation_atomic_failure");
    wallet_lock_reset_for_test();
    struct zcl_result prepared = wallet_creation_prepare(dir, words, sizeof(words), nonce);
    WCR_CHECK("atomic fault fixture prepared", prepared.ok);
    struct node_db db;
    bool opened = wcr_open(&db, dir);
    bool armed = opened && sqlite3_exec(db.db, "CREATE TRIGGER reject_creation BEFORE UPDATE ON node_state WHEN OLD.key='wallet_create_pending_v1' BEGIN SELECT RAISE(ABORT,'injected'); END", NULL, NULL, NULL) == SQLITE_OK;
    if (opened) node_db_close(&db);
    WCR_CHECK("atomic commit fault refuses", armed && !wallet_creation_commit(dir, words, nonce, WCR_PASS, NULL).ok);
    opened = wcr_open(&db, dir);
    struct wallet_create_pending p = {0};
    WCR_CHECK("failed commit retains preparation and no wallet seed", opened && db_wallet_create_pending_get(&db, &p) == WALLET_BIRTHDAY_PROOF_FOUND && !p.committed && db_sapling_key_count(&db) == 0 && creation_fixture_seed_absent(db.db));
    if (opened) node_db_close(&db);
    memory_cleanse(words, sizeof(words));
    return failures;
}

static bool creation_cli_fact(const struct wcr_run *run, const char *key, const char *expected)
{
    struct json_value v; json_init(&v);
    bool ok = json_read(&v, run->wire, strlen(run->wire));
    const struct json_value *facts = ok ? json_get(json_get(&v, "error"), "facts") : NULL;
    const char *value = facts ? json_get_str(json_get(facts, key)) : NULL;
    ok = value && !strcmp(value, expected);
    json_free(&v);
    return ok;
}

static bool creation_cli_prepared(const struct wcr_run *run, const char *nonce)
{
    char state[32], found[65];
    return wcr_field(run, "creation_state", state, sizeof(state)) && !strcmp(state, "prepared") &&
        wcr_field(run, "creation_nonce", found, sizeof(found)) && !strcmp(found, nonce);
}

static int creation_cli_refusals(const char *dir, const char *phrase, const char *nonce)
{
    int failures = 0; char text[4096], wrong[65];
    struct wcr_run run = {0};
    const char *restore[] = {"wallet", "recovery", "restore", "--input=-", "--format=json"};
    snprintf(wrong, sizeof(wrong), "%s", nonce);
    wrong[0] = wrong[0] == '0' ? '1' : '0';
    snprintf(text, sizeof(text), "{\"datadir\":\"%s\",\"phrase\":\"%s\",\"passphrase\":\"%s\",\"creation_nonce\":\"%s\",\"confirm\":true}", dir, phrase, WCR_PASS, wrong);
    WCR_CHECK("CLI refuses wrong nonce", wcr_cli_args(restore, 5, text, &run) && run.rc != 0);
    snprintf(text, sizeof(text), "{\"datadir\":\"%s\",\"phrase\":\"%s\",\"passphrase\":\"%s\",\"creation_nonce\":\"%s\",\"confirm\":true}", dir, WCR_RESTORE_PHRASE, WCR_PASS, nonce);
    WCR_CHECK("CLI refuses wrong phrase", wcr_cli_args(restore, 5, text, &run) && run.rc != 0);
    memory_cleanse(text, sizeof(text));
    return failures;
}

static int creation_cli_fixture(void)
{
    int failures = 0;
    char dir[1024], text[4096], phrase[MNEMONIC_MAX_PHRASE_SIZE] = {0}, nonce[65] = {0};
    struct wcr_run run = {0};
    const char *status[] = {"wallet", "recovery", "status", "--input=-", "--format=json"};
    const char *restore[] = {"wallet", "recovery", "restore", "--input=-", "--format=json"};
    wcr_fixture(dir, sizeof(dir), "creation_cli");
    wallet_lock_reset_for_test();
    snprintf(text, sizeof(text), "{\"datadir\":\"%s\",\"prepare\":true}", dir);
    bool ok = wcr_cli(text, &run) && run.rc == 0 &&
        wcr_field(&run, "phrase", phrase, sizeof(phrase)) &&
        wcr_field(&run, "creation_nonce", nonce, sizeof(nonce));
    WCR_CHECK("CLI prepares phrase and nonce", ok);
    if (ok) failures += creation_cli_refusals(dir, phrase, nonce);
    snprintf(text, sizeof(text), "{\"datadir\":\"%s\"}", dir);
    bool stat = wcr_cli_args(status, 5, text, &run);
    WCR_CHECK("CLI status sees prepared record", stat && creation_cli_prepared(&run, nonce));
    snprintf(text, sizeof(text), "{\"datadir\":\"%s\",\"phrase\":\"%s\",\"passphrase\":\"%s\",\"creation_nonce\":\"%s\",\"confirm\":true}", dir, phrase, WCR_PASS, nonce);
    bool commit = wcr_cli_args(restore, 5, text, &run) && run.rc == 0;
    WCR_CHECK("CLI commits prepared phrase", ok && commit && wcr_data_bool(&run, "committed"));
    bool retry = wcr_cli_args(restore, 5, text, &run) && run.rc == 0;
    WCR_CHECK("CLI confirms retry without mutation", retry && wcr_data_bool(&run, "creation_replayed"));
    snprintf(text, sizeof(text), "{\"datadir\":\"%s\"}", dir);
    stat = wcr_cli_args(status, 5, text, &run);
    WCR_CHECK("CLI locked status exposes committed receipt", stat && creation_cli_fact(&run, "creation_state", "committed") && creation_cli_fact(&run, "creation_nonce", nonce));
    memory_cleanse(phrase, sizeof(phrase)); memory_cleanse(text, sizeof(text));
    return failures;
}

static int creation_after_commit_exit(const char *dir, const char *words, const uint8_t nonce[32])
{
    int failures = 0, status = 0;
    pid_t child = fork();
    if (child == 0) {
        struct zcl_result committed = wallet_creation_commit(dir, words, nonce, WCR_PASS, NULL);
        _exit(committed.ok ? 0 : 1);
    }
    bool exited = child > 0 && waitpid(child, &status, 0) == child &&
        WIFEXITED(status) && WEXITSTATUS(status) == 0;
    struct wallet_recovery_report receipt = {0};
    WCR_CHECK("committed child exit recovers receipt", exited &&
        wallet_creation_commit(dir, words, nonce, WCR_PASS, &receipt).ok && receipt.creation_replayed);
    return failures;
}

static int creation_exit_fixture(void)
{
    int failures = 0, status = 0;
    char dir[1024], words[MNEMONIC_MAX_PHRASE_SIZE] = {0};
    uint8_t nonce[32] = {0};
    wcr_fixture(dir, sizeof(dir), "creation_exit");
    wallet_lock_reset_for_test();
    struct zcl_result prepared = wallet_creation_prepare(dir, words, sizeof(words), nonce);
    WCR_CHECK("process-exit fixture prepared", prepared.ok);
    pid_t interrupted = fork();
    if (interrupted == 0) {
        wallet_sqlite_creation_exit_before_commit_for_test();
        (void)wallet_creation_commit(dir, words, nonce, WCR_PASS, NULL);
        _exit(1);
    }
    bool crashed = interrupted > 0 && waitpid(interrupted, &status, 0) == interrupted &&
        WIFEXITED(status) && WEXITSTATUS(status) == 42;
    struct node_db after; struct wallet_create_pending pending;
    bool reopened = crashed && wcr_open(&after, dir);
    bool rolled_back = reopened && creation_fixture_seed_absent(after.db) &&
        db_sapling_key_count(&after) == 0 &&
        db_wallet_create_pending_get(&after, &pending) == WALLET_BIRTHDAY_PROOF_FOUND && !pending.committed;
    if (reopened) node_db_close(&after);
    WCR_CHECK("uncommitted child exit rolls back wallet and receipt", rolled_back);
    failures += creation_after_commit_exit(dir, words, nonce);
    memory_cleanse(words, sizeof(words));
    return failures;
}

static int creation_fresh_history_fixture(void)
{
    int failures = 0;
    char dir[1024], phrase[MNEMONIC_MAX_PHRASE_SIZE] = {0};
    struct wallet_recovery_report report;
    struct node_db db;
    wcr_fixture(dir, sizeof(dir), "fresh_history_only");
    bool opened = wcr_open(&db, dir);
    bool inserted = opened && sqlite3_exec(db.db, "INSERT INTO wallet_transactions(txid,raw_tx,time_received) VALUES(x'01',x'01',0)", NULL, NULL, NULL) == SQLITE_OK;
    if (opened) node_db_close(&db);
    wallet_lock_reset_for_test();
    struct wallet_recovery_request req = {.datadir = dir, .passphrase = WCR_PASS};
    WCR_CHECK("fresh creation refuses transaction-only wallet", inserted && !wallet_recovery_create_fresh(&req, &report, phrase, sizeof(phrase)).ok);
    memory_cleanse(phrase, sizeof(phrase));
    wcr_fixture(dir, sizeof(dir), "fresh_unknown_history");
    opened = wcr_open(&db, dir);
    bool removed = opened && sqlite3_exec(db.db, "DROP TABLE wallet_utxos", NULL, NULL, NULL) == SQLITE_OK;
    if (opened) node_db_close(&db);
    wallet_lock_reset_for_test();
    req.datadir = dir;
    WCR_CHECK("fresh creation refuses unreadable wallet history", removed && !wallet_recovery_create_fresh(&req, &report, phrase, sizeof(phrase)).ok);
    memory_cleanse(phrase, sizeof(phrase));
    return failures;
}

int test_wallet_create(void);
int test_wallet_create(void)
{
    int failures = 0;
    failures += birthday_proof_atomic();
    failures += birthday_identity_change();
    chain_params_select(CHAIN_MAIN);
    checkpoints_set_sha3_override_for_test(&wcr_no_anchor);
    failures += birthday_fresh_ignores_supplied_phrase();
    failures += creation_prepare_fixture();
    failures += creation_cancel_fixture();
    failures += creation_atomic_failure_fixture();
    failures += creation_cli_fixture();
    failures += creation_exit_fixture();
    failures += creation_fresh_history_fixture();
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
    failures += restore_address_reopens();
    failures += t_restore_inputs();
    failures += t_unreadable_file_fails_scan();
    failures += t_seed_proof_needs_a_full_read();
    failures += t_wallet_free_wipes_sapling_keys();
    failures += t_live_wallet_refused();
    failures += t_create_failure_codes();
    failures += t_recovery_new();
    failures += t_recovery_reply_fields();
    failures += t_restore_at_local_tip();
    failures += t_scan_positive_control();
    failures += t_unsynced_create();
    checkpoints_reset_sha3_override_for_test();
    if (failures == 0)
        printf("wallet_create: OK (all wallet creation gates pass)\n");
    else
        printf("=== wallet_create: %d failure(s) ===\n", failures);
    return failures;
}
