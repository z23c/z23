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
 *   5. The tip height is stored as the birthday and scans start there.
 *   6. An empty, short or missing passphrase is refused and nothing is made.
 *   7. An agent-ceiling caller is refused before the handler, and a caller
 *      that did not use standard input is refused by the handler.
 */

#define _POSIX_C_SOURCE 200809L

#include "test/test_core.h"

#include "chain/chainparams.h"
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

/* Run `z23 core wallet create --input=-` in process with `stdin_text` on
 * standard input, capturing stdout and stderr. */
static bool wcr_cli(const char *stdin_text, struct wcr_run *run)
{
    struct wcr_cap in, out, err;
    bool ok = wcr_cap_begin(&in, stdin, stdin_text);
    ok = wcr_cap_begin(&out, stdout, NULL) && ok;
    ok = wcr_cap_begin(&err, stderr, NULL) && ok;
    if (ok) {
        const char *args[] = {"wallet", "create", "--input=-",
                              "--format=json"};
        run->rc = zcl_native_command_main("core", args, 4, "", 0,
                                          CHAIN_MAIN, false);
    }
    ok = wcr_cap_end(&in, NULL, 0) && ok;
    ok = wcr_cap_end(&out, run->wire, sizeof(run->wire)) && ok;
    ok = wcr_cap_end(&err, run->err, sizeof(run->err)) && ok;
    return ok;
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

/* The reply document inside stdout. Opening the database prints boot lines
 * ahead of it, so the document starts at its schema key. */
static const char *wcr_doc(const struct wcr_run *run)
{
    const char *d = strstr(run->wire, "{\"schema\":");
    return d ? d : run->wire;
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

/* ── case 5: the birthday is stored and honoured ───────────────────── */

/* An empty wallet scanning 0..500 against a birthday of 1000 has nothing
 * left to do, and the scanner says its range is empty from 900. */
static bool birthday_scan_skips(struct node_db *ndb, int start)
{
    struct active_chain chain;
    active_chain_init(&chain);
    struct wallet *w = calloc(1, sizeof(*w));
    struct wcr_cap cap;
    bool ok = w && wcr_cap_begin(&cap, stdout, NULL);
    if (ok)
        (void)wallet_scan_blocks(ndb, &chain, w, "/nonexistent", 0, 500);
    char log[4096] = {0};
    ok = wcr_cap_end(&cap, log, sizeof(log)) && ok;
    char want[64];
    snprintf(want, sizeof(want), "range empty (start=%d > end=500)", start);
    active_chain_free(&chain);
    free(w);
    return ok && strstr(log, want) != NULL;
}

static int birthday_stored(const char *dir, const struct wcr_run *run)
{
    int failures = 0;
    struct json_value v;
    json_init(&v);
    bool parsed = json_read(&v, wcr_doc(run), strlen(wcr_doc(run)));
    const struct json_value *data = json_get(&v, "data");
    WCR_CHECK("the reply names the birthday",
              parsed && json_get_bool_or(data, "birthday_recorded", false) &&
              json_get_int(json_get(data, "birthday_height")) == 1000);
    json_free(&v);

    struct node_db ndb;
    int64_t b = 0;
    bool open = wcr_open(&ndb, dir);
    WCR_CHECK("the birthday is stored in the wallet",
              open && db_wallet_birthday_get(&ndb, &b) && b == 1000);
    WCR_CHECK("a scan from 0 starts at the birthday less the margin",
              open && wallet_scan_start_height(&ndb, 0) ==
                          1000 - WALLET_SCAN_BIRTHDAY_MARGIN);
    WCR_CHECK("a later start is left alone",
              open && wallet_scan_start_height(&ndb, 990) == 990);
    WCR_CHECK("wallet_scan_blocks skips blocks below the birthday",
              open && birthday_scan_skips(&ndb,
                                          1000 - WALLET_SCAN_BIRTHDAY_MARGIN));
    if (open)
        node_db_close(&ndb);
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
    bool open = r && wcr_open(&ndb, dir);
    WCR_CHECK("a restored wallet has no birthday and scans from 0",
              open && !db_wallet_birthday_get(&ndb, &b) &&
              wallet_scan_start_height(&ndb, 0) == 0);
    if (open)
        node_db_close(&ndb);
    return failures;
}

static int t_birthday(void)
{
    int failures = 0;
    char dir[1024];
    wcr_fixture(dir, sizeof(dir), "birthday");
    bool seeded = wcr_sql(dir,
        "INSERT INTO blocks(hash,height,prev_hash,version,merkle_root,time,"
        "bits,nonce,solution,chain_work,status) VALUES(zeroblob(32),1000,"
        "zeroblob(32),4,zeroblob(32),0,0,zeroblob(32),zeroblob(1),"
        "zeroblob(32),3)");
    struct wcr_run run;
    memset(&run, 0, sizeof(run));
    WCR_CHECK("a datadir with a chain tip at 1000 creates a wallet",
              seeded && wcr_create(dir, WCR_PASS, &run) && run.rc == 0);
    failures += birthday_stored(dir, &run);
    failures += birthday_absent_when_restored();
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
    if (failures == 0)
        printf("wallet_create: OK (all wallet creation gates pass)\n");
    else
        printf("=== wallet_create: %d failure(s) ===\n", failures);
    return failures;
}
