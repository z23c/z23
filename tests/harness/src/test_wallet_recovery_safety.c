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
 *   4. IT READ AN EXISTING node.db IN FULL TWICE, AND ONE READ DECIDED
 *      NOTHING. A commit into a synced datadir ran PRAGMA quick_check on
 *      the read-only handle and again inside node_db_open(): two whole-file
 *      reads, about 7 minutes each for a 7.4 GB node.db on a phone. The
 *      read-only one looked only at sqlite3_exec's return code, which stays
 *      SQLITE_OK when quick_check reports a damaged index as a result row;
 *      such a node.db passed it, the boot open's own check then renamed
 *      node.db, -wal and -shm aside to *.corrupt-<ts>, and the wallet was
 *      written into a fresh empty database.
 *      ASSERTED (counting every quick_check SQLite starts): zero when the
 *      node's last clean shutdown bound this exact node.db, and the marker
 *      is left for the next boot; exactly one without a matching binding;
 *      a damaged node.db is refused and never renamed aside, with or
 *      without a binding; and with the check skipped, a process that holds
 *      node.db's owner lease (as a node that started afterwards would)
 *      still keeps the commit from writing (-63).
 *
 * Every case runs against a fixture datadir under ./test-tmp. Nothing here
 * reads, writes or dials a live node.
 */

#define _POSIX_C_SOURCE 200809L

#include "test/test_core.h"

#include "chain/chainparams.h"
#include "command/native_command.h"   /* the restore leaf's handler */
#include "config/boot_shutdown_marker.h"
#include "config/command_catalog.h"
#include "config/consensus_state_install_runtime.h"
#include "models/wallet_send_once.h"
#include "controllers/wallet_activity.h"
#include "controllers/wallet_controller.h"
#include "controllers/wallet_native_handlers.h"
#include "controllers/agent_controller.h"
#include "controllers/rpc_client.h"
#include "json/json.h"
#include "kernel/command_registry.h"
#include "models/database.h"
#include "models/database_owner_lease.h"
#include "models/wallet_key.h"
#include "services/wallet_recovery_service.h"
#include "services/wallet_restore_service.h"
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
#include <sys/file.h>
#include <fcntl.h>
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

#if !defined(_WIN32)
static void wrs_status(const char *dir, struct zcl_command_reply *reply)
{
    struct json_value input;
    json_init(&input);
    json_set_object(&input);
    (void)json_push_kv_str(&input, "datadir", dir);
    struct zcl_command_request request = { .input = &input };
    zcl_command_reply_init(reply, "zcl.wallet_recovery_status.v1");
    zcl_native_handle_wallet_recovery_status(&request, reply);
    json_free(&input);
}

static bool wrs_address_reason_match(const struct json_value *facts, bool unavailable)
{
    const struct json_value *reason = json_get(facts, "receive_address_status");
    return unavailable ? reason && reason->type == JSON_STR &&
        !strcmp(json_get_str(reason), "unavailable") : !reason;
}

static bool wrs_envelope_facts_match(const struct json_value *facts,
    const char *address, const char *cutover, bool locked, bool unavailable)
{
    if (!locked) return !facts;
    if (!facts || facts->type != JSON_OBJ ||
        facts->num_children != ((address || unavailable) ? 3u : 2u)) return false;
    const char *creation = json_get_str(json_get(facts, "creation_state"));
    if (strcmp(creation, "none") || json_get(facts, "creation_nonce")) return false;
    const char *state = json_get_str(json_get(facts, "wallet_cutover_state"));
    if (strcmp(state, cutover ? cutover : "unknown")) return false;
    const char *actual = json_get_str(json_get(facts, "persisted_shielded_address"));
    if (address ? strcmp(actual, address) != 0 : json_get(facts, "persisted_shielded_address") != NULL) return false;
    return wrs_address_reason_match(facts, unavailable);
}

static bool wrs_envelope_fields_match(const struct json_value *root,
    enum zcl_command_exit exit_code, const char *code, const char *address,
    const char *cutover, bool unavailable)
{
    const struct json_value *ok = json_get(root, "ok");
    const struct json_value *error = json_get(root, "error");
    const char *actual_code = json_get_str(json_get(error, "code"));
    const struct json_value *facts = json_get(error, "facts");
    bool valid = exit_code == ZCL_COMMAND_EXIT_BLOCKED &&
                 ok && ok->type == JSON_BOOL && !json_get_bool(ok) &&
                 actual_code && !strcmp(actual_code, code) &&
                 !json_get(root, "data");
    return valid && wrs_envelope_facts_match(facts, address, cutover, !strcmp(code, "WALLET_LOCKED"), unavailable);
}

/* Execute through the same registry serializer as the CLI. */
static bool wrs_status_envelope(const char *dir, const char *code,
                                const char *address, const char *cutover, bool unavailable)
{
    const struct zcl_command_registry *reg = zcl_command_catalog();
    const struct zcl_command_spec *spec = zcl_command_registry_find(
        reg, "core.wallet.recovery.status", NULL);
    if (!spec) return false;
    struct zcl_command_context ctx = {
        .registry = reg, .granted_capabilities = ~(uint64_t)0,
        .authority_ceiling = ZCL_COMMAND_AUTH_OWNER,
    };
    struct json_value input = {0}, root = {0};
    json_set_object(&input);
    bool built = json_push_kv_str(&input, "datadir", dir);
    char wire[16384];
    enum zcl_command_exit exit_code = ZCL_COMMAND_EXIT_OK;
    size_t n = built ? zcl_command_registry_execute_json(
        reg, spec, &ctx, &input, false, spec->path, "normal", 0, 0, NULL,
        wire, sizeof(wire), &exit_code) : 0;
    bool parsed = n > 0 && n < sizeof(wire) && json_read(&root, wire, n);
    bool valid = parsed && wrs_envelope_fields_match(&root, exit_code, code, address, cutover, unavailable);
    json_free(&root);
    json_free(&input);
    return valid;
}

static int wrs_cutover_floor(void)
{
    int failures = 0, floor = -1;
    sqlite3 *db = NULL;
    WRS_CHECK("floor fixture opens", sqlite3_open(":memory:", &db) == SQLITE_OK);
    if (!db) return failures + 1;
    struct wallet_sqlite ws = {.db = db, .open = true};
    WRS_CHECK("floor fixture schema", sqlite3_exec(db,
        "CREATE TABLE node_state(key TEXT PRIMARY KEY,value)", NULL, NULL, NULL) == SQLITE_OK);
    WRS_CHECK("missing scan cursor starts at zero",
        wallet_sqlite_cutover_scan_floor(&ws, &floor) == WALLET_CUTOVER_FLOOR_ABSENT && floor == 0);
    int32_t height = 10; sqlite3_stmt *s = NULL;
    bool inserted = sqlite3_prepare_v2(db, "INSERT INTO node_state VALUES('wallet_scan_height',?)", -1, &s, NULL) == SQLITE_OK &&
        sqlite3_bind_blob(s, 1, &height, sizeof(height), SQLITE_TRANSIENT) == SQLITE_OK && sqlite3_step(s) == SQLITE_DONE;
    if (s) sqlite3_finalize(s);
    WRS_CHECK("floor saved cursor", inserted && wallet_sqlite_cutover_scan_floor(&ws, &floor) == WALLET_CUTOVER_FLOOR_FOUND && floor == 11);
    WRS_CHECK("floor unread marker fixture", sqlite3_exec(db,
        "INSERT INTO node_state VALUES('wallet_scan_incomplete','from=5 depth=10 since=0 blocker=prior')", NULL, NULL, NULL) == SQLITE_OK);
    WRS_CHECK("floor keeps earlier unread range", wallet_sqlite_cutover_scan_floor(&ws, &floor) == WALLET_CUTOVER_FLOOR_FOUND && floor == 5);
    WRS_CHECK("floor malformed marker fixture", sqlite3_exec(db,
        "UPDATE node_state SET value='from=5 depth=10 since=0 blocker=prior trailing' WHERE key='wallet_scan_incomplete'", NULL, NULL, NULL) == SQLITE_OK);
    WRS_CHECK("floor malformed marker refuses", wallet_sqlite_cutover_scan_floor(&ws, &floor) == WALLET_CUTOVER_FLOOR_MALFORMED);
    WRS_CHECK("floor malformed cursor fixture", sqlite3_exec(db,
        "DELETE FROM node_state WHERE key='wallet_scan_incomplete'; UPDATE node_state SET value='10' WHERE key='wallet_scan_height'", NULL, NULL, NULL) == SQLITE_OK);
    WRS_CHECK("floor malformed cursor refuses", wallet_sqlite_cutover_scan_floor(&ws, &floor) == WALLET_CUTOVER_FLOOR_MALFORMED);
    WRS_CHECK("floor missing table fixture", sqlite3_exec(db, "DROP TABLE node_state", NULL, NULL, NULL) == SQLITE_OK);
    WRS_CHECK("floor storage failure distinct", wallet_sqlite_cutover_scan_floor(&ws, &floor) == WALLET_CUTOVER_FLOOR_IO_ERROR);
    sqlite3_close(db); return failures;
}

static int wrs_deny_sync_raise(void *unused, int action, const char *name,
                               const char *value, const char *db, const char *trigger)
{
    (void)unused; (void)db; (void)trigger;
    return action == SQLITE_PRAGMA && name && value &&
           !strcmp(name, "synchronous") && !strcmp(value, "2") ? SQLITE_DENY : SQLITE_OK;
}

static int wrs_deny_sync_restore(void *unused, int action, const char *name,
                                 const char *value, const char *db, const char *trigger)
{
    (void)unused; (void)db; (void)trigger;
    return action == SQLITE_PRAGMA && name && value &&
           !strcmp(name, "synchronous") && !strcmp(value, "0") ? SQLITE_DENY : SQLITE_OK;
}

static bool wrs_prepare_cutover(sqlite3 *db)
{
    struct wallet_sqlite ws = {0};
    struct wallet *w = calloc(1, sizeof(*w));
    if (!w) return false;
    wallet_init(w);
    bool opened = wallet_sqlite_open_r(&ws, db).ok;
    w->scan_retry.pending = true; w->scan_retry.from = 0;
    struct wallet_cutover_binding b = {.old_height = 0, .target_height = 1};
    b.old_hash[0] = 1; b.target_hash[0] = 2; b.artifact_digest[0] = 3;
    struct node_db node = {.db = db, .open = true};
    bool ok = opened && consensus_state_wallet_commit_fence_test(&node, &ws, w, &b);
    if (opened) wallet_sqlite_close(&ws);
    wallet_free(w); free(w); return ok;
}

/* The native bridge calls the real RPC implementation against the fixture. */
static char *wrs_latest_rpc_hook(const char *method, const char *params_json)
{
    (void)params_json;
    if (!method || strcmp(method, "walletlatestaddress")) return strdup("null");
    struct json_value params = {0}, result = {0};
    json_set_array(&params);
    bool ok = rpc_walletlatestaddress(&params, false, &result);
    char wire[4096];
    size_t n = ok ? json_write(&result, wire, sizeof(wire)) : 0;
    char *answer = n && n < sizeof(wire) ? strdup(wire) : NULL;
    json_free(&params);
    json_free(&result);
    return answer;
}

static bool wrs_latest_envelope(char *out, size_t cap)
{
    const struct zcl_command_registry *reg = zcl_command_catalog();
    const struct zcl_command_spec *spec = zcl_command_registry_find(
        reg, "core.wallet.shielded.latest", NULL);
    if (!spec) return false;
    struct zcl_command_context ctx = {
        .registry = reg, .granted_capabilities = ~(uint64_t)0,
        .authority_ceiling = ZCL_COMMAND_AUTH_OWNER,
    };
    struct json_value input = {0}, root = {0};
    json_set_object(&input);
    char wire[8192];
    enum zcl_command_exit exit_code = ZCL_COMMAND_EXIT_FAILED;
    node_rpc_client_set_test_hook(wrs_latest_rpc_hook);
    size_t n = zcl_command_registry_execute_json(reg, spec, &ctx, &input,
        false, spec->path, "normal", 0, 0, NULL, wire, sizeof(wire), &exit_code);
    node_rpc_client_set_test_hook(NULL);
    bool ok = n > 0 && n < sizeof(wire) && json_read(&root, wire, n) &&
              exit_code == ZCL_COMMAND_EXIT_OK;
    const char *value = json_get_str(json_get(json_get(&root, "data"), "address"));
    if (ok && value && strlen(value) < cap) snprintf(out, cap, "%s", value);
    else ok = false;
    json_free(&root);
    json_free(&input);
    return ok;
}

/* Load the same fixture through the node's public latest-address selector. */
static bool wrs_loaded_latest(const char *path, char *out, size_t cap, size_t *count)
{
    sqlite3 *db = NULL;
    if (sqlite3_open_v2(path, &db, SQLITE_OPEN_READONLY, NULL) != SQLITE_OK) {
        if (db) sqlite3_close(db);
        return false;
    }
    struct wallet_sqlite ws;
    if (!wallet_sqlite_open_r(&ws, db).ok) { sqlite3_close(db); return false; }
    struct wallet *w = malloc(sizeof(*w));
    if (!w) { wallet_sqlite_close(&ws); sqlite3_close(db); return false; }
    wallet_init(w);
    bool ok = wallet_sqlite_read_sapling_keys(&ws, w);
    *count = w->sapling_keys.num_keys;
    rpc_wallet_set_state(w, NULL, NULL, &ws, NULL, NULL);
    ok = ok && wrs_latest_envelope(out, cap);
    rpc_wallet_set_state(NULL, NULL, NULL, NULL, NULL, NULL);
    wallet_free(w);
    free(w);
    wallet_sqlite_close(&ws);
    sqlite3_close(db);
    return ok;
}

/* Reinsert in reverse order and create a child-index tie in this fixture. */
static bool wrs_reorder_accounts(const char *path)
{
    sqlite3 *db = NULL;
    if (sqlite3_open(path, &db) != SQLITE_OK) {
        if (db) sqlite3_close(db);
        return false;
    }
    bool ok = sqlite3_exec(db,
        "CREATE TEMP TABLE rev AS SELECT * FROM wallet_sapling_keys;"
        "DELETE FROM wallet_sapling_keys;"
        "INSERT INTO wallet_sapling_keys SELECT * FROM rev ORDER BY child_index DESC,ivk DESC;"
        "UPDATE wallet_sapling_keys SET child_index=0 WHERE ivk IN "
        "(SELECT ivk FROM wallet_sapling_keys ORDER BY child_index,ivk LIMIT 2)",
        NULL, NULL, NULL) == SQLITE_OK;
    sqlite3_close(db);
    return ok;
}

static int wrs_address_storage_cases(const char *dir, const char *dbpath, const char *live)
{
    int failures = 0;
    struct zcl_command_reply reply;
    sqlite3 *db = NULL;
    int rc = sqlite3_open(dbpath, &db);
    WRS_CHECK("fixture database opens", rc == SQLITE_OK);
    if (rc == SQLITE_OK) {
        struct node_db sync_node = {.db = db, .open = true};
        WRS_CHECK("unsafe journal fixture", sqlite3_exec(db, "PRAGMA journal_mode=OFF", NULL, NULL, NULL) == SQLITE_OK);
        WRS_CHECK("unsafe journal refuses fence", !wrs_prepare_cutover(db));
        WRS_CHECK("unsafe journal leaves no fence", wrs_status_envelope(dir, "WALLET_LOCKED", live, "clear", false));
        WRS_CHECK("restore journal fixture", sqlite3_exec(db, "PRAGMA journal_mode=WAL", NULL, NULL, NULL) == SQLITE_OK);
        WRS_CHECK("cutover fixture starts OFF", sqlite3_exec(db, "PRAGMA synchronous=OFF", NULL, NULL, NULL) == SQLITE_OK);
        WRS_CHECK("deny FULL setup", sqlite3_set_authorizer(db, wrs_deny_sync_raise, NULL) == SQLITE_OK);
        WRS_CHECK("cutover refuses without FULL", !wrs_prepare_cutover(db));
        WRS_CHECK("deny FULL removed", sqlite3_set_authorizer(db, NULL, NULL) == SQLITE_OK);
        WRS_CHECK("failed FULL leaves no fence", wrs_status_envelope(dir, "WALLET_LOCKED", live, "clear", false));
        WRS_CHECK("cutover raises sync and restores OFF", wrs_prepare_cutover(db) && db_wallet_send_once_sync_level(&sync_node) == 0);
        WRS_CHECK("cutover OFF fixture reset", sqlite3_exec(db,
                  "DELETE FROM node_state WHERE key IN ('wallet_cutover_binding','wallet_scan_incomplete')", NULL, NULL, NULL) == SQLITE_OK);
        WRS_CHECK("cutover restore failure setup", sqlite3_set_authorizer(db, wrs_deny_sync_restore, NULL) == SQLITE_OK);
        WRS_CHECK("cutover restore failure refuses", !wrs_prepare_cutover(db));
        WRS_CHECK("cutover restore authorizer cleared", sqlite3_set_authorizer(db, NULL, NULL) == SQLITE_OK);
        WRS_CHECK("restore failure preserves pending fence", wrs_status_envelope(dir, "WALLET_LOCKED", live, "pending", false));
        WRS_CHECK("cutover restore fixture reset", sqlite3_exec(db,
                  "DELETE FROM node_state WHERE key IN ('wallet_cutover_binding','wallet_scan_incomplete'); PRAGMA synchronous=NORMAL", NULL, NULL, NULL) == SQLITE_OK);
        WRS_CHECK("cutover fixture prepared at NORMAL", wrs_prepare_cutover(db) && db_wallet_send_once_sync_level(&sync_node) == 1);
        WRS_CHECK("locked envelope reports pending cutover",
                  wrs_status_envelope(dir, "WALLET_LOCKED", live, "pending", false));
        WRS_CHECK("cutover malformed fixture", sqlite3_exec(db,
                  "UPDATE node_state SET value=x'00' WHERE key='wallet_cutover_binding'", NULL, NULL, NULL) == SQLITE_OK);
        WRS_CHECK("locked envelope reports malformed as unknown",
                  wrs_status_envelope(dir, "WALLET_LOCKED", live, "unknown", false));
        WRS_CHECK("cutover fixture removed", sqlite3_exec(db,
                  "DELETE FROM node_state WHERE key IN ('wallet_cutover_binding','wallet_scan_incomplete')", NULL, NULL, NULL) == SQLITE_OK);
        rc = sqlite3_exec(db,
            "INSERT INTO wallet_sapling_diversifier(ivk,next_index) "
            "SELECT ivk,0 FROM wallet_sapling_keys ORDER BY child_index,ivk LIMIT 1",
            NULL, NULL, NULL);
        WRS_CHECK("fixture plants an invalid selected counter", rc == SQLITE_OK);
        WRS_CHECK("invalid counter exports only a constant reason",
                  wrs_status_envelope(dir, "WALLET_LOCKED", NULL, "clear", true));
        WRS_CHECK("fixture removes invalid counter",
            sqlite3_exec(db, "DELETE FROM wallet_sapling_diversifier", NULL, NULL, NULL) == SQLITE_OK);
        rc = sqlite3_exec(db,
            "CREATE TEMP TABLE saved AS SELECT * FROM wallet_sapling_keys;"
            "UPDATE wallet_sapling_keys SET child_index=-1 WHERE ivk="
            "(SELECT ivk FROM wallet_sapling_keys ORDER BY child_index DESC,ivk DESC LIMIT 1)",
            NULL, NULL, NULL);
        WRS_CHECK("fixture corrupts later account ordering", rc == SQLITE_OK);
        WRS_CHECK("bad account ordering exports only a constant reason",
                  wrs_status_envelope(dir, "WALLET_LOCKED", NULL, "clear", true));
        rc = sqlite3_exec(db, "DELETE FROM wallet_sapling_keys;"
                              "INSERT INTO wallet_sapling_keys SELECT * FROM saved;"
                              "UPDATE wallet_sapling_keys SET pk_d=zeroblob(32) WHERE ivk="

                              "(SELECT ivk FROM wallet_sapling_keys ORDER BY child_index,ivk LIMIT 1)", NULL, NULL, NULL);
        WRS_CHECK("fixture invalidates public keys", rc == SQLITE_OK);
        wrs_status(dir, &reply);
        WRS_CHECK("mismatched public key is not exposed", !json_get(&reply.data, "persisted_shielded_address"));
        WRS_CHECK("unsafe leading account exports only a constant reason",
                  wrs_status_envelope(dir, "WALLET_LOCKED", NULL, "clear", true));
        zcl_command_reply_free(&reply);
        const char *const damage[] = {
            "CAST(zeroblob(4)||substr(xsk,5) AS BLOB)",
            "CAST(substr(xsk,1,4)||zeroblob(4)||substr(xsk,9) AS BLOB)",
            "CAST(substr(xsk,1,8)||zeroblob(4)||substr(xsk,13) AS BLOB)",
            "zeroblob(0)"
        };
        for (size_t i = 0; i < sizeof(damage) / sizeof(damage[0]); i++) {
            char sql[512];
            snprintf(sql, sizeof(sql), "DELETE FROM wallet_sapling_keys;"
                     "INSERT INTO wallet_sapling_keys SELECT * FROM saved;"
                     "UPDATE wallet_sapling_keys SET xsk=%s", damage[i]);
            rc = sqlite3_exec(db, sql, NULL, NULL, NULL);
            WRS_CHECK("fixture changes xsk envelope field", rc == SQLITE_OK);
            wrs_status(dir, &reply);
            WRS_CHECK("invalid envelope or watch-only row exposes no address",
                      !json_get(&reply.data, "persisted_shielded_address"));
            WRS_CHECK("invalid envelope or watch-only row exports only a reason",
                      wrs_status_envelope(dir, "WALLET_LOCKED", NULL, "clear", true));
            zcl_command_reply_free(&reply);
        }
        rc = sqlite3_exec(db, "DELETE FROM wallet_sapling_keys;"
                              "INSERT INTO wallet_sapling_keys SELECT * FROM saved;"
                              "UPDATE wallet_sapling_keys SET xsk=zeroblob(1)", NULL, NULL, NULL);
        WRS_CHECK("fixture invalidates xsk rows", rc == SQLITE_OK);
        wrs_status(dir, &reply);
        WRS_CHECK("malformed xsk is not exposed", !json_get(&reply.data, "persisted_shielded_address"));
        zcl_command_reply_free(&reply);
        rc = sqlite3_exec(db, "DELETE FROM wallet_sapling_keys", NULL, NULL, NULL);
        WRS_CHECK("fixture removes sapling rows", rc == SQLITE_OK);
        sqlite3_close(db);
        wrs_status(dir, &reply);
        WRS_CHECK("missing row exposes no address", !json_get(&reply.data, "persisted_shielded_address"));
        WRS_CHECK("missing row exports no address facts",
                  wrs_status_envelope(dir, "WALLET_LOCKED", NULL, "clear", false));
        zcl_command_reply_free(&reply);
    } else if (db) sqlite3_close(db);
    return failures;
}

static int t_persisted_receive_address(void)
{
    int failures = 0;
    failures += wrs_cutover_floor();
    char dir[256], pid[300], dbpath[300];
    wrs_mkfixture(dir, sizeof(dir), "receive");
    wrs_set_at_rest("case-receive-passphrase", NULL);
    struct wallet_recovery_report rep;
    struct zcl_result r = wrs_restore(dir, WRS_PHRASE_A, &rep);
    WRS_CHECK("encrypted wallet fixture created", r.ok);
    if (!r.ok) { test_rm_rf(dir); return failures; }
    wrs_set_at_rest(NULL, NULL);
    wallet_lock_reset_for_test();
    struct zcl_command_reply reply;
    wrs_status(dir, &reply);
    WRS_CHECK("missing pidfile does not expose persisted address",
              !json_get(&reply.data, "persisted_shielded_address"));
    WRS_CHECK("missing pidfile exports no address facts",
              wrs_status_envelope(dir, "WALLET_LOCKED", NULL, NULL, false));
    zcl_command_reply_free(&reply);
    snprintf(pid, sizeof(pid), "%s/zclassic23.pid", dir);
    int fd = open(pid, O_CREAT | O_RDWR, 0600);
    WRS_CHECK("pidfile fixture created", fd >= 0);
    if (fd < 0) { test_rm_rf(dir); return failures; }
    int guard_fd = -1;
    struct zcl_result guard = wallet_restore_node_lock_acquire(dir, &guard_fd);
    WRS_CHECK("status guard holds the node lock", guard.ok && guard_fd >= 0);
    WRS_CHECK("a competing node cannot acquire the held guard",
              flock(fd, LOCK_EX | LOCK_NB) != 0);
    wallet_restore_node_lock_release(&guard_fd);
    wrs_status(dir, &reply);
    const char *address = json_get_str(json_get(&reply.data, "persisted_shielded_address"));
    WRS_CHECK("locked wallet exposes its persisted public address", address && address[0]);
    WRS_CHECK("selected address is the first committed address",
              address && !strcmp(address, rep.first_shielded_address));
    char live[160] = "";
    size_t loaded_count = 0;
    snprintf(dbpath, sizeof(dbpath), "%s/node.db", dir);
    bool loaded = wrs_loaded_latest(dbpath, live, sizeof(live), &loaded_count);
    WRS_CHECK("fixture loads multiple persisted Sapling accounts", loaded && loaded_count > 1);
    WRS_CHECK("stopped and live selectors agree before a new address",
              loaded && address && !strcmp(live, address));

    WRS_CHECK("locked wallet remains locked", !strcmp(reply.error.code, "WALLET_LOCKED"));
    WRS_CHECK("locked serialized reply exposes the public address and cutover state",
              wrs_status_envelope(dir, "WALLET_LOCKED", rep.first_shielded_address, "clear", false));
    zcl_command_reply_free(&reply);
    WRS_CHECK("fixture reverses rows and ties two account indices", wrs_reorder_accounts(dbpath));
    wrs_status(dir, &reply);
    address = json_get_str(json_get(&reply.data, "persisted_shielded_address"));
    loaded = wrs_loaded_latest(dbpath, live, sizeof(live), &loaded_count);
    WRS_CHECK("tied accounts choose the same address independent of insertion order",
              loaded && address && !strcmp(live, address));
    zcl_command_reply_free(&reply);
    WRS_CHECK("fixture acquires node lock", flock(fd, LOCK_EX | LOCK_NB) == 0);

    wrs_status(dir, &reply);
    WRS_CHECK("held node lock refuses status", !strcmp(reply.error.code, "DATADIR_LOCKED"));
    WRS_CHECK("held node lock exposes no address", !json_get(&reply.data, "persisted_shielded_address"));
    WRS_CHECK("held node lock exports no address facts",
              wrs_status_envelope(dir, "DATADIR_LOCKED", NULL, NULL, false));
    zcl_command_reply_free(&reply);
    (void)flock(fd, LOCK_UN);
    snprintf(dbpath, sizeof(dbpath), "%s/node.db", dir);
    failures += wrs_address_storage_cases(dir, dbpath, live);
    close(fd);
    wallet_lock_reset_for_test();
    test_rm_rf(dir);
    return failures;
}
#endif

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

static int t_recovery_status_rejects_a_truncated_datadir(void)
{
    int failures = 0;
    char datadir[1025];
    memset(datadir, 'x', sizeof(datadir) - 1);
    datadir[sizeof(datadir) - 1] = '\0';

    struct json_value input;
    json_init(&input);
    json_set_object(&input);
    if (!json_push_kv_str(&input, "datadir", datadir)) {
        WRS_CHECK("the overlong recovery status input is constructed", 0);
        json_free(&input);
        return failures;
    }

    struct zcl_command_request request = { .input = &input };
    struct zcl_command_reply reply;
    zcl_command_reply_init(&reply, "zcl.wallet_recovery_status.v1");
    zcl_native_handle_wallet_recovery_status(&request, &reply);

    WRS_CHECK("recovery status refuses a target it cannot copy exactly",
              reply.exit_code == ZCL_COMMAND_EXIT_INVALID);
    WRS_CHECK("the recovery status overlong target refusal is named",
              strcmp(reply.error.code, "DATADIR_TOO_LONG") == 0);
    WRS_CHECK("the recovery status target refusal reports no mutation",
              !reply.error.mutated);

    zcl_command_reply_free(&reply);
    json_free(&input);
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

static int t_backup_restore_leaf_rejects_a_truncated_datadir(void)
{
    int failures = 0;
    char datadir[1025];
    memset(datadir, 'x', sizeof(datadir) - 1);
    datadir[sizeof(datadir) - 1] = '\0';

    struct json_value input;
    json_init(&input);
    json_set_object(&input);
    (void)json_push_kv_str(&input, "from", "missing-backup.sqlite");
    (void)json_push_kv_str(&input, "datadir", datadir);
    (void)json_push_kv_bool(&input, "confirm", true);

    struct zcl_command_request request = { .input = &input };
    struct zcl_command_reply reply;
    zcl_command_reply_init(&reply, "zcl.wallet_restore.v1");
    zcl_native_handle_wallet_restore(&request, &reply);

    WRS_CHECK("backup restore refuses a target it cannot copy exactly",
              reply.exit_code == ZCL_COMMAND_EXIT_INVALID);
    WRS_CHECK("the backup restore overlong target refusal is named",
              strcmp(reply.error.code, "DATADIR_TOO_LONG") == 0);
    WRS_CHECK("the backup restore target refusal reports no mutation",
              !reply.error.mutated);

    zcl_command_reply_free(&reply);
    json_free(&input);
    return failures;
}

static int t_restore_leaf_rejects_a_truncated_datadir(void)
{
    int failures = 0;
    char datadir[1025];
    memset(datadir, 'x', sizeof(datadir) - 1);
    datadir[sizeof(datadir) - 1] = '\0';

    struct json_value input;
    json_init(&input);
    json_set_object(&input);
    (void)json_push_kv_str(&input, "phrase", WRS_PHRASE_A);
    (void)json_push_kv_str(&input, "datadir", datadir);
    (void)json_push_kv_bool(&input, "confirm", true);

    struct zcl_command_request request = { .input = &input };
    struct zcl_command_reply reply;
    zcl_command_reply_init(&reply, "zcl.wallet_recovery_restore.v1");
    zcl_native_handle_wallet_recovery_restore(&request, &reply);

    WRS_CHECK("restore refuses a datadir that cannot be copied exactly",
              reply.exit_code == ZCL_COMMAND_EXIT_INVALID);
    WRS_CHECK("the overlong datadir refusal is named",
              strcmp(reply.error.code, "DATADIR_TOO_LONG") == 0);
    WRS_CHECK("the overlong datadir refusal reports no mutation",
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

/* Fork one of the two restore children. The child closes the barrier's
 * write end and never returns; the parent only needs the pid back. */
static pid_t wrs_fork_restore_child(int write_fd, int read_fd,
                                    const char *dir, const char *phrase)
{
    pid_t pid = fork();
    if (pid == 0) { close(write_fd); wrs_child_restore(read_fd, dir, phrase); }
    return pid;
}
#endif

/* What deriving the two case-2 phrases produced. */
enum wrs_seed_pair_state {
    WRS_SEED_PAIR_UNUSABLE,   /* a derivation failed; the case cannot run */
    WRS_SEED_PAIR_IDENTICAL,  /* both worked, but they name one wallet */
    WRS_SEED_PAIR_DISTINCT,   /* both worked, and they name two wallets */
};

/* Derive both case-2 seeds, short-circuiting exactly like the check that
 * guards it: phrase B is not derived when phrase A already failed. */
static enum wrs_seed_pair_state wrs_derive_case2_seed_pair(uint8_t *seed_a,
                                                           uint8_t *seed_b)
{
    if (!(mnemonic_to_wallet_seed(WRS_PHRASE_A, NULL, seed_a) &&
          mnemonic_to_wallet_seed(WRS_PHRASE_B, NULL, seed_b)))
        return WRS_SEED_PAIR_UNUSABLE;
    if (memcmp(seed_a, seed_b, 32) == 0)
        return WRS_SEED_PAIR_IDENTICAL;
    return WRS_SEED_PAIR_DISTINCT;
}

/* Case-2 helpers that print WRS_CHECK lines take the caller's running
 * failure count as `failures_out`. WRS_CHECK increments a plain local
 * named `failures`, so each of them keeps one and merges it into
 * `failures_out` on every exit. */

/* Start both restores so they genuinely overlap, wait for both, and say
 * which succeeded. Returns false when the case cannot proceed (the
 * failing checks have already printed); the caller then cleans the
 * fixture up and stops. */
static bool wrs_race_two_concurrent_restores(const char *dir, bool *ok_a,
                                             bool *ok_b, int *failures_out)
{
    int failures = 0;
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
        *failures_out += failures;
        return false;
    }

    /* Release both at once. */
    FILE *gof = fopen(go_path, "w");
    if (gof) fclose(gof);
    WRS_CHECK("both processes were released together", gof != NULL);

    int sa = test_self_child_wait(ha);
    int sb = test_self_child_wait(hb);
    _putenv_s("ZCL_WRS_DIR", "");
    _putenv_s("ZCL_WRS_GO", "");
    *ok_a = (sa == 0);
    *ok_b = (sb == 0);
    *failures_out += failures;
    return true;
#else
    int barrier[2];
    if (pipe(barrier) != 0) {
        WRS_CHECK("barrier pipe created", false);
        *failures_out += failures;
        return false;
    }

    fflush(stdout);
    fflush(stderr);
    pid_t pa = wrs_fork_restore_child(barrier[1], barrier[0], dir,
                                      WRS_PHRASE_A);
    pid_t pb = wrs_fork_restore_child(barrier[1], barrier[0], dir,
                                      WRS_PHRASE_B);
    close(barrier[0]);

    bool forked = pa > 0 && pb > 0;
    WRS_CHECK("two concurrent recovery processes started", forked);
    if (!forked) {
        close(barrier[1]);
        if (pa > 0) waitpid(pa, NULL, 0);
        if (pb > 0) waitpid(pb, NULL, 0);
        *failures_out += failures;
        return false;
    }

    /* Release both at once. */
    ssize_t released = write(barrier[1], "gg", 2);
    close(barrier[1]);
    WRS_CHECK("both processes were released together", released == 2);

    int sa = -1, sb = -1;
    waitpid(pa, &sa, 0);
    waitpid(pb, &sb, 0);
    *ok_a = WIFEXITED(sa) && WEXITSTATUS(sa) == 0;
    *ok_b = WIFEXITED(sb) && WEXITSTATUS(sb) == 0;
    *failures_out += failures;
    return true;
#endif
}

/* Open the node.db the winning restore left in the fixture. */
static bool wrs_open_result_node_db(struct node_db *ndb, const char *path)
{
    return node_db_open(ndb, path) && ndb->open;
}

/* Read the wallet's keys back and ask, by derivation, which seed governs
 * them. */
static void wrs_report_keys_descend_from_one_seed(struct wallet_sqlite *ws,
                                                  const uint8_t *seed_a,
                                                  const uint8_t *seed_b,
                                                  bool is_a, bool is_b,
                                                  int *failures_out)
{
    int failures = 0;
    /* The defect's fingerprint was keys from BOTH seeds under a
     * single seed row. Ask by derivation, exactly as boot does. */
    struct wallet *w = calloc(1, sizeof(*w));
    if (w) {
        wallet_init(w);
        struct zcl_result kr = wallet_sqlite_read_keys_r(ws, w);
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
    *failures_out += failures;
}

/* Unlock the wallet the race left behind and prove the datadir holds ONE
 * wallet: one readable seed row, and keys descended from that seed
 * alone. */
static void wrs_verify_datadir_holds_one_seed_wallet(struct node_db *ndb,
                                                     const uint8_t *seed_a,
                                                     const uint8_t *seed_b,
                                                     int *failures_out)
{
    int failures = 0;
    wallet_lock_reset_for_test();
    struct zcl_result ur = wallet_lock_unlock(
        NULL, NULL, "case2-passphrase");
    WRS_CHECK("the restored wallet explicitly unlocks for inspection",
              ur.ok);
    struct wallet_sqlite ws;
    struct zcl_result wr = wallet_sqlite_open_r(&ws, ndb->db);
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
        wrs_report_keys_descend_from_one_seed(&ws, seed_a, seed_b,
                                              is_a, is_b, &failures);
        memory_cleanse(on_disk, sizeof(on_disk));
        wallet_sqlite_close(&ws);
    }
    *failures_out += failures;
}

static int t_two_concurrent_restores_leave_one_wallet(void)
{
    int failures = 0;
    char dir[256];
    wrs_mkfixture(dir, sizeof(dir), "concurrent");

    /* Anti-vacuous: the whole case rests on the two phrases naming two
     * different wallets. */
    uint8_t seed_a[32], seed_b[32];
    enum wrs_seed_pair_state seeds =
        wrs_derive_case2_seed_pair(seed_a, seed_b);
    WRS_CHECK("the two test phrases derive two DIFFERENT seeds",
              seeds == WRS_SEED_PAIR_DISTINCT);
    if (seeds == WRS_SEED_PAIR_UNUSABLE) { test_rm_rf(dir); return failures; }

    bool ok_a = false, ok_b = false;
    if (!wrs_race_two_concurrent_restores(dir, &ok_a, &ok_b, &failures)) {
        test_rm_rf(dir);
        return failures;
    }
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
    bool opened = wrs_open_result_node_db(&ndb, db_path);
    WRS_CHECK("the resulting node.db opens", opened);
    if (opened) {
        wrs_verify_datadir_holds_one_seed_wallet(&ndb, seed_a, seed_b,
                                                 &failures);
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

/* ── the reply carries encrypted_at_rest exactly once, truthfully ───── */

static int wrs_count_substr(const char *hay, const char *needle)
{
    int n = 0;
    for (const char *p = strstr(hay, needle); p; p = strstr(p + 1, needle))
        n++;
    return n;
}

/* Run the restore leaf on a fixture and return the reply data as text. */
static bool wrs_leaf_reply_text(const char *dir, bool confirm, char *out,
                                size_t n, bool *refused)
{
    struct json_value input;
    json_init(&input);
    json_set_object(&input);
    (void)json_push_kv_str(&input, "phrase", WRS_PHRASE_A);
    (void)json_push_kv_str(&input, "datadir", dir);
    (void)json_push_kv_bool(&input, "confirm", confirm);
    struct zcl_command_request request = { .input = &input };
    struct zcl_command_reply reply;
    zcl_command_reply_init(&reply, "zcl.wallet_recovery_restore.v1");
    zcl_native_handle_wallet_recovery_restore(&request, &reply);
    *refused = reply.exit_code != 0;
    bool ok = json_write(&reply.data, out, n) != 0;
    zcl_command_reply_free(&reply);
    json_free(&input);
    return ok;
}

static int t_reply_reports_encrypted_at_rest_once(void)
{
    int failures = 0;
    char dir[512], text[16384];
    bool refused = false;

    printf("  encrypted_at_rest appears once and tells the truth\n");

    /* (a) commit, policy variable only: the service encrypts. */
    wrs_mkfixture(dir, sizeof(dir), "reply_commit");
    wrs_set_at_rest("correct horse battery staple", NULL);
    wallet_lock_reset_for_test();
    bool got = wrs_leaf_reply_text(dir, true, text, sizeof(text), &refused);
    WRS_CHECK("commit reply was produced and not refused", got && !refused);
    WRS_CHECK("commit reply names encrypted_at_rest exactly once",
              wrs_count_substr(text, "\"encrypted_at_rest\"") == 1);
    WRS_CHECK("and it is true for the encrypted wallet",
              strstr(text, "\"encrypted_at_rest\":true") != NULL);
    wallet_lock_reset_for_test();

    /* (b) plan, no passphrase and no policy: a commit would refuse. */
    wrs_mkfixture(dir, sizeof(dir), "reply_plan");
    wrs_set_at_rest(NULL, NULL);
    got = wrs_leaf_reply_text(dir, false, text, sizeof(text), &refused);
    WRS_CHECK("plan reply was produced", got && !refused);
    WRS_CHECK("plan reply names encrypted_at_rest exactly once",
              wrs_count_substr(text, "\"encrypted_at_rest\"") == 1);
    WRS_CHECK("and it is false: a commit would not encrypt",
              strstr(text, "\"encrypted_at_rest\":false") != NULL);
    WRS_CHECK("and the plan says the commit would refuse",
              strstr(text, "WALLET_AT_REST_UNDECIDED") != NULL);

    wrs_set_at_rest(NULL, NULL);
    return failures;
}

/* ── case 4: an existing node.db is read in full at most once ──────── */

/* Every connection opened while the hook is armed traces its statements
 * here (sqlite3_auto_extension runs on each open), so the count covers the
 * read-only inspection and the write open alike. */
static int g_wrs_full_checks;

static int wrs_trace_stmt(unsigned type, void *ctx, void *stmt, void *sql)
{
    (void)type;
    (void)ctx;
    (void)stmt;
    if (sql && strncmp((const char *)sql, "PRAGMA quick_check", 18) == 0)
        g_wrs_full_checks++;
    return 0;
}

static int wrs_trace_open(sqlite3 *db, char **err,
                          const sqlite3_api_routines *api)
{
    (void)err;
    (void)api;
    return sqlite3_trace_v2(db, SQLITE_TRACE_STMT, wrs_trace_stmt, NULL);
}

/* One recovery of phrase A into `dir`; returns the quick_checks it ran. */
static int wrs_counted_run(const char *dir, bool dry_run,
                           struct wallet_recovery_report *rep,
                           struct zcl_result *r)
{
    struct wallet_recovery_request req = {
        .phrase = WRS_PHRASE_A, .datadir = dir, .dry_run = dry_run,
    };
    void (*hook)(void) = (void (*)(void))wrs_trace_open;
    g_wrs_full_checks = 0;
    if (sqlite3_auto_extension(hook) != SQLITE_OK)
        return -1;
    *r = wallet_recovery_run(&req, rep);
    sqlite3_cancel_auto_extension(hook);
    printf("    %s %s: ok=%d code=%d full_checks=%d\n",
           dry_run ? "plan" : "commit", dir, (int)r->ok, r->code,
           g_wrs_full_checks);
    return g_wrs_full_checks;
}

/* A datadir holding a node.db the node created and closed cleanly. */
struct wrs_node_db {
    char dir[256];
    char db_path[1200];
    long page_size;
    int roots[8];
    int nroots;
};

/* Root pages of the schema object `name` (a table with its indexes, or one
 * index alone), and the page size. */
static bool wrs_object_roots(sqlite3 *db, const char *name,
                             struct wrs_node_db *fx)
{
    sqlite3_stmt *s = NULL;
    if (sqlite3_prepare_v2(db, "SELECT rootpage FROM sqlite_master "
                           "WHERE (name=?1 OR tbl_name=?1) AND rootpage>1",
                           -1, &s, NULL) != SQLITE_OK)
        return false;
    sqlite3_bind_text(s, 1, name, -1, SQLITE_STATIC);
    while (fx->nroots < 8 && sqlite3_step(s) == SQLITE_ROW)
        fx->roots[fx->nroots++] = sqlite3_column_int(s, 0);
    sqlite3_finalize(s);
    if (sqlite3_prepare_v2(db, "PRAGMA page_size", -1, &s, NULL) != SQLITE_OK)
        return false;
    if (sqlite3_step(s) == SQLITE_ROW)
        fx->page_size = (long)sqlite3_column_int64(s, 0);
    sqlite3_finalize(s);
    return fx->nroots > 0 && fx->page_size > 0;
}

/* Create the node.db (no -wal is left once it closes), note the root pages
 * of `object` when one is named, and with `bound` write the clean-shutdown
 * marker the node writes last. */
static bool wrs_mk_node_db(struct wrs_node_db *fx, const char *tag,
                           const char *object, bool bound)
{
    memset(fx, 0, sizeof(*fx));
    wrs_mkfixture(fx->dir, sizeof(fx->dir), tag);
    snprintf(fx->db_path, sizeof(fx->db_path), "%s/node.db", fx->dir);
    struct node_db ndb;
    memset(&ndb, 0, sizeof(ndb));
    if (!node_db_open(&ndb, fx->db_path))
        return false;
    bool roots = !object || wrs_object_roots(ndb.db, object, fx);
    node_db_close(&ndb);
    return roots && (!bound || boot_shutdown_marker_write_clean(fx->dir));
}

/* Overwrite the noted root pages in place with bytes no b-tree page starts
 * with. Size and header stay put, so a shutdown binding still matches. */
static bool wrs_damage_roots(const struct wrs_node_db *fx)
{
    static unsigned char junk[65536];
    if (fx->page_size <= 0 || fx->page_size > (long)sizeof(junk))
        return false;
    memset(junk, 0xA5, sizeof(junk));
    FILE *f = fopen(fx->db_path, "r+b");
    bool ok = f != NULL;
    for (int i = 0; ok && i < fx->nroots; i++)
        ok = fseek(f, (long)(fx->roots[i] - 1) * fx->page_size,
                   SEEK_SET) == 0 &&
             fwrite(junk, 1, (size_t)fx->page_size, f) ==
                 (size_t)fx->page_size;
    if (f && fclose(f) != 0)
        ok = false;
    return ok;
}

/* One committed write that moves node.db's header identity. */
static bool wrs_touch_node_db(const char *db_path)
{
    sqlite3 *db = NULL;
    bool ok = sqlite3_open_v2(db_path, &db, SQLITE_OPEN_READWRITE,
                              NULL) == SQLITE_OK &&
              sqlite3_exec(db, "CREATE TABLE wrs_touch(x)", NULL, NULL,
                           NULL) == SQLITE_OK;
    sqlite3_close(db);
    return ok;
}

/* The next boot's decision for this datadir: deferred, never verified. */
static bool wrs_next_boot_defers(const struct wrs_node_db *fx)
{
    boot_shutdown_marker_reset_for_test();
    (void)boot_shutdown_marker_detect_unclean(fx->dir);
    bool skip = boot_shutdown_marker_quick_check_probe(fx->db_path);
    bool deferred = skip && boot_shutdown_marker_quick_check_was_deferred() &&
                    !boot_shutdown_marker_quick_check_was_skipped();
    boot_shutdown_marker_reset_for_test();
    return deferred;
}

static int t_verified_clean_binding_skips_every_full_check(void)
{
    int failures = 0;
    struct wrs_node_db fx;
    struct wallet_recovery_report rep;
    struct zcl_result r;
    bool made = wrs_mk_node_db(&fx, "clean_binding", NULL, true);
    WRS_CHECK("fixture: a cleanly shut down node.db and its binding", made);
    char marker[1300];
    snprintf(marker, sizeof(marker), "%s/.shutdown_clean", fx.dir);
    int64_t size_before = -1, size_after = -1;
    uint64_t hash_before = wrs_file_hash(marker, &size_before);

    int plan = made ? wrs_counted_run(fx.dir, true, &rep, &r) : -1;
    WRS_CHECK("a plan holds no lock, so it still checks once", plan == 1);
    int checks = made ? wrs_counted_run(fx.dir, false, &rep, &r) : -1;
    WRS_CHECK("the commit succeeds", checks >= 0 && r.ok &&
              rep.seed_installed);
    WRS_CHECK("and reads node.db in full ZERO times", checks == 0);
    uint64_t hash_after = wrs_file_hash(marker, &size_after);
    WRS_CHECK("the marker is left byte-for-byte for the next boot",
              hash_before != 0 && hash_after == hash_before &&
              size_after == size_before);
    /* The wallet's write moved node.db's identity, so the next boot runs
     * its existing fail-closed background check instead of a skip. */
    WRS_CHECK("the next boot defers its check to the background",
              made && wrs_next_boot_defers(&fx));
    test_rm_rf(fx.dir);
    return failures;
}

static int t_unbound_node_db_is_checked_exactly_once(void)
{
    int failures = 0;
    struct wrs_node_db fx;
    struct wallet_recovery_report rep;
    struct zcl_result r;

    bool made = wrs_mk_node_db(&fx, "no_binding", NULL, false);
    int checks = made ? wrs_counted_run(fx.dir, false, &rep, &r) : -1;
    WRS_CHECK("no binding: the commit succeeds", checks >= 0 && r.ok);
    WRS_CHECK("no binding: node.db is read in full exactly once",
              checks == 1);
    test_rm_rf(fx.dir);

    /* A binding for an earlier identity of the file is no binding. */
    made = wrs_mk_node_db(&fx, "stale_binding", NULL, true) &&
           wrs_touch_node_db(fx.db_path);
    checks = made ? wrs_counted_run(fx.dir, false, &rep, &r) : -1;
    WRS_CHECK("stale binding: the commit succeeds", checks >= 0 && r.ok);
    WRS_CHECK("stale binding: node.db is read in full exactly once",
              checks == 1);
    test_rm_rf(fx.dir);

    /* An empty datadir: the boot open creates node.db, as before. */
    wrs_mkfixture(fx.dir, sizeof(fx.dir), "empty_target");
    checks = wrs_counted_run(fx.dir, false, &rep, &r);
    WRS_CHECK("empty datadir: created and checked once by the boot open",
              r.ok && rep.target_created && checks == 1);
    test_rm_rf(fx.dir);
    return failures;
}

/* Refused, unchanged, nothing renamed: the damaged-target promise. */
static void wrs_check_untouched(const struct wrs_node_db *fx,
                                uint64_t hash_before, int64_t size_before,
                                const struct wallet_recovery_report *rep,
                                int *failures_io)
{
    int failures = 0;
    int64_t size_after = -1;
    uint64_t hash_after = wrs_file_hash(fx->db_path, &size_after);
    wrs_list_dir("after", fx->dir);
    WRS_CHECK("damaged: no key was installed", !rep->seed_installed);
    WRS_CHECK("damaged: node.db is still there, byte-for-byte",
              hash_after != 0 && hash_after == hash_before &&
              size_after == size_before);
    WRS_CHECK("damaged: nothing was quarantined to node.db.corrupt-*",
              wrs_count_entries(fx->dir, "node.db.corrupt-") == 0);
    *failures_io += failures;
}

/* No binding, `object`'s pages damaged: refused once, as damaged. */
static int wrs_unbound_damage_is_refused(const char *tag, const char *object)
{
    int failures = 0;
    struct wrs_node_db fx;
    struct wallet_recovery_report rep;
    struct zcl_result r;
    bool made = wrs_mk_node_db(&fx, tag, object, false) &&
                wrs_damage_roots(&fx);
    printf("    damaged object: %s\n", object);
    WRS_CHECK("fixture: a node.db with damaged pages, no binding", made);
    int64_t size_before = -1;
    uint64_t hash_before = wrs_file_hash(fx.db_path, &size_before);
    int checks = made ? wrs_counted_run(fx.dir, false, &rep, &r) : -1;
    WRS_CHECK("damaged, no binding: REFUSED as damaged (-66)",
              checks >= 0 && !r.ok && r.code == -66);
    WRS_CHECK("damaged, no binding: checked exactly once", checks == 1);
    wrs_check_untouched(&fx, hash_before, size_before, &rep, &failures);
    test_rm_rf(fx.dir);
    return failures;
}

static int t_damaged_sqlite_node_db_is_refused_not_reset(void)
{
    int failures = 0;
    struct wrs_node_db fx;
    struct wallet_recovery_report rep;
    struct zcl_result r;

    /* Opens fine, fails its integrity check. A damaged table also fails
     * the row scan quick_check runs after its b-tree walk, so the statement
     * itself errors; a damaged index is reported only as a result row, so
     * the read-only check must read quick_check's answer, not only
     * sqlite3_exec's return code. */
    failures += wrs_unbound_damage_is_refused("damaged_table",
                                              "view_integrity");
    failures += wrs_unbound_damage_is_refused("damaged_index",
                                              "idx_js_height");

    /* A binding the file still matches, over the node_state pages every
     * write open reads first: no check runs, and the write open must fail
     * rather than rename the file aside and start an empty one. */
    bool made = wrs_mk_node_db(&fx, "damaged_bound", "node_state", true) &&
                wrs_damage_roots(&fx);
    WRS_CHECK("fixture: a bound node.db with damaged pages", made);
    int64_t size_before = -1;
    uint64_t hash_before = wrs_file_hash(fx.db_path, &size_before);
    int checks = made ? wrs_counted_run(fx.dir, false, &rep, &r) : -1;
    WRS_CHECK("damaged, bound: the run does not succeed",
              checks >= 0 && !r.ok);
    wrs_check_untouched(&fx, hash_before, size_before, &rep, &failures);
    test_rm_rf(fx.dir);
    return failures;
}

#if !defined(_WIN32)
/* A node that started after the run's peek, reduced to the part that
 * refuses the run: node.db's owner lease, held in another process until
 * `release_fd` reaches end of file. Writes 1 to `ready_fd` once it holds
 * the lease, 0 when it could not take it. Never returns. */
static void wrs_child_hold_lease(const char *db_path, int ready_fd,
                                 int release_fd)
{
    struct node_db ndb;
    memset(&ndb, 0, sizeof(ndb));
    ndb.lifetime_owner_lease_slot = -1;
    snprintf(ndb.path, sizeof(ndb.path), "%s", db_path);
    char held = node_db_owner_lease_acquire(&ndb, false) ? 1 : 0;
    bool told = write(ready_fd, &held, 1) == 1;
    close(ready_fd);
    char go = 0;
    while (told && held && read(release_fd, &go, 1) < 0)
        ;
    close(release_fd);
    if (held)
        node_db_owner_lease_release(&ndb);
    _exit(told && held ? 0 : 1);
}

/* With the lease held by a child, commit phrase A into fx; returns the
 * quick_checks the run started, -1 when the child never held the lease.
 * The child is released and reaped before this returns. */
static int wrs_commit_under_held_lease(const struct wrs_node_db *fx,
                                       struct wallet_recovery_report *rep,
                                       struct zcl_result *r, bool *reaped)
{
    int ready[2] = { -1, -1 }, release[2] = { -1, -1 };
    *reaped = false;
    if (pipe(ready) != 0)
        return -1;
    if (pipe(release) != 0) {
        close(ready[0]);
        close(ready[1]);
        return -1;
    }
    pid_t pid = fork();
    if (pid == 0) {
        close(ready[0]);
        close(release[1]);
        wrs_child_hold_lease(fx->db_path, ready[1], release[0]);
    }
    close(ready[1]);
    close(release[0]);
    char held = 0;
    bool holding = pid > 0 && read(ready[0], &held, 1) == 1 && held == 1;
    int checks = holding ? wrs_counted_run(fx->dir, false, rep, r) : -1;
    close(release[1]);
    close(ready[0]);
    int status = 0;
    *reaped = pid > 0 && waitpid(pid, &status, 0) == pid &&
              WIFEXITED(status) && WEXITSTATUS(status) == 0;
    return checks;
}

/* The binding matched at the peek and no check ran; a node that took
 * node.db afterwards still keeps the run from writing. */
static int t_node_lease_refuses_a_bound_commit(void)
{
    int failures = 0;
    struct wrs_node_db fx;
    struct wallet_recovery_report rep;
    struct zcl_result r;
    memset(&rep, 0, sizeof(rep));
    memset(&r, 0, sizeof(r));
    bool made = wrs_mk_node_db(&fx, "lease_held", NULL, true);
    char marker[1300];
    snprintf(marker, sizeof(marker), "%s/.shutdown_clean", fx.dir);
    int64_t db_size = -1, mk_size = -1, db_after = -1, mk_after = -1;
    uint64_t db_hash = wrs_file_hash(fx.db_path, &db_size);
    uint64_t mk_hash = wrs_file_hash(marker, &mk_size);
    bool reaped = false;
    int checks = made ? wrs_commit_under_held_lease(&fx, &rep, &r, &reaped)
                      : -1;
    WRS_CHECK("lease held: another process held node.db's owner lease",
              checks >= 0);
    WRS_CHECK("lease held: the binding matched, so no full check ran",
              checks == 0);
    WRS_CHECK("lease held: the write open is refused (-63)",
              checks >= 0 && !r.ok && r.code == -63 && !rep.seed_installed);
    WRS_CHECK("lease held: node.db and the marker are byte-for-byte as they "
              "were, nothing quarantined",
              db_hash != 0 && wrs_file_hash(fx.db_path, &db_after) == db_hash &&
              db_after == db_size && mk_hash != 0 &&
              wrs_file_hash(marker, &mk_after) == mk_hash &&
              mk_after == mk_size &&
              wrs_count_entries(fx.dir, "node.db.corrupt-") == 0);
    WRS_CHECK("lease held: the holder released it and exited cleanly", reaped);
    test_rm_rf(fx.dir);
    return failures;
}
#endif

#if !defined(_WIN32)
/* Environment and boot context are changed only in the child. */
static bool wrs_default_datadir_child(void)
{
    char out[256];
    rpc_agent_set_boot_context(NULL, NULL, NULL, 0, 0, 0, 0);
    if (unsetenv("HOME") != 0) return false;
    wnh_default_datadir(out, sizeof(out));
    if (strcmp(out, "./.zclassic-c23") != 0 || setenv("HOME", "", 1) != 0) return false;
    wnh_default_datadir(out, sizeof(out));
    if (strcmp(out, "./.zclassic-c23") != 0 || setenv("HOME", "/fixture-home", 1) != 0) return false;
    wnh_default_datadir(out, sizeof(out));
    if (strcmp(out, "/fixture-home/.zclassic-c23") != 0) return false;
    rpc_agent_set_boot_context(NULL, NULL, "/fixture-runtime", 0, 0, 0, 0);
    wnh_default_datadir(out, sizeof(out));
    return strcmp(out, "/fixture-runtime") == 0;
}

static int t_wallet_default_datadir(void)
{
    int failures = 0, status = 0;
    fflush(NULL);
    pid_t child = fork();
    if (child == 0) _exit(wrs_default_datadir_child() ? 0 : 1);
    WRS_CHECK("offline default datadir respects context and HOME", child > 0 &&
        waitpid(child, &status, 0) == child && WIFEXITED(status) && WEXITSTATUS(status) == 0);
    return failures;
}
#endif


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
            platform_sleep_ms(2); /* real-clock: pre-existing bounded poll loop, seeded when check_no_real_clock_test_deadline.sh was introduced */
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

#if !defined(_WIN32)
    failures += t_wallet_default_datadir();
#endif
    failures += t_damaged_db_is_refused_not_reset();
    failures += t_recovery_status_rejects_a_truncated_datadir();
#if !defined(_WIN32)
    failures += t_persisted_receive_address();
#endif
    failures += t_restore_leaf_requires_an_explicit_datadir();
    failures += t_backup_restore_leaf_rejects_a_truncated_datadir();
    failures += t_restore_leaf_rejects_a_truncated_datadir();
    failures += t_two_concurrent_restores_leave_one_wallet();
    failures += t_at_rest_policy_is_obeyed();
    failures += t_reply_reports_encrypted_at_rest_once();

    wrs_set_at_rest(NULL, "1");
    failures += t_verified_clean_binding_skips_every_full_check();
    failures += t_unbound_node_db_is_checked_exactly_once();
    failures += t_damaged_sqlite_node_db_is_refused_not_reset();
#if !defined(_WIN32)
    failures += t_node_lease_refuses_a_bound_commit();
#endif
    wrs_set_at_rest(NULL, NULL);

    wallet_lock_reset_for_test();
    unsetenv("ZCL_WALLET_KDF_ITERS");
    return failures;
}
