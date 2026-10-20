/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Proves that local machine pairing is explicit, Noise-bound, narrowly
 * scoped, expiring, and durably revoked. */

#include "test/test_core.h"

#include "config/boot_mesh_pairing.h"
#include "config/boot_internal.h"
#include "chain/chainparams.h"
#include "config/boot_mesh_status.h"
#include "config/boot_mesh_machines.h"
#include "base/cleanse.h"
#include "base/safe_alloc.h"
#include "base/hex.h"
#include "command/native_command.h"
#include "config/command_catalog.h"
#include "crypto/ed25519.h"
#include "json/json.h"
#include "kernel/command_registry.h"
#include "models/mesh_machine_observation.h"
#include "models/mesh_pairing.h"
#include "models/zid_identity.h"
#include "net/v2_identity.h"
#include "platform/time_compat.h"
#include "services/mesh_pairing_service.h"
#include "validation/main_constants.h"
#include "vcs/zcode_dht_delegation.h"

#include <stdio.h>
#include <limits.h>
#include <string.h>

static void mesh_fill32(uint8_t out[32], uint8_t value)
{
    memset(out, value, 32);
}

/* raw-sql-ok:test-fixture -- creates only the connected chain rows required
 * to exercise the production chain-bound pairing verifier. */
static bool mesh_seed_block(struct node_db *ndb, int height,
                            const uint8_t hash[32])
{
    sqlite3_stmt *st = NULL;
    static const char sql[] =
        "INSERT INTO blocks(hash,height,prev_hash,version,merkle_root,time,"
        "bits,nonce,solution,chain_work,status,num_tx) "
        "VALUES(?,?,zeroblob(32),4,zeroblob(32),1,1,zeroblob(32),"
        "X'00',zeroblob(32),3,0)";
    if (sqlite3_prepare_v2(ndb->db, sql, -1, &st, NULL) != SQLITE_OK)
        return false;
    sqlite3_bind_blob(st, 1, hash, 32, SQLITE_STATIC);
    sqlite3_bind_int(st, 2, height);
    bool ok = sqlite3_step(st) == SQLITE_DONE;
    sqlite3_finalize(st);
    return ok;
}

static bool mesh_fixture(struct node_db *ndb, const char *path,
                         struct vcs_zcode_dht_delegation *delegation,
                         uint8_t fingerprint[32], uint8_t out_genesis[32])
{
    if (!node_db_open(ndb, path))
        return false;
    uint8_t genesis[32], beacon[32], tip[32], online[32], noise[32], seed[32];
    mesh_fill32(genesis, 0x11);
    mesh_fill32(beacon, 0x22);
    mesh_fill32(tip, 0x33);
    mesh_fill32(online, 0x44);
    mesh_fill32(noise, 0x55);
    mesh_fill32(seed, 0x66);
    if (!mesh_seed_block(ndb, ZCL_FINALITY_DEPTH, beacon) ||
        !mesh_seed_block(ndb, 2 * ZCL_FINALITY_DEPTH, tip) ||
        vcs_zcode_dht_delegation_sign(
            delegation, genesis, online, noise, ZCL_FINALITY_DEPTH, beacon,
            1000, 4000, 7, seed) != VCS_ZCODE_DHT_DELEGATION_OK ||
        !v2_identity_public_fingerprint(noise, fingerprint))
        return false;
    struct zid_identity identity = {0};
    memcpy(identity.master_pubkey, delegation->doc.master_pubkey, 32);
    mesh_fill32(identity.anchor_txid, 0x77);
    identity.anchor_height = 0;
    identity.updated_height = 0;
    snprintf(identity.status, sizeof(identity.status), "%s",
             ZID_IDENTITY_STATUS_ACTIVE);
    snprintf(identity.source, sizeof(identity.source), "%s",
             ZID_IDENTITY_SOURCE_ZID_OVERLAY);
    /* No genesis row is seeded: a locally-mining node never persists one,
     * and the authority must bind the caller-supplied genesis instead. */
    memcpy(out_genesis, genesis, 32);
    return db_zid_identity_save(ndb, &identity);
}

static bool mesh_observation_fixture(
    const struct db_mesh_pairing *pairing, int64_t observed_unix,
    const char *capsule, struct db_mesh_machine_observation *out)
{
    if (!pairing || !capsule || !out || observed_unix <= 0)
        return false;
    struct mesh_status_receipt_v1 receipt = {0};
    receipt.version = MESH_STATUS_PROTO_VERSION;
    receipt.flags = MESH_STATUS_PROTO_FLAGS_NONE;
    receipt.status = MESH_STATUS_RECEIPT_OK;
    mesh_fill32(receipt.request_id, 0xa1);
    mesh_fill32(receipt.request_root, 0xa2);
    memcpy(receipt.network_genesis, pairing->network_genesis, 32);
    if (!zcl_hex_decode_lower(pairing->pairing_id, receipt.pairing_id, 32))
        return false;
    memcpy(receipt.responder_master_pubkey, pairing->peer_master_pubkey, 32);
    memcpy(receipt.responder_noise_static, pairing->peer_noise_pubkey, 32);
    uint8_t online_seed[32], secret[32];
    mesh_fill32(online_seed, 0xb1);
    ed25519_keypair(receipt.responder_online_pubkey, secret, online_seed);
    memory_cleanse(secret, sizeof(secret));
    mesh_fill32(receipt.transcript_hash, 0xa3);
    receipt.connection_generation = 1;
    receipt.revocation_generation = 0;
    receipt.observed_unix = (uint64_t)observed_unix;
    receipt.expires_unix = (uint64_t)observed_unix + 30;
    receipt.capsule_len = (uint16_t)strlen(capsule);
    memcpy(receipt.capsule, capsule, receipt.capsule_len);
    if (mesh_status_capsule_v1_root(receipt.capsule, receipt.capsule_len,
                                    receipt.capsule_root) !=
            MESH_STATUS_PROTO_OK ||
        mesh_status_receipt_v1_sign(&receipt, online_seed) !=
            MESH_STATUS_PROTO_OK)
        return false;
    memset(out, 0, sizeof(*out));
    memcpy(out->pairing_id, pairing->pairing_id, sizeof(out->pairing_id));
    if (mesh_status_receipt_v1_encode(
            &receipt, out->receipt_wire, sizeof(out->receipt_wire),
            &out->receipt_len) != MESH_STATUS_PROTO_OK ||
        mesh_status_receipt_v1_root(&receipt, out->receipt_root) !=
            MESH_STATUS_PROTO_OK)
        return false;
    out->status = receipt.status;
    out->observed_unix = observed_unix;
    out->expires_unix = observed_unix + 30;
    out->received_unix = observed_unix + 1;
    return true;
}

/* ops.mesh.roster's page is ROSTER_ROW_MAX in native_fleet_roster.c. One
 * extra paired machine is what makes the second page exist. */
enum { ROSTER_PAGE = 32, ROSTER_MACHINES = ROSTER_PAGE + 1 };

static const char *roster_row_id(const struct zcl_command_reply *reply,
                                 size_t index)
{
    const struct json_value *rows = json_get(&reply->data, "rows");
    const struct json_value *row = rows ? json_at(rows, index) : NULL;
    const struct json_value *id = row ? json_get(row, "pairing_id") : NULL;
    const char *text = id ? json_get_str(id) : NULL;
    return text ? text : "";
}

static bool roster_call(struct zcl_command_reply *reply, const char *dir,
                        bool with_after, int64_t after)
{
    struct json_value input;
    struct zcl_command_request request;
    char why[192];
    bool ok = false;
    why[0] = '\0';
    json_init(&input);
    json_set_object(&input);
    memset(&request, 0, sizeof(request));
    request.input = &input;
    request.spec = zcl_command_registry_find(zcl_command_catalog(),
                                             "ops.mesh.roster", NULL);
    zcl_command_reply_init(reply, "zcl.fleet_roster.v1");
    if (!json_push_kv_str(&input, "datadir", dir) ||
        (with_after && !json_push_kv_int(&input, "after", after)) ||
        !request.spec ||
        !zcl_command_registry_input_validate(request.spec, &input, why,
                                            sizeof(why))) {
        printf("[roster input %s] ", why[0] ? why : "rejected");
    } else {
        zcl_native_handle_fleet_roster(&request, reply);
        ok = reply->status == ZCL_COMMAND_STATUS_PASSED;
        if (!ok)
            printf("[roster %s] ", reply->error.code);
    }
    json_free(&input);
    return ok;
}

static int test_mesh_roster_page(void)
{
    int failures = 0;
    struct node_db ndb = {0};
    struct zcl_command_reply page1, page2, past;
    memset(&page1, 0, sizeof(page1));
    memset(&page2, 0, sizeof(page2));
    memset(&past, 0, sizeof(past));
    TEST("ops.mesh.roster: a fleet past the page cap resumes without "
         "repeating a pairing") {
        char dir[256], path[320];
        struct vcs_zcode_dht_delegation delegation;
        uint8_t genesis[32], beacon[32], tip[32], online[32];
        char ids[ROSTER_MACHINES][MESH_PAIRING_ID_HEX + 1];
        int64_t wall = platform_time_wall_unix();
        test_make_tmpdir(dir, sizeof(dir), "mesh_pairing", "roster-page");
        snprintf(path, sizeof(path), "%s/node.db", dir);
        ASSERT(node_db_open(&ndb, path));
        mesh_fill32(genesis, 0x11);
        mesh_fill32(beacon, 0x22);
        mesh_fill32(tip, 0x33);
        mesh_fill32(online, 0x44);
        ASSERT(mesh_seed_block(&ndb, ZCL_FINALITY_DEPTH, beacon));
        ASSERT(mesh_seed_block(&ndb, 2 * ZCL_FINALITY_DEPTH, tip));
        for (int i = 0; i < ROSTER_MACHINES; i++) {
            uint8_t seed[32], noise[32], fingerprint[32];
            struct zid_identity identity = {0};
            struct db_mesh_pairing row;
            enum mesh_pairing_reason reason;
            mesh_fill32(seed, (uint8_t)(0x80u + (unsigned)i));
            mesh_fill32(noise, (uint8_t)(0xa0u + (unsigned)i));
            ASSERT(vcs_zcode_dht_delegation_sign(
                       &delegation, genesis, online, noise,
                       ZCL_FINALITY_DEPTH, beacon,
                       (uint64_t)(wall - 100), (uint64_t)(wall + 86400), 7,
                       seed) == VCS_ZCODE_DHT_DELEGATION_OK);
            memcpy(identity.master_pubkey, delegation.doc.master_pubkey, 32);
            mesh_fill32(identity.anchor_txid, 0x77);
            identity.anchor_height = 0;
            identity.updated_height = 0;
            snprintf(identity.status, sizeof(identity.status), "%s",
                     ZID_IDENTITY_STATUS_ACTIVE);
            snprintf(identity.source, sizeof(identity.source), "%s",
                     ZID_IDENTITY_SOURCE_ZID_OVERLAY);
            ASSERT(db_zid_identity_save(&ndb, &identity));
            ASSERT(v2_identity_public_fingerprint(noise, fingerprint));
            reason = mesh_pairing_service_accept(
                &ndb, genesis, &delegation, fingerprint, noise, true,
                MESH_PAIRING_CAP_STATUS_READ, wall - 40 + i, wall + 86400,
                &row);
            if (reason != MESH_PAIRING_OK)
                printf("[accept %s] ", mesh_pairing_reason_token(reason));
            ASSERT(reason == MESH_PAIRING_OK);
            if (i == ROSTER_PAGE) {
                struct db_mesh_machine_observation observed;
                ASSERT(mesh_observation_fixture(&row, wall - 1, "{}", &observed));
                ASSERT(db_mesh_machine_observation_save(&ndb, &observed));
            }
            memcpy(ids[i], row.pairing_id, sizeof(ids[i]));
        }
        node_db_close(&ndb);
        ASSERT(roster_call(&page1, dir, false, 0));
        ASSERT_EQ(json_get_int(json_get(&page1.data, "total")),
                  (int64_t)ROSTER_MACHINES);
        ASSERT_EQ(json_get_int(json_get(&page1.data, "row_count")),
                  (int64_t)ROSTER_PAGE);
        ASSERT(json_get_bool(json_get(&page1.data, "truncated")));
        ASSERT_EQ(json_get_int(json_get(&page1.data, "next_resume_after")),
                  (int64_t)ROSTER_PAGE);
        for (int i = 0; i < ROSTER_PAGE; i++)
            ASSERT_STR_EQ(roster_row_id(&page1, (size_t)i), ids[i]);
        ASSERT(roster_call(&page2, dir, true,
                           json_get_int(json_get(&page1.data,
                                                 "next_resume_after"))));
        ASSERT_EQ(json_get_int(json_get(&page2.data, "row_count")), (int64_t)1);
        ASSERT_EQ(json_get_int(json_get(&page2.data, "total")),
                  (int64_t)ROSTER_MACHINES);
        ASSERT(!json_get_bool(json_get(&page2.data, "truncated")));
        ASSERT(json_get(&page2.data, "next_resume_after") == NULL);
        ASSERT_STR_EQ(roster_row_id(&page2, 0), ids[ROSTER_PAGE]);
        const struct json_value *rows = json_get(&page2.data, "rows");
        const struct json_value *verified = json_get(json_at(rows, 0), "verified");
        bool retained = false;
        for (size_t i = 0; i < json_size(verified); i++) {
            const struct json_value *fact = json_at(verified, i);
            const char *name = json_get_str(json_get(fact, "fact"));
            if (name && strcmp(name, "reachable") == 0)
                retained = json_get_bool(json_get(fact, "observed")) &&
                           json_get_int(json_get(fact, "observed_unix")) == wall - 1;
        }
        ASSERT(retained);
        ASSERT(roster_call(&past, dir, true, ROSTER_MACHINES));
        ASSERT_EQ(json_get_int(json_get(&past.data, "row_count")), (int64_t)0);
        ASSERT_EQ(json_get_int(json_get(&past.data, "total")),
                  (int64_t)ROSTER_MACHINES);
        ASSERT(!json_get_bool(json_get(&past.data, "truncated")));
        PASS();
    } _test_next:;
    if (ndb.open)
        node_db_close(&ndb);
    zcl_command_reply_free(&page1);
    zcl_command_reply_free(&page2);
    zcl_command_reply_free(&past);
    return failures;
}

/* Arm interruption from the statement trace: preparation has finished,
 * so the failure is a read step rather than a prepare refusal. */
struct mesh_read_interrupt {
    sqlite3 *db;
    bool traced;
    unsigned calls;
};

static int mesh_interrupt_trace(unsigned event, void *arg, void *stmt,
                                 void *text)
{
    (void)stmt;
    (void)text;
    struct mesh_read_interrupt *fault = arg;
    if (event == SQLITE_TRACE_STMT) {
        fault->traced = true;
        fault->calls++;
        sqlite3_interrupt(fault->db);
    }
    return 0;
}

static int test_mesh_observation_interrupted_step(void)
{
    int failures = 0;
    struct node_db ndb = {0};
    char dir[256], path[320];
    test_make_tmpdir(dir, sizeof(dir), "mesh_pairing", "interrupted-read");
    snprintf(path, sizeof(path), "%s/node.db", dir);
    TEST("mesh observations: an interrupted read step returns -1") {
        struct vcs_zcode_dht_delegation delegation;
        uint8_t fingerprint[32], genesis[32];
        struct db_mesh_machine_view row;
        ASSERT(mesh_fixture(&ndb, path, &delegation, fingerprint, genesis));
        struct mesh_read_interrupt fault = { .db = ndb.db };
        ASSERT_EQ(sqlite3_trace_v2(ndb.db, SQLITE_TRACE_STMT,
                                   mesh_interrupt_trace, &fault), SQLITE_OK);
        int count = db_mesh_machine_observation_list_after(&ndb, &row, 1, 2000, 0);
        ASSERT_EQ(sqlite3_trace_v2(ndb.db, 0, NULL, NULL), SQLITE_OK);
        printf("[traced=%d interrupts=%u count=%d] ",
               fault.traced, fault.calls, count);
        ASSERT(fault.traced && fault.calls > 0 && count == -1);
        PASS();
    } _test_next:;
    if (ndb.open) {
        (void)sqlite3_trace_v2(ndb.db, 0, NULL, NULL);
        node_db_close(&ndb);
    }
    test_cleanup_tmpdir(dir);
    return failures;
}

static unsigned mesh_roster_denied_reads;

static int mesh_roster_interrupt_observation(unsigned event, void *arg,
                                              void *statement, void *text)
{
    (void)statement;
    const char *sql = text;
    if (event == SQLITE_TRACE_STMT && sql &&
        (strstr(sql, "LEFT JOIN mesh_machine_observations") ||
         strstr(sql, "FROM mesh_machine_observations"))) {
        mesh_roster_denied_reads++;
        sqlite3_interrupt(arg);
    }
    return 0;
}

static int mesh_roster_read_fault(sqlite3 *db, char **error,
                                  const sqlite3_api_routines *api)
{
    (void)error;
    (void)api;
    return sqlite3_trace_v2(db, SQLITE_TRACE_STMT,
                          mesh_roster_interrupt_observation, db);
}

static int test_mesh_roster_observation_refusal(bool allocation)
{
    int failures = 0;
    struct node_db ndb = {0};
    struct zcl_command_reply reply = {0};
    char dir[256], path[320];
    test_make_tmpdir(dir, sizeof(dir), "mesh_pairing", "roster-refusal");
    snprintf(path, sizeof(path), "%s/node.db", dir);
    TEST(allocation ? "ops.mesh.roster: refuses observation allocation failure"
                    : "ops.mesh.roster: refuses an observation read failure") {
        struct vcs_zcode_dht_delegation delegation;
        uint8_t fingerprint[32], genesis[32];
        struct db_mesh_pairing row;
        ASSERT(mesh_fixture(&ndb, path, &delegation, fingerprint, genesis));
        ASSERT_EQ(mesh_pairing_service_accept(
                      &ndb, genesis, &delegation, fingerprint,
                      delegation.noise_static_pubkey, true,
                      MESH_PAIRING_CAP_STATUS_READ, 2000, 3000, &row),
                  MESH_PAIRING_OK);
        node_db_close(&ndb);
        mesh_roster_denied_reads = 0;
        if (allocation)
            zcl_alloc_fault_fail_next("roster_machines");
        else
            ASSERT_EQ(sqlite3_auto_extension((void (*)(void))mesh_roster_read_fault),
                      SQLITE_OK);
        bool passed = roster_call(&reply, dir, false, 0);
        bool consumed = zcl_alloc_fault_armed_label() == NULL;
        zcl_alloc_fault_clear();
        (void)sqlite3_cancel_auto_extension((void (*)(void))mesh_roster_read_fault);
        ASSERT(allocation ? consumed : mesh_roster_denied_reads > 0);
        ASSERT(!passed);
        ASSERT_EQ(reply.status, ZCL_COMMAND_STATUS_FAILED);
        ASSERT_STR_EQ(reply.error.code, "ROSTER_OBSERVATIONS_UNAVAILABLE");
        ASSERT(reply.error.message[0] != '\0');
        ASSERT(json_get(&reply.data, "rows") == NULL);
        PASS();
    } _test_next:;
    zcl_alloc_fault_clear();
    (void)sqlite3_cancel_auto_extension((void (*)(void))mesh_roster_read_fault);
    zcl_command_reply_free(&reply);
    if (ndb.open)
        node_db_close(&ndb);
    test_cleanup_tmpdir(dir);
    return failures;
}

static bool mesh_boundary_fixture(struct node_db *ndb, const char *path,
                                  char ids[3][MESH_PAIRING_ID_HEX + 1])
{
    if (!node_db_open(ndb, path))
        return false;
    for (unsigned i = 0; i < 3; i++) {
        struct db_mesh_pairing row = {0};
        mesh_fill32(row.network_genesis, 0x11);
        mesh_fill32(row.peer_master_pubkey, (uint8_t)(0x70u + i));
        mesh_fill32(row.peer_noise_pubkey, (uint8_t)(0x80u + i));
        row.capability_mask = MESH_PAIRING_CAP_STATUS_READ;
        row.delegation_sequence = 1;
        row.paired_at = 1000;
        row.expires_at = 4000;
        if (!db_mesh_pairing_insert(ndb, &row) ||
            !mesh_pairing_id_derive(row.network_genesis, row.peer_master_pubkey,
                                   row.peer_noise_pubkey, ids[i]))
            return false;
    }
    for (unsigned i = 0; i < 3; i++) {
        for (unsigned j = i + 1; j < 3; j++) {
            if (strcmp(ids[i], ids[j]) > 0) {
                char tmp[MESH_PAIRING_ID_HEX + 1];
                memcpy(tmp, ids[i], sizeof(tmp));
                memcpy(ids[i], ids[j], sizeof(tmp));
                memcpy(ids[j], tmp, sizeof(tmp));
            }
        }
    }
    return true;
}

static bool mesh_buffer_is(const void *buffer, size_t size, unsigned char byte)
{
    const unsigned char *bytes = buffer;
    for (size_t i = 0; i < size; i++)
        if (bytes[i] != byte)
            return false;
    return true;
}

static int mesh_interrupt_after_row(unsigned event, void *arg, void *stmt,
                                     void *text)
{
    (void)stmt;
    (void)text;
    struct mesh_read_interrupt *fault = arg;
    if (event == SQLITE_TRACE_ROW) {
        fault->calls++;
        if (fault->calls == 1)
            sqlite3_interrupt(fault->db);
    }
    return 0;
}

static int test_mesh_observation_boundary(unsigned which)
{
    static const char *const names[] = {
        "mesh observations: INT64_MAX offset is an empty page",
        "mesh observations: zero capacity preserves output",
        "mesh observations: invalid time preserves output",
        "mesh observations: oversized capacity preserves output",
        "mesh observations: unrepresentable offset preserves output",
        "mesh observations: null database preserves output",
        "mesh observations: closed database preserves output",
        "mesh observations: null output is refused",
        "mesh observations: timestamp ties order by pairing id",
        "mesh observations: failure after a returned row refuses a partial count"
    };
    int failures = 0;
    struct node_db ndb = {0};
    static struct db_mesh_machine_view out[3];
    char dir[256], path[320];
    test_make_tmpdir(dir, sizeof(dir), "mesh_pairing", "observation-boundary");
    snprintf(path, sizeof(path), "%s/node.db", dir);
    TEST(names[which]) {
        char ids[3][MESH_PAIRING_ID_HEX + 1];
        ASSERT(mesh_boundary_fixture(&ndb, path, ids));
        memset(out, 0xa5, sizeof(out));
        int count = -2;
        if (which == 0) {
            size_t huge = SIZE_MAX < (uint64_t)INT64_MAX ? SIZE_MAX
                                                       : (size_t)INT64_MAX;
            count = db_mesh_machine_observation_list_after(&ndb, out, 3, 2000, huge);
            ASSERT_EQ(count, 0);
        } else if (which < 8) {
            struct node_db closed = {0};
            struct node_db *db = which == 5 ? NULL : which == 6 ? &closed : &ndb;
            size_t max = which == 1 ? 0 : which == 3 ? (size_t)INT_MAX + 1 : 3;
            int64_t now = which == 2 ? 0 : 2000;
            size_t skip = which == 4 ? SIZE_MAX : 0;
            count = db_mesh_machine_observation_list_after(
                db, which == 7 ? NULL : out, max, now, skip);
            ASSERT_EQ(count, -1);
            ASSERT(mesh_buffer_is(out, sizeof(out), 0xa5));
        } else if (which == 8) {
            ASSERT_EQ(db_mesh_machine_observation_list_after(&ndb, out, 3, 2000, 0), 3);
            for (unsigned i = 0; i < 3; i++)
                ASSERT_STR_EQ(out[i].pairing.pairing_id, ids[i]);
            ASSERT_EQ(db_mesh_machine_observation_list_after(&ndb, out, 1, 2000, 1), 1);
            ASSERT_STR_EQ(out[0].pairing.pairing_id, ids[1]);
        } else {
            struct mesh_read_interrupt fault = { .db = ndb.db };
            ASSERT_EQ(sqlite3_trace_v2(ndb.db, SQLITE_TRACE_ROW,
                                      mesh_interrupt_after_row, &fault), SQLITE_OK);
            count = db_mesh_machine_observation_list_after(&ndb, out, 3, 2000, 0);
            ASSERT_EQ(sqlite3_trace_v2(ndb.db, 0, NULL, NULL), SQLITE_OK);
            printf("[returned-row trace=%u count=%d] ", fault.calls, count);
            ASSERT_EQ(fault.calls, 1);
            ASSERT_STR_EQ(out[0].pairing.pairing_id, ids[0]);
            ASSERT(mesh_buffer_is(&out[1], sizeof(out[1]), 0xa5));
            ASSERT_EQ(count, -1);
        }
        PASS();
    } _test_next:;
    if (ndb.open) {
        (void)sqlite3_trace_v2(ndb.db, 0, NULL, NULL);
        node_db_close(&ndb);
    }
    test_cleanup_tmpdir(dir);
    return failures;
}

struct mesh_roster_insert_fault {
    struct node_db *writer;
    struct db_mesh_pairing row;
    unsigned attempts;
    bool inserted;
};

static struct mesh_roster_insert_fault mesh_roster_between;

static int mesh_roster_insert_trace(unsigned event, void *arg,
                                    void *statement, void *text)
{
    (void)arg;
    (void)statement;
    const char *sql = text;
    if (event == SQLITE_TRACE_STMT && sql &&
        strstr(sql, "mesh_machine_observations") &&
        mesh_roster_between.attempts == 0) {
        mesh_roster_between.attempts++;
        mesh_roster_between.inserted = db_mesh_pairing_insert(
            mesh_roster_between.writer, &mesh_roster_between.row);
    }
    return 0;
}

static int mesh_roster_insert_extension(sqlite3 *db, char **error,
                                         const sqlite3_api_routines *api)
{
    (void)error;
    (void)api;
    return sqlite3_trace_v2(db, SQLITE_TRACE_STMT, mesh_roster_insert_trace, NULL);
}

static bool mesh_roster_observed(const struct zcl_command_reply *reply,
                                 size_t index, int64_t at)
{
    const struct json_value *rows = json_get(&reply->data, "rows");
    const struct json_value *facts = json_get(json_at(rows, index), "verified");
    for (size_t i = 0; i < json_size(facts); i++) {
        const struct json_value *fact = json_at(facts, i);
        const char *name = json_get_str(json_get(fact, "fact"));
        if (name && strcmp(name, "reachable") == 0)
            return json_get_bool(json_get(fact, "observed")) &&
                   (at == 0 || json_get_int(json_get(fact, "observed_unix")) == at);
    }
    return false;
}

static bool mesh_roster_page_fixture(struct node_db *ndb, const char *path,
                                     int64_t wall,
                                     char ids[][MESH_PAIRING_ID_HEX + 1], unsigned members)
{
    if (!node_db_open(ndb, path))
        return false;
    for (unsigned i = 0; i < members; i++) {
        struct db_mesh_pairing row = {0};
        mesh_fill32(row.network_genesis, 0x11);
        mesh_fill32(row.peer_master_pubkey, (uint8_t)(0x40u + i));
        mesh_fill32(row.peer_noise_pubkey, (uint8_t)(0x80u + i));
        row.capability_mask = MESH_PAIRING_CAP_STATUS_READ;
        row.delegation_sequence = 1;
        row.paired_at = wall - 80 + i;
        row.expires_at = wall + 86400;
        if (!db_mesh_pairing_insert(ndb, &row))
            return false;
        memcpy(ids[i], row.pairing_id, sizeof(ids[i]));
        if (i % ROSTER_PAGE == 0 || i % ROSTER_PAGE == ROSTER_PAGE - 1) {
            struct db_mesh_machine_observation observed;
            int64_t at = wall - 2 - 2 * (i / ROSTER_PAGE) +
                         (i % ROSTER_PAGE == ROSTER_PAGE - 1);
            if (!mesh_observation_fixture(&row, at, "{}", &observed) ||
                !db_mesh_machine_observation_save(ndb, &observed))
                return false;
        }
    }
    return true;
}

static int test_mesh_roster_selected_evidence(unsigned which)
{
    static const char *const names[] = {
        "ops.mesh.roster: an insertion between queries retains selected evidence",
        "ops.mesh.roster: a member without observation stays unobserved",
        "ops.mesh.roster: an exactly-full last page has no continuation",
        "ops.mesh.roster: later-page insertion retains each selected identity"
    };
    int failures = 0;
    struct node_db ndb = {0};
    struct zcl_command_reply reply = {0};
    char dir[256], path[320];
    test_make_tmpdir(dir, sizeof(dir), "mesh_pairing", "selected-evidence");
    snprintf(path, sizeof(path), "%s/node.db", dir);
    TEST(names[which]) {
        int64_t wall = platform_time_wall_unix();
        unsigned skip = which == 3 ? ROSTER_PAGE : 0;
        unsigned members = ROSTER_PAGE + skip;
        char ids[2 * ROSTER_PAGE][MESH_PAIRING_ID_HEX + 1];
        ASSERT(mesh_roster_page_fixture(&ndb, path, wall, ids, members));
        memset(&mesh_roster_between, 0, sizeof(mesh_roster_between));
        if (which == 0 || which == 3) {
            mesh_roster_between.writer = &ndb;
            struct db_mesh_pairing *row = &mesh_roster_between.row;
            mesh_fill32(row->network_genesis, 0x11);
            mesh_fill32(row->peer_master_pubkey, 0xe1);
            mesh_fill32(row->peer_noise_pubkey, 0xe2);
            row->capability_mask = MESH_PAIRING_CAP_STATUS_READ;
            row->delegation_sequence = 1;
            row->paired_at = wall - 100;
            row->expires_at = wall + 86400;
            ASSERT_EQ(sqlite3_auto_extension((void (*)(void))mesh_roster_insert_extension),
                      SQLITE_OK);
        }
        bool passed = roster_call(&reply, dir, skip != 0, skip);
        (void)sqlite3_cancel_auto_extension((void (*)(void))mesh_roster_insert_extension);
        if (which == 0 || which == 3) {
            printf("[between-query attempts=%u inserted=%d] ",
                   mesh_roster_between.attempts, mesh_roster_between.inserted);
            ASSERT_EQ(mesh_roster_between.attempts, 1);
            ASSERT(mesh_roster_between.inserted);
        }
        ASSERT(passed);
        ASSERT_EQ(json_get_int(json_get(&reply.data, "row_count")), ROSTER_PAGE);
        ASSERT_EQ(json_get_int(json_get(&reply.data, "total")), members);
        for (unsigned i = 0; i < ROSTER_PAGE; i++)
            ASSERT_STR_EQ(roster_row_id(&reply, i), ids[skip + i]);
        if (which == 1)
            ASSERT(!mesh_roster_observed(&reply, 1, 0));
        if (which == 2) {
            ASSERT(!json_get_bool(json_get(&reply.data, "truncated")));
            ASSERT(json_get(&reply.data, "next_resume_after") == NULL);
        }
        ASSERT(mesh_roster_observed(&reply, 0, wall - 2 - 2 * (skip / ROSTER_PAGE)));
        ASSERT(mesh_roster_observed(&reply, ROSTER_PAGE - 1,
                                    wall - 1 - 2 * (skip / ROSTER_PAGE)));
        if (which == 3) {
            for (unsigned i = 1; i < ROSTER_PAGE - 1; i++)
                ASSERT(!mesh_roster_observed(&reply, i, 0));
        }
        PASS();
    } _test_next:;
    (void)sqlite3_cancel_auto_extension((void (*)(void))mesh_roster_insert_extension);
    memset(&mesh_roster_between, 0, sizeof(mesh_roster_between));
    zcl_command_reply_free(&reply);
    if (ndb.open)
        node_db_close(&ndb);
    test_cleanup_tmpdir(dir);
    return failures;
}

static int test_mesh_roster_by_ids_contract(bool invalid_id)
{
    int failures = 0;
    struct node_db ndb = {0};
    static struct db_mesh_machine_observation out[2];
    char dir[256], path[320];
    test_make_tmpdir(dir, sizeof(dir), "mesh_pairing", "by-ids-contract");
    snprintf(path, sizeof(path), "%s/node.db", dir);
    TEST(invalid_id ? "mesh observations by IDs: invalid IDs preserve output"
                    : "mesh observations by IDs: insufficient capacity preserves output") {
        int64_t wall = platform_time_wall_unix();
        char ids[ROSTER_PAGE][MESH_PAIRING_ID_HEX + 1];
        ASSERT(mesh_roster_page_fixture(&ndb, path, wall, ids, ROSTER_PAGE));
        char bad[MESH_PAIRING_ID_HEX + 1];
        memset(bad, 'A', MESH_PAIRING_ID_HEX);
        bad[MESH_PAIRING_ID_HEX] = '\0';
        const char *selected[] = { invalid_id ? bad : ids[0], ids[ROSTER_PAGE - 1] };
        memset(out, 0xa5, sizeof(out));
        ASSERT_EQ(db_mesh_machine_observation_list_by_ids(
                      &ndb, selected, 2, out, invalid_id ? 2 : 1), -1);
        ASSERT(mesh_buffer_is(out, sizeof(out), 0xa5));
        PASS();
    } _test_next:;
    if (ndb.open)
        node_db_close(&ndb);
    test_cleanup_tmpdir(dir);
    return failures;
}

static int test_mesh_roster_success_page(unsigned which)
{
    static const char *const names[] = {
        "ops.mesh.roster: empty page past end passes",
        "ops.mesh.roster: one-row page passes",
        "ops.mesh.roster: exactly-full page passes"
    };
    int failures = 0;
    struct node_db ndb = {0};
    struct zcl_command_reply reply = {0};
    static struct mesh_pairing_public_view views[ROSTER_PAGE];
    char dir[256], path[320];
    test_make_tmpdir(dir, sizeof(dir), "mesh_pairing", "success-page");
    snprintf(path, sizeof(path), "%s/node.db", dir);
    TEST(names[which]) {
        int64_t wall = platform_time_wall_unix();
        unsigned members = which == 1 ? 1 : ROSTER_PAGE;
        size_t skip = which == 0 ? members : 0;
        size_t expected = which == 0 ? 0 : members;
        char ids[ROSTER_PAGE][MESH_PAIRING_ID_HEX + 1];
        ASSERT(mesh_roster_page_fixture(&ndb, path, wall, ids, members));
        struct db_mesh_pairing_counts counts;
        size_t count = SIZE_MAX;
        bool read = mesh_pairing_service_list_after(
            &ndb, wall, skip, views, ROSTER_PAGE, &count, &counts);
        int code = sqlite3_errcode(ndb.db);
        printf("[sqlite=%s page=%u read=%d rows=%zu errcode=%d] ",
               sqlite3_libversion(), which, read, count, code);
        ASSERT(read);
        ASSERT_EQ(count, expected);
        for (size_t i = 0; i < count; i++)
            ASSERT_STR_EQ(views[i].pairing_id, ids[i]);
        node_db_close(&ndb);
        ASSERT(roster_call(&reply, dir, true, (int64_t)skip));
        ASSERT_EQ(reply.status, ZCL_COMMAND_STATUS_PASSED);
        ASSERT_EQ(json_get_int(json_get(&reply.data, "row_count")), (int64_t)expected);
        ASSERT_EQ(json_get_int(json_get(&reply.data, "total")), members);
        ASSERT(!json_get_bool(json_get(&reply.data, "truncated")));
        ASSERT(json_get(&reply.data, "next_resume_after") == NULL);
        for (size_t i = 0; i < expected; i++)
            ASSERT_STR_EQ(roster_row_id(&reply, i), ids[i]);
        PASS();
    } _test_next:;
    if (ndb.open)
        node_db_close(&ndb);
    zcl_command_reply_free(&reply);
    test_cleanup_tmpdir(dir);
    return failures;
}

static int test_mesh_roster_by_ids_large_capacity(void)
{
    int failures = 0;
    struct node_db ndb = {0};
    static struct db_mesh_machine_observation out;
    char dir[256], path[320];
    test_make_tmpdir(dir, sizeof(dir), "mesh_pairing", "by-ids-large");
    snprintf(path, sizeof(path), "%s/node.db", dir);
    TEST("mesh observations by IDs: capacity above INT_MAX preserves output") {
        ASSERT(node_db_open(&ndb, path));
        memset(&out, 0xa5, sizeof(out));
        ASSERT_EQ(db_mesh_machine_observation_list_by_ids(
                      &ndb, NULL, 0, &out, (size_t)INT_MAX + 1), -1);
        ASSERT(mesh_buffer_is(&out, sizeof(out), 0xa5));
        PASS();
    } _test_next:;
    if (ndb.open)
        node_db_close(&ndb);
    test_cleanup_tmpdir(dir);
    return failures;
}

static unsigned mesh_roster_membership_interrupts;
static bool mesh_roster_membership_partial;

static int mesh_roster_membership_trace(unsigned event, void *arg,
                                        void *statement, void *text)
{
    (void)text;
    const char *sql = sqlite3_sql(statement);
    unsigned trigger = mesh_roster_membership_partial ? SQLITE_TRACE_ROW : SQLITE_TRACE_STMT;
    if (event == trigger && sql && strstr(sql, "FROM mesh_pairings ORDER BY") &&
        mesh_roster_membership_interrupts == 0) {
        mesh_roster_membership_interrupts++;
        sqlite3_interrupt(arg);
    }
    return 0;
}

static int mesh_roster_membership_extension(sqlite3 *db, char **error,
                                             const sqlite3_api_routines *api)
{
    (void)error;
    (void)api;
    return sqlite3_trace_v2(db, SQLITE_TRACE_STMT | SQLITE_TRACE_ROW,
                           mesh_roster_membership_trace, db);
}

static int test_mesh_roster_membership_refusal(unsigned which)
{
    static const char *const names[] = {
        "ops.mesh.roster: refuses membership prepare failure after a valid count",
        "ops.mesh.roster: refuses membership step failure after a valid count",
        "ops.mesh.roster: refuses a partial membership read"
    };
    int failures = 0;
    struct node_db ndb = {0};
    struct zcl_command_reply reply = {0};
    char dir[256], path[320];
    test_make_tmpdir(dir, sizeof(dir), "mesh_pairing", "membership-refusal");
    snprintf(path, sizeof(path), "%s/node.db", dir);
    TEST(names[which]) {
        int64_t wall = platform_time_wall_unix();
        char ids[ROSTER_PAGE][MESH_PAIRING_ID_HEX + 1];
        ASSERT(mesh_roster_page_fixture(&ndb, path, wall, ids, ROSTER_PAGE));
        if (which == 0) {
            ASSERT(node_db_exec(&ndb,
                "PRAGMA foreign_keys=OFF; DROP TABLE mesh_pairings;"
                "CREATE TABLE mesh_pairings(pairing_id TEXT PRIMARY KEY,"
                "revoked_at INTEGER,expires_at INTEGER);"
                "INSERT INTO mesh_pairings VALUES('countable',0,9223372036854775807)"));
        }
        struct db_mesh_pairing_counts counts;
        ASSERT(db_mesh_pairing_count_states(&ndb, wall, &counts));
        ASSERT_EQ(counts.total, which == 0 ? 1 : ROSTER_PAGE);
        node_db_close(&ndb);
        mesh_roster_membership_interrupts = 0;
        mesh_roster_membership_partial = which == 2;
        if (which != 0)
            ASSERT_EQ(sqlite3_auto_extension((void (*)(void))mesh_roster_membership_extension),
                      SQLITE_OK);
        bool passed = roster_call(&reply, dir, false, 0);
        (void)sqlite3_cancel_auto_extension((void (*)(void))mesh_roster_membership_extension);
        printf("[count=%lld interrupts=%u status=%d rows=%lld] ",
               (long long)counts.total, mesh_roster_membership_interrupts,
               reply.status, (long long)json_get_int(json_get(&reply.data, "row_count")));
        if (which != 0)
            ASSERT_EQ(mesh_roster_membership_interrupts, 1);
        ASSERT(!passed);
        ASSERT_EQ(reply.status, ZCL_COMMAND_STATUS_FAILED);
        ASSERT_STR_EQ(reply.error.code, "ROSTER_STORE_UNREADABLE");
        ASSERT(reply.error.message[0] != '\0');
        ASSERT(json_get(&reply.data, "rows") == NULL);
        PASS();
    } _test_next:;
    (void)sqlite3_cancel_auto_extension((void (*)(void))mesh_roster_membership_extension);
    mesh_roster_membership_interrupts = 0;
    mesh_roster_membership_partial = false;
    zcl_command_reply_free(&reply);
    if (ndb.open)
        node_db_close(&ndb);
    test_cleanup_tmpdir(dir);
    return failures;
}

static int test_mesh_pairing_service_read_failure(unsigned which)
{
    static const char *const names[] = {
        "mesh pairing service: preparation failure returns false",
        "mesh pairing service: initial step failure returns false",
        "mesh pairing service: partial step failure returns false"
    };
    int failures = 0;
    struct node_db ndb = {0};
    static struct mesh_pairing_public_view views[ROSTER_PAGE];
    char dir[256], path[320];
    test_make_tmpdir(dir, sizeof(dir), "mesh_pairing", "service-read-failure");
    snprintf(path, sizeof(path), "%s/node.db", dir);
    TEST(names[which]) {
        int64_t wall = platform_time_wall_unix();
        char ids[ROSTER_PAGE][MESH_PAIRING_ID_HEX + 1];
        ASSERT(mesh_roster_page_fixture(&ndb, path, wall, ids, ROSTER_PAGE));
        if (which == 0)
            ASSERT(node_db_exec(&ndb,
                "PRAGMA foreign_keys=OFF; DROP TABLE mesh_pairings;"
                "CREATE TABLE mesh_pairings(pairing_id TEXT PRIMARY KEY,"
                "revoked_at INTEGER,expires_at INTEGER);"
                "INSERT INTO mesh_pairings VALUES('countable',0,9223372036854775807)"));
        mesh_roster_membership_interrupts = 0;
        mesh_roster_membership_partial = which == 2;
        if (which != 0)
            ASSERT_EQ(sqlite3_trace_v2(ndb.db, SQLITE_TRACE_STMT | SQLITE_TRACE_ROW,
                                     mesh_roster_membership_trace, ndb.db), SQLITE_OK);
        memset(views, 0xa5, sizeof(views));
        struct db_mesh_pairing_counts counts;
        size_t count = SIZE_MAX;
        bool read = mesh_pairing_service_list_after(
            &ndb, wall, 0, views, ROSTER_PAGE, &count, &counts);
        if (which != 0)
            ASSERT_EQ(mesh_roster_membership_interrupts, 1);
        ASSERT(!read);
        ASSERT_EQ(count, 0);
        ASSERT(mesh_buffer_is(views, sizeof(views), 0xa5));
        PASS();
    } _test_next:;
    if (ndb.open) {
        (void)sqlite3_trace_v2(ndb.db, 0, NULL, NULL);
        node_db_close(&ndb);
    }
    mesh_roster_membership_interrupts = 0;
    mesh_roster_membership_partial = false;
    test_cleanup_tmpdir(dir);
    return failures;
}

static const struct {
    const char *name;
    const char *sql;
} mesh_pairing_malformed_cases[] = {
    { "short blob", "UPDATE mesh_pairings SET network_genesis=X'00'" },
    { "NULL blob", "UPDATE mesh_pairings SET peer_master_pubkey=NULL" },
    { "overlong pairing ID", "UPDATE mesh_pairings SET pairing_id=pairing_id||'a'" },
    { "wrong-type pairing ID", "UPDATE mesh_pairings SET pairing_id=CAST(pairing_id AS BLOB)" },
    { "overlong blob", "UPDATE mesh_pairings SET peer_noise_pubkey=zeroblob(33)" },
    { "wrong-type blob", "UPDATE mesh_pairings SET network_genesis='aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'" },
    { "embedded-NUL pairing ID", "UPDATE mesh_pairings SET pairing_id=pairing_id||char(0)||'a'" },
    { "NULL integer", "UPDATE mesh_pairings SET delegation_sequence=NULL" },
    { "wrong-type integer", "UPDATE mesh_pairings SET capability_mask='not an integer'" },
    { "NULL revoked_at", "UPDATE mesh_pairings SET revoked_at=NULL" },
};

/* raw-sql-ok:test-fixture -- weakens only an isolated replacement table to
 * plant readable rows that the normal schema's constraints would reject. */
static bool mesh_pairing_malformed_fixture(struct node_db *ndb,
                                           const char *path, int64_t wall,
                                           unsigned which)
{
    char ids[1][MESH_PAIRING_ID_HEX + 1];
    if (!mesh_roster_page_fixture(ndb, path, wall, ids, 1))
        return false;
    if (!node_db_exec(ndb,
        "PRAGMA foreign_keys=OFF;"
        "CREATE TEMP TABLE mesh_pairing_saved AS SELECT * FROM mesh_pairings;"
        "DROP TABLE mesh_pairings;"
        "CREATE TABLE mesh_pairings("
        "pairing_id TEXT,network_genesis BLOB,peer_master_pubkey BLOB,"
        "peer_noise_pubkey BLOB,capability_mask INTEGER,"
        "delegation_sequence INTEGER,paired_at INTEGER,expires_at INTEGER,"
        "revoked_at INTEGER,revocation_generation INTEGER);"
        "INSERT INTO mesh_pairings SELECT * FROM mesh_pairing_saved;"
        "DROP TABLE mesh_pairing_saved;"))
        return false;
    return node_db_exec(ndb, mesh_pairing_malformed_cases[which].sql);
}

static int test_mesh_pairing_malformed_row(unsigned which, unsigned layer)
{
    static const char *const layers[] = { "model", "service", "roster CLI" };
    int failures = 0;
    struct node_db ndb = {0};
    struct zcl_command_reply reply = {0};
    char dir[256], path[320], label[160];
    test_make_tmpdir(dir, sizeof(dir), "mesh_pairing", "malformed-row");
    snprintf(path, sizeof(path), "%s/node.db", dir);
    snprintf(label, sizeof(label), "mesh pairing malformed %s: %s refuses",
             mesh_pairing_malformed_cases[which].name, layers[layer]);
    TEST(label) {
        int64_t wall = platform_time_wall_unix();
        ASSERT(mesh_pairing_malformed_fixture(&ndb, path, wall, which));
        struct db_mesh_pairing_counts counts;
        /* NULL revoked_at already fails the counts invariant; its direct
         * model case proves decoding rather than that earlier refusal. */
        if (which != 9) {
            ASSERT(db_mesh_pairing_count_states(&ndb, wall, &counts));
            ASSERT_EQ(counts.total, 1);
            ASSERT_EQ(counts.active, 1);
        }
        if (layer == 0) {
            struct db_mesh_pairing row;
            int found = db_mesh_pairing_list_after_checked(&ndb, &row, 1, 0);
            printf("[model count=%d] ", found);
            ASSERT_EQ(found, -1);
        } else if (layer == 1) {
            struct mesh_pairing_public_view view;
            memset(&view, 0xa5, sizeof(view));
            size_t count = SIZE_MAX;
            bool read = mesh_pairing_service_list_after(
                &ndb, wall, 0, &view, 1, &count, &counts);
            printf("[service read=%d count=%zu] ", read, count);
            ASSERT(!read);
            ASSERT_EQ(count, 0);
            ASSERT(mesh_buffer_is(&view, sizeof(view), 0xa5));
        } else {
            node_db_close(&ndb);
            bool passed = roster_call(&reply, dir, false, 0);
            printf("[roster passed=%d status=%d rows=%lld] ", passed,
                   reply.status,
                   (long long)json_get_int(json_get(&reply.data, "row_count")));
            ASSERT(!passed);
            ASSERT_EQ(reply.status, ZCL_COMMAND_STATUS_FAILED);
            ASSERT_STR_EQ(reply.error.code, "ROSTER_STORE_UNREADABLE");
            ASSERT(reply.error.message[0] != '\0');
            ASSERT(json_get(&reply.data, "rows") == NULL);
        }
        PASS();
    } _test_next:;
    zcl_command_reply_free(&reply);
    if (ndb.open)
        node_db_close(&ndb);
    test_cleanup_tmpdir(dir);
    return failures;
}

static int test_mesh_pairing_malformed_authority(void)
{
    int failures = 0;
    struct node_db ndb = {0};
    char dir[256], path[320];
    test_make_tmpdir(dir, sizeof(dir), "mesh_pairing", "malformed-authority");
    snprintf(path, sizeof(path), "%s/node.db", dir);
    TEST("mesh pairing: malformed revocation authority is refused") {
        struct vcs_zcode_dht_delegation delegation;
        uint8_t fingerprint[32], genesis[32];
        struct db_mesh_pairing row, out;
        ASSERT(mesh_fixture(&ndb, path, &delegation, fingerprint, genesis));
        ASSERT_EQ(mesh_pairing_service_accept(
                      &ndb, genesis, &delegation, fingerprint,
                      delegation.noise_static_pubkey, true,
                      MESH_PAIRING_CAP_STATUS_READ, 2000, 3000, &row),
                  MESH_PAIRING_OK);
        ASSERT(db_mesh_pairing_find(&ndb, row.pairing_id, &out));
        ASSERT_EQ(mesh_pairing_service_authorize_status(
                      &ndb, genesis, row.pairing_id, &delegation,
                      delegation.noise_static_pubkey, 2500), MESH_PAIRING_OK);
        /* raw-sql-ok:test-fixture -- malformed authority in an isolated DB. */
        ASSERT_EQ(sqlite3_exec(ndb.db,
                      "UPDATE mesh_pairings SET revoked_at=X'01'",
                      NULL, NULL, NULL), SQLITE_OK);
        bool found = db_mesh_pairing_find(&ndb, row.pairing_id, &out);
        int reason = mesh_pairing_service_authorize_status(
            &ndb, genesis, row.pairing_id, &delegation,
            delegation.noise_static_pubkey, 2500);
        printf("[malformed found=%d authorization=%d] ", found, reason);
        ASSERT(!found);
        ASSERT(reason != MESH_PAIRING_OK);
        ASSERT_EQ(db_mesh_pairing_list(&ndb, &out, 1), 0);
        PASS();
    }
_test_next:
    if (ndb.open)
        node_db_close(&ndb);
    test_cleanup_tmpdir(dir);
    return failures;
}

static int test_mesh_pairing_wiring_lifecycle(void)
{
    struct net_manager net = {0};
    struct msg_processor processor = {0};
    struct boot_svc_ctx svc = {0};
    struct boot_mesh_pairing_plan plan;
    const struct chain_params *params = chain_params_get();
    if (!params)
        return 1;
    processor.net_mgr = &net;
    processor.params = params;
    svc.msg_processor = &processor;
    boot_mesh_pairing_shutdown();
    bool unavailable = boot_mesh_pairing_plan(NULL, &plan) == MESH_PAIR_PLAN_UNAVAILABLE;
    boot_mesh_pairing_wire(&svc);
    bool disabled = boot_mesh_pairing_plan(NULL, &plan) == MESH_PAIR_PLAN_NOISE_DISABLED;
    /* Retire the borrowed stack composition on every path before returning. */
    boot_mesh_pairing_shutdown();
    bool retired = boot_mesh_pairing_plan(NULL, &plan) == MESH_PAIR_PLAN_UNAVAILABLE;
    if (!unavailable || !disabled || !retired) {
        fprintf(stderr, "mesh_pairing: wiring lifecycle failed unavailable=%d disabled=%d retired=%d\n",
            unavailable, disabled, retired);
        return 1;
    }
    return 0;
}

int test_mesh_pairing(void)
{
    int failures = test_mesh_pairing_wiring_lifecycle();
    char dir[256], path[320];
    test_make_tmpdir(dir, sizeof(dir), "mesh_pairing", "authority");
    snprintf(path, sizeof(path), "%s/node.db", dir);
    struct node_db ndb = {0};
    struct vcs_zcode_dht_delegation delegation;
    uint8_t fingerprint[32];
    uint8_t genesis[32];

    TEST("mesh pairing: explicit Noise-bound acceptance is durable") {
        ASSERT(mesh_fixture(&ndb, path, &delegation, fingerprint, genesis));
        struct db_mesh_pairing row;
        uint8_t wrong[32];
        mesh_fill32(wrong, 0x99);
        ASSERT_EQ(mesh_pairing_service_accept(
                      &ndb, genesis, &delegation, wrong,
                      delegation.noise_static_pubkey, true,
                      MESH_PAIRING_CAP_STATUS_READ, 2000, 3000, &row),
                  MESH_PAIRING_FINGERPRINT_MISMATCH);
        ASSERT_EQ(db_mesh_pairing_list(&ndb, &row, 1), 0);
        ASSERT_EQ(mesh_pairing_service_accept(
                      &ndb, genesis, &delegation, fingerprint, wrong, true,
                      MESH_PAIRING_CAP_STATUS_READ, 2000, 3000, &row),
                  MESH_PAIRING_SESSION_MISMATCH);
        /* A delegation bound to a foreign network never pairs, even with an
         * exact fingerprint — and no genesis row needs to exist to say so. */
        uint8_t foreign[32];
        mesh_fill32(foreign, 0xde);
        ASSERT_EQ(mesh_pairing_service_accept(
                      &ndb, foreign, &delegation, fingerprint,
                      delegation.noise_static_pubkey, true,
                      MESH_PAIRING_CAP_STATUS_READ, 2000, 3000, &row),
                  MESH_PAIRING_NETWORK_MISMATCH);
        ASSERT_EQ(db_mesh_pairing_list(&ndb, &row, 1), 0);
        ASSERT_EQ(mesh_pairing_service_accept(
                      &ndb, genesis, &delegation, fingerprint,
                      delegation.noise_static_pubkey, true,
                      MESH_PAIRING_CAP_STATUS_READ, 2000, 3000, &row),
                  MESH_PAIRING_OK);
        ASSERT(mesh_pairing_allows(&row, MESH_PAIRING_CAP_STATUS_READ, 2500));
        ASSERT(!mesh_pairing_allows(&row, MESH_PAIRING_CAP_STATUS_READ, 3000));
        struct db_mesh_pairing_counts counts;
        ASSERT(db_mesh_pairing_count_states(&ndb, 2500, &counts));
        ASSERT_EQ(counts.total, 1);
        ASSERT_EQ(counts.active, 1);
        ASSERT_EQ(counts.expired, 0);
        ASSERT_EQ(counts.revoked, 0);
        ASSERT(db_mesh_pairing_count_states(&ndb, 3000, &counts));
        ASSERT_EQ(counts.active, 0);
        ASSERT_EQ(counts.expired, 1);
        ASSERT_EQ(mesh_pairing_service_authorize_status(
                      &ndb, genesis, row.pairing_id, &delegation,
                      delegation.noise_static_pubkey, 2500),
                  MESH_PAIRING_OK);
        node_db_close(&ndb);
        ASSERT(node_db_open(&ndb, path));
        struct db_mesh_pairing persisted;
        ASSERT(db_mesh_pairing_find(&ndb, row.pairing_id, &persisted));
        ASSERT_EQ(persisted.delegation_sequence, 7);
        PASS();
    }

    TEST("mesh machine observation: exact latest receipt survives reopen") {
        struct db_mesh_pairing pairing;
        ASSERT_EQ(db_mesh_pairing_list(&ndb, &pairing, 1), 1);
        struct db_mesh_machine_observation latest;
        ASSERT(mesh_observation_fixture(&pairing, 2400, "{}", &latest));
        ASSERT(db_mesh_machine_observation_save(&ndb, &latest));
        /* An exact replay is idempotent. */
        latest.received_unix++;
        ASSERT(db_mesh_machine_observation_save(&ndb, &latest));

        struct db_mesh_machine_view view;
        ASSERT_EQ(db_mesh_machine_observation_list(&ndb, &view, 1, 2500), 1);
        ASSERT(view.has_observation);
        ASSERT_STR_EQ(view.pairing.pairing_id, pairing.pairing_id);
        ASSERT_STR_EQ(view.observation.pairing_id, pairing.pairing_id);
        ASSERT_EQ(view.observation.status, MESH_STATUS_RECEIPT_OK);
        ASSERT_EQ(view.observation.observed_unix, 2400);
        ASSERT_EQ(view.observation.expires_unix, 2430);
        ASSERT_EQ(view.observation.received_unix, 2402);
        ASSERT_EQ(view.observation.receipt_len, latest.receipt_len);
        ASSERT(memcmp(view.observation.receipt_wire, latest.receipt_wire,
                      latest.receipt_len) == 0);
        ASSERT(memcmp(view.observation.receipt_root, latest.receipt_root,
                      32) == 0);

        struct json_value machines;
        json_init(&machines);
        boot_mesh_status_machines_test_render(&ndb, 2401, &machines);
        ASSERT_STR_EQ(json_get_str(json_get(&machines, "schema")),
                      "zcl.mesh.machines.v1");
        ASSERT_EQ(json_get_int(json_get(&machines, "total")), 1);
        ASSERT_EQ(json_get_int(json_get(&machines, "returned_fresh")), 1);
        const struct json_value *items = json_get(&machines, "machines");
        const struct json_value *item = json_at(items, 0);
        ASSERT_STR_EQ(json_get_str(json_get(item, "observation_state")),
                      "fresh");
        ASSERT(json_get(item, "peer_master_pubkey") == NULL);
        ASSERT(json_get(item, "peer_noise_pubkey") == NULL);
        json_free(&machines);

        /* Stale evidence remains visible and does not become "never seen". */
        ASSERT_EQ(db_mesh_machine_observation_list(&ndb, &view, 1, 5000), 1);
        ASSERT(view.has_observation);
        ASSERT_EQ(view.observation.expires_unix, 2430);
        node_db_close(&ndb);
        ASSERT(node_db_open(&ndb, path));
        ASSERT_EQ(db_mesh_machine_observation_list(&ndb, &view, 1, 5000), 1);
        ASSERT(view.has_observation);
        ASSERT_EQ(view.observation.observed_unix, 2400);
        json_init(&machines);
        boot_mesh_status_machines_test_render(&ndb, 5000, &machines);
        ASSERT_EQ(json_get_int(json_get(&machines, "returned_stale")), 1);
        items = json_get(&machines, "machines");
        item = json_at(items, 0);
        ASSERT_STR_EQ(json_get_str(json_get(item, "observation_state")),
                      "stale");
        json_free(&machines);
        PASS();
    }

    TEST("mesh machine observation: older and same-time equivocation refuse") {
        struct db_mesh_pairing pairing;
        ASSERT_EQ(db_mesh_pairing_list(&ndb, &pairing, 1), 1);
        struct db_mesh_machine_observation older;
        ASSERT(mesh_observation_fixture(&pairing, 2300, "{}", &older));
        ASSERT(!db_mesh_machine_observation_save(&ndb, &older));
        struct db_mesh_machine_observation equivocation;
        ASSERT(mesh_observation_fixture(&pairing, 2400, "{\"changed\":true}",
                                        &equivocation));
        ASSERT(!db_mesh_machine_observation_save(&ndb, &equivocation));

        struct db_mesh_machine_observation tampered = equivocation;
        tampered.receipt_root[0] ^= 1;
        ASSERT(!db_mesh_machine_observation_save(&ndb, &tampered));
        struct db_mesh_machine_view view;
        ASSERT_EQ(db_mesh_machine_observation_list(&ndb, &view, 1, 5000), 1);
        ASSERT(view.has_observation);
        ASSERT_EQ(view.observation.observed_unix, 2400);
        ASSERT(memcmp(view.observation.receipt_root, equivocation.receipt_root,
                      32) != 0);
        PASS();
    }

    TEST("mesh machines: live probe row and durable store agree on identity") {
        /* One verified receipt feeds BOTH halves of the unified fleet view:
         * the durable observation store (through the lane's single handoff)
         * and the live sidecar row the refresh derives. Pin that both derive
         * the same pairing identity and responder Noise fingerprint from the
         * same receipt, and that the rendered document agrees. */
        struct db_mesh_pairing pairing;
        ASSERT_EQ(db_mesh_pairing_list(&ndb, &pairing, 1), 1);
        struct db_mesh_machine_observation stored;
        ASSERT(mesh_observation_fixture(&pairing, 2500, "{}", &stored));
        /* Decode the exact wire, as the status lane delivers it to the
         * persistence handoff. */
        struct mesh_status_receipt_v1 receipt;
        ASSERT_EQ(mesh_status_receipt_v1_decode(&receipt, stored.receipt_wire,
                                                stored.receipt_len),
                  MESH_STATUS_PROTO_OK);
        /* The synchronous store handoff; production writers (poll path,
         * fleet refresh, background refresh scheduler) run this same store
         * write through boot_mesh_status_receipt_persist on the serialized
         * db_service lane. */
        ASSERT(boot_mesh_status_persist_observation(&ndb, &receipt));

        struct mesh_machine_row live;
        memset(&live, 0, sizeof(live));
        snprintf(live.pairing_id, sizeof(live.pairing_id), "%s",
                 pairing.pairing_id);
        live.probed = true;
        live.state = MESH_MACHINE_ONLINE;
        ASSERT(mesh_machines_fill_live_identity(&live, &receipt));
        ASSERT_STR_EQ(live.pairing_id, pairing.pairing_id);
        ASSERT_EQ(live.observed_unix, 2500);
        uint8_t expect_fingerprint[32];
        ASSERT(v2_identity_public_fingerprint(receipt.responder_noise_static,
                                              expect_fingerprint));
        ASSERT(memcmp(expect_fingerprint, live.responder_noise_fingerprint,
                      32) == 0);

        /* The durable projection carries the same identity: receipt's
         * responder Noise key is the pairing's peer key, and the row ids
         * match the live row byte for byte. */
        struct db_mesh_machine_view view;
        ASSERT_EQ(db_mesh_machine_observation_list(&ndb, &view, 1, 2501), 1);
        ASSERT(view.has_observation);
        ASSERT_STR_EQ(view.pairing.pairing_id, live.pairing_id);
        ASSERT_STR_EQ(view.observation.pairing_id, live.pairing_id);
        ASSERT(memcmp(view.pairing.peer_noise_pubkey,
                      receipt.responder_noise_static, 32) == 0);
        ASSERT_EQ(view.observation.observed_unix, 2500);
        ASSERT_EQ(view.observation.expires_unix, 2530);

        /* The rendered document (durable evidence only, no live sidecar)
         * agrees: same pairing id, same fingerprint from the lane's one
         * shared helper, and no live keys appear. */
        struct json_value doc;
        json_init(&doc);
        boot_mesh_status_machines_test_render(&ndb, 2501, &doc);
        ASSERT_EQ(json_get_int(json_get(&doc, "returned_fresh")), 1);
        const struct json_value *item = json_at(json_get(&doc, "machines"), 0);
        ASSERT_STR_EQ(json_get_str(json_get(item, "pairing_id")),
                      live.pairing_id);
        ASSERT_STR_EQ(json_get_str(json_get(item, "observation_state")),
                      "fresh");
        char expect_hex[65];
        boot_mesh_status_key_fingerprint("zcl.mesh.noise.fingerprint.v1",
                                         receipt.responder_noise_static,
                                         expect_hex);
        ASSERT_STR_EQ(json_get_str(json_get(item, "peer_noise_fingerprint")),
                      expect_hex);
        ASSERT(json_get(item, "live_reachability") == NULL);
        json_free(&doc);
        PASS();
    }

    TEST("mesh pairing: revocation is sticky and cannot resurrect") {
        struct db_mesh_pairing row;
        ASSERT_EQ(db_mesh_pairing_list(&ndb, &row, 1), 1);
        ASSERT_EQ(mesh_pairing_service_revoke(&ndb, row.pairing_id, 2600),
                  MESH_PAIRING_OK);
        ASSERT_EQ(mesh_pairing_service_revoke(&ndb, row.pairing_id, 2700),
                  MESH_PAIRING_OK);
        node_db_close(&ndb);
        ASSERT(node_db_open(&ndb, path));
        ASSERT(db_mesh_pairing_find(&ndb, row.pairing_id, &row));
        ASSERT_EQ(row.revoked_at, 2600);
        ASSERT_EQ(row.revocation_generation, 1);
        struct db_mesh_pairing_counts counts;
        ASSERT(db_mesh_pairing_count_states(&ndb, 2800, &counts));
        ASSERT_EQ(counts.total, 1);
        ASSERT_EQ(counts.active, 0);
        ASSERT_EQ(counts.expired, 0);
        ASSERT_EQ(counts.revoked, 1);
        ASSERT_EQ(mesh_pairing_service_authorize_status(
                      &ndb, genesis, row.pairing_id, &delegation,
                      delegation.noise_static_pubkey, 2800),
                  MESH_PAIRING_ALREADY_REVOKED);
        struct db_mesh_pairing refused;
        ASSERT_EQ(mesh_pairing_service_accept(
                      &ndb, genesis, &delegation, fingerprint,
                      delegation.noise_static_pubkey, true,
                      MESH_PAIRING_CAP_STATUS_READ, 2000, 3000, &refused),
                  MESH_PAIRING_ALREADY_REVOKED);
        PASS();
    }

    TEST("pairing commands: days default, clamp boundaries, and rejection") {
        ASSERT_EQ(BOOT_MESH_PAIRING_DEFAULT_DAYS, 7);
        ASSERT_EQ(BOOT_MESH_PAIRING_MAX_DAYS, 30);
        ASSERT(boot_mesh_pairing_days_valid(1));
        ASSERT(boot_mesh_pairing_days_valid(30));
        ASSERT(!boot_mesh_pairing_days_valid(0));
        ASSERT(!boot_mesh_pairing_days_valid(-1));
        ASSERT(!boot_mesh_pairing_days_valid(31));
        ASSERT_EQ(boot_mesh_pairing_expiry(10000, 7), 10000 + 7 * 86400);
        ASSERT_EQ(boot_mesh_pairing_expiry(10000, 30), 10000 + 30 * 86400);
        /* The 30-day ceiling lands exactly on the service's own window. */
        ASSERT_EQ(BOOT_MESH_PAIRING_MAX_DAYS * 86400,
                  MESH_PAIRING_MAX_LIFETIME_SECONDS);
        PASS();
    }

    TEST("pairing commands: selector matches addr substring or fingerprint prefix") {
        char fingerprint_hex[65];
        uint8_t fp[32];
        mesh_fill32(fp, 0xab);
        zcl_hex_encode(fp, 32, fingerprint_hex);
        ASSERT(boot_mesh_pairing_selector_matches(
            "168.1", "192.168.1.7:8033", fingerprint_hex));
        ASSERT(boot_mesh_pairing_selector_matches(
            fingerprint_hex, "192.168.1.7:8033", fingerprint_hex));
        fingerprint_hex[20] = '\0'; /* prefix match on the fingerprint hex */
        ASSERT(boot_mesh_pairing_selector_matches(
            fingerprint_hex, "192.168.1.7:8033",
            "ababababababababababababababababababababababababababababababababb"));
        ASSERT(!boot_mesh_pairing_selector_matches(
            "ffff", "192.168.1.7:8033",
            "abababababababababababababababababababababababababababababababab"));
        ASSERT(boot_mesh_pairing_selector_matches(
            NULL, "192.168.1.7:8033",
            "abababababababababababababababababababababababababababababababab"));
        ASSERT(boot_mesh_pairing_selector_matches(
            "", "192.168.1.7:8033",
            "abababababababababababababababababababababababababababababababab"));
        PASS();
    }

    TEST("pairing commands: record state derives from now, revocation wins") {
        struct db_mesh_pairing row = {0};
        row.paired_at = 1000;
        row.expires_at = 3000;
        ASSERT_STR_EQ(boot_mesh_pairing_state(&row, 2500), "active");
        ASSERT_STR_EQ(boot_mesh_pairing_state(&row, 3000), "expired");
        row.revoked_at = 2600;
        ASSERT_STR_EQ(boot_mesh_pairing_state(&row, 2500), "revoked");
        ASSERT_STR_EQ(boot_mesh_pairing_state(&row, 3500), "revoked");
        PASS();
    }

    TEST("pairing commands: fingerprint decode is canonical lowercase hex") {
        uint8_t out[32];
        ASSERT(boot_mesh_pairing_decode_fingerprint(
            "abababababababababababababababababababababababababababababababab",
            out));
        ASSERT_EQ(out[0], 0xab);
        ASSERT_EQ(out[31], 0xab);
        ASSERT(!boot_mesh_pairing_decode_fingerprint("ab", out));
        ASSERT(!boot_mesh_pairing_decode_fingerprint(
            "ABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABAB",
            out));
        ASSERT(!boot_mesh_pairing_decode_fingerprint(NULL, out));
        PASS();
    }

    TEST("pairing commands: every service reason maps to a distinct named code") {
        const enum mesh_pairing_reason reasons[] = {
            MESH_PAIRING_OK, MESH_PAIRING_BAD_ARGUMENT,
            MESH_PAIRING_CAPABILITY_UNAVAILABLE,
            MESH_PAIRING_FINGERPRINT_MISMATCH, MESH_PAIRING_NETWORK_MISMATCH,
            MESH_PAIRING_MASTER_INACTIVE, MESH_PAIRING_BEACON_UNAVAILABLE,
            MESH_PAIRING_BEACON_PROVISIONAL, MESH_PAIRING_DELEGATION_INVALID,
            MESH_PAIRING_WINDOW_INVALID, MESH_PAIRING_ALREADY_REVOKED,
            MESH_PAIRING_IDENTITY_COLLISION, MESH_PAIRING_PERSIST_FAILED,
            MESH_PAIRING_NOT_FOUND, MESH_PAIRING_EXPIRED,
            MESH_PAIRING_SESSION_MISMATCH, MESH_PAIRING_AUTHORITY_CHANGED,
            MESH_PAIRING_CONFIRMATION_INVALID, MESH_PAIRING_PLAN_EXPIRED,
        };
        for (size_t i = 0; i < sizeof(reasons) / sizeof(reasons[0]); i++) {
            const char *code = boot_mesh_pairing_reason_code(reasons[i]);
            ASSERT(code && code[0]);
            for (size_t j = i + 1;
                 j < sizeof(reasons) / sizeof(reasons[0]); j++)
                ASSERT(strcmp(code,
                              boot_mesh_pairing_reason_code(reasons[j])) != 0);
        }
        ASSERT_STR_EQ(
            boot_mesh_pairing_reason_code(MESH_PAIRING_FINGERPRINT_MISMATCH),
            "FINGERPRINT_MISMATCH");
        ASSERT_STR_EQ(boot_mesh_pairing_reason_code(MESH_PAIRING_NOT_FOUND),
                      "NOT_FOUND");
        ASSERT_STR_EQ(
            boot_mesh_pairing_reason_code(MESH_PAIRING_CONFIRMATION_INVALID),
            "CONFIRMATION_INVALID");
        ASSERT_STR_EQ(boot_mesh_pairing_reason_code(MESH_PAIRING_PLAN_EXPIRED),
                      "PLAN_EXPIRED");
        PASS();
    }

    for (unsigned which = 0; which < 10; which++)
        for (unsigned layer = 0; layer < (which == 9 ? 1u : 3u); layer++)
            failures += test_mesh_pairing_malformed_row(which, layer);
    failures += test_mesh_pairing_malformed_authority();
    failures += test_mesh_observation_interrupted_step();
    failures += test_mesh_roster_page();
    for (unsigned which = 0; which < 3; which++)
        failures += test_mesh_roster_success_page(which);
    failures += test_mesh_roster_by_ids_large_capacity();
    failures += test_mesh_roster_observation_refusal(true);
    failures += test_mesh_roster_observation_refusal(false);
    for (unsigned which = 0; which < 3; which++)
        failures += test_mesh_roster_membership_refusal(which);
    for (unsigned which = 0; which < 3; which++)
        failures += test_mesh_pairing_service_read_failure(which);
    failures += test_mesh_roster_by_ids_contract(false);
    failures += test_mesh_roster_by_ids_contract(true);
    for (unsigned which = 0; which < 4; which++)
        failures += test_mesh_roster_selected_evidence(which);
    for (unsigned which = 0; which < 10; which++) {
        if (which == 4 && SIZE_MAX <= (uint64_t)INT64_MAX) {
            printf("mesh observations: unrepresentable-offset case unavailable on this size_t\n");
            continue;
        }
        failures += test_mesh_observation_boundary(which);
    }

_test_next:
    if (ndb.open)
        node_db_close(&ndb);
    test_rm_rf_recursive(dir);
    return failures;
}
