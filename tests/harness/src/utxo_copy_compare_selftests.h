/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0
 * Purpose: admitted offline stream comparator fixtures using the real readers. */
#ifndef ZCL_TEST_UTXO_COPY_COMPARE_SELFTESTS_H
#define ZCL_TEST_UTXO_COPY_COMPARE_SELFTESTS_H
#include "config/utxo_copy_compare.h"
#include "config/utxo_copy_capture_validate.h"
#include "base/hex.h"
#include "storage/utxo_mirror_schema.h"

/* Included only after the existing CSI bundle writer/fixture definitions.
 * No stream mock, canonical store, service or production failure hook. */
enum ucf_mode {
    UCF_EQUAL, UCF_AUTHORITY_ONLY, UCF_PROJECTION_ONLY, UCF_VALUE,
    UCF_SCRIPT, UCF_HEIGHT, UCF_COINBASE, UCF_ALL, UCF_BOTH_ONLY,
    UCF_CAPTURE, UCF_FRONTIER, UCF_BRANCH, UCF_NETWORK,
    UCF_ORDER, UCF_DUPLICATE, UCF_UNKNOWN, UCF_TRUST_FLAG, UCF_TAMPER, UCF_ROW_ERROR
};
struct ucf_cancel_state { unsigned calls, target; };
static bool ucf_cancel(void *context)
{
    struct ucf_cancel_state *s = context;
    s->calls++;
    return s->target && s->calls == s->target;
}
static bool ucf_file_digest(const char *path, uint8_t digest[32])
{
    FILE *f = fopen(path, "rb");
    if (!f) return false;
    struct sha3_256_ctx hash;
    sha3_256_init(&hash);
    uint8_t buf[4096]; size_t n;
    while ((n = fread(buf, 1, sizeof(buf), f)) != 0)
        sha3_256_write(&hash, buf, n);
    bool ok = !ferror(f);
    if (fclose(f) != 0) ok = false;
    if (ok) sha3_256_finalize(&hash, digest);
    return ok;
}
static size_t ucf_rows(const struct csi_fixture *bundle, enum ucf_mode mode,
                        struct csi_coin rows[3])
{
    rows[0] = bundle->coins[0]; rows[1] = bundle->coins[1];
    rows[2] = rows[1]; memset(rows[2].txid, 0xff, 32); rows[2].vout = 2;
    if (mode == UCF_VALUE || mode == UCF_ALL) rows[0].value++;
    if (mode == UCF_SCRIPT || mode == UCF_ALL) rows[0].script[0] ^= 1;
    if (mode == UCF_HEIGHT || mode == UCF_ALL) rows[0].height--;
    if (mode == UCF_COINBASE || mode == UCF_ALL) rows[0].coinbase = !rows[0].coinbase;
    if (mode == UCF_ROW_ERROR) {
        rows[0].value++; /* Accumulate a difference before the late error. */
        rows[1].height = bundle->height + 1;
    }
    if (mode == UCF_BOTH_ONLY) rows[1] = rows[2];
    return mode == UCF_AUTHORITY_ONLY ? 1 : mode == UCF_PROJECTION_ONLY ? 3 : 2;
}
static bool ucf_insert_row(sqlite3_stmt *insert, const struct csi_coin *r)
{
    return sqlite3_reset(insert) == SQLITE_OK && sqlite3_clear_bindings(insert) == SQLITE_OK &&
        sqlite3_bind_blob(insert, 1, r->txid, 32, SQLITE_TRANSIENT) == SQLITE_OK &&
        sqlite3_bind_int64(insert, 2, r->vout) == SQLITE_OK &&
        sqlite3_bind_int64(insert, 3, r->value) == SQLITE_OK &&
        sqlite3_bind_blob(insert, 4, r->script, (int)r->script_len, SQLITE_TRANSIENT) == SQLITE_OK &&
        sqlite3_bind_int(insert, 5, r->height) == SQLITE_OK &&
        sqlite3_bind_int(insert, 6, r->coinbase) == SQLITE_OK && sqlite3_step(insert) == SQLITE_DONE;
}
static bool ucf_cursor_insert(sqlite3 *db, const uint8_t cursor_bytes[8], sqlite3_stmt **cursor)
{
    return sqlite3_prepare_v2(db, "INSERT INTO node_state VALUES(?,?)", -1, cursor, NULL) == SQLITE_OK &&
        sqlite3_bind_text(*cursor, 1, UTXO_MIRROR_SYNC_CURSOR_KEY, -1, SQLITE_STATIC) == SQLITE_OK &&
        sqlite3_bind_blob(*cursor, 2, cursor_bytes, 8, SQLITE_TRANSIENT) == SQLITE_OK &&
        sqlite3_step(*cursor) == SQLITE_DONE;
}
static bool ucf_projection(const char *path, const struct csi_fixture *bundle,
    enum ucf_mode mode, enum utxo_mirror_byte_order order, uint8_t digest[32])
{
    sqlite3 *db = NULL;
    bool ok = sqlite3_open(path, &db) == SQLITE_OK;
    const char *schema =
        "CREATE TABLE node_state(key TEXT PRIMARY KEY,value BLOB);"
        "CREATE TABLE utxos(txid BLOB NOT NULL,vout INTEGER NOT NULL,"
        "value INTEGER NOT NULL CHECK(value>=0 AND value<=2100000000000000),"
        "script BLOB NOT NULL,script_type INTEGER NOT NULL DEFAULT 0,"
        "address_hash BLOB,height INTEGER NOT NULL CHECK(height>=0),"
        "is_coinbase INTEGER NOT NULL DEFAULT 0,PRIMARY KEY(txid,vout));";
    if (ok) ok = sqlite3_exec(db, schema, NULL, NULL, NULL) == SQLITE_OK;
    sqlite3_stmt *cursor = NULL, *insert = NULL;
    /* Explicit producer-native int64 BLOB bytes for the selected fixture
     * producer order; never let the test host's endianness select encoding. */
    uint64_t frontier = (uint64_t)bundle->height + 1u;
    uint8_t cursor_bytes[8];
    for (unsigned i = 0; i < 8; i++) {
        unsigned at = order == UTXO_MIRROR_LITTLE_ENDIAN ? i : 7u - i;
        cursor_bytes[at] = (uint8_t)(frontier >> (8u * i));
    }
    if (ok) ok = ucf_cursor_insert(db, cursor_bytes, &cursor);
    int cursor_done = sqlite3_finalize(cursor);
    struct csi_coin rows[3];
    size_t count = ucf_rows(bundle, mode, rows);
    if (ok) ok = sqlite3_prepare_v2(db,
        "INSERT INTO utxos(txid,vout,value,script,height,is_coinbase) VALUES(?,?,?,?,?,?)",
        -1, &insert, NULL) == SQLITE_OK;
    for (size_t i = 0; ok && i < count; i++) {
        ok = ucf_insert_row(insert, &rows[i]);
    }
    int rows_done = sqlite3_finalize(insert);
    int closed = sqlite3_close(db);
    return ok && cursor_done == SQLITE_OK && rows_done == SQLITE_OK && closed == SQLITE_OK &&
        chmod(path, 0400) == 0 && ucf_file_digest(path, digest);
}
struct ucf_manifest {
    struct json_value json;
    const struct chain_params *network;
    char raw[8192];
    size_t length;
    uint8_t accepted_sha3[32];
};
static bool ucf_push_hash(struct json_value *v, const char *key, const uint8_t hash[32])
{
    char hex[65];
    zcl_hex_encode(hash, 32, hex);
    return json_push_kv_str(v, key, hex);
}
static bool ucf_external_fields(struct json_value *v)
{
    /* Synthetic coherent-capture acceptance belongs ONLY to this fixture;
     * these statements do not constitute real-world capture evidence. */
    return json_push_kv_str(v, "schema", "zcl.utxo_copy_capture.v1") &&
        json_push_kv_str(v, "capture_id", "fixture-capture") &&
        json_push_kv_str(v, "capture_method", "completed_backup") &&
        json_push_kv_str(v, "producer_id", "fixture-producer/v1") &&
        json_push_kv_str(v, "owner_evidence_ref", "fixture-owner") &&
        json_push_kv_int(v, "quiescence_start_us", 100) &&
        json_push_kv_int(v, "quiescence_end_us", 101) &&
        json_push_kv_str(v, "quiescence_scope", "both-copied-stores") &&
        json_push_kv_str(v, "overlay_disposition", "absent") &&
        json_push_kv_str(v, "authority_generation", "7") &&
        json_push_kv_str(v, "backup_completion_ref", "fixture-completed-backup");
}
static bool ucf_source_fields(struct json_value *v)
{
    const char *const absent[] = {
        "authority_wal_disposition", "authority_shm_disposition", "authority_journal_disposition",
        "projection_wal_disposition", "projection_shm_disposition", "projection_journal_disposition"
    };
    for (size_t i = 0; i < sizeof(absent) / sizeof(absent[0]); i++)
        if (!json_push_kv_str(v, absent[i], "absent")) return false;
    return json_push_kv_str(v, "authority_source_object_id", "fixture-authority-source") &&
        json_push_kv_str(v, "projection_source_object_id", "fixture-projection-source");
}
static bool ucf_authority_fields(struct json_value *v,
    const struct consensus_state_artifact_evidence *ev,
    const struct consensus_state_bundle_manifest *m, enum ucf_mode mode)
{
    uint8_t file[32], branch[32];
    memcpy(branch, m->block_hash, 32);
    if (mode == UCF_BRANCH) branch[0] ^= 1;
    int64_t next = (int64_t)m->height + 1 + (mode == UCF_FRONTIER);
    if (!consensus_state_artifact_evidence_file_digest(ev, file)) return false;
    return ucf_push_hash(v, "authority_file_sha3", file) &&
        ucf_push_hash(v, "artifact_digest", m->artifact_digest) &&
        json_push_kv_int(v, "authority_next_height", next) &&
        json_push_kv_int(v, "authority_last_applied_height", m->height) &&
        ucf_push_hash(v, "authority_block_hash", m->block_hash) &&
        json_push_kv_int(v, "projection_branch_height", m->height) &&
        ucf_push_hash(v, "projection_branch_hash", branch);
}
static bool ucf_projection_fields(struct json_value *v,
    const struct utxo_mirror_read_attestation *p, enum ucf_mode mode)
{
    char size[32];
    int n = snprintf(size, sizeof(size), "%llu", (unsigned long long)p->file.size);
    if (n < 0 || (size_t)n >= sizeof(size)) return false;
    const char *order = NULL;
    if (p->producer_order == UTXO_MIRROR_LITTLE_ENDIAN) order = "little";
    if (p->producer_order == UTXO_MIRROR_BIG_ENDIAN) order = "big";
    if (!order) return false;
    if (mode == UCF_ORDER) order = p->producer_order == UTXO_MIRROR_LITTLE_ENDIAN ? "big" : "little";
    return ucf_push_hash(v, "projection_file_sha3", p->file_sha3) &&
        json_push_kv_str(v, "projection_size", size) &&
        json_push_kv_int(v, "projection_next_height", p->next_height) &&
        json_push_kv_str(v, "producer_byte_order", order);
}
/* Replace a required member rather than simply appending: the duplicate
 * case preserves exact member count and reaches duplicate-name validation. */
static bool ucf_replace_member(struct json_value *v, const char *key,
                                const char *replacement, bool trust_flag)
{
    struct json_value changed = {0}, value = {0};
    json_set_object(&changed);
    if (trust_flag) json_set_bool(&value, true);
    else json_set_str(&value, "fixture-capture");
    bool ok = true;
    for (size_t i = 0; ok && i < v->num_children; i++) {
        bool replacing = strcmp(v->keys[i], key) == 0;
        ok = json_push_kv(&changed, replacing ? replacement : v->keys[i],
            replacing ? &value : &v->children[i]);
    }
    json_free(&value);
    if (ok) { json_free(v); *v = changed; }
    else json_free(&changed);
    return ok;
}
static bool ucf_manifest_mutation(struct json_value *v, enum ucf_mode mode)
{
    if (mode == UCF_DUPLICATE) return ucf_replace_member(v, "producer_id", "capture_id", false);
    if (mode == UCF_UNKNOWN) return ucf_replace_member(v, "producer_id", "unknown_field", false);
    if (mode == UCF_TRUST_FLAG) return ucf_replace_member(v, "producer_id", "manifest_validated", true);
    return true;
}
static bool ucf_manifest_build(struct ucf_manifest *manifest,
    const struct consensus_state_artifact_evidence *ev,
    struct utxo_mirror_read_snapshot *projection, enum ucf_mode mode)
{
    struct consensus_state_bundle_manifest m;
    struct utxo_mirror_read_attestation p;
    manifest->network = chain_params_get();
    if (!manifest->network || !consensus_state_artifact_evidence_manifest_copy(ev, &m) ||
        !utxo_mirror_read_snapshot_attestation(projection, &p)) return false;
    uint8_t genesis[32];
    memcpy(genesis, manifest->network->consensus.hashGenesisBlock.data, 32);
    if (mode == UCF_NETWORK) genesis[0] ^= 1;
    json_set_object(&manifest->json);
    if (!ucf_external_fields(&manifest->json) || !ucf_source_fields(&manifest->json) ||
        !ucf_authority_fields(&manifest->json, ev, &m, mode) ||
        !ucf_projection_fields(&manifest->json, &p, mode) ||
        !ucf_push_hash(&manifest->json, "network_genesis", genesis)) return false;
    return ucf_manifest_mutation(&manifest->json, mode);
}
static bool ucf_manifest_serialize(struct ucf_manifest *manifest, enum ucf_mode mode)
{
    manifest->length = json_write(&manifest->json, manifest->raw, sizeof(manifest->raw));
    if (manifest->length >= sizeof(manifest->raw) - 1) return false;
    struct sha3_256_ctx hash;
    sha3_256_init(&hash);
    sha3_256_write(&hash, (const unsigned char *)manifest->raw, manifest->length);
    sha3_256_finalize(&hash, manifest->accepted_sha3);
    /* Still valid JSON, but no longer the exact fixture-accepted bytes. */
    if (mode == UCF_TAMPER) manifest->raw[manifest->length++] = ' ';
    manifest->raw[manifest->length] = '\0';
    return true;
}
static bool ucf_capture(
    const struct consensus_state_artifact_evidence *ev,
    struct utxo_mirror_read_snapshot *projection, enum ucf_mode mode,
    struct utxo_copy_capture **capture, enum utxo_copy_capture_status *status)
{
    struct ucf_manifest manifest = {0};
    *capture = NULL;
    bool ok = ucf_manifest_build(&manifest, ev, projection, mode) &&
        ucf_manifest_serialize(&manifest, mode);
    *status = UTXO_COPY_CAPTURE_ERROR;
    if (ok) {
        struct utxo_copy_capture_request request = {
            .manifest = manifest.raw, .manifest_len = manifest.length,
            .accepted_manifest_sha3 = mode == UCF_CAPTURE ? NULL : manifest.accepted_sha3,
            .network = manifest.network, .authority = ev, .projection = projection
        };
        *status = utxo_copy_capture_open(&request, capture);
    }
    json_free(&manifest.json);
    return ok;
}
static bool ucf_invalid_report(const struct utxo_copy_compare_report *report)
{
    struct utxo_copy_compare_report copy;
    uint8_t zero[sizeof(copy)];
    memset(zero, 0, sizeof(zero));
    memcpy(&copy, report, sizeof(copy));
    copy.status = 0; copy.failure = 0;
    return memcmp(&copy, zero, sizeof(copy)) == 0;
}
static uint32_t ucf_mask(enum ucf_mode mode)
{
    if (mode == UCF_VALUE) return UTXO_COPY_FIELD_VALUE;
    if (mode == UCF_SCRIPT) return UTXO_COPY_FIELD_SCRIPT;
    if (mode == UCF_HEIGHT) return UTXO_COPY_FIELD_HEIGHT;
    if (mode == UCF_COINBASE) return UTXO_COPY_FIELD_COINBASE;
    return mode == UCF_ALL ? 15u : 0;
}
/* Independent fixture wire layout at explicit offsets; do not call the
 * production commitment encoder to manufacture its own expected answer. */
static bool ucf_expected_root(const struct csi_coin *rows, size_t count, uint8_t root[32])
{
    struct sha3_256_ctx hash;
    sha3_256_init(&hash);
    for (size_t i = 0; i < count; i++) {
        const struct csi_coin *r = &rows[i];
        uint8_t record[56] = {0};
        if (r->script_len > sizeof(r->script) || r->script_len > sizeof(record) - 53u)
            return false;
        memcpy(record, r->txid, 32);
        for (unsigned j = 0; j < 4; j++) record[32 + j] = (uint8_t)(r->vout >> (8u * j));
        for (unsigned j = 0; j < 8; j++) record[36 + j] = (uint8_t)((uint64_t)r->value >> (8u * j));
        for (unsigned j = 0; j < 4; j++) record[44 + j] = (uint8_t)((uint32_t)r->script_len >> (8u * j));
        memcpy(record + 48, r->script, r->script_len);
        for (unsigned j = 0; j < 4; j++) record[48 + r->script_len + j] = (uint8_t)((uint32_t)r->height >> (8u * j));
        record[52 + r->script_len] = r->coinbase ? 1 : 0;
        sha3_256_write(&hash, record, 53 + r->script_len);
    }
    sha3_256_finalize(&hash, root);
    return true;
}
static bool ucf_example_side(const struct csi_coin *row, int64_t value,
                              uint64_t length, const uint8_t digest[32])
{
    uint8_t expected[32] = {0};
    if (!row) return value == 0 && length == 0 && memcmp(digest, expected, 32) == 0;
    if (row->script_len > sizeof(row->script)) return false;
    struct sha3_256_ctx hash;
    sha3_256_init(&hash);
    if (row->script_len) sha3_256_write(&hash, row->script, row->script_len);
    sha3_256_finalize(&hash, expected);
    return value == row->value && length == row->script_len && memcmp(digest, expected, 32) == 0;
}
static bool ucf_example_matches(const struct utxo_copy_compare_example *e,
                                 enum utxo_copy_example_kind kind, uint32_t fields,
                                 const struct csi_coin *authority, const struct csi_coin *projection)
{
    const struct csi_coin *key = authority ? authority : projection;
    return key && e->kind == kind && e->fields == fields &&
        memcmp(e->txid, key->txid, 32) == 0 && e->vout == key->vout &&
        ucf_example_side(authority, e->authority_value, e->authority_script_len, e->authority_script_sha3) &&
        ucf_example_side(projection, e->projection_value, e->projection_script_len, e->projection_script_sha3);
}
static bool ucf_examples(const struct utxo_copy_compare_report *r,
                          const struct csi_fixture *bundle, const struct csi_coin rows[3],
                          enum ucf_mode mode)
{
    if (!r->example_count) return true;
    if (ucf_mask(mode)) return r->example_count == 1 &&
        ucf_example_matches(&r->examples[0], UTXO_COPY_SHARED_DIFFERENT, ucf_mask(mode),
                            &bundle->coins[0], &rows[0]);
    if (mode == UCF_PROJECTION_ONLY) return r->example_count == 1 &&
        ucf_example_matches(&r->examples[0], UTXO_COPY_PROJECTION_ONLY, 0, NULL, &rows[2]);
    if (mode == UCF_AUTHORITY_ONLY || mode == UCF_BOTH_ONLY) {
        if (!ucf_example_matches(&r->examples[0], UTXO_COPY_AUTHORITY_ONLY, 0,
                                 &bundle->coins[1], NULL)) return false;
        return r->example_count == 1 || (mode == UCF_BOTH_ONLY && r->example_count == 2 &&
            ucf_example_matches(&r->examples[1], UTXO_COPY_PROJECTION_ONLY, 0, NULL, &rows[1]));
    }
    return false;
}
static bool ucf_report_details(const struct utxo_copy_compare_report *r,
                               enum ucf_mode mode, unsigned limit,
                               uint64_t ao, uint64_t po, uint64_t different)
{
    uint64_t equal = mode == UCF_EQUAL || mode == UCF_PROJECTION_ONLY ? 2 : 1;
    unsigned examples = (unsigned)(ao + po + different);
    return r->authority_only == ao && r->projection_only == po &&
        r->shared_equal == equal && r->shared_different == different &&
        r->shared_fields == ucf_mask(mode) && r->count_delta_negative == (ao > po) &&
        r->count_delta_magnitude == (ao > po ? ao - po : po - ao) &&
        r->example_count == (examples < limit ? examples : limit) &&
        r->examples_truncated == (examples > limit);
}
static bool ucf_report_counts(const struct utxo_copy_compare_report *r,
                              enum ucf_mode mode, unsigned limit)
{
    uint64_t ao = mode == UCF_AUTHORITY_ONLY || mode == UCF_BOTH_ONLY;
    uint64_t po = mode == UCF_PROJECTION_ONLY || mode == UCF_BOTH_ONLY;
    uint64_t different = ucf_mask(mode) != 0;
    unsigned examples = (unsigned)(ao + po + different);
    bool changed = examples != 0;
    return r->complete && r->counts_valid && r->roots_valid &&
        r->status == (changed ? UTXO_COPY_COMPARE_DIFFERENT : UTXO_COPY_COMPARE_EQUAL) &&
        r->failure == UTXO_COPY_FAILURE_NONE && r->authority_count == 2 &&
        r->projection_count == (mode == UCF_AUTHORITY_ONLY ? 1u : mode == UCF_PROJECTION_ONLY ? 3u : 2u) &&
        ucf_report_details(r, mode, limit, ao, po, different);
}
static bool ucf_valid_report(const struct utxo_copy_compare_report *r,
                              const struct csi_fixture *bundle, const uint8_t projection_digest[32],
                              enum ucf_mode mode, unsigned limit)
{
    struct csi_coin rows[3];
    size_t count = ucf_rows(bundle, mode, rows);
    uint8_t authority_root[32], projection_root[32];
    bool roots = ucf_expected_root(bundle->coins, 2, authority_root) &&
        ucf_expected_root(rows, count, projection_root);
    bool ok = roots && ucf_report_counts(r, mode, limit) &&
        r->capture_binding == UTXO_COPY_CAPTURE_EXTERNALLY_ATTESTED &&
        memcmp(r->authority_root, authority_root, 32) == 0 &&
        memcmp(r->projection_root, projection_root, 32) == 0 &&
        memcmp(r->projection_file_sha3, projection_digest, 32) == 0 &&
        r->next_height == bundle->height + 1 && r->last_applied_height == bundle->height;
    return ok && ucf_examples(r, bundle, rows, mode);
}
struct ucf_owners {
    struct consensus_state_artifact_evidence *authority;
    struct utxo_mirror_read_snapshot *projection;
    struct utxo_copy_capture *capture;
    char path[1024];
    uint8_t digest[32];
};
static bool ucf_fixture_path(const char *dir, char path[1024])
{
    static unsigned serial;
    char absolute[PATH_MAX];
    if (!realpath(dir, absolute) || strlen(absolute) + 32 >= 1024) return false;
    int n = snprintf(path, 1024, "%s/compare-%u.db", absolute, ++serial);
    return n >= 0 && n < 1024;
}
static bool ucf_admit_projection(struct ucf_owners *owners, const struct csi_fixture *bundle,
                                 enum utxo_mirror_byte_order order)
{
    int32_t height = -1;
    return utxo_mirror_read_snapshot_open(owners->path, order, owners->digest,
        &owners->projection, &height) && height == bundle->height + 1;
}
static bool ucf_owners_open(struct ucf_owners *owners, const char *dir,
    const struct csi_fixture *bundle, enum ucf_mode mode, enum utxo_mirror_byte_order order)
{
    if (order != UTXO_MIRROR_LITTLE_ENDIAN && order != UTXO_MIRROR_BIG_ENDIAN) return false;
    if (!ucf_fixture_path(dir, owners->path)) return false;
    if (!ucf_projection(owners->path, bundle, mode, order, owners->digest)) return false;
    struct zcl_result opened = consensus_state_artifact_evidence_open(bundle->path, -1,
        &owners->authority);
    if (!opened.ok || !owners->authority) return false;
    return ucf_admit_projection(owners, bundle, order);
}
static bool ucf_factory_negative(enum ucf_mode mode)
{
    return mode >= UCF_CAPTURE && mode <= UCF_TAMPER;
}
static enum utxo_copy_capture_status ucf_factory_expected(enum ucf_mode mode)
{
    if (mode == UCF_DUPLICATE || mode == UCF_UNKNOWN || mode == UCF_TRUST_FLAG)
        return UTXO_COPY_CAPTURE_ERROR;
    return UTXO_COPY_CAPTURE_NOT_COMPARABLE;
}
static bool ucf_run_comparison(struct ucf_owners *owners, const struct csi_fixture *bundle,
                                enum ucf_mode mode, unsigned limit, unsigned cancel_at)
{
    struct ucf_cancel_state cancel = {0, cancel_at};
    struct utxo_copy_compare_inputs in = {
        .authority = owners->authority, .projection = &owners->projection,
        .capture = owners->capture, .example_limit = limit,
        .cancelled = ucf_cancel, .cancel_ctx = &cancel
    };
    struct utxo_copy_compare_report result;
    memset(&result, 0xa5, sizeof(result));
    enum utxo_copy_compare_status status = utxo_copy_compare_run(&in, &result);
    bool ok;
    if (limit > UTXO_COPY_COMPARE_EXAMPLE_MAX) ok = status == UTXO_COPY_COMPARE_ERROR &&
        result.failure == UTXO_COPY_FAILURE_INPUT && ucf_invalid_report(&result);
    else if (cancel_at) ok = status == UTXO_COPY_COMPARE_CANCELLED &&
        result.failure == UTXO_COPY_FAILURE_CANCEL && cancel.calls == cancel_at && ucf_invalid_report(&result);
    else if (mode == UCF_ROW_ERROR) ok = status == UTXO_COPY_COMPARE_ERROR &&
        result.failure == UTXO_COPY_FAILURE_PROJECTION_NEXT && ucf_invalid_report(&result);
    else ok = ucf_valid_report(&result, bundle, owners->digest, mode, limit);
    return ok && owners->projection == NULL;
}
static bool ucf_owners_close(struct ucf_owners *owners)
{
    utxo_copy_capture_free(owners->capture); owners->capture = NULL;
    bool projection_closed = !owners->projection || utxo_mirror_read_snapshot_abort(&owners->projection);
    bool authority_closed = consensus_state_artifact_evidence_close(&owners->authority);
    /* A retained callback owner must keep its fixture file alive on failure. */
    if (!owners->projection && !owners->authority && owners->path[0]) TEST_DISCARD(unlink(owners->path));
    return projection_closed && authority_closed && !owners->projection && !owners->authority;
}
static bool ucf_case_order(const char *dir, const struct csi_fixture *bundle,
    enum ucf_mode mode, unsigned limit, unsigned cancel_at, enum utxo_mirror_byte_order order)
{
    struct ucf_owners owners = {0};
    bool ok = ucf_owners_open(&owners, dir, bundle, mode, order);
    enum utxo_copy_capture_status admitted = UTXO_COPY_CAPTURE_ERROR;
    if (ok) ok = ucf_capture(owners.authority, owners.projection, mode, &owners.capture, &admitted);
    if (ok && ucf_factory_negative(mode)) {
        /* Constructor refusal is NOT a comparator verdict. No report exists,
         * and neither borrowed owner may have been consumed by the factory. */
        ok = admitted == ucf_factory_expected(mode) && owners.capture == NULL &&
            owners.authority != NULL && owners.projection != NULL;
    } else if (ok) {
        ok = admitted == UTXO_COPY_CAPTURE_VALIDATED && owners.capture != NULL;
        if (ok) ok = ucf_run_comparison(&owners, bundle, mode, limit, cancel_at);
    }
    bool closed = ucf_owners_close(&owners);
    return ok && closed;
}
static bool ucf_case(const char *dir, const struct csi_fixture *bundle,
                      enum ucf_mode mode, unsigned limit, unsigned cancel_at)
{
    uint16_t endian = 1;
    enum utxo_mirror_byte_order order = *(uint8_t *)&endian ?
        UTXO_MIRROR_LITTLE_ENDIAN : UTXO_MIRROR_BIG_ENDIAN;
    return ucf_case_order(dir, bundle, mode, limit, cancel_at, order);
}
static int csi_compare_cases(const char *dir, const struct csi_fixture *bundle)
{
    int failures = 0;
    struct csi_coin oversized = bundle->coins[0];
    uint8_t unused_root[32];
    oversized.script_len = sizeof(oversized.script) + 1u;
    CSI_CHECK("offline comparator independent root fixture refuses oversized script",
        !ucf_expected_root(&oversized, 1, unused_root));
    for (unsigned mode = UCF_EQUAL; mode <= UCF_ROW_ERROR; mode++) {
        char label[96];
        snprintf(label, sizeof(label), "offline comparator admitted fixture mode %u", mode);
        CSI_CHECK(label, ucf_case(dir, bundle, (enum ucf_mode)mode, 32, 0));
    }
    CSI_CHECK("offline comparator real little-endian capture admits and compares",
        ucf_case_order(dir, bundle, UCF_EQUAL, 32, 0, UTXO_MIRROR_LITTLE_ENDIAN));
    CSI_CHECK("offline comparator real big-endian capture admits and compares",
        ucf_case_order(dir, bundle, UCF_EQUAL, 32, 0, UTXO_MIRROR_BIG_ENDIAN));
    CSI_CHECK("offline comparator zero sample budget keeps exact totals",
        ucf_case(dir, bundle, UCF_BOTH_ONLY, 0, 0));
    CSI_CHECK("offline comparator one sample truncates independently of totals",
        ucf_case(dir, bundle, UCF_BOTH_ONLY, 1, 0));
    CSI_CHECK("offline comparator excess sample limit rejects input and clears report",
        ucf_case(dir, bundle, UCF_EQUAL, UTXO_COPY_COMPARE_EXAMPLE_MAX + 1u, 0));
    CSI_CHECK("offline comparator cancellation before traversal clears report",
        ucf_case(dir, bundle, UCF_EQUAL, 32, 1));
    CSI_CHECK("offline comparator cancellation after first row clears report",
        ucf_case(dir, bundle, UCF_EQUAL, 32, 3));
    /* Exactly two equal rows: initial poll, two merge polls, pre-finish,
     * post-finish, final post-revalidation poll. v1 has no sixth poll, so
     * it incorrectly publishes EQUAL and this regression must fail. */
    CSI_CHECK("offline comparator final post-revalidation cancellation clears report",
        ucf_case(dir, bundle, UCF_EQUAL, 32, 6));
    return failures;
}
#endif
