/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * getutxocommitment and getutxoaudit (core.consensus.utxo.commitment / .audit)
 * must name the running build, so a consensus-parity result is tied to the
 * exact binary that computed it. Isolated fixture: an in-memory node.db and a
 * fresh progress store under test-tmp. Reporting only: the commitment fields
 * are asserted unchanged. */

#include "test/test_core.h"

#include "controllers/blockchain_controller.h"
#include "json/json.h"
#include "models/database.h"
#include "storage/coins_kv.h"
#include "storage/progress_store.h"
#include "util/clientversion.h"
#include "validation/main_state.h"

#include <limits.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>

bool rpc_getutxocommitment(const struct json_value *params, bool help,
                           struct json_value *result);
bool rpc_getutxoaudit(const struct json_value *params, bool help,
                      struct json_value *result);

#define UBI_CHECK(name, expr) do {                              \
    printf("utxo_build_identity: %s... ", (name));              \
    if (expr) { printf("OK\n"); }                               \
    else { printf("FAIL\n"); failures++; }                      \
} while (0)

/* The reply carries a "build" object whose source_id_sha256 is non-empty and
 * equals the running binary's own source id. */
static bool ubi_names_build(const struct json_value *res)
{
    const struct json_value *b = json_get(res, "build");
    if (!b) return false;
    const char *id = json_get_str(json_get(b, "source_id_sha256"));
    return id && id[0] && strcmp(id, zcl_build_source_id_sha256()) == 0 &&
           json_get_str(json_get(b, "build_commit")) != NULL;
}

static bool ubi_call(bool (*fn)(const struct json_value *, bool,
                                struct json_value *),
                     struct json_value *res)
{
    struct json_value params;
    json_init(&params);
    json_set_array(&params);
    json_init(res);
    bool ok = fn(&params, false, res);
    json_free(&params);
    return ok;
}

static int ubi_check_replies(void)
{
    int failures = 0;
    struct json_value res;

    bool ok = ubi_call(rpc_getutxocommitment, &res);
    UBI_CHECK("commitment replies", ok);
    UBI_CHECK("commitment keeps sha3_hash/height/utxo_count",
              json_get(&res, "sha3_hash") && json_get(&res, "height") &&
              json_get(&res, "utxo_count"));
    UBI_CHECK("commitment names the running build", ubi_names_build(&res));
    json_free(&res);

    ok = ubi_call(rpc_getutxoaudit, &res);
    UBI_CHECK("audit replies", ok);
    UBI_CHECK("audit keeps local_sha3/local_utxo_count",
              json_get(&res, "local_sha3") && json_get(&res, "local_utxo_count"));
    UBI_CHECK("audit names the running build", ubi_names_build(&res));
    json_free(&res);
    return failures;
}

int test_utxo_build_identity(void);
int test_utxo_build_identity(void)
{
    printf("\n=== UTXO commitment/audit name the running build ===\n");
    int failures = 0;

    test_reset_shared_globals();

    char dir[PATH_MAX];
    UBI_CHECK("fixture: temp datadir", test_mkdtemp(dir, sizeof(dir), "ubi"));
    if (failures) return failures;

    static struct node_db ndb;
    static struct main_state ms;
    memset(&ndb, 0, sizeof(ndb));
    bool dbok = node_db_open(&ndb, ":memory:");
    UBI_CHECK("fixture: in-memory node_db opens", dbok);
    bool psok = dbok && progress_store_open(dir) &&
                coins_kv_ensure_schema(progress_store_db());
    UBI_CHECK("fixture: progress store + coins schema", psok);
    if (psok) {
        main_state_init(&ms);
        rpc_blockchain_set_state(&ms, NULL, NULL);
        rpc_blockchain_set_node_db(&ndb);
        failures += ubi_check_replies();
        rpc_blockchain_set_node_db(NULL);
        rpc_blockchain_set_state(NULL, NULL, NULL);
        progress_store_close();
    }
    if (dbok) node_db_close(&ndb);
    test_rm_rf(dir);
    return failures;
}
