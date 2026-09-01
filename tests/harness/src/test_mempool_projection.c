/* Copyright 2026 Rhett Creighton - Apache License 2.0 */

#include "test/test_core.h"

#include "storage/event_log.h"
#include "storage/event_log_payloads.h"
#include "storage/mempool_projection.h"
#include "models/database.h"
#include "models/mempool_entry.h"

#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#define MP_CHECK(label, cond) do { \
    bool _ok = (cond); \
    printf("mempool_projection: %s... %s\n", (label), _ok ? "OK" : "FAIL"); \
    if (!_ok) failures++; \
} while (0)


static void fill_txid(uint8_t txid[32], uint8_t seed)
{
    for (size_t i = 0; i < 32; i++)
        txid[i] = (uint8_t)(seed + i);
}

static bool append_admit(event_log_t *log, const uint8_t txid[32],
                         int64_t fee, uint32_t size, uint32_t weight)
{
    static const uint8_t raw[] = {0x01, 0x02, 0x03, 0x04};
    struct ev_tx_admit_mempool ev;
    uint8_t payload[EV_TX_ADMIT_MEMPOOL_FIXED_LEN + sizeof(raw)];
    size_t len = 0;
    memset(&ev, 0, sizeof(ev));
    memcpy(ev.txid, txid, 32);
    ev.fee = fee;
    ev.size_bytes = size;
    ev.weight = weight;
    ev.admitted_unix = 1700000000u;
    ev.raw_tx = raw;
    ev.raw_tx_len = sizeof(raw);
    if (!ev_tx_admit_mempool_serialize(&ev, payload, sizeof(payload), &len))
        return false;
    return event_log_append(log, EV_TX_ADMIT_MEMPOOL, payload, len) != UINT64_MAX;
}

static bool append_remove(event_log_t *log, const uint8_t txid[32])
{
    struct ev_tx_remove_mempool ev;
    uint8_t payload[EV_TX_REMOVE_MEMPOOL_LEN];
    memset(&ev, 0, sizeof(ev));
    memcpy(ev.txid, txid, 32);
    ev.reason = 3;
    if (!ev_tx_remove_mempool_serialize(&ev, payload))
        return false;
    return event_log_append(log, EV_TX_REMOVE_MEMPOOL,
                            payload, sizeof(payload)) != UINT64_MAX;
}

static int t_payload_roundtrip(void)
{
    int failures = 0;
    uint8_t raw[] = {0xaa, 0xbb, 0xcc};
    uint8_t payload[EV_TX_ADMIT_MEMPOOL_FIXED_LEN + sizeof(raw)];
    struct ev_tx_admit_mempool in, out;
    size_t len = 0;
    memset(&in, 0, sizeof(in));
    fill_txid(in.txid, 7);
    in.fee = 12345;
    in.size_bytes = sizeof(raw);
    in.weight = 99;
    in.admitted_unix = 1700000001u;
    in.priority_class = 2;
    in.raw_tx = raw;
    in.raw_tx_len = sizeof(raw);
    MP_CHECK("admit serialize",
             ev_tx_admit_mempool_serialize(&in, payload, sizeof(payload),
                                           &len));
    MP_CHECK("admit parse",
             ev_tx_admit_mempool_parse(payload, len, &out));
    MP_CHECK("admit roundtrip",
             memcmp(in.txid, out.txid, 32) == 0 &&
             out.fee == in.fee &&
             out.size_bytes == in.size_bytes &&
             out.weight == in.weight &&
             out.admitted_unix == in.admitted_unix &&
             out.priority_class == in.priority_class &&
             out.raw_tx_len == sizeof(raw) &&
             memcmp(out.raw_tx, raw, sizeof(raw)) == 0);

    struct ev_tx_remove_mempool rin, rout;
    uint8_t removed[EV_TX_REMOVE_MEMPOOL_LEN];
    memset(&rin, 0, sizeof(rin));
    fill_txid(rin.txid, 22);
    rin.reason = 4;
    MP_CHECK("remove serialize",
             ev_tx_remove_mempool_serialize(&rin, removed));
    MP_CHECK("remove parse",
             ev_tx_remove_mempool_parse(removed, sizeof(removed), &rout));
    MP_CHECK("remove roundtrip",
             memcmp(rin.txid, rout.txid, 32) == 0 &&
             rout.reason == rin.reason);
    return failures;
}

static int t_add_remove_replay(void)
{
    int failures = 0;
    char dir[256], elog_path[300], proj_path[300];
    uint8_t txid[32];
    int64_t fee = 0;
    uint32_t size = 0, weight = 0;
    test_make_tmpdir(dir, sizeof(dir), "mempool_projection", "addremove");
    test_projection_paths(dir, "mempool", elog_path, sizeof(elog_path),
                          proj_path, sizeof(proj_path));
    fill_txid(txid, 42);
    event_log_t *log = event_log_open(elog_path);
    mempool_projection_t *p = mempool_projection_open(proj_path, log);
    MP_CHECK("open handles", log && p);
    MP_CHECK("append admit", append_admit(log, txid, 5000, 4, 16));
    MP_CHECK("catch up admit", mempool_projection_catch_up(p) != UINT64_MAX);
    MP_CHECK("count after admit", mempool_projection_count(p) == 1);
    MP_CHECK("get admitted",
             mempool_projection_get(p, txid, &fee, &size, &weight) &&
             fee == 5000 && size == 4 && weight == 16);
    MP_CHECK("totals after admit",
             mempool_projection_total_fee(p) == 5000 &&
             mempool_projection_total_weight(p) == 16);
    MP_CHECK("idempotent catch up", mempool_projection_catch_up(p) != UINT64_MAX);
    MP_CHECK("append remove", append_remove(log, txid));
    MP_CHECK("catch up remove", mempool_projection_catch_up(p) != UINT64_MAX);
    MP_CHECK("count after remove", mempool_projection_count(p) == 0);
    MP_CHECK("get absent",
             !mempool_projection_get(p, txid, NULL, NULL, NULL));
    mempool_projection_close(p);
    event_log_close(log);
    test_cleanup_tmpdir(dir);
    return failures;
}

struct iter_ctx {
    uint8_t first_bytes[8];
    int count;
};

static bool iter_cb(const uint8_t txid[32], int64_t fee,
                    uint32_t size_bytes, uint32_t weight, void *user)
{
    (void)fee;
    (void)size_bytes;
    (void)weight;
    struct iter_ctx *ctx = user;
    if (!ctx || ctx->count >= (int)(sizeof(ctx->first_bytes) /
                                    sizeof(ctx->first_bytes[0])))
        return false;
    ctx->first_bytes[ctx->count++] = txid[0];
    return true;
}

static int t_iterate_sorted(void)
{
    int failures = 0;
    char dir[256], elog_path[300], proj_path[300];
    uint8_t txid1[32], txid2[32], txid3[32];
    struct iter_ctx ctx = {0};
    test_make_tmpdir(dir, sizeof(dir), "mempool_projection", "iter");
    test_projection_paths(dir, "mempool", elog_path, sizeof(elog_path),
                          proj_path, sizeof(proj_path));
    fill_txid(txid1, 3);
    fill_txid(txid2, 1);
    fill_txid(txid3, 2);
    event_log_t *log = event_log_open(elog_path);
    mempool_projection_t *p = mempool_projection_open(proj_path, log);
    MP_CHECK("append iter 3", append_admit(log, txid1, 300, 4, 12));
    MP_CHECK("append iter 1", append_admit(log, txid2, 100, 4, 4));
    MP_CHECK("append iter 2", append_admit(log, txid3, 200, 4, 8));
    MP_CHECK("catch up iterate", mempool_projection_catch_up(p) != UINT64_MAX);
    MP_CHECK("iterate count",
             mempool_projection_each(p, iter_cb, &ctx) == 3);
    MP_CHECK("iterate sorted",
             ctx.count == 3 && ctx.first_bytes[0] == 1 &&
             ctx.first_bytes[1] == 2 && ctx.first_bytes[2] == 3);
    mempool_projection_close(p);
    event_log_close(log);
    test_cleanup_tmpdir(dir);
    return failures;
}

static int t_emit_helpers(void)
{
    int failures = 0;
    char dir[256], elog_path[300], proj_path[300];
    uint8_t txid[32];
    uint8_t raw[] = {0x10, 0x20, 0x30, 0x40, 0x50};
    test_make_tmpdir(dir, sizeof(dir), "mempool_projection", "emit");
    test_projection_paths(dir, "mempool", elog_path, sizeof(elog_path),
                          proj_path, sizeof(proj_path));
    fill_txid(txid, 91);
    event_log_t *log = event_log_open(elog_path);
    mempool_projection_t *p = mempool_projection_open(proj_path, log);
    mempool_projection_set_event_log(log);
    MP_CHECK("emit admit",
             mempool_projection_emit_admit(txid, 7000, sizeof(raw),
                                           sizeof(raw), 123, raw,
                                           sizeof(raw)));
    MP_CHECK("catch emitted admit",
             mempool_projection_catch_up(p) != UINT64_MAX &&
             mempool_projection_count(p) == 1);
    MP_CHECK("emit remove", mempool_projection_emit_remove(txid, 2));
    MP_CHECK("catch emitted remove",
             mempool_projection_catch_up(p) != UINT64_MAX &&
             mempool_projection_count(p) == 0);
    mempool_projection_set_event_log(NULL);
    mempool_projection_close(p);
    event_log_close(log);
    test_cleanup_tmpdir(dir);
    return failures;
}

static int t_model_clear_emits_removes(void)
{
    int failures = 0;
    char dir[256], elog_path[300], proj_path[300], db_path[300];
    uint8_t txid[32];
    uint8_t raw[] = {0x01, 0x02, 0x03};
    test_make_tmpdir(dir, sizeof(dir), "mempool_projection", "clear");
    test_projection_paths(dir, "mempool", elog_path, sizeof(elog_path),
                          proj_path, sizeof(proj_path));
    snprintf(db_path, sizeof(db_path), "%s/node.db", dir);
    fill_txid(txid, 122);

    event_log_t *log = event_log_open(elog_path);
    mempool_projection_t *p = mempool_projection_open(proj_path, log);
    struct node_db ndb;
    memset(&ndb, 0, sizeof(ndb));
    MP_CHECK("model db open", node_db_open(&ndb, db_path));
    mempool_projection_set_event_log(log);

    struct db_mempool_entry e;
    memset(&e, 0, sizeof(e));
    memcpy(e.txid, txid, 32);
    e.raw_tx = raw;
    e.raw_tx_len = sizeof(raw);
    e.fee = 9000;
    e.size = (int)sizeof(raw);
    e.time_added = 1700000002;
    MP_CHECK("model save emits admit", db_mempool_save(&ndb, &e));
    MP_CHECK("projection sees model save",
             mempool_projection_catch_up(p) != UINT64_MAX &&
             mempool_projection_count(p) == 1 &&
             mempool_projection_total_fee(p) == 9000);
    MP_CHECK("model fee aggregate", db_mempool_total_fee(&ndb) == 9000);
    MP_CHECK("model clear emits remove", db_mempool_clear(&ndb));
    MP_CHECK("projection sees model clear",
             mempool_projection_catch_up(p) != UINT64_MAX &&
             mempool_projection_count(p) == 0);

    mempool_projection_set_event_log(NULL);
    node_db_close(&ndb);
    mempool_projection_close(p);
    event_log_close(log);
    test_cleanup_tmpdir(dir);
    return failures;
}

int test_mempool_projection(void)
{
    int failures = 0;
    printf("\n=== mempool_projection tests ===\n");
    failures += t_payload_roundtrip();
    failures += t_add_remove_replay();
    failures += t_iterate_sorted();
    failures += t_emit_helpers();
    failures += t_model_clear_emits_removes();
    printf("mempool_projection: %d failures\n", failures);
    return failures;
}
