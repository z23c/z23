/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Defensive-bounds regression tests for three latent-hazard hardening
 * fixes from the tree-wide concurrency/defensive sweep:
 *
 *   #6 serialize.c stream_read  — integer-overflow bound. The old guard
 *       `s->read_pos + len > s->size` can wrap when len is near SIZE_MAX,
 *       passing the check and over-reading in the following memcpy. The
 *       non-wrapping form `len > s->size - s->read_pos` rejects it.
 *
 *   #5 fast_sync.c serve_chunk_db — missing clamp of the caller-supplied
 *       chunk_size against the fixed entries[1000] capacity. A caller
 *       passing chunk_size > 1000 (e.g. 5000) over a >1000-row utxos table
 *       would write out of bounds. The clamp caps chunk_size at 1000 so
 *       num_entries can never exceed the array capacity.
 *
 *   #4 connman.c connman_get_node_count — torn read of num_nodes. The
 *       count is now read under cs_nodes; this test guards the functional
 *       contract that the count reflects the nodes actually registered.
 */

#include "test/test_core.h"
#include "core/serialize.h"
#include "primitives/transaction.h"
#include "primitives/block.h"
#include "net/fast_sync.h"
#include "net/connman.h"
#include "net/netaddr.h"
#include "util/sync.h"
#include "util/safe_alloc.h"
#include <sqlite3.h>
#include <stdint.h>
#include <string.h>

/* #6 — stream_read must reject an oversize length without wrapping. */
int test_stream_read_no_overflow(void)
{
    int failures = 0;
    TEST_CASE("stream_read rejects SIZE_MAX len without integer overflow") {
        const unsigned char src[4] = { 0xDE, 0xAD, 0xBE, 0xEF };
        struct byte_stream s;
        stream_init_from_data(&s, src, sizeof(src));

        /* Oversize read: read_pos(0) + SIZE_MAX wraps in the old form and
         * would pass the bound, then memcpy SIZE_MAX bytes. The hardened
         * form rejects it and flags the stream. */
        unsigned char buf[4];
        ASSERT(stream_read(&s, buf, SIZE_MAX) == false);
        ASSERT(s.error == true);

        /* A fresh, in-bounds read still succeeds and advances read_pos. */
        struct byte_stream s2;
        stream_init_from_data(&s2, src, sizeof(src));
        unsigned char got[2];
        ASSERT(stream_read(&s2, got, 2) == true);
        ASSERT(s2.error == false);
        ASSERT(s2.read_pos == 2);
        ASSERT(got[0] == 0xDE && got[1] == 0xAD);

        stream_free(&s);
        stream_free(&s2);
    } TEST_END
    return failures;
}

/* #5 — serve_chunk_db must clamp num_entries to the entries[1000] capacity
 * even when the caller passes a chunk_size far larger than 1000. */
int test_fast_sync_serve_chunk_db_clamps(void)
{
    int failures = 0;
    TEST_CASE("fast_sync_serve_chunk_db clamps oversize chunk_size to 1000") {
        sqlite3 *db = NULL;
        ASSERT(sqlite3_open(":memory:", &db) == SQLITE_OK);

        const char *schema =
            "CREATE TABLE utxos ("
            "txid BLOB NOT NULL,vout INTEGER NOT NULL,"
            "value INTEGER NOT NULL CHECK(value >= 0 AND value <= 2100000000000000),"
            "script BLOB NOT NULL,"
            "script_type INTEGER NOT NULL DEFAULT 0,"
            "address_hash BLOB,height INTEGER NOT NULL CHECK(height >= 0),"
            "is_coinbase INTEGER NOT NULL DEFAULT 0,"
            "PRIMARY KEY (txid,vout))";
        ASSERT(sqlite3_exec(db, schema, NULL, NULL, NULL) == SQLITE_OK);

        sqlite3_stmt *ins = NULL;
        ASSERT(sqlite3_prepare_v2(db,
            "INSERT INTO utxos"
            "(txid,vout,value,script,script_type,height,is_coinbase)"
            " VALUES(?,?,?,?,0,?,?)",
            -1, &ins, NULL) == SQLITE_OK);

        /* Insert > 1000 rows so an unclamped chunk_size=5000 would walk
         * past entries[1000]. Distinct txids keep the PRIMARY KEY happy. */
        enum { ROWS = 1500 };
        const uint8_t script[1] = { 0x51 };
        for (int i = 0; i < ROWS; i++) {
            uint8_t txid[32];
            memset(txid, 0, sizeof(txid));
            memcpy(txid, &i, sizeof(i));
            sqlite3_bind_blob(ins, 1, txid, 32, SQLITE_TRANSIENT);
            sqlite3_bind_int(ins, 2, 0);
            sqlite3_bind_int64(ins, 3, 1000);
            sqlite3_bind_blob(ins, 4, script, 1, SQLITE_STATIC);
            sqlite3_bind_int(ins, 5, i);
            sqlite3_bind_int(ins, 6, 0);
            ASSERT(sqlite3_step(ins) == SQLITE_DONE); // raw-sql-ok:test-fixture-setup
            sqlite3_reset(ins);
            sqlite3_clear_bindings(ins);
        }
        sqlite3_finalize(ins);

        struct utxo_chunk *chunk =
            zcl_calloc(1, sizeof(struct utxo_chunk), "test_clamp_chunk");
        ASSERT(chunk != NULL);

        /* Oversize chunk_size: unclamped this would write 1500 entries into
         * entries[1000]. The clamp caps it at the array capacity. */
        ASSERT(fast_sync_serve_chunk_db(db, 0, 5000, chunk));
        ASSERT(chunk->num_entries <= 1000);

        free(chunk);
        sqlite3_close(db);
    } TEST_END
    return failures;
}

/* #7 — transaction_deserialize must reject an implausible vin/vout count
 * (a 5-byte compact-size claiming 65536 with a truncated body) BEFORE the
 * ~627 MB / ~626 MB allocation, and must not crash. A minimal valid tx
 * still round-trips, proving the guard does not narrow the accept set. */
int test_transaction_deserialize_count_amplification(void)
{
    int failures = 0;
    TEST_CASE("transaction_deserialize rejects implausible vin/vout counts") {
        /* v1 tx header, then num_vin = 65536 encoded as 0xFE 00 00 01 00,
         * then the stream ends. 65536 vin need >=65536*41 bytes; only 0
         * remain, so the plausibility guard must reject before allocating. */
        const unsigned char vin_bomb[] = {
            0x01, 0x00, 0x00, 0x00,       /* version 1, not overwintered */
            0xFE, 0x00, 0x00, 0x01, 0x00, /* num_vin = 65536 */
        };
        struct byte_stream s;
        stream_init_from_data(&s, vin_bomb, sizeof(vin_bomb));
        struct transaction tx;
        ASSERT(transaction_deserialize(&tx, &s) == false);
        transaction_free(&tx);
        stream_free(&s);

        /* num_vout = 65536 (after a 0 vin count) with a truncated body. */
        const unsigned char vout_bomb[] = {
            0x01, 0x00, 0x00, 0x00,       /* version 1 */
            0x00,                         /* num_vin = 0 */
            0xFE, 0x00, 0x00, 0x01, 0x00, /* num_vout = 65536 */
        };
        struct byte_stream s2;
        stream_init_from_data(&s2, vout_bomb, sizeof(vout_bomb));
        struct transaction tx2;
        ASSERT(transaction_deserialize(&tx2, &s2) == false);
        transaction_free(&tx2);
        stream_free(&s2);

        /* A minimal VALID v1 tx (0 vin, 0 vout, lock_time 0) still parses —
         * the guard rejects only counts the body cannot satisfy. */
        struct transaction valid;
        transaction_init(&valid);
        valid.version = 1;
        valid.overwintered = false;
        struct byte_stream ser;
        stream_init(&ser, 64);
        ASSERT(transaction_serialize(&valid, &ser));
        struct byte_stream rd;
        stream_init_from_data(&rd, ser.data, ser.size);
        struct transaction got;
        ASSERT(transaction_deserialize(&got, &rd) == true);
        ASSERT(got.num_vin == 0 && got.num_vout == 0);
        transaction_free(&got);
        transaction_free(&valid);
        stream_free(&ser);
        stream_free(&rd);
    } TEST_END
    return failures;
}

/* #7b — block_deserialize must reject an implausible tx count (a 5-byte
 * compact-size claiming 50000 with a truncated stream) before the ~14 MB
 * slot allocation, without crashing. */
int test_block_deserialize_txcount_amplification(void)
{
    int failures = 0;
    TEST_CASE("block_deserialize rejects implausible tx count") {
        /* Build a valid 1487-byte block header, then claim num_vtx = 50000
         * (0xFE 50 C3 00 00) with no tx bytes following. 50000 tx need
         * >=500000 bytes; the guard must reject before allocating slots. */
        struct block_header h;
        memset(&h, 0, sizeof(h));
        h.nVersion = 4;
        h.nSolutionSize = 0;
        struct byte_stream hs;
        stream_init(&hs, 256);
        ASSERT(block_header_serialize(&h, &hs));
        /* Append num_vtx = 50000 as a 254-marker compact size. */
        ASSERT(stream_write_compact_size(&hs, 50000));
        /* Stream ends here — no tx bodies. */

        struct byte_stream rd;
        stream_init_from_data(&rd, hs.data, hs.size);
        struct block b;
        block_init(&b);
        ASSERT(block_deserialize(&b, &rd) == false);
        block_free(&b);
        stream_free(&hs);
        stream_free(&rd);
    } TEST_END
    return failures;
}

/* #4 — connman_get_node_count reflects the registered node count and is
 * read under cs_nodes (the lock acquisition is structurally verified by
 * reading; this guards the functional contract). */
int test_connman_node_count_locked(void)
{
    int failures = 0;
    TEST_CASE("connman_get_node_count returns the registered node count") {
        struct connman cm;
        memset(&cm, 0, sizeof(cm));
        net_manager_init(&cm.manager);
        memcpy(cm.manager.message_start, "\xfa\x1a\xf9\xbf", 4);

        ASSERT(connman_get_node_count(&cm) == 0);

        enum { N = 5 };
        /* Register N nodes directly into the manager's array, mirroring how
         * the socket thread populates nodes[]/num_nodes under cs_nodes.
         * net_manager_free() owns and frees every entry afterwards. */
        struct net_manager *nm = &cm.manager;
        zcl_mutex_lock(&nm->cs_nodes);
        nm->nodes = zcl_calloc(N, sizeof(*nm->nodes), "test_count_nodes");
        ASSERT(nm->nodes != NULL);
        nm->nodes_cap = N;
        for (int i = 0; i < N; i++) {
            struct net_address addr;
            net_address_init(&addr);
            unsigned char ip4[4] = { 50, 0, 0, (unsigned char)(i + 1) };
            net_addr_set_ipv4(&addr.svc.addr, ip4);
            addr.svc.port = (uint16_t)(8233 + i);
            struct p2p_node *node =
                p2p_node_create(nm, ZCL_INVALID_SOCKET, &addr, "test-peer",
                                false);
            ASSERT(node != NULL);
            nm->nodes[nm->num_nodes++] = node;
        }
        zcl_mutex_unlock(&nm->cs_nodes);

        ASSERT(connman_get_node_count(&cm) == (size_t)N);

        net_manager_free(&cm.manager);
    } TEST_END
    return failures;
}
