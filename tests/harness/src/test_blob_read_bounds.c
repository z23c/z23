/* Copyright 2026 Rhett Creighton - Apache License 2.0 */

#include "test/test_core.h"

#include "models/database.h"
#include "models/file_offer.h"
#include "models/swap_contract.h"
#include "models/znam.h"
#include "models/zmsg.h"

#include <sqlite3.h>
#include <stdio.h>
#include <string.h>

static bool exec_sql(sqlite3 *db, const char *sql)
{
    char *err = NULL;
    int rc = sqlite3_exec(db, sql, NULL, NULL, &err);
    if (rc != SQLITE_OK) {
        fprintf(stderr, "test_blob_read_bounds sql failed: %s\n",
                err ? err : sqlite3_errmsg(db));
        sqlite3_free(err);
        return false;
    }
    return true;
}

int test_blob_read_bounds(void)
{
    int failures = 0;

    printf("blob_read_bounds: malformed fixed blobs fail closed via model APIs... ");
    {
        struct node_db ndb;
        memset(&ndb, 0, sizeof(ndb));
        bool ok = node_db_open(&ndb, ":memory:");

        ok = ok && exec_sql(ndb.db,
            "INSERT INTO file_offers"
            "(root_hash,filename,size_bytes,num_chunks,price_per_mb,"
            "z_addr,peer_ip,peer_port,last_seen,ttl)"
            " VALUES(X'aa','bad.dat',100,1,0,NULL,X'0102',8033,2,1)");

        ok = ok && exec_sql(ndb.db,
            "INSERT INTO file_offers"
            "(root_hash,filename,size_bytes,num_chunks,price_per_mb,"
            "z_addr,peer_ip,peer_port,last_seen,ttl)"
            " VALUES("
            "X'1111111111111111111111111111111111111111111111111111111111111111',"
            "'good.dat',100,1,0,"
            "X'22222222222222222222222222222222222222222222222222222222222222222222222222222222222222',"
            "X'33333333333333333333333333333333',8033,1,1)");

        ok = ok && exec_sql(ndb.db,
            "INSERT INTO zswp_contracts"
            "(swap_id,role,state,chain,secret_hash,secret,amount,locktime,"
            "my_address,counter_address,funding_txid,funding_vout,"
            "redeem_script,redeem_script_len,p2sh_address,created_at)"
            " VALUES('bad',0,0,0,X'aa',X'bb',1,960,"
            "'me','them',X'cc',0,X'deadbeef',64,'p2sh',2)");

        ok = ok && exec_sql(ndb.db,
            "INSERT INTO zswp_contracts"
            "(swap_id,role,state,chain,secret_hash,secret,amount,locktime,"
            "my_address,counter_address,funding_txid,funding_vout,"
            "redeem_script,redeem_script_len,p2sh_address,created_at)"
            " VALUES('good',0,0,0,"
            "X'4444444444444444444444444444444444444444444444444444444444444444',"
            "NULL,1,960,'me','them',"
            "X'5555555555555555555555555555555555555555555555555555555555555555',"
            "0,X'76a91488ac',5,'p2sh',1)");

        ok = ok && exec_sql(ndb.db,
            "INSERT INTO znam_names"
            "(name,owner_address,target_type,target_value,"
            "reg_txid,reg_height,last_update_txid)"
            " VALUES('bad','owner',1,'target',X'aa',2,X'bb')");

        ok = ok && exec_sql(ndb.db,
            "INSERT INTO znam_names"
            "(name,owner_address,target_type,target_value,"
            "reg_txid,reg_height,last_update_txid)"
            " VALUES('good','owner',1,'target',"
            "X'6666666666666666666666666666666666666666666666666666666666666666',"
            "1,"
            "X'7777777777777777777777777777777777777777777777777777777777777777')");

        ok = ok && exec_sql(ndb.db,
            "INSERT INTO zmsg_messages"
            "(msg_id,direction,channel,sender,recipient,body,"
            "timestamp,txid,read)"
            " VALUES(X'aa',0,1,'sender','recipient','body',2,X'bb',0)");

        ok = ok && exec_sql(ndb.db,
            "INSERT INTO zmsg_messages"
            "(msg_id,direction,channel,sender,recipient,body,"
            "timestamp,txid,read)"
            " VALUES("
            "X'8888888888888888888888888888888888888888888888888888888888888888',"
            "0,1,'sender','recipient','body',1,NULL,0)");

        struct file_offer offers[2];
        memset(offers, 0xff, sizeof(offers));
        int offer_count = ok ? db_file_offer_list(&ndb, offers, 2) : 0;
        ok = ok && offer_count == 1;
        ok = ok && strcmp(offers[0].filename, "good.dat") == 0;

        struct swap_contract swap;
        memset(&swap, 0xff, sizeof(swap));
        ok = ok && !db_swap_find(&ndb, "bad", &swap);
        struct swap_contract swaps[2];
        memset(swaps, 0xff, sizeof(swaps));
        int swap_count = ok ? db_swap_list(&ndb, swaps, 2, -1) : 0;
        ok = ok && swap_count == 1;
        ok = ok && strcmp(swaps[0].swap_id, "good") == 0;

        struct znam_entry znams[2];
        memset(znams, 0xff, sizeof(znams));
        ok = ok && !db_znam_find(&ndb, "bad", &znams[0]);
        int znam_count = ok ? db_znam_list(&ndb, znams, 2) : 0;
        ok = ok && znam_count == 1;
        ok = ok && strcmp(znams[0].name, "good") == 0;

        struct zmsg_message msgs[2];
        memset(msgs, 0xff, sizeof(msgs));
        int msg_count = ok ? db_zmsg_list(&ndb, msgs, 2, false) : 0;
        ok = ok && msg_count == 1;
        ok = ok && strcmp(msgs[0].sender, "sender") == 0;

        node_db_close(&ndb);

        if (ok) {
            printf("OK\n");
        } else {
            printf("FAIL\n");
            failures++;
        }
    }

    return failures;
}
