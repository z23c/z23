/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * API resource reads: ZSLP tokens, onion announcements, file services, file
 * manifests, and peers.
 */

#include "test/api_test_fixtures.h"

int api_resource_reads_focused_tests(void)
{
    int failures = 0;
    uint8_t resp[8192];

    printf("api: zslp token resources serve REST reads... ");
    {
        char dbdir[256];
        char dbpath[320];
        uint8_t txid[32];
        uint8_t token_id[32];
        uint8_t addr_hash[20];
        struct node_db ndb;
        memset(&ndb, 0, sizeof(ndb));
        memset(txid, 0x44, sizeof(txid));
        memset(token_id, 0x55, sizeof(token_id));
        memset(addr_hash, 0x66, sizeof(addr_hash));
        test_make_tmpdir(dbdir, sizeof(dbdir), "api_resources", "zslp");
        snprintf(dbpath, sizeof(dbpath), "%s/node.db", dbdir);

        bool ok = node_db_open(&ndb, dbpath);
        if (ok) {
            ok = db_zslp_token_save_key(&ndb, "apitoken", "APITOKEN",
                                        "API Token", 0, "", 42, 1234);
            ok = ok && db_zslp_transfer_save(&ndb, txid, 99, token_id, 2, 77, 1, addr_hash);
            ok = ok && db_zslp_token_save_key(&ndb,
                "5555555555555555555555555555555555555555555555555555555555555555",
                "HEX55", "Hex Token", 0, "", 99, 77);
            ok = ok && api_test_seed_durable_tip(dbdir, 99);
            reducer_frontier_provable_tip_reset();
            api_set_state(NULL, NULL, NULL, &ndb, dbdir);

            size_t n = api_handle_request("GET", "/api/zslp/tokens?limit=10",
                                          NULL, 0, resp, sizeof(resp));
            ok = ok && (n > 0) && (strstr((char *)resp, "200 OK") != NULL);
            const char *body = api_test_body(resp, n, sizeof(resp));
            struct json_value root;
            json_init(&root);
            ok = ok && body && json_read(&root, body, strlen(body));
            ok = ok && strcmp(json_get_str(json_get(&root, "schema")),
                              "zcl.zslp_tokens.index.v1") == 0;
            ok = ok && api_test_expect_freshness(&root, "zslp_projection",
                                                 99, 99, true);
            ok = ok && json_size(json_get(&root, "tokens")) >= 2;
            ok = ok && (strstr(body, "APITOKEN") != NULL);
            json_free(&root);

            n = api_handle_request("GET", "/api/zslp/tokens/APITOKEN",
                                   NULL, 0, resp, sizeof(resp));
            ok = ok && (n > 0);
            body = api_test_body(resp, n, sizeof(resp));
            json_init(&root);
            ok = ok && body && json_read(&root, body, strlen(body));
            ok = ok && strcmp(json_get_str(json_get(&root, "schema")),
                              "zcl.zslp_tokens.show.v1") == 0;
            ok = ok && api_test_expect_freshness(&root, "zslp_projection",
                                                 99, 99, true);
            ok = ok && strcmp(json_get_str(json_get(&root, "token_id")),
                              "APITOKEN") == 0;
            json_free(&root);

            n = api_handle_request("GET",
                "/api/zslp/tokens/5555555555555555555555555555555555555555555555555555555555555555/transfers?limit=5",
                NULL, 0, resp, sizeof(resp));
            ok = ok && (n > 0);
            body = api_test_body(resp, n, sizeof(resp));
            json_init(&root);
            ok = ok && body && json_read(&root, body, strlen(body));
            ok = ok && strcmp(json_get_str(json_get(&root, "schema")),
                              "zcl.zslp_token_transfers.index.v1") == 0;
            ok = ok && api_test_expect_freshness(&root, "zslp_projection",
                                                 99, 99, true);
            ok = ok && json_size(json_get(&root, "transfers")) == 1;
            ok = ok && json_get_int(json_get(json_at(json_get(&root,
                                      "transfers"), 0), "amount")) == 77;
            json_free(&root);

            n = api_handle_request("GET", "/api/zslp/tokens/BAD-TOKEN!",
                                   NULL, 0, resp, sizeof(resp));
            ok = ok && (n > 0) && (strstr((char *)resp, "404") != NULL);

            n = api_handle_request("GET", "/api/zslp/tokens?limit=999",
                                   NULL, 0, resp, sizeof(resp));
            ok = ok && (n > 0) && (strstr((char *)resp, "404") != NULL);

            api_set_state(NULL, NULL, NULL, NULL, NULL);
            reducer_frontier_provable_tip_reset();
            progress_store_close();
            node_db_close(&ndb);
        }

        char cmd[384];
        snprintf(cmd, sizeof(cmd), "rm -rf %s", dbdir);
        system(cmd);

        if (ok) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    printf("api: onion announcements serve REST reads... ");
    {
        char dbdir[256];
        char dbpath[320];
        struct node_db ndb;
        bool ok;
        test_make_tmpdir(dbdir, sizeof(dbdir), "api_resources", "onion");
        snprintf(dbpath, sizeof(dbpath), "%s/node.db", dbdir);
        memset(&ndb, 0, sizeof(ndb));
        ok = node_db_open(&ndb, dbpath);

        if (ok) {
            struct db_onion_announcement a, b;
            memset(&a, 0, sizeof(a));
            memset(&b, 0, sizeof(b));
            snprintf(a.onion_address, sizeof(a.onion_address),
                     "%s", "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb.onion");
            snprintf(a.script_hex, sizeof(a.script_hex), "%s", "6a01");
            a.announced_at = 1;
            snprintf(b.onion_address, sizeof(b.onion_address),
                     "%s", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.onion");
            snprintf(b.script_hex, sizeof(b.script_hex), "%s", "6a02");
            b.announced_at = 2;
            ok = db_onion_announcement_save(&ndb, &a);
            ok = ok && db_onion_announcement_save(&ndb, &b);
            ok = ok && api_test_seed_durable_tip(dbdir, 77);
            reducer_frontier_provable_tip_reset();
            api_set_state(NULL, NULL, NULL, &ndb, dbdir);

            size_t n = api_handle_request("GET", "/api/onion/announcements?limit=2",
                                          NULL, 0, resp, sizeof(resp));
            ok = ok && (n > 0);
            const char *body = api_test_body(resp, n, sizeof(resp));
            struct json_value root;
            json_init(&root);
            ok = ok && body && json_read(&root, body, strlen(body));
            ok = ok && strcmp(json_get_str(json_get(&root, "schema")),
                              "zcl.onion_announcements.index.v1") == 0;
            ok = ok && api_test_expect_freshness(&root, "onion_projection",
                                                 77, 77, true);
            ok = ok && json_size(json_get(&root, "announcements")) == 2;
            ok = ok && (strstr(body,
                "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.onion") != NULL);
            json_free(&root);

            n = api_handle_request("GET", "/api/onion/announcements?limit=99",
                                   NULL, 0, resp, sizeof(resp));
            ok = ok && (n > 0) && (strstr((char *)resp, "404") != NULL);

            api_set_state(NULL, NULL, NULL, NULL, NULL);
            reducer_frontier_provable_tip_reset();
            progress_store_close();
            node_db_close(&ndb);
        }

        char cmd[384];
        snprintf(cmd, sizeof(cmd), "rm -rf %s", dbdir);
        system(cmd);

        if (ok) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    printf("api: file services serve REST reads... ");
    {
        char dbdir[256];
        char dbpath[320];
        struct node_db ndb;
        bool ok;
        test_make_tmpdir(dbdir, sizeof(dbdir),
                         "api_resources", "file_services");
        snprintf(dbpath, sizeof(dbpath), "%s/node.db", dbdir);
        memset(&ndb, 0, sizeof(ndb));
        ok = node_db_open(&ndb, dbpath);

        if (ok) {
            struct db_file_service fs;
            memset(&fs, 0, sizeof(fs));
            memset(fs.ip, 0x77, sizeof(fs.ip));
            fs.port = 8080;
            fs.is_zcl23 = true;
            ok = db_file_service_save(&ndb, &fs);
            ok = ok && api_test_seed_durable_tip(dbdir, 88);
            reducer_frontier_provable_tip_reset();
            api_set_state(NULL, NULL, NULL, &ndb, dbdir);

            size_t n = api_handle_request("GET", "/api/file-services?limit=1",
                                          NULL, 0, resp, sizeof(resp));
            ok = ok && (n > 0);
            const char *body = api_test_body(resp, n, sizeof(resp));
            struct json_value root;
            json_init(&root);
            ok = ok && body && json_read(&root, body, strlen(body));
            ok = ok && strcmp(json_get_str(json_get(&root, "schema")),
                              "zcl.file_services.index.v1") == 0;
            ok = ok && api_test_expect_freshness(&root,
                                                 "file_service_projection",
                                                 88, 88, true);
            ok = ok && json_size(json_get(&root, "file_services")) == 1;
            ok = ok && json_get_int(json_get(json_at(json_get(&root,
                                      "file_services"), 0), "port")) == 8080;
            json_free(&root);

            n = api_handle_request("GET", "/api/file-services?limit=99",
                                   NULL, 0, resp, sizeof(resp));
            ok = ok && (n > 0) && (strstr((char *)resp, "404") != NULL);

            api_set_state(NULL, NULL, NULL, NULL, NULL);
            reducer_frontier_provable_tip_reset();
            progress_store_close();
            node_db_close(&ndb);
        }

        char cmd[384];
        snprintf(cmd, sizeof(cmd), "rm -rf %s", dbdir);
        system(cmd);

        if (ok) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    printf("api: file manifest exposes REST envelope and freshness... ");
    {
        char dbdir[256];
        char blocksdir[320];
        char blkpath[384];
        test_make_tmpdir(dbdir, sizeof(dbdir),
                         "api_resources", "manifest");
        snprintf(blocksdir, sizeof(blocksdir), "%s/blocks", dbdir);
        snprintf(blkpath, sizeof(blkpath), "%s/blk00000.dat", blocksdir);
        mkdir(blocksdir, 0755);

        FILE *f = fopen(blkpath, "wb");
        bool ok = f != NULL;
        if (ok) {
            static const unsigned char payload[] = {
                0x5a, 0x43, 0x4c, 0x32, 0x33, 0x2d, 0x61, 0x70, 0x69
            };
            ok = fwrite(payload, 1, sizeof(payload), f) == sizeof(payload);
            fclose(f);
        }
        if (ok) {
            struct utimbuf old_time;
            time_t stable_time =
                (time_t)(platform_time_wall_time_t() - 7200);
            old_time.actime = stable_time;
            old_time.modtime = stable_time;
            ok = utime(blkpath, &old_time) == 0;
        }
        if (ok) {
            progress_store_close();
            reducer_frontier_provable_tip_reset();
            api_set_state(NULL, NULL, NULL, NULL, dbdir);
            file_controller_init(dbdir);
            ok = file_controller_refresh_manifest();
        }
        if (ok) {
            size_t n = api_handle_request("GET", "/api/files/manifest",
                                          NULL, 0, resp, sizeof(resp));
            const char *body = api_test_body(resp, n, sizeof(resp));
            struct json_value root;
            json_init(&root);
            ok = n > 0 && body && json_read(&root, body, strlen(body));
            ok = ok && strcmp(json_get_str(json_get(&root, "schema")),
                              "zcl.files_manifest.v1") == 0;
            ok = ok && api_test_expect_freshness(&root, "file_manifest",
                                                 0, 0, true);
            ok = ok && json_get_int(json_get(&root, "num_chunks")) == 1;
            ok = ok && json_get_int(json_get(&root, "total_bytes")) == 9;
            const struct json_value *chunks = json_get(&root, "chunks");
            ok = ok && chunks && json_size(chunks) == 1;
            ok = ok && json_get_int(json_get(json_at(chunks, 0),
                                             "size")) == 9;
            ok = ok && json_get_int(json_get(json_at(chunks, 0),
                                             "file")) == 0;
            json_free(&root);
        }

        api_set_state(NULL, NULL, NULL, NULL, NULL);
        reducer_frontier_provable_tip_reset();
        progress_store_close();
        file_controller_init(NULL);

        char cmd[384];
        snprintf(cmd, sizeof(cmd), "rm -rf %s", dbdir);
        system(cmd);

        if (ok) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    printf("api: peers serve REST reads... ");
    {
        char dbdir[256];
        char dbpath[320];
        struct node_db ndb;
        bool ok;
        test_make_tmpdir(dbdir, sizeof(dbdir), "api_resources", "peers");
        snprintf(dbpath, sizeof(dbpath), "%s/node.db", dbdir);
        memset(&ndb, 0, sizeof(ndb));
        ok = node_db_open(&ndb, dbpath);

        if (ok) {
            struct db_peer peer;
            struct p2p_node live;
            memset(&peer, 0, sizeof(peer));
            peer.ip[10] = 0xff;
            peer.ip[11] = 0xff;
            peer.ip[12] = 203;
            peer.ip[13] = 0;
            peer.ip[14] = 113;
            peer.ip[15] = 85;
            peer.port = 8333;
            peer.services = 5;
            peer.is_zcl23 = false;
            ok = db_peer_save(&ndb, &peer);

            peer_lifecycle_reset_for_test();
            memset(&live, 0, sizeof(live));
            memcpy(live.addr.svc.addr.ip, peer.ip, sizeof(peer.ip));
            live.addr.svc.port = peer.port;
            live.id = 833301;
            live.state = PEER_HANDSHAKE_COMPLETE;
            live.services = NODE_NETWORK | NODE_ZCL23;
            snprintf(live.addr_name, sizeof(live.addr_name),
                     "203.0.113.85:8333");
            snprintf(live.sub_ver, sizeof(live.sub_ver),
                     "%s", "/ZClassic23:0.1.0/");
            peer_lifecycle_note_connected(&live,
                                          PEER_LIFECYCLE_SOURCE_ADDNODE);
            peer_lifecycle_note_version_received(&live, live.services,
                                                 3173000, live.sub_ver);
            peer_lifecycle_note_handshake_complete(&live);
            peer_lifecycle_note_active(&live);

            ok = ok && api_test_seed_durable_tip(dbdir, 66);
            reducer_frontier_provable_tip_reset();
            api_set_state(NULL, NULL, NULL, &ndb, dbdir);

            size_t n = api_handle_request("GET", "/api/peers?limit=1",
                                          NULL, 0, resp, sizeof(resp));
            ok = ok && (n > 0);
            const char *body = api_test_body(resp, n, sizeof(resp));
            struct json_value root;
            json_init(&root);
            ok = ok && body && json_read(&root, body, strlen(body));
            ok = ok && strcmp(json_get_str(json_get(&root, "schema")),
                              "zcl.peers.index.v1") == 0;
            ok = ok && api_test_expect_freshness(&root, "peer_projection",
                                                 66, 66, true);
            const struct json_value *peers = json_get(&root, "peers");
            const struct json_value *item = json_at(peers, 0);
            ok = ok && json_size(peers) == 1;
            ok = ok && item &&
                 json_get_int(json_get(item, "port")) == 8333;
            ok = ok && item &&
                 strcmp(json_get_str(json_get(item, "addr")),
                        "203.0.113.85:8333") == 0;
            ok = ok && item &&
                 !json_get_bool(json_get(item, "projection_is_zcl23"));
            ok = ok && item &&
                 json_get_bool(json_get(item, "live_peer"));
            ok = ok && item &&
                 json_get_bool(json_get(item, "live_zclassic23"));
            ok = ok && item &&
                 json_get_bool(json_get(item, "is_zcl23"));
            ok = ok && item &&
                 json_get_bool(json_get(item,
                                        "zclassic23_projection_stale"));
            ok = ok && item &&
                 strcmp(json_get_str(json_get(item,
                                              "zclassic23_verified_by")),
                        "live_handshake") == 0;
            ok = ok && item &&
                 strcmp(json_get_str(json_get(item,
                                              "bootstrap_readiness")),
                        "useful") == 0;
            ok = ok && item &&
                 json_get_bool(json_get(item, "fast_sync_useful"));
            const struct json_value *live_lifecycle =
                item ? json_get(item, "live_lifecycle") : NULL;
            ok = ok && live_lifecycle &&
                 json_get_bool(json_get(live_lifecycle, "zclassic23"));
            json_free(&root);

            n = api_handle_request("GET", "/api/peers?limit=99",
                                   NULL, 0, resp, sizeof(resp));
            ok = ok && (n > 0) && (strstr((char *)resp, "404") != NULL);

            api_set_state(NULL, NULL, NULL, NULL, NULL);
            reducer_frontier_provable_tip_reset();
            progress_store_close();
            node_db_close(&ndb);
            peer_lifecycle_reset_for_test();
        }

        char cmd[384];
        snprintf(cmd, sizeof(cmd), "rm -rf %s", dbdir);
        system(cmd);

        if (ok) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    return failures;
}
