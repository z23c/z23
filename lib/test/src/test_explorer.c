/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Explorer controller unit tests — routing, edge cases, factoids. */

/* realpath() reaches this TU only through the glibc fortify inline that
 * -D_FORTIFY_SOURCE=2 pulls in at -O1 and above; the build's
 * -D_POSIX_C_SOURCE=200809L declares it nowhere. Without this the file
 * compiles by accident of optimisation and breaks at -O0, under
 * -U_FORTIFY_SOURCE, and on any non-glibc libc. It must precede every
 * include: after them it does nothing. See lib/util/src/hw_profile.c. */
#if !defined(_WIN32) && !defined(_DEFAULT_SOURCE)
#define _DEFAULT_SOURCE
#endif

#include "test/test_core.h"
#include "controllers/explorer_controller.h"
#include "controllers/explorer_internal.h"
#include "jobs/reducer_frontier.h"
#include "models/hodl_wave.h"
#include "crypto/sha3.h"
#include "views/explorer_factoids_internal.h"
#include "views/explorer_factoids_view.h"
#include "views/explorer_dashboard_view.h"
#include "views/site_css.h"
#include "views/explorer_pages_loading_view.h"
#include "views/explorer_pages_view.h"
#include "views/explorer_stats_internal.h"
#include <string.h>
#include <inttypes.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

/* Build "<cwd>/.zcl_test_explorer_<stem>_<pid>" — an ABSOLUTE fixture
 * datadir. Cases whose subject only reads from the datadir spell it
 * relatively; a case whose subject WRITES into it must not, because the
 * production writers go through platform_private_path_resolve, which
 * realpath()s the destination's parent and refuses any pathname that does not
 * start at the root. On getcwd failure this falls back to the relative
 * spelling so the caller's write fails loudly rather than silently landing
 * somewhere else. */
static void ex_abs_dbdir(char *buf, size_t n, const char *stem)
{
    char cwd[256];
    if (!getcwd(cwd, sizeof(cwd))) {
        (void)snprintf(buf, n, ".zcl_test_explorer_%s_%d", stem,
                       (int)getpid());
        return;
    }
    (void)snprintf(buf, n, "%s/.zcl_test_explorer_%s_%d", cwd, stem,
                   (int)getpid());
}

int test_explorer(void)
{
    int failures = 0;
    uint8_t resp[8192];

    printf("explorer: NULL path returns 0... ");
    {
        size_t n = explorer_handle_request("GET", NULL, NULL, 0,
                                            resp, sizeof(resp));
        bool ok = (n == 0);
        if (ok) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    printf("explorer: NULL response returns 0... ");
    {
        size_t n = explorer_handle_request("GET", "/explorer", NULL, 0,
                                            NULL, sizeof(resp));
        bool ok = (n == 0);
        if (ok) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    printf("explorer: /api/ delegation to api controller... ");
    {
        size_t n = explorer_handle_request("GET", "/api/nonexistent", NULL, 0,
                                            resp, sizeof(resp));
        resp[n < sizeof(resp) ? n : sizeof(resp) - 1] = '\0';
        bool ok = (n > 0 && strstr((char *)resp, "404") != NULL);
        if (ok) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    printf("explorer: unknown path returns 0... ");
    {
        size_t n = explorer_handle_request("GET", "/foobar", NULL, 0,
                                            resp, sizeof(resp));
        bool ok = (n == 0);
        if (ok) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    printf("explorer: projection status pages do not ask users to refresh... ");
    {
        uint8_t out[16384];
        size_t n = explorer_view_loading_placeholder(out, sizeof(out) - 1,
            "Statistics Index Warming", "#33ff99",
            "Charts are being computed from blockchain data.");
        out[n < sizeof(out) ? n : sizeof(out) - 1] = '\0';
        bool ok = n > 0 &&
             strstr((char *)out, "Statistics Index Warming") != NULL &&
             strstr((char *)out, "Open blocks") != NULL &&
             strstr((char *)out, "/api/v1/status") != NULL &&
             strstr((char *)out, "http-equiv='refresh'") == NULL &&
             strstr((char *)out, "Auto-refresh") == NULL &&
             strstr((char *)out, "Refresh in a minute") == NULL &&
             strstr((char *)out, "please retry") == NULL;

        n = explorer_view_tokens_loading(out, sizeof(out) - 1);
        out[n < sizeof(out) ? n : sizeof(out) - 1] = '\0';
        ok = ok && n > 0 &&
             strstr((char *)out, "Token Index Warming") != NULL &&
             strstr((char *)out, "Open blocks") != NULL &&
             strstr((char *)out, "/api/v1/status") != NULL &&
             strstr((char *)out, "Loading Token Data") == NULL &&
             strstr((char *)out, "http-equiv='refresh'") == NULL &&
             strstr((char *)out, "Auto-refresh") == NULL &&
             strstr((char *)out, "Refresh in a minute") == NULL &&
             strstr((char *)out, "please retry") == NULL;

        if (ok) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    printf("explorer: dashboard exposes verified bootstrap peers... ");
    {
        uint8_t out[65536];
        struct explorer_dashboard_native_view v = {0};

        v.tip = 3173255;
        v.difficulty = 102.20;
        v.mempool_count = 0;
        v.mempool_bytes = 0;
        v.network.peer_count = 9;
        v.network.zclassic23_peers = 1;
        v.network.zclassic23_nodes_seen = 2;
        v.network.magicbean_peers = 6;

        size_t n = explorer_dashboard_view_native(out, sizeof(out) - 1, &v);
        out[n < sizeof(out) ? n : sizeof(out) - 1] = '\0';
        bool ok = n > 0 &&
             strstr((char *)out, "Z23 Bootstrap") != NULL &&
             strstr((char *)out, "Ready") != NULL &&
             strstr((char *)out, "verified live peer handshakes") != NULL &&
             strstr((char *)out, "Connected Peers</div>"
                    "<div class='bb-value'>9") != NULL &&
             strstr((char *)out, "Z23 Nodes</div>"
                    "<div class='bb-value'>2") != NULL &&
             strstr((char *)out, "this node + 1 peer") != NULL &&
             strstr((char *)out, "Legacy Peers</div>"
                    "<div class='bb-value'>6") != NULL &&
             strstr((char *)out, "Searching") == NULL;

        if (ok) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    printf("explorer: top-level /factoids redirects canonical... ");
    {
        size_t n = explorer_handle_request("GET", "/factoids", NULL, 0,
                                            resp, sizeof(resp));
        resp[n < sizeof(resp) ? n : sizeof(resp) - 1] = '\0';
        bool ok = (n > 0 &&
                   strstr((char *)resp, "302 Found") != NULL &&
                   strstr((char *)resp,
                          "Location: /explorer/factoids") != NULL);
        if (ok) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    printf("explorer: top-level /hodl redirects canonical... ");
    {
        size_t n = explorer_handle_request("GET", "/hodl", NULL, 0,
                                            resp, sizeof(resp));
        resp[n < sizeof(resp) ? n : sizeof(resp) - 1] = '\0';
        bool ok = (n > 0 &&
                   strstr((char *)resp, "302 Found") != NULL &&
                   strstr((char *)resp, "Location: /explorer/hodl") != NULL);
        if (ok) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    printf("explorer: HODL page uses historical snapshots for time series... ");
    {
        char dbdir[256];
        char dbpath[320];
        sqlite3 *db = NULL;
        snprintf(dbdir, sizeof(dbdir), ".zcl_test_explorer_hodl_%d",
                 (int)getpid());
        mkdir(dbdir, 0755);
        snprintf(dbpath, sizeof(dbpath), "%s/node.db", dbdir);

        bool ok = sqlite3_open(dbpath, &db) == SQLITE_OK;
        ok = ok && sqlite3_exec(db,
            "CREATE TABLE blocks(height INTEGER, time INTEGER);"
            "CREATE TABLE utxos(height INTEGER, value INTEGER);"
            "CREATE TABLE hodl_history(height INTEGER, time INTEGER,"
            "total_zat INTEGER,"
            "older_6m_zat INTEGER, older_1y_zat INTEGER,"
            "older_2y_zat INTEGER, older_5y_zat INTEGER,"
            "older_6m_pct REAL, older_1y_pct REAL,"
            "older_2y_pct REAL, older_5y_pct REAL,"
            "calc_version INTEGER, source_tip_height INTEGER);"
            "INSERT INTO blocks(height,time) VALUES"
            "(4320,1000),(8640,2000),(21600,5000),(25920,6000);"
            "INSERT INTO utxos(height,value) VALUES"
            "(4320,400),(8640,400),(21600,100),(25920,100);"
            "INSERT INTO hodl_history(height,time,total_zat,"
            "older_6m_zat,older_1y_zat,older_2y_zat,older_5y_zat,"
            "older_6m_pct,older_1y_pct,older_2y_pct,older_5y_pct,"
            "calc_version,source_tip_height) VALUES"
            "(4320,1000,400,80,50,25,0,20.0,12.5,6.25,0.0,2,4320),"
            "(8640,2000,800,300,200,100,50,37.5,25.0,12.5,6.25,2,8640),"
            "(21600,5000,900,600,450,200,100,66.667,50.0,22.222,11.111,2,21600),"
            "(25920,6000,1000,900,800,500,200,90.0,80.0,50.0,20.0,2,25920);",
            NULL, NULL, NULL) == SQLITE_OK;
        if (db)
            sqlite3_close(db);

        reducer_frontier_provable_tip_set(25920);
        uint8_t out[65536];
        size_t n = explorer_view_hodl(dbdir, out, sizeof(out) - 1);
        reducer_frontier_provable_tip_reset();
        out[n < sizeof(out) ? n : sizeof(out) - 1] = '\0';

        int one_year_segments = 0;
        const char *scan = (const char *)out;
        while ((scan = strstr(scan,
                              "<polyline fill='none' stroke='#35d07f'")) != NULL) {
            one_year_segments++;
            scan++;
        }
        ok = ok && n > 0 &&
             strstr((char *)out, "<main class='hodl-page'>") != NULL &&
             strstr((char *)out, "<h1 class='hodl-title'>") != NULL &&
             strstr((char *)out, ".hodl-stats{display:grid") != NULL &&
             strstr((char *)out, "class='stats-row hodl-stats'") != NULL &&
             strstr((char *)out, "class='hodl-table-wrap'") != NULL &&
             strstr((char *)out, "class='txlist hodl-table'") != NULL &&
             strstr((char *)out, "id='hodl-survival-wave'") != NULL &&
             strstr((char *)out, "id='hodl-survival-canvas'") != NULL &&
             strstr((char *)out,
                    "class='hodl-chart-canvas'><svg id='hodl-survival-wave'") != NULL &&
             strstr((char *)out,
                    "var wrap=document.getElementById('hodl-survival-canvas')") != NULL &&
             strstr((char *)out, "Historical HODL wave") != NULL &&
             strstr((char *)out, "4 verified samples") != NULL &&
             strstr((char *)out, "Source: historical UTXO snapshots") != NULL &&
             strstr((char *)out, "class='hodl-end-label'") != NULL &&
             strstr((char *)out, "class='hodl-x-tick'") != NULL &&
             strstr((char *)out, ".hodl-x-tick{display:none;}") != NULL &&
             strstr((char *)out, "touch-action:pan-x pan-y") != NULL &&
             strstr((char *)out, "touchstart',onTouch,{passive:true}") != NULL &&
             strstr((char *)out, "touchmove',onTouch,{passive:true}") != NULL &&
             strstr((char *)out, "passive:false") == NULL &&
             strstr((char *)out, "Timeline by block height") == NULL &&
             strstr((char *)out, "id='hodl-survival-wrap'") != NULL &&
             strstr((char *)out, "requestAnimationFrame(maybeScrollLatest)") != NULL &&
             strstr((char *)out, "var hmin=") != NULL &&
             strstr((char *)out, "var tmin=") == NULL &&
             strstr((char *)out, "6 months") != NULL &&
             strstr((char *)out, "2 years") != NULL &&
             strstr((char *)out, "5 years") != NULL &&
             strstr((char *)out, "214748") == NULL &&
             strstr((char *)out, "id='hodl-survival-dot-0'") != NULL &&
             strstr((char *)out, "class='hodl-svg-title'") == NULL &&
             strstr((char *)out, "{{") == NULL &&
             strstr((char *)out, "[4320,1000,400,20000,12500,6250,0,80,50,25,0]") != NULL &&
             strstr((char *)out, "[8640,2000,800,37500,25000,12500,6250,300,200,100,50]") != NULL &&
             strstr((char *)out, "[25920,6000,1000,90000,80000,50000,20000,900,800,500,200]") != NULL &&
             strstr((char *)out, "id='hodl-ts'") == NULL &&
             one_year_segments == 1 &&
             strstr((char *)out, "surviving creation") == NULL &&
             strstr((char *)out,
                    "style='max-width:1000px;margin:20px auto'") == NULL &&
             strstr((char *)out,
                    "style='max-width:1000px;margin:18px auto'") == NULL;

        char cmd[384];
        snprintf(cmd, sizeof(cmd), "rm -rf %s", dbdir);
        system(cmd);

        if (ok) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    printf("explorer: HODL sparse history falls back to cohort wave... ");
    {
        char dbdir[256];
        char dbpath[320];
        sqlite3 *db = NULL;
        snprintf(dbdir, sizeof(dbdir), ".zcl_test_explorer_hodl_sparse_%d",
                 (int)getpid());
        mkdir(dbdir, 0755);
        snprintf(dbpath, sizeof(dbpath), "%s/node.db", dbdir);

        bool ok = sqlite3_open(dbpath, &db) == SQLITE_OK;
        ok = ok && sqlite3_exec(db,
            "CREATE TABLE blocks(height INTEGER, hash BLOB, time INTEGER);"
            "CREATE TABLE utxos(height INTEGER, value INTEGER);"
            "CREATE TABLE hodl_history(height INTEGER, time INTEGER,"
            "total_zat INTEGER,"
            "older_6m_zat INTEGER, older_1y_zat INTEGER,"
            "older_2y_zat INTEGER, older_5y_zat INTEGER,"
            "older_6m_pct REAL, older_1y_pct REAL,"
            "older_2y_pct REAL, older_5y_pct REAL,"
            "calc_version INTEGER, source_tip_height INTEGER);"
            "INSERT INTO blocks(height,hash,time) VALUES"
            "(4320,x'1111111111111111111111111111111111111111111111111111111111111111',3000),"
            "(8640,x'2222222222222222222222222222222222222222222222222222222222222222',2000),"
            "(12960,x'3333333333333333333333333333333333333333333333333333333333333333',1000);"
            "INSERT INTO utxos(height,value) VALUES(1,700),(4000,300);"
            "INSERT INTO hodl_history(height,time,total_zat,"
            "older_6m_zat,older_1y_zat,older_2y_zat,older_5y_zat,"
            "older_6m_pct,older_1y_pct,older_2y_pct,older_5y_pct,"
            "calc_version,source_tip_height) VALUES"
            "(4320,3000,700,0,0,0,0,0.0,0.0,0.0,0.0,2,4320),"
            "(12960,1000,1000,100,50,0,0,10.0,5.0,0.0,0.0,2,12960);",
            NULL, NULL, NULL) == SQLITE_OK;
        if (db)
            sqlite3_close(db);

        reducer_frontier_provable_tip_set(12960);
        uint8_t out[65536];
        size_t n = explorer_view_hodl(dbdir, out, sizeof(out) - 1);
        reducer_frontier_provable_tip_reset();
        out[n < sizeof(out) ? n : sizeof(out) - 1] = '\0';

        ok = ok && n > 0 &&
             strstr((char *)out, "HODL wave over time") != NULL &&
             strstr((char *)out, "cohort samples") != NULL &&
             strstr((char *)out, "Source: current surviving transparent UTXO set") != NULL &&
             strstr((char *)out, "Historical HODL wave") == NULL &&
             strstr((char *)out, "var hmin=") != NULL &&
             strstr((char *)out, "var tmin=") == NULL &&
             strstr((char *)out, "214748") == NULL;

        char cmd[384];
        snprintf(cmd, sizeof(cmd), "rm -rf %s", dbdir);
        system(cmd);

        if (ok) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    printf("explorer: HODL page renders latest measurement without refresh prompt... ");
    {
        char dbdir[256];
        char dbpath[320];
        sqlite3 *db = NULL;
        snprintf(dbdir, sizeof(dbdir), ".zcl_test_explorer_hodl_latest_%d",
                 (int)getpid());
        mkdir(dbdir, 0755);
        snprintf(dbpath, sizeof(dbpath), "%s/node.db", dbdir);

        bool ok = sqlite3_open(dbpath, &db) == SQLITE_OK;
        ok = ok && sqlite3_exec(db,
            "CREATE TABLE blocks(height INTEGER, hash BLOB, time INTEGER);"
            "CREATE TABLE utxos(height INTEGER, value INTEGER);"
            "CREATE TABLE hodl_history(height INTEGER, time INTEGER,"
            "total_zat INTEGER,"
            "older_6m_zat INTEGER, older_1y_zat INTEGER,"
            "older_2y_zat INTEGER, older_5y_zat INTEGER,"
            "older_6m_pct REAL, older_1y_pct REAL,"
            "older_2y_pct REAL, older_5y_pct REAL,"
            "calc_version INTEGER, source_tip_height INTEGER);"
            "INSERT INTO blocks(height,hash,time) VALUES"
            "(10,x'1111111111111111111111111111111111111111111111111111111111111111',1000);"
            "INSERT INTO utxos(height,value) VALUES(10,100000000);",
            NULL, NULL, NULL) == SQLITE_OK;
        if (db)
            sqlite3_close(db);

        reducer_frontier_provable_tip_set(10);
        uint8_t out[65536];
        size_t n = explorer_view_hodl(dbdir, out, sizeof(out) - 1);
        reducer_frontier_provable_tip_reset();
        out[n < sizeof(out) ? n : sizeof(out) - 1] = '\0';

        ok = ok && n > 0 &&
             strstr((char *)out, "Unspent transparent value by age") != NULL &&
             strstr((char *)out,
                    "Current transparent UTXO value distribution") != NULL &&
             strstr((char *)out, "id='hodl-age-wave'") != NULL &&
             strstr((char *)out, "id='hodl-age-wrap'") != NULL &&
             strstr((char *)out, "id='hodl-age-canvas'") != NULL &&
             strstr((char *)out,
                    "class='hodl-chart-canvas'><svg id='hodl-age-wave'") != NULL &&
             strstr((char *)out,
                    "var wrap=document.getElementById('hodl-age-canvas')") != NULL &&
             strstr((char *)out, "class='hodl-age-hit'") != NULL &&
             strstr((char *)out, "aria-label='") != NULL &&
             strstr((char *)out, "requestAnimationFrame(maybeScrollSelected)") != NULL &&
             strstr((char *)out,
                    "touchstart',function(e){render(+el.dataset.i);},{passive:true}") != NULL &&
             strstr((char *)out,
                    "touchmove',function(e){render(+el.dataset.i);},{passive:true}") != NULL &&
             strstr((char *)out, "stroke-width='1'><title>") == NULL &&
             strstr((char *)out, "stroke-width='2'><title>") == NULL &&
             strstr((char *)out, "svg.addEventListener('keydown'") != NULL &&
             strstr((char *)out, "id='hodl-ts'") == NULL &&
             strstr((char *)out, "{{") == NULL &&
             strstr((char *)out, "Refresh in a minute") == NULL &&
             strstr((char *)out, "still being indexed") == NULL;
        ok = ok && strstr((char *)out, "Unspent transparent value by age") <
                   strstr((char *)out, "class='stats-row hodl-stats'");

        char cmd[384];
        snprintf(cmd, sizeof(cmd), "rm -rf %s", dbdir);
        system(cmd);

        if (ok) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    printf("explorer: HODL page cache is keyed by block hash... ");
    {
        char dbdir[384];
        char dbpath[448];
        char cachepath[512];
        sqlite3 *db = NULL;
        /* ABSOLUTE, unlike the read-only fixtures above: the HODL view
         * persists its snapshot through platform_private_path_resolve, which
         * realpath()s the destination's parent and refuses any pathname that
         * does not start at the root ("destination parent is not a safe real
         * directory"). A relative datadir means the cache file is never
         * written and the cache assertion below can never pass. */
        ex_abs_dbdir(dbdir, sizeof(dbdir), "hodl_cache");
        mkdir(dbdir, 0755);
        snprintf(dbpath, sizeof(dbpath), "%s/node.db", dbdir);
        snprintf(cachepath, sizeof(cachepath),
                 "%s/explorer/hodl-current-v1.cache", dbdir);

        bool ok = sqlite3_open(dbpath, &db) == SQLITE_OK;
        ok = ok && sqlite3_exec(db,
            "CREATE TABLE blocks(height INTEGER, hash BLOB, time INTEGER);"
            "CREATE TABLE utxos(height INTEGER, value INTEGER);"
            "CREATE TABLE hodl_history(height INTEGER, time INTEGER,"
            "total_zat INTEGER,"
            "older_6m_zat INTEGER, older_1y_zat INTEGER,"
            "older_2y_zat INTEGER, older_5y_zat INTEGER,"
            "older_6m_pct REAL, older_1y_pct REAL,"
            "older_2y_pct REAL, older_5y_pct REAL,"
            "calc_version INTEGER, source_tip_height INTEGER);"
            "INSERT INTO blocks(height,hash,time) VALUES"
            "(10,x'1111111111111111111111111111111111111111111111111111111111111111',1000);"
            "INSERT INTO utxos(height,value) VALUES(10,100000000);",
            NULL, NULL, NULL) == SQLITE_OK;
        if (db)
            sqlite3_close(db);

        reducer_frontier_provable_tip_set(10);
        uint8_t out1[65536];
        uint8_t out2[65536];
        uint8_t out3[65536];
        uint8_t out4[65536];
        size_t n1 = explorer_view_hodl(dbdir, out1, sizeof(out1) - 1);
        out1[n1 < sizeof(out1) ? n1 : sizeof(out1) - 1] = '\0';
        explorer_test_reset_hodl_view_cache();

        ok = ok && sqlite3_open(dbpath, &db) == SQLITE_OK;
        ok = ok && sqlite3_exec(db,
            "DELETE FROM utxos;"
            "INSERT INTO utxos(height,value) VALUES(10,200000000);",
            NULL, NULL, NULL) == SQLITE_OK;
        if (db) {
            sqlite3_close(db);
            db = NULL;
        }

        size_t n2 = explorer_view_hodl(dbdir, out2, sizeof(out2) - 1);
        out2[n2 < sizeof(out2) ? n2 : sizeof(out2) - 1] = '\0';
        explorer_test_reset_hodl_view_cache();

        ok = ok && sqlite3_open(dbpath, &db) == SQLITE_OK;
        ok = ok && sqlite3_exec(db,
            "UPDATE blocks SET hash="
            "x'2222222222222222222222222222222222222222222222222222222222222222'"
            "WHERE height=10;",
            NULL, NULL, NULL) == SQLITE_OK;
        if (db)
            sqlite3_close(db);

        size_t n3 = explorer_view_hodl(dbdir, out3, sizeof(out3) - 1);
        out3[n3 < sizeof(out3) ? n3 : sizeof(out3) - 1] = '\0';
        explorer_test_reset_hodl_view_cache();

        ok = ok && sqlite3_open(dbpath, &db) == SQLITE_OK;
        ok = ok && sqlite3_exec(db,
            "INSERT INTO blocks(height,hash,time) VALUES"
            "(11,x'3333333333333333333333333333333333333333333333333333333333333333',1100);"
            "DELETE FROM utxos;"
            "INSERT INTO utxos(height,value) VALUES(11,300000000);",
            NULL, NULL, NULL) == SQLITE_OK;
        if (db) {
            sqlite3_close(db);
            db = NULL;
        }

        reducer_frontier_provable_tip_set(11);
        size_t n4 = explorer_view_hodl(dbdir, out4, sizeof(out4) - 1);
        out4[n4 < sizeof(out4) ? n4 : sizeof(out4) - 1] = '\0';
        for (int spin = 0;
             spin < 200 && explorer_test_hodl_view_refresh_active();
             spin++) {
            struct timespec ts = { .tv_sec = 0, .tv_nsec = 10000000L };
            nanosleep(&ts, NULL);
        }
        reducer_frontier_provable_tip_reset();

        ok = ok && n1 > 0 && n2 > 0 && n3 > 0 && n4 > 0 &&
             access(cachepath, F_OK) == 0 &&
             strstr((char *)out1, "1.00000000") != NULL &&
             strstr((char *)out2, "1.00000000") != NULL &&
             strstr((char *)out2, "2.00000000") == NULL &&
             strstr((char *)out3, "2.00000000") != NULL &&
             strstr((char *)out4, "verified cached snapshot") != NULL &&
             strstr((char *)out4, "2.00000000") != NULL &&
             strstr((char *)out4, "3.00000000") == NULL &&
             strstr((char *)out4,
                    "verified cached transparent UTXO set") != NULL;

        char cmd[448];
        snprintf(cmd, sizeof(cmd), "rm -rf %s", dbdir);
        system(cmd);

        if (ok) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    printf("explorer: factoids HTML caps to served frontier... ");
    {
        char dbdir[256];
        char dbpath[320];
        sqlite3 *db = NULL;
        snprintf(dbdir, sizeof(dbdir), ".zcl_test_explorer_factoids_%d",
                 (int)getpid());
        mkdir(dbdir, 0755);
        snprintf(dbpath, sizeof(dbpath), "%s/node.db", dbdir);

        bool ok = sqlite3_open(dbpath, &db) == SQLITE_OK;
        ok = ok && sqlite3_exec(db,
            "CREATE TABLE blocks(height INTEGER, hash BLOB, time INTEGER, "
            "status INTEGER, num_tx INTEGER, sapling_value INTEGER, "
            "sprout_value INTEGER);"
            "CREATE TABLE utxos(height INTEGER, value INTEGER);"
            "CREATE TABLE transactions(block_height INTEGER);"
            "CREATE TABLE tx_outputs(block_height INTEGER);"
            "CREATE TABLE view_integrity(height INTEGER);"
            "INSERT INTO blocks(height,hash,time,status,num_tx,"
            "sapling_value,sprout_value) VALUES"
            "(0,x'00',1478403829,3,1,0,0),"
            "(8,x'08',1478404429,3,1,0,0);"
            "INSERT INTO utxos(height,value) VALUES(8,100000000);",
            NULL, NULL, NULL) == SQLITE_OK;
        if (db)
            sqlite3_close(db);

        uint8_t out[16384];
        size_t n = explorer_factoids_build_for_served_tip(
            out, sizeof(out) - 1, dbdir, 7);
        out[n < sizeof(out) ? n : sizeof(out) - 1] = '\0';
        ok = ok && n > 0 &&
             strstr((char *)out, "Current chain height</td><td>7") != NULL &&
             strstr((char *)out, "Current chain height</td><td>8") == NULL;

        char cmd[384];
        snprintf(cmd, sizeof(cmd), "rm -rf %s", dbdir);
        system(cmd);

        if (ok) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    printf("explorer: factoids cache is keyed by block hash... ");
    {
        char dbdir[256];
        char dbpath[320];
        sqlite3 *db = NULL;
        test_make_tmpdir(dbdir, sizeof(dbdir), "explorer",
                         "factoids_cache");
        snprintf(dbpath, sizeof(dbpath), "%s/node.db", dbdir);

        bool ok = sqlite3_open(dbpath, &db) == SQLITE_OK;
        ok = ok && sqlite3_exec(db,
            "CREATE TABLE blocks(height INTEGER, hash BLOB, time INTEGER, "
            "status INTEGER, num_tx INTEGER, bits INTEGER, chain_work BLOB, "
            "sapling_value INTEGER, sprout_value INTEGER);"
            "CREATE TABLE utxos(height INTEGER, value INTEGER, "
            "is_coinbase INTEGER, script_type INTEGER);"
            "CREATE TABLE transactions(block_height INTEGER, "
            "is_coinbase INTEGER, block_hash BLOB, txid BLOB);"
            "CREATE TABLE tx_outputs(block_height INTEGER, value INTEGER, "
            "vout INTEGER, script_type INTEGER);"
            "CREATE TABLE tx_inputs(block_height INTEGER);"
            "CREATE TABLE joinsplits(block_height INTEGER, vpub_old INTEGER, "
            "vpub_new INTEGER);"
            "CREATE TABLE sapling_spends(block_height INTEGER, anchor BLOB);"
            "CREATE TABLE sapling_outputs(block_height INTEGER);"
            "CREATE TABLE sprout_nullifiers(nullifier BLOB);"
            "CREATE TABLE sapling_nullifiers(nullifier BLOB);"
            "CREATE TABLE op_returns(block_height INTEGER, is_slp INTEGER);"
            "CREATE TABLE zslp_tokens(genesis_height INTEGER, ticker TEXT, "
            "name TEXT, decimals INTEGER, token_id BLOB, "
            "total_minted INTEGER);"
            "CREATE TABLE zslp_transfers(block_height INTEGER, "
            "tx_type INTEGER, token_id BLOB);"
            "CREATE TABLE addresses(address_hash BLOB, balance INTEGER, "
            "utxo_count INTEGER, first_seen_height INTEGER, "
            "last_seen_height INTEGER);"
            "CREATE TABLE hodl_history(height INTEGER, time INTEGER, "
            "total_zat INTEGER, older_1y_zat INTEGER, older_1y_pct REAL);"
            "CREATE TABLE view_integrity(height INTEGER);"
            "INSERT INTO blocks(height,hash,time,status,num_tx,bits,chain_work,"
            "sapling_value,sprout_value) VALUES"
            "(0,x'0206260143838b5ff52dc2eb7b4b8099d4e4c99dc3ef19794289a2cd4c100700',1478403829,3,1,0,x'00',0,0),"
            "(8,x'1111111111111111111111111111111111111111111111111111111111111111',1478404429,3,1,0,x'00',0,0);"
            "INSERT INTO utxos(height,value,is_coinbase,script_type) "
            "VALUES(8,100000000,0,0);"
            "INSERT INTO transactions(block_height,is_coinbase,block_hash,txid) "
            "VALUES(0,1,x'0206260143838b5ff52dc2eb7b4b8099d4e4c99dc3ef19794289a2cd4c100700',x'00');"
            "INSERT INTO view_integrity(height) VALUES(0),(8);",
            NULL, NULL, NULL) == SQLITE_OK;
        if (db) {
            sqlite3_close(db);
            db = NULL;
        }

        uint8_t *out = malloc(262144);
        ok = ok && out != NULL;
        if (ok) {
            reducer_frontier_provable_tip_set(8);
            explorer_test_set_datadir(dbdir);
            explorer_test_reset_factoids_cache();
            ok = ok && explorer_test_compute_factoids_cache_now();

            size_t n1 = explorer_handle_request("GET", "/explorer/factoids",
                                                NULL, 0, out, 262143);
            out[n1 < 262144 ? n1 : 262143] = '\0';
            ok = ok && n1 > 0 &&
                 strstr((char *)out, "1111111111111111") != NULL;

            ok = ok && sqlite3_open(dbpath, &db) == SQLITE_OK;
            ok = ok && sqlite3_exec(db,
                "UPDATE blocks SET hash="
                "x'2222222222222222222222222222222222222222222222222222222222222222'"
                "WHERE height=8;",
                NULL, NULL, NULL) == SQLITE_OK;
            if (db) {
                sqlite3_close(db);
                db = NULL;
            }

            size_t n2 = explorer_handle_request("GET", "/explorer/factoids",
                                                NULL, 0, out, 262143);
            out[n2 < 262144 ? n2 : 262143] = '\0';
            ok = ok && n2 > 0 &&
                 strstr((char *)out, "1111111111111111") == NULL;
            for (int spin = 0;
                 spin < 200 && explorer_test_factoids_compute_active();
                 spin++) {
                struct timespec ts = { .tv_sec = 0, .tv_nsec = 10000000L };
                nanosleep(&ts, NULL);
            }
            ok = ok && !explorer_test_factoids_compute_active();

            ok = ok && explorer_test_compute_factoids_cache_now();
            size_t n3 = explorer_handle_request("GET", "/explorer/factoids",
                                                NULL, 0, out, 262143);
            out[n3 < 262144 ? n3 : 262143] = '\0';
            ok = ok && n3 > 0 &&
                 strstr((char *)out, "2222222222222222") != NULL &&
                 strstr((char *)out, "1111111111111111") == NULL;

            explorer_test_reset_factoids_cache();
            explorer_test_set_datadir(NULL);
            reducer_frontier_provable_tip_reset();
        }
        free(out);

        test_rm_rf_recursive(dbdir);

        if (ok) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    printf("explorer: /explorer/style.css returns CSS... ");
    {
        size_t n = explorer_handle_request("GET", "/explorer/style.css", NULL, 0,
                                            resp, sizeof(resp));
        resp[n < sizeof(resp) ? n : sizeof(resp) - 1] = '\0';
        bool ok = (n > 0 && strstr((char *)resp, "text/css") != NULL);
        if (ok) printf("OK\n");
        else { printf("FAIL (n=%zu)\n", n); failures++; }
    }

    printf("explorer: compiled CSS includes full explorer stylesheet... ");
    {
        const char *css = site_css;
        bool ok = css &&
             strstr(css, "color-scheme:dark") != NULL &&
             strstr(css, ".table-wrap") != NULL &&
             strstr(css, ".back-to-top") != NULL;
        if (ok) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    printf("explorer: compiled CSS wins over stale datadir stylesheet... ");
    {
        char dbdir[256];
        char csspath[320];
        uint8_t css_resp[20000];
        snprintf(dbdir, sizeof(dbdir), ".zcl_test_explorer_css_%d",
                 (int)getpid());
        mkdir(dbdir, 0755);
        explorer_set_state(NULL, NULL, NULL, NULL, dbdir);
        snprintf(csspath, sizeof(csspath), "%s/explorer/style.css", dbdir);
        FILE *f = fopen(csspath, "w");
        bool ok = f != NULL;
        if (f) {
            ok = fputs("body{background:#badbad}.stale-css-marker{}", f) >= 0;
            fclose(f);
        }
        unsetenv("ZCL_EXPLORER_CSS_FILE");
        unsetenv("ZCL_EXPLORER_CSS_LIVE");
        size_t n = explorer_handle_request("GET", "/explorer/style.css",
                                            NULL, 0, css_resp,
                                            sizeof(css_resp) - 1);
        css_resp[n < sizeof(css_resp) ? n : sizeof(css_resp) - 1] = '\0';
        ok = ok && n > 0 &&
             strstr((char *)css_resp, "text/css") != NULL &&
             strstr((char *)css_resp, ".back-to-top") != NULL &&
             strstr((char *)css_resp, "stale-css-marker") == NULL;
        explorer_test_set_datadir(NULL);

        char cmd[384];
        snprintf(cmd, sizeof(cmd), "rm -rf %s", dbdir);
        system(cmd);

        if (ok) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    /* ── Supply calculation edge cases ───────────────────── */

    printf("explorer: supply at negative height is 0... ");
    {
        int64_t s = compute_supply_at_height(-1);
        bool ok = (s == 0);
        if (ok) printf("OK\n");
        else { printf("FAIL (got %" PRId64 ")\n", s); failures++; }
    }

    printf("explorer: supply at height 2387001 shows next halving... ");
    {
        /* At 2,387,001: halvings_raw = (2387001-707000-1)/1680000 = 1680000/1680000 = 1
         * halvings = 1+3 = 4, subsidy = 625000000 >> 4 = 39062500 sat = 0.390625 ZCL */
        int64_t s_before = compute_supply_at_height(2387000);
        int64_t s_at = compute_supply_at_height(2387001);
        int64_t s_after = compute_supply_at_height(2387002);
        /* Check that the rate changed: increment at 2387001 should be less
         * than increment at 2387000 */
        int64_t inc_before = s_at - s_before;  /* last block of era 3 or first of era 4 */
        int64_t inc_after = s_after - s_at;     /* era 4 rate */
        /* Both should be positive */
        bool ok = (inc_before > 0 && inc_after > 0 && inc_after <= inc_before);
        if (ok) printf("OK (rate: %" PRId64 " -> %" PRId64 " sat/block)\n",
                       inc_before, inc_after);
        else { printf("FAIL (inc_before=%" PRId64 ", inc_after=%" PRId64 ")\n",
                      inc_before, inc_after); failures++; }
    }

    printf("explorer: SHA3 receipt is deterministic... ");
    {
        /* compute_receipt is static in factoids — test SHA3 directly */
        struct sha3_256_ctx ctx;
        sha3_256_init(&ctx);
        uint8_t data[] = {0x01, 0x02, 0x03};
        sha3_256_write(&ctx, data, 3);
        unsigned char d1[32];
        sha3_256_finalize(&ctx, d1);

        sha3_256_init(&ctx);
        sha3_256_write(&ctx, data, 3);
        unsigned char d2[32];
        sha3_256_finalize(&ctx, d2);

        bool ok = (memcmp(d1, d2, 32) == 0);
        if (ok) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    printf("explorer: SHA3 different inputs give different hashes... ");
    {
        struct sha3_256_ctx ctx;
        unsigned char d1[32], d2[32];

        sha3_256_init(&ctx);
        uint8_t a[] = {0x01};
        sha3_256_write(&ctx, a, 1);
        sha3_256_finalize(&ctx, d1);

        sha3_256_init(&ctx);
        uint8_t b[] = {0x02};
        sha3_256_write(&ctx, b, 1);
        sha3_256_finalize(&ctx, d2);

        bool ok = (memcmp(d1, d2, 32) != 0);
        if (ok) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    printf("explorer: factoids checkpoint section renders receipts... ");
    {
        sqlite3 *db = NULL;
        sqlite3_open(":memory:", &db);
        sqlite3_exec(db,
            "CREATE TABLE blocks(height INTEGER, hash BLOB, time INTEGER)",
            NULL, NULL, NULL);
        sqlite3_exec(db,
            "INSERT INTO blocks(height,hash,time) VALUES"
            "(30000,x'000000005c2ad200c3c7c8e627f67b306659efca1268c9bb014335fdadc0c392',1482903829)",
            NULL, NULL, NULL);
        uint8_t out[8192];
        size_t n = factoids_emit_section_12_checkpoints(
            out, sizeof(out) - 1, 0, db, 3054000);
        out[n < sizeof(out) ? n : sizeof(out) - 1] = '\0';

        char expected[32] = "";
        compute_receipt(expected, sizeof(expected), 3054000,
                        "000005aa8e8c321cf364788e81b94619434b0dc1a85e658a022b44f23eb85662",
                        "checkpoint");
        bool ok = n > 0 &&
                  strstr((const char *)out, "12. Checkpoint History") != NULL &&
                  strstr((const char *)out, "/explorer/block/3054000") != NULL &&
                  strstr((const char *)out, "000005aa8e8c321c...") != NULL &&
                  strstr((const char *)out, expected) != NULL &&
                  strstr((const char *)out, "Not yet reached") == NULL;
        sqlite3_close(db);
        if (ok) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    printf("explorer: factoids integrity section renders coverage and hash... ");
    {
        sqlite3 *db = NULL;
        sqlite3_open(":memory:", &db);
        sqlite3_exec(db,
            "CREATE TABLE blocks(height INTEGER, hash TEXT, time INTEGER, "
            "num_tx INTEGER, sapling_value INTEGER, sprout_value INTEGER)",
            NULL, NULL, NULL);
        sqlite3_exec(db,
            "CREATE TABLE transactions(is_coinbase INTEGER)",
            NULL, NULL, NULL);
        sqlite3_exec(db, "CREATE TABLE tx_inputs(block_height INTEGER)",
                     NULL, NULL, NULL);
        sqlite3_exec(db, "CREATE TABLE tx_outputs(block_height INTEGER)",
                     NULL, NULL, NULL);
        sqlite3_exec(db,
            "INSERT INTO blocks(height,hash,time,num_tx,sapling_value,sprout_value) "
            "VALUES"
            "(1,'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',10,1,0,0),"
            "(2,'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb',20,2,3,4),"
            "(101,'cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc',30,3,5,6)",
            NULL, NULL, NULL);
        sqlite3_exec(db,
            "INSERT INTO transactions(is_coinbase) VALUES(1),(0),(0)",
            NULL, NULL, NULL);

        char expected[128] = "";
        compute_integrity_hash(db, 101, expected, sizeof(expected));

        uint8_t out[8192];
        size_t n = factoids_emit_section_17_integrity(
            out, sizeof(out) - 1, 0, db, 101, 3);
        out[n < sizeof(out) ? n : sizeof(out) - 1] = '\0';

        bool ok = n > 0 &&
                  strstr((const char *)out, "17. Data Integrity") != NULL &&
                  strstr((const char *)out, "Chain height:</b> 101") != NULL &&
                  strstr((const char *)out, "Indexed blocks:</b> 3") != NULL &&
                  strstr((const char *)out, "Indexed transactions:</b> 3") != NULL &&
                  strstr((const char *)out, "blocks 2") != NULL &&
                  strstr((const char *)out, "101 (last 100)") != NULL &&
                  strstr((const char *)out, expected) != NULL;
        sqlite3_close(db);
        if (ok) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    printf("explorer: factoids difficulty section renders records... ");
    {
        sqlite3 *db = NULL;
        sqlite3_open(":memory:", &db);
        sqlite3_exec(db,
            "CREATE TABLE blocks(height INTEGER, time INTEGER, bits INTEGER, "
            "chain_work BLOB)",
            NULL, NULL, NULL);
        sqlite3_exec(db,
            "INSERT INTO blocks(height,time,bits,chain_work) VALUES"
            "(0,1478403829,520617983,x'01000000'),"
            "(3000000,1780000000,504365055,x'02000000'),"
            "(3000001,1780000075,504207743,x'03000000')",
            NULL, NULL, NULL);

        char expected[32] = "";
        compute_receipt(expected, sizeof(expected), 3000001, "",
                        "hardest_block");

        uint8_t out[8192];
        size_t n = factoids_emit_section_16_difficulty(
            out, sizeof(out) - 1, 0, db);
        out[n < sizeof(out) ? n : sizeof(out) - 1] = '\0';

        bool ok = n > 0 &&
                  strstr((const char *)out, "16. Difficulty History") != NULL &&
                  strstr((const char *)out, "Difficulty Records") != NULL &&
                  strstr((const char *)out, "0x1e0d997f") != NULL &&
                  strstr((const char *)out, "/explorer/block/3000001") != NULL &&
                  strstr((const char *)out, "2 distinct targets") != NULL &&
                  strstr((const char *)out, "recent 2 blocks") != NULL &&
                  strstr((const char *)out, "Cumulative chain-work at tip") != NULL &&
                  strstr((const char *)out, "Peak Difficulty") != NULL &&
                  strstr((const char *)out, expected) != NULL;
        sqlite3_close(db);
        if (ok) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    printf("explorer: factoids empty-block section renders records... ");
    {
        sqlite3 *db = NULL;
        sqlite3_open(":memory:", &db);
        sqlite3_exec(db,
            "CREATE TABLE blocks(height INTEGER, time INTEGER, num_tx INTEGER)",
            NULL, NULL, NULL);
        sqlite3_exec(db,
            "INSERT INTO blocks(height,time,num_tx) VALUES"
            "(1,1478403829,2),"
            "(2,1478403900,1),"
            "(3,1478403975,1),"
            "(4,1478404050,5),"
            "(5,1478404125,1),"
            "(6,1478404200,1),"
            "(7,1478404275,1),"
            "(8,1478404350,3)",
            NULL, NULL, NULL);

        char summary_expected[32] = "";
        char records_expected[32] = "";
        compute_receipt_i64(summary_expected, sizeof(summary_expected),
                            5, 8, "empty_blocks");
        compute_receipt_i64(records_expected, sizeof(records_expected),
                            4, 3, "empty_block_records");

        uint8_t out[8192];
        size_t n = factoids_emit_section_15_empty_blocks(
            out, sizeof(out) - 1, 0, db);
        out[n < sizeof(out) ? n : sizeof(out) - 1] = '\0';

        bool ok = n > 0 &&
                  strstr((const char *)out, "15. Empty Blocks Analysis") != NULL &&
                  strstr((const char *)out, "5 of 8 (62.5%)") != NULL &&
                  strstr((const char *)out, "Empty Blocks Per Year") != NULL &&
                  strstr((const char *)out,
                         "<tr><td>2016</td><td>5</td><td>8</td><td>62.5%</td></tr>") != NULL &&
                  strstr((const char *)out, "Records") != NULL &&
                  strstr((const char *)out, "5 transactions at block") != NULL &&
                  strstr((const char *)out, "/explorer/block/4") != NULL &&
                  strstr((const char *)out,
                         "Longest run of consecutive empty blocks:</b> 3") != NULL &&
                  strstr((const char *)out, "heights 5") != NULL &&
                  strstr((const char *)out, "7)") != NULL &&
                  strstr((const char *)out, summary_expected) != NULL &&
                  strstr((const char *)out, records_expected) != NULL;
        sqlite3_close(db);
        if (ok) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    printf("explorer: factoids blocktime section renders cadence records... ");
    {
        sqlite3 *db = NULL;
        sqlite3_open(":memory:", &db);
        sqlite3_exec(db,
            "CREATE TABLE blocks(height INTEGER, time INTEGER)",
            NULL, NULL, NULL);
        sqlite3_exec(db,
            "INSERT INTO blocks(height,time) VALUES"
            "(1,1478403829),"
            "(2,1478403979),"
            "(3,1478404139),"
            "(707000,1600000000),"
            "(707001,1600000005),"
            "(707002,1600003706)",
            NULL, NULL, NULL);

        char pre_expected[32] = "";
        char post_expected[32] = "";
        char records_expected[32] = "";
        compute_receipt_i64(pre_expected, sizeof(pre_expected),
                            155, 2, "blocktime_pre_bc");
        compute_receipt_i64(post_expected, sizeof(post_expected),
                            1853, 2, "blocktime_post_bc");
        compute_receipt_i64(records_expected, sizeof(records_expected),
                            1, 1, "blocktime_records");

        uint8_t out[8192];
        size_t n = factoids_emit_section_13_blocktimes(
            out, sizeof(out) - 1, 0, db, 707002);
        out[n < sizeof(out) ? n : sizeof(out) - 1] = '\0';

        bool ok = n > 0 &&
                  strstr((const char *)out, "13. Block Time Analysis") != NULL &&
                  strstr((const char *)out, "Pre-Buttercup") != NULL &&
                  strstr((const char *)out, "155.0s") != NULL &&
                  strstr((const char *)out, "150s") != NULL &&
                  strstr((const char *)out, "160s") != NULL &&
                  strstr((const char *)out, "Post-Buttercup") != NULL &&
                  strstr((const char *)out, "1853.0s") != NULL &&
                  strstr((const char *)out, "5s") != NULL &&
                  strstr((const char *)out, "3701s") != NULL &&
                  strstr((const char *)out, "Block Interval Records") != NULL &&
                  strstr((const char *)out, "1 (25.0%)") != NULL &&
                  strstr((const char *)out, "Blocks over 1 hour apart:</b></td><td>1") != NULL &&
                  strstr((const char *)out, pre_expected) != NULL &&
                  strstr((const char *)out, post_expected) != NULL &&
                  strstr((const char *)out, records_expected) != NULL;
        sqlite3_close(db);
        if (ok) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    printf("explorer: factoids transaction section renders records... ");
    {
        sqlite3 *db = NULL;
        sqlite3_open(":memory:", &db);
        sqlite3_exec(db,
            "CREATE TABLE blocks(height INTEGER, hash TEXT, time INTEGER, num_tx INTEGER)",
            NULL, NULL, NULL);
        sqlite3_exec(db,
            "CREATE TABLE transactions(block_hash TEXT, block_height INTEGER, "
            "is_coinbase INTEGER)",
            NULL, NULL, NULL);
        sqlite3_exec(db,
            "CREATE TABLE tx_inputs(block_height INTEGER)",
            NULL, NULL, NULL);
        sqlite3_exec(db,
            "CREATE TABLE tx_outputs(txid TEXT, vout INTEGER, value INTEGER, "
            "script_type INTEGER, block_height INTEGER)",
            NULL, NULL, NULL);
        sqlite3_exec(db,
            "CREATE TABLE op_returns(block_height INTEGER, is_slp INTEGER)",
            NULL, NULL, NULL);
        sqlite3_exec(db,
            "INSERT INTO blocks(height,hash,time,num_tx) VALUES"
            "(1,'h1',1478403829,2),"
            "(2,'h2',1478403979,2)",
            NULL, NULL, NULL);
        sqlite3_exec(db,
            "INSERT INTO transactions(block_hash,block_height,is_coinbase) VALUES"
            "('h1',1,1),('h1',1,0),('h2',2,1),('h2',2,0)",
            NULL, NULL, NULL);
        sqlite3_exec(db,
            "INSERT INTO tx_inputs(block_height) VALUES(1),(2),(2)",
            NULL, NULL, NULL);
        sqlite3_exec(db,
            "INSERT INTO tx_outputs(txid,vout,value,script_type,block_height) VALUES"
            "('a',0,100000000,0,1),"
            "('b',0,200000000,0,1),"
            "('c',1,300000000,1,2),"
            "('d',2,400000000,2,2)",
            NULL, NULL, NULL);
        sqlite3_exec(db,
            "INSERT INTO op_returns(block_height,is_slp) VALUES(1,0),(2,1)",
            NULL, NULL, NULL);

        char summary_expected[32] = "";
        char records_expected[32] = "";
        compute_receipt_i64(summary_expected, sizeof(summary_expected),
                            4, 3, "tx_archaeology");
        compute_receipt_i64(records_expected, sizeof(records_expected),
                            1000000000, 4, "tx_records");

        uint8_t out[8192];
        size_t n = factoids_emit_section_14_transactions(
            out, sizeof(out) - 1, 0, db);
        out[n < sizeof(out) ? n : sizeof(out) - 1] = '\0';

        bool ok = n > 0 &&
                  strstr((const char *)out, "14. Transaction Archaeology") != NULL &&
                  strstr((const char *)out, "Total transactions:</b></td><td>4") != NULL &&
                  strstr((const char *)out, "Coinbase transactions:</b></td><td>2") != NULL &&
                  strstr((const char *)out, "Non-coinbase transactions:</b></td><td>2") != NULL &&
                  strstr((const char *)out, "Total transparent inputs:</b></td><td>3") != NULL &&
                  strstr((const char *)out, "Total transparent outputs:</b></td><td>4") != NULL &&
                  strstr((const char *)out, "Total OP_RETURN outputs:</b></td><td>2") != NULL &&
                  strstr((const char *)out,
                         "<tr><td>2016</td><td>4</td><td>2</td><td>2</td><td>2.00</td></tr>") != NULL &&
                  strstr((const char *)out, "10.00000000 ZCL across 4 outputs") != NULL &&
                  strstr((const char *)out, "3 outputs at block") != NULL &&
                  strstr((const char *)out, "/explorer/block/2") != NULL &&
                  strstr((const char *)out, "4.00000000 ZCL") != NULL &&
                  strstr((const char *)out, "/explorer/block/1") != NULL &&
                  strstr((const char *)out, "Avg inputs per spending tx:</b></td><td>1.50") != NULL &&
                  strstr((const char *)out, "<tr><td>P2PKH</td><td>2</td></tr>") != NULL &&
                  strstr((const char *)out, "<tr><td>P2SH</td><td>1</td></tr>") != NULL &&
                  strstr((const char *)out, "<tr><td>OP_RETURN</td><td>1</td></tr>") != NULL &&
                  strstr((const char *)out, summary_expected) != NULL &&
                  strstr((const char *)out, records_expected) != NULL;
        sqlite3_close(db);
        if (ok) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    printf("explorer: stats gather collapses tx_outputs aggregates... ");
    {
        sqlite3 *db = NULL;
        bool ok = sqlite3_open(":memory:", &db) == SQLITE_OK;
        ok = ok && sqlite3_exec(db,
            "CREATE TABLE blocks(height INTEGER, time INTEGER);"
            "CREATE TABLE transactions(block_height INTEGER, is_coinbase INTEGER);"
            "CREATE TABLE tx_inputs(block_height INTEGER);"
            "CREATE TABLE tx_outputs(value INTEGER, script_type INTEGER, "
            "block_height INTEGER);"
            "CREATE TABLE joinsplits(block_height INTEGER, vpub_old INTEGER, "
            "vpub_new INTEGER);"
            "CREATE TABLE sapling_spends(block_height INTEGER, anchor BLOB);"
            "CREATE TABLE sapling_outputs(block_height INTEGER);"
            "CREATE TABLE sprout_nullifiers(nullifier BLOB);"
            "CREATE TABLE op_returns(block_height INTEGER);"
            "CREATE TABLE zslp_tokens(genesis_height INTEGER);"
            "CREATE TABLE view_integrity(height INTEGER, sha3_hash BLOB);"
            "INSERT INTO blocks(height,time) VALUES(1,1000),(2,1150);"
            "INSERT INTO transactions(block_height,is_coinbase) VALUES"
            "(1,1),(2,0);"
            "INSERT INTO tx_inputs(block_height) VALUES(2),(2);"
            "INSERT INTO tx_outputs(value,script_type,block_height) VALUES"
            "(100000000,0,1),"
            "(300000000,0,1),"
            "(250000000,1,2),"
            "(50000000,2,2);"
            "INSERT INTO joinsplits(block_height,vpub_old,vpub_new) VALUES"
            "(2,7,11);"
            "INSERT INTO sapling_spends(block_height,anchor) VALUES(2,x'aa');"
            "INSERT INTO sapling_outputs(block_height) VALUES(2);"
            "INSERT INTO sprout_nullifiers(nullifier) VALUES(x'bb');"
            "INSERT INTO op_returns(block_height) VALUES(2);"
            "INSERT INTO zslp_tokens(genesis_height) VALUES(2);"
            "INSERT INTO view_integrity(height,sha3_hash) VALUES(2,zeroblob(32));",
            NULL, NULL, NULL) == SQLITE_OK;

        struct stats_ctx c = {0};
        if (ok)
            gather_deep_chain_data(db, &c);
        ok = ok &&
             c.total_outputs == 4 &&
             c.total_inputs == 2 &&
             c.p2pkh_outputs == 2 &&
             c.p2sh_outputs == 1 &&
             c.max_output_value == 300000000 &&
             c.total_value_moved == 700000000;

        if (db)
            sqlite3_close(db);
        if (ok) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    printf("explorer: factoids records section renders records... ");
    {
        sqlite3 *db = NULL;
        sqlite3_open(":memory:", &db);
        sqlite3_exec(db,
            "CREATE TABLE blocks(height INTEGER, time INTEGER, num_tx INTEGER, "
            "bits INTEGER, sapling_value INTEGER)",
            NULL, NULL, NULL);
        sqlite3_exec(db,
            "CREATE TABLE utxos(value INTEGER, height INTEGER)",
            NULL, NULL, NULL);
        sqlite3_exec(db,
            "CREATE TABLE tx_outputs(value INTEGER)",
            NULL, NULL, NULL);
        sqlite3_exec(db,
            "CREATE TABLE joinsplits(block_height INTEGER)",
            NULL, NULL, NULL);
        sqlite3_exec(db,
            "CREATE TABLE sapling_outputs(block_height INTEGER)",
            NULL, NULL, NULL);
        sqlite3_exec(db,
            "CREATE TABLE hodl_history(height INTEGER, older_1y_pct REAL)",
            NULL, NULL, NULL);
        sqlite3_exec(db,
            "INSERT INTO blocks(height,time,num_tx,bits,sapling_value) VALUES"
            "(1,1478403829,1,520617983,0),"
            "(2,1478403929,4,504207743,500000000),"
            "(3,1478404129,2,504365055,-300000000),"
            "(707000,1600000000,1,504365055,0)",
            NULL, NULL, NULL);
        sqlite3_exec(db,
            "INSERT INTO utxos(value,height) VALUES"
            "(1200000000,1),(500000000,707000)",
            NULL, NULL, NULL);
        sqlite3_exec(db,
            "INSERT INTO tx_outputs(value) VALUES(2000000000),(300000000)",
            NULL, NULL, NULL);
        sqlite3_exec(db,
            "INSERT INTO joinsplits(block_height) VALUES(2),(2)",
            NULL, NULL, NULL);
        sqlite3_exec(db,
            "INSERT INTO sapling_outputs(block_height) VALUES(3),(3),(3)",
            NULL, NULL, NULL);
        sqlite3_exec(db,
            "INSERT INTO hodl_history(height,older_1y_pct) VALUES"
            "(3,12.5),(4,15.25)",
            NULL, NULL, NULL);

        char unspent_expected[32] = "";
        char ever_expected[32] = "";
        char hodl_expected[32] = "";
        compute_receipt(unspent_expected, sizeof(unspent_expected),
                        1, "", "Largest unspent transparent output");
        compute_receipt_i64(ever_expected, sizeof(ever_expected),
                            2000000000LL, 0,
                            "Largest transparent output ever");
        compute_receipt_i64(hodl_expected, sizeof(hodl_expected),
                            4, 15250, "hodl_dormant_1y");

        uint8_t out[16384];
        size_t n = factoids_emit_section_5_records(
            out, sizeof(out) - 1, 0, db);
        out[n < sizeof(out) ? n : sizeof(out) - 1] = '\0';

        bool ok = n > 0 &&
                  strstr((const char *)out, "5. All-Time Records") != NULL &&
                  strstr((const char *)out,
                         "Largest unspent transparent output") != NULL &&
                  strstr((const char *)out, "12.00000000 ZCL") != NULL &&
                  strstr((const char *)out,
                         "Largest transparent output ever") != NULL &&
                  strstr((const char *)out, "20.00000000 ZCL") != NULL &&
                  strstr((const char *)out, "Most transactions in a block") != NULL &&
                  strstr((const char *)out, "/explorer/block/2") != NULL &&
                  strstr((const char *)out, "Most JoinSplits in a block") != NULL &&
                  strstr((const char *)out, "Most Sapling outputs in a block") != NULL &&
                  strstr((const char *)out,
                         "Largest single-block shielding") != NULL &&
                  strstr((const char *)out, "5.00000000 ZCL") != NULL &&
                  strstr((const char *)out,
                         "Largest single-block unshielding") != NULL &&
                  strstr((const char *)out, "3.00000000 ZCL") != NULL &&
                  strstr((const char *)out,
                         "Most blocks mined in one UTC day") != NULL &&
                  strstr((const char *)out, "Oldest coin still unspent") != NULL &&
                  strstr((const char *)out,
                         "Supply dormant &gt; 1 year") != NULL &&
                  strstr((const char *)out,
                         "Coins predating Buttercup") != NULL &&
                  strstr((const char *)out, unspent_expected) != NULL &&
                  strstr((const char *)out, ever_expected) != NULL &&
                  strstr((const char *)out, hodl_expected) != NULL;
        sqlite3_close(db);
        if (ok) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    printf("explorer: factoids address section renders holders... ");
    {
        sqlite3 *db = NULL;
        sqlite3_open(":memory:", &db);
        sqlite3_exec(db,
            "CREATE TABLE blocks(height INTEGER, time INTEGER)",
            NULL, NULL, NULL);
        sqlite3_exec(db,
            "CREATE TABLE addresses(address_hash BLOB, balance INTEGER, "
            "utxo_count INTEGER, first_seen_height INTEGER, "
            "last_seen_height INTEGER)",
            NULL, NULL, NULL);
        sqlite3_exec(db,
            "INSERT INTO blocks(height,time) VALUES"
            "(10,1478403829),(20,1478404829),(30,1478405829)",
            NULL, NULL, NULL);
        sqlite3_exec(db,
            "INSERT INTO addresses(address_hash,balance,utxo_count,"
            "first_seen_height,last_seen_height) VALUES"
            "(x'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',100000000000,2,10,10),"
            "(x'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb',10000000000,1,20,30),"
            "(x'cccccccccccccccccccccccccccccccccccccccc',0,0,30,30)",
            NULL, NULL, NULL);

        char stats_expected[32] = "";
        char concentration_expected[32] = "";
        compute_receipt_i64(stats_expected, sizeof(stats_expected),
                            3, 2, "addr_stats");
        compute_receipt_i64(concentration_expected,
                            sizeof(concentration_expected),
                            110000000000LL, 110000000000LL,
                            "addr_concentration");

        uint8_t out[16384];
        size_t n = factoids_emit_section_7_addresses(
            out, sizeof(out) - 1, 0, db);
        out[n < sizeof(out) ? n : sizeof(out) - 1] = '\0';

        bool ok = n > 0 &&
                  strstr((const char *)out, "7. Address Statistics") != NULL &&
                  strstr((const char *)out,
                         "Addresses currently holding coins:</b> 2") != NULL &&
                  strstr((const char *)out,
                         "(of 3 in the index; 1 carry a zero balance)") != NULL &&
                  strstr((const char *)out, "Holding \xe2\x89\xa5 1 ZCL") != NULL &&
                  strstr((const char *)out, "Holding \xe2\x89\xa5 1,000 ZCL") != NULL &&
                  strstr((const char *)out,
                         "None \xe2\x80\x94 no address holds a million ZCL") != NULL &&
                  strstr((const char *)out,
                         "Distribution &amp; Concentration") != NULL &&
                  strstr((const char *)out,
                         "Top 10 addresses hold</b></td><td>100.00%") != NULL &&
                  strstr((const char *)out,
                         "1100.00000000 ZCL held across 2 funded") != NULL &&
                  strstr((const char *)out, "1000.00000000 ZCL") != NULL &&
                  strstr((const char *)out, "550.00000000 ZCL") != NULL &&
                  strstr((const char *)out, "/explorer/block/10") != NULL &&
                  strstr((const char *)out, "Top 10 Richest Addresses") != NULL &&
                  strstr((const char *)out, "AAAAAAAAAAAAAAAA...") != NULL &&
                  strstr((const char *)out, stats_expected) != NULL &&
                  strstr((const char *)out, concentration_expected) != NULL;
        sqlite3_close(db);
        if (ok) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    printf("explorer: difficulty_from_bits handles edge cases... ");
    {
        double d0 = explorer_difficulty_from_bits(0);
        bool ok = (d0 == 1.0);
        /* Current live-chain bits observed at h=3112518. Legacy zclassicd
         * reports difficulty 150.5924424103772 for this compact target. */
        double live = explorer_difficulty_from_bits(0x1e0d997f);
        double d1 = explorer_difficulty_from_bits(0x1f07ffff);
        ok = ok && (d1 > 0.0) &&
             (live > 150.5924 && live < 150.5925);
        if (ok) printf("OK (bits=0 -> %.1f, bits=0x1f07ffff -> %.4f, live -> %.4f)\n",
                       d0, d1, live);
        else { printf("FAIL\n"); failures++; }
    }

    printf("explorer: format_zcl handles negative values... ");
    {
        char buf[64];
        zcl_format_zcl(buf, sizeof(buf), -100000000LL);
        bool ok = (strcmp(buf, "-1.00000000") == 0);
        if (ok) printf("OK\n");
        else { printf("FAIL (got '%s')\n", buf); failures++; }
    }

    printf("explorer: format_zcl handles zero... ");
    {
        char buf[64];
        zcl_format_zcl(buf, sizeof(buf), 0);
        bool ok = (strcmp(buf, "0.00000000") == 0);
        if (ok) printf("OK\n");
        else { printf("FAIL (got '%s')\n", buf); failures++; }
    }

    printf("explorer: format_zcl handles 12.5 ZCL... ");
    {
        char buf[64];
        zcl_format_zcl(buf, sizeof(buf), 1250000000LL);
        bool ok = (strcmp(buf, "12.50000000") == 0);
        if (ok) printf("OK\n");
        else { printf("FAIL (got '%s')\n", buf); failures++; }
    }

    printf("explorer: HODL wave bucket boundaries are canonical... ");
    {
        int young = hodl_wave_bucket_index(0);
        int year = hodl_wave_bucket_index(31557600LL);
        int very_old = hodl_wave_bucket_index(200000000LL);
        bool ok = (young == 0 && year == 6 &&
                   very_old == HODL_WAVE_BUCKETS - 1);
        if (ok) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    printf("explorer: HODL wave validation catches drift... ");
    {
        struct hodl_wave_snapshot h = {0};
        struct ar_errors errors;
        h.tip_height = 100;
        h.total_value = 100;
        h.total_count = 1;
        memcpy(h.buckets, hodl_wave_bucket_defs(), sizeof(h.buckets));
        h.buckets[0].value = 90;
        h.buckets[0].count = 1;
        snprintf(h.source, sizeof(h.source), "current_transparent_utxo_set");
        snprintf(h.metric, sizeof(h.metric), "utxo_age_distribution");
        snprintf(h.status, sizeof(h.status), "ok");
        bool ok = !hodl_wave_validate(&h, &errors) &&
                  strstr(ar_errors_full(&errors), "bucket.value") != NULL;
        if (ok) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    printf("explorer: history validation rejects display-order genesis... ");
    {
        sqlite3 *db = NULL;
        sqlite3_open(":memory:", &db);
        sqlite3_exec(db, "CREATE TABLE blocks(height INTEGER, hash BLOB, time INTEGER, status INTEGER)", NULL, NULL, NULL);
        sqlite3_exec(db, "CREATE TABLE transactions(block_height INTEGER)", NULL, NULL, NULL);
        sqlite3_exec(db, "CREATE TABLE tx_outputs(block_height INTEGER)", NULL, NULL, NULL);
        sqlite3_exec(db, "CREATE TABLE view_integrity(height INTEGER, sha3_hash BLOB)", NULL, NULL, NULL);
        sqlite3_exec(db,
            "INSERT INTO blocks(height,hash,time) VALUES"
            "(0,x'0007104ccda289427919efc39dc9e4d499804b7bebc22df55f8b834301260602',1478403829),"
            "(1,x'1111111111111111111111111111111111111111111111111111111111111111',1478403979)",
            NULL, NULL, NULL);
        sqlite3_exec(db, "INSERT INTO transactions(block_height) VALUES(0)", NULL, NULL, NULL);
        sqlite3_exec(db, "INSERT INTO tx_outputs(block_height) VALUES(0)", NULL, NULL, NULL);
        sqlite3_exec(db, "INSERT INTO view_integrity(height,sha3_hash) VALUES(0,zeroblob(32)),(1,zeroblob(32))", NULL, NULL, NULL);
        struct explorer_history_validation v;
        explorer_validate_block_history(db, 1, &v);
        bool ok = (!v.usable &&
                   strstr(v.reason, "genesis hash") != NULL);
        sqlite3_close(db);
        if (ok) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    printf("explorer: history validation catches partial derived tables... ");
    {
        sqlite3 *db = NULL;
        sqlite3_open(":memory:", &db);
        sqlite3_exec(db, "CREATE TABLE blocks(height INTEGER, hash BLOB, time INTEGER, status INTEGER)", NULL, NULL, NULL);
        sqlite3_exec(db, "CREATE TABLE transactions(block_height INTEGER)", NULL, NULL, NULL);
        sqlite3_exec(db, "CREATE TABLE tx_outputs(block_height INTEGER)", NULL, NULL, NULL);
        sqlite3_exec(db, "CREATE TABLE view_integrity(height INTEGER, sha3_hash BLOB)", NULL, NULL, NULL);
        sqlite3_exec(db,
            "INSERT INTO blocks(height,hash,time) VALUES"
            /* must equal ZCL_EXPLORER_GENESIS_HASH_INTERNAL_HEX (corrected value) */
            "(0,x'0206260143838b5ff52dc2eb7b4b8099d4e4c99dc3ef19794289a2cd4c100700',1478403829),"
            "(1,x'1111111111111111111111111111111111111111111111111111111111111111',1478403979),"
            "(2,x'2222222222222222222222222222222222222222222222222222222222222222',1478404129),"
            "(3,x'3333333333333333333333333333333333333333333333333333333333333333',1478404279),"
            "(4,x'4444444444444444444444444444444444444444444444444444444444444444',1478404429),"
            "(5,x'5555555555555555555555555555555555555555555555555555555555555555',1478404579),"
            "(6,x'6666666666666666666666666666666666666666666666666666666666666666',1478404729),"
            "(7,x'7777777777777777777777777777777777777777777777777777777777777777',1478404879),"
            "(8,x'8888888888888888888888888888888888888888888888888888888888888888',1478405029),"
            "(9,x'9999999999999999999999999999999999999999999999999999999999999999',1478405179),"
            "(10,x'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',1478405329),"
            "(11,x'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb',1478405479)",
            NULL, NULL, NULL);
        sqlite3_exec(db, "INSERT INTO transactions(block_height) VALUES(1)", NULL, NULL, NULL);
        struct explorer_history_validation v;
        explorer_validate_block_history(db, 11, &v);
        bool ok = (!v.usable &&
                   strstr(v.reason, "tx_outputs") != NULL);
        sqlite3_close(db);
        if (ok) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    printf("explorer: history validation tolerates bounded sparse holes... ");
    {
        sqlite3 *db = NULL;
        sqlite3_open(":memory:", &db);
        sqlite3_exec(db, "CREATE TABLE blocks(height INTEGER, hash BLOB, time INTEGER, status INTEGER)", NULL, NULL, NULL);
        sqlite3_exec(db, "CREATE TABLE transactions(block_height INTEGER)", NULL, NULL, NULL);
        sqlite3_exec(db, "CREATE TABLE tx_outputs(block_height INTEGER)", NULL, NULL, NULL);
        sqlite3_exec(db, "CREATE TABLE view_integrity(height INTEGER, sha3_hash BLOB)", NULL, NULL, NULL);
        sqlite3_exec(db,
            "INSERT INTO blocks(height,hash,time,status) VALUES"
            "(0,x'0206260143838b5ff52dc2eb7b4b8099d4e4c99dc3ef19794289a2cd4c100700',1478403829,3)",
            NULL, NULL, NULL);
        sqlite3_exec(db,
            "WITH RECURSIVE seq(h) AS (SELECT 17 UNION ALL SELECT h+1 FROM seq WHERE h < 48) "
            "INSERT INTO blocks(height,hash,time,status) "
            "SELECT h, zeroblob(32), 1478403829 + h * 150, 3 FROM seq",
            NULL, NULL, NULL);
        sqlite3_exec(db, "INSERT INTO transactions(block_height) VALUES(1)", NULL, NULL, NULL);
        sqlite3_exec(db, "INSERT INTO tx_outputs(block_height) VALUES(1)", NULL, NULL, NULL);
        sqlite3_exec(db,
            "WITH RECURSIVE seq(h) AS (SELECT 0 UNION ALL SELECT h+1 FROM seq WHERE h < 48) "
            "INSERT INTO view_integrity(height,sha3_hash) SELECT h, zeroblob(32) FROM seq",
            NULL, NULL, NULL);
        struct explorer_history_validation v;
        explorer_validate_block_history(db, 48, &v);
        bool ok = (v.usable && v.missing_heights == 16 &&
                   v.first_missing_height == 1 &&
                   strcmp(v.reason, "ok") == 0);
        sqlite3_close(db);
        if (ok) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    printf("explorer: history validation still rejects large sparse holes... ");
    {
        sqlite3 *db = NULL;
        sqlite3_open(":memory:", &db);
        sqlite3_exec(db, "CREATE TABLE blocks(height INTEGER, hash BLOB, time INTEGER, status INTEGER)", NULL, NULL, NULL);
        sqlite3_exec(db, "CREATE TABLE transactions(block_height INTEGER)", NULL, NULL, NULL);
        sqlite3_exec(db, "CREATE TABLE tx_outputs(block_height INTEGER)", NULL, NULL, NULL);
        sqlite3_exec(db, "CREATE TABLE view_integrity(height INTEGER, sha3_hash BLOB)", NULL, NULL, NULL);
        sqlite3_exec(db,
            "INSERT INTO blocks(height,hash,time,status) VALUES"
            "(0,x'0206260143838b5ff52dc2eb7b4b8099d4e4c99dc3ef19794289a2cd4c100700',1478403829,3)",
            NULL, NULL, NULL);
        sqlite3_exec(db,
            "WITH RECURSIVE seq(h) AS (SELECT 18 UNION ALL SELECT h+1 FROM seq WHERE h < 50) "
            "INSERT INTO blocks(height,hash,time,status) "
            "SELECT h, zeroblob(32), 1478403829 + h * 150, 3 FROM seq",
            NULL, NULL, NULL);
        sqlite3_exec(db, "INSERT INTO transactions(block_height) VALUES(1)", NULL, NULL, NULL);
        sqlite3_exec(db, "INSERT INTO tx_outputs(block_height) VALUES(1)", NULL, NULL, NULL);
        sqlite3_exec(db,
            "WITH RECURSIVE seq(h) AS (SELECT 0 UNION ALL SELECT h+1 FROM seq WHERE h < 50) "
            "INSERT INTO view_integrity(height,sha3_hash) SELECT h, zeroblob(32) FROM seq",
            NULL, NULL, NULL);
        struct explorer_history_validation v;
        explorer_validate_block_history(db, 50, &v);
        bool ok = (!v.usable && v.missing_heights == 17 &&
                   /* A gap already beyond policy fails before the expensive
                    * exact-hole anti-join; diagnostics stay bounded. */
                   v.first_missing_height == -1 &&
                   strstr(v.reason, "missing heights") != NULL);
        sqlite3_close(db);
        if (ok) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    return failures;
}
