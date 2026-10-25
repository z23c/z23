/* Copyright 2026 Rhett Creighton - Apache License 2.0 */

#include "controllers/wallet_view_internal.h"
#include "controllers/wallet_controller.h"
#include "views/wallet_view_node_view.h"
#include "platform/file_stream.h"
#include "net/version.h"
#include "sync/sync_state.h"
#include "util/log_macros.h"

/* ── Node / Command Center (/wallet/node) ───────────────────── */

static void fetch_node_stats(sqlite3 *db, int *tip, int *peers,
    int *mempool, int *utxo_count, int64_t *supply) {
    if (db) {
        *tip = wv_effective_tip(db);
        *peers = wv_query_int(db, "SELECT count(*) FROM peers");
        *mempool = wv_query_int(db, "SELECT count(*) FROM mempool_entries");
        *utxo_count = wv_query_int(db, "SELECT count(*) FROM utxos");
        *supply = wv_query_int64(db,
            "SELECT COALESCE(SUM(value),0) FROM utxos");
    }
}

static const char *node_sync_label(const char *sync_raw, bool synced) {
    return synced ? "Synced" :
        (strstr(sync_raw, "idle") ? "Ready" : "Syncing...");
}

static const char *node_sync_class(const char *sync_raw, bool synced) {
    return synced ? "pill-synced" :
        (strstr(sync_raw, "idle") ? "pill-ready" : "pill-syncing");
}

static void format_node_height(char *height_s, size_t size, int tip) {
    if (format_with_commas(height_s, size, tip) == 0)
        snprintf(height_s, size, "%d", tip);
}

/* Difficulty from latest block */
static void format_node_difficulty(sqlite3 *db, char *diff_s, size_t size) {
    if (db) {
        int64_t bits = wv_query_int64(db,
            "SELECT bits FROM blocks ORDER BY height DESC LIMIT 1");
        if (bits > 0) {
            double diff = explorer_difficulty_from_bits((uint32_t)bits);
            if (diff >= 1e9)
                snprintf(diff_s, size, "%.2fG", diff / 1e9);
            else if (diff >= 1e6)
                snprintf(diff_s, size, "%.2fM", diff / 1e6);
            else if (diff >= 1e3)
                snprintf(diff_s, size, "%.1fK", diff / 1e3);
            else
                snprintf(diff_s, size, "%.1f", diff);
        }
    }
}

/* Tor .onion address detection */
static void render_node_tor_section(char *tor_section, size_t size) {
    char onion_path[512];
    const char *datadir = g_wv_datadir ? g_wv_datadir : "";
    snprintf(onion_path, sizeof(onion_path), "%s/onion/hostname", datadir);
    FILE *f = platform_file_stream_open_read(onion_path);
    if (f) {
        char onion[128] = "";
        if (fgets(onion, sizeof(onion), f)) {
            char *nl = strchr(onion, '\n');
            if (nl) *nl = '\0';
        }
        fclose(f);
        if (onion[0]) {
            char esc_onion[256];
            html_escape(esc_onion, sizeof(esc_onion), onion);
            struct template_var tv[] = {
                { "tor_color",  "#34d399" },
                { "tor_status", "Active" },
                { "onion_addr", esc_onion },
            };
            template_render(TMPL_NODE_TOR, tv, 3,
                tor_section, size);
        }
    }
    if (!tor_section[0])
        template_render(TMPL_NODE_NO_TOR, NULL, 0,
            tor_section, size);
}

/* Peer table — fetch rows via the port, render via the view. */
static void render_node_peer_table(sqlite3 *db, char *peer_table,
    size_t size) {
    struct wallet_view_peer_row peers[25];
    int n_peers = db ? wv_list_peers(db, peers,
        sizeof(peers) / sizeof(peers[0])) : 0;
    wv_render_peer_table(peer_table, size, peers, n_peers);
}

size_t serve_node(uint8_t *r, size_t max) {
    sqlite3 *db = wv_open_db();

    int tip = 0, peers = 0, mempool = 0, utxo_count = 0;
    int64_t supply = 0;
    fetch_node_stats(db, &tip, &peers, &mempool, &utxo_count, &supply);

    const char *sync_raw = sync_state_name(sync_get_state());
    bool synced = (sync_get_state() == SYNC_AT_TIP);
    const char *sync_label = node_sync_label(sync_raw, synced);
    const char *sync_class = node_sync_class(sync_raw, synced);

    char height_s[20];
    format_node_height(height_s, sizeof(height_s), tip);

    char peers_s[16], mempool_s[16], utxo_s[16], supply_s[32];
    snprintf(peers_s, sizeof(peers_s), "%d", peers);
    snprintf(mempool_s, sizeof(mempool_s), "%d", mempool);
    snprintf(utxo_s, sizeof(utxo_s), "%d", utxo_count);
    snprintf(supply_s, sizeof(supply_s), "%.2f", (double)supply / 1e8);

    char diff_s[32] = "\xe2\x80\x94";
    format_node_difficulty(db, diff_s, sizeof(diff_s));

    char tor_section[2048] = "";
    render_node_tor_section(tor_section, sizeof(tor_section));

    char peer_table[8192];
    render_node_peer_table(db, peer_table, sizeof(peer_table));

    size_t off = wv_emit_header(r, max, "Node — Z23", "/wallet/node");

    struct template_var vars[] = {
        { "height",      height_s },
        { "peers",       peers_s },
        { "mempool",     mempool_s },
        { "difficulty",  diff_s },
        { "sync_class",  sync_class },
        { "sync_label",  sync_label },
        { "tor_section", tor_section },
        { "peer_table",  peer_table },
        { "utxo_count",  utxo_s },
        { "supply",      supply_s },
        { "version",     msg_version_user_agent() },
    };
    off += template_render(TMPL_NODE_PAGE, vars,
        sizeof(vars) / sizeof(vars[0]), (char *)r + off, max - off);

    wv_emit_footer(r, max, &off);
    if (db) sqlite3_close(db);
    return off;
}

/* ── Router ─────────────────────────────────────────────────── */
