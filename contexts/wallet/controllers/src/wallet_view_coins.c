/* Copyright 2026 Rhett Creighton - Apache License 2.0 */

#include "controllers/wallet_view_internal.h"
#include "controllers/wallet_controller.h"
#include "views/wallet_view_coins_view.h"
#include "util/log_macros.h"

/* ── Coins (/wallet/coins) — Full UTXO audit view ──────────── */

size_t serve_coins(uint8_t *r, size_t max) {
    sqlite3 *db = wv_open_db();
    if (!db) {
        size_t off = wv_emit_header(r, max, "Coins — Z23", "/wallet/coins");
        off += template_render(TMPL_LOADING, NULL, 0,
            (char *)r + off, max - off);
        wv_emit_footer(r, max, &off);
        return off;
    }

    int tip = wv_effective_tip(db);
    size_t off = wv_emit_header(r, max, "Coins — Z23", "/wallet/coins");

    /* Pre-render UTXO rows into buffer (fetch via port, render via view) */
    char utxo_rows[16384];
    int64_t t_total = 0;
    int t_count = 0;
    {
        struct wallet_view_coin coins[256];
        int n_coins = wv_list_unspent_coins(db, coins,
            sizeof(coins) / sizeof(coins[0]));
        wv_render_coin_rows(utxo_rows, sizeof(utxo_rows), coins, n_coins,
            tip, &t_total, &t_count);
    }

    /* Shielded notes */
    int z_notes = 0;
    int64_t z_total = wv_query_shielded_balance(db, &z_notes);

    /* Pre-render notes section */
    char notes_section[8192];
    size_t ns = 0;
    if (z_notes > 0) {
        char note_rows[6144];
        {
            struct wallet_view_note_group groups[64];
            int n_groups = wv_list_note_groups(db, groups,
                sizeof(groups) / sizeof(groups[0]));
            wv_render_note_rows(note_rows, sizeof(note_rows), groups, n_groups);
        }

        char z_total_s[32], z_notes_s[16];
        snprintf(z_total_s, sizeof(z_total_s), "%.8f", (double)z_total / 1e8);
        snprintf(z_notes_s, sizeof(z_notes_s), "%d", z_notes);
        struct template_var nv[] = {
            { "note_rows", note_rows },
            { "z_total",   z_total_s },
            { "z_notes",   z_notes_s },
            { "z_plural",  z_notes == 1 ? "" : "s" },
        };
        ns = template_render(TMPL_COINS_NOTES_TABLE, nv, 4,
            notes_section, sizeof(notes_section));
    } else {
        int sapling_keys = wv_query_int(db,
            "SELECT count(*) FROM wallet_sapling_keys");
        char sk_s[16];
        snprintf(sk_s, sizeof(sk_s), "%d", sapling_keys);
        struct template_var nv[] = { { "sapling_keys", sk_s } };
        ns = template_render(TMPL_COINS_NO_NOTES, nv, 1,
            notes_section, sizeof(notes_section));
    }
    notes_section[ns] = '\0';

    /* Pre-render token section */
    char token_section[8192];
    size_t tks = 0;
    {
        int token_count = 0;
        char token_rows[6144];
        {
            struct wallet_view_token_balance tokens[50];
            token_count = wv_list_token_balances(db, tokens,
                sizeof(tokens) / sizeof(tokens[0]));
            wv_render_token_rows(token_rows, sizeof(token_rows),
                tokens, token_count);
        }

        if (token_count > 0) {
            struct template_var tv[] = { { "token_rows", token_rows } };
            tks = template_render(TMPL_COINS_TOKENS, tv, 1,
                token_section, sizeof(token_section));
        } else {
            tks = template_render(TMPL_COINS_NO_TOKENS, NULL, 0,
                token_section, sizeof(token_section));
        }
    }
    token_section[tks] = '\0';

    /* Format numeric strings for template */
    char t_total_s[32], z_total_s[32], grand_s[32];
    char t_count_s[16], speed_bal_s[32], speed_utxos_s[16];
    char chain_supply_s[32], chain_utxos_s[16];
    int64_t grand = t_total + z_total;
    snprintf(t_total_s, sizeof(t_total_s), "%.8f", (double)t_total / 1e8);
    snprintf(z_total_s, sizeof(z_total_s), "%.8f", (double)z_total / 1e8);
    snprintf(grand_s, sizeof(grand_s), "%.8f", (double)grand / 1e8);
    snprintf(t_count_s, sizeof(t_count_s), "%d", t_count);

    int64_t speed_bal = wv_query_speed_balance(db);
    int speed_utxo_count = wv_query_int(db,
        "SELECT count(*) FROM wallet_utxos WHERE spent_txid IS NULL");
    snprintf(speed_bal_s, sizeof(speed_bal_s), "%.8f",
        (double)speed_bal / 1e8);
    snprintf(speed_utxos_s, sizeof(speed_utxos_s), "%d", speed_utxo_count);

    int64_t chain_supply = wv_query_int64(db,
        "SELECT COALESCE(SUM(value),0) FROM utxos");
    int chain_utxo_count = wv_query_int(db, "SELECT count(*) FROM utxos");
    snprintf(chain_supply_s, sizeof(chain_supply_s), "%.2f",
        (double)chain_supply / 1e8);
    snprintf(chain_utxos_s, sizeof(chain_utxos_s), "%d", chain_utxo_count);

    struct template_var vars[] = {
        { "parent_href",   "/wallet/node" },
        { "parent_label",  "Node" },
        { "current",       "Coin Audit" },
        { "utxo_rows",     utxo_rows },
        { "t_count",       t_count_s },
        { "t_plural",      t_count == 1 ? "" : "s" },
        { "t_total",       t_total_s },
        { "notes_section", notes_section },
        { "z_total",       z_total_s },
        { "grand_total",   grand_s },
        { "speed_bal",     speed_bal_s },
        { "speed_utxos",   speed_utxos_s },
        { "diag_status",   (speed_bal == t_total)
            ? "<span class='pill pill-t'>match</span>"
            : "<span class='pill pill-send'>stale</span>" },
        { "token_section", token_section },
        { "chain_supply",  chain_supply_s },
        { "chain_utxos",   chain_utxos_s },
    };
    off += template_render(TMPL_COINS_PAGE, vars,
        sizeof(vars) / sizeof(vars[0]), (char *)r + off, max - off);

    wv_emit_footer(r, max, &off);
    sqlite3_close(db);
    return off;
}

/* ── Shield (/wallet/shield?amount=X) ──────────────────────── */
/* One-click fund securing page.
 * The wallet auto-generates a private address and builds the transaction.
 * User just confirms the amount. */
