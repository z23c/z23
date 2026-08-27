/* Copyright 2026 Rhett Creighton - Apache License 2.0 */

#include "platform/time_compat.h"
#include "controllers/wallet_view_internal.h"
#include "controllers/wallet_controller.h"
#include "views/wallet_view_shield_view.h"
#include "util/log_macros.h"

/* Shield: one-click fund securing. User confirms the amount. */

size_t serve_shield(uint8_t *r, size_t max, const char *query) {
    /* Parse amount from query string */
    double amount = 0;
    if (query) {
        const char *amt = strstr(query, "amount=");
        if (amt) amount = strtod(amt + 7, NULL);
        /* ?all=1 — compute from actual zclassicd listunspent, not SQLite.
         * SQLite may be stale if a prior shield is still pending. */
        if (strstr(query, "all=1")) {
            struct wv_funded_addr addrs[16];
            int n = wv_get_all_funded_taddrs(addrs, 16);
            double total = 0;
            for (int i = 0; i < n; i++) total += addrs[i].amount;
            /* Each address needs its own fee */
            int paying_addrs = 0;
            for (int i = 0; i < n; i++)
                if (addrs[i].amount > FEE_ZCL + 0.00000001) paying_addrs++;
            amount = total - (paying_addrs > 0 ? paying_addrs : 1) * FEE_ZCL;
            if (amount < 0) amount = 0;
        }
    }

    if (amount <= 0) {
        /* No amount specified — show amount input form (or nothing-to-shield) */
        size_t off = wv_emit_header(r, max, "Shield — Z23", "/wallet/shield");
        int64_t avail = 0;
        {
            sqlite3 *sdb = wv_open_db();
            if (sdb) {
                avail = wv_query_ground_truth_balance(sdb, NULL);
                sqlite3_close(sdb);
            }
        }
        double max_val = (double)avail / (double)ZATOSHI_PER_ZCL - FEE_ZCL;
        if (max_val < 0) max_val = 0;

        if (avail < (int64_t)(FEE_ZCL * ZATOSHI_PER_ZCL + 1)) {
            /* Nothing to shield — transparent balance is dust */
            wv_render_shield_nothing(r, max, &off);
        } else {
            char avail_str[32], max_str_buf[32];
            zcl_format_zcl(avail_str, sizeof(avail_str), avail);
            snprintf(max_str_buf, sizeof(max_str_buf), "%.8f", max_val);
            struct template_var fv[] = {
                { "parent_href",  "/wallet" },
                { "parent_label", "Home" },
                { "current",      "Shield" },
                { "max_amount",   max_str_buf },
                { "available",    avail_str },
            };
            off += template_render(TMPL_SHIELD_AMOUNT_FORM, fv, 5,
                (char *)r + off, max - off);
        }
        wv_emit_footer(r, max, &off);
        return off;
    }

    double fee = FEE_ZCL;
    double total_cost = amount + fee;

    size_t off = wv_emit_header(r, max, "Shield — Z23", "/wallet/shield");

    /* Render shield confirmation using template */
    char amt_s[32], fee_s[32], tot_s[32];
    snprintf(amt_s, sizeof(amt_s), "%.8f", amount);
    zcl_format_zcl_short(fee_s, sizeof(fee_s), WALLET_VIEW_FEE_ZAT);
    snprintf(tot_s, sizeof(tot_s), "%.8f", total_cost);

    struct template_var shield_vars[] = {
        { "amount", amt_s },
        { "fee",    fee_s },
        { "total",  tot_s },
    };
    off += template_render(TMPL_SHIELD_CONFIRM, shield_vars,
        sizeof(shield_vars) / sizeof(shield_vars[0]),
        (char *)r + off, max - off);

    wv_emit_footer(r, max, &off);
    return off;
}

/* ── Shield Confirm (/wallet/shield/confirm POST) ──────────── */
/* Executes the shielding transaction via the node's z_sendmany. */

size_t serve_shield_confirm(uint8_t *r, size_t max,
                                    const uint8_t *body, size_t body_len) {
    double amount = 0;
    char amount_str[32] = "";
    if (body && body_len > 0)
        wv_parse_form_field(body, body_len, "amount", amount_str, sizeof(amount_str));
    if (amount_str[0])
        amount = strtod(amount_str, NULL);

    size_t off = wv_emit_header(r, max, "Shield — Z23", "/wallet/shield");

    if (amount <= 0) {
        off += template_render(TMPL_SHIELD_INVALID, NULL, 0,
            (char *)r + off, max - off);
        wv_emit_footer(r, max, &off);
        return off;
    }

    /* Look up a z-address from the wallet to use as destination */
    char z_dest[256] = "";
    {
        sqlite3 *sdb = wv_open_db();
        if (sdb) {
            wv_first_sapling_address(sdb, z_dest, sizeof(z_dest));
            sqlite3_close(sdb);
        }
    }

    if (!z_dest[0]) {
        struct template_var ev[] = {{ "message",
            "No private address available. Is the node running?" }};
        off += template_render(TMPL_SHIELD_ERROR, ev, 1,
            (char *)r + off, max - off);
        wv_emit_footer(r, max, &off);
        return off;
    }

    /* Get ALL funded t-addresses. "Secure All" must shield from every
     * address, not just the one with the highest balance. Each address
     * requires a separate z_sendmany call (zclassicd requirement). */
    struct wv_funded_addr funded[16];
    int n_funded = wv_get_all_funded_taddrs(funded, 16);

    if (n_funded == 0) {
        struct template_var ev[] = {{ "message",
            "No public address found in wallet." }};
        off += template_render(TMPL_SHIELD_ERROR, ev, 1,
            (char *)r + off, max - off);
        wv_emit_footer(r, max, &off);
        return off;
    }

    /* Issue z_sendmany for each funded address.
     * Each deducts its own fee. Total shielded = sum(addr_amount - fee). */
    bool success = false;
    int ops_started = 0;
    char opid_str[128] = "";
    char shield_err[256] = "";
    double total_shielded = 0;

    for (int ai = 0; ai < n_funded; ai++) {
        double addr_amt = funded[ai].amount - FEE_ZCL;
        if (addr_amt <= 0.00000001) continue; /* dust, skip */

        /* Cap at requested amount minus what we've already queued */
        double remaining = amount - total_shielded;
        if (remaining <= 0.00000001) break;
        if (addr_amt > remaining) addr_amt = remaining;

        char z_params[2304];
        int params_len = snprintf(z_params, sizeof(z_params),
            "[\"%s\",[{\"address\":\"%s\",\"amount\":%.8f}],1,%.8f]",
            funded[ai].addr, z_dest, addr_amt, FEE_ZCL);
        if (params_len < 0 || (size_t)params_len >= sizeof(z_params)) {
            snprintf(shield_err, sizeof(shield_err),
                     "Shielding address input exceeds the RPC limit");
            continue;
        }

        char rpc_buf[4096] = "";
        int rpc_rc = wv_rpc_call("z_sendmany", z_params,
                                           rpc_buf, sizeof(rpc_buf));

        if (rpc_rc > 0) {
            char result_val[256] = "";
            zcl_json_extract_str(rpc_buf, "result",
                result_val, sizeof(result_val));
            if (strstr(result_val, "opid-") || strstr(rpc_buf, "opid-")) {
                if (!opid_str[0]) {
                    /* Save first opid for tracking */
                    if (result_val[0] && strstr(result_val, "opid-"))
                        snprintf(opid_str, sizeof(opid_str), "%s",
                            result_val);
                    else {
                        const char *op = strstr(rpc_buf, "opid-");
                        size_t oi = 0;
                        while (op[oi] && op[oi] != '"' &&
                               op[oi] != '}' && oi < 127) {
                            opid_str[oi] = op[oi]; oi++;
                        }
                        opid_str[oi] = '\0';
                    }
                }
                total_shielded += addr_amt;
                ops_started++;
                success = true;
            } else {
                /* Try nested error.message first, then top-level message */
                zcl_json_extract_str(rpc_buf, "message",
                    shield_err, sizeof(shield_err));
                if (!shield_err[0]) {
                    /* Show raw RPC response for debugging */
                    snprintf(shield_err, sizeof(shield_err),
                        "z_sendmany failed for %.100s (%.4f ZCL). "
                        "RPC response: %.100s",
                        funded[ai].addr, addr_amt, rpc_buf);
                }
            }
        } else if (!shield_err[0]) {
            snprintf(shield_err, sizeof(shield_err),
                "Could not connect to zclassicd (port %d). "
                "Start it with: zclassicd -daemon", ZCLASSICD_RPC_DEFAULT_PORT);
        }
    }

    /* If we iterated all addresses but none had enough after fees */
    if (!success && !shield_err[0] && ops_started == 0) {
        double total_funded = 0;
        for (int i = 0; i < n_funded; i++)
            total_funded += funded[i].amount;
        if (total_funded < 0.00011)
            snprintf(shield_err, sizeof(shield_err),
                "No spendable transparent balance found in zclassicd. "
                "If you recently shielded, the previous operation may "
                "still be pending (~2.5 min for 1 confirmation). "
                "Check with: zcl-rpc z_getoperationstatus");
        else
            snprintf(shield_err, sizeof(shield_err),
                "All %d funded addresses (total %.8f ZCL) have "
                "insufficient balance after the min-relay fee per address.",
                n_funded, total_funded);
    }

    if (success) {
        /* Track the pending shield operation for dashboard feedback */
        g_shield_pending_since = platform_time_wall_time_t();
        snprintf(g_shield_opid, sizeof(g_shield_opid), "%s", opid_str);
        g_shield_pending_amount = (int64_t)(total_shielded * 1e8 + 0.5);
        /* Sync wallet tables immediately so balance is correct on return */
        wv_sync_wallet_from_zclassicd();
        g_balance_dirty = 1; /* Also recompute on next pulse */
        /* Build balance card */
        char bal_card[512] = "";
        {
            sqlite3 *sdb = wv_open_db();
            if (sdb) {
                int64_t new_t = wv_query_ground_truth_balance(sdb, NULL);
                int64_t new_z = wv_query_shielded_balance(sdb, NULL);
                char ts[32], zs[32], gs[32];
                snprintf(ts, sizeof(ts), "%.8f", (double)new_t / 1e8);
                snprintf(zs, sizeof(zs), "%.8f", (double)new_z / 1e8);
                snprintf(gs, sizeof(gs), "%.8f", (double)(new_t+new_z) / 1e8);
                struct template_var bv[] = {
                    {"total", gs}, {"transparent", ts}, {"shielded", zs}
                };
                template_render(TMPL_SHIELD_BALANCE_CARD, bv, 3,
                    bal_card, sizeof(bal_card));
                sqlite3_close(sdb);
            }
        }

        char amt_s[32], ops_s[16];
        snprintf(amt_s, sizeof(amt_s), "%.8f", total_shielded);
        snprintf(ops_s, sizeof(ops_s), "%d", ops_started);
        struct template_var sv[] = {
            { "amount",       amt_s },
            { "opid",         opid_str },
            { "balance_card", bal_card },
            { "ops_count",    ops_s },
        };
        off += template_render(TMPL_SHIELD_SUCCESS, sv, 4,
            (char *)r + off, max - off);
    } else {
        struct template_var ev[] = {{ "message",
            shield_err[0] ? shield_err : "Unknown error" }};
        off += template_render(TMPL_SHIELD_ERROR, ev, 1,
            (char *)r + off, max - off);
    }

    off += template_render(TMPL_BACK_TO_WALLET, NULL, 0,
        (char *)r + off, max - off);

    wv_emit_footer(r, max, &off);
    return off;
}

/* ── Pulse endpoint (JSON) ──────────────────────────────────── */
/* Balance cache: recompute only when block height changes.
 * The ground-truth query has 3 JOINs — too heavy for 2-second polls. */

struct {
    int height;
    int64_t balance, shielded, speed_bal;
    int t_utxos, z_notes;
} pulse_cache;
