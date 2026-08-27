/* Copyright 2026 Rhett Creighton - Apache License 2.0 */

#include "controllers/wallet_view_internal.h"
#include "controllers/wallet_controller.h"
#include "controllers/sovereignty_controller.h"
#include "models/contact.h"
#include "util/log_macros.h"

/* ── Send (/wallet/send) ────────────────────────────────────── */

size_t serve_send(uint8_t *r, size_t max) {
    sqlite3 *db = wv_open_db();

    int64_t balance = 0;
    int64_t shielded_bal = 0;
    /* Contacts for autocomplete (max 20) */
    struct db_contact contacts[20];
    int n_contacts = 0;
    /* ZSLP tokens held (max 10) */
    struct wv_held_token tokens[10];
    int n_tokens = 0;
    if (db) {
        balance = wv_query_ground_truth_balance(db, NULL);
        shielded_bal = wv_query_shielded_balance(db, NULL);
        n_tokens = wv_list_held_tokens(db, tokens,
            sizeof(tokens) / sizeof(tokens[0]));
        /* Load contacts */
        n_contacts = wv_recent_contacts(contacts, 20);
        sqlite3_close(db);
    }

    size_t off = wv_emit_header(r, max, "Send — Z23", "/wallet/send");

    char bal_fmt[32];
    int64_t spendable_total = balance + shielded_bal;
    zcl_format_zcl(bal_fmt, sizeof(bal_fmt), spendable_total);

    /* Shielded note (raw HTML, empty if no shielded balance) */
    char shielded_note[256] = "";
    if (shielded_bal > 0) {
        char z_fmt[32];
        zcl_format_zcl(z_fmt, sizeof(z_fmt), shielded_bal);
        snprintf(shielded_note, sizeof(shielded_note),
            "<div style='color:#a78bfa;font-size:14px;margin-top:8px'>"
            "&#x1F512; %s ZCL private "
            "<span style='color:#666'>&mdash; send to zs1... address to use</span>"
            "</div>",
            z_fmt);
    }

    /* Currency selector (raw HTML, empty if no tokens) */
    char currency_selector[2048] = "";
    if (n_tokens > 0) {
        size_t cs_off = 0;
        cs_off += (size_t)snprintf(currency_selector + cs_off,
            sizeof(currency_selector) - cs_off,
            "<div class='form-group'>"
            "<label class='form-label' for='currency'>Currency</label>"
            "<select class='form-input' id='currency' name='currency' "
            "style='padding:12px 16px'>"
            "<option value='ZCL'>ZCL (ZClassic)</option>");
        for (int i = 0; i < n_tokens; i++) {
            char esc_tk[32], esc_tid[130];
            html_escape(esc_tk, sizeof(esc_tk), tokens[i].ticker);
            html_escape(esc_tid, sizeof(esc_tid), tokens[i].token_id);
            cs_off += (size_t)snprintf(currency_selector + cs_off,
                sizeof(currency_selector) - cs_off,
                "<option value='%s'>%s (ZSLP Token)</option>",
                esc_tid, esc_tk);
        }
        snprintf(currency_selector + cs_off,
            sizeof(currency_selector) - cs_off,
            "</select></div>");
    }

    /* Fee string — short form of the min-relay floor, never rounded to zero. */
    char fee_str[16];
    zcl_format_zcl_short(fee_str, sizeof(fee_str), WALLET_VIEW_FEE_ZAT);

    /* Contacts datalist (raw HTML) */
    char contacts_html[4096];
    {
        size_t cl_off = 0;
        cl_off += (size_t)snprintf(contacts_html + cl_off,
            sizeof(contacts_html) - cl_off, "<datalist id='contacts'>");
        for (int i = 0; i < n_contacts; i++) {
            char esc_name[128], esc_addr[512];
            html_escape(esc_name, sizeof(esc_name), contacts[i].name);
            html_escape(esc_addr, sizeof(esc_addr), contacts[i].address);
            cl_off += (size_t)snprintf(contacts_html + cl_off,
                sizeof(contacts_html) - cl_off,
                "<option value='%s' label='%s'>",
                esc_addr, esc_name);
        }
        snprintf(contacts_html + cl_off,
            sizeof(contacts_html) - cl_off, "</datalist>");
    }

    struct template_var send_vars[] = {
        { "spendable",         bal_fmt },
        { "shielded_note",     shielded_note },
        { "currency_selector", currency_selector },
        { "fee",               fee_str },
        { "contacts_datalist", contacts_html },
    };
    off += template_render(TMPL_SEND, send_vars,
        sizeof(send_vars) / sizeof(send_vars[0]),
        (char *)r + off, max - off);

    APPEND(off, r, max,
        "<script>"
        "var BAL=%.8f;"
        "function updateRemaining(){"
        "var a=parseFloat(document.getElementById('amt').value)||0;"
        "var r=document.getElementById('remaining');"
        "if(a>0&&a<=BAL){r.textContent='Remaining: '+(BAL-a-%.8f).toFixed(8)+' ZCL';"
        "r.style.color='#666';}"
        "else if(a>BAL){r.textContent='Insufficient funds';"
        "r.style.color='#f87171';}"
        "else{r.textContent='';}}"
        "function validateSend(){"
        "var a=document.getElementById('addr').value.trim();"
        "var m=document.getElementById('amt').value.trim();"
        "document.getElementById('addr-err').textContent='';"
        "document.getElementById('amt-err').textContent='';"
        "var minLen=a&&a.startsWith('zs1')?70:26;"
        "if(!a||a.length<minLen){"
        "document.getElementById('addr-err').textContent="
        "'Enter a valid address';return false;}"
        "if(!(/^(t[13]|zs1)/.test(a))){"
        "document.getElementById('addr-err').textContent="
        "'Must start with t1, t3, or zs1';return false;}"
        "if(!(/^[a-zA-Z0-9]+$/.test(a))){"
        "document.getElementById('addr-err').textContent="
        "'Invalid characters in address';return false;}"
        "var amt=parseFloat(m);"
        "if(isNaN(amt)||amt<=0){"
        "document.getElementById('amt-err').textContent="
        "'Enter an amount';return false;}"
        "if(amt+%.8f>BAL){"
        "document.getElementById('amt-err').textContent="
        "'Insufficient funds: need '+(amt+%.8f-BAL).toFixed(8)+' more ZCL';"
        "return false;}"
        "return true;}"
        /* Real-time address validation + privacy hint on input */
        "document.getElementById('addr').addEventListener('input',function(){"
        "var a=this.value.trim(),e=document.getElementById('addr-err');"
        "var ph=document.getElementById('privacy-hint');"
        "e.textContent='';"
        "if(ph){if(a.startsWith('zs1')&&a.length>10)"
        "{ph.innerHTML='&#x1F512; <span style=\"color:#a78bfa\">"
        "Private send</span>';}"
        "else if(a.startsWith('t1')||a.startsWith('t3'))"
        "{ph.innerHTML='&#x1F534; <span style=\"color:#fbbf24\">"
        "Visible on blockchain</span>';}"
        "else{ph.textContent='';}}"
        "if(!a)return;"
        "var ml=a.startsWith('zs1')?70:26;"
        "if(a.length>=ml&&/^(t[13]|zs1)/.test(a)&&/^[a-zA-Z0-9]+$/.test(a))"
        "{this.style.borderColor='#34d399';"
        "setTimeout(function(){document.getElementById('addr')"
        ".style.borderColor='';},1500);}});"
        "document.getElementById('addr').addEventListener('blur',function(){"
        "var a=this.value.trim(),e=document.getElementById('addr-err');"
        "e.textContent='';"
        "if(!a)return;"
        "var ml=a.startsWith('zs1')?70:26;"
        "if(a.length<ml){e.textContent='Address too short';return;}"
        "if(!(/^(t[13]|zs1)/.test(a))){e.textContent="
        "'Must start with t1, t3, or zs1';return;}"
        "if(!(/^[a-zA-Z0-9]+$/.test(a))){e.textContent="
        "'Invalid characters';return;}"
        "this.style.borderColor='#34d399';"
        "setTimeout(function(){document.getElementById('addr')"
        ".style.borderColor='';},1500);});"
        /* Loading overlay on submit */
        "document.getElementById('review-btn').addEventListener('click',"
        "function(e){if(!validateSend()){e.preventDefault();return;}"
        "this.disabled=true;this.textContent='Reviewing...';"
        "});"
        "</script>",
        (double)spendable_total / (double)ZATOSHI_PER_ZCL, FEE_ZCL, FEE_ZCL, FEE_ZCL);

    wv_emit_footer(r, max, &off);
    return off;
}

/* Intermediate confirmation step: show details before executing. */

size_t serve_send_review(uint8_t *r, size_t max,
                                 const uint8_t *body, size_t body_len) {
    size_t off = wv_emit_header(r, max, "Review — Z23", "/wallet/send");

    char address[128] = "", amount_str[32] = "";
    wv_parse_form_field(body, body_len, "address", address, sizeof(address));
    wv_parse_form_field(body, body_len, "amount", amount_str, sizeof(amount_str));

    /* Validate address: checksum verification (Base58Check or Bech32) */
    bool addr_ok = wv_validate_zcl_address(address);
    const char *addr_err = NULL;
    if (!addr_ok) {
        size_t alen = strlen(address);
        if (alen < 26)
            addr_err = "Address too short.";
        else if (!(address[0] == 't' || (alen >= 3 && address[0] == 'z')))
            addr_err = "ZClassic addresses start with t1, t3, or zs1.";
        else
            addr_err = "Invalid address checksum. Check for typos.";
    }

    double amount = strtod(amount_str, NULL);
    const char *err_reason = !addr_ok
        ? (addr_err ? addr_err : "Invalid address.")
        : "Invalid amount";
    if (!addr_ok || amount <= 0) {
        struct template_var ev[] = {
            { "heading",   "Invalid Transaction" },
            { "message",   err_reason },
            { "back_url",  "/wallet" },
            { "back_label", "Back to Wallet" },
            { "retry_url", "/wallet/send" },
        };
        off += template_render(TMPL_VALIDATION_ERROR, ev, 5,
            (char *)r + off, max - off);
        wv_emit_footer(r, max, &off);
        return off;
    }

    bool is_shielded = (strncmp(address, "zs1", 3) == 0);
    double fee = FEE_ZCL;
    double total_deducted = amount + fee;

    /* Query balance — use BOTH transparent and shielded */
    int64_t t_balance = 0, z_balance = 0;
    {
        sqlite3 *db = wv_open_db();
        if (db) {
            t_balance = wv_query_ground_truth_balance(db, NULL);
            z_balance = wv_query_shielded_balance(db, NULL);
            sqlite3_close(db);
        }
    }
    int64_t spendable = t_balance + z_balance;
    double remaining = (double)spendable / (double)ZATOSHI_PER_ZCL - total_deducted;

    char safe_addr[256];
    html_escape(safe_addr, sizeof(safe_addr), address);

    {
        char amt_s[32], fee_s[32], tot_s[32], rem_s[32];
        snprintf(amt_s, sizeof(amt_s), "%.8f", amount);
        snprintf(fee_s, sizeof(fee_s), "%.8f", fee);
        snprintf(tot_s, sizeof(tot_s), "%.8f", total_deducted);
        snprintf(rem_s, sizeof(rem_s), "%.8f", remaining);

        const char *pw = is_shielded
            ? "<div style='color:#fbbf24;font-size:13px;margin-top:4px'>"
              "&#x26A0; Your sending address is visible on-chain "
              "(t&#x2192;z send)</div>"
            : "";

        struct template_var rv[] = {
            { "parent_href",     "/wallet/send" },
            { "parent_label",    "Send" },
            { "current",         "Review" },
            { "address",         safe_addr },
            { "amount",          amt_s },
            { "fee",             fee_s },
            { "total",           tot_s },
            { "remaining",       rem_s },
            { "privacy_pill",    is_shielded ? "pill-private" : "pill-t" },
            { "privacy_label",   is_shielded ? "&#x1F512; Recipient private"
                                              : "&#x1F534; Public" },
            { "privacy_warning", pw },
        };
        off += template_render(TMPL_SEND_REVIEW, rv, 11,
            (char *)r + off, max - off);
    }

    /* Cancel / Confirm buttons */
    {
        char amt_s[32];
        snprintf(amt_s, sizeof(amt_s), "%.8f", amount);
        struct template_var bv[] = {
            { "address",   safe_addr },
            { "amount",    amt_s },
            { "btn_color", is_shielded ? "#a78bfa" : "#34d399" },
            { "btn_text",  is_shielded ? "#fff" : "#0c0c0c" },
        };
        off += template_render(TMPL_SEND_CONFIRM_BUTTONS, bv, 4,
            (char *)r + off, max - off);
    }

    wv_emit_footer(r, max, &off);
    return off;
}

/* ── Send Confirm (/wallet/send/confirm POST) ──────────────── */

size_t serve_send_confirm(uint8_t *r, size_t max,
                                  const uint8_t *body, size_t body_len) {
    size_t off = wv_emit_header(r, max, "Sending — Z23", "/wallet/send");

    char address[128] = "", amount_str[32] = "";
    wv_parse_form_field(body, body_len, "address", address, sizeof(address));
    wv_parse_form_field(body, body_len, "amount", amount_str, sizeof(amount_str));

    /* Validate address: checksum verification */
    bool addr_ok = wv_validate_zcl_address(address);

    double amount = strtod(amount_str, NULL);
    if (!addr_ok || amount <= 0) {
        struct template_var ev[] = {
            { "heading",    "Invalid Transaction" },
            { "message",    !addr_ok ? "Invalid address" : "Invalid amount" },
            { "back_url",   "/wallet/send" },
            { "back_label", "Try Again" },
            { "retry_url",  "/wallet/send" },
        };
        off += template_render(TMPL_VALIDATION_ERROR, ev, 5,
            (char *)r + off, max - off);
        wv_emit_footer(r, max, &off);
        return off;
    }

    /* Sovereign guard, ahead of the transparent/shielded split so every branch
     * of this form refuses identically. The transparent branch inherits the
     * guard inside wallet_direct_sendtoaddress, but the shielded branch reaches
     * z_sendmany over wv_rpc_call directly — so without this, the same form
     * refused a t-address send and completed a zs1 one while the tip is
     * release_assisted. Checked once here rather than duplicated into each
     * branch, so a third branch cannot be added ungated. Placed after input
     * validation (unlike the RPC paths, which have no separate validation
     * stage) so a typo still reads as a typo. */
    {
        char sov_reason[96] = {0};
        if (!sovereignty_guard_allow("wallet_spend", sov_reason,
                                     sizeof(sov_reason))) {
            LOG_WARN("wallet_view", "send/confirm: spend refused — %s",
                     sov_reason);
            struct template_var sv[] = {
                { "heading",    "Spend Refused" },
                { "message",    "Spend refused — tip is release_assisted "
                                "(borrowed shielded history, not self-folded). "
                                "No spend, transparent or shielded, is "
                                "released until the node has folded its own "
                                "history." },
                { "back_url",   "/wallet" },
                { "back_label", "Back to Wallet" },
                { "retry_url",  "/wallet/send" },
            };
            off += template_render(TMPL_VALIDATION_ERROR, sv, 5,
                                   (char *)r + off, max - off);
            wv_emit_footer(r, max, &off);
            return off;
        }
    }

    /* Execute send */
    bool is_shielded = (strncmp(address, "zs1", 3) == 0);
    char txid_result[128] = "";
    char error_msg[256] = "";
    int64_t amount_sat = (int64_t)(amount * 1e8 + 0.5);
    bool send_ok = false;

    if (is_shielded) {
        /* Shielded send: delegate to zclassicd z_sendmany.
         * Try z-address first (z→z, fully private), fall back to
         * t-address (t→z, sender visible on-chain). */
        char from_addr[256] = "";

        /* Prefer sending from z-address (z→z = fully private) */
        double z_bal = 0;
        wv_get_funded_zaddr(from_addr, sizeof(from_addr), &z_bal);

        /* Fall back to t-address if z-address has insufficient funds */
        if (z_bal < amount + FEE_ZCL) {
            from_addr[0] = '\0';
            wv_get_funded_taddr(from_addr, sizeof(from_addr));
        }

        if (from_addr[0]) {
            char zp[1024];
            snprintf(zp, sizeof(zp),
                "[\"%s\",[{\"address\":\"%s\",\"amount\":%.8f}],1,%.8f]",
                from_addr, address, amount, FEE_ZCL);
            char rb[4096] = "";
            if (wv_rpc_call("z_sendmany", zp, rb, sizeof(rb)) > 0) {
                char rv[256] = "";
                zcl_json_extract_str(rb, "result", rv, sizeof(rv));
                if (strstr(rv, "opid-") || strstr(rb, "opid-")) {
                    snprintf(txid_result, sizeof(txid_result), "%s",
                        rv[0] ? rv : "submitted");
                    send_ok = true;
                } else {
                    zcl_json_extract_str(rb, "message", error_msg,
                                          sizeof(error_msg));
                    if (!error_msg[0])
                        snprintf(error_msg, sizeof(error_msg),
                            "z_sendmany error: %.180s", rb);
                }
            } else {
                snprintf(error_msg, sizeof(error_msg),
                    "Could not connect to zclassicd (port %d)",
                    ZCLASSICD_RPC_DEFAULT_PORT);
            }
        } else {
            snprintf(error_msg, sizeof(error_msg),
                "No funded address found (transparent or shielded)");
        }
    } else {
        send_ok = wallet_direct_sendtoaddress(address, amount_sat,
            txid_result, sizeof(txid_result),
            error_msg, sizeof(error_msg));
    }

    if (send_ok) {
        /* Sync wallet tables immediately so balance is correct on return */
        wv_sync_wallet_from_zclassicd();
        g_balance_dirty = 1;
        char safe_addr[256], safe_txid[256];
        html_escape(safe_addr, sizeof(safe_addr), address);
        html_escape(safe_txid, sizeof(safe_txid), txid_result);

        bool is_opid = (strncmp(txid_result, "opid-", 5) == 0);
        char txid_html[600] = "";
        if (is_opid)
            snprintf(txid_html, sizeof(txid_html),
                "<div class='hash' style='word-break:break-all;"
                "color:#a78bfa;font-size:14px'>%s</div>"
                "<div style='color:#888;font-size:14px;margin-top:8px'>"
                "Funds will arrive after ~10 confirmations (~25 min)</div>",
                safe_txid);
        else
            snprintf(txid_html, sizeof(txid_html),
                "<a href='/explorer/tx/%s' class='hash' "
                "style='word-break:break-all'>%s</a>",
                safe_txid, safe_txid);

        wv_save_contact(address, address);

        char amt_s[32];
        snprintf(amt_s, sizeof(amt_s), "%.8f", amount);
        struct template_var sv[] = {
            { "heading",   is_opid ? "&#x1F512; Send to Private Address Started"
                                   : "Transaction Sent" },
            { "amount",    amt_s },
            { "address",   address },
            { "txid_html", txid_html },
        };
        off += template_render(TMPL_SEND_SUCCESS, sv, 4,
            (char *)r + off, max - off);
    } else {
        struct template_var ev[] = {
            { "heading", "Send Failed" },
            { "message", error_msg[0] ? error_msg : "Unknown error" },
        };
        off += template_render(TMPL_SEND_ERROR, ev, 2,
            (char *)r + off, max - off);
    }

    wv_emit_footer(r, max, &off);
    return off;
}

/* ── Transaction Detail (/wallet/tx/:txid) ──────────────────── */
