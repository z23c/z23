/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: connection state machine, model update from worker results and
 * publication of display strings into the UI's bound-data table. All UI
 * strings are ASCII. Amounts are formatted from int64 zatoshi only. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "zw.h"

#define RPC_WARMING (-28)

void zw_model_init(struct zw_model *m)
{
    memset(m, 0, sizeof(*m));
    m->conn = ZW_CONN_SEARCHING;
}

uint32_t zw_backoff_s(int fail_count)
{
    static const uint32_t k[] = { 1, 2, 4, 8, 15 };
    if (fail_count <= 1) return k[0];
    size_t i = (size_t)fail_count - 1;
    return i >= sizeof(k) / sizeof(k[0]) ? 15u : k[i];
}

static int percent_in(const char *msg)
{
    const char *p = strchr(msg, '%');
    if (!p || p == msg) return -1;
    const char *d = p;
    while (d > msg && d[-1] >= '0' && d[-1] <= '9') d--;
    return d == p ? -1 : (int)strtol(d, NULL, 10);
}

static void apply_error(struct zw_model *m, const struct zw_result *r)
{
    snprintf(m->conn_msg, sizeof(m->conn_msg), "%s", r->rpc.message);
    switch (r->err) {
    case ZW_ERR_SEARCHING:
        m->conn = ZW_CONN_SEARCHING;
        m->ntried = r->report.ntried;
        memcpy(m->tried, r->report.tried, sizeof(m->tried));
        break;
    case ZW_ERR_AUTH: m->conn = ZW_CONN_AUTH; break;
    case ZW_ERR_BAD_REPLY: m->conn = ZW_CONN_BAD_REPLY; break;
    case ZW_ERR_RPC:
        if (r->rpc.code == RPC_WARMING) {
            m->conn = ZW_CONN_WARMING;
            m->warm_percent = percent_in(r->rpc.message);
            m->fail_count = 0;
            return;
        }
        if (r->kind == ZW_Q_WALLET) { /* wallet-only failure: node still answers */
            m->have_wallet = true;
            m->wallet = (struct zw_wallet){0};
            snprintf(m->wallet.reason, sizeof(m->wallet.reason), "%.111s", r->rpc.message);
            return;
        }
        m->conn = ZW_CONN_BAD_REPLY;
        break;
    default: m->conn = ZW_CONN_REFUSED; break;
    }
    m->fail_count++;
}

bool zw_model_apply(struct zw_model *m, const struct zw_result *r)
{
    if (r->generation != m->generation) return false; /* stale after a reconnect */
    struct zw_model before = *m;
    if (r->err != ZW_OK) {
        apply_error(m, r);
    } else {
        m->conn = ZW_CONN_ONLINE;
        m->fail_count = 0;
        m->port = r->port;
        snprintf(m->datadir, sizeof(m->datadir), "%s", r->datadir);
        if (r->profile != ZW_PROFILE_AUTO) m->profile = r->profile;
        if (r->kind == ZW_Q_CHAIN) { m->chain = r->chain; m->have_chain = true; }
        else if (r->kind == ZW_Q_NET) { m->net = r->net; m->have_net = true; }
        else { m->wallet = r->wallet; m->have_wallet = true; }
    }
    return memcmp(&before, m, sizeof(*m)) != 0;
}

static void fmt_int(int64_t v, char *buf, size_t cap)
{
    char d[24];
    int n = snprintf(d, sizeof(d), "%lld", (long long)(v < 0 ? -v : v));
    size_t o = 0;
    char out[40];
    if (v < 0) out[o++] = '-';
    for (int i = 0; i < n; i++) {
        if (i && (n - i) % 3 == 0) out[o++] = ',';
        out[o++] = d[i];
    }
    out[o] = 0;
    snprintf(buf, cap, "%s", out);
}

static bool is_synced(const struct zw_model *m)
{
    return m->have_chain && m->chain.blocks + 1 >= m->chain.headers && m->chain.headers > 0;
}

static void status_text(const struct zw_model *m, char *buf, size_t cap)
{
    char a[40], b[40];
    switch (m->conn) {
    case ZW_CONN_ONLINE:
        if (!m->have_chain) { snprintf(buf, cap, "Connected"); break; }
        fmt_int(m->chain.blocks, a, sizeof(a));
        if (is_synced(m)) {
            fmt_int(m->have_net ? m->net.connections : 0, b, sizeof(b));
            snprintf(buf, cap, "Connected - block %s - %s peers", a, b);
        } else {
            fmt_int(m->chain.headers, b, sizeof(b));
            snprintf(buf, cap, "Syncing - validated block %s of ~%s", a, b);
        }
        break;
    case ZW_CONN_WARMING: snprintf(buf, cap, "Starting node - %s", m->conn_msg); break;
    case ZW_CONN_SEARCHING: snprintf(buf, cap, "Looking for your node"); break;
    case ZW_CONN_REFUSED:
    case ZW_CONN_AUTH:
    case ZW_CONN_BAD_REPLY:
        snprintf(buf, cap, "Can't reach your node - retrying in %u s", zw_backoff_s(m->fail_count));
        break;
    }
}

static void connect_text(const struct zw_model *m, char *buf, size_t cap)
{
    char paths[600] = "";
    for (size_t i = 0; i < m->ntried; i++) {
        size_t l = strlen(paths);
        snprintf(paths + l, sizeof(paths) - l, "%s%s", i ? ", " : "", m->tried[i]);
    }
    switch (m->conn) {
    case ZW_CONN_SEARCHING:
        snprintf(buf, cap, "Couldn't find a Z23 node on this computer. Looked in: %s. "
                 "Start Z23, or run z23-wallet --datadir=<folder>.", paths);
        break;
    case ZW_CONN_REFUSED:
        snprintf(buf, cap, "Your node isn't answering yet. Retrying in %u s.", zw_backoff_s(m->fail_count));
        break;
    case ZW_CONN_WARMING: snprintf(buf, cap, "Your node is starting: %s", m->conn_msg); break;
    case ZW_CONN_AUTH:
        snprintf(buf, cap, "Your node refused this wallet's login. The node's .cookie in %s may "
                 "belong to another node; check --datadir.", m->datadir[0] ? m->datadir : "the data folder");
        break;
    default:
        snprintf(buf, cap, "Your node sent a reply this wallet doesn't understand (%s). Check that "
                 "z23-wallet and z23 are from the same release.", m->conn_msg);
        break;
    }
}

static const char *profile_name(enum zw_profile p)
{
    return p == ZW_PROFILE_ZCLASSICD ? "zclassicd (read only)" : "Z23";
}

static void publish_home(const struct zw_model *m, struct gui_ui *ui, int64_t now_s)
{
    char b[96], t[160];
    const struct zw_wallet *w = &m->wallet;
    bool k = m->have_wallet && w->known;
    zw_amount_format(w->spendable, b, sizeof(b), true);
    gui_ui_set(ui, "home.private", k ? b : "--");
    zw_amount_format(w->publicf, b, sizeof(b), true);
    gui_ui_set(ui, "home.transparent", k ? b : "--");
    zw_amount_format(w->total, b, sizeof(b), true);
    gui_ui_set(ui, "home.total", k ? b : "--");
    zw_amount_format(w->pending, b, sizeof(b), true);
    snprintf(t, sizeof(t), "Some funds are still confirming: %s", b);
    gui_ui_set(ui, "home.pending", t);
    zw_amount_format(w->publicf, b, sizeof(b), true);
    snprintf(t, sizeof(t), "%s is PUBLIC - visible to everyone", b);
    gui_ui_set(ui, "home.public_warn", t);
    char sc[24], hd[24];
    fmt_int(w->scanned, sc, sizeof(sc));
    fmt_int(m->chain.headers, hd, sizeof(hd));
    snprintf(t, sizeof(t), "Wallet catching up: scanned to block %s of %s. Balances may be incomplete.", sc, hd);
    gui_ui_set(ui, "home.sync_note", t);
    gui_ui_set(ui, "home.blocked", w->reason);
    if (m->conn == ZW_CONN_ONLINE) {
        t[0] = 0;
    } else {
        snprintf(t, sizeof(t), "Last updated %lld s ago - reconnecting",
                 (long long)(now_s - m->last_update_s));
    }
    gui_ui_set(ui, "home.updated", t);
}

static void publish_node(const struct zw_model *m, struct gui_ui *ui)
{
    char a[40], t[600];
    fmt_int(m->chain.blocks, a, sizeof(a));
    snprintf(t, sizeof(t), "Validated block %s", a);
    gui_ui_set(ui, "node.blocks", m->have_chain ? t : "Validated block --");
    fmt_int(m->chain.headers, a, sizeof(a));
    snprintf(t, sizeof(t), "Known headers %s", a);
    gui_ui_set(ui, "node.headers", m->have_chain ? t : "Known headers --");
    if (m->have_net && m->net.inbound >= 0 && m->net.outbound >= 0)
        snprintf(t, sizeof(t), "Peers %lld (%lld in, %lld out)", (long long)m->net.connections,
                 (long long)m->net.inbound, (long long)m->net.outbound);
    else
        snprintf(t, sizeof(t), "Peers %lld", (long long)m->net.connections);
    gui_ui_set(ui, "node.peers", m->have_net ? t : "Peers --");
    snprintf(t, sizeof(t), "Node version %s", m->net.subversion[0] ? m->net.subversion : "--");
    gui_ui_set(ui, "node.version", t);
    snprintf(t, sizeof(t), "Network %s", m->chain.chain[0] ? m->chain.chain : "--");
    gui_ui_set(ui, "node.network", t);
    snprintf(t, sizeof(t), "Data folder %s", m->datadir);
    gui_ui_set(ui, "node.datadir", t);
    snprintf(t, sizeof(t), "RPC port %u", (unsigned)m->port);
    gui_ui_set(ui, "node.port", t);
    snprintf(t, sizeof(t), "Profile %s", profile_name(m->profile));
    gui_ui_set(ui, "node.profile", t);
    gui_ui_set(ui, "node.hint", m->have_net && m->net.connections == 0
               ? "Waiting for peers - check your internet connection" : "");
}

void zw_model_publish(const struct zw_model *m, struct gui_ui *ui, int64_t now_s)
{
    char t[700];
    status_text(m, t, sizeof(t));
    gui_ui_set(ui, "status.text", t);
    const char *net = m->chain.chain;
    gui_ui_set(ui, "status.badge", !strcmp(net, "test") ? "TESTNET" : !strcmp(net, "regtest") ? "REGTEST" : "");
    connect_text(m, t, sizeof(t));
    gui_ui_set(ui, "connect.text", t);
    char pm[16] = "";
    if (m->conn == ZW_CONN_WARMING && m->warm_percent >= 0) snprintf(pm, sizeof(pm), "%d", m->warm_percent * 10);
    gui_ui_set(ui, "connect.progress", pm);
    publish_home(m, ui, now_s);
    publish_node(m, ui);
}

static uint32_t bit(bool v, unsigned n) { return v ? 1u << n : 0u; }

/* Which wallet cards exist: pending, public funds, catching up, send blocked, long number. */
static uint32_t wallet_bits(const struct zw_model *m)
{
    const struct zw_wallet *w = &m->wallet;
    bool known = m->have_wallet && w->known;
    return bit(known && w->pending > 0, 8) | bit(known && w->publicf > 0, 9) | bit(known && !w->current, 10) |
           bit(m->have_wallet && !w->send_allowed && w->reason[0], 11) |
           bit(known && w->spendable >= INT64_C(100000000000000), 12);
}

uint32_t zw_structure_key(const struct zw_model *m, size_t screen)
{
    uint32_t k = (uint32_t)m->conn | (uint32_t)screen << 4 | wallet_bits(m);
    k |= bit(m->conn != ZW_CONN_ONLINE && (m->have_wallet || m->have_chain), 13);
    k |= bit(m->conn == ZW_CONN_WARMING && m->warm_percent >= 0, 14);
    k |= bit(m->have_net && m->net.connections == 0, 15);
    k |= bit(m->profile == ZW_PROFILE_ZCLASSICD, 16);
    k |= bit(m->chain.chain[0] && strcmp(m->chain.chain, "main"), 17);
    return k;
}

void zw_diagnostics(const struct zw_model *m, char *buf, size_t cap)
{
    snprintf(buf, cap,
             "z23-wallet diagnostics\nprofile: %s\nblocks: %lld\nheaders: %lld\nchain: %s\n"
             "peers: %lld\nnode: %s\nport: %u\ndatadir: %s\n",
             profile_name(m->profile), (long long)m->chain.blocks, (long long)m->chain.headers,
             m->chain.chain, (long long)m->net.connections, m->net.subversion, (unsigned)m->port,
             m->datadir);
}
