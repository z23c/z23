/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: connection state machine, model update from worker results, the
 * beta13 sync verdict (SyncState::classify) and the structure key that says
 * when the widget tree must be rebuilt. Display strings are published by the
 * shell and screen files. Amounts stay int64 zatoshi. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "zw.h"

#define RPC_WARMING (-28)
#define FRESH_TIP_S 7200
#define CLOCK_SKEW_S 7200

void zw_model_init(struct zw_model *m, enum zw_profile requested)
{
    memset(m, 0, sizeof(*m));
    m->conn = ZW_CONN_STARTING;
    m->requested = requested;
    m->profile = requested;
    m->menu_row = -1;
}

void zw_model_free(struct zw_model *m)
{
    free(m->bal);
    m->bal = NULL;
}

/* R9 watchdog: no result for 6 s. A node that was (or was about to be) online
 * is shown as unreachable on its port, and the generation moves on so a late
 * reply of the stuck request is dropped instead of applied. */
void zw_model_watchdog(struct zw_model *m, uint16_t port)
{
    if (m->conn == ZW_CONN_STARTING || m->conn == ZW_CONN_ONLINE) {
        m->conn = ZW_CONN_REFUSED;
        m->port = port;
        m->fail_count++;
    }
    m->generation++;
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

/* An RPC error that only concerns one query; the node still answers. */
static bool soft_rpc_error(struct zw_model *m, const struct zw_result *r)
{
    if (r->kind == ZW_Q_INFO || r->kind == ZW_Q_BALANCES) return true; /* keep the last values */
    if (r->kind != ZW_Q_WALLET) return false;
    m->have_wallet = true;
    m->wallet = (struct zw_wallet){0};
    snprintf(m->wallet.reason, sizeof(m->wallet.reason), "%.111s", r->rpc.message);
    return true;
}

static void apply_error(struct zw_model *m, const struct zw_result *r)
{
    snprintf(m->conn_msg, sizeof(m->conn_msg), "%s", r->rpc.message);
    m->port = r->port ? r->port : m->port;
    snprintf(m->conf_path, sizeof(m->conf_path), "%s", r->conf_path);
    m->cred_src = r->cred_src;
    if (r->datadir[0]) snprintf(m->datadir, sizeof(m->datadir), "%s", r->datadir);
    switch (r->err) {
    case ZW_ERR_SEARCHING:
        m->conn = ZW_CONN_NOT_FOUND;
        m->report = r->report;
        break;
    case ZW_ERR_AUTH: m->conn = ZW_CONN_AUTH; break;
    case ZW_ERR_BAD_REPLY:
        if (r->kind == ZW_Q_INFO || r->kind == ZW_Q_BALANCES) return;
        m->conn = ZW_CONN_BAD_REPLY;
        break;
    case ZW_ERR_RPC:
        if (r->rpc.code == RPC_WARMING) {
            m->conn = ZW_CONN_WARMING;
            m->warm_percent = percent_in(r->rpc.message);
            m->fail_count = 0;
            return;
        }
        if (soft_rpc_error(m, r)) return;
        m->conn = ZW_CONN_BAD_REPLY;
        break;
    default: m->conn = ZW_CONN_REFUSED; break;
    }
    m->fail_count++;
}

static void apply_ok(struct zw_model *m, struct zw_result *r)
{
    m->conn = ZW_CONN_ONLINE;
    m->fail_count = 0;
    m->port = r->port;
    m->testnet = r->testnet;
    m->cred_src = r->cred_src;
    snprintf(m->datadir, sizeof(m->datadir), "%s", r->datadir);
    snprintf(m->conf_path, sizeof(m->conf_path), "%s", r->conf_path);
    if (r->profile != ZW_PROFILE_AUTO) m->profile = r->profile;
    switch (r->kind) {
    case ZW_Q_CHAIN:
        m->chain = r->chain;
        m->have_chain = true;
        if (r->chain.blocks + 2 >= r->chain.headers && !r->chain.ibd && r->chain.headers > 0) m->ever_synced = true;
        break;
    case ZW_Q_NET:
        m->net = r->net;
        m->have_net = true;
        m->peerless_polls = r->net.connections == 0 ? m->peerless_polls + 1 : 0;
        break;
    case ZW_Q_INFO: m->info = r->info; m->have_info = true; break;
    case ZW_Q_BALANCES:
        free(m->bal);
        m->bal = r->bal;
        r->bal = NULL;
        break;
    default: m->wallet = r->wallet; m->have_wallet = true; break;
    }
}

bool zw_model_apply(struct zw_model *m, struct zw_result *r)
{
    if (r->generation != m->generation) { /* stale after a reconnect */
        zw_result_release(r);
        return false;
    }
    struct zw_model before = *m;
    bool bal_changed = r->kind == ZW_Q_BALANCES && r->err == ZW_OK && r->bal;
    if (r->err != ZW_OK) apply_error(m, r);
    else apply_ok(m, r);
    zw_result_release(r);
    before.bal = m->bal; /* the table pointer alone is compared by bal_changed */
    return bal_changed || memcmp(&before, m, sizeof(*m)) != 0;
}

/* ---- sync verdict ---- */

static int64_t peers_of(const struct zw_model *m)
{
    if (m->have_net) return m->net.connections;
    return m->have_info ? m->info.connections : -1;
}

enum zw_sync zw_sync_classify(const struct zw_model *m, int64_t now_s)
{
    if (m->conn != ZW_CONN_ONLINE || !m->have_chain) return ZW_SYNC_CONNECTING;
    const struct zw_chain *c = &m->chain;
    if (!strcmp(c->chain, "regtest")) return ZW_SYNC_LOCAL;
    int64_t age = c->tiptime > 0 ? now_s - c->tiptime : -1;
    int64_t peers = peers_of(m);
    if (c->tiptime > 0 && age < -CLOCK_SKEW_S) return ZW_SYNC_SKEW;
    if (peers == 0 && m->peerless_polls >= 3) return ZW_SYNC_PEERLESS;
    if (c->headers <= 0) return ZW_SYNC_FINDING;
    if (c->blocks + 2 < c->headers) return ZW_SYNC_SYNCING;
    if (c->ibd || age > FRESH_TIP_S) return m->ever_synced && peers > 0 ? ZW_SYNC_STALE : ZW_SYNC_SYNCING;
    return ZW_SYNC_SYNCED;
}

bool zw_model_synced(const struct zw_model *m, int64_t now_s)
{
    enum zw_sync s = zw_sync_classify(m, now_s);
    return s == ZW_SYNC_SYNCED || s == ZW_SYNC_LOCAL;
}

const char *zw_node_kind(const struct zw_model *m)
{
    enum zw_profile p = m->profile != ZW_PROFILE_AUTO ? m->profile : m->requested;
    return p == ZW_PROFILE_ZCLASSICD ? "zclassicd" : "Z23";
}

/* zclassicd CLIENT_VERSION: major*1e6 + minor*1e4 + revision*100 + build. */
void zw_version_decode(int64_t v, char *buf, size_t cap)
{
    if (v <= 0) { snprintf(buf, cap, "unknown"); return; }
    long long major = v / 1000000, minor = (v / 10000) % 100, rev = (v / 100) % 100, b = v % 100;
    if (b < 25) snprintf(buf, cap, "v%lld.%lld.%lld-beta%lld", major, minor, rev, b + 1);
    else if (b < 50) snprintf(buf, cap, "v%lld.%lld.%lld-rc%lld", major, minor, rev, b - 24);
    else if (b == 50) snprintf(buf, cap, "v%lld.%lld.%lld", major, minor, rev);
    else snprintf(buf, cap, "v%lld.%lld.%lld-%lld", major, minor, rev, b - 50);
}

void zw_node_line(const struct zw_model *m, char *buf, size_t cap)
{
    if (m->conn != ZW_CONN_ONLINE) { snprintf(buf, cap, "Node: not connected yet"); return; }
    if (!strcmp(zw_node_kind(m), "zclassicd")) {
        char ver[40];
        zw_version_decode(m->have_info && m->info.version ? m->info.version : m->net.version, ver, sizeof(ver));
        snprintf(buf, cap, "Node: zclassicd %s at 127.0.0.1:%u (read only)", ver, (unsigned)m->port);
    } else {
        snprintf(buf, cap, "Node: Z23 at 127.0.0.1:%u", (unsigned)m->port);
    }
}

/* ---- structure key: everything the tree shape depends on ---- */

static uint32_t bit(bool v, unsigned n) { return v ? 1u << n : 0u; }

static uint32_t home_bits(const struct zw_model *m)
{
    const struct zw_wallet *w = &m->wallet;
    bool known = m->have_wallet && w->known;
    bool synced = m->conn == ZW_CONN_ONLINE && zw_model_synced(m, m->now_s);
    return bit(known, 10) | bit(known && w->total == 0, 11) | bit(known && w->publicf > 10, 12) |
           bit(m->bal && m->bal->any_unconfirmed, 13) | bit(synced, 14) |
           bit(m->have_wallet && m->have_chain, 15);
}

uint32_t zw_structure_key(const struct zw_model *m, size_t screen)
{
    uint32_t k = (uint32_t)m->conn | (uint32_t)screen << 3 | (uint32_t)m->menu << 6 | home_bits(m);
    k |= bit(m->conn != ZW_CONN_ONLINE && (m->have_wallet || m->have_chain), 16);
    k |= bit(m->conn == ZW_CONN_WARMING && m->warm_percent >= 0, 17);
    k |= bit(m->profile == ZW_PROFILE_ZCLASSICD, 18);
    k |= bit(m->narrow, 19) | bit(m->about_open, 20) | bit(m->msg[0] != 0, 21);
    k |= bit(peers_of(m) == 0, 22) | bit(m->have_info && m->info.has_solps, 23);
    k |= (uint32_t)(zw_sync_classify(m, m->now_s) & 7u) << 24;
    return k;
}

void zw_diagnostics(const struct zw_model *m, char *buf, size_t cap)
{
    snprintf(buf, cap,
             "z23-wallet diagnostics\nnode: %s\nblocks: %lld\nheaders: %lld\nchain: %s\n"
             "peers: %lld\nversion: %s\nport: %u\ndatadir: %s\n",
             zw_node_kind(m), (long long)m->chain.blocks, (long long)m->chain.headers,
             m->chain.chain, (long long)m->net.connections, m->net.subversion, (unsigned)m->port,
             m->datadir);
}
