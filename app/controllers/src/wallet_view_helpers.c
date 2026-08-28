/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Wallet view shared helpers: global state, zclassicd RPC auth/calls, form
 * parsing, and wallet-view initialization. */

#include "platform/time_compat.h"
#include "platform/socket_compat.h"
#include "controllers/wallet_view_internal.h"
#include "controllers/web_form.h"
/* CSS is now in app/views/css/wallet.ccss, compiled as CSS_WALLET */
#include "models/contact.h"
#include "models/shared_validators.h"
#include "models/wallet_tx.h"
#include "crypto/sha256.h"
#include "encoding/utilstrencodings.h"
#include "util/log_macros.h"
#include "util/safe_alloc.h"
#include <sys/time.h>
#include <sys/socket.h>
#include <netinet/in.h>

/* ── Global state (non-static, declared extern in wallet_view_internal.h) ── */

const char *g_wv_datadir = NULL;
int g_balance_dirty = 0;
time_t g_shield_pending_since = 0;
char g_shield_opid[128] = "";
int64_t g_shield_pending_amount = 0;
bool g_sync_enabled = false;

/* ── Init / enable ─────────────────────────────────────────── */

void wallet_view_init(const char *datadir) {
    g_wv_datadir = datadir;
    g_balance_dirty = 0;
    g_shield_pending_since = 0;
    g_shield_opid[0] = '\0';
    g_shield_pending_amount = 0;
    tmpl_init_partials();
}

void wallet_view_enable_sync(void) {
    g_sync_enabled = true;
}

/* ── RPC auth ──────────────────────────────────────────────── */

static bool wv_copy_credential(char out[64], const char *value)
{
    size_t len = strlen(value);
    if (len >= 64) {
        out[0] = '\0';
        return false;
    }
    memcpy(out, value, len + 1);
    return true;
}

const char *wv_zclassicd_auth(void) {
    static char auth[256] = "";
    if (auth[0]) return auth;
    const char *home = getenv("HOME");
    if (!home) home = "/root";
    char path[512];
    /* Try zclassic.conf first (stable credentials survive restarts) */
    snprintf(path, sizeof(path), "%s/.zclassic/zclassic.conf", home);
    FILE *f = fopen(path, "r");
    if (f) {
        char user[64] = "", pass[64] = "", line[256];
        while (fgets(line, sizeof(line), f)) {
            if (strncmp(line, "rpcuser=", 8) == 0) {
                char *e = strchr(line + 8, '\n'); if (e) *e = '\0';
                char *r = strchr(line + 8, '\r'); if (r) *r = '\0';
                (void)wv_copy_credential(user, line + 8);
            }
            if (strncmp(line, "rpcpassword=", 12) == 0) {
                char *e = strchr(line + 12, '\n'); if (e) *e = '\0';
                char *r = strchr(line + 12, '\r'); if (r) *r = '\0';
                (void)wv_copy_credential(pass, line + 12);
            }
        }
        fclose(f);
        if (user[0] && pass[0]) {
            snprintf(auth, sizeof(auth), "%s:%s", user, pass);
            return auth;
        }
    }
    /* Fall back to cookie file (ephemeral, changes on restart) */
    snprintf(path, sizeof(path), "%s/.zclassic/.cookie", home);
    f = fopen(path, "r");
    if (f) {
        size_t n = fread(auth, 1, sizeof(auth) - 1, f);
        fclose(f);
        auth[n] = '\0';
        char *nl = strchr(auth, '\n'); if (nl) *nl = '\0';
        if (auth[0]) return auth;
    }
    /* No cached auth, no conf credentials, no cookie file: report none
     * and let the RPC caller fail closed. Inventing a credential here
     * fired guessable basic-auth at a service that might accept it; this
     * process sends only credentials it was actually given. */
    auth[0] = '\0';
    LOG_RETURN(auth, "wallet_view",
               "no RPC credentials found in conf or cookie");
}

/* ── RPC to running zclassicd node ─────────────────────────── */

int wv_rpc_call(const char *method, const char *params_json,
                char *out, size_t outmax)
{
    if (!out || outmax == 0)
        LOG_ERR("wallet_view", "rpc_call(%s): invalid output buffer", method);
    out[0] = '\0';

    const char *auth_cookie = wv_zclassicd_auth();
    char cookie[256] = "";

    if (auth_cookie && auth_cookie[0]) {
        snprintf(cookie, sizeof(cookie), "%s", auth_cookie);
    } else {
        /* Datadir-scoped credentials: with no datadir there is nothing
         * to read, and with neither file there is no request to send —
         * fail closed by name rather than issuing an unauthenticated
         * call. The LOG_ERR macros below log and RETURN -1; callers of
         * wv_rpc_call already treat <= 0 as "no response". */
        if (!g_wv_datadir || !g_wv_datadir[0])
            LOG_ERR("wallet_view", "rpc_call(%s): no datadir set", method);

        /* Read auth cookie */
        char cookie_path[1024];
        snprintf(cookie_path, sizeof(cookie_path), "%s/.cookie", g_wv_datadir);
        FILE *f = fopen(cookie_path, "r");
        if (!f) {
            /* Try config file credentials */
            char conf_path[1024];
            snprintf(conf_path, sizeof(conf_path), "%s/zclassic.conf",
                     g_wv_datadir);
            f = fopen(conf_path, "r");
            if (!f)
                LOG_ERR("wallet_view",
                        "rpc_call(%s): no cookie or conf under %s",
                        method, g_wv_datadir);
            char user[64] = "", pass[64] = "";
            char line[256];
            while (fgets(line, sizeof(line), f)) {
                if (strncmp(line, "rpcuser=", 8) == 0) {
                    char *nl = strchr(line + 8, '\n'); if (nl) *nl = '\0';
                    (void)wv_copy_credential(user, line + 8);
                }
                if (strncmp(line, "rpcpassword=", 12) == 0) {
                    char *nl = strchr(line + 12, '\n'); if (nl) *nl = '\0';
                    (void)wv_copy_credential(pass, line + 12);
                }
            }
            fclose(f);
            if (!user[0] || !pass[0])
                LOG_ERR("wallet_view",
                        "rpc_call(%s): missing rpcuser/rpcpassword in conf",
                        method);
            snprintf(cookie, sizeof(cookie), "%s:%s", user, pass);
        } else {
            size_t n = fread(cookie, 1, sizeof(cookie) - 1, f);
            fclose(f);
            cookie[n] = '\0';
            char *nl = strchr(cookie, '\n'); if (nl) *nl = '\0';
        }
    }

    platform_socket_t fd = platform_socket_open(AF_INET, SOCK_STREAM, 0,
                                                 true, false);
    if (fd == PLATFORM_SOCKET_INVALID)
        LOG_ERR("wallet_view", "rpc_call(%s): socket() failed", method);

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    addr.sin_port = htons(ZCLASSICD_RPC_DEFAULT_PORT);

    platform_socket_set_receive_timeout(fd, 3000);
    platform_socket_set_send_timeout(fd, 3000);

    if (connect(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        platform_socket_close(fd);
        LOG_ERR("wallet_view", "rpc_call(%s): connect to port %d failed",
                method, ZCLASSICD_RPC_DEFAULT_PORT);
    }

    char body[1024];
    int blen = snprintf(body, sizeof(body),
        "{\"jsonrpc\":\"1.0\",\"id\":1,\"method\":\"%s\",\"params\":%s}",
        method, params_json);
    if (blen < 0 || (size_t)blen >= sizeof(body)) {
        platform_socket_close(fd);
        LOG_ERR("wallet_view", "rpc_call(%s): request body too large (%d bytes)", method, blen);
    }

    static const char b64[] =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    char auth_b64[512];
    size_t alen = strlen(cookie), bo = 0;
    for (size_t i = 0; i < alen; i += 3) {
        uint32_t n2 = ((uint32_t)(uint8_t)cookie[i]) << 16;
        if (i + 1 < alen) n2 |= ((uint32_t)(uint8_t)cookie[i+1]) << 8;
        if (i + 2 < alen) n2 |= (uint32_t)(uint8_t)cookie[i+2];
        auth_b64[bo++] = b64[(n2 >> 18) & 63];
        auth_b64[bo++] = b64[(n2 >> 12) & 63];
        auth_b64[bo++] = (i + 1 < alen) ? b64[(n2 >> 6) & 63] : '=';
        auth_b64[bo++] = (i + 2 < alen) ? b64[n2 & 63] : '=';
    }
    auth_b64[bo] = '\0';

    char req[4096];
    int rlen = snprintf(req, sizeof(req),
        "POST / HTTP/1.1\r\nHost: 127.0.0.1\r\n"
        "Authorization: Basic %s\r\n"
        "Content-Type: application/json\r\n"
        "Content-Length: %d\r\nConnection: close\r\n\r\n%s",
        auth_b64, blen, body);
    if (rlen < 0 || (size_t)rlen >= sizeof(req)) {
        platform_socket_close(fd);
        LOG_ERR("wallet_view", "rpc_call(%s): request too large (%d bytes)", method, rlen);
    }

    if (!platform_socket_send_all(fd, req, (size_t)rlen)) {
        platform_socket_close(fd);
        LOG_ERR("wallet_view", "rpc_call(%s): write failed (expected %d bytes)", method, rlen);
    }

    size_t total = 0;
    while (total < outmax - 1) {
        ptrdiff_t r = platform_socket_receive(fd, out + total,
                                              outmax - 1 - total);
        if (r <= 0) break;
        total += (size_t)r;
    }
    out[total] = '\0';
    platform_socket_close(fd);

    char *body_start = strstr(out, "\r\n\r\n");
    if (body_start) {
        body_start += 4;
        size_t body_len = total - (size_t)(body_start - out);
        memmove(out, body_start, body_len);
        out[body_len] = '\0';
        return (int)body_len;
    }
    return (int)total;
}

/* ── Get best-funded transparent address ───────────────────── */

/* Get ALL funded t-addresses with per-address balances.
 * Aggregates UTXOs by address. Returns count of addresses found.
 * Each entry: addrs[i].addr, addrs[i].amount (ZCL as double). */
int wv_get_all_funded_taddrs(struct wv_funded_addr *addrs, int max_addrs) {
    char lu[16384] = "";
    if (wv_rpc_call("listunspent", "[]", lu, sizeof(lu)) <= 0)
        return 0;
    int n = 0;
    /* Parse listunspent JSON: aggregate amounts per address */
    const char *p = lu;
    while ((p = strstr(p, "\"address\"")) != NULL) {
        p += 9;
        while (*p == ' ' || *p == ':' || *p == '"') p++;
        const char *a = p;
        while (*p && *p != '"') p++;
        size_t al = (size_t)(p - a);
        if (al < 20 || al >= 128) continue;
        const char *am = strstr(p, "\"amount\"");
        if (!am) continue;
        am += 8;
        while (*am == ' ' || *am == ':') am++;
        double v = strtod(am, NULL);
        if (v <= 0) continue;
        /* Find existing entry or add new */
        int found = -1;
        for (int i = 0; i < n; i++) {
            if (strlen(addrs[i].addr) == al &&
                memcmp(addrs[i].addr, a, al) == 0) {
                found = i; break;
            }
        }
        if (found >= 0) {
            addrs[found].amount += v;
        } else if (n < max_addrs) {
            memcpy(addrs[n].addr, a, al);
            addrs[n].addr[al] = '\0';
            addrs[n].amount = v;
            n++;
        }
    }
    return n;
}

void wv_get_funded_taddr(char *out, size_t max) {
    out[0] = '\0';
    struct wv_funded_addr addrs[16];
    int n = wv_get_all_funded_taddrs(addrs, 16);
    /* Return address with highest balance */
    double best = 0;
    for (int i = 0; i < n; i++) {
        if (addrs[i].amount > best) {
            best = addrs[i].amount;
            snprintf(out, max, "%s", addrs[i].addr);
        }
    }
}

/* ── DB helpers ────────────────────────────────────────────── */

sqlite3 *wv_open_db(void) {
    /* No datadir is a normal, handled state (fresh install, hermetic
     * tests): callers degrade gracefully on NULL. Return quietly rather
     * than logging — a per-request WARN here is noise, not a fault. */
    if (!g_wv_datadir)
        return NULL;
    char path[1024];
    snprintf(path, sizeof(path), "%s/node.db", g_wv_datadir);
    sqlite3 *db = NULL;
    if (sqlite3_open_v2(path, &db, SQLITE_OPEN_READONLY, NULL) != SQLITE_OK) {
        if (db) sqlite3_close(db);
        LOG_NULL("wallet_view", "open_db: cannot open %s", path);
    }
    sqlite3_busy_timeout(db, 3000);
    return db;
}

sqlite3 *wv_open_db_rw(void) {
    /* See wv_open_db(): no datadir is a handled state, not a fault. */
    if (!g_wv_datadir)
        return NULL;
    char path[1024];
    snprintf(path, sizeof(path), "%s/node.db", g_wv_datadir);
    sqlite3 *db = NULL;
    if (sqlite3_open_v2(path, &db, SQLITE_OPEN_READWRITE, NULL) != SQLITE_OK) {
        if (db) sqlite3_close(db);
        LOG_NULL("wallet_view", "open_db_rw: cannot open %s", path);
    }
    sqlite3_busy_timeout(db, 5000);
    return db;
}

/* ── Contacts (address book) ───────────────────────────────── */

void wv_save_contact(const char *address, const char *name) {
    sqlite3 *db = wv_open_db_rw();
    struct node_db ndb;
    struct db_contact contact;
    if (!db) return;
    memset(&ndb, 0, sizeof(ndb));
    ndb.db = db;
    ndb.open = true;
    memset(&contact, 0, sizeof(contact));
    snprintf(contact.address, sizeof(contact.address), "%s", address ? address : "");
    snprintf(contact.name, sizeof(contact.name), "%s", name ? name : "");
    (void)db_contact_save(&ndb, &contact);
    sqlite3_close(db);
}

int wv_recent_contacts(struct db_contact *out, size_t max)
{
    sqlite3 *db = wv_open_db();
    struct node_db ndb;
    int count = 0;

    if (!db || !out || max == 0)
        return 0;
    memset(&ndb, 0, sizeof(ndb));
    ndb.db = db;
    ndb.open = true;
    count = db_contact_recent(&ndb, out, max);
    sqlite3_close(db);
    return count;
}


/* ── Query helpers ─────────────────────────────────────────── */

/* sql_query_int() and sql_query_i64() provided by controllers/explorer_internal.h */
#define query_int sql_query_int
#define query_int64 sql_query_i64

int wv_query_int(sqlite3 *db, const char *sql) {
    return query_int(db, sql);
}

int64_t wv_query_int64(sqlite3 *db, const char *sql) {
    return query_int64(db, sql);
}

int wv_effective_tip(sqlite3 *db) {
    struct node_db ndb;

    if (!db)
        return 0;
    memset(&ndb, 0, sizeof(ndb));
    ndb.db = db;
    ndb.open = true;
    return db_wallet_effective_tip_height(&ndb);
}

/* ── Funded z-address lookup ───────────────────────────────── */

void wv_get_funded_zaddr(char *out, size_t max, double *out_balance) {
    out[0] = '\0';
    if (out_balance) *out_balance = 0;

    char buf[65536] = "";
    int rc = wv_rpc_call("z_listunspent", "[0]", buf, sizeof(buf));
    if (rc <= 0) return;

    /* Aggregate balances per z-address */
    struct { char addr[256]; double total; } addrs[16];
    int n_addrs = 0;

    const char *p = buf;
    while ((p = strstr(p, "\"address\"")) != NULL) {
        p += 9;
        const char *q = strchr(p, '"');
        if (!q) break;
        q++;
        const char *end = strchr(q, '"');
        if (!end || (size_t)(end - q) >= 256) { p = end ? end : q; continue; }

        char addr[256];
        size_t alen = (size_t)(end - q);
        memcpy(addr, q, alen);
        addr[alen] = '\0';

        /* Find amount for this entry */
        const char *amt_p = strstr(end, "\"amount\"");
        if (!amt_p) break;
        amt_p += 8;
        while (*amt_p && (*amt_p == ' ' || *amt_p == ':' || *amt_p == '\t'))
            amt_p++;
        double amt = strtod(amt_p, NULL);

        /* Aggregate into addrs[] */
        bool found = false;
        for (int i = 0; i < n_addrs; i++) {
            if (strcmp(addrs[i].addr, addr) == 0) {
                addrs[i].total += amt;
                found = true;
                break;
            }
        }
        if (!found && n_addrs < 16) {
            snprintf(addrs[n_addrs].addr, 256, "%s", addr);
            addrs[n_addrs].total = amt;
            n_addrs++;
        }
        p = amt_p;
    }

    /* Find the address with the highest balance */
    double best = 0;
    int best_idx = -1;
    for (int i = 0; i < n_addrs; i++) {
        if (addrs[i].total > best) {
            best = addrs[i].total;
            best_idx = i;
        }
    }
    if (best_idx >= 0) {
        snprintf(out, max, "%s", addrs[best_idx].addr);
        if (out_balance) *out_balance = best;
    }
}

/* ── Txid formatting ───────────────────────────────────────── */

void wv_txid_short(const char *hex, char *out, size_t out_max) {
    if (!hex || !out || out_max < 18) { if (out && out_max > 0) out[0] = '\0'; return; }
    size_t len = strlen(hex);
    if (len < 8) { snprintf(out, out_max, "%s", hex); return; }
    snprintf(out, out_max, "%.8s...%.4s", hex, len >= 4 ? hex + len - 4 : hex);
}

void wv_txid_lower(const char *hex, char *out, size_t out_max) {
    if (!hex || !out || out_max == 0) return;
    size_t len = strlen(hex);
    if (len >= out_max) len = out_max - 1;
    for (size_t i = 0; i < len; i++)
        out[i] = (hex[i] >= 'A' && hex[i] <= 'F') ? (char)(hex[i] + 32) : hex[i];
    out[len] = '\0';
}

/* ── Time formatting ───────────────────────────────────────── */

void wv_format_time(int64_t timestamp, char *out, size_t out_max) {
    zcl_format_time(out, out_max, timestamp);
}

void wv_format_relative_time(int64_t timestamp, char *out, size_t out_max) {
    if (!out || out_max == 0) return;
    out[0] = '\0';
    if (timestamp <= 0) { snprintf(out, out_max, "Just now"); return; }
    time_t now = platform_time_wall_time_t();
    int64_t diff = (int64_t)now - timestamp;
    if (diff < 0) { snprintf(out, out_max, "just now"); return; }
    if (diff < 60)    { snprintf(out, out_max, "%d second%s ago", (int)diff, diff == 1 ? "" : "s"); return; }
    if (diff < 3600)  { int m = (int)(diff / 60);  snprintf(out, out_max, "%d minute%s ago", m, m == 1 ? "" : "s"); return; }
    if (diff < 86400) { int h = (int)(diff / 3600); snprintf(out, out_max, "%d hour%s ago", h, h == 1 ? "" : "s"); return; }
    if (diff < 2592000)  { int d = (int)(diff / 86400);   snprintf(out, out_max, "%d day%s ago", d, d == 1 ? "" : "s"); return; }
    if (diff < 31536000) { int mo = (int)(diff / 2592000); snprintf(out, out_max, "%d month%s ago", mo, mo == 1 ? "" : "s"); return; }
    int y = (int)(diff / 31536000);
    snprintf(out, out_max, "%d year%s ago", y, y == 1 ? "" : "s");
}

/* ── Balance queries ───────────────────────────────────────── */

int64_t wv_query_ground_truth_balance(sqlite3 *db, int *utxo_count) {
    struct node_db ndb;

    if (!db)
        return 0;
    memset(&ndb, 0, sizeof(ndb));
    ndb.db = db;
    ndb.open = true;
    return db_wallet_utxo_balance_with_count(&ndb, utxo_count);
}

int64_t wv_query_shielded_balance(sqlite3 *db, int *note_count) {
    struct node_db ndb;

    if (!db)
        return 0;
    memset(&ndb, 0, sizeof(ndb));
    ndb.db = db;
    ndb.open = true;
    return db_sapling_note_balance_with_count(&ndb, note_count);
}

int64_t wv_query_speed_balance(sqlite3 *db) {
    struct node_db ndb;
    struct db_wallet_projection_summary summary;

    if (!db)
        return 0;
    memset(&ndb, 0, sizeof(ndb));
    memset(&summary, 0, sizeof(summary));
    ndb.db = db;
    ndb.open = true;
    if (!db_wallet_projection_summary(&ndb, &summary))
        return 0;
    return summary.speed_balance;
}

/* ── Shield status check ───────────────────────────────────── */

int wv_shield_check_status(void) {
    if (!g_shield_opid[0] || g_shield_pending_since == 0)
        return 0;
    if (platform_time_wall_time_t() - g_shield_pending_since > 600) {
        g_shield_opid[0] = '\0';
        g_shield_pending_since = 0;
        g_shield_pending_amount = 0;
        return 0;
    }
    char params[256];
    snprintf(params, sizeof(params), "[[\"%.120s\"]]", g_shield_opid);
    char buf[2048] = "";
    int rc = wv_rpc_call("z_getoperationstatus", params, buf, sizeof(buf));
    if (rc <= 0) return 1;
    if (strstr(buf, "\"success\"")) {
        g_shield_opid[0] = '\0';
        g_shield_pending_since = 0;
        g_shield_pending_amount = 0;
        g_balance_dirty = 1;
        return 2;
    }
    if (strstr(buf, "\"failed\"")) {
        g_shield_opid[0] = '\0';
        g_shield_pending_since = 0;
        g_shield_pending_amount = 0;
        return -1; // raw-return-ok:state-machine-shield-failed
    }
    return 1;
}


/* ── Form parsing ──────────────────────────────────────────── */

/* Bodies are length-delimited slices without a NUL sentinel, so the
 * bounded scanner in web_form.h owns field lookup and decoding here.
 * A miss logs, returns false, and leaves the caller's buffer empty;
 * empty values count as absent. Callers that ignore the return are
 * still covered — web_form_field clears out on every refusal — but the
 * boolean is now the contract it always claimed to be. */
bool wv_parse_form_field(const uint8_t *body, size_t body_len,
                          const char *key, char *out, size_t outmax) {
    if (!web_form_field((const char *)body, body_len, key, out, outmax)) {
        LOG_FAIL("wallet_view",
                 "parse_form_field: key '%s' not found or empty (%zu bytes)",
                 key ? key : "(null)", body_len);
        return false;
    }
    return true;
}

/* ── Address validation ────────────────────────────────────── */

bool wv_validate_zcl_address(const char *addr) {
    return zcl_validate_zcl_address(addr);
}
