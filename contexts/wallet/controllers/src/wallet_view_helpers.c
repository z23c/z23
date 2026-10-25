/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Wallet view shared helpers: global state, zclassicd RPC auth/calls, form
 * parsing, and wallet-view initialization. */

#include "platform/time_compat.h"
#include "platform/socket_compat.h"
#include "platform/file_stream.h"
#include "controllers/wallet_view_internal.h"
#include "controllers/web_form.h"
/* CSS is now in contexts/wallet/views/css/wallet.ccss, compiled as CSS_WALLET */
#include "models/contact.h"
#include "models/shared_validators.h"
#include "models/wallet_tx.h"
#include "crypto/sha256.h"
#include "encoding/utilstrencodings.h"
#include "util/log_macros.h"
#include "util/safe_alloc.h"

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

/* Scan rpcuser=/rpcpassword= pairs from an open conf file into user/pass.
 * strip_cr also drops a trailing CR so CRLF conf files yield clean
 * credentials; the datadir path keeps its original LF-only handling. */
static void wv_scan_conf_credentials(FILE *f, char user[64], char pass[64],
                                     bool strip_cr)
{
    char line[256];
    while (fgets(line, sizeof(line), f)) {
        if (strncmp(line, "rpcuser=", 8) == 0) {
            char *e = strchr(line + 8, '\n'); if (e) *e = '\0';
            if (strip_cr) {
                char *r = strchr(line + 8, '\r'); if (r) *r = '\0';
            }
            (void)wv_copy_credential(user, line + 8);
        }
        if (strncmp(line, "rpcpassword=", 12) == 0) {
            char *e = strchr(line + 12, '\n'); if (e) *e = '\0';
            if (strip_cr) {
                char *r = strchr(line + 12, '\r'); if (r) *r = '\0';
            }
            (void)wv_copy_credential(pass, line + 12);
        }
    }
}

const char *wv_zclassicd_auth(void) {
    static char auth[256] = "";
    if (auth[0]) return auth;
    const char *home = getenv("HOME");
    if (!home) home = "/root";
    char path[512];
    /* Try zclassic.conf first (stable credentials survive restarts) */
    snprintf(path, sizeof(path), "%s/.zclassic/zclassic.conf", home);
    FILE *f = platform_file_stream_open_read(path);
    if (f) {
        char user[64] = "", pass[64] = "";
        wv_scan_conf_credentials(f, user, pass, true);
        fclose(f);
        if (user[0] && pass[0]) {
            snprintf(auth, sizeof(auth), "%s:%s", user, pass);
            return auth;
        }
    }
    /* Fall back to cookie file (ephemeral, changes on restart) */
    snprintf(path, sizeof(path), "%s/.zclassic/.cookie", home);
    f = platform_file_stream_open_read(path);
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

/* Outcome of resolving RPC credentials from cached zclassicd auth or the
 * datadir's .cookie / zclassic.conf files. */
enum wv_cred_status {
    WV_CRED_OK = 0,
    WV_CRED_NO_DATADIR,
    WV_CRED_NO_FILES,
    WV_CRED_MISSING_PAIR,
};

static bool wv_snprintf_truncated(int len, size_t bufsize)
{
    return len < 0 || (size_t)len >= bufsize;
}

/* Resolve the credentials for one RPC call into cookie[256]: cached
 * zclassicd auth first, then the datadir cookie/conf fallbacks. The
 * caller logs and fails closed on every non-OK status. */
static int wv_resolve_rpc_credentials(char cookie[256])
{
    const char *auth_cookie = wv_zclassicd_auth();
    if (auth_cookie && auth_cookie[0]) {
        snprintf(cookie, 256, "%s", auth_cookie);
        return WV_CRED_OK;
    }
    if (!g_wv_datadir || !g_wv_datadir[0])
        return WV_CRED_NO_DATADIR;
    /* Read auth cookie */
    char cookie_path[1024];
    snprintf(cookie_path, sizeof(cookie_path), "%s/.cookie", g_wv_datadir);
    FILE *f = platform_file_stream_open_read(cookie_path);
    if (!f) {
        /* Try config file credentials */
        char conf_path[1024];
        snprintf(conf_path, sizeof(conf_path), "%s/zclassic.conf",
                 g_wv_datadir);
        f = platform_file_stream_open_read(conf_path);
        if (!f)
            return WV_CRED_NO_FILES;
        char user[64] = "", pass[64] = "";
        wv_scan_conf_credentials(f, user, pass, false);
        fclose(f);
        if (!user[0] || !pass[0])
            return WV_CRED_MISSING_PAIR;
        snprintf(cookie, 256, "%s:%s", user, pass);
        return WV_CRED_OK;
    }
    size_t n = fread(cookie, 1, 255, f);
    fclose(f);
    cookie[n] = '\0';
    char *nl = strchr(cookie, '\n'); if (nl) *nl = '\0';
    return WV_CRED_OK;
}

static void wv_base64_encode(const char *cookie, char auth_b64[512])
{
    static const char b64[] =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
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
}

static size_t wv_receive_rpc_response(platform_socket_t fd, char *out,
                                      size_t outmax)
{
    size_t total = 0;
    while (total < outmax - 1) {
        int r = platform_socket_receive(fd, out + total,
                                        outmax - 1 - total);
        if (r <= 0) break;
        total += (size_t)r;
    }
    return total;
}

static int wv_strip_http_headers(char *out, size_t total)
{
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

int wv_rpc_call(const char *method, const char *params_json,
                char *out, size_t outmax)
{
    if (!out || outmax == 0)
        LOG_ERR("wallet_view", "rpc_call(%s): invalid output buffer", method);
    out[0] = '\0';

    char cookie[256] = "";
    /* Datadir-scoped credentials: with no datadir there is nothing
     * to read, and with neither file there is no request to send —
     * fail closed by name rather than issuing an unauthenticated
     * call. The LOG_ERR macros below log and RETURN -1; callers of
     * wv_rpc_call already treat <= 0 as "no response". */
    int cred = wv_resolve_rpc_credentials(cookie);
    if (cred == WV_CRED_NO_DATADIR)
        LOG_ERR("wallet_view", "rpc_call(%s): no datadir set", method);
    if (cred == WV_CRED_NO_FILES)
        LOG_ERR("wallet_view",
                "rpc_call(%s): no cookie or conf under %s",
                method, g_wv_datadir);
    if (cred == WV_CRED_MISSING_PAIR)
        LOG_ERR("wallet_view",
                "rpc_call(%s): missing rpcuser/rpcpassword in conf",
                method);

    platform_socket_t fd = platform_socket_open(AF_INET, SOCK_STREAM, 0,
                                                true, false);
    if (fd == PLATFORM_SOCKET_INVALID)
        LOG_ERR("wallet_view", "rpc_call(%s): socket() failed", method);

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    addr.sin_port = htons(ZCLASSICD_RPC_DEFAULT_PORT);

    (void)platform_socket_set_receive_timeout(fd, 3000);
    (void)platform_socket_set_send_timeout(fd, 3000);

    if (platform_socket_connect(fd, (struct sockaddr *)&addr,
                                sizeof(addr)) < 0) {
        (void)platform_socket_close(fd);
        LOG_ERR("wallet_view", "rpc_call(%s): connect to port %d failed",
                method, ZCLASSICD_RPC_DEFAULT_PORT);
    }

    char body[1024];
    int blen = snprintf(body, sizeof(body),
        "{\"jsonrpc\":\"1.0\",\"id\":1,\"method\":\"%s\",\"params\":%s}",
        method, params_json);
    if (wv_snprintf_truncated(blen, sizeof(body))) {
        (void)platform_socket_close(fd);
        LOG_ERR("wallet_view", "rpc_call(%s): request body too large (%d bytes)", method, blen);
    }

    char auth_b64[512];
    wv_base64_encode(cookie, auth_b64);

    char req[4096];
    int rlen = snprintf(req, sizeof(req),
        "POST / HTTP/1.1\r\nHost: 127.0.0.1\r\n"
        "Authorization: Basic %s\r\n"
        "Content-Type: engine/application/json\r\n"
        "Content-Length: %d\r\nConnection: close\r\n\r\n%s",
        auth_b64, blen, body);
    if (wv_snprintf_truncated(rlen, sizeof(req))) {
        (void)platform_socket_close(fd);
        LOG_ERR("wallet_view", "rpc_call(%s): request too large (%d bytes)", method, rlen);
    }

    if (!platform_socket_send_all(fd, req, (size_t)rlen)) {
        (void)platform_socket_close(fd);
        LOG_ERR("wallet_view", "rpc_call(%s): write failed (expected %d bytes)", method, rlen);
    }

    size_t total = wv_receive_rpc_response(fd, out, outmax);
    out[total] = '\0';
    (void)platform_socket_close(fd);

    return wv_strip_http_headers(out, total);
}

/* ── Get best-funded transparent address ───────────────────── */

static const char *wv_skip_addr_separators(const char *p)
{
    while (*p == ' ' || *p == ':' || *p == '"') p++;
    return p;
}

static const char *wv_scan_addr_value(const char *p)
{
    while (*p && *p != '"') p++;
    return p;
}

static bool wv_parse_amount_after(const char *p, double *out)
{
    const char *am = strstr(p, "\"amount\"");
    if (!am) return false;
    am += 8;
    while (*am == ' ' || *am == ':') am++;
    *out = strtod(am, NULL);
    return true;
}

static int wv_find_funded_addr(const struct wv_funded_addr *addrs, int n,
                               const char *a, size_t al)
{
    for (int i = 0; i < n; i++) {
        if (strlen(addrs[i].addr) == al &&
            memcmp(addrs[i].addr, a, al) == 0) {
            return i;
        }
    }
    return -1;
}

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
        p = wv_skip_addr_separators(p + 9);
        const char *a = p;
        p = wv_scan_addr_value(p);
        size_t al = (size_t)(p - a);
        if (al < 20 || al >= 128) continue;
        double v;
        if (!wv_parse_amount_after(p, &v)) continue;
        if (v <= 0) continue;
        /* Find existing entry or add new */
        int found = wv_find_funded_addr(addrs, n, a, al);
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

/* Per-z-address running total while aggregating z_listunspent entries. */
struct wv_zaddr_balance {
    char addr[256];
    double total;
};

/* Outcome of scanning one z_listunspent entry. */
enum wv_zaddr_scan {
    WV_ZADDR_FOUND = 0,
    WV_ZADDR_SKIP,
    WV_ZADDR_STOP,
};

/* Scan one z_listunspent record at *pp (positioned on its "address" key):
 * extract the quoted address and its amount, advance *pp past the amount,
 * and report whether the caller should keep, skip, or stop. */
static int wv_scan_zaddr_amount(const char **pp, char addr[256], double *amt)
{
    const char *p = *pp + 9;
    const char *q = strchr(p, '"');
    if (!q) return WV_ZADDR_STOP;
    q++;
    const char *end = strchr(q, '"');
    if (!end || (size_t)(end - q) >= 256) {
        *pp = end ? end : q;
        return WV_ZADDR_SKIP;
    }

    size_t alen = (size_t)(end - q);
    memcpy(addr, q, alen);
    addr[alen] = '\0';

    /* Find amount for this entry */
    const char *amt_p = strstr(end, "\"amount\"");
    if (!amt_p) return WV_ZADDR_STOP;
    amt_p += 8;
    while (*amt_p && (*amt_p == ' ' || *amt_p == ':' || *amt_p == '\t'))
        amt_p++;
    *amt = strtod(amt_p, NULL);
    *pp = amt_p;
    return WV_ZADDR_FOUND;
}

static int wv_find_zaddr_index(const struct wv_zaddr_balance *addrs, int n,
                               const char *addr)
{
    for (int i = 0; i < n; i++) {
        if (strcmp(addrs[i].addr, addr) == 0)
            return i;
    }
    return -1;
}

static void wv_copy_best_zaddr(const struct wv_zaddr_balance *addrs, int n,
                               char *out, size_t max, double *out_balance)
{
    /* Find the address with the highest balance */
    double best = 0;
    int best_idx = -1;
    for (int i = 0; i < n; i++) {
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

void wv_get_funded_zaddr(char *out, size_t max, double *out_balance) {
    out[0] = '\0';
    if (out_balance) *out_balance = 0;

    char buf[65536] = "";
    int rc = wv_rpc_call("z_listunspent", "[0]", buf, sizeof(buf));
    if (rc <= 0) return;

    /* Aggregate balances per z-address */
    struct wv_zaddr_balance addrs[16];
    int n_addrs = 0;

    const char *p = buf;
    char addr[256];
    double amt;
    while ((p = strstr(p, "\"address\"")) != NULL) {
        int s = wv_scan_zaddr_amount(&p, addr, &amt);
        if (s == WV_ZADDR_SKIP) continue;
        if (s != WV_ZADDR_FOUND) break;
        /* Aggregate into addrs[] */
        int idx = wv_find_zaddr_index(addrs, n_addrs, addr);
        if (idx >= 0) {
            addrs[idx].total += amt;
        } else if (n_addrs < 16) {
            snprintf(addrs[n_addrs].addr, 256, "%s", addr);
            addrs[n_addrs].total = amt;
            n_addrs++;
        }
    }

    wv_copy_best_zaddr(addrs, n_addrs, out, max, out_balance);
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

static const char *wv_plural_suffix(int64_t n)
{
    return n == 1 ? "" : "s";
}

void wv_format_relative_time(int64_t timestamp, char *out, size_t out_max) {
    if (!out || out_max == 0) return;
    out[0] = '\0';
    if (timestamp <= 0) { snprintf(out, out_max, "Just now"); return; }
    time_t now = platform_time_wall_time_t();
    int64_t diff = (int64_t)now - timestamp;
    if (diff < 0) { snprintf(out, out_max, "just now"); return; }
    if (diff < 60)    { snprintf(out, out_max, "%d second%s ago", (int)diff, wv_plural_suffix(diff)); return; }
    if (diff < 3600)  { int m = (int)(diff / 60);  snprintf(out, out_max, "%d minute%s ago", m, wv_plural_suffix(m)); return; }
    if (diff < 86400) { int h = (int)(diff / 3600); snprintf(out, out_max, "%d hour%s ago", h, wv_plural_suffix(h)); return; }
    if (diff < 2592000)  { int d = (int)(diff / 86400);   snprintf(out, out_max, "%d day%s ago", d, wv_plural_suffix(d)); return; }
    if (diff < 31536000) { int mo = (int)(diff / 2592000); snprintf(out, out_max, "%d month%s ago", mo, wv_plural_suffix(mo)); return; }
    int y = (int)(diff / 31536000);
    snprintf(out, out_max, "%d year%s ago", y, wv_plural_suffix(y));
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
