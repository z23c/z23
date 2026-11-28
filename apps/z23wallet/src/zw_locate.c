/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: find the node's data folder, RPC port and credentials for the Z23
 * profile (.cookie) and the legacy zclassicd profile (zclassic.conf, then
 * .cookie). Every candidate is recorded with the reason it was rejected, so
 * "not found" always lists what was searched. Only .cookie, .rpcport and
 * zclassic.conf are ever read; nothing in a node folder is written. */
#if !defined(_WIN32)
#include <fcntl.h>
#include <unistd.h>
#endif
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

#include "base/cleanse.h"
#include "zw.h"

#if defined(_WIN32)
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#endif

#define Z23_DEFAULT_PORT 18232
#define LEGACY_PORT 8023
#define LEGACY_TESTNET_PORT 18023
#define CONF_LINE_MAX (ZW_CRED_MAX + 160)

FILE *zw_fopen_read(const char *path)
{
#if defined(_WIN32)
    wchar_t w[1024];
    if (MultiByteToWideChar(CP_UTF8, 0, path, -1, w, 1024) <= 0) return NULL;
    return _wfopen(w, L"rb");
#else
    return fopen(path, "rb");
#endif
}

/* Log files hold lifecycle lines only, but stay owner-only on POSIX (0600). */
FILE *zw_fopen_append_private(const char *path)
{
#if defined(_WIN32)
    wchar_t w[1024];
    if (MultiByteToWideChar(CP_UTF8, 0, path, -1, w, 1024) <= 0) return NULL;
    return _wfopen(w, L"ab");
#else
    int fd = open(path, O_WRONLY | O_CREAT | O_APPEND, 0600);
    if (fd < 0) return NULL;
    FILE *f = fdopen(fd, "ab");
    if (!f) close(fd);
    return f;
#endif
}

static bool dir_exists(const char *path)
{
#if defined(_WIN32)
    wchar_t w[1024];
    if (MultiByteToWideChar(CP_UTF8, 0, path, -1, w, 1024) <= 0) return false;
    DWORD a = GetFileAttributesW(w);
    return a != INVALID_FILE_ATTRIBUTES && (a & FILE_ATTRIBUTE_DIRECTORY);
#else
    struct stat st;
    return stat(path, &st) == 0 && S_ISDIR(st.st_mode);
#endif
}

/* Environment variable as UTF-8; empty string when unset or too long. */
static const char *env_utf8(const char *name, char *buf, size_t cap)
{
    buf[0] = 0;
#if defined(_WIN32)
    wchar_t wn[64], *wv;
    if (MultiByteToWideChar(CP_UTF8, 0, name, -1, wn, 64) <= 0) return buf;
    wv = _wgetenv(wn);
    if (wv && WideCharToMultiByte(CP_UTF8, 0, wv, -1, buf, (int)cap, NULL, NULL) <= 0) buf[0] = 0;
#else
    const char *v = getenv(name);
    if (v && strlen(v) < cap) memcpy(buf, v, strlen(v) + 1);
#endif
    return buf;
}

bool zw_base64(const unsigned char *in, size_t n, char *out, size_t cap)
{
    static const char t[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    if (cap < ((n + 2) / 3) * 4 + 1) return false;
    size_t o = 0;
    for (size_t i = 0; i < n; i += 3) {
        uint32_t v = (uint32_t)in[i] << 16;
        if (i + 1 < n) v |= (uint32_t)in[i + 1] << 8;
        if (i + 2 < n) v |= in[i + 2];
        out[o++] = t[(v >> 18) & 63];
        out[o++] = t[(v >> 12) & 63];
        out[o++] = i + 1 < n ? t[(v >> 6) & 63] : '=';
        out[o++] = i + 2 < n ? t[v & 63] : '=';
    }
    out[o] = 0;
    return true;
}

void zw_endpoint_wipe(struct zw_endpoint *ep) { memory_cleanse(ep->auth, sizeof(ep->auth)); }

static void tried(struct zw_locate_report *rep, const char *path, const char *reason)
{
    if (!rep || rep->ntried >= ZW_TRIED_MAX) return;
    struct zw_tried *t = &rep->tried[rep->ntried++];
    snprintf(t->path, sizeof(t->path), "%s", path);
    snprintf(t->reason, sizeof(t->reason), "%s", reason);
    zw_log("locate: tried %s -> %s", path, reason);
}

static bool read_small(const char *dir, const char *name, char *buf, size_t cap, size_t *len)
{
    char path[ZW_PATH + 32];
    snprintf(path, sizeof(path), "%s/%s", dir, name);
    FILE *f = zw_fopen_read(path);
    if (!f) return false;
    size_t n = fread(buf, 1, cap - 1, f);
    fclose(f);
    buf[n] = 0;
    *len = n;
    return n > 0;
}

static bool set_basic(struct zw_endpoint *ep, const char *userpass, size_t n)
{
    char b64[sizeof(ep->auth) - 8];
    if (!zw_base64((const unsigned char *)userpass, n, b64, sizeof(b64))) return false;
    zw_endpoint_wipe(ep);
    snprintf(ep->auth, sizeof(ep->auth), "Basic %s", b64);
    zw_log_secret(b64);
    memory_cleanse(b64, sizeof(b64));
    return true;
}

bool zw_cookie_load(struct zw_endpoint *ep)
{
    char buf[400];
    size_t n = 0;
    if (!read_small(ep->cookie_dir[0] ? ep->cookie_dir : ep->datadir, ".cookie", buf, sizeof(buf), &n)) {
        memory_cleanse(buf, sizeof(buf));
        return false;
    }
    while (n && (buf[n - 1] == '\n' || buf[n - 1] == '\r')) buf[--n] = 0;
    zw_log_secret(buf);
    char *colon = strchr(buf, ':');
    if (colon) zw_log_secret(colon + 1); /* the password half alone must not leak either */
    bool ok = n > 0 && colon && set_basic(ep, buf, n);
    memory_cleanse(buf, sizeof(buf));
    if (ok) ep->cred_src = ZW_CRED_COOKIE;
    return ok;
}

/* ---- zclassic.conf (first value wins, case-sensitive keys: like zclassicd) ---- */

struct conf {
    char user[ZW_CRED_MAX + 1], pass[ZW_CRED_MAX + 1], datadir[ZW_PATH];
    long port;
    bool testnet, regtest, has_user, has_pass, has_port, has_testnet, has_regtest, has_datadir, found;
};

static char *trim(char *s)
{
    while (*s == ' ' || *s == '\t') s++;
    size_t n = strlen(s);
    while (n && (s[n - 1] == ' ' || s[n - 1] == '\t' || s[n - 1] == '\r' || s[n - 1] == '\n')) s[--n] = 0;
    return s;
}

static void conf_str(char *dst, size_t cap, bool *seen, const char *v)
{
    if (*seen) return;
    *seen = true;
    if (strlen(v) < cap) memcpy(dst, v, strlen(v) + 1);
    else zw_log("locate: a zclassic.conf value is longer than %u bytes; ignored", (unsigned)(cap - 1));
}

static void conf_network_flag(const char *key, const char *value, struct conf *c)
{
    bool negated = !strncmp(key, "no", 2);
    const char *name = negated ? key + 2 : key;
    /* Beta15 treats an empty value as true and keeps the first effective setting. */
    if (!strcmp(name, "testnet") && !c->has_testnet) {
        c->has_testnet = true;
        c->testnet = (!*value || atoi(value) != 0) != negated;
    } else if (!strcmp(name, "regtest") && !c->has_regtest) {
        c->has_regtest = true;
        c->regtest = (!*value || atoi(value) != 0) != negated;
    }
}

static void conf_line(struct conf *c, char *line)
{
    char *h = strchr(line, '#');
    if (h) *h = 0;
    char *eq = strchr(line, '=');
    if (!eq) return;
    *eq = 0;
    const char *k = trim(line), *v = trim(eq + 1);
    if (!strcmp(k, "rpcuser")) conf_str(c->user, sizeof(c->user), &c->has_user, v);
    else if (!strcmp(k, "rpcpassword")) {
        conf_str(c->pass, sizeof(c->pass), &c->has_pass, v);
        if (c->pass[0]) zw_log_secret(c->pass);
    } else if (!strcmp(k, "datadir")) conf_str(c->datadir, sizeof(c->datadir), &c->has_datadir, v);
    else if (!strcmp(k, "rpcport") && !c->has_port) { c->has_port = true; c->port = strtol(v, NULL, 10); }
    else conf_network_flag(k, v, c);
}

static void parse_conf(const char *path, struct conf *c)
{
    char line[CONF_LINE_MAX];
    FILE *f = zw_fopen_read(path);
    if (!f) return;
    c->found = true;
    while (fgets(line, sizeof(line), f)) {
        size_t n = strlen(line);
        bool whole = n == 0 || line[n - 1] == '\n' || feof(f);
        if (whole) {
            conf_line(c, line);
            continue;
        }
        int ch; /* an over-long line is skipped entirely, never half-read */
        while ((ch = fgetc(f)) != EOF && ch != '\n') {}
    }
    fclose(f);
    memory_cleanse(line, sizeof(line));
}

static void conf_wipe(struct conf *c) { memory_cleanse(c, sizeof(*c)); }

/* ---- legacy zclassicd ---- */

static bool legacy_dir(const struct zw_options *o, char *out, size_t cap, struct zw_locate_report *rep)
{
    char a[ZW_PATH - 48];
    if (o->datadir[0] && o->profile == ZW_PROFILE_ZCLASSICD) {
        snprintf(out, cap, "%s", o->datadir);
        return true;
    }
#if defined(_WIN32)
    if (!env_utf8("APPDATA", a, sizeof(a))[0]) { tried(rep, "%APPDATA%\\ZClassic", "APPDATA is not set"); return false; }
    snprintf(out, cap, "%s/ZClassic", a);
#elif defined(__APPLE__)
    if (!env_utf8("HOME", a, sizeof(a))[0]) { tried(rep, "~/Library/Application Support/ZClassic", "HOME is not set"); return false; }
    snprintf(out, cap, "%s/Library/Application Support/ZClassic", a);
#else
    if (!env_utf8("HOME", a, sizeof(a))[0]) { tried(rep, "~/.zclassic", "HOME is not set"); return false; }
    snprintf(out, cap, "%s/.zclassic", a);
#endif
    return true;
}

static bool legacy_creds(struct zw_endpoint *ep, struct conf *c, const char *dir, struct zw_locate_report *rep)
{
    if (c->regtest && c->testnet) {
        tried(rep, dir, "Invalid combination of -regtest and -testnet.");
        return false;
    }
    if (c->pass[0]) {
        char up[2 * ZW_CRED_MAX + 2];
        int n = snprintf(up, sizeof(up), "%s:%s", c->user, c->pass);
        bool ok = n > 0 && (size_t)n < sizeof(up) && set_basic(ep, up, (size_t)n);
        memory_cleanse(up, sizeof(up));
        if (ok) ep->cred_src = ZW_CRED_CONF;
        return ok;
    }
    const char *base = c->datadir[0] ? c->datadir : dir;
    snprintf(ep->cookie_dir, sizeof(ep->cookie_dir), "%.480s%s", base,
             c->regtest ? "/regtest" : c->testnet ? "/testnet3" : "");
    char cookie[ZW_PATH + 16];
    snprintf(cookie, sizeof(cookie), "%s/.cookie", ep->cookie_dir);
    FILE *f = zw_fopen_read(cookie);
    if (!f) {
        tried(rep, dir, c->found ? "no rpcpassword and no .cookie" : "no zclassic.conf");
        return false;
    }
    fclose(f);
    if (zw_cookie_load(ep)) return true;
    tried(rep, cookie, ".cookie unreadable");
    return false;
}

static bool locate_legacy(const struct zw_options *o, struct zw_endpoint *ep, struct zw_locate_report *rep)
{
    char dir[ZW_PATH];
    if (!legacy_dir(o, dir, sizeof(dir), rep)) return false;
    if (!dir_exists(dir)) { tried(rep, dir, "not found"); return false; }
    struct conf *c = calloc(1, sizeof(*c));
    if (!c) { tried(rep, dir, "out of memory"); return false; }
    snprintf(ep->conf_path, sizeof(ep->conf_path), "%.480s/zclassic.conf", dir);
    parse_conf(ep->conf_path, c);
    snprintf(ep->datadir, sizeof(ep->datadir), "%s", c->datadir[0] ? c->datadir : dir);
    ep->cookie_dir[0] = 0;
    bool ok = legacy_creds(ep, c, dir, rep);
    if (ok) {
        ep->profile = ZW_PROFILE_ZCLASSICD;
        ep->testnet = c->testnet;
        ep->regtest = c->regtest;
        long port = c->port;
        ep->port = o->rpcport ? o->rpcport
                 : port > 0 && port < 65536 ? (uint16_t)port
                 : (uint16_t)(c->testnet || c->regtest ? LEGACY_TESTNET_PORT : LEGACY_PORT);
        if (!c->found) ep->conf_path[0] = 0;
    }
    conf_wipe(c);
    free(c);
    return ok;
}

/* ---- Z23 ---- */

static void add_unique(char c[6][ZW_PATH], size_t *n, const char *path)
{
    for (size_t i = 0; i < *n; i++)
        if (!strcmp(c[i], path)) return;
    if (*n < 6) snprintf(c[(*n)++], ZW_PATH, "%s", path);
}

static void add_candidates(const struct zw_options *o, char c[6][ZW_PATH], size_t *n)
{
    char e[ZW_PATH - 48], t[ZW_PATH];
    *n = 0;
    if (o->datadir[0]) add_unique(c, n, o->datadir);
#if defined(_WIN32)
    if (env_utf8("LOCALAPPDATA", e, sizeof(e))[0]) {
        snprintf(t, sizeof(t), "%s/Z23/data", e); /* make windows-service-install */
        add_unique(c, n, t);
        snprintf(t, sizeof(t), "%s/Z23Node/data", e); /* the per-user scheduled-task install */
        add_unique(c, n, t);
    }
    if (env_utf8("USERPROFILE", e, sizeof(e))[0]) {
        snprintf(t, sizeof(t), "%s/.zclassic-c23", e);
        add_unique(c, n, t);
    }
#endif
    if (env_utf8("HOME", e, sizeof(e))[0]) {
        snprintf(t, sizeof(t), "%s/.zclassic-c23", e);
        add_unique(c, n, t);
    }
}

static bool try_z23(const struct zw_options *o, const char *dir, struct zw_endpoint *ep,
                    struct zw_locate_report *rep)
{
    char buf[32];
    size_t len = 0;
    if (!dir_exists(dir)) { tried(rep, dir, "not found"); return false; }
    snprintf(ep->datadir, sizeof(ep->datadir), "%.*s", (int)(sizeof(ep->datadir) - 1), dir);
    snprintf(ep->cookie_dir, sizeof(ep->cookie_dir), "%.*s", (int)(sizeof(ep->cookie_dir) - 1), dir);
    ep->conf_path[0] = 0;
    if (!zw_cookie_load(ep)) { tried(rep, dir, "no .cookie"); return false; }
    ep->profile = ZW_PROFILE_Z23;
    ep->testnet = ep->regtest = false;
    ep->port = Z23_DEFAULT_PORT;
    if (o->rpcport) ep->port = o->rpcport;
    else if (read_small(dir, ".rpcport", buf, sizeof(buf), &len)) {
        long p = strtol(buf, NULL, 10);
        if (p > 0 && p < 65536) ep->port = (uint16_t)p;
    }
    return true;
}

static const char *cred_name(enum zw_cred c) { return c == ZW_CRED_CONF ? "conf" : "cookie"; }

bool zw_locate(const struct zw_options *o, struct zw_endpoint *ep, struct zw_locate_report *rep)
{
    snprintf(ep->host, sizeof(ep->host), "127.0.0.1");
    ep->valid = false;
    ep->cred_src = ZW_CRED_NONE;
    if (rep) rep->ntried = 0;
    if (o->profile != ZW_PROFILE_ZCLASSICD) {
        char cand[6][ZW_PATH];
        size_t n = 0;
        add_candidates(o, cand, &n);
        for (size_t i = 0; i < n && !ep->valid; i++) ep->valid = try_z23(o, cand[i], ep, rep);
    }
    if (!ep->valid && o->profile != ZW_PROFILE_Z23) ep->valid = locate_legacy(o, ep, rep);
    if (ep->valid)
        zw_log("locate: using %s port %u creds=%s", ep->profile == ZW_PROFILE_Z23 ? "z23" : "zclassicd",
               (unsigned)ep->port, cred_name(ep->cred_src));
    return ep->valid;
}
