/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: find the node's data folder, RPC port and credentials for the Z23
 * profile (cookie) and the legacy zclassicd profile (zclassic.conf or
 * cookie). Only .cookie, .rpcport and zclassic.conf are ever read. */
#include <ctype.h>
#include <stdlib.h>
#include <string.h>

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

/* Environment variable as UTF-8; empty string when unset. */
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
    char b64[200];
    if (!zw_base64((const unsigned char *)userpass, n, b64, sizeof(b64))) return false;
    zw_endpoint_wipe(ep);
    snprintf(ep->auth, sizeof(ep->auth), "Basic %s", b64);
    memory_cleanse(b64, sizeof(b64));
    return true;
}

bool zw_cookie_load(struct zw_endpoint *ep)
{
    char buf[160];
    size_t n = 0;
    if (!read_small(ep->datadir, ".cookie", buf, sizeof(buf), &n)) return false;
    while (n && (buf[n - 1] == '\n' || buf[n - 1] == '\r')) buf[--n] = 0;
    zw_log_secret(buf);
    char *colon = strchr(buf, ':');
    if (colon) zw_log_secret(colon + 1); /* the password half alone must not leak either */
    bool ok = n > 0 && set_basic(ep, buf, n);
    memory_cleanse(buf, sizeof(buf));
    return ok;
}

static void trim(char *s)
{
    size_t n = strlen(s);
    while (n && isspace((unsigned char)s[n - 1])) s[--n] = 0;
}

/* zclassic.conf: key=value lines, '#' comments, later keys win. */
static void parse_conf(const char *dir, char *user, char *pass, long *port, bool *testnet)
{
    char path[ZW_PATH + 32], line[256];
    snprintf(path, sizeof(path), "%s/zclassic.conf", dir);
    FILE *f = zw_fopen_read(path);
    if (!f) return;
    while (fgets(line, sizeof(line), f)) {
        char *h = strchr(line, '#');
        if (h) *h = 0;
        trim(line);
        char *eq = strchr(line, '=');
        if (!eq) continue;
        *eq = 0;
        char *k = line, *v = eq + 1;
        while (isspace((unsigned char)*k)) k++;
        trim(k);
        for (char *p = k; *p; p++) *p = (char)tolower((unsigned char)*p);
        if (!strcmp(k, "rpcuser") && strlen(v) < 64) strcpy(user, v);
        else if (!strcmp(k, "rpcpassword") && strlen(v) < 96) { strcpy(pass, v); zw_log_secret(v); }
        else if (!strcmp(k, "rpcport")) *port = strtol(v, NULL, 10);
        else if (!strcmp(k, "testnet")) *testnet = atoi(v) != 0;
    }
    fclose(f);
    memory_cleanse(line, sizeof(line));
}

static void cp_path(char *dst, const char *src)
{
    size_t n = strnlen(src, ZW_PATH - 1);
    memcpy(dst, src, n);
    dst[n] = 0;
}

static bool legacy_dir(const struct zw_options *o, char *out, size_t cap)
{
    char a[ZW_PATH - 40];
    if (o->datadir[0] && o->profile == ZW_PROFILE_ZCLASSICD) {
        snprintf(out, cap, "%s", o->datadir);
        return true;
    }
#if defined(_WIN32)
    env_utf8("APPDATA", a, sizeof(a));
    if (!a[0]) return false;
    snprintf(out, cap, "%s/ZClassic", a);
#else
    env_utf8("HOME", a, sizeof(a));
    if (!a[0]) return false;
    snprintf(out, cap, "%s/.zclassic", a);
#endif
    return true;
}

static bool locate_legacy(const struct zw_options *o, struct zw_endpoint *ep,
                          struct zw_locate_report *rep)
{
    char dir[ZW_PATH], user[64] = "", pass[96] = "";
    long port = 0;
    bool testnet = false;
    if (!legacy_dir(o, dir, sizeof(dir))) return false;
    if (rep && rep->ntried < 8) snprintf(rep->tried[rep->ntried++], ZW_PATH, "%s", dir);
    parse_conf(dir, user, pass, &port, &testnet);
    snprintf(ep->datadir, sizeof(ep->datadir), "%s", dir);
    bool ok = false;
    if (user[0] && pass[0]) {
        char up[200];
        int n = snprintf(up, sizeof(up), "%s:%s", user, pass);
        ok = n > 0 && set_basic(ep, up, (size_t)n);
        memory_cleanse(up, sizeof(up));
    } else {
        ok = zw_cookie_load(ep);
    }
    memory_cleanse(pass, sizeof(pass));
    if (!ok) return false;
    ep->profile = ZW_PROFILE_ZCLASSICD;
    ep->testnet = testnet;
    ep->port = o->rpcport ? o->rpcport
             : port > 0 ? (uint16_t)port : (uint16_t)(testnet ? LEGACY_TESTNET_PORT : LEGACY_PORT);
    return true;
}

static void add_unique(char c[6][ZW_PATH], size_t *n, const char *path)
{
    for (size_t i = 0; i < *n; i++)
        if (!strcmp(c[i], path)) return;
    if (*n < 6) cp_path(c[(*n)++], path);
}

static void add_candidates(const struct zw_options *o, char c[6][ZW_PATH], size_t *n)
{
    char e[ZW_PATH - 40];
    *n = 0;
    if (o->datadir[0]) add_unique(c, n, o->datadir);
    char t[ZW_PATH];
#if defined(_WIN32)
    if (env_utf8("LOCALAPPDATA", e, sizeof(e))[0]) {
        snprintf(t, sizeof(t), "%s/Z23/data", e);
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

bool zw_locate(const struct zw_options *o, struct zw_endpoint *ep, struct zw_locate_report *rep)
{
    char cand[6][ZW_PATH];
    size_t n = 0;
    char buf[32];
    size_t len = 0;
    snprintf(ep->host, sizeof(ep->host), "127.0.0.1");
    ep->valid = false;
    if (rep) rep->ntried = 0;
    if (o->profile != ZW_PROFILE_ZCLASSICD) {
        add_candidates(o, cand, &n);
        for (size_t i = 0; i < n; i++) {
            if (rep && rep->ntried < 8) cp_path(rep->tried[rep->ntried++], cand[i]);
            cp_path(ep->datadir, cand[i]);
            if (!zw_cookie_load(ep)) continue;
            ep->profile = ZW_PROFILE_Z23;
            ep->testnet = false;
            ep->port = Z23_DEFAULT_PORT;
            if (o->rpcport) ep->port = o->rpcport;
            else if (read_small(cand[i], ".rpcport", buf, sizeof(buf), &len)) {
                long p = strtol(buf, NULL, 10);
                if (p > 0 && p < 65536) ep->port = (uint16_t)p;
            }
            ep->valid = true;
            return true;
        }
    }
    if (o->profile != ZW_PROFILE_Z23 && locate_legacy(o, ep, rep)) {
        ep->valid = true;
        return true;
    }
    return false;
}
