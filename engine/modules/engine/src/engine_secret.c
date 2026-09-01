/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * The key holder and the scrubber. See engine/engine_secret.h for the design
 * rule: redaction happens because the redacting writer is the only writer,
 * not because a caller remembered to ask for it.
 *
 * The scrub is length-non-increasing on purpose. Every run it replaces is at
 * least as long as the replacement token, so it can rewrite in place with a
 * read and a write cursor and never needs a second buffer — which means the
 * emitters cannot fail to redact because an allocation failed.
 */

#include "engine/engine_secret.h"

#include "base/log_macros.h"

#include <ctype.h>
#include <fcntl.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

/* The Windows CRT does not expose O_CLOEXEC. Its descriptors wrap
 * non-inheritable handles unless inheritance is explicitly requested, so a
 * zero-valued compatibility flag preserves the intended boundary.
 * (Same zero fallback as core/modules/net/src/rom_fetch.c.) */
#ifndef O_CLOEXEC
#define O_CLOEXEC 0
#endif

#define ENGINE_SECRET_MIN 12
#define ENGINE_REDACTED   "[REDACTED]"

static char g_secret[ENGINE_SECRET_MAX];
static size_t g_secret_len;

void engine_secret_clear(void)
{
    /* volatile write loop: a plain memset here is exactly what an optimizer
     * is allowed to delete on a buffer that is never read again. */
    volatile char *p = g_secret;
    for (size_t i = 0; i < sizeof(g_secret); i++)
        p[i] = 0;
    g_secret_len = 0;
}

bool engine_secret_loaded(void)
{
    return g_secret_len > 0;
}

/* Trim trailing whitespace and refuse anything that is not plausibly a key.
 * A short or space-bearing value is a misconfiguration, and sending it would
 * put a fragment of a real credential into a vendor's logs. */
static bool adopt(const char *raw)
{
    if (!raw)
        return false;
    size_t n = strlen(raw);
    while (n > 0 && (raw[n - 1] == '\n' || raw[n - 1] == '\r'
                     || raw[n - 1] == ' ' || raw[n - 1] == '\t'))
        n--;
    if (n < ENGINE_SECRET_MIN || n >= sizeof(g_secret))
        LOG_FAIL("engine", "refusing a key of %zu bytes: outside [%d, %zu)", n,
                 ENGINE_SECRET_MIN, sizeof(g_secret));
    for (size_t i = 0; i < n; i++) {
        const unsigned char c = (unsigned char)raw[i];
        if (c <= 0x20 || c >= 0x7f)
            LOG_FAIL("engine",
                     "refusing a key containing whitespace or a control byte");
    }
    memcpy(g_secret, raw, n);
    g_secret[n] = '\0';
    g_secret_len = n;
    return true;
}

/* Read a key file. Mode must be exactly 0600 and it must be a regular file.
 * Both are refusals, not warnings. */
static bool load_from_file(const char *path, char *where, size_t where_len)
{
    struct stat st;
    if (stat(path, &st) != 0)
        LOG_FAIL("engine", "no key file at the configured path");
    if (!S_ISREG(st.st_mode))
        LOG_FAIL("engine", "the configured key path is not a regular file");
    if ((st.st_mode & 0777) != 0600)
        LOG_FAIL("engine",
                 "refusing a key file whose mode is %03o: it must be 0600",
                 (unsigned)(st.st_mode & 0777));
    if (st.st_size <= 0 || (size_t)st.st_size >= sizeof(g_secret))
        LOG_FAIL("engine", "refusing a key file of %lld bytes",
                 (long long)st.st_size);

    const int fd = open(path, O_RDONLY | O_CLOEXEC);
    if (fd < 0)
        LOG_FAIL("engine", "cannot open the configured key file");
    char buf[ENGINE_SECRET_MAX] = {0};
    const ssize_t got = read(fd, buf, sizeof(buf) - 1);
    (void)close(fd);
    if (got <= 0)
        LOG_FAIL("engine", "the configured key file is empty");
    buf[got] = '\0';
    const bool ok = adopt(buf);
    volatile char *wipe = buf;
    for (size_t i = 0; i < sizeof(buf); i++)
        wipe[i] = 0;
    if (ok)
        (void)snprintf(where, where_len, "a 0600 key file outside the repo");
    return ok;
}

bool engine_secret_load(const struct engine_vendor *v, const char *explicit_path,
                        char *where, size_t where_len)
{
    if (!where || where_len == 0)
        return false;
    where[0] = '\0';
    engine_secret_clear();
    if (!v)
        LOG_FAIL("engine", "refusing to load a key for no vendor");
    if (!engine_needs_key(v)) {
        /* A CLI engine authenticates through its own installed session and a
         * fixture engine authenticates against nothing. Handing either one a
         * key would put a credential somewhere it is not needed, which is the
         * only way it can leak from a process that never prints it. */
        (void)snprintf(where, where_len, "no key needed by %s", v->id);
        return true;
    }
    if (explicit_path && explicit_path[0])
        return load_from_file(explicit_path, where, where_len);

    if (v->key_env) {
        const char *env = getenv(v->key_env);
        if (env && env[0]) {
            if (!adopt(env))
                return false;
            (void)snprintf(where, where_len, "the %s environment variable",
                           v->key_env);
            return true;
        }
    }
    if (v->key_file_rel) {
        const char *home = getenv("HOME");
        char path[1024];
        if (home && home[0]
            && (size_t)snprintf(path, sizeof(path), "%s/%s", home,
                                v->key_file_rel) < sizeof(path))
            return load_from_file(path, where, where_len);
    }
    LOG_FAIL("engine",
             "no API key for %s: set %s, or place one in ~/%s with mode 0600",
             v->id, v->key_env ? v->key_env : "(none)",
             v->key_file_rel ? v->key_file_rel : "(none)");
}

bool engine_secret_authorization_header(char *out, size_t out_len)
{
    if (!out || out_len == 0)
        return false;
    out[0] = '\0';
    if (g_secret_len == 0)
        LOG_FAIL("engine", "no key is loaded");
    if ((size_t)snprintf(out, out_len, "Bearer %s", g_secret) >= out_len) {
        out[0] = '\0';
        LOG_FAIL("engine", "the authorization header does not fit its buffer");
    }
    return true;
}

/* ── the scrubber ────────────────────────────────────────────────────── */

static bool tok_byte(char c)
{
    return isalnum((unsigned char)c) || c == '-' || c == '_' || c == '.';
}

static size_t token_run(const char *s)
{
    size_t n = 0;
    while (s[n] && tok_byte(s[n]))
        n++;
    return n;
}

/* Length of a key-shaped run starting at `s`, or 0. Four shapes, each chosen
 * because it has actually appeared in a transcript on this host. */
static size_t key_shape_len(const char *s)
{
    static const char *const k_prefix[] = { "sk-", "xai-", "gsk_", "sk_live_",
                                            "ghp_", "glpat-" };
    for (size_t i = 0; i < sizeof(k_prefix) / sizeof(k_prefix[0]); i++) {
        const size_t pl = strlen(k_prefix[i]);
        if (strncmp(s, k_prefix[i], pl) == 0) {
            const size_t n = token_run(s);
            if (n >= 20)
                return n;
        }
    }
    /* <32+ hex>.<16+ alnum> — the Z.ai / JWT-ish two-part shape. */
    size_t h = 0;
    while (isxdigit((unsigned char)s[h]))
        h++;
    if (h >= 32 && s[h] == '.') {
        size_t t = h + 1;
        while (isalnum((unsigned char)s[t]))
            t++;
        if (t - h - 1 >= 16)
            return t;
    }
    return 0;
}

/* `Bearer <token>` — redact the token, keep the word so a reader can still
 * see that authentication was present. */
static size_t bearer_token_offset(const char *s, size_t *run)
{
    static const char k[] = "Bearer ";
    if (strncmp(s, k, sizeof(k) - 1) != 0)
        return 0;
    const size_t n = token_run(s + sizeof(k) - 1);
    if (n < 16)
        return 0;
    *run = n;
    return sizeof(k) - 1;
}

void engine_redact_inplace(char *s)
{
    if (!s)
        return;
    const size_t marker = strlen(ENGINE_REDACTED);
    char *w = s;
    for (const char *r = s; *r;) {
        size_t run = 0;
        size_t skip = 0;

        if (g_secret_len >= marker && strncmp(r, g_secret, g_secret_len) == 0) {
            run = g_secret_len;
        } else if ((skip = bearer_token_offset(r, &run)) != 0) {
            memmove(w, r, skip);
            w += skip;
            r += skip;
        } else {
            run = key_shape_len(r);
        }

        if (run >= marker) {
            memcpy(w, ENGINE_REDACTED, marker);
            w += marker;
            r += run;
            continue;
        }
        *w++ = *r++;
    }
    *w = '\0';
}

void engine_emit(FILE *f, const char *fmt, ...)
{
    if (!f || !fmt)
        return;
    char line[8192];
    va_list ap;
    va_start(ap, fmt);
    const int n = vsnprintf(line, sizeof(line), fmt, ap);
    va_end(ap);
    if (n < 0)
        return;
    engine_redact_inplace(line);
    (void)fputs(line, f);
    /* Flush every line. A dispatch runs for minutes and its output is almost
     * always redirected to a file someone is tailing; block buffering turns
     * that into a silent process, which is indistinguishable from a hung one.
     * A harness whose whole purpose is honest reporting must not look wedged
     * while it is working. */
    (void)fflush(f);
}

bool engine_emit_file(const char *path, const char *text, size_t len)
{
    if (!path || !text)
        LOG_FAIL("engine", "refusing to write an artifact with no path or body");
    char *copy = malloc(len + 1); /* raw-alloc-ok:scrub buffer, wiped below */
    if (!copy)
        LOG_FAIL("engine", "cannot allocate %zu bytes to scrub an artifact",
                 len + 1);
    memcpy(copy, text, len);
    copy[len] = '\0';
    engine_redact_inplace(copy);

    const int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0600);
    bool ok = false;
    if (fd < 0) {
        LOG_WARN("engine", "cannot create the artifact file");
    } else {
        const size_t n = strlen(copy);
        ok = (n == 0) || (write(fd, copy, n) == (ssize_t)n);
        if (!ok)
            LOG_WARN("engine", "short write on the artifact file");
        (void)close(fd);
    }
    volatile char *wipe = copy;
    for (size_t i = 0; i <= len; i++)
        wipe[i] = 0;
    free(copy);
    return ok;
}
