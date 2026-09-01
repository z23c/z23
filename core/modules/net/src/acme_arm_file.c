/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * The node/worker handoff file. See net/acme_arm_file.h for the format and
 * for why it is not a secret.
 */

#if !defined(_WIN32)
#define _XOPEN_SOURCE 700
#endif

#include "net/acme_arm_file.h"

#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>

#if !defined(_WIN32)
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#endif

#include "net/acme_b64url.h"

#include "base/log_macros.h"

/* Both fields are ASCII by construction: a DNS name, and a token plus a
 * base64url thumbprint. Anything else in this file did not come from the
 * worker, so it is refused rather than passed on to a certificate builder. */
#define ACME_ARM_MAX_FIELD 512
#define ACME_ARM_MAX_FILE  2048

static bool field_is_plain(const char *s)
{
    if (!s || !s[0])
        return false;
    for (const char *p = s; *p; p++) {
        const unsigned char c = (unsigned char)*p;
        const bool ok = (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
                        (c >= '0' && c <= '9') || c == '.' || c == '-' ||
                        c == '_' || c == '*';
        if (!ok)
            return false;
    }
    return true;
}

bool acme_arm_file_write(const char *path, const char *domain,
                         const char *key_authz)
{
    if (!path || !path[0])
        LOG_FAIL("acme", "cannot write the challenge handoff without a path");
    if (!field_is_plain(domain) || !field_is_plain(key_authz))
        LOG_FAIL("acme",
                 "refusing to write a challenge handoff carrying a byte outside "
                 "the domain/base64url alphabet");
    if (strlen(domain) >= ACME_ARM_MAX_FIELD ||
        strlen(key_authz) >= ACME_ARM_MAX_FIELD)
        LOG_FAIL("acme", "refusing an over-long challenge handoff field");

    char tmp[1024];
    const int n = snprintf(tmp, sizeof(tmp), "%s.tmp", path);
    if (n < 0 || (size_t)n >= sizeof(tmp))
        LOG_FAIL("acme", "challenge handoff path is too long to stage");

    FILE *f = NULL;
#if !defined(_WIN32)
    (void)unlink(tmp);
    const int fd = open(tmp, O_WRONLY | O_CREAT | O_EXCL, S_IRUSR | S_IWUSR);
    if (fd < 0)
        LOG_FAIL("acme", "cannot create %s", tmp);
    f = fdopen(fd, "wb");
    if (!f) {
        close(fd);
        LOG_FAIL("acme", "cannot buffer writes to %s", tmp);
    }
#else
    f = fopen(tmp, "wb");
    if (!f)
        LOG_FAIL("acme", "cannot create %s", tmp);
#endif
    const bool wrote =
        fprintf(f, "domain=%s\nkeyauth=%s\n", domain, key_authz) > 0 &&
        fflush(f) == 0;
    fclose(f);
    if (!wrote) {
        remove(tmp);
        LOG_FAIL("acme", "cannot write the challenge handoff to %s", tmp);
    }
    if (rename(tmp, path) != 0) {
        remove(tmp);
        LOG_FAIL("acme", "cannot move the challenge handoff into place at %s", path);
    }
    return true;
}

/* Copy the value of `key=` from one line into `out`, refusing anything that
 * would not fit rather than truncating. */
static bool take_field(const char *line, const char *key, char *out,
                       size_t out_len)
{
    const size_t key_len = strlen(key);
    if (strncmp(line, key, key_len) != 0 || line[key_len] != '=')
        return false;
    const char *value = line + key_len + 1;
    const size_t n = strlen(value);
    if (n == 0 || n + 1 > out_len)
        return false;
    memcpy(out, value, n + 1);
    return true;
}

bool acme_arm_file_read(const char *path, char *domain, size_t domain_len,
                        char *key_authz, size_t key_authz_len)
{
    if (!domain || !key_authz || domain_len == 0 || key_authz_len == 0)
        return false;
    domain[0] = '\0';
    key_authz[0] = '\0';
    if (!path || !path[0])
        return false;

    FILE *f = fopen(path, "rb");
    if (!f)
        return false; /* absent is the ordinary state, not an error */
    char buf[ACME_ARM_MAX_FILE];
    const size_t got = fread(buf, 1, sizeof(buf) - 1, f);
    const bool overlong = !feof(f) && got == sizeof(buf) - 1;
    fclose(f);
    if (overlong)
        LOG_FAIL("acme", "refusing a challenge handoff over %d bytes",
                 ACME_ARM_MAX_FILE);
    buf[got] = '\0';

    char *save = buf;
    bool have_domain = false;
    bool have_authz = false;
    while (*save) {
        char *nl = strchr(save, '\n');
        if (nl)
            *nl = '\0';
        if (take_field(save, "domain", domain, domain_len))
            have_domain = true;
        else if (take_field(save, "keyauth", key_authz, key_authz_len))
            have_authz = true;
        if (!nl)
            break;
        save = nl + 1;
    }
    if (!have_domain || !have_authz ||
        !field_is_plain(domain) || !field_is_plain(key_authz)) {
        domain[0] = '\0';
        key_authz[0] = '\0';
        LOG_FAIL("acme", "challenge handoff at %s is not a usable domain/keyauth pair",
                 path);
    }
    return true;
}

bool acme_arm_file_clear(const char *path)
{
    if (!path || !path[0])
        return true;
    if (remove(path) != 0) {
        if (errno == ENOENT)
            return true;
        FILE *f = fopen(path, "rb");
        if (f)
            fclose(f);
        LOG_FAIL("acme", "cannot remove the challenge handoff at %s", path);
    }
    return true;
}

/* ── the key authorization ───────────────────────────────────────────── */

static bool token_is_base64url(const char *token)
{
    if (!token || !token[0])
        return false;
    for (const char *p = token; *p; p++) {
        const char c = *p;
        const bool ok = (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') ||
                        (c >= '0' && c <= '9') || c == '-' || c == '_';
        if (!ok)
            return false;
    }
    return true;
}

bool acme_key_authorization(const char *token, const uint8_t thumbprint[32],
                            char *out, size_t out_len)
{
    if (!out || out_len == 0)
        return false;
    out[0] = '\0';
    if (!thumbprint)
        return false;
    if (!token_is_base64url(token))
        LOG_FAIL("acme",
                 "refusing a challenge token outside the base64url alphabet: it "
                 "would be signed into a certificate this node presents");
    char b64[64];
    if (acme_b64url_encode(thumbprint, 32, b64, sizeof(b64)) == 0)
        LOG_FAIL("acme", "cannot base64url the account key thumbprint");
    const size_t need = strlen(token) + 1 + strlen(b64);
    if (need + 1 > out_len)
        LOG_FAIL("acme", "key authorization needs %zu bytes, buffer holds %zu",
                 need + 1, out_len);
    memcpy(out, token, strlen(token));
    out[strlen(token)] = '.';
    memcpy(out + strlen(token) + 1, b64, strlen(b64) + 1);
    return true;
}
