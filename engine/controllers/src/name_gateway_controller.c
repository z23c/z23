/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * ZCL Names onion gateway — see controllers/name_gateway_controller.h for
 * the contract, the opt-in, and the full list of bounds.
 *
 * This file dials. It does not render: every byte it returns is
 * attacker-chosen and is handed to the caller as opaque bytes. */

#include "controllers/name_gateway_controller.h"

#include "net/tor_integration.h"
#include "util/log_macros.h"

#include <stdlib.h>
#include <string.h>

bool name_gateway_enabled(void)
{
    /* Same shape as ZCL_NAMES_PUBLIC_REGISTER: absent or anything other
     * than exactly "1" means OFF. Read per call so an operator can flip it
     * with a restart and nothing caches a stale "on". */
    const char *v = getenv("ZCL_NAMES_ONION_GATEWAY");
    return v && strcmp(v, "1") == 0;
}

bool name_gateway_host_valid(const char *h)
{
    if (!h) return false;
    if (strlen(h) != 62 || strcmp(h + 56, ".onion") != 0) return false;
    for (size_t i = 0; i < 56; i++) {
        char c = h[i];
        if (!((c >= 'a' && c <= 'z') || (c >= '2' && c <= '7')))
            return false;
    }
    return true;
}

/* ASCII case-insensitive compare of `len` bytes of `s` against the
 * NUL-terminated `want`. Written out rather than strncasecmp so the fold
 * is locale-independent — a Turkish locale must not change which scheme
 * this node accepts. */
static bool gw_ascii_ieq(const char *s, size_t len, const char *want)
{
    size_t i;
    for (i = 0; i < len; i++) {
        char c = s[i];
        if (c >= 'A' && c <= 'Z') c = (char)(c + 32);
        if (!want[i] || c != want[i]) return false;
    }
    return want[i] == '\0';
}

/* Refuse one target and say which rule refused it. WARN, not ERROR: the
 * target text is on-chain and therefore attacker-chosen, so a hostile
 * registration must not be able to pump this node's error log. */
static bool gw_refuse(const char *rule, char *out)
{
    if (out) out[0] = '\0';
    LOG_WARN("name.gateway", "target refused: %s", rule);
    return false; /* raw-return-ok:refusal-logged-on-the-line-above */
}

/* Point *after at the first byte past a leading "scheme://", or at
 * `target` itself when the target has no scheme separator, and report
 * whether the scheme, when there is one, is http or https. */
static bool gw_scheme_ok(const char *target, const char **after)
{
    const char *sep = strstr(target, "://");
    size_t slen;

    if (!sep) {
        *after = target;
        return true;
    }
    slen = (size_t)(sep - target);
    *after = sep + 3;
    return gw_ascii_ieq(target, slen, "http") ||
           gw_ascii_ieq(target, slen, "https");
}

/* True when the authority at `p` carries user@ userinfo. */
static bool gw_host_has_userinfo(const char *p)
{
    for (const char *q = p; *q && *q != '/' && *q != '?' && *q != '#'; q++)
        if (*q == '@')
            return true;
    return false;
}

/* Copy the authority at `p` into `out` and NUL-terminate it. Returns
 * false, with `out` left unterminated, once one more byte would leave no
 * room for the terminator. */
static bool gw_copy_authority(const char *p, char *out, size_t cap)
{
    size_t n = 0;
    while (p[n] && p[n] != '/' && p[n] != '?' && p[n] != '#') {
        if (n + 1 >= cap)
            return false;
        out[n] = p[n];
        n++;
    }
    out[n] = '\0';
    return true;
}

/* Truncate an explicit ":80" off `host`; any other explicit port leaves
 * `host` untouched and is reported as false for the caller to refuse. */
static bool gw_port_is_default(char *host)
{
    char *colon = strchr(host, ':');
    bool port80;

    if (!colon)
        return true;
    port80 = strcmp(colon + 1, "80") == 0;
    if (port80)
        *colon = '\0';
    return port80;
}

/* Fold A-Z down to a-z in place. */
static void gw_ascii_lower(char *s)
{
    for (size_t i = 0; s[i]; i++)
        if (s[i] >= 'A' && s[i] <= 'Z') s[i] = (char)(s[i] + 32);
}

bool name_gateway_host_from_target(const char *target, char *out, size_t cap)
{
    const char *p;

    if (!out || cap == 0)
        LOG_FAIL("name.gateway", "host_from_target: no output buffer");
    out[0] = '\0';
    if (!target || !target[0])
        return gw_refuse("empty target", out);

    /* Scheme: only http/https, and only as an exact prefix. Anything else
     * (javascript:, data:, a bare "://") is refused rather than guessed.
     * URL schemes are case-insensitive, so "HTTP://" is the same scheme —
     * comparing case-sensitively would reject a legitimate target. */
    if (!gw_scheme_ok(target, &p))
        return gw_refuse("scheme is not http/https", out);

    /* Userinfo (user@host) is a phishing shape and we have no use for it. */
    if (gw_host_has_userinfo(p))
        return gw_refuse("userinfo in host", out);

    /* Authority runs to the first path/query/fragment delimiter. */
    if (!gw_copy_authority(p, out, cap))
        return gw_refuse("host longer than the buffer", out);

    /* An explicit port is only tolerated when it is the one we dial. The
     * fetch primitive is hardwired to 80; silently ignoring :8080 would
     * send the visitor somewhere they did not ask for. */
    if (!gw_port_is_default(out))
        return gw_refuse("port other than 80", out);

    /* Hostnames are case-insensitive; onion base32 is lowercase. Fold
     * before validating so "ABCD….ONION" is accepted, not silently
     * rejected as malformed. */
    gw_ascii_lower(out);

    if (!name_gateway_host_valid(out))
        return gw_refuse("not an exact Tor v3 onion host", out);
    return true;
}

const char *name_gateway_status_code(enum name_gateway_status s)
{
    switch (s) {
    case NAME_GATEWAY_OK:               return "GATEWAY_OK";
    case NAME_GATEWAY_DISABLED:         return "GATEWAY_DISABLED";
    case NAME_GATEWAY_BAD_HOST:         return "GATEWAY_BAD_HOST";
    case NAME_GATEWAY_TOR_UNAVAILABLE:  return "GATEWAY_TOR_UNAVAILABLE";
    case NAME_GATEWAY_FETCH_FAILED:     return "GATEWAY_FETCH_FAILED";
    case NAME_GATEWAY_EMPTY:            return "GATEWAY_EMPTY";
    }
    return "GATEWAY_UNKNOWN_STATUS";
}

const char *name_gateway_status_message(enum name_gateway_status s)
{
    switch (s) {
    case NAME_GATEWAY_OK:
        return "Fetched.";
    case NAME_GATEWAY_DISABLED:
        return "This node does not relay third-party sites. The name still "
               "resolves — the link below goes to it directly, and needs a "
               "Tor-capable browser.";
    case NAME_GATEWAY_BAD_HOST:
        return "This name's target is not an exact Tor v3 onion address on "
               "port 80, so nothing was dialled.";
    case NAME_GATEWAY_TOR_UNAVAILABLE:
        return "This node's Tor is not running, so it cannot reach the "
               "target. The name resolved fine.";
    case NAME_GATEWAY_FETCH_FAILED:
        return "The target did not answer within this node's deadline, or "
               "the circuit failed.";
    case NAME_GATEWAY_EMPTY:
        return "The target answered with nothing to show.";
    }
    return "Unknown gateway status.";
}

enum name_gateway_status name_gateway_fetch(const char *target,
                                            struct name_gateway_result *out)
{
    struct onion_fetch_result fetched;
    size_t keep;

    if (!out) {
        LOG_WARN("name.gateway", "fetch called with NULL result");
        return NAME_GATEWAY_FETCH_FAILED;
    }
    memset(out, 0, sizeof(*out));

    if (!name_gateway_enabled())
        return NAME_GATEWAY_DISABLED;

    if (!name_gateway_host_from_target(target, out->host, sizeof(out->host)))
        return NAME_GATEWAY_BAD_HOST;

    if (!tor_integration_is_ready()) {
        LOG_WARN("name.gateway", "tor not ready; not dialling %s", out->host);
        return NAME_GATEWAY_TOR_UNAVAILABLE;
    }

    /* Root only. No visitor-supplied path, query, body, method, or header
     * crosses this boundary — the primitive's whole outbound surface is
     * (host, port 80, path). */
    memset(&fetched, 0, sizeof(fetched));
    if (tor_integration_fetch_onion_blocking(out->host, "/", &fetched,
                                             NAME_GATEWAY_TIMEOUT_SECS) != 0) {
        free(fetched.body);
        LOG_WARN("name.gateway", "fetch failed for %s", out->host);
        return NAME_GATEWAY_FETCH_FAILED;
    }

    out->http_status = fetched.status;
    out->upstream_bytes = fetched.body_len;
    if (!fetched.body || fetched.body_len == 0) {
        free(fetched.body);
        return NAME_GATEWAY_EMPTY;
    }

    keep = fetched.body_len;
    if (keep > NAME_GATEWAY_MAX_BODY_BYTES) {
        keep = NAME_GATEWAY_MAX_BODY_BYTES;
        out->truncated = true;
    }
    memcpy(out->body, fetched.body, keep);
    out->body_len = keep;
    free(fetched.body);
    return NAME_GATEWAY_OK;
}
