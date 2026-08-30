/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Two names, one listener, one certificate each — graded from the outside,
 * over real TLS, against the real front door.
 *
 * WHY FROM THE WIRE. "The server picks the certificate matching the name the
 * client asked for" is a statement about what a client receives, and only a
 * client can make it. Every check here opens a real connection to the real
 * listener, sends (or deliberately omits) a real SNI name, completes a real
 * handshake, and reads the subject CN off the leaf the server presented.
 * Nothing inspects the server's internal tables; a refactor that keeps the
 * tables and breaks the wire fails this test, which is the right way round.
 *
 * THE ORDERING THIS FILE EXISTS TO PIN. The SNI callback swaps the
 * connection's SSL_CTX, and swapping an SSL_CTX resets the connection's
 * certificate. The TLS-ALPN-01 responder sets an SSL-scoped certificate for
 * the ACME challenge. If those two ran in the wrong order the SNI swap would
 * silently discard the challenge certificate and NO certificate on this host
 * could ever be renewed — a failure that is invisible for ninety days and
 * then total. The ALPN leg below asks a client for "acme-tls/1" while naming
 * a configured host in SNI and requires the challenge certificate back,
 * identified by the critical acmeIdentifier extension RFC 8737 puts in it.
 *
 * The certificates are self-signed on purpose and the client verifies
 * nothing: what is under test is WHICH certificate arrives, not whether
 * anybody vouched for it. The TLS-client symbols this file links are why
 * lib/test objects are excluded from test_cold_join_sovereign P2's scan —
 * the node itself is server-side only and carries none of them.
 */

#include "test/test_core.h"

#include "net/acme_challenge.h"
#include "net/acme_selfsigned.h"
#include "net/https_server.h"

#include <openssl/err.h>
#include <openssl/objects.h>
#include <openssl/pem.h>
#include <openssl/ssl.h>
#include <openssl/x509.h>

#include "platform/socket_compat.h"

#include <errno.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#define SN_CHECK(name, expr) do {                          \
    printf("https_sni_select: %s... ", (name));            \
    if (expr) { printf("OK\n"); }                          \
    else { printf("FAIL\n"); failures++; }                 \
} while (0)

/* The name in the DEFAULT certificate — the one the listener starts on and
 * the one every unmatched client must keep getting. */
#define DEFAULT_CN "origin.example"
#define ALPHA      "alpha.example"
#define BRAVO      "bravo.example"
/* What alpha's certificate says after it is renewed in place. A different CN
 * from ALPHA so "alpha reloaded" and "alpha did not reload" are two
 * different observations on the wire, not the same one. */
#define ALPHA_RENEWED_CN "alpha-renewed.example"
/* A name the server was never told about. */
#define STRANGER   "stranger.example"

static _Atomic int g_port = 0;

static uint16_t free_port(void)
{
    platform_socket_t fd = platform_socket_open(AF_INET, SOCK_STREAM, 0,
                                                true, false);
    if (fd == PLATFORM_SOCKET_INVALID)
        return 0;
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    addr.sin_port = htons(0);
    uint16_t port = 0;
    if (platform_socket_bind(fd, (struct sockaddr *)&addr,
                             sizeof(addr)) == 0) {
        size_t len = sizeof(addr);
        if (platform_socket_local_address(fd, (struct sockaddr *)&addr,
                                          &len) == 0)
            port = ntohs(addr.sin_port);
    }
    platform_socket_close(fd);
    return port;
}

/* What one handshake produced. */
struct served {
    char cn[256];       /* subject CN of the leaf the server presented */
    char alpn[64];      /* the protocol the server selected, or "" */
    bool acme_identifier; /* the leaf carries the RFC 8737 extension */
};

/* True when this leaf is an ACME TLS-ALPN-01 challenge certificate. The
 * extension, not the name: a challenge certificate carries the SAME subject
 * CN as the ordinary certificate for that domain, so the name cannot tell
 * them apart and this is the only honest discriminator. */
static bool leaf_has_acme_identifier(X509 *leaf)
{
    ASN1_OBJECT *obj = OBJ_txt2obj(ACME_ID_OID_TEXT, 1);
    if (!obj)
        return false;
    const int idx = X509_get_ext_by_OBJ(leaf, obj, -1);
    ASN1_OBJECT_free(obj);
    return idx >= 0;
}

/* Connect, handshake, record what came back. `sni` NULL means send no
 * server_name extension at all — the old client / bare IP case. Returns
 * false when the handshake did not complete, which is the failure mode a
 * name mismatch produces and therefore the thing most of these checks are
 * really asserting the absence of. */
static bool handshake(const char *sni, bool offer_acme_alpn,
                      struct served *out)
{
    memset(out, 0, sizeof(*out));

    const int port = atomic_load(&g_port);
    if (port <= 0)
        return false;

    bool ok = false;
    SSL_CTX *ctx = NULL;
    SSL *ssl = NULL;
    X509 *leaf = NULL;

    const platform_socket_t fd = platform_socket_open(AF_INET, SOCK_STREAM,
                                                      0, true, false);
    if (fd == PLATFORM_SOCKET_INVALID)
        return false;
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    addr.sin_port = htons((uint16_t)port);
    if (platform_socket_connect(fd, (struct sockaddr *)&addr,
                                sizeof(addr)) != 0)
        goto done;

    ctx = SSL_CTX_new(TLS_client_method());
    ssl = ctx ? SSL_new(ctx) : NULL;
    if (!ssl || SSL_set_fd(ssl, (int)(intptr_t)fd) != 1)
        goto done;
    if (sni && !SSL_set_tlsext_host_name(ssl, sni))
        goto done;
    if (offer_acme_alpn) {
        /* One-byte length prefix, then the protocol name. */
        static const unsigned char offer[] = {
            (unsigned char)(sizeof(ACME_ALPN_PROTOCOL) - 1),
            'a', 'c', 'm', 'e', '-', 't', 'l', 's', '/', '1'
        };
        if (SSL_set_alpn_protos(ssl, offer, (unsigned)sizeof(offer)) != 0)
            goto done;
    }
    if (SSL_connect(ssl) != 1) {
        ERR_clear_error();
        goto done;
    }

    {
        const unsigned char *sel = NULL;
        unsigned sel_len = 0;
        SSL_get0_alpn_selected(ssl, &sel, &sel_len);
        if (sel && sel_len > 0 && sel_len < sizeof(out->alpn)) {
            memcpy(out->alpn, sel, sel_len);
            out->alpn[sel_len] = '\0';
        }
    }

    leaf = SSL_get1_peer_certificate(ssl);
    if (!leaf)
        goto done;
    if (X509_NAME_get_text_by_NID(X509_get_subject_name(leaf), NID_commonName,
                                  out->cn, (int)sizeof(out->cn)) <= 0)
        goto done;
    out->acme_identifier = leaf_has_acme_identifier(leaf);
    ok = true;

done:
    X509_free(leaf);
    if (ssl) {
        SSL_shutdown(ssl);
        SSL_free(ssl);
    }
    SSL_CTX_free(ctx);
    if (fd != PLATFORM_SOCKET_INVALID)
        platform_socket_close(fd);
    return ok;
}

/* Which certificate a plain browser-shaped client is served for `sni`. */
static bool served_cn(const char *sni, char *out, size_t out_len)
{
    struct served s;
    if (!handshake(sni, false, &s))
        return false;
    snprintf(out, out_len, "%s", s.cn);
    return true;
}

/* ── writing a test certificate pair ─────────────────────────────────────
 *
 * Deliberately NOT acme_selfsigned_write(): that one exists to write the
 * BOOT PLACEHOLDER and stamps ACME_SELFSIGNED_ORGANIZATION into the subject
 * O to say so in words. Nothing here is a placeholder, and a change to that
 * label — its wording, or the bound X.509 puts on organizationName — is a
 * change to the placeholder's policy, not to certificate selection by name.
 * Binding this test to it would let one break the other for no reason.
 * acme_selfsigned_build() with no organization is the same builder, one
 * layer down, and is what the TLS-ALPN-01 responder itself uses.
 *
 * Published by rename() from a temporary, which is how the certificate
 * worker and the placeholder writer publish, and what the front door's
 * change detection is built around: a renewed pair always lands on a fresh
 * inode, so "this file was replaced" never depends on mtime granularity. */
static bool pem_publish(const char *path, X509 *cert, EVP_PKEY *key)
{
    char tmp[900];
    if (snprintf(tmp, sizeof(tmp), "%s.tmp", path) >= (int)sizeof(tmp))
        return false;
    FILE *f = fopen(tmp, "wb");
    if (!f)
        return false;
    const bool wrote = cert ? (PEM_write_X509(f, cert) == 1)
                            : (PEM_write_PrivateKey(f, key, NULL, NULL, 0,
                                                    NULL, NULL) == 1);
    if (fclose(f) != 0 || !wrote) {
        (void)remove(tmp);
        return false;
    }
    if (rename(tmp, path) != 0) {
        (void)remove(tmp);
        return false;
    }
    return true;
}

/* Key first, certificate second — a reader that sees the certificate always
 * finds the matching key already beside it. */
static bool pair_write(const char *cert_path, const char *key_path,
                       const char *cn)
{
    const struct acme_selfsigned_spec spec = {
        .domain = cn,
        .organization = NULL,
        .backdate_seconds = 3600,
        .lifetime_seconds = 7 * 24 * 3600,
        .extra = NULL,
    };
    X509 *cert = NULL;
    EVP_PKEY *key = NULL;
    if (!acme_selfsigned_build(&spec, &cert, &key))
        return false;
    const bool ok = pem_publish(key_path, NULL, key) &&
                    pem_publish(cert_path, cert, NULL);
    X509_free(cert);
    EVP_PKEY_free(key);
    return ok;
}

/* A name's pair, in its own directory — the shape boot uses:
 * <root>/<name>/fullchain.pem and <root>/<name>/privkey.pem. */
struct name_pair {
    char cert[768];
    char key[768];
};

static bool name_pair_write(struct name_pair *p, const char *root,
                            const char *name, const char *cn)
{
    char dir[640];
    snprintf(dir, sizeof(dir), "%s/%s", root, name);
    if (mkdir(dir, 0700) != 0 && errno != EEXIST)
        return false;
    snprintf(p->cert, sizeof(p->cert), "%s/fullchain.pem", dir);
    snprintf(p->key, sizeof(p->key), "%s/privkey.pem", dir);
    return pair_write(p->cert, p->key, cn);
}

int test_https_sni_select(void)
{
    int failures = 0;

    char dir[512];
    char def_cert[640], def_key[640];
    struct name_pair alpha, bravo;
    test_make_tmpdir(dir, sizeof(dir), "https_sni_select", "ssl");
    snprintf(def_cert, sizeof(def_cert), "%s/fullchain.pem", dir);
    snprintf(def_key, sizeof(def_key), "%s/privkey.pem", dir);

    SN_CHECK("a default certificate pair is written",
             pair_write(def_cert, def_key, DEFAULT_CN));
    SN_CHECK("a pair for the first extra name is written in its own directory",
             name_pair_write(&alpha, dir, ALPHA, ALPHA));
    SN_CHECK("a pair for the second extra name is written beside it",
             name_pair_write(&bravo, dir, BRAVO, BRAVO));

    const uint16_t https_port = free_port();
    const uint16_t http_port = free_port();
    SN_CHECK("two free ports were found", https_port != 0 && http_port != 0);
    if (https_port == 0 || http_port == 0) {
        test_rm_rf(dir);
        return failures;
    }
    atomic_store(&g_port, (int)https_port);

    /* ── the unchanged default: one certificate, no names ──────────── */

    SN_CHECK("the front door starts on the default pair alone",
             https_server_start_on_port(def_cert, def_key, DEFAULT_CN,
                                        (int)https_port, (int)http_port));
    if (!https_server_is_running()) {
        printf("https_sni_select: SKIP (the listener did not come up on port "
               "%u; nothing further was asserted in this run)\n",
               (unsigned)https_port);
        https_server_stop();
        test_rm_rf(dir);
        return failures;
    }

    {
        char cn[256] = "";
        SN_CHECK("with no name configured, a client asking for one is still "
                 "served the default certificate",
                 served_cn(ALPHA, cn, sizeof(cn)) &&
                 strcmp(cn, DEFAULT_CN) == 0);
        cn[0] = '\0';
        SN_CHECK("and a client that sends no name at all is too",
                 served_cn(NULL, cn, sizeof(cn)) &&
                 strcmp(cn, DEFAULT_CN) == 0);
    }

    /* ── one configured name ───────────────────────────────────────── */

    SN_CHECK("a name is given its own certificate pair",
             https_server_watch_certificate_for_name(ALPHA, alpha.cert,
                                                     alpha.key));
    SN_CHECK("and the pair is picked up on the next look at the disk",
             https_server_certificate_refresh());
    SN_CHECK("looking again finds nothing more to do",
             !https_server_certificate_refresh());

    {
        char cn[256] = "";
        SN_CHECK("a client asking for that name is served THAT name's "
                 "certificate",
                 served_cn(ALPHA, cn, sizeof(cn)) && strcmp(cn, ALPHA) == 0);
        cn[0] = '\0';
        SN_CHECK("a client asking for a name nobody configured completes its "
                 "handshake on the default certificate",
                 served_cn(STRANGER, cn, sizeof(cn)) &&
                 strcmp(cn, DEFAULT_CN) == 0);
        cn[0] = '\0';
        SN_CHECK("a client that sends no name is served the default "
                 "certificate",
                 served_cn(NULL, cn, sizeof(cn)) &&
                 strcmp(cn, DEFAULT_CN) == 0);
    }

    /* ── a second name, added to a running listener ─────────────────── */

    SN_CHECK("a second name is added while the listener is serving",
             https_server_watch_certificate_for_name(BRAVO, bravo.cert,
                                                     bravo.key));
    SN_CHECK("and its pair is picked up too",
             https_server_certificate_refresh());

    {
        char cn[256] = "";
        SN_CHECK("the first name still gets the first certificate",
                 served_cn(ALPHA, cn, sizeof(cn)) && strcmp(cn, ALPHA) == 0);
        cn[0] = '\0';
        SN_CHECK("the second name gets the second certificate",
                 served_cn(BRAVO, cn, sizeof(cn)) && strcmp(cn, BRAVO) == 0);
        cn[0] = '\0';
        SN_CHECK("and the default is still the default",
                 served_cn(NULL, cn, sizeof(cn)) &&
                 strcmp(cn, DEFAULT_CN) == 0);
    }

    /* ── the name is matched case-insensitively, as SNI is ─────────── */
    {
        char cn[256] = "";
        SN_CHECK("the same name in a different case selects the same "
                 "certificate",
                 served_cn("ALPHA.Example", cn, sizeof(cn)) &&
                 strcmp(cn, ALPHA) == 0);
    }

    /* ── TLS-ALPN-01 outranks SNI ──────────────────────────────────── */

    {
        struct served s;
        SN_CHECK("an ordinary client is served a certificate that is NOT a "
                 "challenge certificate",
                 handshake(ALPHA, false, &s) && !s.acme_identifier &&
                 strcmp(s.cn, ALPHA) == 0);

        SN_CHECK("a validation is armed for the configured name",
                 acme_alpn_challenge_arm(ALPHA, "token.thumbprint"));

        memset(&s, 0, sizeof(s));
        const bool got = handshake(ALPHA, true, &s);
        SN_CHECK("a client offering acme-tls/1 for a CONFIGURED name "
                 "completes its handshake", got);
        SN_CHECK("the server selects acme-tls/1",
                 got && strcmp(s.alpn, ACME_ALPN_PROTOCOL) == 0);
        SN_CHECK("and presents the CHALLENGE certificate, not the one "
                 "configured for that name",
                 got && s.acme_identifier);

        acme_alpn_challenge_disarm();
        memset(&s, 0, sizeof(s));
        SN_CHECK("with nothing armed, that same name is served its own "
                 "certificate again",
                 handshake(ALPHA, false, &s) && !s.acme_identifier &&
                 strcmp(s.cn, ALPHA) == 0);

        /* A scanner offering acme-tls/1 with no validation in flight must
         * not be handed a challenge certificate, and must not be refused
         * either — the responder declines the protocol and the ordinary
         * certificate is served. */
        memset(&s, 0, sizeof(s));
        SN_CHECK("acme-tls/1 offered with nothing armed gets the name's "
                 "ordinary certificate and no ALPN",
                 handshake(ALPHA, true, &s) && !s.acme_identifier &&
                 strcmp(s.cn, ALPHA) == 0 && s.alpn[0] == '\0');
    }

    /* ── renewing one name disturbs no other ───────────────────────── */

    {
        SN_CHECK("one name's certificate is replaced on disk",
                 pair_write(alpha.cert, alpha.key,
                                       ALPHA_RENEWED_CN));
        SN_CHECK("the front door adopts it with no restart",
                 https_server_certificate_refresh());

        char cn[256] = "";
        SN_CHECK("that name now serves the renewed certificate",
                 served_cn(ALPHA, cn, sizeof(cn)) &&
                 strcmp(cn, ALPHA_RENEWED_CN) == 0);
        cn[0] = '\0';
        SN_CHECK("the other name is untouched",
                 served_cn(BRAVO, cn, sizeof(cn)) && strcmp(cn, BRAVO) == 0);
        cn[0] = '\0';
        SN_CHECK("and so is the default",
                 served_cn(NULL, cn, sizeof(cn)) &&
                 strcmp(cn, DEFAULT_CN) == 0);
        SN_CHECK("and a further look finds nothing more to do",
                 !https_server_certificate_refresh());
    }

    /* ── what is refused, and refused without breaking anything ────── */

    {
        SN_CHECK("a name that is not a plain LDH name is refused",
                 !https_server_watch_certificate_for_name(
                     "not a name/../etc", alpha.cert, alpha.key));
        SN_CHECK("a name with no key path is refused",
                 !https_server_watch_certificate_for_name(BRAVO, bravo.cert,
                                                          ""));
        char cn[256] = "";
        SN_CHECK("and the listener is still serving every name it had",
                 served_cn(BRAVO, cn, sizeof(cn)) && strcmp(cn, BRAVO) == 0);
    }

    https_server_stop();
    test_rm_rf(dir);
    return failures;
}
