/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * The self-signed certificate the node signs for itself, and the one
 * question that must never be answered wrongly: is what we are serving
 * something an authority issued, or something we made up?
 *
 * Every structural assertion below is made against a DER round-trip, not
 * against the in-memory X509 the builder returned. A structure that is
 * correct only in memory — an extension attached but never encoded, a name
 * set on the wrong object — passes a same-object check and fails on the
 * wire, which is the only place it matters.
 *
 * The "not self-signed" direction is proved with a real second certificate:
 * a throwaway authority is built here and asked to sign a leaf, so the
 * negative case is a certificate that genuinely has a different issuer,
 * never a flag flipped to make the check say no.
 */

#include "test/test_core.h"

#include "net/acme_selfsigned.h"

#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>

#include <stdio.h>
#include <string.h>
#include <sys/stat.h>

#define AS_CHECK(name, expr) do {                         \
    printf("acme_selfsigned: %s... ", (name));            \
    if (expr) { printf("OK\n"); }                         \
    else { printf("FAIL\n"); failures++; }                \
} while (0)

/* Round-trip through DER so every later assertion reads the wire form. */
static X509 *reparse(X509 *cert)
{
    unsigned char *der = NULL;
    const int n = i2d_X509(cert, &der);
    if (n <= 0 || !der)
        return NULL;
    const unsigned char *p = der;
    X509 *back = d2i_X509(NULL, &p, n);
    OPENSSL_free(der);
    return back;
}

static bool subject_field_equals(X509 *cert, int nid, const char *want)
{
    char got[512] = "";
    X509_NAME *name = X509_get_subject_name(cert);
    if (!name)
        return false;
    if (X509_NAME_get_text_by_NID(name, nid, got, (int)sizeof(got)) <= 0)
        return false;
    return strcmp(got, want) == 0;
}

static bool has_dns_san(X509 *cert, const char *want)
{
    bool found = false;
    GENERAL_NAMES *names =
        X509_get_ext_d2i(cert, NID_subject_alt_name, NULL, NULL);
    if (!names)
        return false;
    for (int i = 0; i < sk_GENERAL_NAME_num(names) && !found; i++) {
        const GENERAL_NAME *gn = sk_GENERAL_NAME_value(names, i);
        if (!gn || gn->type != GEN_DNS)
            continue;
        const ASN1_IA5STRING *dns = gn->d.dNSName;
        const int len = ASN1_STRING_length(dns);
        const unsigned char *data = ASN1_STRING_get0_data(dns);
        found = len == (int)strlen(want) &&
                memcmp(data, want, (size_t)len) == 0;
    }
    GENERAL_NAMES_free(names);
    return found;
}

/* A throwaway certificate authority, so "issued by someone else" can be
 * asserted against a certificate that really was. */
static X509 *sign_leaf_with_a_different_issuer(void)
{
    EVP_PKEY *ca_key = EVP_EC_gen("P-256");
    EVP_PKEY *leaf_key = EVP_EC_gen("P-256");
    X509 *ca = X509_new();
    X509 *leaf = X509_new();
    bool ok = false;

    if (!ca_key || !leaf_key || !ca || !leaf)
        goto done;
    if (X509_set_version(ca, 2) != 1 || X509_set_version(leaf, 2) != 1)
        goto done;
    if (!X509_gmtime_adj(X509_getm_notBefore(ca), -3600) ||
        !X509_gmtime_adj(X509_getm_notAfter(ca), 86400) ||
        !X509_gmtime_adj(X509_getm_notBefore(leaf), -3600) ||
        !X509_gmtime_adj(X509_getm_notAfter(leaf), 86400))
        goto done;
    if (X509_set_pubkey(ca, ca_key) != 1 ||
        X509_set_pubkey(leaf, leaf_key) != 1)
        goto done;
    if (X509_NAME_add_entry_by_txt(X509_get_subject_name(ca), "CN",
                                   MBSTRING_ASC,
                                   (const unsigned char *)"test-authority", -1,
                                   -1, 0) != 1)
        goto done;
    if (X509_set_issuer_name(ca, X509_get_subject_name(ca)) != 1)
        goto done;
    if (X509_NAME_add_entry_by_txt(X509_get_subject_name(leaf), "CN",
                                   MBSTRING_ASC,
                                   (const unsigned char *)"leaf.example.org",
                                   -1, -1, 0) != 1)
        goto done;
    if (X509_set_issuer_name(leaf, X509_get_subject_name(ca)) != 1)
        goto done;
    ok = X509_sign(ca, ca_key, EVP_sha256()) != 0 &&
         X509_sign(leaf, ca_key, EVP_sha256()) != 0;

done:
    X509_free(ca);
    EVP_PKEY_free(ca_key);
    EVP_PKEY_free(leaf_key);
    if (!ok) {
        X509_free(leaf);
        return NULL;
    }
    return leaf;
}

static bool file_mode_is(const char *path, mode_t want)
{
    struct stat st;
    if (stat(path, &st) != 0)
        return false;
    return (st.st_mode & 07777) == want;
}

static bool file_inode(const char *path, unsigned long long *out)
{
    struct stat st;
    if (stat(path, &st) != 0)
        return false;
    *out = (unsigned long long)st.st_ino;
    return true;
}

static void write_text(const char *path, const char *text)
{
    FILE *f = fopen(path, "wb");
    if (!f)
        return;
    fputs(text, f);
    fclose(f);
}

int test_acme_selfsigned(void)
{
    int failures = 0;

    /* ── the name ──────────────────────────────────────────────────── */
    {
        char long_label[80];
        memset(long_label, 'a', 64);
        long_label[64] = '\0';
        char too_long[300];
        memset(too_long, 'a', 254);
        too_long[254] = '\0';

        AS_CHECK("a plain hostname is an LDH name",
                 acme_domain_is_ldh("node.example.org"));
        AS_CHECK("a single label is an LDH name", acme_domain_is_ldh("a"));
        AS_CHECK("a wildcard label is accepted",
                 acme_domain_is_ldh("*.example.org"));
        AS_CHECK("a name with a space is refused",
                 !acme_domain_is_ldh("bad domain"));
        AS_CHECK("an empty label is refused", !acme_domain_is_ldh("a..b"));
        AS_CHECK("a trailing dot is refused",
                 !acme_domain_is_ldh("example.org."));
        AS_CHECK("a slash is refused", !acme_domain_is_ldh("host/../etc"));
        AS_CHECK("a 64-byte label is refused", !acme_domain_is_ldh(long_label));
        AS_CHECK("a 254-byte name is refused", !acme_domain_is_ldh(too_long));
        AS_CHECK("an empty name is refused", !acme_domain_is_ldh(""));
        AS_CHECK("no name at all is refused", !acme_domain_is_ldh(NULL));
    }

    /* ── the certificate the builder makes ─────────────────────────── */
    X509 *cert = NULL;
    EVP_PKEY *key = NULL;
    X509 *wire = NULL;
    {
        const struct acme_selfsigned_spec spec = {
            .domain = "node.example.org",
            .organization = ACME_SELFSIGNED_ORGANIZATION,
            .backdate_seconds = 3600,
            .lifetime_seconds = ACME_SELFSIGNED_LIFETIME_SECONDS,
            .extra = NULL,
        };
        AS_CHECK("the placeholder certificate builds",
                 acme_selfsigned_build(&spec, &cert, &key) && cert && key);
        wire = cert ? reparse(cert) : NULL;
        AS_CHECK("it survives a DER round trip", wire != NULL);
        if (wire) {
            AS_CHECK("the subject CN is the domain",
                     subject_field_equals(wire, NID_commonName,
                                          "node.example.org"));
            AS_CHECK("the subject says in words that it is a placeholder",
                     subject_field_equals(wire, NID_organizationName,
                                          ACME_SELFSIGNED_ORGANIZATION));
            AS_CHECK("it carries a subjectAltName for the domain",
                     has_dns_san(wire, "node.example.org"));
            AS_CHECK("it is a v3 certificate", X509_get_version(wire) == 2);
            AS_CHECK("the key it was signed with is its own",
                     X509_check_private_key(wire, key) == 1);
            AS_CHECK("it names ITSELF as its own issuer",
                     acme_certificate_is_self_issued(wire));
            AS_CHECK("it does not expire soon enough to close the ALPN door",
                     X509_cmp_current_time(X509_get0_notAfter(wire)) > 0);
        }
    }

    /* ── the other direction: a certificate someone else issued ────── */
    {
        X509 *leaf = sign_leaf_with_a_different_issuer();
        AS_CHECK("a leaf signed by an authority builds", leaf != NULL);
        X509 *leaf_wire = leaf ? reparse(leaf) : NULL;
        AS_CHECK("and it is NOT reported as self-issued",
                 leaf_wire && !acme_certificate_is_self_issued(leaf_wire));
        X509_free(leaf_wire);
        X509_free(leaf);
        AS_CHECK("no certificate at all is not reported as self-issued",
                 !acme_certificate_is_self_issued(NULL));
    }

    /* ── what the builder refuses ──────────────────────────────────── */
    {
        X509 *c = NULL;
        EVP_PKEY *k = NULL;
        AS_CHECK("no specification is refused",
                 !acme_selfsigned_build(NULL, &c, &k) && !c && !k);
        const struct acme_selfsigned_spec bad_name = {
            .domain = "not a domain", .organization = NULL,
            .backdate_seconds = 0, .lifetime_seconds = 60, .extra = NULL,
        };
        AS_CHECK("a domain that is not an LDH name is refused",
                 !acme_selfsigned_build(&bad_name, &c, &k) && !c && !k);
        const struct acme_selfsigned_spec no_life = {
            .domain = "node.example.org", .organization = NULL,
            .backdate_seconds = 0, .lifetime_seconds = 0, .extra = NULL,
        };
        AS_CHECK("a certificate that would be born expired is refused",
                 !acme_selfsigned_build(&no_life, &c, &k) && !c && !k);
    }

    /* ── the pair on disk ──────────────────────────────────────────── */
    {
        char dir[512];
        char cert_path[640], key_path[640], junk_path[640], missing[700];
        test_make_tmpdir(dir, sizeof(dir), "acme_selfsigned", "pair");
        snprintf(cert_path, sizeof(cert_path), "%s/placeholder.pem", dir);
        snprintf(key_path, sizeof(key_path), "%s/placeholder-key.pem", dir);
        snprintf(junk_path, sizeof(junk_path), "%s/junk.pem", dir);
        snprintf(missing, sizeof(missing), "%s/no-such-dir/c.pem", dir);

        AS_CHECK("an absent file is not reported as self-issued",
                 !acme_certificate_file_is_self_issued(cert_path));

        AS_CHECK("the placeholder pair is written",
                 acme_selfsigned_write(cert_path, key_path, "node.example.org"));
        AS_CHECK("the certificate on disk is self-issued",
                 acme_certificate_file_is_self_issued(cert_path));
        AS_CHECK("the private key is 0600", file_mode_is(key_path, 0600));
        AS_CHECK("the certificate is world readable",
                 file_mode_is(cert_path, 0644));
        AS_CHECK("ensure leaves a usable pair alone",
                 acme_selfsigned_ensure(cert_path, key_path, "node.example.org"));
        unsigned long long before = 0, after = 0;
        AS_CHECK("and does not rewrite it",
                 file_inode(cert_path, &before) &&
                 acme_selfsigned_ensure(cert_path, key_path,
                                        "node.example.org") &&
                 file_inode(cert_path, &after) && before == after);

        write_text(junk_path, "this is not a certificate\n");
        AS_CHECK("a file that is not a certificate is not self-issued",
                 !acme_certificate_file_is_self_issued(junk_path));

        /* A mismatched pair is exactly what a half-finished copy of a
         * datadir leaves behind, and it is the pair that would stop the
         * listener from binding at all. */
        write_text(cert_path, "not a certificate\n");
        AS_CHECK("ensure replaces a certificate that does not parse",
                 acme_selfsigned_ensure(cert_path, key_path,
                                        "node.example.org") &&
                 acme_certificate_file_is_self_issued(cert_path));
        write_text(key_path, "not a key\n");
        AS_CHECK("ensure replaces a key that does not parse",
                 acme_selfsigned_ensure(cert_path, key_path,
                                        "node.example.org"));
        {
            /* Both halves parse, but they do not belong to each other. */
            char other_cert[700], other_key[700];
            snprintf(other_cert, sizeof(other_cert), "%s/other.pem", dir);
            snprintf(other_key, sizeof(other_key), "%s/other-key.pem", dir);
            if (acme_selfsigned_write(other_cert, other_key, "other.example")) {
                FILE *src = fopen(other_key, "rb");
                FILE *dst = fopen(key_path, "wb");
                int c;
                if (src && dst)
                    while ((c = fgetc(src)) != EOF)
                        fputc(c, dst);
                if (src) fclose(src);
                if (dst) fclose(dst);
            }
            unsigned long long mismatched = 0, repaired = 0;
            AS_CHECK("ensure replaces a pair whose key is not its own",
                     file_inode(cert_path, &mismatched) &&
                     acme_selfsigned_ensure(cert_path, key_path,
                                            "node.example.org") &&
                     file_inode(cert_path, &repaired) &&
                     mismatched != repaired);
        }

        AS_CHECK("a pair that cannot be written is refused, not faked",
                 !acme_selfsigned_write(missing, key_path, "node.example.org"));
        AS_CHECK("and ensure reports that failure rather than claiming a pair",
                 !acme_selfsigned_ensure(missing, key_path, "node.example.org"));
        AS_CHECK("a write with no certificate path is refused",
                 !acme_selfsigned_write(NULL, key_path, "node.example.org"));
        AS_CHECK("a write for a domain that is not an LDH name is refused",
                 !acme_selfsigned_write(cert_path, key_path, "not a domain"));
        AS_CHECK("no domain at all falls back to a name that IS legal",
                 acme_selfsigned_write(cert_path, key_path, NULL) &&
                 acme_certificate_file_is_self_issued(cert_path));

        test_rm_rf(dir);
    }

    X509_free(wire);
    X509_free(cert);
    EVP_PKEY_free(key);
    return failures;
}
