/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * The self-signed certificate the node signs for itself.
 * See net/acme_selfsigned.h for why it exists and why it lives here.
 *
 * This file owns the whole X509 skeleton — key, serial, validity, subject,
 * subjectAltName, self-issuance, signature. acme_alpn_challenge.c builds its
 * TLS-ALPN-01 certificate through the same builder and adds one extension,
 * so there is exactly one place in the tree that decides what a certificate
 * this node signs looks like.
 */

#if !defined(_WIN32)
#define _XOPEN_SOURCE 700
#endif

#include "net/acme_selfsigned.h"

#include <openssl/bn.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/x509v3.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#if !defined(_WIN32)
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#endif

#include "base/log_macros.h"

/* ── the name ────────────────────────────────────────────────────────── */

bool acme_domain_is_ldh(const char *domain)
{
    if (!domain || !domain[0])
        return false;
    const size_t len = strlen(domain);
    if (len > 253)
        return false;
    size_t label = 0;
    size_t label_start = 0;
    for (size_t i = 0; i < len; i++) {
        const unsigned char c = (unsigned char)domain[i];
        if (c == '.') {
            if (label == 0 || domain[i - 1] == '-')
                return false;
            label = 0;
            label_start = i + 1u;
            continue;
        }
        if (label == 0 && c == '-')
            return false;
        const bool ok = (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
                        (c >= '0' && c <= '9') || c == '-' ||
                        (c == '*' && i == 0 && len > 2 && domain[1] == '.');
        if (!ok)
            return false;
        if (++label > 63)
            return false;
    }
    return label != 0 && domain[len - 1] != '-' && label_start < len;
}

/* ── the skeleton ────────────────────────────────────────────────────── */

static bool set_subject_alt_name(X509 *cert, const char *domain)
{
    bool ok = false;
    GENERAL_NAMES *names = GENERAL_NAMES_new();
    GENERAL_NAME *name = GENERAL_NAME_new();
    ASN1_IA5STRING *dns = ASN1_IA5STRING_new();
    X509_EXTENSION *ext = NULL;

    if (!names || !name || !dns)
        goto done;
    if (ASN1_STRING_set(dns, domain, (int)strlen(domain)) != 1)
        goto done;
    GENERAL_NAME_set0_value(name, GEN_DNS, dns);
    dns = NULL; /* owned by `name` now */
    if (sk_GENERAL_NAME_push(names, name) <= 0)
        goto done;
    name = NULL; /* owned by `names` now */
    ext = X509V3_EXT_i2d(NID_subject_alt_name, 0, names);
    if (!ext)
        goto done;
    ok = X509_add_ext(cert, ext, -1) == 1;

done:
    X509_EXTENSION_free(ext);
    ASN1_IA5STRING_free(dns);
    GENERAL_NAME_free(name);
    GENERAL_NAMES_free(names);
    if (!ok)
        LOG_FAIL("acme", "cannot attach the subjectAltName for %s", domain);
    return true;
}

static bool set_subject(X509 *cert, const char *domain, const char *org)
{
    X509_NAME *subject = X509_get_subject_name(cert);
    if (!subject)
        LOG_FAIL("acme", "certificate has no subject to fill in");
    if (X509_NAME_add_entry_by_txt(subject, "CN", MBSTRING_ASC,
                                   (const unsigned char *)domain, -1, -1,
                                   0) != 1)
        LOG_FAIL("acme",
                 "cannot set the subject CN to %s (%zu bytes; X.509 caps the "
                 "common name at %d and OpenSSL refuses an over-long value "
                 "rather than truncating it)",
                 domain, strlen(domain), ub_common_name);
    if (org && org[0] &&
        X509_NAME_add_entry_by_txt(subject, "O", MBSTRING_ASC,
                                   (const unsigned char *)org, -1, -1, 0) != 1)
        LOG_FAIL("acme",
                 "cannot label the certificate subject with O=%s (%zu bytes; "
                 "X.509 caps the organization name at %d and OpenSSL refuses "
                 "an over-long value rather than truncating it)",
                 org, strlen(org), ub_organization_name);
    /* Self-issued by construction: issuer IS the subject. This is what
     * acme_certificate_is_self_issued() later reads back. */
    if (X509_set_issuer_name(cert, subject) != 1)
        LOG_FAIL("acme", "cannot make the certificate self-issued");
    return true;
}

bool acme_selfsigned_build(const struct acme_selfsigned_spec *spec,
                           X509 **out_cert, EVP_PKEY **out_key)
{
    if (!out_cert || !out_key)
        return false;
    *out_cert = NULL;
    *out_key = NULL;
    if (!spec)
        LOG_FAIL("acme", "cannot build a certificate without a specification");
    if (!acme_domain_is_ldh(spec->domain))
        LOG_FAIL("acme", "refusing to sign a certificate for a domain that is "
                         "not a plain LDH name");
    if (spec->lifetime_seconds <= 0)
        LOG_FAIL("acme", "refusing to sign a certificate that is already "
                         "expired when it is written");

    EVP_PKEY *key = EVP_EC_gen("P-256");
    X509 *cert = X509_new();
    BIGNUM *serial = BN_new();
    bool ok = false;
    if (!key || !cert || !serial)
        goto done;
    if (BN_rand(serial, 128, BN_RAND_TOP_ANY, BN_RAND_BOTTOM_ANY) != 1)
        goto done;
    if (!BN_to_ASN1_INTEGER(serial, X509_get_serialNumber(cert)))
        goto done;
    if (X509_set_version(cert, 2 /* v3 */) != 1)
        goto done;
    if (!X509_gmtime_adj(X509_getm_notBefore(cert), -spec->backdate_seconds) ||
        !X509_gmtime_adj(X509_getm_notAfter(cert), spec->lifetime_seconds))
        goto done;
    if (X509_set_pubkey(cert, key) != 1)
        goto done;
    if (!set_subject(cert, spec->domain, spec->organization))
        goto done;
    if (!set_subject_alt_name(cert, spec->domain))
        goto done;
    if (spec->extra && X509_add_ext(cert, spec->extra, -1) != 1)
        goto done;
    if (X509_sign(cert, key, EVP_sha256()) == 0)
        goto done;
    ok = true;

done:
    BN_free(serial);
    if (!ok) {
        X509_free(cert);
        EVP_PKEY_free(key);
        LOG_FAIL("acme", "cannot build a self-signed certificate for %s",
                 spec->domain);
    }
    *out_cert = cert;
    *out_key = key;
    return true;
}

/* ── telling the two kinds apart ─────────────────────────────────────── */

bool acme_certificate_is_self_issued(X509 *cert)
{
    if (!cert)
        return false;
    X509_NAME *issuer = X509_get_issuer_name(cert);
    X509_NAME *subject = X509_get_subject_name(cert);
    if (!issuer || !subject)
        return false;
    return X509_NAME_cmp(issuer, subject) == 0;
}

bool acme_certificate_file_is_self_issued(const char *pem_path)
{
    if (!pem_path || !pem_path[0])
        return false;
    FILE *f = fopen(pem_path, "rb");
    if (!f)
        return false;
    X509 *leaf = PEM_read_X509(f, NULL, NULL, NULL);
    fclose(f);
    if (!leaf)
        return false;
    const bool self_issued = acme_certificate_is_self_issued(leaf);
    X509_free(leaf);
    return self_issued;
}

/* ── writing the pair ────────────────────────────────────────────────── */

/* Stage into "<path>.tmp" and rename, so no reader ever sees a partial PEM.
 * `secret` narrows the mode to 0600 — the private key, and nothing else. */
static bool write_pem(const char *path, const char *data, size_t len,
                      bool secret)
{
    char tmp[1152];
    if (snprintf(tmp, sizeof(tmp), "%s.tmp", path) >= (int)sizeof(tmp))
        LOG_FAIL("acme", "path is too long to stage a temporary file: %s", path);

    FILE *f = NULL;
#if !defined(_WIN32)
    (void)unlink(tmp);
    const mode_t mode = secret ? (S_IRUSR | S_IWUSR)
                               : (S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH);
    const int fd = open(tmp, O_WRONLY | O_CREAT | O_EXCL, mode);
    if (fd < 0)
        LOG_FAIL("acme", "cannot create %s", tmp);
    f = fdopen(fd, "wb");
    if (!f) {
        close(fd);
        (void)remove(tmp);
        LOG_FAIL("acme", "cannot buffer writes to %s", tmp);
    }
#else
    (void)secret;
    f = fopen(tmp, "wb");
    if (!f)
        LOG_FAIL("acme", "cannot create %s", tmp);
#endif
    const bool wrote = len == 0 || fwrite(data, 1, len, f) == len;
    const bool flushed = fflush(f) == 0;
    fclose(f);
    if (!wrote || !flushed) {
        (void)remove(tmp);
        LOG_FAIL("acme", "cannot write %zu bytes to %s", len, tmp);
    }
    if (rename(tmp, path) != 0) {
        (void)remove(tmp);
        LOG_FAIL("acme", "cannot move %s into place", path);
    }
    return true;
}

static bool write_cert_pem(X509 *cert, const char *path)
{
    BIO *bio = BIO_new(BIO_s_mem());
    if (!bio)
        LOG_FAIL("acme", "cannot buffer the placeholder certificate");
    bool ok = PEM_write_bio_X509(bio, cert) == 1;
    char *data = NULL;
    const long len = ok ? BIO_get_mem_data(bio, &data) : 0;
    ok = ok && len > 0 && data && write_pem(path, data, (size_t)len, false);
    BIO_free(bio);
    if (!ok)
        LOG_FAIL("acme", "cannot write the placeholder certificate to %s", path);
    return true;
}

static bool write_key_pem(EVP_PKEY *key, const char *path)
{
    BIO *bio = BIO_new(BIO_s_mem());
    if (!bio)
        LOG_FAIL("acme", "cannot buffer the placeholder key");
    bool ok = PEM_write_bio_PrivateKey(bio, key, NULL, NULL, 0, NULL, NULL) == 1;
    char *data = NULL;
    const long len = ok ? BIO_get_mem_data(bio, &data) : 0;
    ok = ok && len > 0 && data && write_pem(path, data, (size_t)len, true);
    BIO_free(bio);
    if (!ok)
        LOG_FAIL("acme", "cannot write the placeholder key to %s", path);
    return true;
}

bool acme_selfsigned_write(const char *cert_path, const char *key_path,
                           const char *domain)
{
    if (!cert_path || !cert_path[0] || !key_path || !key_path[0])
        LOG_FAIL("acme", "cannot write a placeholder pair without both paths");

    const char *cn = (domain && domain[0]) ? domain
                                           : ACME_SELFSIGNED_DEFAULT_CN;
    if (!acme_domain_is_ldh(cn))
        LOG_FAIL("acme", "refusing to sign a placeholder for a domain that is "
                         "not a plain LDH name");

    const struct acme_selfsigned_spec spec = {
        .domain = cn,
        .organization = ACME_SELFSIGNED_ORGANIZATION,
        .backdate_seconds = 3600,
        .lifetime_seconds = ACME_SELFSIGNED_LIFETIME_SECONDS,
        .extra = NULL,
    };
    X509 *cert = NULL;
    EVP_PKEY *key = NULL;
    if (!acme_selfsigned_build(&spec, &cert, &key))
        return false;

    /* Key first, then the certificate: whoever sees the new certificate must
     * never find the old key beside it. Same ordering the certificate worker
     * uses for the real pair (tools/acme/acme_client.c). */
    const bool ok = write_key_pem(key, key_path) &&
                    write_cert_pem(cert, cert_path);
    X509_free(cert);
    EVP_PKEY_free(key);
    if (!ok)
        LOG_FAIL("acme", "no placeholder certificate was written to %s",
                 cert_path);
    return true;
}

/* Both files parse AND the key belongs to the certificate. A pair that fails
 * either half would make the listener refuse to start, which is the whole
 * failure this module exists to prevent. */
static bool pair_is_usable(const char *cert_path, const char *key_path)
{
    FILE *cf = fopen(cert_path, "rb");
    if (!cf)
        return false;
    X509 *cert = PEM_read_X509(cf, NULL, NULL, NULL);
    fclose(cf);
    if (!cert)
        return false;

    FILE *kf = fopen(key_path, "rb");
    EVP_PKEY *key = kf ? PEM_read_PrivateKey(kf, NULL, NULL, NULL) : NULL;
    if (kf)
        fclose(kf);

    const bool ok = key != NULL && X509_check_private_key(cert, key) == 1;
    EVP_PKEY_free(key);
    X509_free(cert);
    return ok;
}

bool acme_selfsigned_ensure(const char *cert_path, const char *key_path,
                            const char *domain)
{
    if (!cert_path || !cert_path[0] || !key_path || !key_path[0])
        LOG_FAIL("acme", "cannot place a placeholder pair without both paths");
    if (pair_is_usable(cert_path, key_path))
        return true;
    if (!acme_selfsigned_write(cert_path, key_path, domain))
        return false;
    if (!pair_is_usable(cert_path, key_path))
        LOG_FAIL("acme", "wrote a placeholder pair to %s that does not read "
                         "back as a usable certificate and key", cert_path);
    return true;
}
