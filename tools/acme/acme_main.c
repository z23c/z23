/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * `zclassic23-acme` — the node's certificate worker.
 *
 * WHY THIS IS A SEPARATE PROGRAM. Getting a certificate from Let's Encrypt
 * means being a TLS client with a CA trust store, and a program with a trust
 * store can be told who to trust by whoever ships that store. The node
 * refuses that property: test_cold_join_sovereign P2 asserts that no
 * Z23-authored object the node links carries an undefined reference to any
 * TLS-client or CA-trust-store entry point. So the CA conversation lives
 * out here, exactly as package verification lives in
 * `zclassic23-package-verify`, and the node keeps doing the only thing it
 * ever knew how to do with a certificate: load one from a file.
 *
 * This is deliberately the ONE place in the tree that trusts a public
 * certificate authority. That is acceptable here and nowhere else, because
 * the only thing a public CA is used for is the OPTIONAL clearnet
 * convenience surface — the small HTTPS front door that hands a stranger
 * with a browser the install script. Every sovereign path (onion service,
 * peer-to-peer, block and header validation, consensus) runs with no CA in
 * sight, and this program cannot reach any of them: it opens no datadir,
 * reads no chain state, and writes exactly two files plus one handoff line.
 *
 * Commands:
 *
 *   obtain    Run the full ACME order now, unconditionally.
 *   renew     Look at the certificate on disk and order only if it is inside
 *             the thirty-day renewal window. This is the one to put on a
 *             timer; running it daily costs nothing until it is due.
 *   check     Print the renewal verdict for a certificate and exit. Reads
 *             nothing but the file; contacts nobody.
 *   selftest  Run the offline assertions that travel with this program.
 *
 * The node picks up what this program writes with no restart: its front
 * door watches the certificate path and swaps the running TLS context when
 * the file changes. Renewal is therefore this one command on a timer, and
 * nothing else.
 *
 * Exit codes: 0 success, 1 the operation failed, 2 the arguments were not
 * usable. `check` also uses 3 to mean "renewal is due", so a shell can act
 * on the verdict without parsing text.
 */

#include "acme_client.h"
#include "acme_selftest.h"

#include "net/acme_renewal.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#define ACME_EXIT_OK      0
#define ACME_EXIT_FAILED  1
#define ACME_EXIT_USAGE   2
#define ACME_EXIT_DUE     3

static void usage(FILE *out)
{
    fputs(
        "zclassic23-acme — issue and renew the node's TLS certificate\n"
        "\n"
        "  zclassic23-acme obtain|renew --domain NAME --account PEM --cert PEM\n"
        "                               --key PEM --handoff PATH --agree-tos\n"
        "                               [--staging | --directory URL]\n"
        "                               [--email ADDRESS] [--timeout-ms N]\n"
        "                               [--poll-attempts N] [--poll-interval-ms N]\n"
        "  zclassic23-acme check  --cert PEM\n"
        "  zclassic23-acme selftest\n"
        "\n"
        "  --handoff PATH must be the SAME path the node was told to read.\n"
        "  It is how the node learns the key authorization to present on 443.\n"
        "\n"
        "  --agree-tos is required to create an account: RFC 8555 says an\n"
        "  account agrees to the CA's terms, and only an operator can do that.\n"
        "\n"
        "  --staging selects the Let's Encrypt staging directory. Use it for\n"
        "  anything that is not a real deployment — production rate limits are\n"
        "  measured in weeks, and tripping one is a week-long outage.\n"
        "\n"
        "Exit: 0 ok, 1 failed, 2 bad arguments; `check` returns 3 when renewal\n"
        "is due so a timer can branch without parsing this text.\n",
        out);
}

/* Read `--flag VALUE`. Returns false when the value is missing, so a typo
 * cannot silently swallow the next flag as its argument. */
static bool take_value(int argc, char **argv, int *i, const char **out)
{
    if (*i + 1 >= argc || argv[*i + 1][0] == '\0')
        return false;
    *out = argv[++(*i)];
    return true;
}

static bool take_int(int argc, char **argv, int *i, int *out)
{
    const char *text = NULL;
    if (!take_value(argc, argv, i, &text))
        return false;
    char *end = NULL;
    const long v = strtol(text, &end, 10);
    if (!end || *end != '\0' || v < 0 || v > 3600000)
        return false;
    *out = (int)v;
    return true;
}

static int report_check(const char *cert_path)
{
    const int64_t now = (int64_t)time(NULL);
    const enum acme_renewal_action action = acme_renewal_check(cert_path, now);
    int64_t not_before = 0;
    int64_t not_after = 0;
    (void)acme_certificate_validity(cert_path, &not_before, &not_after);
    printf("verdict=%s cert=%s not_after=%lld seconds_remaining=%lld "
           "seconds_until_due=%lld window_seconds=%d\n",
           acme_renewal_action_name(action), cert_path, (long long)not_after,
           (long long)(not_after ? not_after - now : 0),
           (long long)acme_renewal_seconds_until_due(cert_path, now),
           ACME_RENEWAL_WINDOW_SECONDS);
    switch (action) {
    case ACME_RENEWAL_CURRENT:
        return ACME_EXIT_OK;
    case ACME_RENEWAL_DUE:
    case ACME_RENEWAL_EXPIRED:
    case ACME_RENEWAL_ABSENT:
    case ACME_RENEWAL_NOT_YET_VALID:
        return ACME_EXIT_DUE;
    case ACME_RENEWAL_UNREADABLE:
        return ACME_EXIT_FAILED;
    }
    return ACME_EXIT_FAILED;
}

int main(int argc, char **argv)
{
    if (argc < 2) {
        usage(stderr);
        return ACME_EXIT_USAGE;
    }
    const char *command = argv[1];

    if (strcmp(command, "--help") == 0 || strcmp(command, "help") == 0) {
        usage(stdout);
        return ACME_EXIT_OK;
    }
    if (strcmp(command, "selftest") == 0) {
        const int failures = acme_selftest_transport() + acme_selftest_protocol();
        if (failures == 0) {
            printf("ALL SELFTESTS PASSED\n");
            return ACME_EXIT_OK;
        }
        printf("SOME SELFTESTS FAILED — %d check(s)\n", failures);
        return ACME_EXIT_FAILED;
    }

    const bool obtain = strcmp(command, "obtain") == 0;
    const bool renew = strcmp(command, "renew") == 0;
    const bool check = strcmp(command, "check") == 0;
    if (!obtain && !renew && !check) {
        fprintf(stderr, "zclassic23-acme: unknown command \"%s\"\n", command);
        usage(stderr);
        return ACME_EXIT_USAGE;
    }

    struct acme_client_config cfg = {0};
    const char *cert_path = NULL;
    bool staging = false;

    for (int i = 2; i < argc; i++) {
        const char *a = argv[i];
        bool ok = true;
        if (strcmp(a, "--domain") == 0)             ok = take_value(argc, argv, &i, &cfg.domain);
        else if (strcmp(a, "--account") == 0)       ok = take_value(argc, argv, &i, &cfg.account_key_path);
        else if (strcmp(a, "--cert") == 0)          ok = take_value(argc, argv, &i, &cert_path);
        else if (strcmp(a, "--key") == 0)           ok = take_value(argc, argv, &i, &cfg.cert_key_path);
        else if (strcmp(a, "--handoff") == 0)       ok = take_value(argc, argv, &i, &cfg.handoff_path);
        else if (strcmp(a, "--email") == 0)         ok = take_value(argc, argv, &i, &cfg.contact_email);
        else if (strcmp(a, "--directory") == 0)     ok = take_value(argc, argv, &i, &cfg.directory_url);
        else if (strcmp(a, "--timeout-ms") == 0)    ok = take_int(argc, argv, &i, &cfg.timeout_ms);
        else if (strcmp(a, "--poll-attempts") == 0) ok = take_int(argc, argv, &i, &cfg.poll_attempts);
        else if (strcmp(a, "--poll-interval-ms") == 0) ok = take_int(argc, argv, &i, &cfg.poll_interval_ms);
        else if (strcmp(a, "--staging") == 0)       staging = true;
        else if (strcmp(a, "--agree-tos") == 0)     cfg.agree_terms_of_service = true;
        else {
            fprintf(stderr, "zclassic23-acme: unknown option \"%s\"\n", a);
            usage(stderr);
            return ACME_EXIT_USAGE;
        }
        if (!ok) {
            fprintf(stderr, "zclassic23-acme: %s needs a value\n", a);
            return ACME_EXIT_USAGE;
        }
    }
    cfg.cert_path = cert_path;

    if (!cert_path) {
        fprintf(stderr, "zclassic23-acme: --cert names the certificate this "
                        "command reads or writes; it has no default\n");
        return ACME_EXIT_USAGE;
    }
    if (check)
        return report_check(cert_path);

    if (staging && cfg.directory_url) {
        fprintf(stderr, "zclassic23-acme: --staging and --directory both name a "
                        "certificate authority; pass one\n");
        return ACME_EXIT_USAGE;
    }
    if (staging)
        cfg.directory_url = ACME_DIRECTORY_LETSENCRYPT_STAGING;

    if (renew) {
        const int64_t now = (int64_t)time(NULL);
        const enum acme_renewal_action action = acme_renewal_check(cert_path, now);
        if (action == ACME_RENEWAL_CURRENT) {
            printf("verdict=current cert=%s seconds_until_due=%lld — nothing to do\n",
                   cert_path,
                   (long long)acme_renewal_seconds_until_due(cert_path, now));
            return ACME_EXIT_OK;
        }
        printf("verdict=%s cert=%s — ordering\n",
               acme_renewal_action_name(action), cert_path);
    }

    if (!acme_client_obtain(&cfg))
        return ACME_EXIT_FAILED;

    /* The renewal is end-to-end from here with nothing else to run. The
     * node's front door watches this exact certificate path and swaps the
     * running TLS context when its file identity changes, on the next
     * connection, with no restart and without breaking a handshake already
     * in flight (net/https_server.h). Saying so out loud matters: the
     * ninety-day manual restart this program exists to remove is exactly the
     * step an operator would otherwise go looking for. */
    int64_t not_before = 0;
    int64_t not_after = 0;
    (void)acme_certificate_validity(cfg.cert_path, &not_before, &not_after);
    printf("issued cert=%s key=%s domain=%s not_after=%lld\n", cfg.cert_path,
           cfg.cert_key_path, cfg.domain, (long long)not_after);
    printf("the running node serves this on its next connection; no restart, "
           "and nothing else to run\n");
    return ACME_EXIT_OK;
}
